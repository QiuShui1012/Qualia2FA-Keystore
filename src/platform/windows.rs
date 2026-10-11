// Copyright (C) 2026 Qualia2FA contributors
//
// This library is free software; you can redistribute it and/or modify it under
// the terms of the GNU Lesser General Public License as published by the Free
// Software Foundation; either version 3 of the License, or (at your option) any
// later version.
//
// This library is distributed in the hope that it will be useful, but WITHOUT
// ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
// FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License for more
// details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with this library; if not, see <https://www.gnu.org/licenses/>.

//! Windows 后端：通过 CNG 的 `NCrypt*` 接口使用 TPM 2.0。
//!
//! # 为什么是 `NCrypt*` 而不是 TBS
//!
//! `NCrypt*` 是 CNG 的**密钥**接口（NCRYPT = Cryptography Next Generation
//! **Key** API），它把「密钥存在哪里」抽象成「密钥存储提供程序」（KSP）。指定
//! `MS_PLATFORM_CRYPTO_PROVIDER` 就会把密钥交给 TPM，而指定
//! `MS_KEY_STORAGE_PROVIDER` 则退化为软件密钥——**同一个 API，两种后端**，这让
//! 「有 TPM 用 TPM、没有则降级」变成了改一个字符串的事。
//!
//! TBS（`Tbsi_*`）是更底层的 TPM 命令接口，需要自己拼 TPM 命令、处理会话与授权，
//! 而且 `windows-sys` 里没有它。CNG 已经把这层做完了。
//!
//! # 密钥的所有权
//!
//! 密钥以**持久密钥**（persisted key）的形式存在 KSP 里，有名字。实测确认：
//!
//! - 进程退出后密钥仍在 → 设备身份跨重启稳定。
//! - 同名重复创建会被拒绝（`NTE_EXISTS` = `0x8009000F`），**不会**覆盖。
//! - 删除需要显式调用 → 卸载不会自动清理。这是刻意的：误删等于这台设备永久失去
//!   身份，别的设备再也认不出它。
//!
//! # 私钥不会进入本进程的地址空间
//!
//! 全程只有三种数据跨过边界：密钥的**名字**（进去）、**公钥**（出来）、
//! **签名**（出来）。因此本模块没有需要擦除的秘密——这也是为什么它不需要
//! `zeroize`。这一点与测试用的内存后端（`crate::MockKeyStore`）形成鲜明对比：
//! 那边的私钥就在普通内存里，必须显式擦除。
//!
//! # 线程安全说明
//!
//! `NCryptKeyHandle` 本身不是线程安全的（同一个句柄并发使用需要外部同步）。
//! CNG 的密钥对象可以**多次打开**，每次得到独立的句柄，因此正确的并发做法是每个
//! 线程各开各的，而不是共享一个句柄。本模块因此没有为 [`WindowsSigner`] 实现
//! `Sync`：每个签名器独占一个句柄。
//!
//! # 本模块不提供的功能
//!
//! **无法列出已有密钥。** 详见下方 `KEY_NAME_PREFIX` 附近对 `NCryptEnumKeys`
//! 的说明——那是一个实测结论，不是「暂时没实现」。

use crate::error::{KeyStoreError, Result};
use crate::traits::{
    Backend, DIGEST_LEN, DeviceKeyStore, DeviceSigner, public_key_from_sec1, signature_from_raw,
};
use qualia2fa_core::{DevicePublicKey, DeviceSignature};
use std::fmt;
use windows_sys::Win32::Security::Cryptography::{
    BCRYPT_ECCPUBLIC_BLOB, MS_KEY_STORAGE_PROVIDER, MS_PLATFORM_CRYPTO_PROVIDER,
    NCRYPT_ECDSA_P256_ALGORITHM, NCRYPT_KEY_HANDLE, NCRYPT_PROV_HANDLE, NCRYPT_SILENT_FLAG,
    NCryptCreatePersistedKey, NCryptDeleteKey, NCryptExportKey, NCryptFinalizeKey,
    NCryptFreeObject, NCryptOpenKey, NCryptOpenStorageProvider, NCryptSignHash,
};

/// `NTE_BAD_FLAGS`：标志位不被支持。
///
/// 生产代码用不到它，保留是为了让 [`tests::nte_codes_match_winerror`] 能一次性
/// 钉住整组常量的来源值（把整组值写在一处，抄错时更容易发现）。
// `allow` 而不是 `expect`：这个常量在测试构建里**会**被用到，因此
// `expect(dead_code)` 在 `cfg(test)` 下是「未兑现的期望」，本身会触发警告。
#[allow(dead_code, reason = "供测试对照 winerror.h 钉住常量值")]
const NTE_BAD_FLAGS: i32 = 0x8009_0009_u32 as i32;

/// `NTE_NO_KEY`：没有可用的密钥。某些 KSP 用它代替 [`NTE_BAD_KEYSET`]。
const NTE_NO_KEY: i32 = 0x8009_000D_u32 as i32;

/// `NTE_EXISTS`：同名密钥已存在。
///
/// 出现在用同一个名字再次 [`NCryptCreatePersistedKey`] 时。这是**正常**结果，
/// 见模块文档。
const NTE_EXISTS: i32 = 0x8009_000F_u32 as i32;

/// `NTE_NOT_FOUND`：找不到对象。
const NTE_NOT_FOUND: i32 = 0x8009_0011_u32 as i32;

/// `NTE_BAD_KEYSET`：密钥集不存在，也就是**没有这个密钥**。
///
/// # 这些常量是从头文件抄来的，不要凭印象写
///
/// 本模块的第一版实现把它写成 `0x80090001`，于是**每一个**「先打开看看存不存在」
/// 的调用都被当成了硬件故障，所有涉及创建密钥的测试一起失败——十来个测试报了
/// 同一个 `Hardware { operation: "NCryptOpenKey", code: -2146893802 }`。错误码记错
/// 不会让编译器报错，只会让正确路径变成错误路径。
///
/// 权威来源是 Windows SDK 的 `winerror.h`：
///
/// ```text
/// #define NTE_BAD_FLAGS     _HRESULT_TYPEDEF_(0x80090009L)
/// #define NTE_NO_KEY        _HRESULT_TYPEDEF_(0x8009000DL)
/// #define NTE_EXISTS        _HRESULT_TYPEDEF_(0x8009000FL)
/// #define NTE_NOT_FOUND     _HRESULT_TYPEDEF_(0x80090011L)
/// #define NTE_BAD_KEYSET    _HRESULT_TYPEDEF_(0x80090016L)
/// ```
///
/// `windows-sys` 没有导出这些常量，所以只能手抄；
/// [`tests::nte_codes_match_winerror`] 把这些值钉住，改错时会失败。
const NTE_BAD_KEYSET: i32 = 0x8009_0016_u32 as i32;

/// 本模块使用的密钥名前缀。
///
/// 加前缀是为了让这些密钥在系统密钥列表里一眼可辨——它们和用户的其它密钥混在
/// 同一个 KSP 命名空间里，出问题时需要能快速区分。
///
/// # 关于「列出全部密钥」
///
/// 这里原本有一个基于 `NCryptEnumKeys` 的实现，已被删除。实测结论（Windows 11 +
/// 本机 TPM 2.0）：**`NCryptEnumKeys` 对 `MS_PLATFORM_CRYPTO_PROVIDER` 返回成功但
/// 数量为 0**，即便刚刚用该提供程序创建、打开并成功签名过密钥。也就是说它列不出
/// TPM 里的密钥，而不是作用域没传对——传 `$$$MACHINE$$$` 或 `$$$CURRENT_USER$$$`
/// 会直接返回 `0x80090029`（不支持）。
///
/// 因此「列出本设备上的全部身份」在 Windows 上**做不到**。与其提供一个对主要后端
/// 静默返回空表的接口（那会让「没有身份」与「查不出来」变得无法区分），不如不
/// 提供：需要知道本机有哪些身份的一方，应当**自己记录**创建过哪些 label——例如
/// 账号注册表。那也更可靠，因为密钥名本身并不携带「属于哪个账号」这个信息。
const KEY_NAME_PREFIX: &str = "Qualia2FA-Device-";

/// 标签长度上限。
///
/// 加前缀后总共不超过 CNG 能接受的名字长度，同时留出余量。
const MAX_LABEL_LEN: usize = 128;

/// 把逻辑 `label` 转成 CNG 密钥名（以 NUL 结尾的 UTF-16）。
///
/// # 为什么必须做字符校验
///
/// 密钥名会成为**系统级**命名空间里的一个条目。`label` 来自上层（可能间接来自
/// 用户），若允许其中出现控制字符或空字符，就可能构造出奇怪的名字——最直接的是
/// **空字符截断**：`"a\0b"` 与 `"a"` 在 C 字符串看来是同一个名字，于是两个不同的
/// `label` 会映射到同一份设备身份，而调用方完全察觉不到。
///
/// 因此这里**只允许** ASCII 字母、数字、`-`、`_`、`.`，其余一律拒绝。这是白名单
/// 而不是黑名单：将来发现新的危险字符时，黑名单会漏，白名单不会。
fn key_name(label: &str) -> Result<Vec<u16>> {
    if label.is_empty() {
        return Err(KeyStoreError::InvalidKeyLabel {
            reason: "标签为空"
        });
    }
    if label.len() > MAX_LABEL_LEN {
        return Err(KeyStoreError::InvalidKeyLabel {
            reason: "标签过长（上限 128 字节）",
        });
    }
    if !label
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        return Err(KeyStoreError::InvalidKeyLabel {
            reason: "标签含非法字符（只允许 ASCII 字母、数字、- _ .）",
        });
    }
    let name = format!("{KEY_NAME_PREFIX}{label}");
    let mut wide: Vec<u16> = name.encode_utf16().collect();
    wide.push(0); // NUL 结尾
    Ok(wide)
}

/// 一个会被正确释放的 CNG 对象句柄。
///
/// # 为什么不用手写 `Drop` 加裸句柄
///
/// CNG 的每个句柄都必须 [`NCryptFreeObject`]，而本模块里有多条提前返回的错误
/// 路径。用 `Drop` 保证释放，就不会出现「错误路径上漏释放」——那类泄漏在长时间
/// 运行的桌面应用里会累积成真实的资源耗尽。
struct CngHandle {
    /// 原生句柄。`0` 表示空（CNG 用 0 表示无效句柄）。
    raw: usize,
}

impl CngHandle {
    /// 接管一个原生句柄的所有权。
    fn new(raw: usize) -> Self {
        Self { raw }
    }
}

impl Drop for CngHandle {
    fn drop(&mut self) {
        if self.raw != 0 {
            // SAFETY: `self.raw` 是本结构独占持有的有效 CNG 句柄（构造它的地方都
            // 检查过 API 调用成功），且只在此处释放一次。
            unsafe { NCryptFreeObject(self.raw) };
        }
    }
}

/// 这个状态码是否表示「没有这个密钥」。
///
/// # 为什么是一组而不是一个
///
/// 不同的 KSP 与不同的 CNG 版本用不同的码汇报同一件事：
///
/// - [`NTE_BAD_KEYSET`]——名字不存在（实测本机 TPM 走的是这个）。
/// - [`NTE_NO_KEY`]——没有可用的密钥（某些软件 KSP）。
/// - [`NTE_NOT_FOUND`]——找不到对象。
///
/// 只认其中一个的后果是：在别的机器上，「密钥不存在」会被当成硬件故障，于是
/// **创建**路径永远走不到——而那样的 bug 只在别人的机器上出现。
const fn means_no_such_key(status: i32) -> bool {
    matches!(status, NTE_BAD_KEYSET | NTE_NO_KEY | NTE_NOT_FOUND)
}

/// 打开一个密钥存储提供程序。
///
/// `provider` 必须是 `windows-sys` 里的宽字符串常量（`MS_*_PROVIDER`）。
fn open_provider(provider: *const u16) -> Result<CngHandle> {
    let mut handle: NCRYPT_PROV_HANDLE = 0;
    // SAFETY: `handle` 是有效的可写局部变量；`provider` 是 `windows-sys` 导出的
    // 以 NUL 结尾的静态宽字符串。
    let status = unsafe { NCryptOpenStorageProvider(&raw mut handle, provider, 0) };
    if status < 0 {
        return Err(KeyStoreError::Hardware {
            operation: "NCryptOpenStorageProvider",
            code: status,
        });
    }
    Ok(CngHandle::new(handle))
}

/// 打开一个已存在的密钥。
///
/// 密钥不存在时返回 `Ok(None)`——那是预期路径，不是错误。
fn open_key(provider: &CngHandle, name: &[u16]) -> Result<Option<CngHandle>> {
    let mut handle: NCRYPT_KEY_HANDLE = 0;
    // SAFETY: `provider` 有效；`name` 以 NUL 结尾且在本语句期间存活。
    let status = unsafe {
        NCryptOpenKey(
            provider.raw,
            &raw mut handle,
            name.as_ptr(),
            0,
            NCRYPT_SILENT_FLAG,
        )
    };
    if means_no_such_key(status) {
        return Ok(None);
    }
    if status < 0 {
        return Err(KeyStoreError::Hardware {
            operation: "NCryptOpenKey",
            code: status,
        });
    }
    Ok(Some(CngHandle::new(handle)))
}

/// 创建并 finalize 一个新的持久密钥。
///
/// 同名已存在时返回 `Ok(None)`——那是竞态的正常结果，不是错误。
fn create_key(provider: &CngHandle, name: &[u16]) -> Result<Option<CngHandle>> {
    let mut handle: NCRYPT_KEY_HANDLE = 0;
    // 不传 `NCRYPT_OVERWRITE_KEY_FLAG`：覆盖会**静默替换**掉已有密钥，那等于悄悄
    // 换掉了设备身份。宁可失败。
    // SAFETY: `provider` 有效；`name` 以 NUL 结尾且在本语句期间存活；`handle` 可写。
    let status = unsafe {
        NCryptCreatePersistedKey(
            provider.raw,
            &raw mut handle,
            NCRYPT_ECDSA_P256_ALGORITHM,
            name.as_ptr(),
            0,
            0,
        )
    };
    if status == NTE_EXISTS {
        return Ok(None);
    }
    if status < 0 {
        return Err(KeyStoreError::Hardware {
            operation: "NCryptCreatePersistedKey",
            code: status,
        });
    }

    // 句柄现在归我们管了：从这里到 finalize 之间无论走哪条路都要释放它。
    let guarded = CngHandle::new(handle);

    // SAFETY: `guarded` 持有有效句柄。
    let status = unsafe { NCryptFinalizeKey(guarded.raw, NCRYPT_SILENT_FLAG) };
    if status < 0 {
        return Err(KeyStoreError::Hardware {
            operation: "NCryptFinalizeKey",
            code: status,
        });
    }
    Ok(Some(guarded))
}

/// 导出密钥的公钥部分。
///
/// CNG 返回的是 `BCRYPT_ECCPUBLIC_BLOB`：8 字节头（`magic` = `"ECCS"`，`cbKey`
/// = 32）+ `X`(32) + `Y`(32)。我们把它转换成 SEC1 未压缩点 `0x04 || X || Y`。
///
/// # 为什么公钥导出是允许的
///
/// 因为**公钥不是秘密**——它本来就要印在二维码上给对方看。TPM 里那些「不允许
/// 导出」的对象指的是私钥；导出一个公钥不需要任何授权，实测也不需要用户在场。
fn export_public_key(key: &CngHandle) -> Result<DevicePublicKey> {
    // 第一次调用只为问所需长度：输出缓冲区留空。
    let mut needed: u32 = 0;
    // SAFETY: `key` 有效；输出指针为 null 且长度为 0 是 API 文档允许的
    // 「查询所需长度」用法，此时不会写入任何内存。
    let status = unsafe {
        NCryptExportKey(
            key.raw,
            0,
            BCRYPT_ECCPUBLIC_BLOB,
            std::ptr::null(),
            std::ptr::null_mut(),
            0,
            &raw mut needed,
            0,
        )
    };
    if status < 0 {
        return Err(KeyStoreError::Hardware {
            operation: "NCryptExportKey(查询长度)",
            code: status,
        });
    }
    // 防御：长度字段来自平台 API，正常情况下是 72。给一个荒谬的上限，避免因为
    // 平台异常而申请巨量内存。公钥最多也就几十字节。
    if needed > 1024 {
        return Err(KeyStoreError::InvalidPublicKey {
            reason: "平台报告的公钥长度异常（超过 1024 字节）",
        });
    }

    let mut blob = vec![0_u8; needed as usize];
    // SAFETY: `blob` 至少有 `needed` 字节，与传入的长度一致。
    let status = unsafe {
        NCryptExportKey(
            key.raw,
            0,
            BCRYPT_ECCPUBLIC_BLOB,
            std::ptr::null(),
            blob.as_mut_ptr(),
            needed,
            &raw mut needed,
            0,
        )
    };
    if status < 0 {
        return Err(KeyStoreError::Hardware {
            operation: "NCryptExportKey",
            code: status,
        });
    }
    blob.truncate(needed as usize);

    // `BCRYPT_ECCKEY_BLOB`：{ dwMagic: u32, cbKey: u32 }，均为小端。
    if blob.len() < 8 {
        return Err(KeyStoreError::InvalidPublicKey {
            reason: "平台返回的公钥块短于 8 字节的头",
        });
    }
    let cb_key = u32::from_le_bytes([blob[4], blob[5], blob[6], blob[7]]) as usize;
    let payload = &blob[8..];
    if payload.len() != cb_key * 2 {
        return Err(KeyStoreError::InvalidPublicKey {
            reason: "平台返回的公钥载荷长度与 cbKey 不符",
        });
    }
    if cb_key != 32 {
        return Err(KeyStoreError::InvalidPublicKey {
            reason: "平台返回的公钥不是 32 字节坐标（不是 P-256）",
        });
    }

    // 转成 SEC1 未压缩点：0x04 || X || Y。
    let mut sec1 = [0_u8; 65];
    sec1[0] = 0x04;
    sec1[1..].copy_from_slice(payload);
    public_key_from_sec1(&sec1)
}

/// 对一段摘要签名。
///
/// CNG 直接返回原始的 `r||s`（64 字节），**不是 DER**——这一点与不少「NCrypt
/// 返回 DER」的二手说法相反，已在真机上实测确认。原始格式正好是
/// [`DeviceSignature`] 的线格式，不需要任何转换。
fn sign_digest_raw(key: &CngHandle, digest: &[u8]) -> Result<DeviceSignature> {
    if digest.len() != DIGEST_LEN {
        return Err(KeyStoreError::InvalidDigestLength {
            expected: DIGEST_LEN,
            actual: digest.len(),
        });
    }

    let mut needed: u32 = 0;
    // SAFETY: `key` 有效；`digest` 是有效切片；输出缓冲区为空以查询长度。
    let status = unsafe {
        NCryptSignHash(
            key.raw,
            std::ptr::null(),
            digest.as_ptr(),
            digest.len() as u32,
            std::ptr::null_mut(),
            0,
            &raw mut needed,
            0,
        )
    };
    if status < 0 {
        return Err(KeyStoreError::Hardware {
            operation: "NCryptSignHash(查询长度)",
            code: status,
        });
    }
    if needed > 1024 {
        return Err(KeyStoreError::InvalidSignatureLength {
            expected: 64,
            actual: needed as usize,
        });
    }

    let mut signature = vec![0_u8; needed as usize];
    // SAFETY: `signature` 至少有 `needed` 字节，与传入的长度一致。
    let status = unsafe {
        NCryptSignHash(
            key.raw,
            std::ptr::null(),
            digest.as_ptr(),
            digest.len() as u32,
            signature.as_mut_ptr(),
            needed,
            &raw mut needed,
            0,
        )
    };
    if status < 0 {
        return Err(KeyStoreError::Hardware {
            operation: "NCryptSignHash",
            code: status,
        });
    }
    signature.truncate(needed as usize);
    signature_from_raw(&signature)
}

/// Windows 上使用的密钥存储提供程序。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WindowsProvider {
    /// TPM 2.0（`MS_PLATFORM_CRYPTO_PROVIDER`）。私钥无法导出。
    Tpm,
    /// 软件密钥库（`MS_KEY_STORAGE_PROVIDER`）。私钥**可以**被系统导出，
    /// 仅作为没有 TPM 时的降级选择。
    Software,
}

impl WindowsProvider {
    /// 对应的 CNG 提供程序名。
    const fn provider_name(self) -> *const u16 {
        match self {
            Self::Tpm => MS_PLATFORM_CRYPTO_PROVIDER,
            Self::Software => MS_KEY_STORAGE_PROVIDER,
        }
    }

    /// 对应的后端种类。
    const fn backend(self) -> Backend {
        match self {
            Self::Tpm => Backend::Tpm,
            Self::Software => Backend::Software,
        }
    }

    /// 后端的人类可读名，用于错误消息。
    const fn describe(self) -> &'static str {
        match self {
            Self::Tpm => "平台加密提供程序（TPM）",
            Self::Software => "软件密钥存储提供程序",
        }
    }
}

/// Windows 硬件密钥库。
pub struct WindowsKeyStore {
    /// 已打开的提供程序句柄。
    provider: CngHandle,
    /// 这份密钥库实际绑定的后端。
    backend: Backend,
}

impl fmt::Debug for WindowsKeyStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WindowsKeyStore")
            .field("backend", &self.backend)
            .finish_non_exhaustive()
    }
}

impl WindowsKeyStore {
    /// 打开由 `preferred` 指定的提供程序。
    ///
    /// # 错误
    ///
    /// 该提供程序在本机不可用时返回 [`KeyStoreError::HardwareUnavailable`]。
    pub fn open(preferred: WindowsProvider) -> Result<Self> {
        let provider = open_provider(preferred.provider_name()).map_err(|error| {
            // 打开失败通常意味着「这台机器上没有 TPM」或「被组策略禁用」，属于
            // 环境问题而不是我们的 bug，因此归类为 `HardwareUnavailable`，让 UI
            // 能给出「你的设备没有硬件密钥保护」这种有意义的提示。
            KeyStoreError::HardwareUnavailable {
                reason: format!("无法打开{}（{error}）", preferred.describe()),
            }
        })?;
        Ok(Self {
            provider,
            backend: preferred.backend(),
        })
    }

    /// 优先用 TPM，不可用时退到软件密钥库。
    ///
    /// # 为什么降级必须是显式的、可通过返回值查到的
    ///
    /// 调用方拿到密钥库后可以用 [`DeviceKeyStore::backend`] 查出实际用的是哪种。
    /// 一个「悄悄降级但不告诉你」的接口会让用户以为自己受 TPM 保护，而实际上私钥
    /// 只是一个软件文件——那正是本 crate 最想避免的误解。
    ///
    /// # 错误
    ///
    /// 连软件密钥库都打不开时返回错误——那种情况下系统本身有问题。
    pub fn open_best_available() -> Result<Self> {
        match Self::open(WindowsProvider::Tpm) {
            Ok(store) => Ok(store),
            Err(tpm_error) => Self::open(WindowsProvider::Software).map_err(|software_error| {
                KeyStoreError::HardwareUnavailable {
                    reason: format!(
                        "TPM 与软件密钥库都不可用（TPM: {tpm_error}；软件: {software_error}）"
                    ),
                }
            }),
        }
    }
}

impl DeviceKeyStore for WindowsKeyStore {
    fn backend(&self) -> Backend {
        self.backend
    }

    fn open(&self, label: &str) -> Result<Box<dyn DeviceSigner>> {
        let name = key_name(label)?;
        let key = open_key(&self.provider, &name)?.ok_or_else(|| KeyStoreError::KeyNotFound {
            label: label.to_string(),
        })?;
        Ok(Box::new(WindowsSigner::new(key, label, self.backend)?))
    }

    fn create(&self, label: &str) -> Result<Box<dyn DeviceSigner>> {
        let name = key_name(label)?;
        // 已存在时**不**覆盖：覆盖会悄悄换掉设备身份，而设备身份是别的设备用来
        // 认你的依据。那种 bug 在几天后才表现为「同步莫名失效」，几乎无法回溯。
        //
        // 怎么知道「已存在」：先打开看看。这也顺带把「本方法只在确实不存在时才
        // 创建」这件事写成了代码而不是注释。
        if open_key(&self.provider, &name)?.is_some() {
            return Err(KeyStoreError::KeyAlreadyExists {
                label: label.to_string(),
            });
        }
        let key = match create_key(&self.provider, &name)? {
            Some(key) => key,
            // 竞态：在我们「打开确认不存在」与「创建」之间，另一个进程抢先建好了。
            // 对 `create` 而言这仍然是「已存在」，如实报告。
            None => {
                return Err(KeyStoreError::KeyAlreadyExists {
                    label: label.to_string(),
                });
            }
        };
        Ok(Box::new(WindowsSigner::new(key, label, self.backend)?))
    }

    fn delete(&self, label: &str) -> Result<()> {
        let name = key_name(label)?;
        // 先确认存在，以便给出准确的 `KeyNotFound` 而不是静默成功。对「删一个不
        // 存在的东西」报错是有意义的：那通常意味着 label 拼错了。
        let Some(key) = open_key(&self.provider, &name)? else {
            return Err(KeyStoreError::KeyNotFound {
                label: label.to_string(),
            });
        };

        // SAFETY: `key` 持有有效句柄。`NCryptDeleteKey` 会**连同句柄一起释放**，
        // 因此之后不能再 free 它——让 `CngHandle::drop` 再释放一次就是重复释放。
        // 把 `raw` 置零后 drop 会因为 `raw != 0` 不成立而什么都不做。
        let status = unsafe { NCryptDeleteKey(key.raw, 0) };
        let mut key = key;
        key.raw = 0;
        if status < 0 {
            return Err(KeyStoreError::Hardware {
                operation: "NCryptDeleteKey",
                code: status,
            });
        }
        Ok(())
    }
}

/// 一份 Windows 设备身份：一个 CNG 密钥句柄加上它的公钥。
pub struct WindowsSigner {
    /// 密钥句柄。独占持有，drop 时释放。
    key: CngHandle,
    /// 逻辑名，用于错误消息。
    label: String,
    /// 后端种类。
    backend: Backend,
    /// 已导出的公钥，避免每次查询都调一次平台 API。
    public_key: DevicePublicKey,
}

impl fmt::Debug for WindowsSigner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // 只打印非秘密信息。刻意不派生 `Debug`：那会不加区分地打印句柄与标签。
        f.debug_struct("WindowsSigner")
            .field("label", &self.label)
            .field("backend", &self.backend)
            .field("device_id", &self.public_key.device_id())
            .finish_non_exhaustive()
    }
}

impl WindowsSigner {
    /// 从一个已打开的密钥句柄构造签名器，顺带导出公钥。
    fn new(key: CngHandle, label: &str, backend: Backend) -> Result<Self> {
        let public_key = export_public_key(&key)?;
        Ok(Self {
            key,
            label: label.to_string(),
            backend,
            public_key,
        })
    }
}

impl DeviceSigner for WindowsSigner {
    fn backend(&self) -> Backend {
        self.backend
    }

    fn public_key(&self) -> &DevicePublicKey {
        &self.public_key
    }

    fn sign_digest(&self, digest: &[u8]) -> Result<DeviceSignature> {
        sign_digest_raw(&self.key, digest)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 把 `NTE_*` 常量钉在 Windows SDK `winerror.h` 的值上。
    ///
    /// # 为什么这条测试必须存在
    ///
    /// 这些值只能手抄（`windows-sys` 没有导出），而抄错**不会**触发任何编译
    /// 错误：它只会让「密钥不存在」这条正常路径变成「硬件故障」，于是所有创建
    /// 密钥的代码都走不通。本模块的第一版实现就抄错了两个值，直到集成测试全部
    /// 失败才暴露。
    ///
    /// 有了这条测试，抄错的代价从「调试半小时」降到「一条测试红了」。
    #[test]
    fn nte_codes_match_winerror() {
        // 来源：Windows SDK 10.0.22621.0 的 um\winerror.h。
        assert_eq!(NTE_BAD_FLAGS, 0x8009_0009_u32 as i32, "NTE_BAD_FLAGS");
        assert_eq!(NTE_NO_KEY, 0x8009_000D_u32 as i32, "NTE_NO_KEY");
        assert_eq!(NTE_EXISTS, 0x8009_000F_u32 as i32, "NTE_EXISTS");
        assert_eq!(NTE_NOT_FOUND, 0x8009_0011_u32 as i32, "NTE_NOT_FOUND");
        assert_eq!(NTE_BAD_KEYSET, 0x8009_0016_u32 as i32, "NTE_BAD_KEYSET");
    }

    /// 「没有这个密钥」这一组里必须包含实测遇到的码。
    #[test]
    fn no_such_key_codes_are_recognized() {
        // 实测：在真机上 `NCryptOpenKey` 一个不存在的名字返回 0x80090016。
        assert!(means_no_such_key(0x8009_0016_u32 as i32), "NTE_BAD_KEYSET");
        assert!(means_no_such_key(0x8009_000D_u32 as i32), "NTE_NO_KEY");
        assert!(means_no_such_key(0x8009_0011_u32 as i32), "NTE_NOT_FOUND");
    }

    /// 其它失败**不得**被当成「密钥不存在」。
    ///
    /// 这条防的是相反方向的错误：把权限不足之类的真故障当成「不存在」，于是代码
    /// 默默去创建一个已经存在的密钥，最后报出一个与真实原因无关的错误。
    #[test]
    fn real_failures_are_not_mistaken_for_missing_keys() {
        for status in [
            0x8009_0009_u32 as i32, // NTE_BAD_FLAGS
            0x8009_0010_u32 as i32, // NTE_PERM
            0x8009_0026_u32 as i32, // NTE_INVALID_HANDLE
            0x8009_0029_u32 as i32, // NTE_NOT_SUPPORTED（实测：不支持的 scope 字符串）
            0x8007_0005_u32 as i32, // E_ACCESSDENIED
            0,                      // S_OK
        ] {
            assert!(
                !means_no_such_key(status),
                "0x{:08X} 被误判为「密钥不存在」",
                status as u32
            );
        }
    }

    /// 密钥名必须带前缀，且转换成 NUL 结尾的宽字符串。
    #[test]
    fn key_name_has_prefix_and_nul_terminator() {
        let wide = key_name("device").expect("合法标签");
        assert_eq!(wide.last(), Some(&0), "必须以 NUL 结尾");
        let text = String::from_utf16(&wide[..wide.len() - 1]).expect("合法 UTF-16");
        assert_eq!(text, "Qualia2FA-Device-device");
    }

    /// **空字符截断**：若允许 `\0` 进入标签，`"a\0b"` 与 `"a"` 会在 C 字符串看来
    /// 是同一个密钥名，于是两个不同的标签映射到同一份设备身份。
    #[test]
    fn label_with_nul_is_rejected() {
        assert!(key_name("a\0b").is_err());
        assert!(key_name("a\u{0}").is_err());
    }

    /// 路径与命名空间里有特殊含义的字符都要拒绝。
    #[test]
    fn label_with_special_characters_is_rejected() {
        for bad in [
            "a/b", "a\\b", "a b", "a:b", "a*b", "a?b", "a\"b", "a<b", "a|b", "设备", "a\nb", "a\tb",
        ] {
            assert!(key_name(bad).is_err(), "{bad:?} 不应被接受");
        }
    }

    /// 允许的字符集要刚好够用。
    #[test]
    fn label_with_allowed_characters_is_accepted() {
        for good in ["device", "Device-1", "a_b.c", "ABC123", "x"] {
            assert!(key_name(good).is_ok(), "{good:?} 应被接受");
        }
    }

    /// 空标签与超长标签都要拒绝。
    #[test]
    fn empty_and_oversized_labels_are_rejected() {
        assert!(key_name("").is_err());
        assert!(key_name(&"a".repeat(MAX_LABEL_LEN)).is_ok());
        assert!(key_name(&"a".repeat(MAX_LABEL_LEN + 1)).is_err());
    }

    /// 后端种类与提供程序名的对应关系。
    #[test]
    fn provider_maps_to_backend() {
        assert_eq!(WindowsProvider::Tpm.backend(), Backend::Tpm);
        assert_eq!(WindowsProvider::Software.backend(), Backend::Software);
        assert!(WindowsProvider::Tpm.backend().is_hardware_backed());
        assert!(!WindowsProvider::Software.backend().is_hardware_backed());
    }
}
