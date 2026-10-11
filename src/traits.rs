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

//! 硬件密钥库的抽象接口。
//!
//! # 为什么抽象层放在这个 crate，而不是 Core
//!
//! 把 trait 放在 Core 有两点坏处：
//!
//! 1. Core 会因此在概念上知道「平台」的存在，而它的价值恰恰在于**完全不知道**
//!    自己跑在什么上面。
//! 2. 平台后端要依赖 Core 的类型（`DevicePublicKey` 等），Core 又要定义被平台
//!    后端实现的 trait，形成概念上的双向依赖。
//!
//! 所以：**Core 拥有数据类型与验签**（那是纯逻辑），**本 crate 拥有 trait 与
//! 实现**（那是平台相关）。方向是单向的：keystore → core。

use crate::error::{KeyStoreError, Result};
use qualia2fa_core::device::{PUBLIC_KEY_LEN, SIGNATURE_LEN};
use qualia2fa_core::{DevicePublicKey, DeviceSignature};

/// P-256 的摘要长度（SHA-256）。
///
/// 硬件签名接口（Windows CNG 的 `NCryptSignHash`、Android 的
/// `Signature.update`）都接受**摘要**而不是消息。ECDSA 对 P-256 的标准配对哈希
/// 就是 SHA-256，所以这个长度是曲线的属性，不是可配置项。
pub const DIGEST_LEN: usize = 32;

/// 设备身份密钥所在的后端种类。
///
/// 这个值会被记进保险库并影响 UI 提示，所以要**稳定**：新增变体只能追加，不要
/// 改变已有变体的含义。
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum Backend {
    /// 私钥在 TPM 2.0 内，无法导出。
    Tpm,
    /// 私钥在 macOS Secure Enclave 内，无法导出。
    SecureEnclave,
    /// 私钥在 Android Keystore / StrongBox 内，无法导出。
    AndroidKeystore,
    /// 私钥由操作系统软件密钥库保护（例如 Windows 软件 KSP）。
    ///
    /// **私钥存在于软件中**，虽然通常仍受操作系统用户账户与 DPAPI 保护，但这
    /// 不等于硬件保护：拥有管理员权限或能读取磁盘的攻击者可以把它取走。UI 应当
    /// 在关键操作前如实告知用户。
    Software,
    /// 没有可用的后端。这个平台上要么没实现，要么硬件用不了。
    Unavailable,
}

impl Backend {
    /// 私钥是否真的住在硬件里。
    ///
    /// # 为什么这个方法值得存在
    ///
    /// 「密钥存在系统密钥库里」和「私钥无法离开硬件」是**两件不同的事**，而在
    /// 用户看来它们长得一样。把区别做成一个显式的方法，让调用方必须主动声明
    /// 自己要哪一种。
    #[must_use]
    pub const fn is_hardware_backed(self) -> bool {
        matches!(
            self,
            Self::Tpm | Self::SecureEnclave | Self::AndroidKeystore
        )
    }

    /// 适合放进 UI 或日志的稳定短名。
    ///
    /// 与 `Debug` 的区别：`Debug` 是实现细节，可以随重构变化；这个名字一旦用于
    /// 持久化（例如写进保险库的元数据）就不能再改。
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Tpm => "tpm",
            Self::SecureEnclave => "secure-enclave",
            Self::AndroidKeystore => "android-keystore",
            Self::Software => "software",
            Self::Unavailable => "unavailable",
        }
    }
}

/// 能对一段消息签名、并给出对应公钥的设备身份签名器。
///
/// # 为什么 trait 里没有「导出私钥」
///
/// 因为**那正是这个 trait 存在的意义**。私钥不可导出是硬件密钥库唯一的、也是最
/// 重要的安全属性；一个能导出私钥的实现不满足这个接口的语义。若将来某个平台
/// 真的需要导出（例如换成软件密钥），那必须是一个**不同的**类型，让调用方在
/// 类型层面就看得见自己失去的东西。
///
/// # 为什么要求 `Debug`
///
/// 一是诊断需要：出问题时能打印出「这是哪个后端、哪份身份」很关键。二是
/// 可用性：没有它，`Result<Box<dyn DeviceSigner>, _>` 上的 `expect_err` 之类方法
/// 无法使用，调用方会被迫写更啰嗦的代码，于是更少写测试。
///
/// 各实现必须**自己**实现 `Debug` 而不是派生，因为内部可能持有平台句柄或私钥——
/// 派生会不加区分地打印它们。本 crate 的所有实现都把输出限制在「后端种类 +
/// 设备 ID」这类非秘密信息上。
///
/// # 为什么签名与公钥查询要分开
///
/// 公钥查询是纯读取，可能在锁屏状态下也能做；签名可能触发用户在场验证
/// （Touch ID / Windows Hello）。把它们混在一个方法里，会让「只想读一下公钥」
/// 也弹出认证框。
pub trait DeviceSigner: core::fmt::Debug {
    /// 这份身份所在的后端。
    fn backend(&self) -> Backend;

    /// 这份身份的 SEC1 未压缩公钥（65 字节）。
    ///
    /// 公钥不是秘密，可以自由传播、比较、写进日志。
    fn public_key(&self) -> &DevicePublicKey;

    /// 对一条消息签名，返回原始 `r||s`。
    ///
    /// # 签名的是消息，不是摘要
    ///
    /// 实现内部先做一次 SHA-256 再交给硬件，与
    /// [`qualia2fa_core::device::verify`] 的约定一致——「谁负责哈希」这件事必须
    /// 只有一种答案，否则验证会以「签名随机验不过」的形式失败。
    ///
    /// # 错误
    ///
    /// 硬件拒绝（例如用户取消了生物认证）、密钥被删除、后端不可用等。
    fn sign(&self, message: &[u8]) -> Result<DeviceSignature> {
        let digest = sha256(message);
        self.sign_digest(&digest)
    }

    /// 对一段**已算好的** SHA-256 摘要签名，返回原始 `r||s`。
    ///
    /// # 什么时候该用这个而不是 [`DeviceSigner::sign`]
    ///
    /// 当待签内容的哈希**已经在别处算过**、再算一遍纯属浪费时。例如一个已经带
    /// 着摘要的协议消息。绝大多数调用方应该用 [`DeviceSigner::sign`]。
    ///
    /// # 错误
    ///
    /// 摘要长度不是 [`DIGEST_LEN`] 时返回
    /// [`KeyStoreError::InvalidDigestLength`]。
    fn sign_digest(&self, digest: &[u8]) -> Result<DeviceSignature>;
}

/// 一份设备身份密钥对的持有者：能创建、打开、删除它。
///
/// 与 [`DeviceSigner`] 分开的理由是生命周期不同：签名器代表「这一份身份」，而
/// 密钥库代表「这台机器上所有身份」。UI 通常只需要前者。
pub trait DeviceKeyStore: core::fmt::Debug {
    /// 这份密钥库实际使用的后端。
    ///
    /// 这是**运行时**探测的结果，可能比编译期能力更弱：一台没有 TPM 的 Windows
    /// 机器上会返回 [`Backend::Software`]；尚未实现的平台返回
    /// [`Backend::Unavailable`]。
    fn backend(&self) -> Backend;

    /// 用 `label` 打开已有的设备身份。
    ///
    /// 每个 `label` 对应一份独立的身份（例如不同账号用不同身份）。
    ///
    /// # 错误
    ///
    /// 该 `label` 不存在时返回 [`KeyStoreError::KeyNotFound`]。**本方法不会创建
    /// 密钥**——创建与打开是两件事，混在一起的接口会让「我以为只是读一下」变成
    /// 悄悄生成了新身份。
    fn open(&self, label: &str) -> Result<Box<dyn DeviceSigner>>;

    /// 用 `label` 创建设备身份。
    ///
    /// # 错误
    ///
    /// `label` 已存在时返回 [`KeyStoreError::KeyNotFound`] 的对应变体
    /// （具体见各后端）。需要「有则打开、无则创建」时请用
    /// [`DeviceKeyStore::open_or_create`]。
    fn create(&self, label: &str) -> Result<Box<dyn DeviceSigner>>;

    /// 删除 `label` 对应的身份。
    ///
    /// # 警告
    ///
    /// 这会让该设备**永久无法再证明自己是原来的那台设备**。对方设备上记录的身份
    /// 会变成无法验证的孤儿，需要重新配对。调用方必须先取得用户确认。
    ///
    /// # 错误
    ///
    /// `label` 不存在时返回 [`KeyStoreError::KeyNotFound`]。
    fn delete(&self, label: &str) -> Result<()>;

    /// 打开 `label`；不存在则创建。
    ///
    /// # 为什么这是默认方法而不是要求各后端各写一遍
    ///
    /// 「先开、失败再建」这个顺序里有一个**必须处理对**的竞态：在两个步骤之间，
    /// 另一个进程可能刚好创建了同一个 `label`。此时创建会失败，而正确的反应是
    /// **回头再打开一次**，不是把失败抛给用户。这个逻辑与平台无关，写在默认实现
    /// 里，各后端就不会各漏一次。
    fn open_or_create(&self, label: &str) -> Result<Box<dyn DeviceSigner>> {
        match self.open(label) {
            Ok(signer) => Ok(signer),
            Err(KeyStoreError::KeyNotFound { .. }) => match self.create(label) {
                Ok(signer) => Ok(signer),
                // 竞态：另一个进程在 open 与 create 之间抢先建好了。对
                // `open_or_create` 而言这**正是想要的结果**，不是错误——回头打开
                // 它即可。这也是 `create` 必须把「已存在」与其它失败区分开来的
                // 原因：若它混在 `Hardware { .. }` 里，这里就只能笼统地失败。
                Err(KeyStoreError::KeyAlreadyExists { .. }) => self.open(label),
                Err(other) => Err(other),
            },
            Err(other) => Err(other),
        }
    }
}

/// 计算 SHA-256 摘要。
///
/// 独立成一个函数，是为了让「消息模式的哈希算法」只有一处定义——签名侧与验签侧
/// 必须用同一个，而两处各写一遍正是最容易漂移的地方。
#[must_use]
pub fn sha256(message: &[u8]) -> [u8; DIGEST_LEN] {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(message);
    let mut out = [0_u8; DIGEST_LEN];
    out.copy_from_slice(&digest);
    out
}

/// 把硬件给出的原始 `r||s` 字节转成 [`DeviceSignature`]。
///
/// 长度不对时给出**明确的**错误，而不是截断或填充——硬件返回错误长度的签名说明
/// 后端写错了，掩盖它只会让问题在后面以更难懂的形式出现。
///
/// 只在后端被编译时才有用（各后端目前都由 `cfg` 收窄），因此跟着一起收窄：
/// 否则纯库构建会报「函数从未被使用」。
#[cfg(any(test, feature = "mock", target_os = "windows"))]
pub(crate) fn signature_from_raw(raw: &[u8]) -> Result<DeviceSignature> {
    if raw.len() != SIGNATURE_LEN {
        return Err(KeyStoreError::InvalidSignatureLength {
            expected: SIGNATURE_LEN,
            actual: raw.len(),
        });
    }
    DeviceSignature::from_bytes(raw).map_err(|source| KeyStoreError::Core { source })
}

/// 把硬件给出的 SEC1 未压缩点转成 [`DevicePublicKey`]。
///
/// 收窄理由同 [`signature_from_raw`]。
#[cfg(any(test, feature = "mock", target_os = "windows"))]
pub(crate) fn public_key_from_sec1(bytes: &[u8]) -> Result<DevicePublicKey> {
    if bytes.len() != PUBLIC_KEY_LEN {
        return Err(KeyStoreError::InvalidPublicKey {
            reason: "长度不是 65 字节的 SEC1 未压缩点",
        });
    }
    DevicePublicKey::from_sec1_bytes(bytes).map_err(|source| KeyStoreError::Core { source })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 只有真正硬件持有的后端才算 hardware-backed。
    #[test]
    fn hardware_backed_classification() {
        assert!(Backend::Tpm.is_hardware_backed());
        assert!(Backend::SecureEnclave.is_hardware_backed());
        assert!(Backend::AndroidKeystore.is_hardware_backed());
        assert!(!Backend::Software.is_hardware_backed());
        assert!(!Backend::Unavailable.is_hardware_backed());
    }

    /// 持久化名必须稳定且互不相同——它们可能被写进保险库元数据。
    #[test]
    fn backend_names_are_stable_and_unique() {
        let all = [
            Backend::Tpm,
            Backend::SecureEnclave,
            Backend::AndroidKeystore,
            Backend::Software,
            Backend::Unavailable,
        ];
        let mut names: Vec<&str> = all.iter().map(|b| b.as_str()).collect();
        names.sort_unstable();
        let before = names.len();
        names.dedup();
        assert_eq!(names.len(), before, "后端名有重复");
        for name in names {
            assert!(!name.is_empty());
            assert!(
                name.chars().all(|c| c.is_ascii_lowercase() || c == '-'),
                "{name} 不是适合持久化的小写形式"
            );
        }
    }

    /// `sha256` 必须与已知向量一致（空串的 SHA-256）。
    #[test]
    fn sha256_matches_known_vector() {
        let digest = sha256(b"");
        let expected = [
            0xE3, 0xB0, 0xC4, 0x42, 0x98, 0xFC, 0x1C, 0x14, 0x9A, 0xFB, 0xF4, 0xC8, 0x99, 0x6F,
            0xB9, 0x24, 0x27, 0xAE, 0x41, 0xE4, 0x64, 0x9B, 0x93, 0x4C, 0xA4, 0x95, 0x99, 0x1B,
            0x78, 0x52, 0xB8, 0x55,
        ];
        assert_eq!(digest, expected);
    }

    /// 摘要长度不符时必须报错，且不得截断或填充。
    #[test]
    fn signature_from_raw_rejects_wrong_length() {
        assert!(signature_from_raw(&[]).is_err());
        assert!(signature_from_raw(&[0_u8; SIGNATURE_LEN - 1]).is_err());
        assert!(signature_from_raw(&[0_u8; SIGNATURE_LEN + 1]).is_err());
        assert!(signature_from_raw(&[0_u8; SIGNATURE_LEN]).is_ok());
    }

    /// 公钥长度不符时必须报错。
    #[test]
    fn public_key_from_sec1_rejects_wrong_length() {
        assert!(public_key_from_sec1(&[]).is_err());
        assert!(public_key_from_sec1(&[0x04; PUBLIC_KEY_LEN - 1]).is_err());
        assert!(public_key_from_sec1(&[0x04; PUBLIC_KEY_LEN + 1]).is_err());
    }
}
