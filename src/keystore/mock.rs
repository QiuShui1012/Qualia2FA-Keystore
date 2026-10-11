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

//! 纯软件的内存密钥库，**只用于测试**。
//!
//! # 它为什么必须存在
//!
//! 协议层（注册、登录、挑战-应答）的逻辑必须能在 **CI 上、没有 TPM 的机器上**
//! 被完整测试。若测试只能跑在有硬件的开发者机器上，那些最需要被反复验证的性质
//! （重放被拒绝、伪造公钥被拒绝、篡改被拒绝）就会长期缺乏覆盖。
//!
//! # 它为什么绝不能出现在生产路径上
//!
//! 它的「硬件」就是一个 `HashMap`，私钥是普通内存里的字节。用它做真实设备
//! 身份等于完全没有硬件保护，而且**看起来一切正常**——这是最危险的一类错误。
//!
//! 因此：
//!
//! - 本模块只在 `cfg(test)` 或显式开启 `mock` feature 时编译。
//! - 它报告的后端是 [`Backend::Software`] **且** [`MockKeyStore::backend`] 的
//!   文档反复强调它不是真实后端。
//! - 它**不**实现持久化：密钥只活在进程内。这让任何「忘了换掉 mock」的代码在
//!   重启后立刻暴露，而不是悄悄带着软件密钥一直跑下去。
//!
//! # 私钥的擦除
//!
//! 私钥用 `zeroize` 擦除。这与真实后端形成有趣对比：真实后端的私钥根本不在本
//! 进程里，所以那边没有任何需要擦除的东西。

use crate::device::{DevicePublicKey, DeviceSignature};
use crate::keystore::traits::{
    Backend, DIGEST_LEN, DeviceKeyStore, DeviceSigner, public_key_from_sec1,
};
use crate::{Error, Result};
use p256::ecdsa::{Signature, SigningKey, signature::hazmat::PrehashSigner};
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

/// 内存里的软件密钥库，**仅用于测试**。
///
/// 可以 `clone`，克隆出来的句柄**共享**同一份密钥存储——这模拟了真实密钥库
/// 「同一台机器上多次打开看到同一批密钥」的行为，让「关闭再打开后身份不变」这类
/// 性质可以被测到。
#[derive(Clone, Default)]
pub struct MockKeyStore {
    /// 逻辑名 → 私钥。用 `Arc<Mutex<_>>` 以便克隆共享。
    keys: Arc<Mutex<BTreeMap<String, SigningKey>>>,
}

impl core::fmt::Debug for MockKeyStore {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // **不打印私钥**，连长度都不打印。
        let count = self.keys.lock().map(|k| k.len()).unwrap_or(0);
        f.debug_struct("MockKeyStore")
            .field("key_count", &count)
            .finish_non_exhaustive()
    }
}

impl MockKeyStore {
    /// 建一个空的软件密钥库。
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

impl DeviceKeyStore for MockKeyStore {
    fn backend(&self) -> Backend {
        // 如实报告为软件。**不要**为了让测试「看起来像在测硬件」而返回 Tpm：
        // 那会让任何依赖 backend() 的分支在测试里走到与生产不同的路径上。
        Backend::Software
    }

    fn open(&self, label: &str) -> Result<Box<dyn DeviceSigner>> {
        let keys = self.keys.lock().map_err(|_| Error::Hardware {
            operation: "MockKeyStore 内部锁中毒",
            code: 0,
        })?;
        let signing = keys.get(label).ok_or_else(|| Error::KeyNotFound {
            label: label.to_string(),
        })?;

        // 复制一份标量出来，这样不持有锁也能签名。
        let bytes = signing.to_bytes();
        let owned = SigningKey::from_slice(&bytes).map_err(|_| Error::Hardware {
            operation: "MockKeyStore 私钥复制失败",
            code: 0,
        })?;
        drop(keys);

        Ok(Box::new(MockSigner::new(owned, label)))
    }

    fn create(&self, label: &str) -> Result<Box<dyn DeviceSigner>> {
        let mut keys = self.keys.lock().map_err(|_| Error::Hardware {
            operation: "MockKeyStore 内部锁中毒",
            code: 0,
        })?;
        if keys.contains_key(label) {
            // 与 Windows 后端保持一致：**绝不覆盖**已有身份。
            // 覆盖会悄悄换掉设备身份，是最难排查的一类 bug。
            return Err(Error::Hardware {
                operation: "MockKeyStore::create（同名密钥已存在，拒绝覆盖）",
                code: 0,
            });
        }
        // 用 OS CSPRNG 生成。`SigningKey::random` 需要 `rand_core` 的实现，
        // 这里改用 `getrandom` 直接取 32 字节再规约——避免为一处测试引入 rand 生态。
        let signing = SigningKey::from_slice(&random_scalar()?).map_err(|_| Error::Hardware {
            operation: "MockKeyStore 生成标量失败",
            code: 0,
        })?;
        let public = public_key_from_signing(&signing)?;
        keys.insert(label.to_string(), signing);
        drop(keys);

        // 与 Windows 后端一样，返回一个「打开」出来的签名器。
        let _ = public;
        self.open(label)
    }

    fn delete(&self, label: &str) -> Result<()> {
        let mut keys = self.keys.lock().map_err(|_| Error::Hardware {
            operation: "MockKeyStore 内部锁中毒",
            code: 0,
        })?;
        if keys.remove(label).is_none() {
            return Err(Error::KeyNotFound {
                label: label.to_string(),
            });
        }
        Ok(())
    }
}

/// 取 32 字节 OS 随机数作为私钥标量。
///
/// `p256` 的 `from_slice` 会拒绝零与超出群阶的值；那种概率约 2^-128，但仍要
/// 处理而不是 panic。
fn random_scalar() -> Result<[u8; 32]> {
    let mut bytes = [0_u8; 32];
    getrandom::fill(&mut bytes).map_err(|_| Error::Hardware {
        operation: "MockKeyStore 无法从 OS 取得随机数",
        code: 0,
    })?;
    Ok(bytes)
}

/// 从软件私钥导出 SEC1 未压缩公钥。
fn public_key_from_signing(signing: &SigningKey) -> Result<DevicePublicKey> {
    let sec1 = signing.verifying_key().to_sec1_point(false);
    public_key_from_sec1(sec1.as_bytes())
}

/// 软件签名器。
pub struct MockSigner {
    /// 软件私钥。**只存在于本结构内**，drop 时由 `zeroize` 擦除。
    signing: SigningKey,
    /// 逻辑名。
    label: String,
    /// 已导出的公钥。
    public_key: DevicePublicKey,
}

impl core::fmt::Debug for MockSigner {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // **绝不打印私钥**。
        f.debug_struct("MockSigner")
            .field("label", &self.label)
            .field("device_id", &self.public_key.device_id())
            .finish_non_exhaustive()
    }
}

impl MockSigner {
    /// 用一把软件私钥构造签名器。
    fn new(signing: SigningKey, label: &str) -> Self {
        let public_key = public_key_from_signing(&signing).unwrap_or_else(|_| {
            // 我们自己生成的密钥不可能是非法点。若真发生了，说明 `p256` 与我们的
            // 假设不一致——但库内不得 panic，所以退化成一个可辨认的占位实现。
            // 实际上这条分支不可达；写成这样是为了满足「不 panic」的约束。
            unreachable_public_key()
        });
        Self {
            signing,
            label: label.to_string(),
            public_key,
        }
    }
}

/// 「不可达」路径的占位公钥。
///
/// 用一个固定的、**确定不在 P-256 上**的点是不可能的（那正是 `from_sec1_bytes`
/// 会拒绝的）。所以这里返回一个固定的合法点：生成元 `G` 的 SEC1 编码。它是合法
/// 公钥，只是不对应我们的私钥——若真走到这里，签名会验不过，问题会立刻暴露，
/// 而不是被掩盖。
fn unreachable_public_key() -> DevicePublicKey {
    // P-256 生成元的 SEC1 未压缩编码（FIPS 186-4 / SEC 2 标准值）。
    const GENERATOR: [u8; 65] = [
        0x04, 0x6B, 0x17, 0xD1, 0xF2, 0xE1, 0x2C, 0x42, 0x47, 0xF8, 0xBC, 0xE6, 0xE5, 0x63, 0xA4,
        0x40, 0xF2, 0x77, 0x03, 0x7D, 0x81, 0x2D, 0xEB, 0x33, 0xA0, 0xF4, 0xA1, 0x39, 0x45, 0xD8,
        0x98, 0xC2, 0x96, 0x4F, 0xE3, 0x42, 0xE2, 0xFE, 0x1A, 0x7F, 0x9B, 0x8E, 0xE7, 0xEB, 0x4A,
        0x7C, 0x0F, 0x9E, 0x16, 0x2B, 0xCE, 0x33, 0x57, 0x6B, 0x31, 0x5E, 0xCE, 0xCB, 0xB6, 0x40,
        0x68, 0x37, 0xBF, 0x51, 0xF5,
    ];
    public_key_from_sec1(&GENERATOR).unwrap_or_else(|_| {
        // 连标准生成元都解析不了的话，`p256` 本身坏了。仍然不能 panic。
        // 用一个自造的、必然合法的点：X=1 不行（不在曲线上），所以这里只能
        // 再次依赖生成元。真到这一步，下面的 `expect` 会在测试里立刻暴露。
        unreachable!("P-256 生成元无法解析，p256 实现已损坏")
    })
}

impl DeviceSigner for MockSigner {
    fn backend(&self) -> Backend {
        Backend::Software
    }

    fn public_key(&self) -> &DevicePublicKey {
        &self.public_key
    }

    fn sign_digest(&self, digest: &[u8]) -> Result<DeviceSignature> {
        if digest.len() != DIGEST_LEN {
            return Err(Error::InvalidDigestLength {
                expected: DIGEST_LEN,
                actual: digest.len(),
            });
        }
        // 用预哈希签名接口，与硬件后端的行为对齐：硬件收到的也是摘要。
        let signature: Signature =
            self.signing
                .sign_prehash(digest)
                .map_err(|_| Error::Hardware {
                    operation: "MockKeyStore 签名失败",
                    code: 0,
                })?;
        crate::keystore::traits::signature_from_raw(&signature.to_bytes())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::device;

    /// 建了就能打开，且公钥一致。
    #[test]
    fn create_then_open_yields_same_identity() {
        let store = MockKeyStore::new();
        let created = store.create("device").expect("创建");
        let id_created = created.public_key().device_id();

        let opened = store.open("device").expect("打开");
        assert_eq!(opened.public_key().device_id(), id_created);
    }

    /// 打开不存在的密钥必须报 KeyNotFound，而**不是**顺手创建。
    ///
    /// 「没有创建」这一半靠**再打开一次仍然失败**来验证：如果第一次 `open`
    /// 顺手建了一个，第二次就会成功。
    #[test]
    fn open_missing_key_does_not_create() {
        let store = MockKeyStore::new();
        let error = store.open("nope").expect_err("应失败");
        assert!(matches!(error, Error::KeyNotFound { .. }));
        assert!(
            store.open("nope").is_err(),
            "第一次 open 竟然创建了密钥——open 必须只读"
        );
    }

    /// 重复创建必须被拒绝，且**不改变**已有身份。
    #[test]
    fn create_existing_key_is_rejected_and_does_not_replace() {
        let store = MockKeyStore::new();
        let first = store.create("device").expect("首次创建");
        let id_first = first.public_key().device_id();

        assert!(store.create("device").is_err(), "重复创建应被拒绝");

        let again = store.open("device").expect("打开");
        assert_eq!(
            again.public_key().device_id(),
            id_first,
            "拒绝重复创建的同时必须保留原身份"
        );
    }

    /// `open_or_create` 在两种情况下都工作。
    #[test]
    fn open_or_create_works_both_ways() {
        let store = MockKeyStore::new();
        let a = store.open_or_create("device").expect("首次");
        let b = store.open_or_create("device").expect("再次");
        assert_eq!(a.public_key().device_id(), b.public_key().device_id());
    }

    /// 克隆共享同一份存储（模拟同一台机器上的多次打开）。
    #[test]
    fn clone_shares_storage() {
        let store = MockKeyStore::new();
        let id = store
            .create("device")
            .expect("创建")
            .public_key()
            .device_id();
        let other = store.clone();
        assert_eq!(
            other.open("device").expect("打开").public_key().device_id(),
            id
        );
    }

    /// 软件签名的结果必须能被 Core 的验签函数接受。
    #[test]
    fn software_signature_verifies_with_core() {
        let store = MockKeyStore::new();
        let signer = store.create("device").expect("创建");
        let message = b"\x07pairing message";
        let signature = signer.sign(message).expect("签名");
        assert!(
            device::verify(signer.public_key(), message, &signature).is_ok(),
            "Core 必须接受软件后端的签名"
        );
    }

    /// 摘要长度不对必须报错。
    #[test]
    fn wrong_digest_length_is_rejected() {
        let store = MockKeyStore::new();
        let signer = store.create("device").expect("创建");
        assert!(matches!(
            signer.sign_digest(&[0_u8; 20]),
            Err(Error::InvalidDigestLength { .. })
        ));
    }

    /// 删除之后打开必须失败，列表里也不再有它。
    #[test]
    fn delete_removes_identity() {
        let store = MockKeyStore::new();
        store.create("device").expect("创建");
        assert!(store.open("device").is_ok());

        store.delete("device").expect("删除");
        assert!(store.open("device").is_err(), "删除后不应还能打开");
        // 重复删除报 KeyNotFound。
        assert!(matches!(
            store.delete("device"),
            Err(Error::KeyNotFound { .. })
        ));
    }

    /// 两个不同的 label 必须是两份独立身份。
    #[test]
    fn distinct_labels_are_distinct_identities() {
        let store = MockKeyStore::new();
        let a = store.create("account-a").expect("创建 a");
        let b = store.create("account-b").expect("创建 b");
        assert_ne!(a.public_key().device_id(), b.public_key().device_id());
    }

    /// `backend()` 必须如实报告软件，不能伪装成硬件。
    #[test]
    fn mock_reports_software_backend() {
        let store = MockKeyStore::new();
        assert_eq!(store.backend(), Backend::Software);
        assert!(!store.backend().is_hardware_backed());
        let signer = store.create("device").expect("创建");
        assert_eq!(signer.backend(), Backend::Software);
    }
}
