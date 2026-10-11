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

//! Device identity kit：设备身份的**公钥侧**，加上调用平台原生密钥库的**私钥侧**。
//!
//! # 这个 crate 为什么存在
//!
//! 两件事各自需要它：
//!
//! 1. **调用平台原生 API 必然要 `unsafe`**（Windows CNG、Android Keystore、iOS
//!    Security framework）。这个 crate 是那道边界：整个项目里**唯一**允许出现
//!    `unsafe` 的地方，也是唯一接触平台原生 API 的地方。
//! 2. **设备身份必须能在两个方向上被独立使用**：一台设备要能验证**别人**的签名，
//!    而它自己可能根本不持有任何硬件密钥（桌面端没有 TPM 的机器就是这样）。把
//!    「表示与验签」和「生成与签名」放进同一个 crate，才能让「公钥类型在哪」与
//!    「谁来生成它」是同一个答案。
//!
//! 因此本 crate 分成两半：
//!
//! | 模块 | 做什么 | 持私钥吗 |
//! |------|--------|----------|
//! | [`device`] | 公钥表示、指纹（[`DeviceId`]）、验签 | 否 |
//! | [`keystore`] | 生成密钥、取公钥、对消息签名 | 是（在硬件里） |
//!
//! 两半共用同一个错误类型 [`Error`]，因为调用方看到的是一次「设备身份操作」的失败，
//! 而不是两个子系统的失败。
//!
//! # 它为什么**不依赖** Core
//!
//! 这是一个可独立复用的库：任何需要「平台硬件里的一对 P-256 身份密钥」的项目都能
//! 用它，不需要接受 Qualia2FA 的保险库格式、同步协议或任何别的东西。因此它**不**
//! 依赖下游，而是下游依赖它。放进来的东西必须对得起这个约束——协议逻辑、密码学
//! 原语、任何能用纯 Rust 实现且与设备身份无关的东西都属于下游。
//!
//! # 为什么签名算法是 ECDSA P-256
//!
//! 这是一个**强约束，不是偏好**，因为私钥要放进平台硬件：
//!
//! - **Android**：KeyMint HAL 的 `Algorithm.aidl` 里只有 `RSA=1, EC=3, AES=32,
//!   TRIPLE_DES=33, HMAC=128`——**没有 EdDSA**。注意 `CURVE_25519` 确实存在，但它是
//!   **XDH 密钥协商曲线，不是签名算法**——这是二手资料里最常见的错误。
//! - **iOS**：Apple 文档明确写着 Secure Enclave 只用 NIST P-256。
//!
//! 选 Ed25519 就等于接受「移动端身份密钥只能软件持有」——那必须是一个显式决定，
//! 不能是事故。
//!
//! # 各平台后端
//!
//! | 平台 | 后端 | 状态 |
//! |---|---|---|
//! | Windows | CNG `NCrypt*`，TPM 2.0（`MS_PLATFORM_CRYPTO_PROVIDER`）| 已实现 |
//! | Windows（无 TPM）| CNG 软件 KSP（`MS_KEY_STORAGE_PROVIDER`）| 已实现（降级）|
//! | macOS | Secure Enclave | 未实现（占位后端）|
//! | Linux | TPM 2.0 | 未实现（占位后端）|
//! | Android | Keystore / StrongBox | 未实现（占位后端）|
//! | iOS | Secure Enclave | 未实现（占位后端）|
//!
//! 未实现的平台**不会静默降级**：调用 [`keystore::DeviceKeyStore::backend`] 得到的
//! [`keystore::Backend::Unavailable`] 会如实反映出来，而创建密钥返回
//! [`Error::UnsupportedPlatform`]。静默降级到软件密钥是危险的——用户会以为自己的
//! 私钥在硬件里，而实际不是。
//!
//! 「未实现」与「硬件不存在」是**两件不同的事**，因此用两个不同的值表达：前者是
//! [`keystore::Backend::Unavailable`]（本平台还没有后端），后者是
//! [`keystore::Backend::Software`]（有后端，但这台机器没有硬件）。合并它们会让
//! 「换个平台就能用」与「换台机器就能用」在调用方看来一样。
//!
//! # 本 crate 不做 I/O、不读时钟、不读环境变量
//!
//! 唯一的例外是 `cfg` 与平台 API 自身。硬件句柄由密钥库对象持有，随其 drop 释放。
//!
//! # 示例
//!
//! 用内存后端跑一遍「生成 → 取公钥 → 签名 → 验签」：
//!
//! ```
//! # #[cfg(feature = "mock")]
//! # fn demo() -> Result<(), qualia_dik::Error> {
//! use qualia_dik::{DeviceKeyStore, device};
//! # use qualia_dik::MockKeyStore;
//!
//! let store = MockKeyStore::new();
//! let signer = store.create("my-device")?;
//!
//! // 公钥不是秘密，可以随意传播。
//! println!("设备 ID：{}", signer.public_key().device_id());
//!
//! let message = b"a message to sign";
//! let signature = signer.sign(message)?;
//!
//! // 验签**不需要**密钥库，也不需要私钥——这是「公钥侧」独立存在的理由。
//! device::verify(signer.public_key(), message, &signature)?;
//! # Ok(())
//! # }
//! ```
//!
//! `MockKeyStore` 只在 `mock` feature 下存在——它在生产构建里是一条**不该有的**
//! 「没有硬件保护」的路径，因此默认关闭。想在本地跑这段示例：
//!
//! ```console
//! cargo test --doc --features mock
//! ```
//!
//! 没有开启该 feature 时 `cargo test --doc` 照样通过（整段被 `cfg` 掉），因此
//! CI 不需要为它单独配一次运行。
//!
//! 要在**不开启** `mock` 的情况下拿到本平台的真实后端，用
//! [`keystore::PlatformKeyStore`]。

#![warn(missing_docs)]
#![warn(clippy::missing_docs_in_private_items)]
// `unsafe` 只允许出现在平台后端里。顶层不开 `forbid(unsafe_code)`——平台 FFI
// 调用本质上就是 unsafe——但用 `deny(unsafe_op_in_unsafe_fn)` 强制每个 unsafe
// 操作都显式写在 `unsafe {}` 里，避免「整个函数是 unsafe 于是里面什么都敢写」。
#![deny(unsafe_op_in_unsafe_fn)]

pub mod device;
mod error;
pub mod keystore;

pub use device::{DEVICE_ID_LEN, DeviceId, DevicePublicKey, DeviceSignature};
pub use error::{Error, Result};

pub use keystore::{Backend, DeviceKeyStore, DeviceSigner, KeyStoreError};

#[cfg(any(test, feature = "mock"))]
pub use keystore::MockKeyStore;

/// 本平台是否有可用的硬件密钥库后端实现。
///
/// 调用方（尤其是 UI）应当据此提示用户：没有硬件保护时，设备身份密钥会退化为
/// 软件持有，安全性下降。**本函数不探测硬件是否真的可用**（那需要真的打开一次
/// 密钥库），它回答的是「这个平台有没有实现」。
///
/// 想知道运行时真实情况，请用 [`DeviceKeyStore::backend`]。
///
/// 目前只有 Windows 返回 `true`。未实现的平台上本函数返回 `false`，此时
/// [`keystore::PlatformKeyStore`] 的每个操作都会返回 [`Error::UnsupportedPlatform`]
/// ——**不会**降级为软件密钥。
#[must_use]
pub const fn platform_backend_is_implemented() -> bool {
    cfg!(target_os = "windows")
}
