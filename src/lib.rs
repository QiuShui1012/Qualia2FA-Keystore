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

//! Qualia2FA 的平台硬件密钥库层。
//!
//! # 这个 crate 为什么存在
//!
//! `qualia2fa-core` 有 `#![forbid(unsafe_code)]`，而调用平台原生 API（Windows
//! CNG、Android Keystore、iOS Security framework）**必然**要 `unsafe`。本 crate
//! 就是那道边界：它是整个项目里**唯一**允许出现 `unsafe` 的地方，也是唯一接触
//! 平台原生 API 的地方。
//!
//! 它只做一件事，把三个动作封装成安全的 Rust 接口：
//!
//! 1. 在硬件里生成一个 ECDSA P-256 密钥（私钥永不导出）；
//! 2. 取回对应的公钥；
//! 3. 让硬件对一段消息签名。
//!
//! **不要**把协议逻辑、密码学原语或任何能用纯 Rust 表达的东西放进这里——那些
//! 属于 Core。放进来的东西就无法被 fuzz、无法在 CI 上跨平台跑，并且活在
//! `forbid(unsafe_code)` 的保护之外。
//!
//! # 为什么签名算法是 ECDSA P-256
//!
//! 见 `qualia2fa_core::device` 的模块文档：**P-256 是两个移动平台上唯一能进
//! 硬件的签名算法**，这是强约束而不是偏好。本 crate 的所有后端都必须支持它。
//!
//! # 各平台后端
//!
//! | 平台 | 后端 | 状态 |
//! |---|---|---|
//! | Windows | CNG `NCrypt*`，TPM 2.0（`MS_PLATFORM_CRYPTO_PROVIDER`）| 已实现 |
//! | Windows（无 TPM）| CNG 软件 KSP（`MS_KEY_STORAGE_PROVIDER`）| 已实现（降级）|
//! | macOS | Secure Enclave | 未实现 |
//! | Linux | TPM 2.0 | 未实现 |
//! | Android | Keystore / StrongBox | 未实现 |
//! | iOS | Secure Enclave | 未实现 |
//!
//! 未实现的平台**不会静默降级**：调用 [`Backend`] 得到的
//! [`Backend::Unavailable`] 会如实反映出来，而创建密钥返回
//! [`KeyStoreError::UnsupportedPlatform`]。静默降级到软件密钥是危险的——用户会
//! 以为自己的私钥在硬件里，而实际不是。
//!
//! # 本 crate 不做 I/O、不读时钟、不读环境变量
//!
//! 唯一的例外是 `cfg` 与平台 API 自身。硬件句柄由密钥库对象持有，随其 drop 释放。

#![warn(missing_docs)]
#![warn(clippy::missing_docs_in_private_items)]
// `unsafe` 只允许出现在平台后端里。顶层不开 `forbid(unsafe_code)`——平台 FFI
// 调用本质上就是 unsafe——但用 `deny(unsafe_op_in_unsafe_fn)` 强制每个 unsafe
// 操作都显式写在 `unsafe {}` 里，避免「整个函数是 unsafe 于是里面什么都敢写」。
#![deny(unsafe_op_in_unsafe_fn)]

mod error;
pub mod traits;

/// 平台后端。
///
/// 各平台后端放在这个独立模块里，而不是散在 crate 顶层：这样「平台相关代码的
/// 总量」在目录结构上一目可见，审阅 `unsafe` 时不需要在无关文件之间翻找。
///
/// 声明成 `pub mod platform;`（对应 `src/platform.rs` + `src/platform/` 目录）
/// 而不是在这里写内联的 `pub mod platform { ... }`：后者会与 `src/platform/`
/// 目录**同时**被当作同一个模块名，导致里面的子模块找不到，报的却是
/// 「could not find `windows` in `platform`」这种看不出真正原因的错。
pub mod platform;

#[cfg(any(test, feature = "mock"))]
mod mock;

pub use error::{KeyStoreError, Result};
pub use traits::{Backend, DeviceKeyStore, DeviceSigner};

#[cfg(any(test, feature = "mock"))]
pub use mock::MockKeyStore;

/// 本平台是否有可用的硬件密钥库后端实现。
///
/// 调用方（尤其是 UI）应当据此提示用户：没有硬件保护时，设备身份密钥会退化为
/// 软件持有，安全性下降。**本函数不探测硬件是否真的可用**（那需要真的打开一次
/// 密钥库），它回答的是「这个平台有没有实现」。
///
/// 想知道运行时真实情况，请用 [`DeviceKeyStore::backend`]。
#[must_use]
pub const fn platform_backend_is_implemented() -> bool {
    cfg!(target_os = "windows")
}
