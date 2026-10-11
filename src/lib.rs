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
//! 本 crate 把「在设备硬件里生成一个 ECDSA P-256 密钥、取回对应的公钥、让硬件对
//! 一段消息签名」封装成安全的 Rust 接口，让上层不必接触任何平台原生 API。
//!
//! # 这个 crate 为什么存在
//!
//! `qualia2fa-core` 有 `#![forbid(unsafe_code)]`，而调用平台原生 API（Windows
//! CNG、Android Keystore、iOS Security framework）**必然**要 `unsafe`。本 crate
//! 就是那道边界：它是整个项目里**唯一**允许出现 `unsafe` 的地方，也是唯一接触
//! 平台原生 API 的地方。
//!
//! 因此**不要**把协议逻辑、密码学原语或任何能用纯 Rust 表达的东西放进这里——
//! 那些属于 Core。放进来的东西就无法被 fuzz、无法在 CI 上跨平台跑，并且活在
//! `forbid(unsafe_code)` 的保护之外。
//!
//! # 为什么签名算法是 ECDSA P-256
//!
//! 这是**硬约束，不是偏好**：Android 的 KeyMint HAL 没有 EdDSA（`Algorithm.aidl`
//! 里只有 RSA / EC / AES / TRIPLE_DES / HMAC），而 Apple 的 Secure Enclave 只
//! 支持 NIST P-256。想在两个移动平台上都进硬件，P-256 是唯一选择。

#![warn(missing_docs)]
#![warn(clippy::missing_docs_in_private_items)]
// `unsafe` 只允许出现在平台后端里。顶层不开 `forbid(unsafe_code)`——平台 FFI
// 调用本质上就是 unsafe——但用 `deny(unsafe_op_in_unsafe_fn)` 强制每个 unsafe
// 操作都显式写在 `unsafe {}` 里，避免「整个函数是 unsafe 于是里面什么都敢写」。
#![deny(unsafe_op_in_unsafe_fn)]

/// 本平台是否有可用的硬件密钥库后端实现。
///
/// 调用方（尤其是 UI）应当据此提示用户：没有硬件保护时，设备身份密钥会退化为
/// 软件持有，安全性下降。
///
/// **本函数不探测硬件是否真的可用**（那需要真的打开一次密钥库），它回答的是
/// 「这个平台有没有实现」。
#[must_use]
pub const fn platform_backend_is_implemented() -> bool {
    cfg!(any(target_os = "windows"))
}
