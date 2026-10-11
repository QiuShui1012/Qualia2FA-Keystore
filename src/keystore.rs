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

//! 平台密钥库：在硬件里生成 P-256 密钥、取公钥、对消息签名。
//!
//! # 它只做三件事
//!
//! 1. 在硬件里生成一个 ECDSA P-256 密钥（私钥永不导出）；
//! 2. 取回对应的公钥；
//! 3. 让硬件对一段**消息**签名。
//!
//! **不要**把协议逻辑、密码学原语或任何能用纯 Rust 表达的东西放进这里。放进来的
//! 东西就无法被 fuzz、无法在 CI 上跨平台跑，并且活在 `forbid(unsafe_code)` 的保护
//! 之外。
//!
//! # 为什么签名收的是「消息」而不是「摘要」
//!
//! 平台硬件只接受摘要（Windows CNG 的 `NCryptSignHash` 形参就叫 `pbHashValue`），
//! 所以中间必然有一次 SHA-256。那次哈希**由本模块完成**，调用方传原始消息即可——
//! 让调用方自己哈希会把「谁负责哈希」变成两个调用点之间的约定，而那种约定写错的
//! 表现是「签名随机地验不过」。
//!
//! 验签侧（[`crate::device::verify`]）遵循同一约定：它也接收消息并自己哈希。两侧
//! 因此不可能不一致。

use crate::{Error, Result};

pub mod platform;

mod traits;

#[cfg(any(test, feature = "mock"))]
mod mock;

pub use traits::{Backend, DIGEST_LEN, DeviceKeyStore, DeviceSigner, sha256};

/// 本平台的密钥库实现，编译期选定。
///
/// # 为什么需要它
///
/// 没有它，调用方就得自己写一串 `#[cfg(target_os = "windows")] use …windows::WindowsKeyStore`
/// 与 `#[cfg(not(…))] use …platform_stub::StubKeyStore`——而那正是「上层代码为平台写
/// 分支」这件要避免的事。有了它，调用方只写一次 `PlatformKeyStore::open_best_available()`。
///
/// 未实现的平台上它是占位后端，每个操作都返回
/// [`Error::UnsupportedPlatform`]——**不会**降级为软件密钥。
///
/// # 两个后端的构造函数签名**故意**不同
///
/// | 后端 | 签名 |
/// |---|---|
/// | Windows | `fn open_best_available() -> Result<Self>` |
/// | 其它平台 | `const fn open_best_available() -> Self` |
///
/// 这不是疏忽：在 Windows 上「打开最好的可用提供程序」**真的会失败**（没有 TPM、
/// 被组策略禁用、密钥库被独占），那必须报出来让用户知情；而占位后端什么都不做，
/// 因此它不可能失败——给它一个 `Result` 只会让调用方写一个**永远走不到**的错误分支，
/// 而那种分支正是最容易在真机上第一次运行时才发现写错的地方。
///
/// 代价是调用方那行代码不能在两个平台上是同一个表达式。用 `#[cfg]` 各写一次是
/// 诚实的做法：它让「这两个平台的失败模型不同」这件事实留在代码里，而不是被一个
/// 假装统一的签名抹平。
pub use platform::PlatformKeyStore;

#[cfg(any(test, feature = "mock"))]
pub use mock::MockKeyStore;

/// 平台密钥库的错误类型。
///
/// # 它为什么是 [`Error`] 的别名
///
/// 设备身份与密钥库是**同一次操作**的两半：调用方看到的是「拿不到设备身份」，
/// 而不是两个子系统的失败。因此全 crate 共用一个错误枚举，而这个名字保留下来是
/// 为了让「这里报的是密钥库那一类错」在类型签名上读得出来。
///
/// 它也保留了旧版本的名字：旧的下游写着 `KeyStoreError::Hardware` 的地方不需要改。
pub type KeyStoreError = Error;

/// 密钥库操作的统一结果类型。
///
/// 与 [`crate::Result`] 是同一个类型。两个名字并存是为了让「这个函数只可能因为
/// 密钥库的原因失败」在签名上一眼可见。
pub type KeyStoreResult<T> = Result<T>;
