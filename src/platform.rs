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

//! 各平台的硬件密钥库后端。
//!
//! 每个平台一个模块。**只有当前目标平台的模块会真正提供实现**，其余平台落到
//! `platform_stub`。
//!
//! # 各平台的状态
//!
//! | 平台 | 后端 | 状态 |
//! |---|---|---|
//! | Windows | CNG `NCrypt*` + TPM 2.0 | **已实现并真机验证** |
//! | Windows（无 TPM）| CNG 软件 KSP | 已实现（如实降级为 `Backend::Software`）|
//! | macOS | Secure Enclave | **占位** |
//! | Linux | TPM 2.0 | **占位** |
//! | Android | Keystore / StrongBox | **占位** |
//! | iOS | Secure Enclave | **占位** |
//! | 其他（BSD 等）| 未定 | **占位** |
//!
//! 「占位」的含义是**每一个操作都失败**，而不是「有一个能用的软件实现」。理由见
//! `platform_stub.rs` 的模块文档。
//!
//! # 只有一个入口：[`crate::platform::PlatformKeyStore`]
//!
//! 上层**不要**直接引用 [`crate::platform::WindowsKeyStore`] 之类的具体后端。请用
//! [`crate::platform::PlatformKeyStore`]——它在每个平台上都存在，因而 FFI 层与 UI 层可以
//! **零分支**编译。平台差异只在本文件的一处 `cfg` 里，而不是散落在每一个调用点。
//!
//! # 新增一个平台后端时要做什么
//!
//! 1. 在此目录新建 `<平台>.rs`，实现 [`crate::DeviceKeyStore`] 与
//!    [`crate::DeviceSigner`]。
//! 2. 把本文件里对应的那一行 `pub use platform_stub::StubKeyStore as PlatformKeyStore;`
//!    改成指向新模块，并同步 `platform_backend_is_implemented`。
//! 3. 确认该平台能提供 **P-256 ECDSA**——这是硬约束，理由见 crate 文档。
//! 4. **不要**因为硬件不可用就悄悄退回软件密钥。返回 `UnsupportedPlatform` 或
//!    `HardwareUnavailable`，让上层去征得用户同意。
//!
//! 各后端的公共要求：
//!
//! - 私钥**不得**离开硬件，也不得进入本进程的地址空间。
//! - 签名接口收**摘要**、吐**原始 `r||s`**（64 字节），与
//!   [`crate::traits::DIGEST_LEN`] 的约定一致。
//! - 出错时返回 [`crate::KeyStoreError`]，**不得 panic**。
//! - 每个 `unsafe` 块都要有 `// SAFETY:` 说明。

#[cfg(target_os = "windows")]
pub mod windows;

/// 尚未实现后端的平台上共用的占位实现。
///
/// 在除 Windows 之外的所有平台上编译。「尚未实现」这件事对所有那些平台是同一件
/// 事，因此只有一份实现；各平台**计划**用什么写在 [`platform_identity`] 里。
#[cfg(not(target_os = "windows"))]
pub mod platform_stub;

/// 当前平台上可用的密钥库实现。
///
/// 这是**上层应当使用的入口**。它在每个平台上都存在，因而调用方无需为平台写分支。
#[cfg(target_os = "windows")]
pub use windows::WindowsKeyStore as PlatformKeyStore;

/// 当前平台上可用的密钥库实现（本平台后端尚未实现）。
#[cfg(not(target_os = "windows"))]
pub use platform_stub::StubKeyStore as PlatformKeyStore;

/// 当前平台上的存储提供程序。
#[cfg(target_os = "windows")]
pub use windows::WindowsProvider as PlatformProvider;

/// 当前平台上的存储提供程序（本平台后端尚未实现）。
#[cfg(not(target_os = "windows"))]
pub use platform_stub::StubProvider as PlatformProvider;

/// Windows 后端的主要类型。
///
/// 在这里再导出是为了让调用方只需记住**一个**路径
/// （`qualia2fa_keystore::platform::WindowsKeyStore`），而不必知道它具体放在哪个
/// 子模块里。
///
/// 新代码请优先用 [`crate::platform::PlatformKeyStore`]：它可移植，而本别名只在 Windows 上存在。
#[cfg(target_os = "windows")]
pub use windows::{WindowsKeyStore, WindowsProvider};

/// 本平台叫什么，以及尚未实现的后端计划用什么。
///
/// 这两个值只用于**错误消息与诊断文案**，因此是编译期常量而不是运行期探测。
/// 放在这里而不是塞进 `platform_stub.rs`，是为了让「每个平台各自的名字与计划」
/// 在本文件里一眼可查——将来新增后端时该改哪里也是同一处。
#[cfg(not(target_os = "windows"))]
pub mod platform_identity {
    /// 本平台名称。
    #[must_use]
    pub const fn name() -> &'static str {
        if cfg!(target_os = "macos") {
            "macOS"
        } else if cfg!(target_os = "linux") {
            "Linux"
        } else if cfg!(target_os = "android") {
            "Android"
        } else if cfg!(target_os = "ios") {
            "iOS"
        } else {
            // 未知平台（例如 BSD）。不必单独列名，报「本平台」即可。
            "本平台"
        }
    }

    /// 计划中的后端。
    #[must_use]
    pub const fn planned_backend() -> &'static str {
        if cfg!(any(target_os = "macos", target_os = "ios")) {
            // Secure Enclave 只支持 NIST P-256，这也正是本项目把设备身份签名
            // 固定在 ECDSA P-256 的原因之一。
            "Secure Enclave"
        } else if cfg!(target_os = "linux") {
            // `tss-esapi` 只在 `cfg(all(target_os = "linux", target_env = "gnu"))`
            // 下可用，musl 目标需要另找路线。
            "TPM 2.0"
        } else if cfg!(target_os = "android") {
            // API 28+ 才有 StrongBox，且需要 `FEATURE_STRONGBOX_KEYSTORE` 检查与
            // `StrongBoxUnavailableException` 回退。
            "Keystore / StrongBox"
        } else {
            "未定"
        }
    }
}
