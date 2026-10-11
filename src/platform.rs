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
//! 每个平台一个模块，且**只在目标平台编译**——这样在 Linux 上交叉检查
//! `cfg(target_os = "macos")` 的代码不会因为缺少框架而失败。
//!
//! # 各平台的状态
//!
//! | 平台 | 后端 | 状态 |
//! |---|---|---|
//! | Windows | CNG `NCrypt*` + TPM 2.0 | `windows` |
//! | Windows（无 TPM）| CNG 软件 KSP | `windows`（降级）|
//! | macOS | Secure Enclave | 未实现 |
//! | Linux | TPM 2.0 | 未实现 |
//! | Android | Keystore / StrongBox | 未实现 |
//! | iOS | Secure Enclave | 未实现 |
//!
//! # 新增一个平台后端时要做什么
//!
//! 1. 在此目录新建 `<平台>.rs`，在此处用 `#[cfg(target_os = "...")]` 声明。
//! 2. 实现 [`crate::DeviceKeyStore`] 与 [`crate::DeviceSigner`]。
//! 3. 确认该平台能提供 **P-256 ECDSA**——这是硬约束，理由见 crate 文档。
//! 4. 在 [`crate::platform_backend_is_implemented`] 里加上这个平台。
//! 5. **不要**因为硬件不可用就悄悄退回软件密钥。返回 `UnsupportedPlatform` 或
//!    `HardwareUnavailable`，让上层去征得用户同意。静默降级会让用户以为自己受
//!    硬件保护，而实际不是。
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

/// Windows 后端的主要类型。
///
/// 在这里再导出，是为了让调用方只需要记住**一个**路径
/// （`qualia2fa_keystore::platform::WindowsKeyStore`），而不必知道它具体放在哪个
/// 子模块里。将来为别的平台加后端时，这个模块名保持稳定。
#[cfg(target_os = "windows")]
pub use windows::{WindowsKeyStore, WindowsProvider};
