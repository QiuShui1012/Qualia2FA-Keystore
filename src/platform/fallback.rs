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

//! 尚未实现后端的平台上的回退实现。
//!
//! 本模块在 **除 Windows 之外的所有平台**上编译。它的每一个操作都返回
//! [`crate::KeyStoreError::UnsupportedPlatform`]——**不提供任何密钥功能**。
//!
//! # 为什么要有这个模块，而不是干脆没有后端
//!
//! 因为它让**上层的代码不必为平台写分支**。`qualia2fa_keystore::platform::PlatformKeyStore`
//! 在 Windows 上是真实实现、在其余平台上是本类型，两者满足同一组 trait。于是 FFI
//! 层与 UI 层可以按 `cfg(target_os)` **零分支**地编译，所有平台差异都收在
//! [`super`] 的一处 `cfg` 里。
//!
//! # 为什么它必须失败，而不是降级为软件密钥
//!
//! 没有实现就是没有实现。在这里悄悄用软件密钥顶上，会让「本平台还没有硬件后端」
//! 与「本平台有硬件后端且已在用」在调用方看来完全一样——那正是「静默降级」，
//! 是本项目明确禁止的：用户会以为自己受硬件保护，而私钥其实只是一个软件文件。
//!
//! 因此本类型**如实报告** [`crate::traits::Backend::Unavailable`]，并且永远不产出
//! [`crate::DeviceSigner`]。上层拿到 `UnsupportedPlatform` 后应当提示用户
//! 「本平台尚未支持设备身份」，而不是继续往下走。

use core::fmt;

use crate::error::{KeyStoreError, Result};
use crate::traits::{Backend, DeviceKeyStore};

/// 占位的存储提供程序。
///
/// 存在的意义是让 `PlatformKeyStore` 的形状与 Windows 后端一致。它无法被构造出
/// 一个可用的状态：所有操作都失败。
#[derive(Debug, Clone, Copy, Default)]
pub struct StubProvider;

impl StubProvider {
    /// 本平台名称，用于错误消息。
    ///
    /// 返回固定字符串而不是运行期探测：这个值只用来告诉用户「哪个平台还没有
    /// 后端」，而它本来就是编译期事实。
    const fn platform_name() -> &'static str {
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

    /// 计划中的后端名称，用于让调用方知道将来会用什么。
    const fn planned_backend() -> &'static str {
        if cfg!(target_os = "macos") {
            "Secure Enclave"
        } else if cfg!(any(target_os = "linux", target_os = "android")) {
            "TPM 2.0 / Keystore"
        } else if cfg!(target_os = "ios") {
            "Secure Enclave"
        } else {
            "未定"
        }
    }
}

/// 尚未实现后端的平台上的密钥库。
///
/// 所有操作都返回 [`crate::KeyStoreError::UnsupportedPlatform`]。
///
/// 类型名不叫 `UnsupportedKeyStore`，是因为将来它会被真实实现取代；调用方写的是
/// [`super::PlatformKeyStore`] 这个别名，届时无需改动。
#[derive(Debug, Clone, Copy, Default)]
pub struct StubKeyStore;

impl StubKeyStore {
    /// 构造一个回退密钥库。
    ///
    /// 不需要参数：它没有任何状态。签名与 Windows 后端保持一致，调用方可以按
    /// 同一个模式初始化。
    #[must_use]
    pub const fn open_best_available() -> Self {
        Self
    }

    /// 本平台尚未实现的错误。
    fn unsupported() -> KeyStoreError {
        KeyStoreError::UnsupportedPlatform {
            platform: StubProvider::platform_name(),
        }
    }
}

impl DeviceKeyStore for StubKeyStore {
    fn backend(&self) -> Backend {
        // 如实报告。注意这**不是** `Backend::Software`——本类型连软件密钥都不提供，
        // 报 `Software` 会让调用方以为「至少能用」，从而走进一条必然失败的路。
        Backend::Unavailable
    }

    fn open(&self, _label: &str) -> Result<Box<dyn crate::DeviceSigner>> {
        Err(Self::unsupported())
    }

    fn create(&self, _label: &str) -> Result<Box<dyn crate::DeviceSigner>> {
        Err(Self::unsupported())
    }

    fn delete(&self, _label: &str) -> Result<()> {
        Err(Self::unsupported())
    }
}

/// 供上层做诊断用的一段说明。
///
/// 放在这里而不是让每个调用方各写一遍，是因为「本平台还没有设备身份后端」这句话
/// 应当只有一处措辞。
impl fmt::Display for StubKeyStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} 尚未实现设备身份密钥库后端（计划使用 {}）",
            StubProvider::platform_name(),
            StubProvider::planned_backend()
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 回退实现必须报告「不可用」，而不是「软件」或某个硬件后端。
    #[test]
    fn fallback_reports_unavailable() {
        let store = StubKeyStore::open_best_available();
        assert_eq!(store.backend(), Backend::Unavailable);
        assert!(!store.backend().is_hardware_backed());
    }

    /// 每一个操作都必须失败，且错误是「本平台未支持」而不是别的。
    ///
    /// 这一条是防止将来有人往回退实现里加「临时的」软件密钥支持：只要它开始成功，
    /// 这个测试就会失败。
    #[test]
    fn every_operation_fails_with_unsupported_platform() {
        let store = StubKeyStore::open_best_available();
        for result in [
            store.open("x").map(|_| ()),
            store.create("x").map(|_| ()),
            store.delete("x"),
        ] {
            match result {
                Err(KeyStoreError::UnsupportedPlatform { platform }) => {
                    assert!(!platform.is_empty(), "平台名不得为空");
                }
                other => panic!("期望 UnsupportedPlatform，实际是 {other:?}"),
            }
        }
    }

    /// `open_or_create` 也必须失败——它走的是 `open`，不得有捷径。
    #[test]
    fn open_or_create_also_fails() {
        let store = StubKeyStore::open_best_available();
        assert!(store.open_or_create("x").is_err());
    }

    /// 诊断文案必须同时说清「哪个平台」与「还没实现」。
    #[test]
    fn display_explains_the_situation() {
        let store = StubKeyStore::open_best_available();
        let text = store.to_string();
        assert!(text.contains("尚未实现"), "文案未说明未实现：{text}");
        assert!(!text.is_empty());
    }
}
