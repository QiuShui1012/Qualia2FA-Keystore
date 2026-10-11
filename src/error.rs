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

//! 密钥库的错误类型。

use qualia2fa_core::Error as CoreError;

/// 本 crate 的结果类型。
pub type Result<T> = core::result::Result<T, KeyStoreError>;

/// 密钥库操作失败的原因。
///
/// # 为什么不直接把平台的原生错误码透传出去
///
/// 原生错误码（`NTE_*`、`SECURITY_STATUS`……）**只在产生它的那个平台上**有意义。
/// 上层（FFI、UI）需要的是「该怎么做」：是让用户插上 TPM，还是提示设备不支持，
/// 还是这次签名单纯失败了。所以这里给出的是**跨平台稳定的分类**，而原始码放在
/// [`KeyStoreError::Hardware`] 的 `code` 字段里供诊断使用。
///
/// # `detail` 字段的纪律
///
/// `detail` 里**绝不能**出现秘密材料。本 crate 的所有调用都只处理公钥与消息，
/// 私钥从不进入本 crate 的地址空间，因此这里没有可泄露的东西——但新增后端时
/// 不要破坏这个性质。
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum KeyStoreError {
    /// 这个平台还没有实现后端。
    ///
    /// **不要**把它当作「可以降级到软件密钥」的信号来自动处理。是否允许软件密钥
    /// 是一个安全策略决定，必须由用户显式同意——静默降级会让人以为自己受硬件
    /// 保护。
    #[error("平台 {platform} 尚未实现硬件密钥库后端")]
    UnsupportedPlatform {
        /// 平台名（编译期常量，不含用户数据）。
        platform: &'static str,
    },

    /// 本机没有可用的硬件密钥库（有实现，但这次环境里用不了）。
    ///
    /// 典型情形：虚拟机里没有 TPM、TPM 被组策略禁用、或密钥库被独占。
    #[error("本机没有可用的硬件密钥库：{reason}")]
    HardwareUnavailable {
        /// 固定的原因描述或平台给出的文本。
        reason: String,
    },

    /// 所指的密钥不存在。
    #[error("密钥 {label} 不存在")]
    KeyNotFound {
        /// 密钥的逻辑名（由调用方提供，不含秘密）。
        label: String,
    },

    /// 该 `label` 已经有密钥了。
    ///
    /// # 为什么这是一个独立的变体
    ///
    /// 因为 [`crate::DeviceKeyStore::open_or_create`] 必须能把它与**其它**失败
    /// 区分开：对它而言「已存在」正是想要的结果（回头打开即可），而硬件故障不是。
    /// 若把它混进 [`KeyStoreError::Hardware`]，那个区分就只能靠比较原生错误码，
    /// 而原生码是实现细节。
    ///
    /// 顺带说明为什么 [`crate::DeviceKeyStore::create`] **不覆盖**已有密钥：
    /// 静默覆盖会换掉设备身份，而设备身份是别的设备用来认你的依据——那种 bug 在
    /// 几天后表现为「同步莫名其妙失效」，几乎无法回溯。
    #[error("密钥 {label} 已存在")]
    KeyAlreadyExists {
        /// 密钥的逻辑名。
        label: String,
    },

    /// 平台 API 返回了失败。
    #[error("平台密钥库调用失败（{operation}，原生码 0x{code:08X}）")]
    Hardware {
        /// 失败的操作名，用于定位。
        operation: &'static str,
        /// 平台原生错误码。
        code: i32,
    },

    /// 传入的摘要长度不符合该曲线的要求。
    ///
    /// ECDSA 本身接受被截断的摘要，但**截断规则随曲线固定**，由实现内部处理。
    /// 让调用方传一个长度不对的摘要进来，只会让签名与验签两侧对「截断到多少位」
    /// 产生分歧，而那种分歧在任何测试里都表现为「签名随机地验不过」。
    #[error("摘要长度非法：期望 {expected} 字节，实际 {actual} 字节")]
    InvalidDigestLength {
        /// 期望长度。
        expected: usize,
        /// 实际长度。
        actual: usize,
    },

    /// 密钥标签不合法。
    ///
    /// 标签会成为**系统级**密钥命名空间里的一个条目名，因此必须做白名单校验。
    /// 最直接的危险是空字符截断：若允许 `\0` 出现，`"a\0b"` 与 `"a"` 在 C 字符串
    /// 看来是同一个名字，于是两个不同的标签会映射到同一份设备身份。
    #[error("密钥标签不合法：{reason}")]
    InvalidKeyLabel {
        /// 固定的原因描述。**不含**原始标签——它可能来自用户输入。
        reason: &'static str,
    },

    /// 硬件返回的公钥不是合法的 P-256 公钥。
    ///
    /// 这说明平台后端或核心库的解析逻辑有问题，**不是**用户错误：私钥与公钥都是
    /// 我们自己在硬件里生成的，本不该出现非法点。
    #[error("硬件返回的公钥非法：{reason}")]
    InvalidPublicKey {
        /// 固定的原因描述。
        reason: &'static str,
    },

    /// 硬件返回的签名长度不对。
    ///
    /// 同上，属于内部矛盾而非用户错误。
    #[error("硬件返回的签名长度非法：期望 {expected} 字节，实际 {actual} 字节")]
    InvalidSignatureLength {
        /// 期望长度。
        expected: usize,
        /// 实际长度。
        actual: usize,
    },

    /// 核心库拒绝了某个值。
    ///
    /// 用于把 `qualia2fa_core` 的校验结果原样上抛，而不是在本 crate 里重复实现
    /// 一遍那些校验——两处实现迟早会漂移。
    #[error("核心库拒绝了该值：{source}")]
    Core {
        /// 核心库的原始错误。
        #[from]
        source: CoreError,
    },
}

impl KeyStoreError {
    /// 这个错误是否表示「本机没有硬件保护可用」。
    ///
    /// UI 可以用它决定要不要提示用户「你的设备身份密钥将以软件形式保存」。
    /// **它不表示可以自动降级**——见 [`KeyStoreError::UnsupportedPlatform`]。
    #[must_use]
    pub const fn is_missing_hardware(&self) -> bool {
        matches!(
            self,
            Self::UnsupportedPlatform { .. } | Self::HardwareUnavailable { .. }
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `is_missing_hardware` 必须只对「硬件不可用」这一类为真。
    #[test]
    fn only_hardware_errors_are_classified_as_missing_hardware() {
        let missing = [
            KeyStoreError::UnsupportedPlatform { platform: "linux" },
            KeyStoreError::HardwareUnavailable {
                reason: "no tpm".into(),
            },
        ];
        for error in &missing {
            assert!(error.is_missing_hardware(), "{error:?} 应被判定为缺少硬件");
        }

        let present = [
            KeyStoreError::KeyNotFound {
                label: "device".into(),
            },
            KeyStoreError::Hardware {
                operation: "NCryptSignHash",
                code: 0x8009_000F_u32 as i32,
            },
            KeyStoreError::InvalidDigestLength {
                expected: 32,
                actual: 20,
            },
        ];
        for error in &present {
            assert!(
                !error.is_missing_hardware(),
                "{error:?} 不应被判定为缺少硬件"
            );
        }
    }

    /// `Hardware` 的错误文本必须把原生码以十六进制给出——十进制负数没法查文档。
    #[test]
    fn hardware_error_shows_hex_code() {
        // 用十六进制字面量而不是十进制：手算 `0x8009000F` 的有符号十进制值正是
        // 这个测试第一次写错的地方（写成了 -2_147_467_761，实际是 -2_147_418_097），
        // 于是「错误码显示对不对」这件事反而被一个算错的常数掩盖了。
        let text = KeyStoreError::Hardware {
            operation: "NCryptOpenStorageProvider",
            code: 0x8009_000F_u32 as i32, // NTE_EXISTS
        }
        .to_string();
        assert!(text.contains("8009000F"), "实际: {text}");
        assert!(text.contains("NCryptOpenStorageProvider"), "实际: {text}");
    }

    /// `Error` 必须实现 `std::error::Error`，以便用 `?` 链式传播。
    #[test]
    fn implements_std_error() {
        fn assert_is_std_error<E: std::error::Error>() {}
        assert_is_std_error::<KeyStoreError>();
    }
}
