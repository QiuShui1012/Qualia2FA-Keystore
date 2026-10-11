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

//! 本 crate 的错误类型。
//!
//! # 为什么它不叫 `CoreError`
//!
//! 这个 crate **不依赖** Core，因此它的错误类型必须是自足的。下游会把它包进自己的
//! `Error` 里并保留 `source()`，于是「设备身份库报了什么」在错误链上仍然可查，而
//! 两个 crate 的版本可以各自演进。
//!
//! # 为什么不是一个笼统的 `Other`
//!
//! 调用方对这几类失败的处置**不同**：公钥非法要拒绝这次连接，签名不匹配要提示
//! 「对方身份变了」，[`Error::UnsupportedPlatform`] 要引导用户换平台，而
//! [`Error::HardwareUnavailable`] 要引导他换机器或接受软件密钥。合并成一个变体会
//! 让界面只能说「出错了」。
//!
//! # 为什么不直接把平台的原生错误码透传出去
//!
//! 原生错误码（`NTE_*`、`SECURITY_STATUS`……）**只在产生它的那个平台上**有意义。
//! 上层需要的是「该怎么做」。因此这里给出**跨平台稳定的分类**，而原始码放在
//! [`Error::Hardware`] 的 `code` 字段里供诊断使用——翻译掉它会丢掉排查硬件问题时
//! 唯一能拿去查文档的线索。
//!
//! # 秘密材料不得进入错误消息
//!
//! 带 `reason` 的变体收的都是 `&'static str`，因此它在**类型上**就不可能夹带私钥或
//! 任何来自输入的内容。这是刻意的：错误消息会进日志、进崩溃报告。带 `String` 的
//! 变体只有 `label` 一类——那是应用自己起的名字，不是秘密。

/// 本 crate 的统一结果类型。
pub type Result<T> = core::result::Result<T, Error>;

/// 设备身份与平台密钥库可能出现的失败。
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    // ── 设备身份（公钥侧）───────────────────────────────────────────
    /// 设备公钥不是合法的 P-256 SEC1 未压缩点。
    ///
    /// 公钥来自**外部输入**（二维码、网络），因此这个错误是正常的拒绝路径，不是
    /// 内部矛盾。
    #[error("设备公钥非法：{reason}")]
    DevicePublicKeyInvalid {
        /// 不透明的说明，供日志使用。
        reason: &'static str,
    },

    /// 设备签名格式非法，或验证不通过。
    ///
    /// # 两种情况为什么合并
    ///
    /// 调用方能做的应对完全相同（拒绝这次认证），而区分它们只会给攻击者一个微小
    /// 的预言机：「格式错」与「验签不过」的差别可以用来试探。
    #[error("设备签名非法或验证不通过：{reason}")]
    DeviceSignatureInvalid {
        /// 不透明的说明，供日志使用。**不得**包含签名值本身。
        reason: &'static str,
    },

    // ── 平台密钥库 ──────────────────────────────────────────────────
    /// 这个平台还没有实现后端。
    ///
    /// **不要**把它当作「可以降级到软件密钥」的信号来自动处理。是否允许软件密钥
    /// 是一个安全策略决定，必须由用户显式同意——静默降级会让人以为自己受硬件保护。
    #[error("平台 {platform} 尚未实现硬件密钥库后端")]
    UnsupportedPlatform {
        /// 平台名（编译期常量，不含用户数据）。
        platform: &'static str,
    },

    /// 本机没有可用的硬件密钥库（有实现，但这次环境里用不了）。
    ///
    /// # 它与 [`Error::UnsupportedPlatform`] 是**两件事**
    ///
    /// 这里是「换个环境就能用」（虚拟机里没有 TPM、TPM 被组策略禁用、密钥库被独占），
    /// 那里是「换个平台才能用」。合并它们会让界面在「换台机器」与「换台设备」之间
    /// 给出同一句提示，而那是两条不同的用户操作。
    #[error("本机没有可用的硬件密钥库：{reason}")]
    HardwareUnavailable {
        /// 固定的原因描述或平台给出的文本。
        reason: String,
    },

    /// 平台 API 返回了失败。
    #[error("平台密钥库调用失败（{operation}，原生码 0x{code:08X}）")]
    Hardware {
        /// 失败的操作名，用于定位。
        operation: &'static str,
        /// 平台原生错误码。
        ///
        /// 是 `i32` 而不是 `u32`：Windows 的 `NTSTATUS` / `SECURITY_STATUS` 是**有
        /// 符号**的，很多 NCrypt 失败以负数形式返回。用 `u32` 存会让 `-1` 变成
        /// `0xFFFFFFFF`，在日志里与真实的 `0xFFFFFFFF` 无法区分。
        code: i32,
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
    /// 因为 [`crate::keystore::DeviceKeyStore::open_or_create`] 必须能把它与**其它**
    /// 失败区分开：对它而言「已存在」正是想要的结果（回头打开即可），而硬件故障不是。
    /// 若把它混进 [`Error::Hardware`]，那个区分就只能靠比较原生错误码，而原生码是
    /// 实现细节。
    ///
    /// 顺带说明为什么 `create` **不覆盖**已有密钥：静默覆盖会换掉设备身份，而设备
    /// 身份是别的设备用来认你的依据——那种 bug 在几天后表现为「同步莫名其妙失效」，
    /// 几乎无法回溯。
    #[error("密钥 {label} 已存在")]
    KeyAlreadyExists {
        /// 密钥的逻辑名。
        label: String,
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

    /// **硬件**返回的公钥不是合法的 P-256 公钥。
    ///
    /// 与 [`Error::DevicePublicKeyInvalid`] 分开：那个说的是「对方给来的公钥不合法」
    /// （正常的拒绝路径），这个说的是「我们**自己**刚从硬件里取回来的公钥不合法」
    /// ——那是内部矛盾，说明平台后端或解析逻辑有问题，**不是**用户错误。
    ///
    /// 两者的处置完全不同：前者拒绝这次连接就好，后者必须报一个能让开发者看见的错。
    #[error("硬件返回的公钥非法：{reason}")]
    InvalidPublicKey {
        /// 固定的原因描述。
        reason: &'static str,
    },

    /// **硬件**返回的签名长度不对。
    ///
    /// 同上，属于内部矛盾而非用户错误。
    #[error("硬件返回的签名长度非法：期望 {expected} 字节，实际 {actual} 字节")]
    InvalidSignatureLength {
        /// 期望长度。
        expected: usize,
        /// 实际长度。
        actual: usize,
    },

    /// OS 随机源不可用。
    ///
    /// 只在 `mock` 后端可能出现——真实后端的随机性由硬件负责（密钥在 TPM /
    /// Secure Enclave 内部生成）。
    #[error("OS 随机源不可用")]
    RandomnessUnavailable,
}

impl Error {
    /// 这个错误是否表示「本机没有硬件保护可用」。
    ///
    /// 界面可以用它决定要不要提示用户「你的设备身份密钥将以软件形式保存」。
    /// **它不表示可以自动降级**——见 [`Error::UnsupportedPlatform`]。
    #[must_use]
    pub const fn is_missing_hardware(&self) -> bool {
        matches!(
            self,
            Self::UnsupportedPlatform { .. } | Self::HardwareUnavailable { .. }
        )
    }

    /// 这个错误是否意味着「换台机器或换个平台就能解决」。
    ///
    /// 与 [`Error::is_missing_hardware`] 的区别：那个回答「有没有硬件保护」，这个回答
    /// 「重试有没有用」。平台 API 失败（[`Error::Hardware`]）属于这里，而它**不属于**
    /// `is_missing_hardware`——密钥库可能好好的，只是这一次调用失败了。
    #[must_use]
    pub const fn is_environmental(&self) -> bool {
        matches!(
            self,
            Self::UnsupportedPlatform { .. }
                | Self::HardwareUnavailable { .. }
                | Self::Hardware { .. }
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
            Error::UnsupportedPlatform { platform: "linux" },
            Error::HardwareUnavailable {
                reason: "no tpm".into(),
            },
        ];
        for error in &missing {
            assert!(error.is_missing_hardware(), "{error:?} 应被判定为缺少硬件");
        }

        let present = [
            Error::KeyNotFound {
                label: "device".into(),
            },
            Error::Hardware {
                operation: "NCryptSignHash",
                code: 0x8009_000F_u32 as i32,
            },
            Error::InvalidDigestLength {
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
        let text = Error::Hardware {
            operation: "NCryptOpenStorageProvider",
            code: 0x8009_000F_u32 as i32, // NTE_EXISTS
        }
        .to_string();
        assert!(text.contains("8009000F"), "实际: {text}");
        assert!(text.contains("NCryptOpenStorageProvider"), "实际: {text}");
    }

    /// **负数**原生码也必须显示成可查的十六进制。
    ///
    /// NCrypt 的失败大量以负数返回。`{:08X}` 作用在 `i32` 上会按**补码**打印，
    /// 因此 `-1` 显示为 `FFFFFFFF`——正是 Windows 文档里的写法。
    #[test]
    fn negative_native_codes_print_as_twos_complement() {
        let text = Error::Hardware {
            operation: "NCryptOpenKey",
            code: -1,
        }
        .to_string();
        assert!(text.contains("FFFFFFFF"), "实际: {text}");
    }

    /// 环境问题与签名问题必须分开。
    ///
    /// 前者应当引导用户换设备或接受软件密钥，后者应当拒绝这次认证。混在一起会让
    /// 界面在「对方是攻击者」与「我这台机器没有 TPM」之间给出同一句提示。
    #[test]
    fn environmental_failures_are_recognised() {
        assert!(
            Error::UnsupportedPlatform { platform: "ios" }.is_environmental(),
            "平台未实现属于环境问题"
        );
        assert!(
            Error::Hardware {
                operation: "op",
                code: 0,
            }
            .is_environmental(),
            "平台调用失败属于环境问题"
        );
        assert!(
            !Error::DeviceSignatureInvalid {
                reason: "不匹配"
            }
            .is_environmental(),
            "验签失败**不是**环境问题——它是安全事件"
        );
        assert!(
            !Error::DevicePublicKeyInvalid {
                reason: "非曲线点"
            }
            .is_environmental(),
            "公钥非法不是环境问题"
        );
    }

    /// 「对方给的公钥非法」与「硬件返回的公钥非法」必须是**两个**变体。
    #[test]
    fn the_two_invalid_public_key_cases_are_distinct() {
        let from_peer = Error::DevicePublicKeyInvalid {
            reason: "该点不在 P-256 曲线上",
        };
        let from_hardware = Error::InvalidPublicKey {
            reason: "长度不是 65 字节",
        };
        assert!(
            !from_peer.is_environmental(),
            "对方给的公钥非法是正常的拒绝路径，不是环境问题"
        );
        assert!(
            !from_hardware.is_environmental(),
            "硬件返回非法公钥是内部矛盾，不是环境问题"
        );
        assert_ne!(from_peer.to_string(), from_hardware.to_string());
    }

    /// `Error` 必须实现 `std::error::Error`，以便用 `?` 链式传播。
    #[test]
    fn implements_std_error() {
        fn assert_is_std_error<E: std::error::Error>() {}
        assert_is_std_error::<Error>();
    }

    /// 错误消息必须带上可定位的数值，且不得 panic。
    #[test]
    fn display_includes_diagnostic_numbers() {
        let cases: [(Error, &str); 3] = [
            (
                Error::Hardware {
                    operation: "NCryptOpenKey",
                    code: 0x8009_0016_u32 as i32,
                },
                "0x80090016",
            ),
            (Error::UnsupportedPlatform { platform: "linux" }, "linux"),
            (
                Error::KeyNotFound {
                    label: "device".into(),
                },
                "device",
            ),
        ];
        for (error, needle) in cases {
            let text = error.to_string();
            assert!(text.contains(needle), "错误文本 {text:?} 未包含 {needle:?}");
        }
    }
}
