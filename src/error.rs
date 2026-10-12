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

//! Error type of this crate.
//!
//! This crate does not depend on Qualia2FA Core, so its error type has to be self-contained.
//! Downstream crates wrap it in their own `Error` and keep `source()`, so what the device
//! identity library reported stays visible in the error chain while the versions of the two
//! crates evolve independently.
//!
//! # Distinct variants instead of one generic `Other`
//!
//! Callers handle these failures differently: an invalid public key rejects this connection,
//! a signature mismatch means "the peer's identity changed",
//! [`Error::UnsupportedPlatform`] suggests changing platform, and
//! [`Error::HardwareUnavailable`] suggests changing machine or accepting a software key.
//! Merging them into a single variant would leave the UI able to say only "something went
//! wrong".
//!
//! # Native error codes are not passed through directly
//!
//! Native codes (`NTE_*`, `SECURITY_STATUS`, …) are meaningful only on the platform that
//! produced them, while callers need to know what to do. The variants therefore carry a
//! cross-platform classification, and the raw code is kept in the `code` field of
//! [`Error::Hardware`] for diagnostics: dropping it would discard the only handle available
//! for looking a hardware problem up in vendor documentation.
//!
//! # Secrets must not enter error messages
//!
//! Every variant that carries a `reason` takes a `&'static str`, so it is impossible **by
//! type** to embed a private key or anything else taken from input — error messages reach
//! logs and crash reports. The only variants carrying a `String` are the `label` ones, which
//! hold a name chosen by the application rather than a secret.

/// Unified result type of this crate.
pub type Result<T> = core::result::Result<T, Error>;

/// Failures that can arise from device identity handling and the platform key store.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    // ── Device identity (public-key side) ───────────────────────────
    /// The device public key is not a valid P-256 SEC1 uncompressed point.
    ///
    /// Public keys arrive as **external input** (QR codes, the network), so this is a normal
    /// rejection path rather than an internal inconsistency.
    #[error("设备公钥非法：{reason}")]
    DevicePublicKeyInvalid {
        /// Opaque description for logs.
        reason: &'static str,
    },

    /// The device signature is malformed, or verification failed.
    ///
    /// # Why the two cases are merged
    ///
    /// The caller's response is identical (reject this authentication), and distinguishing
    /// them would give an attacker a small oracle: the difference between "malformed" and
    /// "did not verify" could be probed.
    #[error("设备签名非法或验证不通过：{reason}")]
    DeviceSignatureInvalid {
        /// Opaque description for logs. Must **not** contain the signature value itself.
        reason: &'static str,
    },

    // ── Platform key store ──────────────────────────────────────────
    /// This platform has no backend implementation yet.
    ///
    /// Do **not** treat it as a signal that falling back to a software key is allowed
    /// automatically. Whether software keys are acceptable is a security policy decision that
    /// requires explicit user consent; a silent fallback would leave the user believing the
    /// key is hardware-protected.
    #[error("平台 {platform} 尚未实现硬件密钥库后端")]
    UnsupportedPlatform {
        /// Platform name (a compile-time constant, containing no user data).
        platform: &'static str,
    },

    /// This machine has no usable hardware key store (an implementation exists, but it is
    /// unavailable in this environment).
    ///
    /// # It is a **different thing** from [`Error::UnsupportedPlatform`]
    ///
    /// Here a different environment would work (a virtual machine without a TPM, a TPM
    /// disabled by group policy, a key store held exclusively by another process); there a
    /// different platform is required. Merging them would make the UI give the same advice
    /// for "change machine" and "change device", which are two different user actions.
    #[error("本机没有可用的硬件密钥库：{reason}")]
    HardwareUnavailable {
        /// A fixed reason description, or text supplied by the platform.
        reason: String,
    },

    /// A platform API returned a failure.
    #[error("平台密钥库调用失败（{operation}，原生码 0x{code:08X}）")]
    Hardware {
        /// Name of the failing operation, used for diagnostics.
        operation: &'static str,
        /// Raw platform error code.
        ///
        /// An `i32` rather than a `u32`: Windows `NTSTATUS` / `SECURITY_STATUS` values are
        /// **signed**, and many NCrypt failures are returned as negative numbers. Storing
        /// them as `u32` would turn `-1` into `0xFFFFFFFF`, indistinguishable in a log from a
        /// genuine `0xFFFFFFFF`.
        code: i32,
    },

    /// The referenced key does not exist.
    #[error("密钥 {label} 不存在")]
    KeyNotFound {
        /// Logical name of the key (supplied by the caller, containing no secret).
        label: String,
    },

    /// A key already exists under this `label`.
    ///
    /// # Why this is a separate variant
    ///
    /// [`crate::keystore::DeviceKeyStore::open_or_create`] has to distinguish it from **other**
    /// failures: for that method "already exists" is the desired outcome (the key can simply
    /// be opened), while a hardware fault is not. Folding it into [`Error::Hardware`] would
    /// leave that distinction to a comparison of native error codes, which are an
    /// implementation detail.
    ///
    /// Relatedly, `create` **never overwrites** an existing key: overwriting would replace the
    /// device identity that other devices use to recognise this one.
    #[error("密钥 {label} 已存在")]
    KeyAlreadyExists {
        /// Logical name of the key.
        label: String,
    },

    /// The digest length passed in does not meet the requirement of the curve.
    ///
    /// ECDSA accepts truncated digests, but the truncation rule is fixed per curve and is
    /// handled inside the implementation. Accepting a digest of the wrong length would only
    /// let the signing and verification sides disagree about how far to truncate, and such a
    /// disagreement shows up as "signatures randomly fail to verify".
    #[error("摘要长度非法：期望 {expected} 字节，实际 {actual} 字节")]
    InvalidDigestLength {
        /// Expected length.
        expected: usize,
        /// Actual length.
        actual: usize,
    },

    /// The key label is invalid.
    ///
    /// The label becomes an entry name in the **system-wide** key namespace, so it is
    /// validated against a whitelist. The most direct hazard is NUL truncation: if `\0` were
    /// allowed, `"a\0b"` and `"a"` would be the same name to a C string, and two different
    /// labels would map to one device identity.
    #[error("密钥标签不合法：{reason}")]
    InvalidKeyLabel {
        /// Fixed reason description. Contains **no** raw label — it may come from user input.
        reason: &'static str,
    },

    /// The public key returned by **hardware** is not a valid P-256 public key.
    ///
    /// Separate from [`Error::DevicePublicKeyInvalid`]: that one means "a public key received
    /// from a peer is invalid" (a normal rejection path), while this one means "the public
    /// key we just read back from our own hardware is invalid" — an internal inconsistency
    /// pointing at the platform backend or the parsing logic, **not** a user error.
    ///
    /// The two are handled quite differently: the first only requires rejecting this
    /// connection, the second has to surface an error a developer can see.
    #[error("硬件返回的公钥非法：{reason}")]
    InvalidPublicKey {
        /// Fixed reason description.
        reason: &'static str,
    },

    /// The signature length returned by **hardware** is wrong.
    ///
    /// As above, this is an internal inconsistency rather than a user error.
    #[error("硬件返回的签名长度非法：期望 {expected} 字节，实际 {actual} 字节")]
    InvalidSignatureLength {
        /// Expected length.
        expected: usize,
        /// Actual length.
        actual: usize,
    },

    /// The OS random source is unavailable.
    ///
    /// Can only occur with the `mock` backend; real backends leave randomness to the hardware,
    /// which generates keys inside the TPM / Secure Enclave.
    #[error("OS 随机源不可用")]
    RandomnessUnavailable,
}

impl Error {
    /// Whether this error means "no hardware protection is available on this machine".
    ///
    /// The UI can use it to decide whether to tell the user that the device identity key will
    /// be stored in software. It does **not** mean that falling back automatically is allowed;
    /// see [`Error::UnsupportedPlatform`].
    #[must_use]
    pub const fn is_missing_hardware(&self) -> bool {
        matches!(
            self,
            Self::UnsupportedPlatform { .. } | Self::HardwareUnavailable { .. }
        )
    }

    /// Whether this error means "a different machine or platform would solve it".
    ///
    /// It differs from [`Error::is_missing_hardware`], which answers "is there hardware
    /// protection": this one answers "would retrying help". A platform API failure
    /// ([`Error::Hardware`]) belongs here, and it is **not** missing hardware — the key store
    /// may be perfectly fine and only this call failed.
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

    /// `is_missing_hardware` is true only for the hardware-unavailable cases.
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

    /// The text of a `Hardware` error gives the native code in hexadecimal — a negative
    /// decimal value cannot be looked up in vendor documentation.
    #[test]
    fn hardware_error_shows_hex_code() {
        let text = Error::Hardware {
            operation: "NCryptOpenStorageProvider",
            code: 0x8009_000F_u32 as i32,
        }
        .to_string();
        assert!(text.contains("8009000F"), "实际: {text}");
        assert!(text.contains("NCryptOpenStorageProvider"), "实际: {text}");
    }

    /// **Negative** native codes must also print as a lookup-able hexadecimal value.
    ///
    /// NCrypt failures are frequently returned as negative numbers. `{:08X}` on an `i32`
    /// prints the **two's complement**, so `-1` shows up as `FFFFFFFF`, which is exactly how
    /// Windows documentation writes it.
    #[test]
    fn negative_native_codes_print_as_twos_complement() {
        let text = Error::Hardware {
            operation: "NCryptOpenKey",
            code: -1,
        }
        .to_string();
        assert!(text.contains("FFFFFFFF"), "实际: {text}");
    }

    /// Environment problems and signature problems are kept apart.
    ///
    /// The former should lead the user to change device or accept a software key, the latter
    /// should reject this authentication. Mixing them would make the UI give the same message
    /// for "the peer is an attacker" and "this machine has no TPM".
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

    /// "The peer sent an invalid public key" and "hardware returned an invalid public key"
    /// are **two** distinct variants.
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

    /// `Error` implements `std::error::Error`, so it can be propagated with `?`.
    #[test]
    fn implements_std_error() {
        fn assert_is_std_error<E: std::error::Error>() {}
        assert_is_std_error::<Error>();
    }

    /// Error messages carry locatable numeric values and never panic.
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
