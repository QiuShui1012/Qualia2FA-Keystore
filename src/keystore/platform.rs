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

//! Hardware key store backends, one module per platform.
//!
//! **Only the module of the current target platform provides an implementation**; every
//! other platform falls back to `platform_stub`.
//!
//! # Status per platform
//!
//! | Platform | Backend | Status |
//! |---|---|---|
//! | Windows | CNG `NCrypt*` + TPM 2.0 | **implemented and verified on real hardware** |
//! | Windows (no TPM) | CNG software KSP | implemented (reports `Backend::Software`) |
//! | Android | Keystore, StrongBox preferred | **implemented and verified on real hardware** |
//! | macOS | Secure Enclave | **placeholder** |
//! | Linux | TPM 2.0 | **placeholder** |
//! | iOS | Secure Enclave | **placeholder** |
//! | Other (BSD, …) | undecided | **placeholder** |
//!
//! "Placeholder" means **every operation fails**; it is not a usable software
//! implementation. The exact failure behaviour is documented in the `platform_stub`
//! module.
//!
//! # Single entry point: [`crate::keystore::platform::PlatformKeyStore`]
//!
//! Upper layers must **not** reference a concrete backend such as
//! `windows::WindowsKeyStore` directly. Use
//! [`crate::keystore::platform::PlatformKeyStore`] instead: it exists on every platform,
//! so the FFI and UI layers compile with **zero** platform branches. Platform differences
//! are confined to the `cfg` attributes in this file rather than spread over every call
//! site.
//!
//! # Adding a platform backend
//!
//! 1. Add `<platform>.rs` in this directory, implementing [`crate::DeviceKeyStore`] and
//!    [`crate::DeviceSigner`].
//! 2. Point the matching `pub use platform_stub::StubKeyStore as PlatformKeyStore;` line
//!    in this file at the new module, and update `platform_backend_is_implemented`
//!    accordingly.
//! 3. Make sure the platform can provide **P-256 ECDSA**; this is a hard requirement, see
//!    the crate documentation.
//! 4. **Never** fall back to a software key because hardware is unavailable: return
//!    `UnsupportedPlatform` or `HardwareUnavailable` so that the caller can ask the user.
//! 5. Implement **both** master key forms as well — [`crate::DirectMasterKeyStore`] and
//!    [`crate::WrappedMasterKeyStore`] — and point the two matching
//!    `PlatformDirectMasterKeyStore` / `PlatformWrappedMasterKeyStore` lines here at them.
//!    A platform that can do only one of the two returns
//!    [`crate::Error::UnsupportedPlatform`] from the other, rather than pretending.
//!
//! Requirements common to every backend:
//!
//! - Private keys **must not** leave the hardware, nor enter this process's address
//!   space.
//! - The signing interface takes a **digest** and returns the raw **`r||s`** (64 bytes),
//!   matching the convention of [`crate::keystore::traits::DIGEST_LEN`].
//! - A key-encryption key of the wrapped form **must not** be exportable, and no operation
//!   that would reveal it may appear in an interface.
//! - Failures are returned as [`crate::KeyStoreError`]; **no panics**.
//! - Every `unsafe` block carries a `// SAFETY:` justification.

#[cfg(target_os = "windows")]
pub mod windows;

/// The Android platform API, as the platform declares it.
///
/// Test-only: it holds the declarations every JNI descriptor of the Android backend is
/// checked against, and no runtime code. Every target compiles it, so the check runs
/// wherever `cargo test` does rather than only on Android.
#[cfg(test)]
mod android_api;

/// Android Keystore backend, reached over JNI.
#[cfg(target_os = "android")]
pub mod android;

/// Placeholder implementation shared by all platforms without a backend.
///
/// Compiled on every platform except Windows and Android. "Not implemented yet" is the same
/// situation on all of them, hence a single implementation; what each platform *plans* to
/// use is recorded in [`platform_identity`].
///
/// It also supplies `PlatformProvider` on Android, which has no provider to choose between:
/// there the security level of a key is decided when the key is generated, not by opening a
/// provider.
#[cfg(not(target_os = "windows"))]
pub mod platform_stub;

/// The key store implementation available on the current platform.
///
/// This is the **entry point upper layers should use**. It exists on every platform, so
/// callers need no platform branches.
#[cfg(target_os = "windows")]
pub use windows::WindowsKeyStore as PlatformKeyStore;

/// The key store implementation available on the current platform.
#[cfg(target_os = "android")]
pub use android::AndroidKeyStore as PlatformKeyStore;

/// The key store implementation available on the current platform (this platform's
/// backend is not implemented yet).
#[cfg(not(any(target_os = "windows", target_os = "android")))]
pub use platform_stub::StubKeyStore as PlatformKeyStore;

/// The **direct** master key store of the current platform.
///
/// One of the two ways of holding the application's master key: the platform store keeps the
/// material itself. See [`crate::keystore::DirectMasterKeyStore`] for the contract.
#[cfg(target_os = "windows")]
pub use windows::WindowsDirectMasterKeyStore as PlatformDirectMasterKeyStore;

/// The direct master key store of the current platform.
#[cfg(target_os = "android")]
pub use android::AndroidDirectMasterKeyStore as PlatformDirectMasterKeyStore;

/// The direct master key store of the current platform (this platform's backend is not
/// implemented yet).
#[cfg(not(any(target_os = "windows", target_os = "android")))]
pub use platform_stub::StubDirectMasterKeyStore as PlatformDirectMasterKeyStore;

/// The **wrapped** master key store of the current platform.
///
/// The other way of holding the application's master key: a non-exportable
/// key-encryption key in the platform store wraps it, and only the wrapped bytes are
/// persisted. See [`crate::keystore::WrappedMasterKeyStore`] for the contract.
#[cfg(target_os = "windows")]
pub use windows::WindowsWrappedMasterKeyStore as PlatformWrappedMasterKeyStore;

/// The wrapped master key store of the current platform.
#[cfg(target_os = "android")]
pub use android::AndroidWrappedMasterKeyStore as PlatformWrappedMasterKeyStore;

/// The wrapped master key store of the current platform (this platform's backend is not
/// implemented yet).
#[cfg(not(any(target_os = "windows", target_os = "android")))]
pub use platform_stub::StubWrappedMasterKeyStore as PlatformWrappedMasterKeyStore;

/// The storage provider of the current platform.
#[cfg(target_os = "windows")]
pub use windows::WindowsProvider as PlatformProvider;

/// The storage provider of the current platform (this platform's backend is not
/// implemented yet).
#[cfg(not(target_os = "windows"))]
pub use platform_stub::StubProvider as PlatformProvider;

/// Main types of the Windows backend.
///
/// Re-exported here so that callers only have to remember **one** path
/// (`qualia_dik::keystore::platform::WindowsKeyStore`) instead of which submodule it
/// lives in.
///
/// New code should prefer [`crate::keystore::platform::PlatformKeyStore`]: it is
/// portable, whereas this alias only exists on Windows.
#[cfg(target_os = "windows")]
pub use windows::{WindowsKeyStore, WindowsProvider};

/// Master key stores of the Windows backend.
///
/// Both forms live here: the direct one keeps the material in the provider, the wrapped one
/// keeps a non-exportable key-encryption key there. New code should prefer
/// [`crate::keystore::platform::PlatformDirectMasterKeyStore`] and
/// [`crate::keystore::platform::PlatformWrappedMasterKeyStore`].
#[cfg(target_os = "windows")]
pub use windows::{WindowsDirectMasterKeyStore, WindowsWrappedMasterKeyStore};

/// What this platform is called, and which backend it plans to use.
///
/// Both values appear only in **error messages and diagnostics**, so they are compile-time
/// constants rather than runtime probes. They live here rather than in `platform_stub.rs`
/// so that each platform's name and plan can be looked up in one place.
#[cfg(not(target_os = "windows"))]
pub mod platform_identity {
    /// Name of this platform.
    ///
    /// Platforms not listed here (BSD, for example) report a generic name instead of a
    /// dedicated one.
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
            "this platform"
        }
    }

    /// Planned backend.
    ///
    /// macOS and iOS would use the Secure Enclave, which only supports NIST P-256. Linux
    /// would use TPM 2.0, where the `tss-esapi` binding is available only under
    /// `cfg(all(target_os = "linux", target_env = "gnu"))`, so musl targets need another
    /// route. Android would use Keystore / StrongBox, where StrongBox requires API 28+, a
    /// `FEATURE_STRONGBOX_KEYSTORE` check and a `StrongBoxUnavailableException` fallback.
    #[must_use]
    pub const fn planned_backend() -> &'static str {
        if cfg!(any(target_os = "macos", target_os = "ios")) {
            "Secure Enclave"
        } else if cfg!(target_os = "linux") {
            "TPM 2.0"
        } else if cfg!(target_os = "android") {
            "Keystore / StrongBox"
        } else {
            "undecided"
        }
    }
}
