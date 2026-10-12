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

//! Fallback implementation for platforms whose backend is not implemented yet.
//!
//! This module compiles on **every platform except Windows**. Each of its operations
//! returns [`crate::Error::UnsupportedPlatform`]: it provides **no key functionality at
//! all**.
//!
//! # A backend that exists so that callers need no branches
//!
//! `qualia_dik::keystore::platform::PlatformKeyStore` is the real implementation on
//! Windows and this type on every other platform, and both satisfy the same traits. The
//! FFI and UI layers can therefore be built with **zero** `cfg(target_os)` branches: all
//! platform differences are confined to a single `cfg` in [`super`] and none of them
//! reaches a call site.
//!
//! # It fails instead of degrading to a software key
//!
//! This type **never** substitutes a software key. Such a substitution would make "this
//! platform has no hardware backend yet" look exactly like "this platform has a hardware
//! backend and is using it", while the private key would in fact be an ordinary software
//! file — the user would believe they are hardware-protected.
//!
//! The type therefore reports [`crate::keystore::traits::Backend::Unavailable`] truthfully
//! and never produces a [`crate::DeviceSigner`]. A caller that receives
//! [`crate::Error::UnsupportedPlatform`] should tell the user that this platform does not
//! support device identities yet rather than continue.

use core::fmt;

use crate::keystore::traits::{Backend, DeviceKeyStore};
use crate::{Error, Result};

/// Placeholder storage provider.
///
/// It exists so that `PlatformKeyStore` has the same shape as the Windows backend. No
/// usable state can be constructed from it: every operation fails.
#[derive(Debug, Clone, Copy, Default)]
pub struct StubProvider;

impl StubProvider {
    /// Name of this platform, used in error messages.
    ///
    /// Forwards to [`crate::keystore::platform::platform_identity`], the single source of
    /// "what this platform is called and what it plans to use".
    const fn platform_name() -> &'static str {
        crate::keystore::platform::platform_identity::name()
    }

    /// Name of the planned backend, so that callers know what will be used eventually.
    const fn planned_backend() -> &'static str {
        crate::keystore::platform::platform_identity::planned_backend()
    }
}

/// Key store on platforms whose backend is not implemented yet.
///
/// Every operation returns [`crate::Error::UnsupportedPlatform`].
///
/// The type is not named `UnsupportedKeyStore` because callers refer to it through the
/// alias [`super::PlatformKeyStore`], so a future real implementation replaces it without
/// touching any call site.
#[derive(Debug, Clone, Copy, Default)]
pub struct StubKeyStore;

impl StubKeyStore {
    /// Constructs the fallback key store.
    ///
    /// It takes no arguments because it holds no state, and its signature matches the
    /// Windows backend so that callers initialize both the same way.
    #[must_use]
    pub const fn open_best_available() -> Self {
        Self
    }

    /// The error reporting that this platform's backend is not implemented yet.
    fn unsupported() -> Error {
        Error::UnsupportedPlatform {
            platform: StubProvider::platform_name(),
        }
    }
}

impl DeviceKeyStore for StubKeyStore {
    /// Always [`Backend::Unavailable`], never [`Backend::Software`]: this type offers no
    /// software keys either, and reporting `Software` would send callers down a path that
    /// is bound to fail.
    fn backend(&self) -> Backend {
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

/// A short explanation of the situation, for diagnostics.
///
/// It lives here so that "this platform has no device identity backend yet" has exactly
/// one wording instead of one per caller.
impl fmt::Display for StubKeyStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} has no device identity key store backend yet (planned: {})",
            StubProvider::platform_name(),
            StubProvider::planned_backend()
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The fallback must report "unavailable" rather than "software" or a hardware
    /// backend.
    #[test]
    fn stub_reports_unavailable() {
        let store = StubKeyStore::open_best_available();
        assert_eq!(store.backend(), Backend::Unavailable);
        assert!(!store.backend().is_hardware_backed());
    }

    /// Every operation must fail, and the error must be "this platform is not supported"
    /// rather than anything else.
    ///
    /// A software-key fallback added to this type later would make the test fail, because
    /// the operations would start succeeding.
    #[test]
    fn every_operation_fails_with_unsupported_platform() {
        let store = StubKeyStore::open_best_available();
        for result in [
            store.open("x").map(|_| ()),
            store.create("x").map(|_| ()),
            store.delete("x"),
        ] {
            match result {
                Err(Error::UnsupportedPlatform { platform }) => {
                    assert!(!platform.is_empty(), "the platform name must not be empty");
                }
                other => panic!("expected UnsupportedPlatform, got {other:?}"),
            }
        }
    }

    /// `open_or_create` must fail as well: it goes through `open` and takes no shortcut.
    #[test]
    fn open_or_create_also_fails() {
        let store = StubKeyStore::open_best_available();
        assert!(store.open_or_create("x").is_err());
    }

    /// The diagnostic text must state both which platform this is and that the backend is
    /// not implemented yet.
    #[test]
    fn display_explains_the_situation() {
        let store = StubKeyStore::open_best_available();
        let text = store.to_string();
        assert!(text.contains("has no device identity key store backend yet"), "the text does not say the backend is missing: {text}");
        assert!(!text.is_empty());
    }
}
