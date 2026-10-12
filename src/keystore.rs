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

//! Platform key store: create a P-256 key in hardware, read its public key and
//! sign a message with it.
//!
//! Three operations live here, and nothing else:
//!
//! 1. create an ECDSA P-256 key whose private half never leaves the platform;
//! 2. return the matching public key;
//! 3. sign a **message** with it.
//!
//! Protocol logic, cryptographic primitives and anything expressible in pure Rust
//! belong to the core crate: code in this module cannot be fuzzed, cannot run on
//! CI across platforms, and lives outside the protection of
//! `forbid(unsafe_code)`.
//!
//! # Signing takes a message, not a digest
//!
//! Platform APIs accept digests only (the Windows CNG parameter is named
//! `pbHashValue`), so a SHA-256 happens in between. This module performs that
//! hash itself: the caller passes the raw message. Verification
//! ([`crate::device::verify`]) follows the same convention, so both sides always
//! hash the same bytes.

use crate::{Error, Result};

pub mod platform;

mod traits;

#[cfg(any(test, feature = "mock"))]
mod mock;

pub use traits::{Backend, DIGEST_LEN, DeviceKeyStore, DeviceSigner, sha256};

/// The key store implementation of the current platform, selected at compile time.
///
/// It exists so that callers write `PlatformKeyStore::open_best_available()` once
/// instead of carrying `#[cfg(target_os = "windows")] use ...windows::WindowsKeyStore`
/// themselves.
///
/// On platforms without a backend this is the stub: every operation returns
/// [`Error::UnsupportedPlatform`], and it never falls back to a software key.
///
/// # The two backends have different constructor signatures
///
/// | backend | signature |
/// |---|---|
/// | Windows | `fn open_best_available() -> Result<Self>` |
/// | others | `const fn open_best_available() -> Self` |
///
/// Opening the best available provider can fail on Windows (no TPM, disabled by
/// group policy, key store in use) and the user has to be told. The stub backend
/// cannot fail, so a `Result` around it would only add an error branch that is
/// never taken. Callers therefore write the call once per platform with `#[cfg]`,
/// which keeps the difference between the two failure models visible in the code.
pub use platform::PlatformKeyStore;

#[cfg(any(test, feature = "mock"))]
pub use mock::MockKeyStore;

/// Error type of the key store.
///
/// An alias of [`Error`]: device identity and the key store are two halves of one
/// operation, so the whole crate shares a single error enum. The name stays so
/// that a signature shows which failures originate here.
pub type KeyStoreError = Error;

/// Result type of key store operations.
///
/// The same type as [`crate::Result`], under a name that makes "this function
/// only fails for key store reasons" visible in a signature.
pub type KeyStoreResult<T> = Result<T>;
