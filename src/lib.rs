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

//! Device identity kit: the **public-key side** of a device identity, plus the
//! **private-key side** that drives the platform-native key store.
//!
//! # Scope
//!
//! | Module | Responsibility | Holds private keys |
//! |------|--------|----------|
//! | [`device`] | Public-key representation, fingerprint ([`DeviceId`]), signature verification | No |
//! | [`keystore`] | Key generation, public-key retrieval, message signing | Yes (in platform hardware) |
//!
//! Both halves share the single error type [`Error`]: the caller sees the failure of one
//! device-identity operation, not the failure of two subsystems.
//!
//! This crate is the only place in the project where `unsafe` is allowed, and the only
//! place that calls platform-native APIs (Windows CNG, Android Keystore, iOS Security
//! framework). Every `unsafe` operation must be written explicitly inside an `unsafe {}`
//! block; `#![deny(unsafe_op_in_unsafe_fn)]` enforces this.
//!
//! Representation and verification live in the same crate as generation and signing so that
//! a device can verify **another** device's signature even if it holds no hardware key of
//! its own — a desktop machine without a TPM, for example.
//!
//! # A standalone library
//!
//! Any project that needs a P-256 identity key pair held in platform hardware can use this
//! crate without accepting the Qualia2FA vault format, the sync protocol, or anything else.
//! Downstream crates depend on this one, never the reverse: protocol logic, cryptographic
//! primitives, and anything else that can be written in pure Rust and is unrelated to device
//! identity belongs downstream.
//!
//! # Signature algorithm: ECDSA P-256
//!
//! The algorithm is a hard constraint rather than a preference, because the private key has
//! to live in platform hardware:
//!
//! - **Android**: KeyMint HAL's `Algorithm.aidl` lists only `RSA=1, EC=3, AES=32,
//!   TRIPLE_DES=33, HMAC=128` — there is no EdDSA, and `KeyProperties.java` defines no
//!   Ed25519 constant. `CURVE_25519` exists, but it is an **XDH key-agreement curve, not a
//!   signature algorithm**.
//! - **iOS**: Apple documents the Secure Enclave as NIST P-256 only.
//!
//! P-256/ECDSA is therefore the only signature algorithm that can be held in hardware on
//! both mobile platforms; any other choice restricts mobile identity keys to software
//! storage.
//!
//! # Platform backends
//!
//! | Platform | Backend | Status |
//! |---|---|---|
//! | Windows | CNG `NCrypt*`, TPM 2.0 (`MS_PLATFORM_CRYPTO_PROVIDER`) | Implemented |
//! | Windows (no TPM) | CNG software KSP (`MS_KEY_STORAGE_PROVIDER`) | Implemented (fallback) |
//! | macOS | Secure Enclave | Not implemented (placeholder backend) |
//! | Linux | TPM 2.0 | Not implemented (placeholder backend) |
//! | Android | Keystore / StrongBox | Not implemented (placeholder backend) |
//! | iOS | Secure Enclave | Not implemented (placeholder backend) |
//!
//! Unimplemented platforms **never degrade silently**: calling
//! [`keystore::DeviceKeyStore::backend`] yields [`keystore::Backend::Unavailable`], and key
//! creation returns [`Error::UnsupportedPlatform`].
//!
//! "Not implemented" and "no hardware present" are two different things and have two
//! different values: [`keystore::Backend::Unavailable`] means this platform has no backend
//! yet, while [`keystore::Backend::Software`] means a backend exists but this machine has no
//! hardware. Merging them would make "switch platform" and "switch machine"
//! indistinguishable to callers.
//!
//! # I/O, clock, and environment
//!
//! The crate performs no I/O, reads no clock, and reads no environment variables; the only
//! exceptions are `cfg` and the platform APIs themselves. Hardware handles are owned by the
//! key store object and released when it is dropped.
//!
//! # Example
//!
//! Generate → read public key → sign → verify, using the in-memory backend:
//!
//! ```
//! # #[cfg(feature = "mock")]
//! # fn demo() -> Result<(), qualia_dik::Error> {
//! use qualia_dik::{DeviceKeyStore, device};
//! # use qualia_dik::MockKeyStore;
//!
//! let store = MockKeyStore::new();
//! let signer = store.create("my-device")?;
//!
//! println!("device id: {}", signer.public_key().device_id());
//!
//! let message = b"a message to sign";
//! let signature = signer.sign(message)?;
//!
//! device::verify(signer.public_key(), message, &signature)?;
//! # Ok(())
//! # }
//! ```
//!
//! The public key is not a secret and may be propagated freely. Verification needs neither
//! the key store nor the private key, which is what makes the public-key side usable on its
//! own.
//!
//! `MockKeyStore` exists only under the `mock` feature: it is a path with no hardware
//! protection and is therefore off by default in production builds. To run this example
//! locally:
//!
//! ```console
//! cargo test --doc --features mock
//! ```
//!
//! Without that feature `cargo test --doc` still passes, because the whole example is
//! compiled out by the `cfg`.
//!
//! To obtain the real backend of the current platform **without** enabling `mock`, use
//! [`keystore::PlatformKeyStore`].

#![warn(missing_docs)]
#![warn(clippy::missing_docs_in_private_items)]
#![deny(unsafe_op_in_unsafe_fn)]

pub mod device;
mod error;
pub mod keystore;

pub use device::{DEVICE_ID_LEN, DeviceId, DevicePublicKey, DeviceSignature};
pub use error::{Error, Result};

pub use keystore::{Backend, DeviceKeyStore, DeviceSigner, KeyStoreError};

#[cfg(any(test, feature = "mock"))]
pub use keystore::MockKeyStore;

/// Whether this platform has an implemented hardware key store backend.
///
/// Callers (UI in particular) can use this to tell the user that without hardware
/// protection the device identity key is held in software, which lowers its security.
/// **This function does not probe whether hardware is actually usable** — that would require
/// opening a key store; it answers "does this platform have an implementation".
///
/// For the runtime situation, use [`DeviceKeyStore::backend`].
///
/// Only Windows returns `true` today. On unimplemented platforms the function returns
/// `false`, and every operation of [`keystore::PlatformKeyStore`] returns
/// [`Error::UnsupportedPlatform`] — there is **no** fallback to a software key.
#[must_use]
pub const fn platform_backend_is_implemented() -> bool {
    cfg!(target_os = "windows")
}
