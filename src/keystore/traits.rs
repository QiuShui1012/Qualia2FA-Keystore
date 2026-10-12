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

//! The hardware key store abstraction.
//!
//! The device data types and signature verification live in the core crate
//! because they are pure logic; the traits and their platform implementations
//! live here because they are platform specific. The dependency direction is one
//! way: this crate depends on the core crate.

use crate::device::{DevicePublicKey, DeviceSignature};
use crate::{Error, Result};

/// The two length constants are used only by `signature_from_raw` and
/// `public_key_from_sec1`, which compile under the same `cfg` as this import.
/// The two `cfg`s must stay identical: a library build for Linux or Android drops
/// those functions, and an unused import fails the build under `-D warnings`.
#[cfg(any(test, feature = "mock", target_os = "windows"))]
use crate::device::{PUBLIC_KEY_LEN, SIGNATURE_LEN};

/// Length of a P-256 digest (SHA-256), in bytes.
///
/// Hardware signing interfaces take a digest, not a message (`NCryptSignHash` on
/// Windows CNG, `Signature.update` on Android). SHA-256 is the standard pairing
/// for ECDSA on P-256, so this length is a property of the curve rather than a
/// configuration option.
pub const DIGEST_LEN: usize = 32;

/// The kind of backend that holds the device identity key.
///
/// The value is recorded in the vault and shown in the UI, so it has to stay
/// stable: new variants are appended, existing ones never change meaning.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum Backend {
    /// The private key lives inside a TPM 2.0 and cannot be exported.
    Tpm,
    /// The private key lives inside the macOS Secure Enclave and cannot be exported.
    SecureEnclave,
    /// The private key lives inside the Android Keystore or StrongBox and cannot be exported.
    AndroidKeystore,
    /// The private key is protected by an operating system software key store,
    /// such as the Windows software KSP.
    ///
    /// The private key exists **in software**. It is normally still protected by
    /// the user account and DPAPI, but that is not hardware protection: an
    /// attacker with administrator rights or disk access can take it. The UI has
    /// to tell the user before critical operations.
    Software,
    /// No backend is available, either because this platform has no
    /// implementation or because the hardware cannot be used.
    Unavailable,
}

impl Backend {
    /// Whether the private key is held by hardware.
    ///
    /// "The key is in the operating system key store" and "the private key cannot
    /// leave hardware" look the same to a user but are different properties. This
    /// method forces a caller to state which one it needs.
    #[must_use]
    pub const fn is_hardware_backed(self) -> bool {
        matches!(
            self,
            Self::Tpm | Self::SecureEnclave | Self::AndroidKeystore
        )
    }

    /// A stable short name for the UI and for logs.
    ///
    /// Unlike `Debug`, which is an implementation detail, this name may be
    /// persisted (for example in vault metadata) and cannot change afterwards.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Tpm => "tpm",
            Self::SecureEnclave => "secure-enclave",
            Self::AndroidKeystore => "android-keystore",
            Self::Software => "software",
            Self::Unavailable => "unavailable",
        }
    }
}

/// A device identity signer: it signs a message and reports the matching public key.
///
/// # There is no "export private key"
///
/// An implementation that can export the private key does not satisfy this
/// interface, because a private key that cannot leave the platform is the point
/// of a hardware key store. A platform that needs an exportable key gets a
/// different type, so the caller sees in the type system what it gives up.
///
/// # `Debug` is required
///
/// Diagnostics need it, and so does usability: helpers such as `expect_err` on a
/// `Result<Box<dyn DeviceSigner>, _>` are unavailable without it. Implementations
/// write `Debug` by hand instead of deriving it, because the type may hold
/// platform handles or private key material; the implementations in this crate
/// print only the backend kind and the device id.
///
/// # Signing and public key lookup are separate methods
///
/// Reading the public key is a pure read and may work while the device is locked;
/// signing may require user presence (Touch ID, Windows Hello). A single method
/// for both would raise the authentication prompt just to read a public key.
pub trait DeviceSigner: core::fmt::Debug {
    /// The backend that holds this identity.
    fn backend(&self) -> Backend;

    /// The SEC1 uncompressed public key of this identity (65 bytes).
    ///
    /// The public key is not secret: it can be shared, compared and logged.
    fn public_key(&self) -> &DevicePublicKey;

    /// Signs a message and returns the raw `r||s`.
    ///
    /// The implementation hashes with SHA-256 first and hands the digest to the
    /// hardware, matching the convention of [`crate::device::verify`].
    ///
    /// # Errors
    ///
    /// Hardware refusal (a cancelled biometric prompt, for example), a deleted
    /// key, or an unavailable backend.
    fn sign(&self, message: &[u8]) -> Result<DeviceSignature> {
        let digest = sha256(message);
        self.sign_digest(&digest)
    }

    /// Signs an already computed SHA-256 digest and returns the raw `r||s`.
    ///
    /// Use it when the hash of the content already exists elsewhere, for example
    /// in a protocol message that carries a digest. Most callers want
    /// [`DeviceSigner::sign`].
    ///
    /// # Errors
    ///
    /// [`Error::InvalidDigestLength`] when the digest is not [`DIGEST_LEN`] long.
    fn sign_digest(&self, digest: &[u8]) -> Result<DeviceSignature>;
}

/// Holder of one device identity key pair: create it, open it, delete it.
///
/// Separate from [`DeviceSigner`] because the lifetimes differ: a signer is one
/// identity, while a key store is every identity on this machine. The UI usually
/// needs only the former.
pub trait DeviceKeyStore: core::fmt::Debug {
    /// The backend this key store actually uses.
    ///
    /// The value is probed at run time and may be weaker than what the platform
    /// could provide: a Windows machine without a TPM reports
    /// [`Backend::Software`], and a platform without an implementation reports
    /// [`Backend::Unavailable`].
    fn backend(&self) -> Backend;

    /// Opens the existing device identity stored under `label`.
    ///
    /// Each label is an independent identity, for example one per account.
    ///
    /// # Errors
    ///
    /// [`Error::KeyNotFound`] when the label does not exist. This method never
    /// creates a key: opening and creating are separate operations, and one that
    /// did both would turn "I only wanted to read it" into a new identity.
    fn open(&self, label: &str) -> Result<Box<dyn DeviceSigner>>;

    /// Creates a device identity under `label`.
    ///
    /// # Errors
    ///
    /// The "already exists" variant of [`Error`] when the label is taken; the
    /// exact variant is backend specific. Use [`DeviceKeyStore::open_or_create`]
    /// for open-or-create semantics.
    fn create(&self, label: &str) -> Result<Box<dyn DeviceSigner>>;

    /// Deletes the identity stored under `label`.
    ///
    /// # Warning
    ///
    /// The device can never again prove that it is the same device. Identities
    /// recorded on peer devices become unverifiable orphans and need a new
    /// pairing, so the caller has to ask the user first.
    ///
    /// # Errors
    ///
    /// [`Error::KeyNotFound`] when the label does not exist.
    fn delete(&self, label: &str) -> Result<()>;

    /// Opens `label`, creating it when it does not exist.
    ///
    /// The default implementation covers the race between the two steps: another
    /// process may create the same label in between, and creating then fails with
    /// an "already exists" error. For open-or-create that is the desired outcome,
    /// so the key is opened again instead of reporting a failure.
    fn open_or_create(&self, label: &str) -> Result<Box<dyn DeviceSigner>> {
        match self.open(label) {
            Ok(signer) => Ok(signer),
            Err(Error::KeyNotFound { .. }) => match self.create(label) {
                Ok(signer) => Ok(signer),
                Err(Error::KeyAlreadyExists { .. }) => self.open(label),
                Err(other) => Err(other),
            },
            Err(other) => Err(other),
        }
    }
}

/// Computes a SHA-256 digest.
///
/// A single definition of the hash used in message mode: signing and verification
/// have to agree on it, and two copies would drift apart.
#[must_use]
pub fn sha256(message: &[u8]) -> [u8; DIGEST_LEN] {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(message);
    let mut out = [0_u8; DIGEST_LEN];
    out.copy_from_slice(&digest);
    out
}

/// Converts the raw `r||s` bytes returned by hardware into a [`DeviceSignature`].
///
/// A wrong length is an error rather than a truncation or a padding: it means the
/// backend is wrong, and hiding it only moves the problem somewhere harder to
/// diagnose.
///
/// Compiled only when a backend is, hence the same `cfg`; otherwise a library
/// build reports an unused function.
#[cfg(any(test, feature = "mock", target_os = "windows"))]
pub(crate) fn signature_from_raw(raw: &[u8]) -> Result<DeviceSignature> {
    if raw.len() != SIGNATURE_LEN {
        return Err(Error::InvalidSignatureLength {
            expected: SIGNATURE_LEN,
            actual: raw.len(),
        });
    }
    DeviceSignature::from_bytes(raw)
}

/// Converts the SEC1 uncompressed point returned by hardware into a
/// [`DevicePublicKey`].
///
/// Compiled under the same `cfg` as [`signature_from_raw`].
#[cfg(any(test, feature = "mock", target_os = "windows"))]
pub(crate) fn public_key_from_sec1(bytes: &[u8]) -> Result<DevicePublicKey> {
    if bytes.len() != PUBLIC_KEY_LEN {
        return Err(Error::InvalidPublicKey {
            reason: "长度不是 65 字节的 SEC1 未压缩点",
        });
    }
    DevicePublicKey::from_sec1_bytes(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Only backends that really hold the key in hardware count as hardware-backed.
    #[test]
    fn hardware_backed_classification() {
        assert!(Backend::Tpm.is_hardware_backed());
        assert!(Backend::SecureEnclave.is_hardware_backed());
        assert!(Backend::AndroidKeystore.is_hardware_backed());
        assert!(!Backend::Software.is_hardware_backed());
        assert!(!Backend::Unavailable.is_hardware_backed());
    }

    /// The persisted names are unique and lower case, because they may be written
    /// into vault metadata.
    #[test]
    fn backend_names_are_stable_and_unique() {
        let all = [
            Backend::Tpm,
            Backend::SecureEnclave,
            Backend::AndroidKeystore,
            Backend::Software,
            Backend::Unavailable,
        ];
        let mut names: Vec<&str> = all.iter().map(|b| b.as_str()).collect();
        names.sort_unstable();
        let before = names.len();
        names.dedup();
        assert_eq!(names.len(), before, "后端名有重复");
        for name in names {
            assert!(!name.is_empty());
            assert!(
                name.chars().all(|c| c.is_ascii_lowercase() || c == '-'),
                "{name} 不是适合持久化的小写形式"
            );
        }
    }

    /// `sha256` matches the known vector for the empty input.
    #[test]
    fn sha256_matches_known_vector() {
        let digest = sha256(b"");
        let expected = [
            0xE3, 0xB0, 0xC4, 0x42, 0x98, 0xFC, 0x1C, 0x14, 0x9A, 0xFB, 0xF4, 0xC8, 0x99, 0x6F,
            0xB9, 0x24, 0x27, 0xAE, 0x41, 0xE4, 0x64, 0x9B, 0x93, 0x4C, 0xA4, 0x95, 0x99, 0x1B,
            0x78, 0x52, 0xB8, 0x55,
        ];
        assert_eq!(digest, expected);
    }

    /// A wrong signature length is rejected, never truncated or padded.
    #[test]
    fn signature_from_raw_rejects_wrong_length() {
        assert!(signature_from_raw(&[]).is_err());
        assert!(signature_from_raw(&[0_u8; SIGNATURE_LEN - 1]).is_err());
        assert!(signature_from_raw(&[0_u8; SIGNATURE_LEN + 1]).is_err());
        assert!(signature_from_raw(&[0_u8; SIGNATURE_LEN]).is_ok());
    }

    /// A wrong public key length is rejected.
    #[test]
    fn public_key_from_sec1_rejects_wrong_length() {
        assert!(public_key_from_sec1(&[]).is_err());
        assert!(public_key_from_sec1(&[0x04; PUBLIC_KEY_LEN - 1]).is_err());
        assert!(public_key_from_sec1(&[0x04; PUBLIC_KEY_LEN + 1]).is_err());
    }
}
