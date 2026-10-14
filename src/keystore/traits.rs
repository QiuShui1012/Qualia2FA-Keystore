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
#[cfg(any(test, feature = "mock", target_os = "windows", target_os = "android"))]
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

/// Length of the application's master key, in bytes.
///
/// The master key is **opaque material**: this crate never derives anything from it, never
/// interprets it and never compares it for anything but equality. It is passed to a platform
/// key store and taken back unchanged, so the only thing this crate has to know about it is
/// its length — the length the application's vault layer uses.
pub const MASTER_KEY_LEN: usize = 32;

/// The application's master key: [`MASTER_KEY_LEN`] bytes of opaque material.
///
/// # `Debug` never shows the material
///
/// A master key opens every vault of an account, so it must not reach a log through a
/// `#[derive(Debug)]` on some enclosing type. `Debug` is implemented by hand and prints the
/// length only; the bytes are reachable only through [`MasterKey::as_bytes`], which a caller
/// has to ask for explicitly.
///
/// # The material is wiped on drop
///
/// `Drop` overwrites the bytes with `zeroize`, the same crate the software signer of the
/// `mock` backend uses for its private key. This does not make the type a secure container
/// (copies made by the caller are the caller's business), it removes the one copy this crate
/// owns.
///
/// # There is no `PartialEq`
///
/// Comparing secrets has to be constant time, and a derived `==` is not. A caller that has
/// to compare takes [`MasterKey::as_bytes`] and does the comparison itself, with a
/// constant-time routine of its own.
#[derive(Clone)]
pub struct MasterKey {
    /// The material, overwritten in `Drop`.
    bytes: [u8; MASTER_KEY_LEN],
}

impl MasterKey {
    /// Wraps [`MASTER_KEY_LEN`] bytes as a master key.
    ///
    /// Infallible: any byte string of the right length is valid master key material, because
    /// nothing in this crate interprets it.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; MASTER_KEY_LEN]) -> Self {
        Self { bytes }
    }

    /// The material.
    ///
    /// The returned reference is not secret-aware: a caller that logs it, formats it or
    /// compares it with `==` has taken over the responsibility for it.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; MASTER_KEY_LEN] {
        &self.bytes
    }
}

/// Prints the length only, never the material.
impl core::fmt::Debug for MasterKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("MasterKey")
            .field("len", &MASTER_KEY_LEN)
            .finish_non_exhaustive()
    }
}

/// Wipes the material when the value goes away.
impl Drop for MasterKey {
    fn drop(&mut self) {
        use p256::elliptic_curve::zeroize::Zeroize;
        self.bytes.zeroize();
    }
}

/// The wrapped form of a master key: opaque bytes for the caller to persist.
///
/// This is what a [`WrappedMasterKeyStore`] hands back. The bytes are whatever that store's
/// platform produces — a sealed blob — and they are meaningless to this crate: it never
/// looks inside, and only the store that produced them (holding the key-encryption key in
/// its platform hardware) can turn them back into the master key. The wrapped form is
/// therefore **not secret** in the sense the master key is: an attacker who copies the bytes
/// still needs the platform key that is not in them.
///
/// `Debug` prints the length only. The blob is not a secret, but a debug line is not a place
/// to accumulate it either, and the length is enough to tell "no blob" from "a blob".
#[derive(Clone)]
pub struct WrappedMasterKey {
    /// The bytes as the platform produced them.
    bytes: Vec<u8>,
}

impl WrappedMasterKey {
    /// Takes ownership of bytes a platform store produced.
    #[must_use]
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        Self { bytes }
    }

    /// The bytes to persist, verbatim.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Consumes the value and returns the bytes to persist.
    #[must_use]
    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }
}

/// Prints the length only.
impl core::fmt::Debug for WrappedMasterKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("WrappedMasterKey")
            .field("len", &self.bytes.len())
            .finish_non_exhaustive()
    }
}

/// The master key held **directly** by the platform key store.
///
/// # What "directly" means
///
/// The store is given the material and keeps it; the caller persists nothing of its own for
/// this key. Reading it back returns the same bytes.
///
/// # This is one of two forms, and the caller picks by constructor
///
/// [`WrappedMasterKeyStore`] is the other one. There is no flag and no mode argument: a
/// caller that wants the wrapped form reaches for a different type, and a backend that
/// implements one form cannot silently answer for the other.
///
/// # Honest backends
///
/// [`DirectMasterKeyStore::backend`] reports the platform key store that actually answered,
/// exactly as [`DeviceKeyStore::backend`] does. A platform that cannot hold the material
/// reports [`Error::UnsupportedPlatform`] instead of substituting something weaker.
///
/// # `label`
///
/// A label names one master key among several (one per account, for example) and follows the
/// same rules as the device identity label: ASCII letters, digits, `-`, `_` and `.`, at most
/// 128 bytes. The exact rejection is backend specific; the error is
/// [`Error::InvalidKeyLabel`].
///
/// # Storing replaces
///
/// Storing under a label that already holds material replaces it. The caller owns the vault
/// files, and a recovery or re-pairing legitimately replaces the master key; refusing would
/// leave the caller with no way to follow its own data.
pub trait DirectMasterKeyStore: core::fmt::Debug {
    /// The platform key store that holds the material, as probed at run time.
    fn backend(&self) -> Backend;

    /// Stores `key` under `label`, replacing what was there.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidKeyLabel`] for an unusable label, and a backend specific error when
    /// the platform refuses to hold the material — including the case where it accepts it
    /// but will not hand it back, which is not a usable store for this form
    /// ([`Error::KeyNotExportable`]).
    fn store(&self, label: &str, key: &MasterKey) -> Result<()>;

    /// Reads the master key stored under `label`.
    ///
    /// # Errors
    ///
    /// [`Error::KeyNotFound`] when the label holds nothing. The method never creates or
    /// replaces anything.
    fn load(&self, label: &str) -> Result<MasterKey>;

    /// Deletes the master key stored under `label`.
    ///
    /// # Warning
    ///
    /// Every vault that was opened with this key becomes unreadable on this device unless
    /// the key exists elsewhere (a recovery key, another device). The caller has to ask the
    /// user first.
    ///
    /// # Errors
    ///
    /// [`Error::KeyNotFound`] when the label holds nothing.
    fn delete(&self, label: &str) -> Result<()>;
}

/// The master key held **wrapped** by a non-exportable platform key.
///
/// # What "wrapped" means
///
/// The store generates a key-encryption key (KEK) inside the platform key store. The KEK is
/// **not exportable**: it cannot be read out of the store, by this crate or by anyone else.
/// The store uses it to wrap the master key, and what is left over is the wrapped form, which
/// the caller persists.
///
/// Only the wrapped bytes are ever persisted; the master key itself is not, and the KEK
/// never leaves the platform. Stealing the persisted bytes is therefore not the same as
/// stealing the master key: the thief also needs the platform key store entry, which does not
/// leave the device.
///
/// # The KEK and its operations are not in this interface
///
/// There is no method that encrypts, decrypts, wraps, unwraps or returns the KEK. Wrapping is
/// the internal design of this form: the caller stores a master key and gets back the bytes
/// to keep, and that is the whole interface. A caller that needs a raw wrapping primitive
/// wants a different crate.
///
/// # The bytes belong to one key store entry
///
/// [`WrappedMasterKeyStore::load`] has to be given the bytes that the same store produced for
/// the same label. Bytes from another label, from another device, or bytes that were damaged
/// in storage fail with an error; they never yield a master key that merely differs.
///
/// # Honest backends
///
/// As in [`DirectMasterKeyStore`]: [`WrappedMasterKeyStore::backend`] reports what actually
/// answered, and a platform without an implementation returns
/// [`Error::UnsupportedPlatform`].
///
/// # Storing keeps the KEK
///
/// Storing under an existing label wraps with the KEK that is already there, so previously
/// persisted bytes keep unwrapping. Deleting the label deletes the KEK, and every blob
/// wrapped with it becomes unusable — which is the intent.
pub trait WrappedMasterKeyStore: core::fmt::Debug {
    /// The platform key store that holds the key-encryption key, as probed at run time.
    fn backend(&self) -> Backend;

    /// Wraps `key` under `label` and returns the bytes for the caller to persist.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidKeyLabel`] for an unusable label, and a backend specific error when
    /// the platform cannot generate or use a key-encryption key.
    fn store(&self, label: &str, key: &MasterKey) -> Result<WrappedMasterKey>;

    /// Unwraps `wrapped` with the key-encryption key stored under `label`.
    ///
    /// # Errors
    ///
    /// [`Error::KeyNotFound`] when the label holds no key-encryption key, and
    /// [`Error::InvalidWrappedKey`] when the bytes do not unwrap — a damaged blob, or one
    /// produced by another key store entry. The method never returns bytes it could not
    /// authenticate.
    fn load(&self, label: &str, wrapped: &WrappedMasterKey) -> Result<MasterKey>;

    /// Deletes the key-encryption key stored under `label`.
    ///
    /// # Warning
    ///
    /// Every blob wrapped with that KEK becomes permanently unusable, which is the point of
    /// the operation: it is how a device forgets a master key.
    ///
    /// # Errors
    ///
    /// [`Error::KeyNotFound`] when the label holds no key-encryption key.
    fn delete(&self, label: &str) -> Result<()>;
}

/// Compares two byte strings in constant time.
///
/// Used where this crate has to check that a platform handed back exactly the material it was
/// given. `subtle` is already a dependency through `p256`, and this is the same crate
/// implementations use for secret comparison; a hand written loop would be at the mercy of
/// the optimiser.
///
/// Compiled under the same `cfg` as the backends that call it: on a platform with no such
/// backend the function would be dead code, which `-D warnings` treats as an error.
#[cfg(any(test, feature = "mock", target_os = "windows", target_os = "android"))]
#[must_use]
pub(crate) fn secrets_equal(a: &[u8], b: &[u8]) -> bool {
    use p256::elliptic_curve::subtle::ConstantTimeEq;
    a.ct_eq(b).into()
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
#[cfg(any(test, feature = "mock", target_os = "windows", target_os = "android"))]
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
#[cfg(any(test, feature = "mock", target_os = "windows", target_os = "android"))]
pub(crate) fn public_key_from_sec1(bytes: &[u8]) -> Result<DevicePublicKey> {
    if bytes.len() != PUBLIC_KEY_LEN {
        return Err(Error::InvalidPublicKey {
            reason: "the length is not that of a 65-byte uncompressed SEC1 point",
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
        assert_eq!(names.len(), before, "the backend names contain duplicates");
        for name in names {
            assert!(!name.is_empty());
            assert!(
                name.chars().all(|c| c.is_ascii_lowercase() || c == '-'),
                "{name} is not a lower-case form suitable for persistence"
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

    /// A master key keeps exactly the bytes it was built from.
    #[test]
    fn master_key_round_trips_its_bytes() {
        let bytes = [0xA5_u8; MASTER_KEY_LEN];
        let key = MasterKey::from_bytes(bytes);
        assert_eq!(key.as_bytes(), &bytes);
    }

    /// `Debug` of a master key must not contain the material in any spelling.
    ///
    /// Both the decimal and the hexadecimal rendering are checked, because either one is
    /// enough to read the key out of a log.
    #[test]
    fn master_key_debug_does_not_show_the_material() {
        let bytes = [0x5A_u8; MASTER_KEY_LEN];
        let text = format!("{:?}", MasterKey::from_bytes(bytes));
        assert!(
            !text.contains("90") && !text.contains("5A") && !text.contains("5a"),
            "the debug output of a master key shows its material: {text}"
        );
        assert!(
            text.contains("MasterKey"),
            "the debug output does not name the type: {text}"
        );
    }

    /// A wrapped blob is not secret, but its debug output is still only a length.
    #[test]
    fn wrapped_master_key_debug_shows_only_the_length() {
        let wrapped = WrappedMasterKey::from_bytes(vec![0x33_u8; 20]);
        let text = format!("{wrapped:?}");
        assert!(text.contains("20"), "the length is missing: {text}");
        assert!(
            !text.contains("51") && !text.contains("33"),
            "the debug output shows the bytes: {text}"
        );
        assert_eq!(wrapped.as_bytes().len(), 20);
        assert_eq!(wrapped.into_bytes().len(), 20);
    }

    /// The constant-time comparison agrees with `==`, including on different lengths.
    #[test]
    fn secrets_equal_matches_equality() {
        assert!(secrets_equal(b"abc", b"abc"));
        assert!(secrets_equal(b"", b""));
        assert!(!secrets_equal(b"abc", b"abd"));
        assert!(!secrets_equal(b"abc", b"ab"));
        assert!(!secrets_equal(b"ab", b"abc"));
    }
}
