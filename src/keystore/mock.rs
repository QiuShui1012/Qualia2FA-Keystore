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

//! An in-memory software key store, for tests only.
//!
//! It exists so that the protocol layer (registration, login, challenge-response)
//! can be tested completely on CI and on machines without a TPM. Properties such
//! as "a replay is rejected", "a forged public key is rejected" and "tampering is
//! rejected" need repeated verification, and they would stay uncovered if the
//! tests only ran on a developer machine with hardware.
//!
//! It must never appear on a production path: its "hardware" is a `BTreeMap` and
//! the private keys are ordinary bytes in memory, so a device identity built on it
//! has no hardware protection while looking perfectly normal.
//!
//! Three properties keep it out of the way:
//!
//! - the module compiles only under `cfg(test)` or the explicit `mock` feature;
//! - it reports [`Backend::Software`], and [`MockKeyStore::backend`] says so again
//!   in its own documentation;
//! - it keeps no persistence: keys live in the process only, so code that forgot
//!   to swap the mock out fails right after a restart instead of running on with a
//!   software key.
//!
//! Private keys are wiped with `zeroize` on drop. Real backends have nothing to
//! wipe, because their private keys never enter this process.
//!
//! # Master keys
//!
//! The store implements both ways of holding the application's master key, so that the
//! protocol layer can be tested without a platform:
//!
//! - [`MockDirectMasterKeyStore`] keeps the material in a map;
//! - [`MockWrappedMasterKeyStore`] keeps a key-encryption key per label in a map, wraps the
//!   material with it and hands the ciphertext to the caller, exactly as a platform store
//!   does.
//!
//! Neither has hardware protection, and neither claims any: both report
//! [`Backend::Software`]. The wrapping of the second one is a test double built from SHA-256
//! (HMAC per RFC 2104 §2) and must not be mistaken for a delivered cipher — a real backend
//! wraps inside the platform, and the platform's implementation is the one that matters.

use crate::device::{DevicePublicKey, DeviceSignature};
use crate::keystore::traits::DirectMasterKeyStore;
use crate::keystore::traits::{
    Backend, DIGEST_LEN, DeviceKeyStore, DeviceSigner, MASTER_KEY_LEN, MasterKey, WrappedMasterKey,
    WrappedMasterKeyStore, public_key_from_sec1, secrets_equal,
};
use crate::{Error, Result};
use p256::ecdsa::{Signature, SigningKey, signature::hazmat::PrehashSigner};
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

/// An in-memory software key store, for tests only.
///
/// Cloning shares the same key storage, which mirrors how a real key store shows
/// the same keys to every handle on one machine, so properties such as "the
/// identity survives closing and reopening" can be tested.
#[derive(Clone, Default)]
pub struct MockKeyStore {
    /// Logical name → private key, behind `Arc<Mutex<_>>` so clones share it.
    keys: Arc<Mutex<BTreeMap<String, SigningKey>>>,
}

impl core::fmt::Debug for MockKeyStore {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let count = self.keys.lock().map(|k| k.len()).unwrap_or(0);
        f.debug_struct("MockKeyStore")
            .field("key_count", &count)
            .finish_non_exhaustive()
    }
}

impl MockKeyStore {
    /// Creates an empty software key store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

impl DeviceKeyStore for MockKeyStore {
    /// Reports [`Backend::Software`].
    ///
    /// It never reports [`Backend::Tpm`]: a mock that looked like hardware would
    /// send every branch on `backend()` down a different path in tests than in
    /// production.
    fn backend(&self) -> Backend {
        Backend::Software
    }

    /// Opens an identity, or fails with [`Error::KeyNotFound`].
    ///
    /// The signer owns a copy of the private scalar, so signing never holds the
    /// store's lock.
    fn open(&self, label: &str) -> Result<Box<dyn DeviceSigner>> {
        let keys = self.keys.lock().map_err(|_| Error::Hardware {
            operation: "MockKeyStore mutex poisoned",
            code: 0,
        })?;
        let signing = keys.get(label).ok_or_else(|| Error::KeyNotFound {
            label: label.to_string(),
        })?;

        let bytes = signing.to_bytes();
        let owned = SigningKey::from_slice(&bytes).map_err(|_| Error::Hardware {
            operation: "MockKeyStore failed to copy the private key",
            code: 0,
        })?;
        drop(keys);

        Ok(Box::new(MockSigner::new(owned, label)))
    }

    /// Creates a key, or fails when the label is taken.
    ///
    /// An existing identity is never overwritten, matching the Windows backend: a
    /// silent replacement would swap the device identity, which is the hardest
    /// class of bug to diagnose.
    fn create(&self, label: &str) -> Result<Box<dyn DeviceSigner>> {
        let mut keys = self.keys.lock().map_err(|_| Error::Hardware {
            operation: "MockKeyStore mutex poisoned",
            code: 0,
        })?;
        if keys.contains_key(label) {
            return Err(Error::Hardware {
                operation: "MockKeyStore::create (a key with this label already exists; overwriting is refused)",
                code: 0,
            });
        }
        let signing = SigningKey::from_slice(&random_scalar()?).map_err(|_| Error::Hardware {
            operation: "MockKeyStore failed to generate a scalar",
            code: 0,
        })?;
        let public = public_key_from_signing(&signing)?;
        keys.insert(label.to_string(), signing);
        drop(keys);

        let _ = public;
        self.open(label)
    }

    fn delete(&self, label: &str) -> Result<()> {
        let mut keys = self.keys.lock().map_err(|_| Error::Hardware {
            operation: "MockKeyStore mutex poisoned",
            code: 0,
        })?;
        if keys.remove(label).is_none() {
            return Err(Error::KeyNotFound {
                label: label.to_string(),
            });
        }
        Ok(())
    }
}

/// Draws 32 bytes from the OS random source to use as a private scalar.
///
/// `p256`'s `from_slice` rejects zero and values at or above the group order; that
/// has probability around 2^-128 and still has to be handled rather than panicked
/// on.
fn random_scalar() -> Result<[u8; 32]> {
    let mut bytes = [0_u8; 32];
    getrandom::fill(&mut bytes).map_err(|_| Error::Hardware {
        operation: "MockKeyStore could not obtain randomness from the OS",
        code: 0,
    })?;
    Ok(bytes)
}

/// Derives the SEC1 uncompressed public key from a software private key.
fn public_key_from_signing(signing: &SigningKey) -> Result<DevicePublicKey> {
    let sec1 = signing.verifying_key().to_sec1_point(false);
    public_key_from_sec1(sec1.as_bytes())
}

/// A software signer.
pub struct MockSigner {
    /// The software private key, wiped by `zeroize` on drop.
    signing: SigningKey,
    /// The logical name of this identity.
    label: String,
    /// The public key, derived once at construction.
    public_key: DevicePublicKey,
}

impl core::fmt::Debug for MockSigner {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("MockSigner")
            .field("label", &self.label)
            .field("device_id", &self.public_key.device_id())
            .finish_non_exhaustive()
    }
}

impl MockSigner {
    /// Builds a signer around a software private key.
    ///
    /// A key generated here is never an invalid point, so the fallback of
    /// [`unreachable_public_key`] is unreachable in practice; it exists because
    /// the crate may not panic.
    fn new(signing: SigningKey, label: &str) -> Self {
        let public_key =
            public_key_from_signing(&signing).unwrap_or_else(|_| unreachable_public_key());
        Self {
            signing,
            label: label.to_string(),
            public_key,
        }
    }
}

/// Placeholder public key for the unreachable branch above.
///
/// A fixed point that is *not* on P-256 cannot be used, since it is exactly what
/// `from_sec1_bytes` rejects. This returns a valid fixed point instead — the SEC1
/// encoding of the generator `G`. It parses, but it does not match our private
/// key, so a signature made through this path fails verification immediately
/// rather than hiding the problem.
fn unreachable_public_key() -> DevicePublicKey {
    const GENERATOR: [u8; 65] = [
        0x04, 0x6B, 0x17, 0xD1, 0xF2, 0xE1, 0x2C, 0x42, 0x47, 0xF8, 0xBC, 0xE6, 0xE5, 0x63, 0xA4,
        0x40, 0xF2, 0x77, 0x03, 0x7D, 0x81, 0x2D, 0xEB, 0x33, 0xA0, 0xF4, 0xA1, 0x39, 0x45, 0xD8,
        0x98, 0xC2, 0x96, 0x4F, 0xE3, 0x42, 0xE2, 0xFE, 0x1A, 0x7F, 0x9B, 0x8E, 0xE7, 0xEB, 0x4A,
        0x7C, 0x0F, 0x9E, 0x16, 0x2B, 0xCE, 0x33, 0x57, 0x6B, 0x31, 0x5E, 0xCE, 0xCB, 0xB6, 0x40,
        0x68, 0x37, 0xBF, 0x51, 0xF5,
    ];
    public_key_from_sec1(&GENERATOR).unwrap_or_else(|_| {
        unreachable!("the P-256 generator does not parse; the p256 implementation is broken")
    })
}

impl DeviceSigner for MockSigner {
    fn backend(&self) -> Backend {
        Backend::Software
    }

    fn public_key(&self) -> &DevicePublicKey {
        &self.public_key
    }

    /// Signs a digest with the pre-hash interface, matching the hardware backends,
    /// which also receive a digest.
    fn sign_digest(&self, digest: &[u8]) -> Result<DeviceSignature> {
        if digest.len() != DIGEST_LEN {
            return Err(Error::InvalidDigestLength {
                expected: DIGEST_LEN,
                actual: digest.len(),
            });
        }
        let signature: Signature =
            self.signing
                .sign_prehash(digest)
                .map_err(|_| Error::Hardware {
                    operation: "MockKeyStore signing failed",
                    code: 0,
                })?;
        crate::keystore::traits::signature_from_raw(&signature.to_bytes())
    }
}

/// An in-memory key store holding the master key **directly**, for tests only.
///
/// The map is the whole "key store": the material sits in ordinary memory, so this type
/// offers no protection whatsoever and reports [`Backend::Software`]. It exists so that the
/// callers of the direct form can be tested on a machine without platform hardware, with the
/// same three operations and the same errors a real store produces.
///
/// Cloning shares the same storage, mirroring how a real key store shows the same keys to
/// every handle on one machine.
#[derive(Clone, Default)]
pub struct MockDirectMasterKeyStore {
    /// Label → material, behind `Arc<Mutex<_>>` so clones share it.
    keys: Arc<Mutex<BTreeMap<String, MasterKey>>>,
}

/// Prints the number of stored keys only, never a label's material.
impl core::fmt::Debug for MockDirectMasterKeyStore {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let count = self.keys.lock().map(|k| k.len()).unwrap_or(0);
        f.debug_struct("MockDirectMasterKeyStore")
            .field("key_count", &count)
            .finish_non_exhaustive()
    }
}

impl MockDirectMasterKeyStore {
    /// Creates an empty store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

impl DirectMasterKeyStore for MockDirectMasterKeyStore {
    /// Reports [`Backend::Software`]: the material is in this process's memory.
    fn backend(&self) -> Backend {
        Backend::Software
    }

    /// Inserts the material, replacing whatever was stored under `label`.
    fn store(&self, label: &str, key: &MasterKey) -> Result<()> {
        let mut keys = self.lock()?;
        keys.insert(label.to_string(), key.clone());
        Ok(())
    }

    /// Copies the material out, or reports [`Error::KeyNotFound`].
    fn load(&self, label: &str) -> Result<MasterKey> {
        let keys = self.lock()?;
        keys.get(label).cloned().ok_or_else(|| Error::KeyNotFound {
            label: label.to_string(),
        })
    }

    /// Removes the entry, or reports [`Error::KeyNotFound`].
    fn delete(&self, label: &str) -> Result<()> {
        let mut keys = self.lock()?;
        if keys.remove(label).is_none() {
            return Err(Error::KeyNotFound {
                label: label.to_string(),
            });
        }
        Ok(())
    }
}

impl MockDirectMasterKeyStore {
    /// Locks the map, turning a poisoned mutex into an error rather than a panic.
    fn lock(&self) -> Result<std::sync::MutexGuard<'_, BTreeMap<String, MasterKey>>> {
        self.keys.lock().map_err(|_| Error::Hardware {
            operation: "MockDirectMasterKeyStore mutex poisoned",
            code: 0,
        })
    }
}

/// An in-memory key store holding the master key **wrapped**, for tests only.
///
/// It generates a random key-encryption key per label on first use and keeps it in a map, so
/// the KEK is never handed out through any interface and the caller only ever sees the
/// wrapped bytes — the same shape a platform backend has. It reports
/// [`Backend::Software`]: nothing here is hardware protected.
///
/// The wrapping is a test double: a keystream derived from the KEK by HMAC-SHA256 hides the
/// material, and a second HMAC authenticates it, so a wrong KEK or a damaged blob fails
/// instead of yielding wrong bytes. A real backend wraps inside the platform key store.
#[derive(Clone, Default)]
pub struct MockWrappedMasterKeyStore {
    /// Label → key-encryption key, behind `Arc<Mutex<_>>` so clones share it.
    keks: Arc<Mutex<BTreeMap<String, MasterKey>>>,
}

/// Prints the number of stored keys only, never a key-encryption key.
impl core::fmt::Debug for MockWrappedMasterKeyStore {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let count = self.keks.lock().map(|k| k.len()).unwrap_or(0);
        f.debug_struct("MockWrappedMasterKeyStore")
            .field("kek_count", &count)
            .finish_non_exhaustive()
    }
}

impl MockWrappedMasterKeyStore {
    /// Creates an empty store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Locks the KEK map, turning a poisoned mutex into an error rather than a panic.
    fn lock(&self) -> Result<std::sync::MutexGuard<'_, BTreeMap<String, MasterKey>>> {
        self.keks.lock().map_err(|_| Error::Hardware {
            operation: "MockWrappedMasterKeyStore mutex poisoned",
            code: 0,
        })
    }
}

impl WrappedMasterKeyStore for MockWrappedMasterKeyStore {
    /// Reports [`Backend::Software`].
    fn backend(&self) -> Backend {
        Backend::Software
    }

    /// Wraps `key` with this label's KEK, generating the KEK on first use.
    fn store(&self, label: &str, key: &MasterKey) -> Result<WrappedMasterKey> {
        use std::collections::btree_map::Entry;

        let mut keks = self.lock()?;
        let kek = match keks.entry(label.to_string()) {
            Entry::Occupied(entry) => entry.into_mut(),
            Entry::Vacant(entry) => entry.insert(MasterKey::from_bytes(random_scalar()?)),
        };

        let mut nonce = [0_u8; MOCK_NONCE_LEN];
        getrandom::fill(&mut nonce).map_err(|_| Error::Hardware {
            operation: "MockWrappedMasterKeyStore could not obtain randomness from the OS",
            code: 0,
        })?;

        let mut sealed = [0_u8; MASTER_KEY_LEN];
        let keystream = hmac_sha256(kek.as_bytes(), &[KEYSTREAM_CONTEXT, &nonce].concat());
        for (out, (mask, byte)) in sealed
            .iter_mut()
            .zip(keystream.iter().zip(key.as_bytes().iter()))
        {
            *out = mask ^ byte;
        }
        let tag = hmac_sha256(kek.as_bytes(), &[TAG_CONTEXT, &nonce, &sealed].concat());

        let mut wrapped = Vec::with_capacity(MOCK_WRAPPED_LEN);
        wrapped.extend_from_slice(&nonce);
        wrapped.extend_from_slice(&sealed);
        wrapped.extend_from_slice(&tag);
        Ok(WrappedMasterKey::from_bytes(wrapped))
    }

    /// Unwraps `wrapped` with this label's KEK.
    ///
    /// The authentication tag is checked before anything is decrypted, so a blob that was
    /// damaged or produced by another KEK is rejected rather than turned into 32 bytes that
    /// merely look like a master key.
    fn load(&self, label: &str, wrapped: &WrappedMasterKey) -> Result<MasterKey> {
        let bytes = wrapped.as_bytes();
        if bytes.len() != MOCK_WRAPPED_LEN {
            return Err(Error::InvalidWrappedKey {
                reason: "the wrapped master key is not 96 bytes long",
                code: 0,
            });
        }
        let (nonce, rest) = bytes.split_at(MOCK_NONCE_LEN);
        let (sealed, tag) = rest.split_at(MASTER_KEY_LEN);

        let keks = self.lock()?;
        let kek = keks.get(label).ok_or_else(|| Error::KeyNotFound {
            label: label.to_string(),
        })?;

        let expected = hmac_sha256(kek.as_bytes(), &[TAG_CONTEXT, nonce, sealed].concat());
        if !secrets_equal(&expected, tag) {
            return Err(Error::InvalidWrappedKey {
                reason: "the authentication tag does not match (a damaged blob, or one wrapped by a different key-encryption key)",
                code: 0,
            });
        }

        let mut material = [0_u8; MASTER_KEY_LEN];
        let keystream = hmac_sha256(kek.as_bytes(), &[KEYSTREAM_CONTEXT, nonce].concat());
        for (out, (mask, byte)) in material.iter_mut().zip(keystream.iter().zip(sealed.iter())) {
            *out = mask ^ byte;
        }
        Ok(MasterKey::from_bytes(material))
    }

    /// Deletes the label's KEK, which makes every blob wrapped with it unusable.
    fn delete(&self, label: &str) -> Result<()> {
        let mut keks = self.lock()?;
        if keks.remove(label).is_none() {
            return Err(Error::KeyNotFound {
                label: label.to_string(),
            });
        }
        Ok(())
    }
}

/// Length of the nonce a wrapped blob starts with, in bytes.
const MOCK_NONCE_LEN: usize = 32;

/// Length of a wrapped blob: nonce, sealed material and authentication tag.
const MOCK_WRAPPED_LEN: usize = MOCK_NONCE_LEN + MASTER_KEY_LEN + 32;

/// Domain separator of the keystream, so that the keystream and the tag can never be the
/// same HMAC of the same input.
const KEYSTREAM_CONTEXT: &[u8] = b"qualia-dik/mock/keystream/v1";

/// Domain separator of the authentication tag.
const TAG_CONTEXT: &[u8] = b"qualia-dik/mock/tag/v1";

/// The block size of SHA-256 in bytes: the hash processes 512-bit blocks (FIPS 180-4 §1).
const SHA256_BLOCK_LEN: usize = 64;

/// HMAC-SHA256 of `message` under `key` (RFC 2104 §2).
///
/// The construction is the RFC's, not an invention: the key is reduced to the block size,
/// padded with zeros, and used as the two pads of the nested hashes. It exists because the
/// test double needs a keyed function, and `sha2` is already here.
fn hmac_sha256(key: &[u8], message: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};

    let mut block = [0_u8; SHA256_BLOCK_LEN];
    if key.len() > SHA256_BLOCK_LEN {
        let digest = Sha256::digest(key);
        block[..digest.len()].copy_from_slice(&digest);
    } else {
        block[..key.len()].copy_from_slice(key);
    }

    let mut inner = Sha256::new();
    let mut pad = [0x36_u8; SHA256_BLOCK_LEN];
    for (byte, key_byte) in pad.iter_mut().zip(block.iter()) {
        *byte ^= key_byte;
    }
    inner.update(pad);
    inner.update(message);
    let inner = inner.finalize();

    let mut outer = Sha256::new();
    let mut pad = [0x5C_u8; SHA256_BLOCK_LEN];
    for (byte, key_byte) in pad.iter_mut().zip(block.iter()) {
        *byte ^= key_byte;
    }
    outer.update(pad);
    outer.update(inner);

    let mut out = [0_u8; 32];
    out.copy_from_slice(&outer.finalize());
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::device;

    /// What was created can be opened, and reports the same public key.
    #[test]
    fn create_then_open_yields_same_identity() {
        let store = MockKeyStore::new();
        let created = store.create("device").expect("create");
        let id_created = created.public_key().device_id();

        let opened = store.open("device").expect("open");
        assert_eq!(opened.public_key().device_id(), id_created);
    }

    /// Opening a missing key reports `KeyNotFound` and creates nothing.
    ///
    /// The second half is verified by opening again: if the first `open` had
    /// created a key, the second call would succeed.
    #[test]
    fn open_missing_key_does_not_create() {
        let store = MockKeyStore::new();
        let error = store.open("nope").expect_err("must fail");
        assert!(matches!(error, Error::KeyNotFound { .. }));
        assert!(
            store.open("nope").is_err(),
            "the first open created a key: open must be read-only"
        );
    }

    /// Creating an existing key is rejected and leaves the identity unchanged.
    #[test]
    fn create_existing_key_is_rejected_and_does_not_replace() {
        let store = MockKeyStore::new();
        let first = store.create("device").expect("first create");
        let id_first = first.public_key().device_id();

        assert!(
            store.create("device").is_err(),
            "duplicate creation must be rejected"
        );

        let again = store.open("device").expect("open");
        assert_eq!(
            again.public_key().device_id(),
            id_first,
            "rejecting a duplicate create must keep the original identity"
        );
    }

    /// `open_or_create` works on both paths.
    #[test]
    fn open_or_create_works_both_ways() {
        let store = MockKeyStore::new();
        let a = store.open_or_create("device").expect("first call");
        let b = store.open_or_create("device").expect("second call");
        assert_eq!(a.public_key().device_id(), b.public_key().device_id());
    }

    /// Clones share one storage, which stands for reopening on the same machine.
    #[test]
    fn clone_shares_storage() {
        let store = MockKeyStore::new();
        let id = store
            .create("device")
            .expect("create")
            .public_key()
            .device_id();
        let other = store.clone();
        assert_eq!(
            other.open("device").expect("open").public_key().device_id(),
            id
        );
    }

    /// A software signature is accepted by the verification function of the core
    /// crate.
    #[test]
    fn software_signature_verifies_with_core() {
        let store = MockKeyStore::new();
        let signer = store.create("device").expect("create");
        let message = b"\x07pairing message";
        let signature = signer.sign(message).expect("sign");
        assert!(
            device::verify(signer.public_key(), message, &signature).is_ok(),
            "Core must accept a signature from the software backend"
        );
    }

    /// A digest of the wrong length is rejected.
    #[test]
    fn wrong_digest_length_is_rejected() {
        let store = MockKeyStore::new();
        let signer = store.create("device").expect("create");
        assert!(matches!(
            signer.sign_digest(&[0_u8; 20]),
            Err(Error::InvalidDigestLength { .. })
        ));
    }

    /// After deletion the identity cannot be opened, and deleting twice reports
    /// `KeyNotFound`.
    #[test]
    fn delete_removes_identity() {
        let store = MockKeyStore::new();
        store.create("device").expect("create");
        assert!(store.open("device").is_ok());

        store.delete("device").expect("delete");
        assert!(store.open("device").is_err(), "a deleted key must not open");
        assert!(matches!(
            store.delete("device"),
            Err(Error::KeyNotFound { .. })
        ));
    }

    /// Two labels are two independent identities.
    #[test]
    fn distinct_labels_are_distinct_identities() {
        let store = MockKeyStore::new();
        let a = store.create("account-a").expect("create a");
        let b = store.create("account-b").expect("create b");
        assert_ne!(a.public_key().device_id(), b.public_key().device_id());
    }

    /// `backend()` reports software and never pretends to be hardware.
    #[test]
    fn mock_reports_software_backend() {
        let store = MockKeyStore::new();
        assert_eq!(store.backend(), Backend::Software);
        assert!(!store.backend().is_hardware_backed());
        let signer = store.create("device").expect("create");
        assert_eq!(signer.backend(), Backend::Software);
    }

    /// HMAC-SHA256 matches the two first test vectors of RFC 4231 §4.
    ///
    /// The test double's wrapping rests on this function, and a hand written keyed hash is
    /// exactly the kind of code that is wrong in a way that still "looks random". The
    /// vectors are the specification's, not values taken from this implementation.
    #[test]
    fn hmac_sha256_matches_rfc4231() {
        let case1 = hmac_sha256(&[0x0B_u8; 20], b"Hi There");
        assert_eq!(
            case1,
            [
                0xB0, 0x34, 0x4C, 0x61, 0xD8, 0xDB, 0x38, 0x53, 0x5C, 0xA8, 0xAF, 0xCE, 0xAF, 0x0B,
                0xF1, 0x2B, 0x88, 0x1D, 0xC2, 0x00, 0xC9, 0x83, 0x3D, 0xA7, 0x26, 0xE9, 0x37, 0x6C,
                0x2E, 0x32, 0xCF, 0xF7,
            ]
        );

        let case2 = hmac_sha256(b"Jefe", b"what do ya want for nothing?");
        assert_eq!(
            case2,
            [
                0x5B, 0xDC, 0xC1, 0x46, 0xBF, 0x60, 0x75, 0x4E, 0x6A, 0x04, 0x24, 0x26, 0x08, 0x95,
                0x75, 0xC7, 0x5A, 0x00, 0x3F, 0x08, 0x9D, 0x27, 0x39, 0x83, 0x9D, 0xEC, 0x58, 0xB9,
                0x64, 0xEC, 0x38, 0x43,
            ]
        );

        let long_key = hmac_sha256(
            &[0xAA_u8; 131],
            b"Test Using Larger Than Block-Size Key - Hash Key First",
        );
        assert_eq!(
            long_key,
            [
                0x60, 0xE4, 0x31, 0x59, 0x1E, 0xE0, 0xB6, 0x7F, 0x0D, 0x8A, 0x26, 0xAA, 0xCB, 0xF5,
                0xB7, 0x7F, 0x8E, 0x0B, 0xC6, 0x21, 0x37, 0x28, 0xC5, 0x14, 0x05, 0x46, 0x04, 0x0F,
                0x0E, 0xE3, 0x7F, 0x54,
            ]
        );
    }

    /// Whether two master keys hold the same material, without printing either one.
    fn same_secret(a: &MasterKey, b: &MasterKey) -> bool {
        secrets_equal(a.as_bytes(), b.as_bytes())
    }

    /// The direct form round-trips the material.
    #[test]
    fn direct_form_round_trips() {
        let store = MockDirectMasterKeyStore::new();
        let key = MasterKey::from_bytes([0x11_u8; MASTER_KEY_LEN]);
        store.store("account-1", &key).expect("store");

        let loaded = store.load("account-1").expect("load");
        assert!(
            same_secret(&loaded, &key),
            "the material read back differs from the material stored"
        );
    }

    /// The direct form reports software, and a missing label is `KeyNotFound`.
    #[test]
    fn direct_form_is_honest_and_reports_missing_keys() {
        let store = MockDirectMasterKeyStore::new();
        assert_eq!(store.backend(), Backend::Software);
        assert!(!store.backend().is_hardware_backed());

        let error = store.load("nothing").expect_err("must fail");
        assert!(matches!(error, Error::KeyNotFound { .. }));
        let error = store.delete("nothing").expect_err("must fail");
        assert!(matches!(error, Error::KeyNotFound { .. }));
    }

    /// Storing twice replaces the material, and deleting removes it.
    #[test]
    fn direct_form_replaces_and_deletes() {
        let store = MockDirectMasterKeyStore::new();
        let first = MasterKey::from_bytes([0x22_u8; MASTER_KEY_LEN]);
        let second = MasterKey::from_bytes([0x33_u8; MASTER_KEY_LEN]);

        store.store("account-1", &first).expect("store");
        store.store("account-1", &second).expect("store again");
        let loaded = store.load("account-1").expect("load");
        assert!(
            same_secret(&loaded, &second),
            "storing again must replace the material that was there"
        );

        store.delete("account-1").expect("delete");
        assert!(matches!(
            store.load("account-1"),
            Err(Error::KeyNotFound { .. })
        ));
    }

    /// A clone shares the storage, which stands for reopening on the same machine.
    #[test]
    fn direct_form_clone_shares_storage() {
        let store = MockDirectMasterKeyStore::new();
        let key = MasterKey::from_bytes([0x44_u8; MASTER_KEY_LEN]);
        store.store("account-1", &key).expect("store");

        let other = store.clone();
        let loaded = other.load("account-1").expect("load");
        assert!(same_secret(&loaded, &key));
    }

    /// The wrapped form round-trips, and the wrapped bytes are not the material.
    #[test]
    fn wrapped_form_round_trips() {
        let store = MockWrappedMasterKeyStore::new();
        let key = MasterKey::from_bytes([0x55_u8; MASTER_KEY_LEN]);

        let wrapped = store.store("account-1", &key).expect("wrap");
        assert_eq!(wrapped.as_bytes().len(), MOCK_WRAPPED_LEN);
        assert!(
            !wrapped
                .as_bytes()
                .windows(MASTER_KEY_LEN)
                .any(|w| w == key.as_bytes()),
            "the persisted bytes contain the master key in the clear"
        );

        let loaded = store.load("account-1", &wrapped).expect("unwrap");
        assert!(
            same_secret(&loaded, &key),
            "the material read back differs from the material wrapped"
        );
    }

    /// The wrapped form reports software and reports missing labels.
    #[test]
    fn wrapped_form_is_honest_and_reports_missing_keys() {
        let store = MockWrappedMasterKeyStore::new();
        assert_eq!(store.backend(), Backend::Software);
        assert!(!store.backend().is_hardware_backed());

        let error = store.delete("nothing").expect_err("must fail");
        assert!(matches!(error, Error::KeyNotFound { .. }));

        let key = MasterKey::from_bytes([0x66_u8; MASTER_KEY_LEN]);
        let wrapped = store.store("account-1", &key).expect("wrap");
        store.delete("account-1").expect("delete the KEK");

        let error = store.load("account-1", &wrapped).expect_err("must fail");
        assert!(matches!(error, Error::KeyNotFound { .. }));
    }

    /// A damaged blob fails instead of returning 32 bytes that are not the master key.
    #[test]
    fn wrapped_form_rejects_a_damaged_blob() {
        let store = MockWrappedMasterKeyStore::new();
        let key = MasterKey::from_bytes([0x77_u8; MASTER_KEY_LEN]);
        let wrapped = store.store("account-1", &key).expect("wrap");

        for index in [
            0_usize,
            MOCK_NONCE_LEN,
            MOCK_NONCE_LEN + 5,
            MOCK_WRAPPED_LEN - 1,
        ] {
            let mut bytes = wrapped.as_bytes().to_vec();
            bytes[index] ^= 0x01;
            let damaged = WrappedMasterKey::from_bytes(bytes);
            let error = store
                .load("account-1", &damaged)
                .expect_err("a damaged blob must be rejected");
            assert!(
                matches!(error, Error::InvalidWrappedKey { .. }),
                "wrong error for a blob damaged at byte {index}: {error:?}"
            );
        }

        let truncated =
            WrappedMasterKey::from_bytes(wrapped.as_bytes()[..MOCK_WRAPPED_LEN - 1].to_vec());
        assert!(matches!(
            store.load("account-1", &truncated),
            Err(Error::InvalidWrappedKey { .. })
        ));
    }

    /// A blob wrapped by another KEK is rejected, which is what a regenerated key store
    /// looks like to a restored file.
    #[test]
    fn wrapped_form_rejects_a_blob_from_another_kek() {
        let store = MockWrappedMasterKeyStore::new();
        let key = MasterKey::from_bytes([0x88_u8; MASTER_KEY_LEN]);
        let wrapped = store.store("account-1", &key).expect("wrap");

        store.delete("account-1").expect("delete the KEK");
        let _ = store.store("account-1", &key).expect("wrap with a new KEK");

        let error = store
            .load("account-1", &wrapped)
            .expect_err("a blob from the previous KEK must be rejected");
        assert!(matches!(error, Error::InvalidWrappedKey { .. }));
    }

    /// Two labels get two key-encryption keys, so one label's blob is not another's.
    #[test]
    fn wrapped_form_keeps_labels_apart() {
        let store = MockWrappedMasterKeyStore::new();
        let key = MasterKey::from_bytes([0x99_u8; MASTER_KEY_LEN]);
        let wrapped = store.store("account-1", &key).expect("wrap");

        let error = store
            .load("account-2", &wrapped)
            .expect_err("another label has no key-encryption key");
        assert!(matches!(error, Error::KeyNotFound { .. }));

        let _ = store
            .store("account-2", &key)
            .expect("wrap under a second label");
        let error = store
            .load("account-2", &wrapped)
            .expect_err("the second label's KEK differs, so the blob must be rejected");
        assert!(matches!(error, Error::InvalidWrappedKey { .. }));
    }

    /// Storing again under a label keeps the KEK, so previously persisted bytes still work.
    #[test]
    fn wrapped_form_reuses_the_kek() {
        let store = MockWrappedMasterKeyStore::new();
        let first = MasterKey::from_bytes([0xAA_u8; MASTER_KEY_LEN]);
        let second = MasterKey::from_bytes([0xBB_u8; MASTER_KEY_LEN]);

        let wrapped_first = store.store("account-1", &first).expect("wrap");
        let wrapped_second = store.store("account-1", &second).expect("wrap again");

        let loaded = store.load("account-1", &wrapped_second).expect("unwrap");
        assert!(same_secret(&loaded, &second));
        let loaded = store.load("account-1", &wrapped_first).expect("unwrap");
        assert!(
            same_secret(&loaded, &first),
            "wrapping again must not invalidate the bytes persisted earlier"
        );
    }

    /// No `Debug` output of either store shows key material.
    #[test]
    fn master_key_stores_do_not_leak_through_debug() {
        let direct = MockDirectMasterKeyStore::new();
        let key = MasterKey::from_bytes([0xCC_u8; MASTER_KEY_LEN]);
        direct.store("account-1", &key).expect("store");

        let wrapped_store = MockWrappedMasterKeyStore::new();
        let wrapped = wrapped_store.store("account-1", &key).expect("wrap");

        let rendered = format!(
            "{direct:?} {wrapped_store:?} {key:?} {wrapped:?} {}",
            direct.load("account-1").expect("load").as_bytes().len()
        );
        assert!(
            !rendered.contains("204") && !rendered.contains("CC") && !rendered.contains("cc"),
            "a debug output shows master key material: {rendered}"
        );
    }
}
