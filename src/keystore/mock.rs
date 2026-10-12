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

use crate::device::{DevicePublicKey, DeviceSignature};
use crate::keystore::traits::{
    Backend, DIGEST_LEN, DeviceKeyStore, DeviceSigner, public_key_from_sec1,
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
    public_key_from_sec1(&GENERATOR)
        .unwrap_or_else(|_| unreachable!("the P-256 generator does not parse; the p256 implementation is broken"))
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

        assert!(store.create("device").is_err(), "duplicate creation must be rejected");

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
}
