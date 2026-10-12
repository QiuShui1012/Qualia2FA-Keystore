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

//! Integration tests for the platform backends.
//!
//! # Real hardware
//!
//! These tests **create and delete** keys in the system keystore. Every label
//! starts with `Q2faTest-` and is deleted at the end of its test, so that real
//! user identities are never touched. A test that fails midway can leave a key
//! behind; such leftovers carry the test prefix and can be deleted by hand.
//!
//! # Prerequisites
//!
//! Windows. Tests that need a TPM skip with a printed reason when the hardware
//! is unavailable (for example on a machine without one, including CI) instead
//! of failing; tests that only use the software KSP run everywhere. Failure of
//! any test below means the corresponding property of the public API is broken.

#![cfg(target_os = "windows")]

mod common;

use common::{TestLabel, hardware_store, software_store};
use qualia_dik::DeviceKeyStore;

/// A signature produced by hardware must be accepted by the verification
/// function of `qualia2fa-core`.
///
/// Three independent conventions meet on the signing path, and a mismatch in
/// any of them shows up here as a failed verification:
///
/// 1. Hashing: the crate hashes with SHA-256 and the hardware signs that digest.
/// 2. Signature format: CNG returns the raw `r||s` (64 bytes). DER has a
///    variable length and `DeviceSignature::from_bytes` rejects it.
/// 3. Public key encoding: CNG returns `BCRYPT_ECCPUBLICBLOB` (header plus
///    `X || Y`), which is converted to the SEC1 uncompressed point
///    `0x04 || X || Y`.
///
/// The unit tests use a software keystore and cannot catch a mismatch here.
/// Requires a TPM; skips with a printed reason when none is available. Failure
/// means hardware signatures no longer match what the crate verifies.
#[test]
fn tpm_signature_verifies_with_core() {
    let Some(store) = hardware_store() else {
        return;
    };
    let label = TestLabel::new("sign-verify");
    let _ = store.delete(label.as_str());

    let signer = store.create(label.as_str()).expect("create TPM key");
    let message = b"\x01Qualia2FA pairing challenge";
    let signature = signer.sign(message).expect("TPM sign");

    assert_eq!(
        signature.as_bytes().len(),
        64,
        "the signature is not 64 bytes long, so the backend does not return raw r||s"
    );

    qualia_dik::device::verify(signer.public_key(), message, &signature)
        .expect("Core must accept a signature produced by the TPM");

    let mut tampered = *message;
    tampered[0] ^= 0x01;
    assert!(
        qualia_dik::device::verify(signer.public_key(), &tampered, &signature).is_err(),
        "a tampered message verified"
    );

    store.delete(label.as_str()).expect("clean up");
}

/// Reopening must yield the same identity.
///
/// This covers **persistence**: if the key were not really stored in the KSP,
/// every open would return a new identity, and the device identity would drift
/// on every restart, so peer devices would see an unknown device. Requires a
/// TPM. Failure means the identity does not survive a close and reopen.
#[test]
fn identity_is_stable_across_reopen() {
    let Some(store) = hardware_store() else {
        return;
    };
    let label = TestLabel::new("reopen");
    let _ = store.delete(label.as_str());

    let created = store.create(label.as_str()).expect("create");
    let id_at_create = created.public_key().device_id();
    drop(created);

    let reopened = store.open(label.as_str()).expect("reopen");
    assert_eq!(
        reopened.public_key().device_id(),
        id_at_create,
        "the device identity changed after reopening: the key was not persisted"
    );

    let message = b"reopen test";
    let signature = reopened.sign(message).expect("sign");
    qualia_dik::device::verify(reopened.public_key(), message, &signature)
        .expect("a signature must still verify after reopening");

    store.delete(label.as_str()).expect("clean up");
}

/// Duplicate creation must be rejected and must **not** replace the existing
/// identity.
///
/// A replacement would change the device identity silently: the damage only
/// shows up later, when another device no longer recognizes this one. Requires
/// a TPM. Failure means the original identity was replaced or lost.
#[test]
fn duplicate_create_is_rejected_and_preserves_identity() {
    let Some(store) = hardware_store() else {
        return;
    };
    let label = TestLabel::new("duplicate");
    let _ = store.delete(label.as_str());

    let first = store.create(label.as_str()).expect("first create");
    let id_first = first.public_key().device_id();
    drop(first);

    let error = store
        .create(label.as_str())
        .expect_err("duplicate creation must be rejected");
    assert!(
        matches!(error, qualia_dik::KeyStoreError::KeyAlreadyExists { .. }),
        "wrong error type: {error:?}"
    );

    let again = store.open(label.as_str()).expect("open");
    assert_eq!(
        again.public_key().device_id(),
        id_first,
        "the identity was replaced while rejecting the duplicate create; this is the most dangerous kind of failure"
    );

    store.delete(label.as_str()).expect("clean up");
}

/// `open_or_create` works both when the label already exists and when it does
/// not. Requires a TPM. Failure means one of the two cases creates a new
/// identity instead of reusing the existing one.
#[test]
fn open_or_create_works_in_both_cases() {
    let Some(store) = hardware_store() else {
        return;
    };
    let label = TestLabel::new("open-or-create");
    let _ = store.delete(label.as_str());

    let created = store
        .open_or_create(label.as_str())
        .expect("the first call must create");
    let id = created.public_key().device_id();
    drop(created);

    let opened = store
        .open_or_create(label.as_str())
        .expect("the second call must open");
    assert_eq!(
        opened.public_key().device_id(),
        id,
        "the second call must not generate a new identity"
    );

    store.delete(label.as_str()).expect("clean up");
}

/// Opening and deleting a missing label must report `KeyNotFound` explicitly.
/// Requires a TPM. Failure means a missing key is reported as some other error,
/// or not reported at all.
#[test]
fn missing_label_reports_not_found() {
    let Some(store) = hardware_store() else {
        return;
    };
    let label = TestLabel::new("definitely-missing");
    let _ = store.delete(label.as_str());

    let error = store
        .open(label.as_str())
        .expect_err("must report not found");
    assert!(
        matches!(error, qualia_dik::KeyStoreError::KeyNotFound { .. }),
        "wrong error type: {error:?}"
    );

    let error = store
        .delete(label.as_str())
        .expect_err("must report not found");
    assert!(
        matches!(error, qualia_dik::KeyStoreError::KeyNotFound { .. }),
        "wrong error type: {error:?}"
    );
}

/// Two distinct labels must be two independent identities. Requires a TPM.
/// Failure means labels share one key, so deleting one identity would destroy
/// another.
#[test]
fn distinct_labels_are_distinct_identities() {
    let Some(store) = hardware_store() else {
        return;
    };
    let a = TestLabel::new("distinct-a");
    let b = TestLabel::new("distinct-b");
    let _ = store.delete(a.as_str());
    let _ = store.delete(b.as_str());

    let signer_a = store.create(a.as_str()).expect("create a");
    let signer_b = store.create(b.as_str()).expect("create b");
    assert_ne!(
        signer_a.public_key().device_id(),
        signer_b.public_key().device_id(),
        "two labels produced the same identity"
    );

    store.delete(a.as_str()).expect("clean up a");
    store.delete(b.as_str()).expect("clean up b");
}

/// The TPM backend must report itself as TPM and as hardware-backed. Requires a
/// TPM. Failure means the backend misreports where the private key lives.
#[test]
fn tpm_backend_reports_tpm() {
    let Some(store) = hardware_store() else {
        return;
    };
    assert_eq!(
        qualia_dik::DeviceKeyStore::backend(&store),
        qualia_dik::Backend::Tpm
    );
    assert!(
        qualia_dik::DeviceKeyStore::backend(&store).is_hardware_backed(),
        "the TPM backend must be classified as hardware protected"
    );
}

/// The software KSP goes through **exactly** the same code paths; only the
/// provider name differs.
///
/// The software KSP always exists on Windows, so this test also runs on
/// machines without a TPM and keeps the non-hardware path covered. Requires no
/// TPM. Failure means the software backend cannot sign, or reports itself as
/// hardware-backed.
#[test]
fn software_provider_also_signs_and_verifies() {
    let Some(store) = software_store() else {
        return;
    };
    let label = TestLabel::new("software-provider");
    let _ = store.delete(label.as_str());

    let signer = store.create(label.as_str()).expect("create software key");
    assert_eq!(
        qualia_dik::DeviceKeyStore::backend(&store),
        qualia_dik::Backend::Software
    );
    assert!(
        !qualia_dik::DeviceKeyStore::backend(&store).is_hardware_backed(),
        "the software backend must not be classified as hardware protected"
    );

    let message = b"software path";
    let signature = signer.sign(message).expect("sign");
    qualia_dik::device::verify(signer.public_key(), message, &signature)
        .expect("Core must also accept a signature from the software backend");

    store.delete(label.as_str()).expect("clean up");
}

/// Invalid labels must be rejected **before** any hardware is touched. Requires
/// a TPM, since the store has to open first. Failure means a malformed label
/// reaches the platform API.
#[test]
fn invalid_labels_are_rejected_before_touching_hardware() {
    let Some(store) = hardware_store() else {
        return;
    };
    for bad in ["", "a/b", "a\0b", "has space", "设备", &"x".repeat(200)] {
        let error = store.open(bad).expect_err("must be rejected");
        assert!(
            matches!(error, qualia_dik::KeyStoreError::InvalidKeyLabel { .. }),
            "wrong error type for label {bad:?}: {error:?}"
        );
    }
}
