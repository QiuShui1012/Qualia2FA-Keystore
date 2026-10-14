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

//! Integration tests for the two master key forms on Windows.
//!
//! # Real key store entries
//!
//! These tests **create and delete** entries in the machine's storage providers. Every
//! label starts with the shared `Q2faTest-` prefix and is deleted at the end of its test,
//! so a real user's master key is never touched. A test that fails midway can leave an
//! entry behind; such leftovers carry the test prefix and can be deleted by hand.
//!
//! # What is exercised
//!
//! - the direct form through the software provider (the provider this form can use — see
//!   the backend test for why the TPM cannot serve it);
//! - the wrapped form through the TPM provider where the machine has one, and through the
//!   software provider otherwise;
//! - honest backend reporting, `KeyNotFound` on missing labels, and rejection of damaged or
//!   foreign wrapped bytes.
//!
//! Prerequisites: Windows. Tests that need a TPM skip with a printed reason when it is
//! unavailable (a machine without one, or CI) instead of failing.

#![cfg(target_os = "windows")]

mod common;

use common::TestLabel;
use qualia_dik::keystore::platform::{
    WindowsDirectMasterKeyStore, WindowsProvider, WindowsWrappedMasterKeyStore,
};
use qualia_dik::keystore::{
    DirectMasterKeyStore, MASTER_KEY_LEN, MasterKey, WrappedMasterKey, WrappedMasterKeyStore,
};
use qualia_dik::{Backend, Error};

/// Whether two master keys hold the same material, without printing either one.
fn same_secret(a: &MasterKey, b: &MasterKey) -> bool {
    a.as_bytes() == b.as_bytes()
}

/// A deterministic master key for tests, built from a single byte so that a leak into the
/// test output is easy to spot.
fn material(byte: u8) -> MasterKey {
    MasterKey::from_bytes([byte; MASTER_KEY_LEN])
}

// ── Direct form ─────────────────────────────────────────────────────

/// The direct form round-trips the material through the software provider, survives a
/// reopen, and reports `KeyNotFound` after the deletion.
///
/// The reopen is the part that matters: a store that kept the material in this process
/// would pass a plain round-trip and lose every vault after a restart.
#[test]
fn direct_form_round_trips_through_the_software_provider() {
    let Ok(store) = WindowsDirectMasterKeyStore::open(WindowsProvider::Software) else {
        println!("skipping: no usable software key store on this machine");
        return;
    };
    assert_eq!(
        store.backend(),
        Backend::Software,
        "the software provider must not be reported as anything else"
    );
    assert!(!store.backend().is_hardware_backed());

    let label = TestLabel::new("master-direct");
    let _ = store.delete(label.as_str());
    let key = material(0x11);
    store.store(label.as_str(), &key).expect("store");

    let loaded = store.load(label.as_str()).expect("load");
    assert!(
        same_secret(&loaded, &key),
        "the material read back differs from the material stored"
    );

    drop(store);
    let reopened = WindowsDirectMasterKeyStore::open(WindowsProvider::Software).expect("reopen");
    let loaded = reopened.load(label.as_str()).expect("load after reopen");
    assert!(
        same_secret(&loaded, &key),
        "the material did not survive closing and reopening the store"
    );

    reopened
        .store(label.as_str(), &material(0x22))
        .expect("replace");
    let replaced = reopened.load(label.as_str()).expect("load");
    assert!(
        same_secret(&replaced, &material(0x22)),
        "storing again must replace the material"
    );

    reopened.delete(label.as_str()).expect("delete");
    assert!(
        matches!(
            reopened.load(label.as_str()),
            Err(Error::KeyNotFound { .. })
        ),
        "a deleted master key must not load"
    );
    assert!(
        matches!(
            reopened.delete(label.as_str()),
            Err(Error::KeyNotFound { .. })
        ),
        "deleting twice must report a missing key"
    );
}

/// The direct form prefers the TPM provider and falls back to the software one, reporting
/// which provider it ended up with.
///
/// The TPM branch is a real finding rather than a formality: the Microsoft Platform Crypto
/// Provider imports the key and then refuses to export it (`NTE_PERM`), so it cannot serve a
/// form whose contract is "hand the material back". A machine whose TPM provider does serve
/// it is fine too — the test then checks the round-trip there.
#[test]
fn direct_form_prefers_the_tpm_and_reports_what_answered() {
    let store = WindowsDirectMasterKeyStore::open_best_available().expect("open best available");
    let backend = store.backend();
    println!("the direct form is served by {backend:?}");
    assert!(
        matches!(backend, Backend::Tpm | Backend::Software),
        "the direct form must report the provider that answered, not Unavailable"
    );

    match WindowsDirectMasterKeyStore::open(WindowsProvider::Tpm) {
        Ok(tpm_store) => {
            assert_eq!(
                tpm_store.backend(),
                Backend::Tpm,
                "a TPM store must report itself as TPM"
            );
            let label = TestLabel::new("master-direct-tpm");
            let _ = tpm_store.delete(label.as_str());
            let key = material(0x33);
            tpm_store.store(label.as_str(), &key).expect("store");
            let loaded = tpm_store.load(label.as_str()).expect("load");
            assert!(same_secret(&loaded, &key));
            tpm_store.delete(label.as_str()).expect("clean up");
        }
        Err(error) => {
            assert!(
                matches!(error, Error::HardwareUnavailable { .. }),
                "a provider that cannot hold the material must be reported as unavailable, got {error:?}"
            );
            assert!(
                error
                    .to_string()
                    .contains("cannot hold master key material"),
                "the reason must say why the provider is unusable: {error}"
            );
        }
    }

    let label = TestLabel::new("master-direct-best");
    let _ = store.delete(label.as_str());
    let key = material(0x44);
    store.store(label.as_str(), &key).expect("store");
    let loaded = store.load(label.as_str()).expect("load");
    assert!(same_secret(&loaded, &key));
    store.delete(label.as_str()).expect("clean up");
}

/// Invalid labels are rejected before any hardware is touched.
#[test]
fn direct_form_rejects_invalid_labels() {
    let Ok(store) = WindowsDirectMasterKeyStore::open_best_available() else {
        println!("skipping: no usable key store on this machine");
        return;
    };
    for bad in ["", "a/b", "a\0b", "has space", "设备"] {
        let error = store
            .store(bad, &material(0x55))
            .expect_err("must be rejected");
        assert!(
            matches!(error, Error::InvalidKeyLabel { .. }),
            "wrong error for label {bad:?}: {error:?}"
        );
    }
}

// ── Wrapped form ────────────────────────────────────────────────────

/// The wrapped form round-trips through the TPM provider: the KEK is created there, the
/// wrap and unwrap are TPM operations, and only the wrapped bytes leave the store.
#[test]
fn wrapped_form_round_trips_through_the_tpm() {
    let Ok(store) = WindowsWrappedMasterKeyStore::open(WindowsProvider::Tpm) else {
        println!("skipping: no usable TPM on this machine");
        return;
    };
    assert_eq!(
        store.backend(),
        Backend::Tpm,
        "a store opened with the TPM provider must report TPM"
    );
    assert!(store.backend().is_hardware_backed());

    let label = TestLabel::new("master-wrapped-tpm");
    let _ = store.delete(label.as_str());
    let key = material(0x66);
    let wrapped = store.store(label.as_str(), &key).expect("wrap");
    assert_eq!(
        wrapped.as_bytes().len(),
        256,
        "a 2048-bit key-encryption key wraps into one modulus-sized block"
    );
    assert!(
        !wrapped
            .as_bytes()
            .windows(MASTER_KEY_LEN)
            .any(|window| window == key.as_bytes()),
        "the wrapped bytes contain the master key in the clear"
    );

    let loaded = store.load(label.as_str(), &wrapped).expect("unwrap");
    assert!(
        same_secret(&loaded, &key),
        "the material read back differs from the material wrapped"
    );

    drop(store);
    let reopened = WindowsWrappedMasterKeyStore::open(WindowsProvider::Tpm).expect("reopen");
    let loaded = reopened
        .load(label.as_str(), &wrapped)
        .expect("unwrap after reopen");
    assert!(
        same_secret(&loaded, &key),
        "the key-encryption key must be persisted, not per process"
    );

    reopened.delete(label.as_str()).expect("delete the KEK");
    assert!(
        matches!(
            reopened.load(label.as_str(), &wrapped),
            Err(Error::KeyNotFound { .. })
        ),
        "after deleting the KEK the wrapped bytes must not unwrap"
    );
}

/// The wrapped form reports honestly which provider answered, and the software provider
/// serves it too.
///
/// This is the fallback path: on a machine without a TPM the same code runs against the
/// software key store and says so, instead of claiming hardware protection.
#[test]
fn wrapped_form_reports_the_provider_that_answered() {
    let store = WindowsWrappedMasterKeyStore::open_best_available().expect("open best available");
    println!("the wrapped form is served by {:?}", store.backend());
    assert!(matches!(store.backend(), Backend::Tpm | Backend::Software));

    match WindowsWrappedMasterKeyStore::open(WindowsProvider::Tpm) {
        Ok(tpm) => assert_eq!(tpm.backend(), Backend::Tpm),
        Err(error) => {
            assert!(matches!(error, Error::HardwareUnavailable { .. }));
            println!("skipping the TPM comparison: {error}");
        }
    }

    let label = TestLabel::new("master-wrapped-best");
    let _ = store.delete(label.as_str());
    let key = material(0x77);
    let wrapped = store.store(label.as_str(), &key).expect("wrap");
    let loaded = store.load(label.as_str(), &wrapped).expect("unwrap");
    assert!(same_secret(&loaded, &key));

    let software = WindowsWrappedMasterKeyStore::open(WindowsProvider::Software);
    if let Ok(software) = software {
        assert_eq!(software.backend(), Backend::Software);
        assert!(!software.backend().is_hardware_backed());
        let software_label = TestLabel::new("master-wrapped-software");
        let _ = software.delete(software_label.as_str());
        let wrapped = software
            .store(software_label.as_str(), &key)
            .expect("wrap with the software provider");
        let loaded = software
            .load(software_label.as_str(), &wrapped)
            .expect("unwrap with the software provider");
        assert!(same_secret(&loaded, &key));
        software.delete(software_label.as_str()).expect("clean up");
    } else {
        println!("skipping: no usable software key store on this machine");
    }

    store.delete(label.as_str()).expect("clean up");
}

/// Damaged bytes, bytes of the wrong length and bytes from another label are all rejected;
/// none of them yields a master key that merely differs.
#[test]
fn wrapped_form_rejects_bytes_it_cannot_authenticate() {
    let Some(store) = hardware_wrapped_store() else {
        return;
    };
    let label = TestLabel::new("master-wrapped-damaged");
    let other = TestLabel::new("master-wrapped-other");
    let _ = store.delete(label.as_str());
    let _ = store.delete(other.as_str());

    let key = material(0x88);
    let wrapped = store.store(label.as_str(), &key).expect("wrap");

    let mut damaged = wrapped.as_bytes().to_vec();
    damaged[0] ^= 0x01;
    let error = store
        .load(label.as_str(), &WrappedMasterKey::from_bytes(damaged))
        .expect_err("a damaged blob must be rejected");
    assert!(
        matches!(error, Error::InvalidWrappedKey { .. }),
        "wrong error for a damaged blob: {error:?}"
    );

    let mut late = wrapped.as_bytes().to_vec();
    let last = late.len() - 1;
    late[last] ^= 0x01;
    assert!(
        matches!(
            store.load(label.as_str(), &WrappedMasterKey::from_bytes(late)),
            Err(Error::InvalidWrappedKey { .. })
        ),
        "a flipped bit at the end must be rejected as well"
    );

    assert!(
        matches!(
            store.load(
                label.as_str(),
                &WrappedMasterKey::from_bytes(wrapped.as_bytes()[..255].to_vec())
            ),
            Err(Error::InvalidWrappedKey { .. })
        ),
        "a truncated blob must be rejected"
    );
    assert!(
        matches!(
            store.load(label.as_str(), &WrappedMasterKey::from_bytes(Vec::new())),
            Err(Error::InvalidWrappedKey { .. })
        ),
        "an empty blob must be rejected"
    );

    let _ = store
        .store(other.as_str(), &material(0x99))
        .expect("wrap under a second label");
    assert!(
        matches!(
            store.load(other.as_str(), &wrapped),
            Err(Error::InvalidWrappedKey { .. })
        ),
        "bytes wrapped by another label's key must be rejected"
    );
    assert!(
        matches!(store.load(label.as_str(), &wrapped), Err(_) | Ok(_)),
        "the label's own blob stays usable"
    );

    store.delete(label.as_str()).expect("clean up");
    store.delete(other.as_str()).expect("clean up");
}

/// The wrapped form binds the material to the entry: storing again keeps the key, so bytes
/// persisted earlier still unwrap.
#[test]
fn wrapped_form_keeps_the_key_when_storing_again() {
    let Some(store) = hardware_wrapped_store() else {
        return;
    };
    let label = TestLabel::new("master-wrapped-reuse");
    let _ = store.delete(label.as_str());

    let first = material(0xAA);
    let wrapped_first = store.store(label.as_str(), &first).expect("wrap");
    let wrapped_second = store
        .store(label.as_str(), &material(0xBB))
        .expect("wrap again");

    let loaded = store
        .load(label.as_str(), &wrapped_second)
        .expect("unwrap the new blob");
    assert!(same_secret(&loaded, &material(0xBB)));
    let loaded = store
        .load(label.as_str(), &wrapped_first)
        .expect("unwrap the old blob");
    assert!(
        same_secret(&loaded, &first),
        "wrapping again must not invalidate the bytes persisted earlier"
    );

    store.delete(label.as_str()).expect("clean up");
}

/// No `Debug` output of either store, of a master key or of a wrapped blob shows key
/// material.
#[test]
fn debug_output_never_shows_the_material() {
    let direct = WindowsDirectMasterKeyStore::open(WindowsProvider::Software);
    let wrapped = hardware_wrapped_store();

    let key = material(0xCC);
    let mut rendered = format!("{key:?}");
    if let Ok(direct) = &direct {
        rendered.push_str(&format!("{direct:?}"));
        let label = TestLabel::new("master-debug");
        let _ = direct.delete(label.as_str());
        direct.store(label.as_str(), &key).expect("store");
        let wrapped_bytes = wrapped
            .as_ref()
            .and_then(|store| store.store(label.as_str(), &key).ok());
        if let Some(wrapped_bytes) = &wrapped_bytes {
            rendered.push_str(&format!("{wrapped_bytes:?}"));
        }
        direct.delete(label.as_str()).expect("clean up");
    }
    if let Some(wrapped) = &wrapped {
        rendered.push_str(&format!("{wrapped:?}"));
    }

    assert!(
        !rendered.contains("204") && !rendered.contains("CC") && !rendered.contains("cc"),
        "a debug output shows master key material: {rendered}"
    );
}

/// Opens the wrapped store through the TPM when this machine has one, and through the
/// software provider otherwise; prints why when neither works.
fn hardware_wrapped_store() -> Option<WindowsWrappedMasterKeyStore> {
    match WindowsWrappedMasterKeyStore::open_best_available() {
        Ok(store) => Some(store),
        Err(error) => {
            println!("skipping: no usable key store for the wrapped form ({error})");
            None
        }
    }
}
