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

//! Confirms that the examples in `README.md` **compile**.
//!
//! The README examples are the first code a user sees, and rustdoc does not
//! check them: rustdoc only compiles the code blocks inside doc comments. These
//! are ordinary tests, so `cargo test` covers them without a separate
//! `cargo test --doc` step.
//!
//! Prerequisites: Windows. The usage example opens the keystore explicitly with
//! `WindowsProvider::Tpm` and skips with a printed message when no TPM is
//! available; the `mock` example needs `--features mock`. Failure means a README
//! example no longer compiles or no longer matches the API it documents.

#![cfg(target_os = "windows")]

/// The example from the README "Usage" section, copied line by line.
///
/// The only difference is that `?` becomes `expect`, because the test function
/// does not return a `Result`; the types and the call order are still checked.
/// Requires a TPM: the store is opened with `WindowsProvider::Tpm` so that a
/// software backend cannot be exercised silently. Failure means the documented
/// usage no longer compiles or no longer runs.
#[test]
fn readme_usage_example_compiles_and_runs() {
    use qualia_dik::DeviceKeyStore;
    use qualia_dik::keystore::platform::{WindowsKeyStore, WindowsProvider};

    let Ok(store) = WindowsKeyStore::open(WindowsProvider::Tpm) else {
        println!("skipping: no usable TPM on this machine");
        return;
    };

    assert!(
        store.backend().is_hardware_backed(),
        "a key store opened with the TPM provider must report hardware protection"
    );

    let label = format!("ReadmeExample-{}", std::process::id());
    let _ = store.delete(&label);

    let signer = store.open_or_create(&label).expect("open or create");

    let device_id = signer.public_key().device_id().to_string();
    assert!(!device_id.is_empty(), "the string form of the device id must not be empty");

    let message = b"\x07README example message";
    let signature = signer.sign(message).expect("sign");

    qualia_dik::device::verify(signer.public_key(), message, &signature)
        .expect("the verification in the README example must pass");

    let digest = qualia_dik::keystore::sha256(message);
    let signature2 = signer.sign_digest(&digest).expect("sign digest");
    qualia_dik::device::verify(signer.public_key(), message, &signature2)
        .expect("a signature made over a digest must also verify against the message");

    assert!(
        store.open_or_create("坏 标签").is_err(),
        "the README says a label allows only ASCII letters, digits and - _ ., so one containing a space must be rejected"
    );

    assert!(
        store.create(&label).is_err(),
        "the README says create does not overwrite an existing key"
    );

    store.delete(&label).expect("clean up");
}

/// The `mock` example from the README.
///
/// It is gated behind the `mock` feature, which is what enables `MockKeyStore`;
/// without `--features mock` it is compiled out, so the default test run does
/// not look for a type that is not there. Requires no TPM. Failure means the
/// documented `mock` example no longer compiles or no longer runs.
#[cfg(feature = "mock")]
#[test]
fn readme_mock_example_compiles_and_runs() {
    use qualia_dik::{DeviceKeyStore, MockKeyStore};

    let store = MockKeyStore::new();
    let signer = store.create("test-device").expect("create");

    let message = b"mock example";
    let signature = signer.sign(message).expect("sign");
    qualia_dik::device::verify(signer.public_key(), message, &signature).expect("verify");
}
