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

//! Shared helpers for the integration tests.
//!
//! Every integration test binary includes this module on its own, so helpers a
//! given binary does not use are allowed to be dead code.
//!
//! # Unique labels
//!
//! `cargo test` runs tests in parallel by default, and the platform keystore is
//! global shared state: two tests that use the same label delete each other's
//! keys, which shows up as intermittent failures. [`TestLabel`] therefore
//! combines the test name, the process id, and an atomic sequence number into a
//! label that is unique across the machine.

#![cfg(target_os = "windows")]
#![allow(dead_code)]

use qualia_dik::DeviceKeyStore;
use qualia_dik::keystore::platform::{WindowsKeyStore, WindowsProvider};
use std::sync::atomic::{AtomicU64, Ordering};

/// Common prefix of every test label.
///
/// Do **not** change it, and do not let a test use a label without it: test
/// identities and real user identities live in one namespace, and deleting a
/// real identity means the user loses the device identity permanently.
const TEST_PREFIX: &str = "Q2faTest-";

/// Monotonically increasing per-process sequence number that keeps the labels
/// of one process distinct.
static COUNTER: AtomicU64 = AtomicU64::new(0);

/// A globally unique test label that does **nothing** on drop.
///
/// Cleanup is deliberately not automatic: deleting a key touches hardware, and
/// doing that while a panic unwinds would mask the actual failure. Tests call
/// `delete` explicitly.
#[derive(Debug)]
pub struct TestLabel {
    /// The full label text.
    text: String,
}

impl TestLabel {
    /// Builds a globally unique label from `name`.
    ///
    /// `name` must contain only the characters `key_name` accepts: ASCII
    /// letters, digits, `-`, `_`, and `.`.
    #[must_use]
    pub fn new(name: &str) -> Self {
        let sequence = COUNTER.fetch_add(1, Ordering::Relaxed);
        let pid = std::process::id();
        Self {
            text: format!("{TEST_PREFIX}{name}-{pid}-{sequence}"),
        }
    }

    /// The label text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.text
    }
}

/// Opens the TPM backend; returns `None` and prints the reason when this
/// machine has no usable TPM.
///
/// Tests that need hardware must return early on `None` rather than fail: a
/// machine without a TPM (including CI) then reports a skip, while a developer
/// machine with a TPM really runs the tests. The printed reason keeps a skip
/// distinguishable from a pass in the output. Properties that do not depend on
/// hardware are covered through the `mock` backend instead.
#[must_use]
pub fn hardware_store() -> Option<WindowsKeyStore> {
    match WindowsKeyStore::open(WindowsProvider::Tpm) {
        Ok(store) => Some(store),
        Err(error) => {
            println!("skipping: no usable TPM on this machine ({error})");
            None
        }
    }
}

/// Opens the software KSP backend; returns `None` when even that is
/// unavailable.
///
/// The software KSP always exists on Windows, so this normally succeeds: it
/// lets the non-hardware path be covered on machines without a TPM too.
#[must_use]
pub fn software_store() -> Option<WindowsKeyStore> {
    match WindowsKeyStore::open(WindowsProvider::Software) {
        Ok(store) => Some(store),
        Err(error) => {
            println!("skipping: no usable software key store on this machine ({error})");
            None
        }
    }
}

/// Returns the backend `store` reports, which tells the TPM and software paths
/// apart.
#[must_use]
pub fn backend_of(store: &WindowsKeyStore) -> qualia_dik::Backend {
    store.backend()
}
