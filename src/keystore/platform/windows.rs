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

//! Windows backend: TPM 2.0 through CNG's `NCrypt*` interface.
//!
//! # API surface
//!
//! `NCrypt*` is CNG's **key** interface (NCRYPT = Cryptography Next Generation **Key**
//! API). It abstracts *where a key lives* behind a Key Storage Provider (KSP): passing
//! `MS_PLATFORM_CRYPTO_PROVIDER` hands keys to the TPM, while `MS_KEY_STORAGE_PROVIDER`
//! keeps them in software — the same API with two backends, so selecting one is a matter
//! of a single string. TBS (`Tbsi_*`), the lower-level TPM command interface, is not used
//! here: it requires assembling TPM commands and handling sessions and authorization by
//! hand, and `windows-sys` does not expose it.
//!
//! # Key ownership
//!
//! Keys are persisted in the KSP under a name:
//!
//! - A key survives process exit, so a device identity is stable across restarts.
//! - Re-creating an existing name is rejected (`NTE_EXISTS` = `0x8009000F`) and does
//!   **not** overwrite the existing key.
//! - Deleting a key requires an explicit call, so uninstalling does not clean up keys. A
//!   deleted identity is lost permanently on that device, and other devices can no longer
//!   recognize it.
//!
//! # Private keys never enter this process's address space
//!
//! Only three kinds of data cross the boundary: the key's **name** (in), its **public
//! key** (out) and a **signature** (out). The module therefore holds no secret that would
//! have to be wiped, which is why it does not need `zeroize`. The in-memory test backend
//! (`crate::MockKeyStore`) is the opposite case: its private key sits in ordinary memory
//! and has to be wiped explicitly.
//!
//! # Thread safety
//!
//! `NCryptKeyHandle` is not thread-safe: concurrent use of one handle requires external
//! synchronization. A CNG key object can be **opened several times**, each time yielding
//! an independent handle, so the correct pattern is one handle per thread rather than one
//! shared handle. This module therefore does not implement `Sync` for [`WindowsSigner`]:
//! each signer owns exactly one handle.
//!
//! # Not provided by this module
//!
//! **Existing keys cannot be listed.** See the note on `NCryptEnumKeys` next to
//! `KEY_NAME_PREFIX` below: against `MS_PLATFORM_CRYPTO_PROVIDER` that call reports
//! success with an empty list, so "no identity exists" and "identities cannot be read"
//! would be indistinguishable.

use crate::device::{DevicePublicKey, DeviceSignature};
use crate::keystore::traits::{
    Backend, DIGEST_LEN, DeviceKeyStore, DeviceSigner, public_key_from_sec1, signature_from_raw,
};
use crate::{Error, Result};
use std::fmt;
use windows_sys::Win32::Security::Cryptography::{
    BCRYPT_ECCPUBLIC_BLOB, MS_KEY_STORAGE_PROVIDER, MS_PLATFORM_CRYPTO_PROVIDER,
    NCRYPT_ECDSA_P256_ALGORITHM, NCRYPT_KEY_HANDLE, NCRYPT_PROV_HANDLE, NCRYPT_SILENT_FLAG,
    NCryptCreatePersistedKey, NCryptDeleteKey, NCryptExportKey, NCryptFinalizeKey,
    NCryptFreeObject, NCryptOpenKey, NCryptOpenStorageProvider, NCryptSignHash,
};

/// `NTE_BAD_FLAGS`: the flag combination is not supported.
///
/// Production code does not use it; it is kept so that `tests::nte_codes_match_winerror`
/// can pin the source values of the whole group in one place. `#[allow]` rather than
/// `#[expect]`: the constant *is* used in test builds, where `expect(dead_code)` would
/// itself be an unfulfilled expectation.
#[allow(dead_code, reason = "pinned for tests to check against winerror.h")]
const NTE_BAD_FLAGS: i32 = 0x8009_0009_u32 as i32;

/// `NTE_NO_KEY`: no key is available. Some KSPs report this instead of [`NTE_BAD_KEYSET`].
const NTE_NO_KEY: i32 = 0x8009_000D_u32 as i32;

/// `NTE_EXISTS`: a key with this name already exists.
///
/// Reported when [`NCryptCreatePersistedKey`] is called again with the same name. This is
/// a **normal** outcome; see the module documentation.
const NTE_EXISTS: i32 = 0x8009_000F_u32 as i32;

/// `NTE_NOT_FOUND`: the object was not found.
const NTE_NOT_FOUND: i32 = 0x8009_0011_u32 as i32;

/// `NTE_BAD_KEYSET`: the key set does not exist, that is, **there is no such key**.
///
/// # These values are transcribed from `winerror.h`
///
/// The authoritative source is `winerror.h` in the Windows SDK, since `windows-sys` does
/// not export these constants:
///
/// ```text
/// #define NTE_BAD_FLAGS     _HRESULT_TYPEDEF_(0x80090009L)
/// #define NTE_NO_KEY        _HRESULT_TYPEDEF_(0x8009000DL)
/// #define NTE_EXISTS        _HRESULT_TYPEDEF_(0x8009000FL)
/// #define NTE_NOT_FOUND     _HRESULT_TYPEDEF_(0x80090011L)
/// #define NTE_BAD_KEYSET    _HRESULT_TYPEDEF_(0x80090016L)
/// ```
///
/// A wrong value is **not** a compile error: it turns the normal "no such key" path into a
/// hardware failure, so every caller of [`NCryptOpenKey`] that probes for existence
/// mistakes a missing key for a broken machine. `tests::nte_codes_match_winerror` pins all
/// five values against the definitions above.
const NTE_BAD_KEYSET: i32 = 0x8009_0016_u32 as i32;

/// Key-name prefix used by this module.
///
/// The prefix makes these keys recognizable at a glance in the system's key list: they
/// share one KSP namespace with the user's other keys.
///
/// # On listing existing keys
///
/// **`NCryptEnumKeys` cannot enumerate TPM keys.** Measured on Windows 11 with a TPM 2.0:
/// against `MS_PLATFORM_CRYPTO_PROVIDER` it reports success with a count of 0, even right
/// after a key was created, opened and successfully used for signing through that
/// provider. Passing `$$$MACHINE$$$` or `$$$CURRENT_USER$$$` returns `0x80090029` (not
/// supported) instead.
///
/// Listing every identity on a device is therefore **not possible** on Windows, and this
/// crate does not offer such an operation: an interface that silently returns an empty
/// list for the primary backend would make "there is no identity" and "the identities
/// cannot be read" indistinguishable. A caller that needs to know which identities exist
/// should **record the labels it created itself** (an account registry, for example).
/// That is also more reliable, because a key name carries no information about which
/// account it belongs to.
const KEY_NAME_PREFIX: &str = "Qualia2FA-Device-";

/// Maximum label length.
///
/// With the prefix added, the resulting name stays within the length CNG accepts, with
/// headroom to spare.
const MAX_LABEL_LEN: usize = 128;

/// Converts a logical `label` into a CNG key name (NUL-terminated UTF-16).
///
/// A key name becomes an entry in a **system-wide** namespace, while `label` comes from
/// upper layers (possibly indirectly from the user). Allowing control characters or NUL
/// bytes in it would permit surprising names, most directly through **NUL truncation**:
/// `"a\0b"` and `"a"` are the same C string, so two different labels would map to one
/// device identity without the caller noticing.
///
/// Only ASCII letters, digits, `-`, `_` and `.` are accepted; every other byte is
/// rejected. The label must be non-empty and at most [`MAX_LABEL_LEN`] bytes long.
///
/// # Errors
///
/// Returns [`Error::InvalidKeyLabel`] for an empty label, a label longer than
/// [`MAX_LABEL_LEN`], or a label containing a character outside that set.
fn key_name(label: &str) -> Result<Vec<u16>> {
    if label.is_empty() {
        return Err(Error::InvalidKeyLabel {
            reason: "the label is empty"
        });
    }
    if label.len() > MAX_LABEL_LEN {
        return Err(Error::InvalidKeyLabel {
            reason: "the label is too long (limit is 128 bytes)",
        });
    }
    if !label
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        return Err(Error::InvalidKeyLabel {
            reason: "the label contains characters outside the allowed set (ASCII letters, digits, - _ .)",
        });
    }
    let name = format!("{KEY_NAME_PREFIX}{label}");
    let mut wide: Vec<u16> = name.encode_utf16().collect();
    wide.push(0);
    Ok(wide)
}

/// A CNG object handle that is released exactly once.
///
/// Every CNG handle has to be passed to [`NCryptFreeObject`], and this module has several
/// early-return error paths. Releasing it from `Drop` covers all of them, so no error path
/// can leak a handle.
struct CngHandle {
    /// Native handle. `0` means empty (CNG uses 0 for an invalid handle).
    raw: usize,
}

impl CngHandle {
    /// Takes ownership of a native handle.
    fn new(raw: usize) -> Self {
        Self { raw }
    }
}

impl Drop for CngHandle {
    fn drop(&mut self) {
        if self.raw != 0 {
            // SAFETY: `self.raw` is a valid CNG handle owned exclusively by this struct
            // (every place that constructs it checked that the API call succeeded), and
            // it is released only here, exactly once.
            unsafe { NCryptFreeObject(self.raw) };
        }
    }
}

/// Whether this status code means "there is no such key".
///
/// Different KSPs and CNG versions report that one condition with different codes:
///
/// - [`NTE_BAD_KEYSET`] — the name does not exist (the code this machine's TPM returns).
/// - [`NTE_NO_KEY`] — no key is available (some software KSPs).
/// - [`NTE_NOT_FOUND`] — the object was not found.
///
/// Recognizing only one of them would classify "no such key" as a hardware failure on
/// machines whose KSP reports a different code, which makes the **create** path
/// unreachable there.
const fn means_no_such_key(status: i32) -> bool {
    matches!(status, NTE_BAD_KEYSET | NTE_NO_KEY | NTE_NOT_FOUND)
}

/// Opens a key storage provider.
///
/// `provider` must be a wide-string constant from `windows-sys` (`MS_*_PROVIDER`).
///
/// # Errors
///
/// Returns [`Error::Hardware`] with the negative status code when the call fails.
fn open_provider(provider: *const u16) -> Result<CngHandle> {
    let mut handle: NCRYPT_PROV_HANDLE = 0;
    // SAFETY: `handle` is a valid writable local variable, and `provider` is a
    // NUL-terminated static wide string exported by `windows-sys`.
    let status = unsafe { NCryptOpenStorageProvider(&raw mut handle, provider, 0) };
    if status < 0 {
        return Err(Error::Hardware {
            operation: "NCryptOpenStorageProvider",
            code: status,
        });
    }
    Ok(CngHandle::new(handle))
}

/// Opens an existing key.
///
/// Returns `Ok(None)` when the key does not exist: that is an expected path, not an error.
///
/// # Errors
///
/// Returns [`Error::Hardware`] for any other negative status.
fn open_key(provider: &CngHandle, name: &[u16]) -> Result<Option<CngHandle>> {
    let mut handle: NCRYPT_KEY_HANDLE = 0;
    // SAFETY: `provider` is valid, `name` is NUL-terminated and stays alive for the
    // duration of this statement, and `handle` is writable.
    let status = unsafe {
        NCryptOpenKey(
            provider.raw,
            &raw mut handle,
            name.as_ptr(),
            0,
            NCRYPT_SILENT_FLAG,
        )
    };
    if means_no_such_key(status) {
        return Ok(None);
    }
    if status < 0 {
        return Err(Error::Hardware {
            operation: "NCryptOpenKey",
            code: status,
        });
    }
    Ok(Some(CngHandle::new(handle)))
}

/// Creates and finalizes a new persisted key.
///
/// Returns `Ok(None)` when a key with this name already exists (`NTE_EXISTS`): that is the
/// normal outcome of a race, not an error.
///
/// `NCRYPT_OVERWRITE_KEY_FLAG` is never passed, so an existing key is never replaced.
///
/// # Errors
///
/// Returns [`Error::Hardware`] for any other negative status.
fn create_key(provider: &CngHandle, name: &[u16]) -> Result<Option<CngHandle>> {
    let mut handle: NCRYPT_KEY_HANDLE = 0;
    // SAFETY: `provider` is valid, `name` is NUL-terminated and stays alive for the
    // duration of this statement, and `handle` is writable.
    let status = unsafe {
        NCryptCreatePersistedKey(
            provider.raw,
            &raw mut handle,
            NCRYPT_ECDSA_P256_ALGORITHM,
            name.as_ptr(),
            0,
            0,
        )
    };
    if status == NTE_EXISTS {
        return Ok(None);
    }
    if status < 0 {
        return Err(Error::Hardware {
            operation: "NCryptCreatePersistedKey",
            code: status,
        });
    }

    let guarded = CngHandle::new(handle);

    // SAFETY: `guarded` holds a valid key handle.
    let status = unsafe { NCryptFinalizeKey(guarded.raw, NCRYPT_SILENT_FLAG) };
    if status < 0 {
        return Err(Error::Hardware {
            operation: "NCryptFinalizeKey",
            code: status,
        });
    }
    Ok(Some(guarded))
}

/// Exports the public part of a key.
///
/// CNG returns a `BCRYPT_ECCPUBLIC_BLOB`: an 8-byte header followed by the point. The
/// header is a `BCRYPT_ECCKEY_BLOB`, `{ dwMagic: u32, cbKey: u32 }` in little-endian, with
/// `magic` = `"ECCS"` and `cbKey` = 32; the point follows as `X` (32 bytes) and `Y` (32
/// bytes). The result is converted into the SEC1 uncompressed point `0x04 || X || Y`.
///
/// Exporting a public key needs no authorization and no user presence: the public key is
/// not a secret and is meant to be shown to the other device in a QR code. The
/// non-exportable objects inside a TPM are private keys.
///
/// # Errors
///
/// Returns [`Error::Hardware`] when the export fails, and [`Error::InvalidPublicKey`] when
/// the platform reports an implausible length (more than 1024 bytes) or returns a blob
/// that is not a P-256 public key.
fn export_public_key(key: &CngHandle) -> Result<DevicePublicKey> {
    let mut needed: u32 = 0;
    // SAFETY: `key` is valid; a null output pointer with length 0 is the documented way to
    // query the required length, and nothing is written to memory in that case.
    let status = unsafe {
        NCryptExportKey(
            key.raw,
            0,
            BCRYPT_ECCPUBLIC_BLOB,
            std::ptr::null(),
            std::ptr::null_mut(),
            0,
            &raw mut needed,
            0,
        )
    };
    if status < 0 {
        return Err(Error::Hardware {
            operation: "NCryptExportKey(query length)",
            code: status,
        });
    }
    if needed > 1024 {
        return Err(Error::InvalidPublicKey {
            reason: "the platform reported an implausible public key length (over 1024 bytes)",
        });
    }

    let mut blob = vec![0_u8; needed as usize];
    // SAFETY: `blob` has at least `needed` bytes, matching the length passed in.
    let status = unsafe {
        NCryptExportKey(
            key.raw,
            0,
            BCRYPT_ECCPUBLIC_BLOB,
            std::ptr::null(),
            blob.as_mut_ptr(),
            needed,
            &raw mut needed,
            0,
        )
    };
    if status < 0 {
        return Err(Error::Hardware {
            operation: "NCryptExportKey",
            code: status,
        });
    }
    blob.truncate(needed as usize);

    if blob.len() < 8 {
        return Err(Error::InvalidPublicKey {
            reason: "the public key blob returned by the platform is shorter than its 8-byte header",
        });
    }
    let cb_key = u32::from_le_bytes([blob[4], blob[5], blob[6], blob[7]]) as usize;
    let payload = &blob[8..];
    if payload.len() != cb_key * 2 {
        return Err(Error::InvalidPublicKey {
            reason: "the public key payload length returned by the platform does not match cbKey",
        });
    }
    if cb_key != 32 {
        return Err(Error::InvalidPublicKey {
            reason: "the public key returned by the platform is not a 32-byte coordinate (not P-256)",
        });
    }

    let mut sec1 = [0_u8; 65];
    sec1[0] = 0x04;
    sec1[1..].copy_from_slice(payload);
    public_key_from_sec1(&sec1)
}

/// Signs a digest.
///
/// CNG returns the raw `r||s` (64 bytes), **not** DER — confirmed on real hardware. That
/// raw form is exactly [`DeviceSignature`]'s wire format, so no conversion is needed.
///
/// # Errors
///
/// Returns [`Error::InvalidDigestLength`] unless `digest.len()` is [`DIGEST_LEN`],
/// [`Error::Hardware`] when signing fails, and [`Error::InvalidSignatureLength`] when the
/// platform reports an implausible length (more than 1024 bytes).
fn sign_digest_raw(key: &CngHandle, digest: &[u8]) -> Result<DeviceSignature> {
    if digest.len() != DIGEST_LEN {
        return Err(Error::InvalidDigestLength {
            expected: DIGEST_LEN,
            actual: digest.len(),
        });
    }

    let mut needed: u32 = 0;
    // SAFETY: `key` is valid and `digest` is a valid slice; the output buffer is empty in
    // order to query the required length.
    let status = unsafe {
        NCryptSignHash(
            key.raw,
            std::ptr::null(),
            digest.as_ptr(),
            digest.len() as u32,
            std::ptr::null_mut(),
            0,
            &raw mut needed,
            0,
        )
    };
    if status < 0 {
        return Err(Error::Hardware {
            operation: "NCryptSignHash(query length)",
            code: status,
        });
    }
    if needed > 1024 {
        return Err(Error::InvalidSignatureLength {
            expected: 64,
            actual: needed as usize,
        });
    }

    let mut signature = vec![0_u8; needed as usize];
    // SAFETY: `signature` has at least `needed` bytes, matching the length passed in.
    let status = unsafe {
        NCryptSignHash(
            key.raw,
            std::ptr::null(),
            digest.as_ptr(),
            digest.len() as u32,
            signature.as_mut_ptr(),
            needed,
            &raw mut needed,
            0,
        )
    };
    if status < 0 {
        return Err(Error::Hardware {
            operation: "NCryptSignHash",
            code: status,
        });
    }
    signature.truncate(needed as usize);
    signature_from_raw(&signature)
}

/// Key storage provider used on Windows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WindowsProvider {
    /// TPM 2.0 (`MS_PLATFORM_CRYPTO_PROVIDER`). The private key cannot be exported.
    Tpm,
    /// Software key store (`MS_KEY_STORAGE_PROVIDER`). The private key **can** be exported
    /// by the system; used only as a fallback when no TPM is available.
    Software,
}

impl WindowsProvider {
    /// The matching CNG provider name.
    const fn provider_name(self) -> *const u16 {
        match self {
            Self::Tpm => MS_PLATFORM_CRYPTO_PROVIDER,
            Self::Software => MS_KEY_STORAGE_PROVIDER,
        }
    }

    /// The matching backend kind.
    const fn backend(self) -> Backend {
        match self {
            Self::Tpm => Backend::Tpm,
            Self::Software => Backend::Software,
        }
    }

    /// Human-readable backend name, used in error messages.
    const fn describe(self) -> &'static str {
        match self {
            Self::Tpm => "platform crypto provider (TPM)",
            Self::Software => "software key storage provider",
        }
    }
}

/// Windows hardware key store.
pub struct WindowsKeyStore {
    /// Handle of the opened provider.
    provider: CngHandle,
    /// The backend this key store is actually bound to.
    backend: Backend,
}

/// Prints the backend only; the provider handle is not part of the output.
impl fmt::Debug for WindowsKeyStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WindowsKeyStore")
            .field("backend", &self.backend)
            .finish_non_exhaustive()
    }
}

impl WindowsKeyStore {
    /// Opens the provider selected by `preferred`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::HardwareUnavailable`] when the provider is not available on this
    /// machine (no TPM, or disabled by group policy). That is an environment condition
    /// rather than a bug in this crate, so the UI can report something meaningful such as
    /// "your device has no hardware key protection".
    pub fn open(preferred: WindowsProvider) -> Result<Self> {
        let provider = open_provider(preferred.provider_name()).map_err(|error| {
            Error::HardwareUnavailable {
                reason: format!("cannot open {} ({error})", preferred.describe()),
            }
        })?;
        Ok(Self {
            provider,
            backend: preferred.backend(),
        })
    }

    /// Prefers the TPM and falls back to the software key store when it is unavailable.
    ///
    /// The fallback is always observable: [`DeviceKeyStore::backend`] reports which
    /// backend is actually in use, so a caller can tell the user that the private key is
    /// only a software file.
    ///
    /// # Errors
    ///
    /// Returns [`Error::HardwareUnavailable`] when neither provider can be opened; in that
    /// case the system itself is in a bad state.
    pub fn open_best_available() -> Result<Self> {
        match Self::open(WindowsProvider::Tpm) {
            Ok(store) => Ok(store),
            Err(tpm_error) => Self::open(WindowsProvider::Software).map_err(|software_error| {
                Error::HardwareUnavailable {
                    reason: format!(
                        "neither the TPM nor the software key store is available (TPM: {tpm_error}; software: {software_error})"
                    ),
                }
            }),
        }
    }
}

impl DeviceKeyStore for WindowsKeyStore {
    fn backend(&self) -> Backend {
        self.backend
    }

    /// Opens the identity stored under `label`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidKeyLabel`] for an unusable label and [`Error::KeyNotFound`]
    /// when no key with that name exists.
    fn open(&self, label: &str) -> Result<Box<dyn DeviceSigner>> {
        let name = key_name(label)?;
        let key = open_key(&self.provider, &name)?.ok_or_else(|| Error::KeyNotFound {
            label: label.to_string(),
        })?;
        Ok(Box::new(WindowsSigner::new(key, label, self.backend)?))
    }

    /// Creates the identity stored under `label`.
    ///
    /// An existing key is **never** overwritten: the method first opens the name to see
    /// whether it is taken, and an existing identity is reported as
    /// [`Error::KeyAlreadyExists`] rather than replaced.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidKeyLabel`] for an unusable label and
    /// [`Error::KeyAlreadyExists`] when the key already exists, including when another
    /// process created it between the check and the creation.
    fn create(&self, label: &str) -> Result<Box<dyn DeviceSigner>> {
        let name = key_name(label)?;
        if open_key(&self.provider, &name)?.is_some() {
            return Err(Error::KeyAlreadyExists {
                label: label.to_string(),
            });
        }
        let key = match create_key(&self.provider, &name)? {
            Some(key) => key,
            None => {
                return Err(Error::KeyAlreadyExists {
                    label: label.to_string(),
                });
            }
        };
        Ok(Box::new(WindowsSigner::new(key, label, self.backend)?))
    }

    /// Deletes the identity stored under `label`.
    ///
    /// The key is confirmed to exist first, so that a missing label yields an accurate
    /// [`Error::KeyNotFound`] instead of a silent success. The deletion itself is
    /// permanent.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidKeyLabel`] for an unusable label, [`Error::KeyNotFound`]
    /// when no key with that name exists, and [`Error::Hardware`] when the platform
    /// refuses the deletion.
    fn delete(&self, label: &str) -> Result<()> {
        let name = key_name(label)?;
        let Some(key) = open_key(&self.provider, &name)? else {
            return Err(Error::KeyNotFound {
                label: label.to_string(),
            });
        };

        // SAFETY: `key` holds a valid handle. `NCryptDeleteKey` releases the handle along
        // with the key, so it must not be freed afterwards: letting `CngHandle::drop` free
        // it again would be a double free. Zeroing `raw` makes the drop a no-op, because
        // its `raw != 0` check then fails.
        let status = unsafe { NCryptDeleteKey(key.raw, 0) };
        let mut key = key;
        key.raw = 0;
        if status < 0 {
            return Err(Error::Hardware {
                operation: "NCryptDeleteKey",
                code: status,
            });
        }
        Ok(())
    }
}

/// A Windows device identity: a CNG key handle plus its public key.
pub struct WindowsSigner {
    /// Key handle. Exclusively owned; released on drop.
    key: CngHandle,
    /// Logical name, used in error messages.
    label: String,
    /// Backend kind.
    backend: Backend,
    /// Already exported public key, so that queries do not call the platform API again.
    public_key: DevicePublicKey,
}

/// Prints non-secret information only: the key handle is never included.
impl fmt::Debug for WindowsSigner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WindowsSigner")
            .field("label", &self.label)
            .field("backend", &self.backend)
            .field("device_id", &self.public_key.device_id())
            .finish_non_exhaustive()
    }
}

impl WindowsSigner {
    /// Builds a signer from an already opened key handle and exports its public key.
    fn new(key: CngHandle, label: &str, backend: Backend) -> Result<Self> {
        let public_key = export_public_key(&key)?;
        Ok(Self {
            key,
            label: label.to_string(),
            backend,
            public_key,
        })
    }
}

impl DeviceSigner for WindowsSigner {
    fn backend(&self) -> Backend {
        self.backend
    }

    fn public_key(&self) -> &DevicePublicKey {
        &self.public_key
    }

    /// Signs a digest, forwarding to `sign_digest_raw`.
    fn sign_digest(&self, digest: &[u8]) -> Result<DeviceSignature> {
        sign_digest_raw(&self.key, digest)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Pins the `NTE_*` constants to the values in `winerror.h` from Windows SDK
    /// 10.0.22621.0 (`um\winerror.h`).
    ///
    /// These values are transcribed by hand (`windows-sys` does not export them), and a
    /// transcription error triggers **no** compile error: it turns the normal "no such
    /// key" path into a hardware failure, so every code path that creates a key stops
    /// working.
    #[test]
    fn nte_codes_match_winerror() {
        assert_eq!(NTE_BAD_FLAGS, 0x8009_0009_u32 as i32, "NTE_BAD_FLAGS");
        assert_eq!(NTE_NO_KEY, 0x8009_000D_u32 as i32, "NTE_NO_KEY");
        assert_eq!(NTE_EXISTS, 0x8009_000F_u32 as i32, "NTE_EXISTS");
        assert_eq!(NTE_NOT_FOUND, 0x8009_0011_u32 as i32, "NTE_NOT_FOUND");
        assert_eq!(NTE_BAD_KEYSET, 0x8009_0016_u32 as i32, "NTE_BAD_KEYSET");
    }

    /// The "no such key" group must contain the codes seen in practice.
    ///
    /// On real hardware, `NCryptOpenKey` on a name that does not exist returns
    /// `0x80090016` (`NTE_BAD_KEYSET`).
    #[test]
    fn no_such_key_codes_are_recognized() {
        assert!(means_no_such_key(0x8009_0016_u32 as i32), "NTE_BAD_KEYSET");
        assert!(means_no_such_key(0x8009_000D_u32 as i32), "NTE_NO_KEY");
        assert!(means_no_such_key(0x8009_0011_u32 as i32), "NTE_NOT_FOUND");
    }

    /// Other failures **must not** be mistaken for "no such key".
    ///
    /// The codes below are `NTE_BAD_FLAGS` (`0x80090009`), `NTE_PERM` (`0x80090010`),
    /// `NTE_INVALID_HANDLE` (`0x80090026`), `NTE_NOT_SUPPORTED` (`0x80090029`, returned
    /// for an unsupported scope string), `E_ACCESSDENIED` (`0x80070005`) and `S_OK` (`0`).
    /// A real failure such as insufficient permission must not be taken for "missing",
    /// because the code would then go on to create a key that already exists and finally
    /// report an error unrelated to the real cause.
    #[test]
    fn real_failures_are_not_mistaken_for_missing_keys() {
        for status in [
            0x8009_0009_u32 as i32,
            0x8009_0010_u32 as i32,
            0x8009_0026_u32 as i32,
            0x8009_0029_u32 as i32,
            0x8007_0005_u32 as i32,
            0,
        ] {
            assert!(
                !means_no_such_key(status),
                "0x{:08X} was mistaken for a missing key",
                status as u32
            );
        }
    }

    /// A key name must carry the prefix and be converted into a NUL-terminated wide
    /// string.
    #[test]
    fn key_name_has_prefix_and_nul_terminator() {
        let wide = key_name("device").expect("valid label");
        assert_eq!(wide.last(), Some(&0), "must end with NUL");
        let text = String::from_utf16(&wide[..wide.len() - 1]).expect("valid UTF-16");
        assert_eq!(text, "Qualia2FA-Device-device");
    }

    /// **NUL truncation**: if `\0` were allowed in a label, `"a\0b"` and `"a"` would be
    /// the same key name as far as the C string is concerned, so two different labels
    /// would map to one device identity.
    #[test]
    fn label_with_nul_is_rejected() {
        assert!(key_name("a\0b").is_err());
        assert!(key_name("a\u{0}").is_err());
    }

    /// Characters with a special meaning in paths and namespaces must all be rejected.
    #[test]
    fn label_with_special_characters_is_rejected() {
        for bad in [
            "a/b", "a\\b", "a b", "a:b", "a*b", "a?b", "a\"b", "a<b", "a|b", "设备", "a\nb", "a\tb",
        ] {
            assert!(key_name(bad).is_err(), "{bad:?} must not be accepted");
        }
    }

    /// The allowed character set must be just large enough to be usable.
    #[test]
    fn label_with_allowed_characters_is_accepted() {
        for good in ["device", "Device-1", "a_b.c", "ABC123", "x"] {
            assert!(key_name(good).is_ok(), "{good:?} must be accepted");
        }
    }

    /// Empty labels and labels over the limit must both be rejected.
    #[test]
    fn empty_and_oversized_labels_are_rejected() {
        assert!(key_name("").is_err());
        assert!(key_name(&"a".repeat(MAX_LABEL_LEN)).is_ok());
        assert!(key_name(&"a".repeat(MAX_LABEL_LEN + 1)).is_err());
    }

    /// The mapping between backend kind and provider name.
    #[test]
    fn provider_maps_to_backend() {
        assert_eq!(WindowsProvider::Tpm.backend(), Backend::Tpm);
        assert_eq!(WindowsProvider::Software.backend(), Backend::Software);
        assert!(WindowsProvider::Tpm.backend().is_hardware_backed());
        assert!(!WindowsProvider::Software.backend().is_hardware_backed());
    }
}
