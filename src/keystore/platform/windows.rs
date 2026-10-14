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
    Backend, DIGEST_LEN, DeviceKeyStore, DeviceSigner, DirectMasterKeyStore, MASTER_KEY_LEN,
    MasterKey, WrappedMasterKey, WrappedMasterKeyStore, public_key_from_sec1, secrets_equal,
    signature_from_raw,
};
use crate::{Error, Result};
use std::fmt;
use windows_sys::Win32::Security::Cryptography::{
    BCRYPT_ECCPRIVATE_BLOB, BCRYPT_ECCPUBLIC_BLOB, BCRYPT_ECDSA_PRIVATE_P256_MAGIC,
    BCRYPT_OAEP_PADDING_INFO, BCRYPT_SHA256_ALGORITHM, BCryptBuffer, BCryptBufferDesc,
    MS_KEY_STORAGE_PROVIDER, MS_PLATFORM_CRYPTO_PROVIDER, NCRYPT_ALLOW_EXPORT_FLAG,
    NCRYPT_ALLOW_PLAINTEXT_EXPORT_FLAG, NCRYPT_DO_NOT_FINALIZE_FLAG, NCRYPT_ECDSA_P256_ALGORITHM,
    NCRYPT_EXPORT_POLICY_PROPERTY, NCRYPT_KEY_HANDLE, NCRYPT_LENGTH_PROPERTY, NCRYPT_PAD_OAEP_FLAG,
    NCRYPT_PROV_HANDLE, NCRYPT_RSA_ALGORITHM, NCRYPT_SILENT_FLAG, NCRYPTBUFFER_PKCS_KEY_NAME,
    NCRYPTBUFFER_VERSION, NCryptCreatePersistedKey, NCryptDecrypt, NCryptDeleteKey, NCryptEncrypt,
    NCryptExportKey, NCryptFinalizeKey, NCryptFreeObject, NCryptImportKey, NCryptOpenKey,
    NCryptOpenStorageProvider, NCryptSetProperty, NCryptSignHash,
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
fn key_name_with_prefix(prefix: &str, label: &str) -> Result<Vec<u16>> {
    if label.is_empty() {
        return Err(Error::InvalidKeyLabel {
            reason: "the label is empty",
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
    let name = format!("{prefix}{label}");
    let mut wide: Vec<u16> = name.encode_utf16().collect();
    wide.push(0);
    Ok(wide)
}

/// Key name of a device identity.
fn key_name(label: &str) -> Result<Vec<u16>> {
    key_name_with_prefix(KEY_NAME_PREFIX, label)
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

// ── Master key ──────────────────────────────────────────────────────

/// Key-name prefix under which the direct form stores the material.
const MASTER_KEY_NAME_PREFIX: &str = "Qualia2FA-MasterKey-";

/// Key-name prefix under which the wrapped form stores its key-encryption key.
const MASTER_KEK_NAME_PREFIX: &str = "Qualia2FA-MasterKek-";

/// Prefix of the key name the direct form probes a provider with.
///
/// A provider is only usable for the direct form if it accepts material **and hands it back
/// again**, and that cannot be read off a provider name. Opening the store therefore
/// imports a key, reads it back, compares, and deletes it again.
///
/// The name carries the process id and a sequence number, so two processes — and two
/// threads of one process — never probe under the same name. A shared name would be a race:
/// one probe deletes the key the other has just imported and is about to read, and the store
/// would report a provider as unusable because somebody else was using the same name. The
/// cost is that a process killed in the middle of a probe leaves one key behind, which
/// carries this prefix and can be deleted by hand.
const MASTER_PROBE_KEY_NAME: &str = "Qualia2FA-MasterProbe";

/// Sequence number that makes a probe key name unique inside one process.
static PROBE_SEQUENCE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Length of the RSA key-encryption key of the wrapped form, in bits.
///
/// 2048 bits with OAEP-SHA256 carries a 32-byte master key with room to spare (the maximum
/// is 190 bytes, RFC 8017 §7.1.1) and is the size every CNG provider supports, including
/// the TPM.
const MASTER_KEK_BITS: u32 = 2048;

/// Length of a wrapped master key, in bytes.
///
/// The RSA operation returns one modulus-sized block, so this is `MASTER_KEK_BITS / 8`.
const WRAPPED_MASTER_KEY_LEN: usize = (MASTER_KEK_BITS / 8) as usize;

/// Export policy of a key that holds master key material: export allowed.
///
/// The direct form promises to hand the material back, so the key that holds it has to be
/// exportable. `NCRYPT_ALLOW_EXPORT_FLAG` permits the private blob, and
/// `NCRYPT_ALLOW_PLAINTEXT_EXPORT_FLAG` permits exporting it without an extra prompt.
const MATERIAL_EXPORT_POLICY: u32 = NCRYPT_ALLOW_EXPORT_FLAG | NCRYPT_ALLOW_PLAINTEXT_EXPORT_FLAG;

/// Export policy of the key-encryption key: **no export at all**.
///
/// The wrapped form exists because the key that unwraps the master key cannot leave the
/// platform; a KEK that could be exported would defeat it.
const KEK_EXPORT_POLICY: u32 = 0;

/// Length of a `BCRYPT_ECCPRIVATE_BLOB` for P-256, in bytes.
///
/// The blob is an 8-byte `BCRYPT_ECCKEY_BLOB` header (`{ dwMagic: u32, cbKey: u32 }`)
/// followed by `X` and `Y` (32 bytes each) and the private scalar `d` (32 bytes).
const ECC_PRIVATE_BLOB_LEN: usize = 8 + 3 * 32;

/// Offset of the private scalar inside a `BCRYPT_ECCPRIVATE_BLOB` for P-256.
const ECC_PRIVATE_SCALAR_OFFSET: usize = 8 + 2 * 32;

/// Key name of a directly stored master key.
fn master_key_name(label: &str) -> Result<Vec<u16>> {
    key_name_with_prefix(MASTER_KEY_NAME_PREFIX, label)
}

/// Key name of a wrapped master key's key-encryption key.
fn master_kek_name(label: &str) -> Result<Vec<u16>> {
    key_name_with_prefix(MASTER_KEK_NAME_PREFIX, label)
}

/// A probe key name that no other probe in this process uses.
fn probe_key_name() -> Vec<u16> {
    let sequence = PROBE_SEQUENCE.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let mut name: Vec<u16> = format!("{MASTER_PROBE_KEY_NAME}-{}-{sequence}", std::process::id())
        .encode_utf16()
        .collect();
    name.push(0);
    name
}

/// Builds the `BCRYPT_ECCPRIVATE_BLOB` that carries `material` as a P-256 private scalar.
///
/// # Why a private scalar
///
/// CNG's key storage providers persist **keys**, and nothing else: they refuse to import a
/// symmetric key's material (`BCRYPT_KEY_DATA_BLOB` and `NCRYPT_CIPHER_KEY_BLOB` are both
/// rejected with `NTE_NOT_SUPPORTED`) and they refuse custom key properties. A P-256
/// private key is the one object whose material a provider both stores and — with an export
/// policy that allows it — returns, so the material is carried as the private scalar of a
/// key that is never used for signing. The public point is derived from it because the blob
/// format requires a point that matches.
///
/// # Errors
///
/// [`Error::InvalidMasterKey`] when `material` is not a valid P-256 scalar. Random 32-byte
/// material is below the group order with probability `1 - 2^-32`, so this is a real, if
/// extremely rare, case that has to be an error rather than a panic.
fn material_to_private_blob(material: &[u8; MASTER_KEY_LEN]) -> Result<Vec<u8>> {
    let signing = p256::ecdsa::SigningKey::from_slice(material).map_err(|_| {
        Error::InvalidMasterKey {
            reason: "the material is not a valid P-256 scalar, so the software provider cannot hold it as a key",
        }
    })?;
    let point = signing.verifying_key().to_sec1_point(false);
    let sec1 = point.as_bytes();
    if sec1.len() != 65 {
        return Err(Error::InvalidMasterKey {
            reason: "the P-256 public point is not 65 bytes long",
        });
    }

    let mut blob = Vec::with_capacity(ECC_PRIVATE_BLOB_LEN);
    blob.extend_from_slice(&BCRYPT_ECDSA_PRIVATE_P256_MAGIC.to_le_bytes());
    blob.extend_from_slice(&32_u32.to_le_bytes());
    blob.extend_from_slice(&sec1[1..33]);
    blob.extend_from_slice(&sec1[33..65]);
    blob.extend_from_slice(material);
    Ok(blob)
}

/// Takes the private scalar out of a `BCRYPT_ECCPRIVATE_BLOB`.
///
/// # Errors
///
/// [`Error::InvalidMasterKey`] when the blob is not a P-256 private blob: a wrong length,
/// a magic that is not `BCRYPT_ECDSA_PRIVATE_P256_MAGIC`, or a `cbKey` that is not 32.
fn private_blob_to_material(blob: &[u8]) -> Result<MasterKey> {
    if blob.len() != ECC_PRIVATE_BLOB_LEN {
        return Err(Error::InvalidMasterKey {
            reason: "the private key blob returned by the platform is not 104 bytes long",
        });
    }
    let magic = u32::from_le_bytes([blob[0], blob[1], blob[2], blob[3]]);
    if magic != BCRYPT_ECDSA_PRIVATE_P256_MAGIC {
        return Err(Error::InvalidMasterKey {
            reason: "the private key blob returned by the platform is not a P-256 private blob",
        });
    }
    let cb_key = u32::from_le_bytes([blob[4], blob[5], blob[6], blob[7]]);
    if cb_key != 32 {
        return Err(Error::InvalidMasterKey {
            reason: "the private key blob returned by the platform is not a 32-byte coordinate (not P-256)",
        });
    }

    let mut material = [0_u8; MASTER_KEY_LEN];
    material.copy_from_slice(&blob[ECC_PRIVATE_SCALAR_OFFSET..]);
    Ok(MasterKey::from_bytes(material))
}

/// Writes a 32-bit property on a key.
///
/// # Errors
///
/// [`Error::Hardware`] with the provider's status code.
fn set_key_dword(key: &CngHandle, property: *const u16, value: u32) -> Result<()> {
    // SAFETY: `key` holds a valid key handle, `property` is a static wide string exported by
    // `windows-sys`, and the pointer with its length describe `value`, which outlives the
    // call.
    let status = unsafe {
        NCryptSetProperty(
            key.raw,
            property,
            (&raw const value).cast::<u8>(),
            4,
            NCRYPT_SILENT_FLAG,
        )
    };
    if status < 0 {
        return Err(Error::Hardware {
            operation: "NCryptSetProperty",
            code: status,
        });
    }
    Ok(())
}

/// Exports a key in the format `blob_type` names.
///
/// Two calls, as CNG requires: the first asks for the length, the second fills a buffer of
/// that length.
///
/// # Errors
///
/// [`Error::Hardware`] with the status code, and [`Error::InvalidMasterKey`] when the
/// provider reports an implausible length (more than 4096 bytes).
fn export_blob(key: &CngHandle, blob_type: *const u16, operation: &'static str) -> Result<Vec<u8>> {
    let mut needed: u32 = 0;
    // SAFETY: `key` is valid; a null output pointer with length 0 is the documented way to
    // query the required length, and nothing is written to memory in that case.
    let status = unsafe {
        NCryptExportKey(
            key.raw,
            0,
            blob_type,
            std::ptr::null(),
            std::ptr::null_mut(),
            0,
            &raw mut needed,
            0,
        )
    };
    if status < 0 {
        return Err(Error::Hardware {
            operation,
            code: status,
        });
    }
    if needed > 4096 {
        return Err(Error::InvalidMasterKey {
            reason: "the platform reported an implausible key blob length (over 4096 bytes)",
        });
    }

    let mut blob = vec![0_u8; needed as usize];
    // SAFETY: `blob` has at least `needed` bytes, matching the length passed in.
    let status = unsafe {
        NCryptExportKey(
            key.raw,
            0,
            blob_type,
            std::ptr::null(),
            blob.as_mut_ptr(),
            needed,
            &raw mut needed,
            0,
        )
    };
    if status < 0 {
        return Err(Error::Hardware {
            operation,
            code: status,
        });
    }
    blob.truncate(needed as usize);
    Ok(blob)
}

/// Imports a key blob under a name, so that the provider persists it.
///
/// The name travels in a parameter list (`NCRYPTBUFFER_PKCS_KEY_NAME`), which is how CNG
/// names an imported key: `NCryptImportKey` has no name parameter, and an import without a
/// name is treated as ephemeral.
///
/// # Errors
///
/// [`Error::Hardware`] with the status code. `NTE_EXISTS` is **not** translated here: the
/// callers decide whether an existing entry is a race to resolve or an error.
fn import_named_key(
    provider: &CngHandle,
    name: &[u16],
    blob_type: *const u16,
    blob: &[u8],
    flags: u32,
) -> Result<CngHandle> {
    let mut name_buffer = BCryptBuffer {
        cbBuffer: (name.len() * 2) as u32,
        BufferType: NCRYPTBUFFER_PKCS_KEY_NAME,
        pvBuffer: name.as_ptr().cast_mut().cast(),
    };
    let parameters = BCryptBufferDesc {
        ulVersion: NCRYPTBUFFER_VERSION,
        cBuffers: 1,
        pBuffers: &raw mut name_buffer,
    };
    let mut key: NCRYPT_KEY_HANDLE = 0;
    // SAFETY: `provider` is valid, `parameters` describes a buffer that stays alive and
    // writable for the call, `blob` is a valid slice, and `key` is writable.
    let status = unsafe {
        NCryptImportKey(
            provider.raw,
            0,
            blob_type,
            &parameters,
            &raw mut key,
            blob.as_ptr(),
            blob.len() as u32,
            flags,
        )
    };
    if status < 0 {
        return Err(Error::Hardware {
            operation: "NCryptImportKey",
            code: status,
        });
    }
    Ok(CngHandle::new(key))
}

/// Deletes a persisted key by name.
///
/// # Errors
///
/// [`Error::KeyNotFound`] when no key has that name, and [`Error::Hardware`] when the
/// provider refuses the deletion.
fn delete_key_by_name(provider: &CngHandle, name: &[u16]) -> Result<()> {
    let mut handle: NCRYPT_KEY_HANDLE = 0;
    // SAFETY: `provider` is valid, `name` is NUL-terminated and stays alive for the call,
    // and `handle` is writable.
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
        return Err(Error::KeyNotFound {
            label: String::from_utf16_lossy(&name[..name.len().saturating_sub(1)]),
        });
    }
    if status < 0 {
        return Err(Error::Hardware {
            operation: "NCryptOpenKey",
            code: status,
        });
    }

    let mut key = CngHandle::new(handle);
    // SAFETY: `handle` is valid. `NCryptDeleteKey` releases the handle along with the key,
    // so it must not be freed afterwards: zeroing `raw` makes `CngHandle::drop` a no-op.
    let status = unsafe { NCryptDeleteKey(key.raw, 0) };
    key.raw = 0;
    if status < 0 {
        return Err(Error::Hardware {
            operation: "NCryptDeleteKey",
            code: status,
        });
    }
    Ok(())
}

/// Removes a key object that may never have been finalized, best effort.
///
/// CNG deletes a key through an open handle, and a key that was created but not finalized
/// still occupies its name, so the finalization is retried here before the deletion. Both
/// steps are best effort: this runs while another failure is already being reported, and a
/// second error would replace a diagnosis with a mystery.
fn remove_unfinished_key(provider: &CngHandle, name: &[u16]) {
    let Ok(Some(mut key)) = open_key(provider, name) else {
        return;
    };
    // SAFETY: `key` holds a valid key handle that this function owns.
    let _ = unsafe { NCryptFinalizeKey(key.raw, NCRYPT_SILENT_FLAG) };
    // SAFETY: the handle is still valid. `NCryptDeleteKey` releases it along with the key, so
    // zeroing `raw` keeps `CngHandle::drop` from freeing it a second time.
    let _ = unsafe { NCryptDeleteKey(key.raw, 0) };
    key.raw = 0;
}

/// Stores the material as a persisted P-256 key and finalizes it.
///
/// # Errors
///
/// [`Error::Hardware`] with the status code of the failing step. A key object that was left
/// behind by a failing step is removed again, because it occupies the name and the next
/// attempt would find it taken.
fn store_material_key(
    provider: &CngHandle,
    name: &[u16],
    material: &[u8; MASTER_KEY_LEN],
) -> Result<()> {
    let blob = material_to_private_blob(material)?;
    let result = (|| -> Result<()> {
        let key = import_named_key(
            provider,
            name,
            BCRYPT_ECCPRIVATE_BLOB,
            &blob,
            NCRYPT_SILENT_FLAG | NCRYPT_DO_NOT_FINALIZE_FLAG,
        )?;
        set_key_dword(&key, NCRYPT_EXPORT_POLICY_PROPERTY, MATERIAL_EXPORT_POLICY)?;
        // SAFETY: `key` holds a valid, not yet finalized key handle.
        let status = unsafe { NCryptFinalizeKey(key.raw, NCRYPT_SILENT_FLAG) };
        if status < 0 {
            return Err(Error::Hardware {
                operation: "NCryptFinalizeKey",
                code: status,
            });
        }
        Ok(())
    })();

    if result.is_err() {
        remove_unfinished_key(provider, name);
    }
    result
}

/// Reads the material back out of the persisted key.
///
/// # Errors
///
/// [`Error::KeyNotFound`] when the name holds nothing, and an export failure or a blob that
/// is not a P-256 private blob as documented on the two helpers.
fn load_material(provider: &CngHandle, name: &[u16]) -> Result<MasterKey> {
    let key = open_key(provider, name)?.ok_or_else(|| Error::KeyNotFound {
        label: String::from_utf16_lossy(&name[..name.len().saturating_sub(1)]),
    })?;
    let blob = export_blob(&key, BCRYPT_ECCPRIVATE_BLOB, "NCryptExportKey")?;
    private_blob_to_material(&blob)
}

/// Whether `provider` can hold master key material **and hand it back**.
///
/// This is the probe the direct form decides with. It is not a formality: the Microsoft
/// Platform Crypto Provider imports a key under our name, finalizes it and then refuses to
/// export it (`NTE_PERM`), so a store that only checked "can I create a key here" would
/// accept material it could never return.
///
/// # Errors
///
/// The failure of whichever step the provider refused, so that the caller can report why
/// the provider is unusable for this form.
fn provider_can_hold_material(provider: &CngHandle) -> Result<()> {
    let name = probe_key_name();

    let probe = [0x5A_u8; MASTER_KEY_LEN];
    let result = (|| -> Result<()> {
        store_material_key(provider, &name, &probe)?;
        let read_back = load_material(provider, &name)?;
        if !secrets_equal(read_back.as_bytes(), &probe) {
            return Err(Error::InvalidMasterKey {
                reason: "the provider returned material that differs from what was stored in it",
            });
        }
        Ok(())
    })();

    let _ = delete_key_by_name(provider, &name);
    result
}

/// Opens a key-encryption key that already exists, or creates and finalizes one.
///
/// # Errors
///
/// [`Error::Hardware`] with the status code of the failing step.
fn open_or_create_kek(provider: &CngHandle, name: &[u16]) -> Result<CngHandle> {
    if let Some(key) = open_key(provider, name)? {
        return Ok(key);
    }

    let mut handle: NCRYPT_KEY_HANDLE = 0;
    // SAFETY: `provider` is valid, `name` is NUL-terminated and stays alive for the call,
    // and `handle` is writable.
    let status = unsafe {
        NCryptCreatePersistedKey(
            provider.raw,
            &raw mut handle,
            NCRYPT_RSA_ALGORITHM,
            name.as_ptr(),
            0,
            0,
        )
    };
    if status == NTE_EXISTS {
        return open_key(provider, name)?.ok_or(Error::KeyNotFound {
            label: String::from_utf16_lossy(&name[..name.len().saturating_sub(1)]),
        });
    }
    if status < 0 {
        return Err(Error::Hardware {
            operation: "NCryptCreatePersistedKey",
            code: status,
        });
    }
    let key = CngHandle::new(handle);

    let result = (|| -> Result<()> {
        set_key_dword(&key, NCRYPT_LENGTH_PROPERTY, MASTER_KEK_BITS)?;
        set_key_dword(&key, NCRYPT_EXPORT_POLICY_PROPERTY, KEK_EXPORT_POLICY)?;
        // SAFETY: `key` holds a valid, not yet finalized key handle.
        let status = unsafe { NCryptFinalizeKey(key.raw, NCRYPT_SILENT_FLAG) };
        if status < 0 {
            return Err(Error::Hardware {
                operation: "NCryptFinalizeKey",
                code: status,
            });
        }
        Ok(())
    })();

    if let Err(error) = result {
        remove_unfinished_key(provider, name);
        return Err(error);
    }
    Ok(key)
}

/// The OAEP parameters used for wrapping: SHA-256, no label.
fn oaep_padding() -> BCRYPT_OAEP_PADDING_INFO {
    BCRYPT_OAEP_PADDING_INFO {
        pszAlgId: BCRYPT_SHA256_ALGORITHM,
        pbLabel: std::ptr::null_mut(),
        cbLabel: 0,
    }
}

/// Wraps the material with a key-encryption key (RSA-OAEP-SHA256, RFC 8017 §7.1.1).
///
/// # Errors
///
/// [`Error::Hardware`] with the status code when the provider refuses the operation.
fn wrap_with_kek(kek: &CngHandle, material: &[u8; MASTER_KEY_LEN]) -> Result<WrappedMasterKey> {
    let padding = oaep_padding();
    let mut needed: u32 = 0;
    // SAFETY: `kek` is valid, `material` and `padding` stay alive for the call, and a null
    // output pointer with length 0 is the documented way to query the required length.
    let status = unsafe {
        NCryptEncrypt(
            kek.raw,
            material.as_ptr(),
            material.len() as u32,
            (&raw const padding).cast(),
            std::ptr::null_mut(),
            0,
            &raw mut needed,
            NCRYPT_PAD_OAEP_FLAG,
        )
    };
    if status < 0 {
        return Err(Error::Hardware {
            operation: "NCryptEncrypt(query length)",
            code: status,
        });
    }
    if needed as usize != WRAPPED_MASTER_KEY_LEN {
        return Err(Error::Hardware {
            operation: "NCryptEncrypt reported an unexpected ciphertext length",
            code: needed as i32,
        });
    }

    let mut wrapped = vec![0_u8; WRAPPED_MASTER_KEY_LEN];
    // SAFETY: `wrapped` has exactly `needed` bytes, matching the length passed in.
    let status = unsafe {
        NCryptEncrypt(
            kek.raw,
            material.as_ptr(),
            material.len() as u32,
            (&raw const padding).cast(),
            wrapped.as_mut_ptr(),
            needed,
            &raw mut needed,
            NCRYPT_PAD_OAEP_FLAG,
        )
    };
    if status < 0 {
        return Err(Error::Hardware {
            operation: "NCryptEncrypt",
            code: status,
        });
    }
    wrapped.truncate(needed as usize);
    Ok(WrappedMasterKey::from_bytes(wrapped))
}

/// Unwraps the material with a key-encryption key.
///
/// # Errors
///
/// [`Error::InvalidWrappedKey`] carrying the provider's code when the provider rejects the
/// bytes: OAEP's own check fails for a damaged blob, for a blob from another KEK and for a
/// blob from another device, and the provider reports that as an error rather than as
/// bytes. [`Error::KeyNotFound`] is reported by the caller, not here.
fn unwrap_with_kek(kek: &CngHandle, wrapped: &[u8]) -> Result<MasterKey> {
    let padding = oaep_padding();
    let mut plain = vec![0_u8; MASTER_KEY_LEN];
    let mut needed: u32 = MASTER_KEY_LEN as u32;
    // SAFETY: `kek` is valid, `wrapped` and `padding` stay alive for the call, and `plain`
    // is a writable buffer of exactly the length passed in.
    let status = unsafe {
        NCryptDecrypt(
            kek.raw,
            wrapped.as_ptr(),
            wrapped.len() as u32,
            (&raw const padding).cast(),
            plain.as_mut_ptr(),
            needed,
            &raw mut needed,
            NCRYPT_PAD_OAEP_FLAG,
        )
    };
    if status < 0 {
        return Err(Error::InvalidWrappedKey {
            reason: "the key-encryption key rejected the bytes (damaged, or wrapped by a different key)",
            code: status,
        });
    }
    if needed as usize != MASTER_KEY_LEN {
        return Err(Error::InvalidWrappedKey {
            reason: "the wrapped bytes do not decrypt to a 32-byte master key",
            code: 0,
        });
    }

    let mut material = [0_u8; MASTER_KEY_LEN];
    material.copy_from_slice(&plain);
    Ok(MasterKey::from_bytes(material))
}

/// Master key store of the **direct** form on Windows.
///
/// # What it holds
///
/// The material itself, as the private scalar of a P-256 key in the storage provider that
/// answered. The provider protects the key with whatever it uses for its own keys, and the
/// key is marked exportable, because this form's contract is to hand the material back.
///
/// # Why the material travels as a private key
///
/// A CNG key storage provider persists **keys** and nothing else: importing a symmetric key's
/// material is refused with `NTE_NOT_SUPPORTED`, and so is a custom key property. A P-256
/// private key is the one object whose material a provider both stores and — with an export
/// policy that allows it — returns, so the master key is carried as the private scalar of a
/// key that is never used for signing. 32 bytes of random material is below the group order
/// with probability `1 - 2^-32`; that remainder is an error
/// ([`Error::InvalidMasterKey`]), never a panic.
///
/// # Which provider
///
/// The Microsoft Platform Crypto Provider is tried first, and the Microsoft Software Key
/// Storage Provider is the fallback; [`DirectMasterKeyStore::backend`] reports which one the
/// store ended up with. On a machine with a TPM the answer is still
/// [`Backend::Software`]: the TPM provider imports the key and then refuses to export it
/// (`NTE_PERM`), and a store that cannot return the material is not a store for this form.
/// A caller who wants the material protected by the TPM wants the wrapped form.
pub struct WindowsDirectMasterKeyStore {
    /// Handle of the opened provider.
    provider: CngHandle,
    /// The provider that answered, as probed when the store was opened.
    backend: Backend,
}

/// Prints the backend only.
impl fmt::Debug for WindowsDirectMasterKeyStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WindowsDirectMasterKeyStore")
            .field("backend", &self.backend)
            .finish_non_exhaustive()
    }
}

impl WindowsDirectMasterKeyStore {
    /// Opens `preferred` and checks that it can hold master key material.
    ///
    /// # Errors
    ///
    /// [`Error::HardwareUnavailable`] when the provider cannot be opened, and the same error
    /// carrying the probe's own failure when it opens but cannot hold the material and hand
    /// it back.
    pub fn open(preferred: WindowsProvider) -> Result<Self> {
        let provider = open_provider(preferred.provider_name()).map_err(|error| {
            Error::HardwareUnavailable {
                reason: format!("cannot open {} ({error})", preferred.describe()),
            }
        })?;
        provider_can_hold_material(&provider).map_err(|error| Error::HardwareUnavailable {
            reason: format!(
                "{} cannot hold master key material: {error}",
                preferred.describe()
            ),
        })?;
        Ok(Self {
            provider,
            backend: preferred.backend(),
        })
    }

    /// Prefers the TPM and falls back to the software key store.
    ///
    /// # Errors
    ///
    /// [`Error::HardwareUnavailable`] when neither provider can hold the material; in that
    /// case the system itself is in a bad state.
    pub fn open_best_available() -> Result<Self> {
        match Self::open(WindowsProvider::Tpm) {
            Ok(store) => Ok(store),
            Err(tpm_error) => Self::open(WindowsProvider::Software).map_err(|software_error| {
                Error::HardwareUnavailable {
                    reason: format!(
                        "neither the TPM nor the software key store can hold master key material (TPM: {tpm_error}; software: {software_error})"
                    ),
                }
            }),
        }
    }
}

impl DirectMasterKeyStore for WindowsDirectMasterKeyStore {
    fn backend(&self) -> Backend {
        self.backend
    }

    /// Stores the material, replacing what was under `label`.
    ///
    /// The material is read back and compared before this returns: a store that accepted
    /// material it cannot return would look like a working store until the first attempt to
    /// open a vault.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidKeyLabel`] for an unusable label, [`Error::InvalidMasterKey`] when
    /// the provider returned something else than what was stored, and [`Error::Hardware`]
    /// when the provider refuses.
    fn store(&self, label: &str, key: &MasterKey) -> Result<()> {
        let name = master_key_name(label)?;

        match delete_key_by_name(&self.provider, &name) {
            Ok(()) | Err(Error::KeyNotFound { .. }) => {}
            Err(other) => return Err(other),
        }

        store_material_key(&self.provider, &name, key.as_bytes())?;
        let read_back = load_material(&self.provider, &name)?;
        if !secrets_equal(read_back.as_bytes(), key.as_bytes()) {
            let _ = delete_key_by_name(&self.provider, &name);
            return Err(Error::InvalidMasterKey {
                reason: "the provider returned material that differs from what was stored in it",
            });
        }
        Ok(())
    }

    /// Reads the material back.
    ///
    /// # Errors
    ///
    /// [`Error::KeyNotFound`] when the label holds nothing, plus the label and provider
    /// failures documented on the helpers.
    fn load(&self, label: &str) -> Result<MasterKey> {
        let name = master_key_name(label)?;
        load_material(&self.provider, &name)
    }

    /// Deletes the entry.
    ///
    /// # Errors
    ///
    /// [`Error::KeyNotFound`] when the label holds nothing.
    fn delete(&self, label: &str) -> Result<()> {
        let name = master_key_name(label)?;
        delete_key_by_name(&self.provider, &name)
    }
}

/// Master key store of the **wrapped** form on Windows.
///
/// # What it holds
///
/// A 2048-bit RSA key per label, created in the storage provider, marked **non-exportable**
/// (`NCRYPT_EXPORT_POLICY_PROPERTY` = 0) and never handed out. Wrapping and unwrapping run
/// inside that key: `NCryptEncrypt` / `NCryptDecrypt` with OAEP-SHA256. On the Microsoft
/// Platform Crypto Provider the unwrap is a TPM private key operation, so the material comes
/// back only on the machine that sealed it.
///
/// # Which provider
///
/// The TPM provider is preferred and the software key store is the fallback, with
/// [`WrappedMasterKeyStore::backend`] reporting which one answered. Both support RSA-2048
/// with OAEP, so on a machine with a usable TPM this form really is hardware backed — unlike
/// the direct form, which the TPM provider cannot serve at all.
pub struct WindowsWrappedMasterKeyStore {
    /// Handle of the opened provider.
    provider: CngHandle,
    /// The backend this store is actually bound to.
    backend: Backend,
}

/// Prints the backend only.
impl fmt::Debug for WindowsWrappedMasterKeyStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WindowsWrappedMasterKeyStore")
            .field("backend", &self.backend)
            .finish_non_exhaustive()
    }
}

impl WindowsWrappedMasterKeyStore {
    /// Opens the provider selected by `preferred`.
    ///
    /// # Errors
    ///
    /// [`Error::HardwareUnavailable`] when the provider is not available on this machine.
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

    /// Prefers the TPM and falls back to the software key store.
    ///
    /// # Errors
    ///
    /// [`Error::HardwareUnavailable`] when neither provider can be opened.
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

impl WrappedMasterKeyStore for WindowsWrappedMasterKeyStore {
    fn backend(&self) -> Backend {
        self.backend
    }

    /// Wraps the material with this label's key-encryption key, creating the KEK on first
    /// use.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidKeyLabel`] for an unusable label, and [`Error::Hardware`] when the
    /// provider refuses to create or use the KEK.
    fn store(&self, label: &str, key: &MasterKey) -> Result<WrappedMasterKey> {
        let name = master_kek_name(label)?;
        let kek = open_or_create_kek(&self.provider, &name)?;
        wrap_with_kek(&kek, key.as_bytes())
    }

    /// Unwraps the bytes with this label's key-encryption key.
    ///
    /// # Errors
    ///
    /// [`Error::KeyNotFound`] when the label has no KEK, and [`Error::InvalidWrappedKey`]
    /// when the bytes are not a wrapped master key or do not unwrap on this machine.
    fn load(&self, label: &str, wrapped: &WrappedMasterKey) -> Result<MasterKey> {
        let name = master_kek_name(label)?;
        if wrapped.as_bytes().len() != WRAPPED_MASTER_KEY_LEN {
            return Err(Error::InvalidWrappedKey {
                reason: "the wrapped master key is not the 256 bytes a 2048-bit key-encryption key produces",
                code: 0,
            });
        }
        let kek = open_key(&self.provider, &name)?.ok_or_else(|| Error::KeyNotFound {
            label: label.to_string(),
        })?;
        unwrap_with_kek(&kek, wrapped.as_bytes())
    }

    /// Deletes this label's key-encryption key, which makes every blob it wrapped unusable.
    ///
    /// # Errors
    ///
    /// [`Error::KeyNotFound`] when the label has no KEK.
    fn delete(&self, label: &str) -> Result<()> {
        let name = master_kek_name(label)?;
        delete_key_by_name(&self.provider, &name)
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

    /// The three key prefixes have to stay distinct: an identity, a directly stored master
    /// key and a key-encryption key may share one label, and one must never overwrite
    /// another.
    #[test]
    fn key_prefixes_are_distinct() {
        let identity = key_name("shared").expect("valid label");
        let material = master_key_name("shared").expect("valid label");
        let kek = master_kek_name("shared").expect("valid label");
        assert_ne!(identity, material);
        assert_ne!(identity, kek);
        assert_ne!(material, kek);

        let text =
            |wide: &[u16]| String::from_utf16(&wide[..wide.len() - 1]).expect("valid UTF-16");
        assert_eq!(text(&material), "Qualia2FA-MasterKey-shared");
        assert_eq!(text(&kek), "Qualia2FA-MasterKek-shared");
    }

    /// Master key labels follow the same rules as device identity labels.
    #[test]
    fn master_key_labels_are_validated() {
        for bad in ["", "a/b", "a\0b", "has space", "设备"] {
            assert!(master_key_name(bad).is_err(), "{bad:?} must be rejected");
            assert!(master_kek_name(bad).is_err(), "{bad:?} must be rejected");
        }
        assert!(master_key_name("account-1").is_ok());
        assert!(master_kek_name("account-1").is_ok());
    }

    /// Material survives the trip through the private key blob it is carried in.
    ///
    /// This is the encoding the direct form rests on: if the scalar did not come back, the
    /// store would return material that differs from what it was given, which is the one
    /// thing the form must never do.
    #[test]
    fn material_survives_the_private_blob() {
        let material = [
            0x5A_u8, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD,
            0xEE, 0xFF, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C,
            0x0D, 0x0E, 0x0F, 0x10,
        ];
        let blob = material_to_private_blob(&material).expect("the material is a valid scalar");
        assert_eq!(blob.len(), ECC_PRIVATE_BLOB_LEN);
        let magic = u32::from_le_bytes([blob[0], blob[1], blob[2], blob[3]]);
        assert_eq!(magic, BCRYPT_ECDSA_PRIVATE_P256_MAGIC);
        assert_eq!(&blob[ECC_PRIVATE_SCALAR_OFFSET..], &material[..]);

        let back = private_blob_to_material(&blob).expect("the blob is a P-256 private blob");
        assert!(secrets_equal(back.as_bytes(), &material));
    }

    /// Material that is not a valid P-256 scalar is an error, never a panic.
    #[test]
    fn invalid_scalar_is_rejected() {
        let error = material_to_private_blob(&[0xFF_u8; MASTER_KEY_LEN])
            .expect_err("all-ones is above the group order");
        assert!(matches!(error, Error::InvalidMasterKey { .. }));
        assert!(
            material_to_private_blob(&[0x00_u8; MASTER_KEY_LEN]).is_err(),
            "zero is not a valid scalar either"
        );
    }

    /// A blob that is not a P-256 private blob is rejected rather than interpreted.
    #[test]
    fn foreign_private_blobs_are_rejected() {
        let material = [0x11_u8; MASTER_KEY_LEN];
        let good = material_to_private_blob(&material).expect("valid scalar");

        let mut short = good.clone();
        short.truncate(ECC_PRIVATE_BLOB_LEN - 1);
        let mut wrong_magic = good.clone();
        wrong_magic[0] ^= 0x01;
        let mut wrong_key_size = good.clone();
        wrong_key_size[4] = 64;

        for blob in [short, wrong_magic, wrong_key_size, Vec::new()] {
            let error = private_blob_to_material(&blob).expect_err("must be rejected");
            assert!(matches!(error, Error::InvalidMasterKey { .. }));
        }
    }

    /// The wrapped length is the modulus size of the key-encryption key.
    #[test]
    fn wrapped_length_matches_the_kek_size() {
        assert_eq!(WRAPPED_MASTER_KEY_LEN, 256);
        assert_eq!(MASTER_KEK_BITS, 2048);
    }

    /// The export policies are the ones the two forms need: the material can be read back,
    /// the key-encryption key cannot be exported at all.
    #[test]
    fn export_policies_match_the_forms() {
        assert_ne!(MATERIAL_EXPORT_POLICY & NCRYPT_ALLOW_EXPORT_FLAG, 0);
        assert_ne!(
            MATERIAL_EXPORT_POLICY & NCRYPT_ALLOW_PLAINTEXT_EXPORT_FLAG,
            0
        );
        assert_eq!(KEK_EXPORT_POLICY, 0);
    }

    /// A provider that refuses the material must not be left holding a half-created key.
    ///
    /// This drives the store's own helpers against the real providers under a fixed name,
    /// because the failure that matters is invisible in the public API: the TPM provider
    /// accepts the import and then refuses the export policy, and a key object left behind by
    /// that path occupies the name and accumulates with every attempt.
    ///
    /// Both outcomes are checked. A provider that answered must have the key (and hand the
    /// material back), a provider that refused must have nothing left under the name.
    /// Requires a TPM for the first half; the software provider half runs everywhere.
    #[test]
    fn a_provider_that_refuses_the_material_keeps_no_key() {
        let mut name: Vec<u16> = "Qualia2FA-MasterProbe-UnitTest".encode_utf16().collect();
        name.push(0);
        let material = [0x3C_u8; MASTER_KEY_LEN];

        for preferred in [WindowsProvider::Tpm, WindowsProvider::Software] {
            let Ok(provider) = open_provider(preferred.provider_name()) else {
                println!("skipping {preferred:?}: the provider is not available");
                continue;
            };
            remove_unfinished_key(&provider, &name);

            match store_material_key(&provider, &name, &material) {
                Ok(()) => {
                    let read_back = load_material(&provider, &name).expect("read back");
                    assert!(
                        secrets_equal(read_back.as_bytes(), &material),
                        "{preferred:?} returned material that differs from what was stored"
                    );
                    delete_key_by_name(&provider, &name).expect("clean up");
                }
                Err(error) => {
                    println!("{preferred:?} refused the material: {error}");
                    assert!(
                        open_key(&provider, &name)
                            .expect("the probe must not fail to look")
                            .is_none(),
                        "{preferred:?} left a key behind under the probe name"
                    );
                }
            }
        }
    }
}
