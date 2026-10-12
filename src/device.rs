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

//! Device identity: the long-term key a device uses to prove to other devices that it is
//! itself.
//!
//! # What it is
//!
//! The device identity is an ECDSA P-256 key pair. The private key is generated inside local
//! hardware and never leaves it; the public key may be propagated freely between devices.
//! There is no central server and no account password, so "this device is trustworthy" rests
//! on the key the device itself holds and cannot be asserted by a third party.
//!
//! Authentication therefore has a concrete, verifiable meaning: **the peer produces a
//! signature over data it has not seen before that verifies under some public key, and the
//! fingerprint of that public key matches the device being looked for.**
//!
//! # Signature algorithm: ECDSA P-256
//!
//! The algorithm is fixed, not preferred, because the private key lives in platform
//! hardware:
//!
//! - **Android**: KeyMint HAL's `Algorithm.aidl` lists only `RSA=1, EC=3, AES=32,
//!   TRIPLE_DES=33, HMAC=128`; there is no EdDSA, and `KeyProperties.java` defines no
//!   Ed25519 constant. `CURVE_25519` exists, but it is an **XDH key-agreement curve, not a
//!   signature algorithm**.
//! - **iOS**: Apple documents the Secure Enclave as NIST P-256 only.
//!
//! P-256/ECDSA is therefore the only signature algorithm that can be held in hardware on
//! both mobile platforms.
//!
//! # Scope
//!
//! This module holds no private keys and performs no signing: private keys live in hardware
//! and signing is initiated by [`crate::keystore`]. It covers the **public-key side** of an
//! identity only — representation, fingerprint, and signature verification, which any device
//! must be able to perform, including one that holds no hardware key at all.
//!
//! # I/O and clock
//!
//! The module performs no I/O and reads no clock; time is always passed in by the caller.

use crate::{Error, Result};
use p256::ecdsa::{Signature, VerifyingKey, signature::Verifier};
use sha2::{Digest, Sha256};

/// Fixed length of a SEC1 uncompressed point encoding: `0x04 || X(32) || Y(32)`.
///
/// The uncompressed form is the natural output of Windows CNG (`BCRYPT_ECCPUBLICBLOB`),
/// Android Keystore, and the Secure Enclave, so it can be used directly without implementing
/// point compression. The 32 bytes a compressed point would save do not matter in a QR code.
pub const PUBLIC_KEY_LEN: usize = 65;

/// Fixed length of a raw ECDSA P-256 signature: `r(32) || s(32)`.
///
/// The wire format is raw `r || s`, not DER. DER is variable length (70–72 bytes, depending
/// on leading `0x00` padding), so the encoding length would reveal the high bytes of `r` and
/// `s`, and a single mathematical signature would have several valid encodings. A raw fixed
/// layout has exactly one representation per signature. DER appears only at platform
/// boundaries and never in the protocol; Windows CNG's `NCryptSignHash` also returns
/// `r || s` directly.
pub const SIGNATURE_LEN: usize = 64;

/// Length of the fingerprint of a device identity public key.
pub const DEVICE_ID_LEN: usize = 32;

/// Identity of one device: the SHA-256 fingerprint of its identity public key.
///
/// The identifier is derived from the public key rather than drawn at random or counted, so
/// two devices with no shared state can each compute the same `DeviceId`: a device only has
/// to be able to recompute the fingerprint from a public key and compare. "Identifier and
/// public key agree" is therefore a structural fact that needs no registry to maintain and
/// cannot be forged.
///
/// SHA-256 is used here for identification only and carries no cryptographic duty beyond
/// collision resistance: the authenticity of a device identity is provided by signatures,
/// and the fingerprint is just a short name that is convenient to compare.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DeviceId([u8; DEVICE_ID_LEN]);

impl DeviceId {
    /// Computes the fingerprint from a device identity public key.
    #[must_use]
    pub fn from_public_key(public_key: &DevicePublicKey) -> Self {
        let digest = Sha256::digest(public_key.as_sec1_bytes());
        let mut bytes = [0_u8; DEVICE_ID_LEN];
        bytes.copy_from_slice(&digest);
        Self(bytes)
    }

    /// Constructs a fingerprint from 32 raw bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; DEVICE_ID_LEN]) -> Self {
        Self(bytes)
    }

    /// Returns the raw fingerprint bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; DEVICE_ID_LEN] {
        &self.0
    }

    /// Formats the fingerprint as lowercase hexadecimal.
    #[must_use]
    pub fn to_hex(&self) -> String {
        let mut out = String::with_capacity(DEVICE_ID_LEN * 2);
        for byte in self.0 {
            out.push(char::from_digit(u32::from(byte >> 4), 16).unwrap_or('0'));
            out.push(char::from_digit(u32::from(byte & 0x0F), 16).unwrap_or('0'));
        }
        out
    }
}

impl core::fmt::Display for DeviceId {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(&self.to_hex())
    }
}

impl core::fmt::Debug for DeviceId {
    /// Hexadecimal output, convenient for comparing values in logs and test-failure
    /// messages.
    ///
    /// A device identity is **not** a secret — it is printed in a QR code for the peer to
    /// read — so no redaction is needed here, unlike types that hold secret material.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "DeviceId({})", self.to_hex())
    }
}

/// Device identity public key (SEC1 uncompressed point, 65 bytes).
///
/// A public key is not a secret: it is placed in QR codes, written to logs, and propagated
/// between devices. This type therefore implements the full `Debug` output and is
/// `Clone`able, unlike types that hold secrets.
#[derive(Clone, PartialEq, Eq)]
pub struct DevicePublicKey {
    /// `0x04 || X || Y`. Verified to be a valid point on the curve at construction.
    sec1: [u8; PUBLIC_KEY_LEN],
}

impl DevicePublicKey {
    /// Constructs a public key from a SEC1 uncompressed point and **verifies that it really
    /// is a point on the P-256 curve**.
    ///
    /// Public keys arrive as external input (QR codes, the network), and an invalid-curve
    /// attack feeds a point that belongs to a small subgroup instead of the curve in order to
    /// recover private-key information from the results of later operations. Letting such a
    /// point reach any computation is an unnecessary risk even though ECDSA verification
    /// exposes less than ECDH does.
    ///
    /// The input is parsed by `p256` in full, which checks the curve equation internally, so
    /// **an invalid point cannot be turned into a value of this type**.
    ///
    /// # Errors
    ///
    /// Returns [`Error::DevicePublicKeyInvalid`] if the length is wrong, the prefix is not
    /// `0x04`, or the point is not on P-256.
    pub fn from_sec1_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != PUBLIC_KEY_LEN {
            return Err(Error::DevicePublicKeyInvalid {
                reason: "length is not a 65-byte SEC1 uncompressed point",
            });
        }
        if bytes[0] != 0x04 {
            return Err(Error::DevicePublicKeyInvalid {
                reason: "the SEC1 prefix is not 0x04 (uncompressed form)",
            });
        }
        if VerifyingKey::from_sec1_bytes(bytes).is_err() {
            return Err(Error::DevicePublicKeyInvalid {
                reason: "the point is not on the P-256 curve",
            });
        }

        let mut sec1 = [0_u8; PUBLIC_KEY_LEN];
        sec1.copy_from_slice(bytes);
        Ok(Self { sec1 })
    }

    /// Returns the SEC1 uncompressed point bytes.
    #[must_use]
    pub const fn as_sec1_bytes(&self) -> &[u8; PUBLIC_KEY_LEN] {
        &self.sec1
    }

    /// Identity of this device.
    #[must_use]
    pub fn device_id(&self) -> DeviceId {
        DeviceId::from_public_key(self)
    }
}

impl core::fmt::Debug for DevicePublicKey {
    /// Hexadecimal output. A public key is not a secret and needs no redaction.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "DevicePublicKey(")?;
        for byte in self.sec1 {
            write!(f, "{byte:02x}")?;
        }
        write!(f, ")")
    }
}

/// Device identity signature (raw ECDSA P-256 `r || s`, 64 bytes).
#[derive(Clone, PartialEq, Eq)]
pub struct DeviceSignature([u8; SIGNATURE_LEN]);

impl DeviceSignature {
    /// Constructs a signature from raw `r || s` bytes.
    ///
    /// No range check is done here: the requirement that `r` and `s` are integers in
    /// `[1, n-1]` is the responsibility of **verification**, which recomputes and compares
    /// anyway. Constructing this type only states that these 64 bytes claim to be a
    /// signature.
    ///
    /// # Errors
    ///
    /// Returns [`Error::DeviceSignatureInvalid`] if the input is not 64 bytes long.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let raw: [u8; SIGNATURE_LEN] =
            bytes
                .try_into()
                .map_err(|_| Error::DeviceSignatureInvalid {
                    reason: "length is not 64 raw r||s bytes",
                })?;
        Ok(Self(raw))
    }

    /// Returns the raw `r || s` bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; SIGNATURE_LEN] {
        &self.0
    }
}

impl core::fmt::Debug for DeviceSignature {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "DeviceSignature(")?;
        for byte in self.0 {
            write!(f, "{byte:02x}")?;
        }
        write!(f, ")")
    }
}

/// Verifies a device's signature over `message` with its public key.
///
/// # The message, not a digest
///
/// Platform hardware accepts a **digest** only (the Windows CNG parameter of
/// `NCryptSignHash` is named `pbHashValue`), so the signing side has to hash first. This
/// function takes the **original message** and performs the same SHA-256 itself, so callers
/// do not have to keep one hash algorithm consistent across two call sites.
///
/// The hash mode used here is ECDSA's standard one (`Signer`/`Verifier`), which hashes
/// internally. Do **not** pass an already-computed digest.
///
/// # Errors
///
/// Returns [`Error::DeviceSignatureInvalid`] both for a malformed signature and for a
/// verification failure. The two are deliberately not distinguished: the caller's response
/// is identical (reject this authentication), and separating them would give an attacker a
/// small oracle.
///
/// No input panics; every failure is returned as an error.
#[must_use = "the verification result must be checked; discarding it is the same as not verifying"]
pub fn verify(
    public_key: &DevicePublicKey,
    message: &[u8],
    signature: &DeviceSignature,
) -> Result<()> {
    let verifying_key =
        VerifyingKey::from_sec1_bytes(public_key.as_sec1_bytes()).map_err(|_| {
            Error::DeviceSignatureInvalid {
                reason: "the public key failed to parse (should not happen: it was validated at construction)",
            }
        })?;

    let signature =
        Signature::from_slice(signature.as_bytes()).map_err(|_| Error::DeviceSignatureInvalid {
            reason: "the signature is not a valid P-256 r||s",
        })?;

    verifying_key
        .verify(message, &signature)
        .map_err(|_| Error::DeviceSignatureInvalid {
            reason: "the signature does not match the public key or the message",
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::ecdsa::{SigningKey, signature::Signer};

    /// Builds a key pair for tests (generated in software, for tests only).
    fn test_key() -> (SigningKey, DevicePublicKey) {
        let signing = SigningKey::from_slice(&[7_u8; 32]).expect("valid scalar");
        let sec1 = signing.verifying_key().to_sec1_point(false);
        let public = DevicePublicKey::from_sec1_bytes(sec1.as_bytes()).expect("valid point");
        (signing, public)
    }

    /// Signs a message with a software key and produces our wire format.
    fn sign(signing: &SigningKey, message: &[u8]) -> DeviceSignature {
        let sig: Signature = signing.sign(message);
        DeviceSignature::from_bytes(&sig.to_bytes()).expect("64 bytes")
    }

    /// Round trip: a signature over a message verifies against that message.
    #[test]
    fn valid_signature_verifies() {
        let (signing, public) = test_key();
        let message = b"\x01Qualia2FA test message";
        let signature = sign(&signing, message);
        assert!(verify(&public, message, &signature).is_ok());
    }

    /// A message with one flipped bit must not verify.
    #[test]
    fn modified_message_fails() {
        let (signing, public) = test_key();
        let mut message = *b"hello qualia2fa!";
        let signature = sign(&signing, &message);
        message[0] ^= 0x01;
        assert!(verify(&public, &message, &signature).is_err());
    }

    /// A signature with one flipped bit must not verify.
    #[test]
    fn modified_signature_fails() {
        let (signing, public) = test_key();
        let message = b"hello qualia2fa!";
        let signature = sign(&signing, message);
        for index in [0_usize, 31, 32, 63] {
            let mut raw = *signature.as_bytes();
            raw[index] ^= 0x01;
            let tampered = DeviceSignature::from_bytes(&raw).expect("still 64 bytes");
            assert!(
                verify(&public, message, &tampered).is_err(),
                "byte {index} was modified but still verified"
            );
        }
    }

    /// Verifying with the public key of a different key pair must fail.
    #[test]
    fn wrong_public_key_fails() {
        let (signing, _) = test_key();
        let other = SigningKey::from_slice(&[9_u8; 32]).expect("valid scalar");
        let other_sec1 = other.verifying_key().to_sec1_point(false);
        let other_public =
            DevicePublicKey::from_sec1_bytes(other_sec1.as_bytes()).expect("valid point");

        let message = b"hello qualia2fa!";
        let signature = sign(&signing, message);
        assert!(verify(&other_public, message, &signature).is_err());
    }

    /// **Invalid-curve attack**: a point that is not on P-256 must be rejected, not
    /// accepted.
    #[test]
    fn off_curve_point_is_rejected() {
        let mut bytes = [0_u8; PUBLIC_KEY_LEN];
        bytes[0] = 0x04;
        bytes[32] = 1;
        bytes[64] = 1;
        assert!(
            DevicePublicKey::from_sec1_bytes(&bytes).is_err(),
            "an off-curve point was accepted, which enables invalid-curve attacks"
        );
    }

    /// Both the length and the SEC1 prefix are checked.
    #[test]
    fn malformed_public_key_is_rejected() {
        assert!(DevicePublicKey::from_sec1_bytes(&[]).is_err());
        assert!(DevicePublicKey::from_sec1_bytes(&[0x04; 64]).is_err());
        assert!(DevicePublicKey::from_sec1_bytes(&[0x04; 66]).is_err());

        let (_, public) = test_key();
        let mut compressed = *public.as_sec1_bytes();
        compressed[0] = 0x02;
        assert!(
            DevicePublicKey::from_sec1_bytes(&compressed).is_err(),
            "the compressed form must not be accepted"
        );
    }

    /// A signature must be exactly 64 bytes long.
    #[test]
    fn malformed_signature_is_rejected() {
        assert!(DeviceSignature::from_bytes(&[]).is_err());
        assert!(DeviceSignature::from_bytes(&[0_u8; 63]).is_err());
        assert!(DeviceSignature::from_bytes(&[0_u8; 65]).is_err());
    }

    /// `DeviceId` is determined by the public key alone and is consistent with it.
    #[test]
    fn device_id_is_derived_from_public_key() {
        let (_, public) = test_key();
        let id = public.device_id();
        assert_eq!(id, DeviceId::from_public_key(&public));
        assert_eq!(id.as_bytes().len(), DEVICE_ID_LEN);
        assert_eq!(id.to_hex().len(), DEVICE_ID_LEN * 2);

        let (_, other) = {
            let signing = SigningKey::from_slice(&[9_u8; 32]).expect("valid scalar");
            let sec1 = signing.verifying_key().to_sec1_point(false);
            let public = DevicePublicKey::from_sec1_bytes(sec1.as_bytes()).expect("valid point");
            (signing, public)
        };
        assert_ne!(id, other.device_id());
    }

    /// `Debug` output contains the full hexadecimal value, for logs and test-failure
    /// messages.
    #[test]
    fn debug_shows_hex() {
        let (_, public) = test_key();
        let text = format!("{public:?}");
        assert!(text.starts_with("DevicePublicKey(04"), "actual: {text}");
        assert_eq!(
            text.len(),
            "DevicePublicKey(".len() + PUBLIC_KEY_LEN * 2 + 1
        );
        assert_eq!(public.device_id().to_string().len(), DEVICE_ID_LEN * 2);
    }
}
