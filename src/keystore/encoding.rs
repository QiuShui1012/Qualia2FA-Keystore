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

//! Converting what a platform hands back into this crate's encodings.
//!
//! Platform key stores answer in their own shapes: a coordinate as a signed, minimal
//! big-endian integer; a signature in the DER form every PKCS#11-alike uses. Neither is this
//! crate's convention — a point is the uncompressed SEC1 encoding, a signature is the fixed
//! `r‖s` — and the difference is where a mistake shows up as "the signature does not verify"
//! rather than as a compile error.
//!
//! These conversions are pure and live here, **outside** any platform module, so that they
//! are compiled and tested on every target. A conversion that only exists on the platform
//! it serves can only be tested on that platform, which in CI means never.

use crate::keystore::traits::{public_key_from_sec1, signature_from_raw};
use crate::{DevicePublicKey, DeviceSignature, Error, Result};

/// Width of a P-256 field element, in bytes.
const COORDINATE_LEN: usize = 32;

/// A coordinate of a P-256 point, as a fixed 32-byte big-endian integer.
///
/// The input is what `BigInteger.toByteArray()` produces: two's complement and as short as
/// the value allows. So a value whose top bit is set arrives with a leading zero byte, and a
/// value with leading zero bytes arrives short — both are normal for a coordinate, which is
/// uniform in the field, and both are adjusted here rather than treated as errors. Only a
/// value that cannot fit the field is one.
pub(crate) fn fixed_width(bytes: &[u8]) -> Result<[u8; COORDINATE_LEN]> {
    let significant = match bytes.iter().position(|byte| *byte != 0) {
        Some(position) => &bytes[position..],
        None => &[],
    };
    if significant.len() > COORDINATE_LEN {
        return Err(Error::InvalidPublicKey {
            reason: "a coordinate of the public key is wider than the curve",
        });
    }
    let mut out = [0_u8; COORDINATE_LEN];
    out[COORDINATE_LEN - significant.len()..].copy_from_slice(significant);
    Ok(out)
}

/// The SEC1 uncompressed encoding of a public point: `0x04 ‖ X ‖ Y`.
///
/// The point is decoded by the same code every verifier uses, so a coordinate that is not on
/// the curve is refused here rather than at verification time.
pub(crate) fn sec1_from_coordinates(x: &[u8], y: &[u8]) -> Result<DevicePublicKey> {
    let mut encoded = [0_u8; 65];
    encoded[0] = 0x04;
    encoded[1..33].copy_from_slice(&fixed_width(x)?);
    encoded[33..].copy_from_slice(&fixed_width(y)?);
    public_key_from_sec1(&encoded)
}

/// The raw `r‖s` of a DER signature.
///
/// The platform signs in the DER form that every Java and PKCS#11 signature uses; this
/// crate's convention is the fixed-width one. `p256` reads the DER, so the encoding is
/// parsed by the same code that parses it everywhere else in this workspace.
pub(crate) fn signature_from_der(der: &[u8]) -> Result<DeviceSignature> {
    let signature = p256::ecdsa::Signature::from_der(der).map_err(|_| Error::Hardware {
        operation: "Signature.sign",
        // Not a platform failure code: the platform returned a signature that is not a DER
        // ECDSA signature, which is a broken contract rather than a broken device. Reported
        // through the variant that carries an operation name and no invented code.
        code: 0,
    })?;
    signature_from_raw(&signature.to_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keystore::traits::DIGEST_LEN;
    use p256::ecdsa::{Signature, SigningKey, signature::hazmat::PrehashSigner};

    /// The sign byte `BigInteger.toByteArray()` adds must not shift the coordinate.
    #[test]
    fn a_signed_coordinate_loses_its_sign_byte() {
        let mut padded = vec![0x00];
        padded.extend([0xAB; 32]);
        assert_eq!(fixed_width(&padded).expect("32 bytes"), [0xAB; 32]);
    }

    /// A coordinate shorter than the field is padded on the **left**, not the right.
    #[test]
    fn a_short_coordinate_is_padded_on_the_left() {
        let short = [0x01, 0x02, 0x03];
        let mut expected = [0_u8; 32];
        expected[29..].copy_from_slice(&short);
        assert_eq!(fixed_width(&short).expect("32 bytes"), expected);
    }

    /// Zero is a coordinate like any other, and must not be confused with "absent".
    #[test]
    fn a_zero_coordinate_is_thirty_two_zero_bytes() {
        assert_eq!(fixed_width(&[0x00]).expect("32 bytes"), [0x00; 32]);
        assert_eq!(fixed_width(&[]).expect("32 bytes"), [0x00; 32]);
    }

    /// Wider than the field is a real disagreement with the curve, not something to
    /// truncate: truncating would turn a wrong key into a wrong-but-accepted one.
    #[test]
    fn an_overlong_coordinate_is_rejected() {
        assert!(fixed_width(&[0x01; 33]).is_err());
    }

    /// The assembled point has the uncompressed tag and survives the curve's own decoding.
    #[test]
    fn coordinates_assemble_into_a_point_the_curve_accepts() {
        let signing = SigningKey::from_slice(&[7_u8; 32]).expect("a valid scalar");
        let point = signing.verifying_key().to_sec1_point(false);
        let (x, y) = (point.x().expect("x"), point.y().expect("y"));

        let assembled = sec1_from_coordinates(x, y).expect("a point");
        assert_eq!(assembled.as_sec1_bytes().len(), 65);
        assert_eq!(assembled.as_sec1_bytes()[0], 0x04);
        assert_eq!(assembled.as_sec1_bytes(), point.as_bytes());
    }

    /// Coordinates that are not on the curve are refused, not passed along.
    #[test]
    fn coordinates_off_the_curve_are_rejected() {
        assert!(sec1_from_coordinates(&[0xFF; 32], &[0xFF; 32]).is_err());
    }

    /// The DER the platform produces reads back as the raw signature of the same value.
    #[test]
    fn a_der_signature_becomes_the_raw_one() {
        let signing = SigningKey::from_slice(&[11_u8; 32]).expect("a valid scalar");
        let digest = [3_u8; DIGEST_LEN];
        let signature: Signature = signing.sign_prehash(&digest).expect("a signature");

        let raw = signature_from_der(signature.to_der().as_bytes()).expect("parsable");
        assert_eq!(raw.as_bytes(), signature.to_bytes().as_slice());
    }

    /// Bytes that are not a DER signature are refused rather than guessed at.
    #[test]
    fn a_broken_der_signature_is_rejected() {
        assert!(signature_from_der(&[0x30, 0x02, 0x01, 0x00]).is_err());
        assert!(signature_from_der(&[]).is_err());
        assert!(signature_from_der(&[0xFF; 8]).is_err());
    }
}
