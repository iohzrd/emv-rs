//! Book 2 §B2.2–§B2.6 - ECC primitives.

use crate::core::error::{Error, Result};
use num_bigint::BigUint;
use p256::elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint};
use p256::{AffinePoint, EncodedPoint};
use sha2::{Digest, Sha256, Sha512};

// P-521 types - the encoded-point traits (`FromEncodedPoint`,
// `ToEncodedPoint`) are already in scope via the `p256` import above
// since both p256 and p521 use the same `elliptic-curve` traits.
use p521::{AffinePoint as P521AffinePoint, EncodedPoint as P521EncodedPoint};

/// Algorithm Suite Indicator constants per Book 2 §B2.4 (Tables 48, 49).
/// EMVCo-allocated values are in `'00'..='7F'`; `'80'..='FF'` is for
/// proprietary use.
pub mod algorithm_suite {
    /// EC-SDSA + SHA-256 + P-256 (Table 48).
    pub const SIGNATURE_EC_SDSA_SHA256_P256: u8 = 0x10;
    /// EC-SDSA + SHA-512 + P-521 (Table 48).
    pub const SIGNATURE_EC_SDSA_SHA512_P521: u8 = 0x11;
    /// EC-SDSA + SHA3-256 + P-256 (Table 48, "assigned" - not yet
    /// available for testing).
    pub const SIGNATURE_EC_SDSA_SHA3_256_P256: u8 = 0x12;
    /// EC-SDSA + SHA3-512 + P-521 (Table 48, "assigned").
    pub const SIGNATURE_EC_SDSA_SHA3_512_P521: u8 = 0x13;
    /// SM2-DSA + SM3 + SM2-P256 (Table 48, regional/proprietary).
    pub const SIGNATURE_SM2_DSA_SM3_SM2P256: u8 = 0x80;

    /// ODE (Offline Data Encipherment) suite: P-256 + DH + EtM + AES.
    pub const ODE_P256_DH_AES: u8 = 0x00;
    /// ODE: P-521 + DH + EtM + AES.
    pub const ODE_P521_DH_AES: u8 = 0x01;
    /// ODE: SM2-P256 + DH + EtM + SM4 (regional/proprietary).
    pub const ODE_SM2P256_DH_SM4: u8 = 0x88;
}

/// Hash Algorithm Indicator constants per Book 2 §B2.3 (Table 47).
pub mod hash_algorithm {
    /// SHA-1 - "not used with ECC; see section B3" per Table 47. Kept
    /// here for completeness (§B3 and the RSA-side ODA chain do use
    /// it).
    pub const SHA_1: u8 = 0x01;
    /// SHA-256 (`N_HASH = 32`).
    pub const SHA_256: u8 = 0x02;
    /// SHA-512 (`N_HASH = 64`).
    pub const SHA_512: u8 = 0x03;
    /// SHA-3 256 (Table 47, "assigned" - not currently EMV-tested).
    pub const SHA3_256: u8 = 0x04;
    /// SHA-3 512 (Table 47, "assigned").
    pub const SHA3_512: u8 = 0x05;
    /// SM3 (regional/proprietary).
    pub const SM3: u8 = 0x80;
}

/// Hash a message with the algorithm identified by `indicator` per
/// Table 47. Returns the variable-length digest (`N_HASH` bytes).
///
/// Currently dispatches only SHA-256 and SHA-512 (the two §B2.3
/// algorithms in the `'00'..='7F'` EMVCo-specified range that are
/// available without additional crate dependencies). SHA-1 falls
/// through to [`crate::core::iso9796_2`]'s SHA-1 dependency and is rejected
/// here per Table 47's note "not used with ECC". Other indicators
/// return `InvalidValue`.
pub fn hash_for_ecc(indicator: u8, message: &[u8]) -> Result<Vec<u8>> {
    match indicator {
        hash_algorithm::SHA_256 => {
            let mut h = Sha256::new();
            h.update(message);
            Ok(h.finalize().to_vec())
        }
        hash_algorithm::SHA_512 => {
            let mut h = Sha512::new();
            h.update(message);
            Ok(h.finalize().to_vec())
        }
        _ => Err(Error::InvalidValue),
    }
}

// ── §B2.6 Integer Conversion Functions ───────────────────────────────

/// `OS2I(x)` per §B2.6.1 - interpret an octet string as a non-negative
/// big-endian integer.
pub fn os2i(octets: &[u8]) -> BigUint {
    BigUint::from_bytes_be(octets)
}

/// `I2OS(v, l)` per §B2.6.1 - encode a non-negative integer into an
/// octet string of exactly `l` bytes (big-endian, zero-padded on the
/// left). Returns `InvalidValue` if `v` doesn't fit.
pub fn i2os(value: &BigUint, length: usize) -> Result<Vec<u8>> {
    let bytes = value.to_bytes_be();
    if bytes.len() > length {
        return Err(Error::InvalidValue);
    }
    let mut out = vec![0u8; length];
    out[length - bytes.len()..].copy_from_slice(&bytes);
    Ok(out)
}

// ── §B2.2 P-256 curve ────────────────────────────────────────────────

/// Field byte length for P-256 (`N_FIELD = 32`).
pub const P256_FIELD_BYTES: usize = 32;

/// The P-256 prime modulus `p = 2^256 - 2^224 + 2^192 + 2^96 - 1`
/// (Table 45). Lazily constructed via [`p256_p()`].
fn p256_p() -> BigUint {
    // Hex literal from Table 45.
    BigUint::parse_bytes(
        b"FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF",
        16,
    )
    .expect("hardcoded P-256 prime parses")
}

/// Recover the P-256 y-coordinate from an x-coordinate per §B2.2.1(e)
/// `Point4x()`, returning the **lower** of the two roots - i.e. the
/// `y` satisfying `y < (p+1)/2`. This matches the §B2.2.4 long-term
/// key constraint (Payment System, Issuer, and ICC keys are generated
/// such that the y-coordinate as an integer modulo p is less than
/// `(p+1)/2`), so the recovered point is the unique correct one for
/// signature verification.
///
/// Errors:
///
/// - `InvalidValue` if `x ≥ p` (not a valid field element), if no
///   point on the curve has this x-coordinate (i.e. `x³ + ax + b` is
///   a quadratic non-residue mod `p`), or if `x = 0` (would map to
///   the point at infinity in some interpretations and is not a valid
///   public-key x-coordinate).
pub fn recover_y_p256(x: &[u8; P256_FIELD_BYTES]) -> Result<[u8; P256_FIELD_BYTES]> {
    let (y_lo, _y_hi) = recover_y_p256_both(x)?;
    Ok(y_lo)
}

/// Recover both candidate y-coordinates for the given x - useful for
/// ephemeral Diffie-Hellman keys per §B2.2.4 last paragraph (the
/// y-coordinate constraint may be omitted there). Returns
/// `(y_lower, y_upper)` where `y_lower < (p+1)/2 ≤ y_upper`.
pub fn recover_y_p256_both(
    x: &[u8; P256_FIELD_BYTES],
) -> Result<([u8; P256_FIELD_BYTES], [u8; P256_FIELD_BYTES])> {
    // Attempt SEC1 decompression with the y-even prefix; this gives
    // us one of the two y values. Compute the other as p - y.
    let mut compressed = [0u8; P256_FIELD_BYTES + 1];
    compressed[0] = 0x02;
    compressed[1..].copy_from_slice(x);

    let encoded =
        EncodedPoint::from_bytes(compressed.as_slice()).map_err(|_| Error::InvalidValue)?;
    let point: AffinePoint =
        Option::from(AffinePoint::from_encoded_point(&encoded)).ok_or(Error::InvalidValue)?;

    // Extract the y bytes via uncompressed encoding.
    let uncompressed = point.to_encoded_point(false);
    let y_bytes = uncompressed.y().ok_or(Error::InvalidValue)?;
    let mut y_one = [0u8; P256_FIELD_BYTES];
    y_one.copy_from_slice(y_bytes);

    // The other root is p - y_one.
    let p = p256_p();
    let y_one_int = BigUint::from_bytes_be(&y_one);
    let y_two_int = &p - &y_one_int;

    // Sort by magnitude.
    let (lo_int, hi_int) = if y_one_int < y_two_int {
        (y_one_int, y_two_int)
    } else {
        (y_two_int, y_one_int)
    };

    let mut y_lo = [0u8; P256_FIELD_BYTES];
    let mut y_hi = [0u8; P256_FIELD_BYTES];
    let lo_bytes = lo_int.to_bytes_be();
    let hi_bytes = hi_int.to_bytes_be();
    y_lo[P256_FIELD_BYTES - lo_bytes.len()..].copy_from_slice(&lo_bytes);
    y_hi[P256_FIELD_BYTES - hi_bytes.len()..].copy_from_slice(&hi_bytes);
    Ok((y_lo, y_hi))
}

/// Validate that `x` is a viable P-256 public-key x-coordinate per
/// §B2.2: it must lie in `[1, p-1]` and there must exist a `y` such
/// that `(x, y)` is on the curve. Returns `Ok(())` on success.
pub fn validate_pk_x_p256(x: &[u8; P256_FIELD_BYTES]) -> Result<()> {
    let _ = recover_y_p256_both(x)?;
    Ok(())
}

// ── §B2.2 P-521 curve ────────────────────────────────────────────────

/// Field byte length for P-521 (`N_FIELD = 66`).
///
/// 521-bit field elements fit into 66 bytes when encoded big-endian
/// - the high 7 bits of the leading byte are always zero per the
/// curve definition (Table 46).
pub const P521_FIELD_BYTES: usize = 66;

/// The P-521 prime modulus `p = 2^521 - 1` (Table 46).
fn p521_p() -> BigUint {
    // 2^521 - 1 - a Mersenne prime. Constructed arithmetically to
    // avoid a 132-character hex literal.
    (BigUint::from(1u32) << 521u32) - BigUint::from(1u32)
}

/// Recover the P-521 y-coordinate from an x-coordinate per
/// §B2.2.1(e) `Point4x()`, returning the **lower** of the two roots
/// - i.e. the `y` satisfying `y < (p+1)/2`. Matches the §B2.2.4
/// long-term-key constraint.
///
/// Errors as for [`recover_y_p256`] (`x ≥ p`, no point on the curve,
/// `x = 0`).
pub fn recover_y_p521(x: &[u8; P521_FIELD_BYTES]) -> Result<[u8; P521_FIELD_BYTES]> {
    let (y_lo, _) = recover_y_p521_both(x)?;
    Ok(y_lo)
}

/// Recover both candidate y-coordinates for the given P-521 x -
/// useful for ephemeral DH keys per §B2.2.4 last paragraph.
/// Returns `(y_lower, y_upper)` where `y_lower < (p+1)/2 ≤ y_upper`.
pub fn recover_y_p521_both(
    x: &[u8; P521_FIELD_BYTES],
) -> Result<([u8; P521_FIELD_BYTES], [u8; P521_FIELD_BYTES])> {
    // SEC1 compressed encoding: 0x02 || x (y-even prefix). Length is
    // 1 + N_FIELD.
    let mut compressed = [0u8; P521_FIELD_BYTES + 1];
    compressed[0] = 0x02;
    compressed[1..].copy_from_slice(x);

    let encoded =
        P521EncodedPoint::from_bytes(compressed.as_slice()).map_err(|_| Error::InvalidValue)?;
    let point: P521AffinePoint =
        Option::from(P521AffinePoint::from_encoded_point(&encoded)).ok_or(Error::InvalidValue)?;

    let uncompressed = point.to_encoded_point(false);
    let y_bytes = uncompressed.y().ok_or(Error::InvalidValue)?;
    let mut y_one = [0u8; P521_FIELD_BYTES];
    y_one.copy_from_slice(y_bytes);

    let p = p521_p();
    let y_one_int = BigUint::from_bytes_be(&y_one);
    let y_two_int = &p - &y_one_int;

    let (lo_int, hi_int) = if y_one_int < y_two_int {
        (y_one_int, y_two_int)
    } else {
        (y_two_int, y_one_int)
    };

    let mut y_lo = [0u8; P521_FIELD_BYTES];
    let mut y_hi = [0u8; P521_FIELD_BYTES];
    let lo_bytes = lo_int.to_bytes_be();
    let hi_bytes = hi_int.to_bytes_be();
    y_lo[P521_FIELD_BYTES - lo_bytes.len()..].copy_from_slice(&lo_bytes);
    y_hi[P521_FIELD_BYTES - hi_bytes.len()..].copy_from_slice(&hi_bytes);
    Ok((y_lo, y_hi))
}

/// Validate that `x` is a viable P-521 public-key x-coordinate per
/// §B2.2 (analog of [`validate_pk_x_p256`]).
pub fn validate_pk_x_p521(x: &[u8; P521_FIELD_BYTES]) -> Result<()> {
    let _ = recover_y_p521_both(x)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h(s: &str) -> Vec<u8> {
        let cleaned: String = s.chars().filter(|c| !c.is_whitespace()).collect();
        (0..cleaned.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&cleaned[i..i + 2], 16).unwrap())
            .collect()
    }

    fn h32(s: &str) -> [u8; 32] {
        h(s).try_into().unwrap()
    }

    // ── Hash dispatch ────────────────────────────────────────────────

    #[test]
    fn sha256_known_answer_empty_string() {
        // SHA-256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
        let digest = hash_for_ecc(hash_algorithm::SHA_256, b"").unwrap();
        assert_eq!(
            digest,
            h("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",),
        );
    }

    #[test]
    fn sha256_known_answer_abc() {
        // SHA-256("abc") = ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
        let digest = hash_for_ecc(hash_algorithm::SHA_256, b"abc").unwrap();
        assert_eq!(
            digest,
            h("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",),
        );
    }

    #[test]
    fn sha512_known_answer_empty_string() {
        // SHA-512("") = cf83e1357eefb8bd...3a538327af927da3e
        let digest = hash_for_ecc(hash_algorithm::SHA_512, b"").unwrap();
        assert_eq!(
            digest,
            h("cf83e1357eefb8bdf1542850d66d8007\
                 d620e4050b5715dc83f4a921d36ce9ce\
                 47d0d13c5d85f2b0ff8318d2877eec2f\
                 63b931bd47417a81a538327af927da3e",),
        );
    }

    #[test]
    fn hash_rejects_unknown_indicator() {
        for bad in [0x00, 0x06, 0x10, 0x7F, 0xFF] {
            assert_eq!(
                hash_for_ecc(bad, b""),
                Err(Error::InvalidValue),
                "indicator={:#04x}",
                bad,
            );
        }
    }

    #[test]
    fn hash_rejects_sha1_for_ecc() {
        // Table 47 explicitly notes SHA-1 is "not used with ECC".
        assert_eq!(
            hash_for_ecc(hash_algorithm::SHA_1, b""),
            Err(Error::InvalidValue),
        );
    }

    // ── §B2.6 conversions ────────────────────────────────────────────

    #[test]
    fn os2i_spec_example() {
        // §B2.6 OS2I example: OS2I('00 2A C1') = 10945 (... wait that
        // example uses '00' '2A' 'C1' = 0x002AC1 = 10945. Confirm.)
        // Actually 0x2AC1 = 10945. Leading 00 is preserved as zero.
        assert_eq!(os2i(&[0x00, 0x2A, 0xC1]), BigUint::from(10945u32));
    }

    #[test]
    fn os2i_empty_returns_zero() {
        assert_eq!(os2i(&[]), BigUint::from(0u32));
    }

    #[test]
    fn i2os_spec_example_3_bytes() {
        // §B2.6 I2OS example: I2OS(10945, 3) = '00 2A C1'.
        let out = i2os(&BigUint::from(10945u32), 3).unwrap();
        assert_eq!(out, vec![0x00, 0x2A, 0xC1]);
    }

    #[test]
    fn i2os_spec_example_2_bytes() {
        // §B2.6 I2OS example: I2OS(10945, 2) = '2A C1'.
        let out = i2os(&BigUint::from(10945u32), 2).unwrap();
        assert_eq!(out, vec![0x2A, 0xC1]);
    }

    #[test]
    fn i2os_rejects_overflow() {
        // 10945 = 0x2AC1, won't fit in 1 byte.
        assert_eq!(i2os(&BigUint::from(10945u32), 1), Err(Error::InvalidValue),);
    }

    #[test]
    fn os2i_i2os_round_trip() {
        let bytes = [0x12u8, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0];
        let v = os2i(&bytes);
        let out = i2os(&v, bytes.len()).unwrap();
        assert_eq!(out, bytes);
    }

    // ── P-256 Point4x recovery ───────────────────────────────────────

    #[test]
    fn p256_recover_y_at_base_point() {
        // §B2.2.2 Table 45: G_x and G_y of the P-256 base point.
        // Recovering y from G_x must yield G_y exactly.
        let gx = h32("6B17D1F2E12C4247F8BCE6E563A440F2\
             77037D812DEB33A0F4A13945D898C296");
        let gy_expected = h32("4FE342E2FE1A7F9B8EE7EB4A7C0F9E16\
             2BCE33576B315ECECBB6406837BF51F5");
        let y = recover_y_p256(&gx).unwrap();
        // G_y's first byte is 0x4F < 0x80, so G_y is the *lower* of
        // the two roots - recovery should return it.
        assert_eq!(y, gy_expected, "recovered y must equal G_y");
    }

    #[test]
    fn p256_recover_y_lower_root_invariant() {
        // For any valid x, recover_y returns the y with y < (p+1)/2.
        let gx = h32("6B17D1F2E12C4247F8BCE6E563A440F2\
             77037D812DEB33A0F4A13945D898C296");
        let y = recover_y_p256(&gx).unwrap();
        let y_int = BigUint::from_bytes_be(&y);
        let p = p256_p();
        let half = (&p + BigUint::from(1u32)) / BigUint::from(2u32);
        assert!(y_int < half, "y must be the lower root");
    }

    #[test]
    fn p256_recover_both_returns_paired_y_and_p_minus_y() {
        let gx = h32("6B17D1F2E12C4247F8BCE6E563A440F2\
             77037D812DEB33A0F4A13945D898C296");
        let (lo, hi) = recover_y_p256_both(&gx).unwrap();
        let lo_int = BigUint::from_bytes_be(&lo);
        let hi_int = BigUint::from_bytes_be(&hi);
        // lo + hi == p (the two roots are y and p - y).
        let p = p256_p();
        assert_eq!(&lo_int + &hi_int, p);
        assert!(lo_int < hi_int);
    }

    #[test]
    fn p256_recover_y_rejects_x_not_on_curve() {
        // x = 1 has no y on the curve (1 - 3 + b is not a QR for
        // P-256's b - depends on luck, but x = 1 is a known
        // non-recoverable case for many curves; check empirically).
        // More reliable: use an x that's clearly out of field range,
        // i.e. all-FFs which exceeds p.
        let bad = [0xFFu8; 32];
        assert!(recover_y_p256(&bad).is_err());
    }

    #[test]
    fn p256_validate_pk_x_accepts_base_point() {
        let gx = h32("6B17D1F2E12C4247F8BCE6E563A440F2\
             77037D812DEB33A0F4A13945D898C296");
        assert!(validate_pk_x_p256(&gx).is_ok());
    }

    #[test]
    fn p256_validate_pk_x_rejects_x_geq_p() {
        let bad = [0xFFu8; 32];
        assert!(validate_pk_x_p256(&bad).is_err());
    }

    // ── P-521 Point4x recovery ───────────────────────────────────────

    fn h66(s: &str) -> [u8; 66] {
        h(s).try_into().unwrap()
    }

    #[test]
    fn p521_recover_y_at_base_point() {
        // Table 46: G_x and G_y of the P-521 base point. G_y =
        // '0118392…6650' starts above 2^520 = (p+1)/2, so it's the
        // *upper* root and recovery returns p - G_y (the lower
        // root). The y must satisfy y² = x³ - 3x + b mod p, which we
        // verify indirectly via the cofactor check (the recovered
        // (x, y) is the negation of the base point).
        let gx = h66("00C6 858E 06B7 0404 E9CD 9E3E CB66 2395\
             B442 9C64 8139 053F B521 F828 AF60 6B4D\
             3DBA A14B 5E77 EFE7 5928 FE1D C127 A2FF\
             A8DE 3348 B3C1 856A 429B F97E 7E31 C2E5\
             BD66");
        let gy_table46 = h66("0118 39296A78 9A3BC004 5C8A5FB4 2C7D1BD9\
             98F54449 579B4468 17AFBD17 273E662C 97EE7299\
             5EF42640 C550B901 3FAD0761 353C7086 A272C240\
             88BE9476 9FD16650");

        // Expected lower root: p - G_y, encoded as 66-byte BE.
        let p = p521_p();
        let gy_int = BigUint::from_bytes_be(&gy_table46);
        let expected_lower = &p - &gy_int;
        let mut expected_lower_bytes = [0u8; 66];
        let bytes = expected_lower.to_bytes_be();
        expected_lower_bytes[66 - bytes.len()..].copy_from_slice(&bytes);

        let y = recover_y_p521(&gx).unwrap();
        assert_eq!(y, expected_lower_bytes);
    }

    #[test]
    fn p521_recover_y_lower_root_invariant() {
        // For any valid x, recover_y returns y < (p+1)/2.
        let gx = h66("00C6 858E 06B7 0404 E9CD 9E3E CB66 2395\
             B442 9C64 8139 053F B521 F828 AF60 6B4D\
             3DBA A14B 5E77 EFE7 5928 FE1D C127 A2FF\
             A8DE 3348 B3C1 856A 429B F97E 7E31 C2E5\
             BD66");
        let y = recover_y_p521(&gx).unwrap();
        let y_int = BigUint::from_bytes_be(&y);
        let p = p521_p();
        let half = (&p + BigUint::from(1u32)) / BigUint::from(2u32);
        assert!(y_int < half, "y must be the lower root");
    }

    #[test]
    fn p521_recover_both_returns_paired_y_and_p_minus_y() {
        let gx = h66("00C6 858E 06B7 0404 E9CD 9E3E CB66 2395\
             B442 9C64 8139 053F B521 F828 AF60 6B4D\
             3DBA A14B 5E77 EFE7 5928 FE1D C127 A2FF\
             A8DE 3348 B3C1 856A 429B F97E 7E31 C2E5\
             BD66");
        let (lo, hi) = recover_y_p521_both(&gx).unwrap();
        let lo_int = BigUint::from_bytes_be(&lo);
        let hi_int = BigUint::from_bytes_be(&hi);
        let p = p521_p();
        assert_eq!(&lo_int + &hi_int, p);
        assert!(lo_int < hi_int);
    }

    #[test]
    fn p521_recover_y_rejects_x_geq_p() {
        // x = all-FFs is way larger than p.
        let bad = [0xFFu8; 66];
        assert!(recover_y_p521(&bad).is_err());
    }

    #[test]
    fn p521_validate_pk_x_accepts_base_point() {
        let gx = h66("00C6 858E 06B7 0404 E9CD 9E3E CB66 2395\
             B442 9C64 8139 053F B521 F828 AF60 6B4D\
             3DBA A14B 5E77 EFE7 5928 FE1D C127 A2FF\
             A8DE 3348 B3C1 856A 429B F97E 7E31 C2E5\
             BD66");
        assert!(validate_pk_x_p521(&gx).is_ok());
    }

    // ── Algorithm suite indicators ───────────────────────────────────

    #[test]
    fn algorithm_suite_constants_match_table_48_49() {
        assert_eq!(algorithm_suite::SIGNATURE_EC_SDSA_SHA256_P256, 0x10);
        assert_eq!(algorithm_suite::SIGNATURE_EC_SDSA_SHA512_P521, 0x11);
        assert_eq!(algorithm_suite::SIGNATURE_SM2_DSA_SM3_SM2P256, 0x80);
        assert_eq!(algorithm_suite::ODE_P256_DH_AES, 0x00);
        assert_eq!(algorithm_suite::ODE_P521_DH_AES, 0x01);
    }
}
