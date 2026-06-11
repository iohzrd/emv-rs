//! Book 2 §A2.2 - EC-SDSA (Schnorr) signature.

use crate::core::ecc_primitives::{
    P256_FIELD_BYTES, algorithm_suite, hash_algorithm, hash_for_ecc, i2os, os2i, recover_y_p256,
};
use crate::core::error::{Error, Result};
use num_bigint::BigUint;
use p256::elliptic_curve::generic_array::GenericArray;
use p256::elliptic_curve::ops::Reduce;
use p256::elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint};
use p256::elliptic_curve::{Field, PrimeField};
use p256::{AffinePoint, EncodedPoint, ProjectivePoint, Scalar, U256};

/// Verify an EC-SDSA signature per Book 2 §A2.2.3.
///
/// `suite` is the Algorithm Suite Indicator from Table 48 (only
/// [`SIGNATURE_EC_SDSA_SHA256_P256`](algorithm_suite::SIGNATURE_EC_SDSA_SHA256_P256)
/// = `'10'` is currently supported). `public_key_x` is the 32-byte
/// x-coordinate of the signer's public key - the y is recovered via
/// `Point4x()` with the §B2.2.4 lower-y convention. `signature` is the
/// 64-byte concatenation `(r || s)` produced by [`ec_sdsa_p256_sign`]
/// or an issuer signing flow.
///
/// Returns `Ok(true)` if the signature is valid, `Ok(false)` if any
/// of the §A2.2.3 verification steps fails (length, range, hash
/// mismatch), or `Err` for malformed inputs (unsupported suite,
/// public-key x not on the curve).
pub fn ec_sdsa_p256_verify(
    suite: u8,
    public_key_x: &[u8; P256_FIELD_BYTES],
    message: &[u8],
    signature: &[u8],
) -> Result<bool> {
    let hash_alg = match suite {
        algorithm_suite::SIGNATURE_EC_SDSA_SHA256_P256 => hash_algorithm::SHA_256,
        _ => return Err(Error::InvalidValue),
    };
    let n_hash = 32usize; // SHA-256 output length per Table 47
    let n_field = P256_FIELD_BYTES;

    // §A2.2.3 step a: length check.
    if signature.len() != n_hash + n_field {
        return Ok(false);
    }
    // §A2.2.3 step b: parse.
    let r = &signature[..n_hash];
    let s = &signature[n_hash..];

    // §A2.2.3 step c: s → s'. p256's Scalar::from_repr fails if the
    // canonical encoding is ≥ n, which directly enforces the upper
    // bound from step (e).
    let s_bytes = GenericArray::clone_from_slice(s);
    let s_prime: Scalar = Option::from(Scalar::from_repr(s_bytes)).ok_or(Error::InvalidValue)?;

    // §A2.2.3 step e: 0 < s' < n. The < n part is enforced by
    // Scalar::from_repr above; here we just check non-zero.
    if bool::from(s_prime.is_zero()) {
        return Ok(false);
    }

    // §A2.2.3 step d: r' = OS2I(r) mod n. The reduce-mod-n form is
    // tolerant of `r ≥ n` (which can happen since r is a hash output,
    // not a canonical scalar).
    let r_int = os2i(r);
    let r_prime = Scalar::reduce(U256::from_be_slice(&i2os(&r_int, 32)?));

    // §A2.2.3 step e: 0 < r'.
    if bool::from(r_prime.is_zero()) {
        return Ok(false);
    }

    // §A2.2.3 preliminary: recover full public-key point from x.
    let p_point = decode_public_key_p256(public_key_x)?;

    // §A2.2.3 step f: Q = s'·G − r'·P.
    let q = ProjectivePoint::GENERATOR * s_prime - p_point * r_prime;
    let q_affine: AffinePoint = q.to_affine();

    // Q at infinity → no x-coordinate, signature invalid.
    if bool::from(q_affine.is_identity()) {
        return Ok(false);
    }

    // §A2.2.3 step g: B2 = I2OS(x_Q, 32).
    let q_encoded = q_affine.to_encoded_point(false);
    let x_q = q_encoded.x().ok_or(Error::InvalidValue)?;
    let mut b2 = [0u8; 32];
    b2.copy_from_slice(x_q);

    // §A2.2.3 step h: v = Hash(B2 || MSG).
    let mut hash_input = Vec::with_capacity(b2.len() + message.len());
    hash_input.extend_from_slice(&b2);
    hash_input.extend_from_slice(message);
    let v = hash_for_ecc(hash_alg, &hash_input)?;

    // §A2.2.3 step i: v == r.
    Ok(v == r)
}

/// Sign a message with EC-SDSA per Book 2 §A2.2.2.
///
/// **The caller must supply `k` as a cryptographically unpredictable
/// 32-byte integer in `[1, n-1]`** (§A2.2.2 step a - "a statistically
/// unique and unpredictable integer"). Reusing `k` between two
/// signatures under the same private key compromises the private
/// key. Production code must source `k` from a §B2.5-compliant RNG
/// and zero it after the signature is computed.
///
/// `suite` is currently restricted to
/// [`SIGNATURE_EC_SDSA_SHA256_P256`](algorithm_suite::SIGNATURE_EC_SDSA_SHA256_P256)
/// (Suite `'10'`). `private_key` is `d`, the 32-byte private signing
/// key. Returns the 64-byte signature `(r || s)`.
pub fn ec_sdsa_p256_sign(
    suite: u8,
    private_key: &[u8; P256_FIELD_BYTES],
    k: &[u8; P256_FIELD_BYTES],
    message: &[u8],
) -> Result<Vec<u8>> {
    let hash_alg = match suite {
        algorithm_suite::SIGNATURE_EC_SDSA_SHA256_P256 => hash_algorithm::SHA_256,
        _ => return Err(Error::InvalidValue),
    };

    // §A2.2.2 step a: k must be in [1, n-1].
    let k_bytes = GenericArray::clone_from_slice(k);
    let k_scalar: Scalar = Option::from(Scalar::from_repr(k_bytes)).ok_or(Error::InvalidValue)?;
    if bool::from(k_scalar.is_zero()) {
        return Err(Error::InvalidValue);
    }

    // d must also be in [1, n-1].
    let d_bytes = GenericArray::clone_from_slice(private_key);
    let d_scalar: Scalar = Option::from(Scalar::from_repr(d_bytes)).ok_or(Error::InvalidValue)?;
    if bool::from(d_scalar.is_zero()) {
        return Err(Error::InvalidValue);
    }

    // §A2.2.2 step b: kG, take x1 → B1 = I2OS(x1, 32).
    let kg = ProjectivePoint::GENERATOR * k_scalar;
    let kg_affine = kg.to_affine();
    let kg_encoded = kg_affine.to_encoded_point(false);
    let x1 = kg_encoded.x().ok_or(Error::InvalidValue)?;
    let mut b1 = [0u8; 32];
    b1.copy_from_slice(x1);

    // §A2.2.2 step c: r = Hash(B1 || MSG).
    let mut hash_input = Vec::with_capacity(b1.len() + message.len());
    hash_input.extend_from_slice(&b1);
    hash_input.extend_from_slice(message);
    let r = hash_for_ecc(hash_alg, &hash_input)?;

    // §A2.2.2 step d: s' = (k + r' · d) mod n.
    let r_int = os2i(&r);
    let r_reduced_bytes = i2os(&r_int, 32)?;
    let r_prime = Scalar::reduce(U256::from_be_slice(&r_reduced_bytes));
    let s_prime = k_scalar + r_prime * d_scalar;

    // §A2.2.2 step e: s = I2OS(s', 32).
    let s_bytes = s_prime.to_repr();

    // §A2.2.2 step f: output (r || s).
    let mut signature = Vec::with_capacity(r.len() + s_bytes.len());
    signature.extend_from_slice(&r);
    signature.extend_from_slice(&s_bytes);
    Ok(signature)
}

/// Decode a 32-byte x-coordinate into a P-256 [`ProjectivePoint`] by
/// recovering the lower-y root via [`recover_y_p256`].
fn decode_public_key_p256(x: &[u8; P256_FIELD_BYTES]) -> Result<ProjectivePoint> {
    let y = recover_y_p256(x)?;
    let mut uncompressed = [0u8; 1 + 2 * P256_FIELD_BYTES];
    uncompressed[0] = 0x04;
    uncompressed[1..33].copy_from_slice(x);
    uncompressed[33..].copy_from_slice(&y);
    let encoded =
        EncodedPoint::from_bytes(uncompressed.as_slice()).map_err(|_| Error::InvalidValue)?;
    let affine: AffinePoint =
        Option::from(AffinePoint::from_encoded_point(&encoded)).ok_or(Error::InvalidValue)?;
    Ok(affine.into())
}

/// Apply the §B2.2.4 long-term-key constraint to a candidate private
/// key for P-256: returns `d` if `dG.y < (p+1)/2`, else returns `n -
/// d` (whose public point is `-dG`, with `y' = p - y < (p+1)/2`).
///
/// Per §B2.2.4 long-term keys (Payment System / Issuer / ICC) must
/// generate a public point whose y as an integer mod p is less than
/// `(p+1)/2`, so that x-only recovery via `Point4x()` (which returns
/// the lower root) reconstructs the correct point. Wrap candidate
/// signing keys with this helper before use.
///
/// Errors with `InvalidValue` for `d = 0` or any other non-canonical
/// scalar encoding.
pub fn constrain_long_term_private_key_p256(
    d: &[u8; P256_FIELD_BYTES],
) -> Result<[u8; P256_FIELD_BYTES]> {
    let d_bytes = GenericArray::clone_from_slice(d);
    let d_scalar: Scalar = Option::from(Scalar::from_repr(d_bytes)).ok_or(Error::InvalidValue)?;
    if bool::from(d_scalar.is_zero()) {
        return Err(Error::InvalidValue);
    }
    let point = ProjectivePoint::GENERATOR * d_scalar;
    let affine = point.to_affine();
    let encoded = affine.to_encoded_point(false);
    let y_bytes = encoded.y().ok_or(Error::InvalidValue)?;

    // Compare y to (p+1)/2.
    let y_int = BigUint::from_bytes_be(y_bytes);
    let p_field = BigUint::parse_bytes(
        b"FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF",
        16,
    )
    .unwrap();
    let half = (&p_field + BigUint::from(1u32)) / BigUint::from(2u32);
    if y_int < half {
        Ok(*d)
    } else {
        let neg = -d_scalar;
        let neg_bytes = neg.to_repr();
        let mut out = [0u8; P256_FIELD_BYTES];
        out.copy_from_slice(&neg_bytes);
        Ok(out)
    }
}

/// Compute the public-key x-coordinate `dG.x` for a private key `d`
/// per §B2.2.4. Test/issuer helper; for the long-term key constraint
/// `y < (p+1)/2` apply [`constrain_long_term_private_key_p256`] to
/// `d` first.
pub fn public_key_x_from_private(d: &[u8; P256_FIELD_BYTES]) -> Result<[u8; P256_FIELD_BYTES]> {
    let d_bytes = GenericArray::clone_from_slice(d);
    let d_scalar: Scalar = Option::from(Scalar::from_repr(d_bytes)).ok_or(Error::InvalidValue)?;
    let p = ProjectivePoint::GENERATOR * d_scalar;
    let p_affine = p.to_affine();
    let encoded = p_affine.to_encoded_point(false);
    let x = encoded.x().ok_or(Error::InvalidValue)?;
    let mut out = [0u8; 32];
    out.copy_from_slice(x);
    Ok(out)
}

// ── P-521 Suite '11' ─────────────────────────────────────────────────

mod p521_impl {
    use crate::core::ecc_primitives::{
        P521_FIELD_BYTES, algorithm_suite, hash_algorithm, hash_for_ecc, recover_y_p521,
    };
    use crate::core::error::{Error, Result};
    use num_bigint::BigUint;
    use p521::elliptic_curve::PrimeField;
    use p521::elliptic_curve::generic_array::GenericArray;
    use p521::elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint};
    use p521::{AffinePoint, EncodedPoint, ProjectivePoint, Scalar};

    /// Verify an EC-SDSA P-521 signature per Book 2 §A2.2.3 with
    /// Suite `'11'` (SHA-512 + P-521). Mirrors
    /// [`super::ec_sdsa_p256_verify`]; differences:
    ///
    /// - Hash is SHA-512 (`N_HASH = 64`).
    /// - Field bytes is 66 (`N_FIELD = 66`).
    /// - Signature length is `64 + 66 = 130` bytes.
    pub fn ec_sdsa_p521_verify(
        suite: u8,
        public_key_x: &[u8; P521_FIELD_BYTES],
        message: &[u8],
        signature: &[u8],
    ) -> Result<bool> {
        let hash_alg = match suite {
            algorithm_suite::SIGNATURE_EC_SDSA_SHA512_P521 => hash_algorithm::SHA_512,
            _ => return Err(Error::InvalidValue),
        };
        let n_hash = 64usize;
        let n_field = P521_FIELD_BYTES;

        // Step a.
        if signature.len() != n_hash + n_field {
            return Ok(false);
        }
        // Step b: parse.
        let r = &signature[..n_hash];
        let s = &signature[n_hash..];

        // Step c / e (upper bound s' < n): from_repr fails for s ≥ n.
        let s_bytes = GenericArray::clone_from_slice(s);
        let s_prime: Scalar =
            Option::from(Scalar::from_repr(s_bytes)).ok_or(Error::InvalidValue)?;
        if bool::from(s_prime.is_zero()) {
            return Ok(false);
        }

        // Step d: r' = OS2I(r) mod n. The 64-byte SHA-512 output is
        // always < n (n ≈ 2^521), so reduction is a no-op - but we
        // still left-pad to the canonical 66-byte scalar repr and
        // run from_repr through to enforce that. We accept r' = r
        // when r as integer < n; otherwise we reduce explicitly.
        let r_prime = scalar_from_be_bytes_reduced(r)?;
        if bool::from(r_prime.is_zero()) {
            return Ok(false);
        }

        // Preliminary processing: recover P from x.
        let p_point = decode_public_key_p521(public_key_x)?;

        // Step f: Q = s'·G − r'·P.
        let q = ProjectivePoint::GENERATOR * s_prime - p_point * r_prime;
        let q_affine: AffinePoint = q.into();
        if bool::from(q_affine.is_identity()) {
            return Ok(false);
        }

        // Step g: B2 = I2OS(x_Q, 66).
        let q_encoded = q_affine.to_encoded_point(false);
        let x_q = q_encoded.x().ok_or(Error::InvalidValue)?;
        let mut b2 = [0u8; P521_FIELD_BYTES];
        b2.copy_from_slice(x_q);

        // Step h: v = Hash(B2 || MSG).
        let mut hash_input = Vec::with_capacity(b2.len() + message.len());
        hash_input.extend_from_slice(&b2);
        hash_input.extend_from_slice(message);
        let v = hash_for_ecc(hash_alg, &hash_input)?;

        // Step i.
        Ok(v == r)
    }

    /// Sign a message with EC-SDSA P-521 (Suite `'11'`) per §A2.2.2.
    ///
    /// Mirror of [`super::ec_sdsa_p256_sign`] - `k` is caller-supplied
    /// for testability; production code must source it from a
    /// §B2.5-compliant RNG and zero it after use.
    pub fn ec_sdsa_p521_sign(
        suite: u8,
        private_key: &[u8; P521_FIELD_BYTES],
        k: &[u8; P521_FIELD_BYTES],
        message: &[u8],
    ) -> Result<Vec<u8>> {
        let hash_alg = match suite {
            algorithm_suite::SIGNATURE_EC_SDSA_SHA512_P521 => hash_algorithm::SHA_512,
            _ => return Err(Error::InvalidValue),
        };

        let k_bytes = GenericArray::clone_from_slice(k);
        let k_scalar: Scalar =
            Option::from(Scalar::from_repr(k_bytes)).ok_or(Error::InvalidValue)?;
        if bool::from(k_scalar.is_zero()) {
            return Err(Error::InvalidValue);
        }

        let d_bytes = GenericArray::clone_from_slice(private_key);
        let d_scalar: Scalar =
            Option::from(Scalar::from_repr(d_bytes)).ok_or(Error::InvalidValue)?;
        if bool::from(d_scalar.is_zero()) {
            return Err(Error::InvalidValue);
        }

        // Step b: kG, B1 = I2OS(x_1, 66).
        let kg = ProjectivePoint::GENERATOR * k_scalar;
        let kg_affine: AffinePoint = kg.into();
        let kg_encoded = kg_affine.to_encoded_point(false);
        let x1 = kg_encoded.x().ok_or(Error::InvalidValue)?;
        let mut b1 = [0u8; P521_FIELD_BYTES];
        b1.copy_from_slice(x1);

        // Step c: r = Hash(B1 || MSG).
        let mut hash_input = Vec::with_capacity(b1.len() + message.len());
        hash_input.extend_from_slice(&b1);
        hash_input.extend_from_slice(message);
        let r = hash_for_ecc(hash_alg, &hash_input)?;

        // Step d: s' = (k + r' · d) mod n.
        let r_prime = scalar_from_be_bytes_reduced(&r)?;
        let s_prime = k_scalar + r_prime * d_scalar;

        // Step e: s = I2OS(s', 66).
        let s_bytes = s_prime.to_repr();

        // Step f: output (r || s).
        let mut signature = Vec::with_capacity(r.len() + s_bytes.len());
        signature.extend_from_slice(&r);
        signature.extend_from_slice(&s_bytes);
        Ok(signature)
    }

    /// §B2.2.4 long-term-key constraint for P-521: returns `d` if
    /// `dG.y < (p+1)/2`, else returns `n - d` (whose public point's
    /// y becomes `p - y`, the lower root).
    pub fn constrain_long_term_private_key_p521(
        d: &[u8; P521_FIELD_BYTES],
    ) -> Result<[u8; P521_FIELD_BYTES]> {
        let d_bytes = GenericArray::clone_from_slice(d);
        let d_scalar: Scalar =
            Option::from(Scalar::from_repr(d_bytes)).ok_or(Error::InvalidValue)?;
        if bool::from(d_scalar.is_zero()) {
            return Err(Error::InvalidValue);
        }
        let point = ProjectivePoint::GENERATOR * d_scalar;
        let affine: AffinePoint = point.into();
        let encoded = affine.to_encoded_point(false);
        let y_bytes = encoded.y().ok_or(Error::InvalidValue)?;

        let y_int = BigUint::from_bytes_be(y_bytes);
        let p_field = (BigUint::from(1u32) << 521u32) - BigUint::from(1u32);
        let half = (&p_field + BigUint::from(1u32)) / BigUint::from(2u32);
        if y_int < half {
            Ok(*d)
        } else {
            let neg = -d_scalar;
            let neg_bytes = neg.to_repr();
            let mut out = [0u8; P521_FIELD_BYTES];
            out.copy_from_slice(&neg_bytes);
            Ok(out)
        }
    }

    /// Compute `dG.x` for a P-521 private key. Test/issuer helper.
    pub fn public_key_x_from_private_p521(
        d: &[u8; P521_FIELD_BYTES],
    ) -> Result<[u8; P521_FIELD_BYTES]> {
        let d_bytes = GenericArray::clone_from_slice(d);
        let d_scalar: Scalar =
            Option::from(Scalar::from_repr(d_bytes)).ok_or(Error::InvalidValue)?;
        let p = ProjectivePoint::GENERATOR * d_scalar;
        let p_affine: AffinePoint = p.into();
        let encoded = p_affine.to_encoded_point(false);
        let x = encoded.x().ok_or(Error::InvalidValue)?;
        let mut out = [0u8; P521_FIELD_BYTES];
        out.copy_from_slice(x);
        Ok(out)
    }

    fn decode_public_key_p521(x: &[u8; P521_FIELD_BYTES]) -> Result<ProjectivePoint> {
        let y = recover_y_p521(x)?;
        let mut uncompressed = [0u8; 1 + 2 * P521_FIELD_BYTES];
        uncompressed[0] = 0x04;
        uncompressed[1..1 + P521_FIELD_BYTES].copy_from_slice(x);
        uncompressed[1 + P521_FIELD_BYTES..].copy_from_slice(&y);
        let encoded =
            EncodedPoint::from_bytes(uncompressed.as_slice()).map_err(|_| Error::InvalidValue)?;
        let affine: AffinePoint =
            Option::from(AffinePoint::from_encoded_point(&encoded)).ok_or(Error::InvalidValue)?;
        Ok(affine.into())
    }

    /// Reduce an arbitrary big-endian byte string into a P-521
    /// scalar via OS2I → reduce mod n. Implementation: BigUint mod
    /// n, then encode as a 66-byte canonical scalar repr.
    ///
    /// For SHA-512 outputs (`N_HASH = 64`) the integer is always
    /// less than n (n ≈ 2^521 > 2^512), so the reduction is a
    /// no-op; the function still pads/encodes correctly.
    fn scalar_from_be_bytes_reduced(bytes: &[u8]) -> Result<Scalar> {
        let v = BigUint::from_bytes_be(bytes);
        // Group order n for P-521 from Table 46.
        let n = BigUint::parse_bytes(
            b"01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFA51868783BF2F966B7FCC0148F709A5D03BB5C9B8899C47AEBB6FB71E91386409",
            16,
        )
        .expect("hardcoded P-521 n parses");
        let reduced = v % n;
        let mut canonical = [0u8; P521_FIELD_BYTES];
        let bytes = reduced.to_bytes_be();
        canonical[P521_FIELD_BYTES - bytes.len()..].copy_from_slice(&bytes);
        let arr = GenericArray::clone_from_slice(&canonical);
        Option::from(Scalar::from_repr(arr)).ok_or(Error::InvalidValue)
    }
}

pub use p521_impl::{
    constrain_long_term_private_key_p521, ec_sdsa_p521_sign, ec_sdsa_p521_verify,
    public_key_x_from_private_p521,
};

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

    /// A reasonably-arbitrary private key in [1, n-1] used across
    /// round-trip tests.
    fn test_private_key() -> [u8; 32] {
        h32("c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721")
    }

    /// A separate ephemeral k value, also in range.
    fn test_k() -> [u8; 32] {
        h32("a6e3c57dd01abe90086538398355dd4c3b17aa873382b0f24d6129493d8aad60")
    }

    // ── Sign / verify round trip ─────────────────────────────────────

    #[test]
    fn sign_then_verify_round_trip() {
        let d = test_private_key();
        let k = test_k();
        let pk_x = public_key_x_from_private(&d).unwrap();
        let msg = b"sample message";

        let sig =
            ec_sdsa_p256_sign(algorithm_suite::SIGNATURE_EC_SDSA_SHA256_P256, &d, &k, msg).unwrap();
        assert_eq!(sig.len(), 64);

        let ok = ec_sdsa_p256_verify(
            algorithm_suite::SIGNATURE_EC_SDSA_SHA256_P256,
            &pk_x,
            msg,
            &sig,
        )
        .unwrap();
        assert!(ok);
    }

    #[test]
    fn verify_fails_on_tampered_signature() {
        let d = test_private_key();
        let pk_x = public_key_x_from_private(&d).unwrap();
        let msg = b"sample message";
        let mut sig = ec_sdsa_p256_sign(
            algorithm_suite::SIGNATURE_EC_SDSA_SHA256_P256,
            &d,
            &test_k(),
            msg,
        )
        .unwrap();
        sig[0] ^= 0x01; // flip a bit in r
        let ok = ec_sdsa_p256_verify(
            algorithm_suite::SIGNATURE_EC_SDSA_SHA256_P256,
            &pk_x,
            msg,
            &sig,
        )
        .unwrap();
        assert!(!ok);
    }

    #[test]
    fn verify_fails_on_tampered_s() {
        let d = test_private_key();
        let pk_x = public_key_x_from_private(&d).unwrap();
        let msg = b"sample message";
        let mut sig = ec_sdsa_p256_sign(
            algorithm_suite::SIGNATURE_EC_SDSA_SHA256_P256,
            &d,
            &test_k(),
            msg,
        )
        .unwrap();
        sig[40] ^= 0x01; // flip a bit in s
        let ok = ec_sdsa_p256_verify(
            algorithm_suite::SIGNATURE_EC_SDSA_SHA256_P256,
            &pk_x,
            msg,
            &sig,
        )
        .unwrap();
        assert!(!ok);
    }

    #[test]
    fn verify_fails_on_modified_message() {
        let d = test_private_key();
        let pk_x = public_key_x_from_private(&d).unwrap();
        let sig = ec_sdsa_p256_sign(
            algorithm_suite::SIGNATURE_EC_SDSA_SHA256_P256,
            &d,
            &test_k(),
            b"original message",
        )
        .unwrap();
        let ok = ec_sdsa_p256_verify(
            algorithm_suite::SIGNATURE_EC_SDSA_SHA256_P256,
            &pk_x,
            b"modified message",
            &sig,
        )
        .unwrap();
        assert!(!ok);
    }

    #[test]
    fn verify_fails_on_wrong_public_key() {
        let d_signer = test_private_key();
        let other_d = h32("1111111111111111111111111111111111111111111111111111111111111111");
        let other_pk_x = public_key_x_from_private(&other_d).unwrap();
        let sig = ec_sdsa_p256_sign(
            algorithm_suite::SIGNATURE_EC_SDSA_SHA256_P256,
            &d_signer,
            &test_k(),
            b"msg",
        )
        .unwrap();
        let ok = ec_sdsa_p256_verify(
            algorithm_suite::SIGNATURE_EC_SDSA_SHA256_P256,
            &other_pk_x,
            b"msg",
            &sig,
        )
        .unwrap();
        assert!(!ok);
    }

    #[test]
    fn verify_round_trip_with_empty_message() {
        // §A2.2.2 / §A2.2.3 explicitly allow MSG of length L ≥ 0.
        let d = test_private_key();
        let pk_x = public_key_x_from_private(&d).unwrap();
        let sig = ec_sdsa_p256_sign(
            algorithm_suite::SIGNATURE_EC_SDSA_SHA256_P256,
            &d,
            &test_k(),
            &[],
        )
        .unwrap();
        let ok = ec_sdsa_p256_verify(
            algorithm_suite::SIGNATURE_EC_SDSA_SHA256_P256,
            &pk_x,
            &[],
            &sig,
        )
        .unwrap();
        assert!(ok);
    }

    #[test]
    fn verify_round_trip_with_long_message() {
        let d = test_private_key();
        let pk_x = public_key_x_from_private(&d).unwrap();
        let msg: Vec<u8> = (0..1000).map(|i| (i % 256) as u8).collect();
        let sig = ec_sdsa_p256_sign(
            algorithm_suite::SIGNATURE_EC_SDSA_SHA256_P256,
            &d,
            &test_k(),
            &msg,
        )
        .unwrap();
        let ok = ec_sdsa_p256_verify(
            algorithm_suite::SIGNATURE_EC_SDSA_SHA256_P256,
            &pk_x,
            &msg,
            &sig,
        )
        .unwrap();
        assert!(ok);
    }

    // ── Length / range validation ────────────────────────────────────

    #[test]
    fn verify_rejects_wrong_signature_length() {
        let d = test_private_key();
        let pk_x = public_key_x_from_private(&d).unwrap();
        // 63 bytes (one short).
        let sig = vec![0u8; 63];
        let ok = ec_sdsa_p256_verify(
            algorithm_suite::SIGNATURE_EC_SDSA_SHA256_P256,
            &pk_x,
            b"msg",
            &sig,
        )
        .unwrap();
        assert!(!ok);
        // 65 bytes (one long).
        let sig = vec![0u8; 65];
        let ok = ec_sdsa_p256_verify(
            algorithm_suite::SIGNATURE_EC_SDSA_SHA256_P256,
            &pk_x,
            b"msg",
            &sig,
        )
        .unwrap();
        assert!(!ok);
    }

    #[test]
    fn verify_rejects_zero_s() {
        let d = test_private_key();
        let pk_x = public_key_x_from_private(&d).unwrap();
        let mut sig = vec![0u8; 64];
        // r non-zero, s = 0.
        sig[0] = 0xAA;
        let ok = ec_sdsa_p256_verify(
            algorithm_suite::SIGNATURE_EC_SDSA_SHA256_P256,
            &pk_x,
            b"msg",
            &sig,
        )
        .unwrap();
        assert!(!ok);
    }

    #[test]
    fn verify_rejects_s_geq_n() {
        let d = test_private_key();
        let pk_x = public_key_x_from_private(&d).unwrap();
        // s = all-FFs (much larger than n) → Scalar::from_repr fails.
        let mut sig = vec![0u8; 64];
        for b in sig.iter_mut().skip(32) {
            *b = 0xFF;
        }
        sig[0] = 0xAA; // r non-zero
        // Should error rather than silently fail (this is a malformed
        // signature - not a tamper but an out-of-range encoding).
        assert!(
            ec_sdsa_p256_verify(
                algorithm_suite::SIGNATURE_EC_SDSA_SHA256_P256,
                &pk_x,
                b"msg",
                &sig,
            )
            .is_err()
        );
    }

    #[test]
    fn verify_rejects_unsupported_suite() {
        let d = test_private_key();
        let pk_x = public_key_x_from_private(&d).unwrap();
        let sig = vec![0u8; 64];
        // Suite '11' (P-521) not yet supported.
        assert!(
            ec_sdsa_p256_verify(
                algorithm_suite::SIGNATURE_EC_SDSA_SHA512_P521,
                &pk_x,
                b"msg",
                &sig,
            )
            .is_err()
        );
    }

    #[test]
    fn sign_rejects_unsupported_suite() {
        let result = ec_sdsa_p256_sign(
            algorithm_suite::SIGNATURE_EC_SDSA_SHA512_P521,
            &test_private_key(),
            &test_k(),
            b"msg",
        );
        assert!(result.is_err());
    }

    #[test]
    fn sign_rejects_zero_k() {
        let result = ec_sdsa_p256_sign(
            algorithm_suite::SIGNATURE_EC_SDSA_SHA256_P256,
            &test_private_key(),
            &[0u8; 32],
            b"msg",
        );
        assert!(result.is_err());
    }

    #[test]
    fn sign_rejects_zero_private_key() {
        let result = ec_sdsa_p256_sign(
            algorithm_suite::SIGNATURE_EC_SDSA_SHA256_P256,
            &[0u8; 32],
            &test_k(),
            b"msg",
        );
        assert!(result.is_err());
    }

    // ── Determinism ──────────────────────────────────────────────────

    #[test]
    fn sign_is_deterministic_for_fixed_k() {
        let d = test_private_key();
        let k = test_k();
        let msg = b"sample message";
        let sig1 =
            ec_sdsa_p256_sign(algorithm_suite::SIGNATURE_EC_SDSA_SHA256_P256, &d, &k, msg).unwrap();
        let sig2 =
            ec_sdsa_p256_sign(algorithm_suite::SIGNATURE_EC_SDSA_SHA256_P256, &d, &k, msg).unwrap();
        assert_eq!(sig1, sig2);
    }

    #[test]
    fn different_k_yields_different_signature() {
        let d = test_private_key();
        let k1 = test_k();
        let k2 = h32("1111111111111111111111111111111111111111111111111111111111111111");
        let msg = b"sample message";
        let sig1 = ec_sdsa_p256_sign(algorithm_suite::SIGNATURE_EC_SDSA_SHA256_P256, &d, &k1, msg)
            .unwrap();
        let sig2 = ec_sdsa_p256_sign(algorithm_suite::SIGNATURE_EC_SDSA_SHA256_P256, &d, &k2, msg)
            .unwrap();
        assert_ne!(sig1, sig2);
    }

    // ── P-521 (Suite '11') ───────────────────────────────────────────

    fn h66(s: &str) -> [u8; 66] {
        h(s).try_into().unwrap()
    }

    /// A P-521 private key in [1, n-1], wrapped with the §B2.2.4
    /// long-term-key constraint so that recover_y_p521 reconstructs
    /// the correct point.
    fn test_private_key_p521() -> [u8; 66] {
        constrain_long_term_private_key_p521(&h66("00C9 AFA9 D845 BA75 166B 5C21 5767 B1D6\
             934E 50C3 DB36 E89B 127B 8A62 2B12 0F67\
             21AB CDEF 0123 4567 89AB CDEF 0123 4567\
             89AB CDEF 0123 4567 89AB CDEF 0123 4567\
             8901"))
        .unwrap()
    }

    fn test_k_p521() -> [u8; 66] {
        h66("00A6 E3C5 7DD0 1ABE 9008 6538 3983 55DD\
             4C3B 17AA 8733 82B0 F24D 6129 493D 8AAD\
             6011 2233 4455 6677 8899 AABB CCDD EEFF\
             0011 2233 4455 6677 8899 AABB CCDD EEFF\
             0011")
    }

    #[test]
    fn p521_sign_then_verify_round_trip() {
        let d = test_private_key_p521();
        let k = test_k_p521();
        let pk_x = public_key_x_from_private_p521(&d).unwrap();
        let msg = b"sample message";

        let sig =
            ec_sdsa_p521_sign(algorithm_suite::SIGNATURE_EC_SDSA_SHA512_P521, &d, &k, msg).unwrap();
        assert_eq!(
            sig.len(),
            64 + 66,
            "Suite '11' signature is N_HASH + N_FIELD"
        );

        let ok = ec_sdsa_p521_verify(
            algorithm_suite::SIGNATURE_EC_SDSA_SHA512_P521,
            &pk_x,
            msg,
            &sig,
        )
        .unwrap();
        assert!(ok);
    }

    #[test]
    fn p521_verify_fails_on_tampered_signature() {
        let d = test_private_key_p521();
        let pk_x = public_key_x_from_private_p521(&d).unwrap();
        let msg = b"sample message";
        let mut sig = ec_sdsa_p521_sign(
            algorithm_suite::SIGNATURE_EC_SDSA_SHA512_P521,
            &d,
            &test_k_p521(),
            msg,
        )
        .unwrap();
        sig[0] ^= 0x01;
        let ok = ec_sdsa_p521_verify(
            algorithm_suite::SIGNATURE_EC_SDSA_SHA512_P521,
            &pk_x,
            msg,
            &sig,
        )
        .unwrap();
        assert!(!ok);
    }

    #[test]
    fn p521_verify_fails_on_modified_message() {
        let d = test_private_key_p521();
        let pk_x = public_key_x_from_private_p521(&d).unwrap();
        let sig = ec_sdsa_p521_sign(
            algorithm_suite::SIGNATURE_EC_SDSA_SHA512_P521,
            &d,
            &test_k_p521(),
            b"original",
        )
        .unwrap();
        let ok = ec_sdsa_p521_verify(
            algorithm_suite::SIGNATURE_EC_SDSA_SHA512_P521,
            &pk_x,
            b"modified",
            &sig,
        )
        .unwrap();
        assert!(!ok);
    }

    #[test]
    fn p521_verify_fails_on_wrong_public_key() {
        let d = test_private_key_p521();
        let other_d =
            constrain_long_term_private_key_p521(&h66("0011 1111 1111 1111 1111 1111 1111 1111\
             1111 1111 1111 1111 1111 1111 1111 1111\
             1111 1111 1111 1111 1111 1111 1111 1111\
             1111 1111 1111 1111 1111 1111 1111 1111\
             1111"))
            .unwrap();
        let other_pk_x = public_key_x_from_private_p521(&other_d).unwrap();
        let sig = ec_sdsa_p521_sign(
            algorithm_suite::SIGNATURE_EC_SDSA_SHA512_P521,
            &d,
            &test_k_p521(),
            b"msg",
        )
        .unwrap();
        let ok = ec_sdsa_p521_verify(
            algorithm_suite::SIGNATURE_EC_SDSA_SHA512_P521,
            &other_pk_x,
            b"msg",
            &sig,
        )
        .unwrap();
        assert!(!ok);
    }

    #[test]
    fn p521_verify_round_trip_long_message() {
        let d = test_private_key_p521();
        let pk_x = public_key_x_from_private_p521(&d).unwrap();
        let msg: Vec<u8> = (0..2000).map(|i| (i % 256) as u8).collect();
        let sig = ec_sdsa_p521_sign(
            algorithm_suite::SIGNATURE_EC_SDSA_SHA512_P521,
            &d,
            &test_k_p521(),
            &msg,
        )
        .unwrap();
        assert!(
            ec_sdsa_p521_verify(
                algorithm_suite::SIGNATURE_EC_SDSA_SHA512_P521,
                &pk_x,
                &msg,
                &sig,
            )
            .unwrap()
        );
    }

    #[test]
    fn p521_verify_rejects_wrong_signature_length() {
        let pk_x = public_key_x_from_private_p521(&test_private_key_p521()).unwrap();
        let sig = vec![0u8; 129];
        assert!(
            !ec_sdsa_p521_verify(
                algorithm_suite::SIGNATURE_EC_SDSA_SHA512_P521,
                &pk_x,
                b"msg",
                &sig,
            )
            .unwrap()
        );
    }

    #[test]
    fn p521_verify_rejects_unsupported_suite() {
        let pk_x = public_key_x_from_private_p521(&test_private_key_p521()).unwrap();
        let sig = vec![0u8; 130];
        // Suite '10' (P-256) doesn't apply to the P-521 verify
        // function.
        assert!(
            ec_sdsa_p521_verify(
                algorithm_suite::SIGNATURE_EC_SDSA_SHA256_P256,
                &pk_x,
                b"msg",
                &sig,
            )
            .is_err()
        );
    }

    #[test]
    fn p521_sign_rejects_zero_k() {
        let result = ec_sdsa_p521_sign(
            algorithm_suite::SIGNATURE_EC_SDSA_SHA512_P521,
            &test_private_key_p521(),
            &[0u8; 66],
            b"msg",
        );
        assert!(result.is_err());
    }

    #[test]
    fn p521_sign_is_deterministic_for_fixed_k() {
        let d = test_private_key_p521();
        let k = test_k_p521();
        let msg = b"sample";
        let s1 =
            ec_sdsa_p521_sign(algorithm_suite::SIGNATURE_EC_SDSA_SHA512_P521, &d, &k, msg).unwrap();
        let s2 =
            ec_sdsa_p521_sign(algorithm_suite::SIGNATURE_EC_SDSA_SHA512_P521, &d, &k, msg).unwrap();
        assert_eq!(s1, s2);
    }
}
