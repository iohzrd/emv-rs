//! Book 2 §A2.1 / §B2.1 - ISO/IEC 9796-2 signature with message recovery.

use crate::core::error::{Error, Result};
use num_bigint::BigUint;
use sha1::{Digest, Sha1};

pub fn rsa_recover(sig: &[u8], exponent: &[u8], modulus: &[u8]) -> Result<Vec<u8>> {
    if sig.len() != modulus.len() {
        return Err(Error::WrongLength {
            expected: modulus.len(),
            got: sig.len(),
        });
    }
    let s = BigUint::from_bytes_be(sig);
    let e = BigUint::from_bytes_be(exponent);
    let n = BigUint::from_bytes_be(modulus);
    if n.bits() == 0 || s >= n {
        return Err(Error::InvalidValue);
    }
    let m = s.modpow(&e, &n);
    let mut out = m.to_bytes_be();
    if out.len() < modulus.len() {
        let mut padded = vec![0u8; modulus.len() - out.len()];
        padded.append(&mut out);
        out = padded;
    }
    Ok(out)
}

pub fn verify(sig: &[u8], exponent: &[u8], modulus: &[u8], msg2: &[u8]) -> Result<Vec<u8>> {
    let n = modulus.len();
    if n < 22 {
        return Err(Error::InvalidValue);
    }
    let x = rsa_recover(sig, exponent, modulus)?;
    if x[0] != 0x6A {
        return Err(Error::InvalidValue);
    }
    if x[n - 1] != 0xBC {
        return Err(Error::InvalidValue);
    }
    let msg1 = &x[1..(n - 21)];
    let recovered_hash = &x[(n - 21)..(n - 1)];
    let mut hasher = Sha1::new();
    hasher.update(msg1);
    hasher.update(msg2);
    let computed = hasher.finalize();
    if recovered_hash != computed.as_slice() {
        return Err(Error::InvalidValue);
    }
    Ok(msg1.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn identity_key(byte_length: usize) -> (Vec<u8>, Vec<u8>) {
        (vec![1u8], vec![0xFFu8; byte_length])
    }

    fn sha1_hash(data: &[u8]) -> [u8; 20] {
        let mut h = Sha1::new();
        h.update(data);
        h.finalize().into()
    }

    // ── rsa_recover ──────────────────────────────────────────────────

    #[test]
    fn rsa_recover_textbook_toy_keypair() {
        let result = rsa_recover(&[3], &[7], &[143]).unwrap();
        assert_eq!(result, vec![42]);
    }

    #[test]
    fn rsa_recover_pads_to_modulus_length() {
        let result = rsa_recover(&[0, 0, 0, 3], &[7], &[0, 0, 0, 143]).unwrap();
        assert_eq!(result, vec![0, 0, 0, 42]);
    }

    #[test]
    fn rsa_recover_identity_key_returns_input() {
        let (e, n) = identity_key(2);
        assert_eq!(
            rsa_recover(&[0x12, 0x34], &e, &n).unwrap(),
            vec![0x12, 0x34]
        );
    }

    #[test]
    fn rsa_recover_rejects_signature_length_mismatch() {
        let result = rsa_recover(&[1, 2], &[7], &[143]);
        assert_eq!(
            result,
            Err(Error::WrongLength {
                expected: 1,
                got: 2
            })
        );
    }

    #[test]
    fn rsa_recover_rejects_s_ge_n() {
        let result = rsa_recover(&[143], &[7], &[143]);
        assert_eq!(result, Err(Error::InvalidValue));
    }

    // ── verify ───────────────────────────────────────────────────────

    fn build_x(msg1: &[u8], msg2: &[u8], modulus_len: usize) -> Vec<u8> {
        assert_eq!(msg1.len(), modulus_len - 22);
        let mut hasher = Sha1::new();
        hasher.update(msg1);
        hasher.update(msg2);
        let h = hasher.finalize();
        let mut x = Vec::with_capacity(modulus_len);
        x.push(0x6A);
        x.extend_from_slice(msg1);
        x.extend_from_slice(&h);
        x.push(0xBC);
        x
    }

    #[test]
    fn verify_happy_path_returns_msg1() {
        let (e, n) = identity_key(64);
        let msg1: Vec<u8> = (0..(64 - 22)).map(|i| i as u8).collect();
        let msg2 = b"appendix data";
        let sig = build_x(&msg1, msg2, 64);
        let recovered = verify(&sig, &e, &n, msg2).unwrap();
        assert_eq!(recovered, msg1);
    }

    #[test]
    fn verify_empty_msg2() {
        let (e, n) = identity_key(64);
        let msg1 = vec![0xAB; 64 - 22];
        let sig = build_x(&msg1, &[], 64);
        let recovered = verify(&sig, &e, &n, &[]).unwrap();
        assert_eq!(recovered, msg1);
    }

    #[test]
    fn verify_rejects_bad_header() {
        let (e, n) = identity_key(64);
        let msg1 = vec![0xAB; 64 - 22];
        let mut sig = build_x(&msg1, b"", 64);
        sig[0] = 0x6B;
        assert_eq!(verify(&sig, &e, &n, b""), Err(Error::InvalidValue));
    }

    #[test]
    fn verify_rejects_bad_trailer() {
        let (e, n) = identity_key(64);
        let msg1 = vec![0xAB; 64 - 22];
        let mut sig = build_x(&msg1, b"", 64);
        sig[63] = 0xBD;
        assert_eq!(verify(&sig, &e, &n, b""), Err(Error::InvalidValue));
    }

    #[test]
    fn verify_rejects_corrupted_hash() {
        let (e, n) = identity_key(64);
        let msg1 = vec![0xAB; 64 - 22];
        let mut sig = build_x(&msg1, b"", 64);
        sig[50] ^= 0x01;
        assert_eq!(verify(&sig, &e, &n, b""), Err(Error::InvalidValue));
    }

    #[test]
    fn verify_rejects_modified_msg2() {
        let (e, n) = identity_key(64);
        let msg1 = vec![0xAB; 64 - 22];
        let sig = build_x(&msg1, b"original", 64);
        assert_eq!(verify(&sig, &e, &n, b"modified"), Err(Error::InvalidValue));
    }

    #[test]
    fn verify_rejects_short_modulus() {
        let n = vec![0xFF; 16];
        let sig = vec![0u8; 16];
        assert_eq!(verify(&sig, &[1], &n, b""), Err(Error::InvalidValue));
    }

    #[test]
    fn verify_propagates_recover_length_error() {
        let (e, n) = identity_key(64);
        assert_eq!(
            verify(&[0u8; 32], &e, &n, b""),
            Err(Error::WrongLength {
                expected: 64,
                got: 32
            }),
        );
    }

    #[test]
    fn sha1_of_empty_string_known_answer() {
        let h = sha1_hash(b"");
        assert_eq!(
            h,
            [
                0xda, 0x39, 0xa3, 0xee, 0x5e, 0x6b, 0x4b, 0x0d, 0x32, 0x55, 0xbf, 0xef, 0x95, 0x60,
                0x18, 0x90, 0xaf, 0xd8, 0x07, 0x09,
            ],
        );
    }
}
