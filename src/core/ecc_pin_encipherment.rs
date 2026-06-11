//! Book 2 §13.2 - ECC Offline Enciphered PIN data construction.

use crate::core::ec_encryption::{
    decrypt_etm_p256, decrypt_etm_p521, derive_keys_p256, derive_keys_p521, encrypt_etm_p256,
    encrypt_etm_p521,
};
use crate::core::ec_sdsa::{public_key_x_from_private, public_key_x_from_private_p521};
use crate::core::ecc_primitives::{P256_FIELD_BYTES, P521_FIELD_BYTES, algorithm_suite};
use crate::core::error::{Error, Result};

/// `'7F'` data-header byte from Table 40.
pub const PIN_DATA_HEADER: u8 = 0x7F;

/// Build the §13.2 Enciphered Data for ODE Algorithm Suite `'00'`
/// (P-256 + DH + AES). Returns `R_x || C` - total 57 bytes.
///
/// Arguments:
///
/// - `pin_block` - 8-byte plaintext PIN block (Book 3 §6.5.12).
/// - `un_ode` - 8-byte response to GET CHALLENGE (§13.2 step 2).
/// - `icc_ode_pk_x` - 32-byte x-coordinate of the ICC's ODE public
///   key, recovered from the ICC PK Certificate for ODE (tag `'9F2D'`).
/// - `ephemeral_d` - 32-byte ephemeral private key satisfying
///   `1 ≤ d ≤ n-1`. Caller-supplied for testability; production code
///   sources it from a §B2.5-compliant RNG and discards it after use.
///
/// The caller wraps the returned bytes in the value field of VERIFY
/// (P2 = `'88'`, the Offline Enciphered PIN CVM marker).
pub fn enciphered_pin_data_ecc_p256(
    pin_block: [u8; 8],
    un_ode: [u8; 8],
    icc_ode_pk_x: &[u8; P256_FIELD_BYTES],
    ephemeral_d: &[u8; P256_FIELD_BYTES],
) -> Result<Vec<u8>> {
    let suite = algorithm_suite::ODE_P256_DH_AES;

    // §13.2 step 3a: ephemeral pair (d, R), R_x = x-coord of R.
    let r_x = public_key_x_from_private(ephemeral_d)?;

    // §13.2 step 3b: derive session keys with UN_KD = UN_ODE, Q = ICC
    // ODE public key, d = ephemeral private.
    let keys = derive_keys_p256(&un_ode, suite, ephemeral_d, icc_ode_pk_x)?;

    // §13.2 step 4: ECC encrypt the Table 40 plaintext under (K_1,
    // K_2) with A = null.
    let msg = build_pin_plaintext(pin_block, un_ode);
    let (c, _new_n) = encrypt_etm_p256(suite, &keys.k1, &keys.k2, &msg, &[], keys.counter)?;

    // §13.2 step 5: Enciphered Data := R_x || C.
    let mut enciphered = Vec::with_capacity(r_x.len() + c.len());
    enciphered.extend_from_slice(&r_x);
    enciphered.extend_from_slice(&c);
    Ok(enciphered)
}

/// ICC-side §13.3 PIN deciphering for ODE Algorithm Suite `'00'`.
///
/// Provided for symmetry / testing; a real ICC implementation lives
/// in card firmware and is out of scope for this kernel-side crate,
/// but the function lets host-test scaffolding round-trip the §13.2
/// flow without an actual card.
///
/// Returns the recovered `(pin_block, un_recovered)` if every check
/// passes:
///
/// - Length ≥ N_FIELD + 8 (32 + 8 = 40, §13.3 step 1).
/// - MAC verifies (§13.3 step 4 / §A2.3.4 step i).
/// - Recovered UN matches the supplied `un_ode` (§13.3 step 6).
/// - Recovered Data Header equals `'7F'` (§13.3 step 7).
///
/// PIN-vs-card-PIN comparison (§13.3 step 8) is the caller's
/// responsibility - this function returns the recovered PIN block.
pub fn decipher_pin_data_ecc_p256(
    enciphered: &[u8],
    un_ode: [u8; 8],
    icc_ode_private_key: &[u8; P256_FIELD_BYTES],
) -> Result<[u8; 8]> {
    let suite = algorithm_suite::ODE_P256_DH_AES;

    // §13.3 step 1: length check. R_x = 32 bytes, MAC = 8 bytes,
    // C* ≥ 0 → minimum 40 bytes overall (Table 40 has 17-byte
    // payload, so a real value is 32 + 17 + 8 = 57).
    if enciphered.len() < P256_FIELD_BYTES + 8 {
        return Err(Error::InvalidValue);
    }

    // §13.3 step 2: extract R_x and C.
    let r_x: [u8; P256_FIELD_BYTES] = enciphered[..P256_FIELD_BYTES]
        .try_into()
        .map_err(|_| Error::InvalidValue)?;
    let c = &enciphered[P256_FIELD_BYTES..];

    // §13.3 step 3: derive session keys with d = ICC private, Q = R
    // (the terminal's ephemeral public key recovered from R_x).
    let keys = derive_keys_p256(&un_ode, suite, icc_ode_private_key, &r_x)?;

    // §13.3 step 4: ECC decrypt under (K_1, K_2) with A = null.
    let (plaintext, _) = decrypt_etm_p256(suite, &keys.k1, &keys.k2, c, &[], keys.counter)?;

    // §13.3 steps 6-7: layout checks.
    if plaintext.len() != 17 {
        return Err(Error::InvalidValue);
    }
    if plaintext[0] != PIN_DATA_HEADER {
        return Err(Error::InvalidValue);
    }
    let recovered_un: [u8; 8] = plaintext[9..17]
        .try_into()
        .map_err(|_| Error::InvalidValue)?;
    if recovered_un != un_ode {
        return Err(Error::InvalidValue);
    }

    // PIN block recovered.
    let pin_block: [u8; 8] = plaintext[1..9]
        .try_into()
        .map_err(|_| Error::InvalidValue)?;
    Ok(pin_block)
}

/// Assemble the §13.2 / Table 40 plaintext: `'7F' || PIN block ||
/// UN_ODE`.
fn build_pin_plaintext(pin_block: [u8; 8], un_ode: [u8; 8]) -> [u8; 17] {
    let mut out = [0u8; 17];
    out[0] = PIN_DATA_HEADER;
    out[1..9].copy_from_slice(&pin_block);
    out[9..17].copy_from_slice(&un_ode);
    out
}

// ── P-521 (Suite '01') variants ──────────────────────────────────────

/// Suite-`'01'` (P-521 + DH + AES) variant of
/// [`enciphered_pin_data_ecc_p256`]. Returns `R_x || C` - total
/// 66 + 25 = 91 bytes.
pub fn enciphered_pin_data_ecc_p521(
    pin_block: [u8; 8],
    un_ode: [u8; 8],
    icc_ode_pk_x: &[u8; P521_FIELD_BYTES],
    ephemeral_d: &[u8; P521_FIELD_BYTES],
) -> Result<Vec<u8>> {
    let suite = algorithm_suite::ODE_P521_DH_AES;

    // §13.2 step 3a: ephemeral pair (d, R), R_x = x-coord of R.
    let r_x = public_key_x_from_private_p521(ephemeral_d)?;

    // §13.2 step 3b: derive session keys.
    let keys = derive_keys_p521(&un_ode, suite, ephemeral_d, icc_ode_pk_x)?;

    // §13.2 step 4: ECC encrypt the Table 40 plaintext (curve-
    // independent - same 17-byte plaintext for both suites).
    let msg = build_pin_plaintext(pin_block, un_ode);
    let (c, _) = encrypt_etm_p521(suite, &keys.k1, &keys.k2, &msg, &[], keys.counter)?;

    // §13.2 step 5: Enciphered Data := R_x || C.
    let mut enciphered = Vec::with_capacity(r_x.len() + c.len());
    enciphered.extend_from_slice(&r_x);
    enciphered.extend_from_slice(&c);
    Ok(enciphered)
}

/// Suite-`'01'` variant of [`decipher_pin_data_ecc_p256`].
pub fn decipher_pin_data_ecc_p521(
    enciphered: &[u8],
    un_ode: [u8; 8],
    icc_ode_private_key: &[u8; P521_FIELD_BYTES],
) -> Result<[u8; 8]> {
    let suite = algorithm_suite::ODE_P521_DH_AES;

    // §13.3 step 1: minimum length = N_FIELD + 8 (= 74 for P-521).
    if enciphered.len() < P521_FIELD_BYTES + 8 {
        return Err(Error::InvalidValue);
    }

    // §13.3 step 2: extract R_x and C.
    let r_x: [u8; P521_FIELD_BYTES] = enciphered[..P521_FIELD_BYTES]
        .try_into()
        .map_err(|_| Error::InvalidValue)?;
    let c = &enciphered[P521_FIELD_BYTES..];

    // §13.3 step 3: derive session keys.
    let keys = derive_keys_p521(&un_ode, suite, icc_ode_private_key, &r_x)?;

    // §13.3 step 4: decrypt.
    let (plaintext, _) = decrypt_etm_p521(suite, &keys.k1, &keys.k2, c, &[], keys.counter)?;

    // §13.3 steps 6-7.
    if plaintext.len() != 17 {
        return Err(Error::InvalidValue);
    }
    if plaintext[0] != PIN_DATA_HEADER {
        return Err(Error::InvalidValue);
    }
    let recovered_un: [u8; 8] = plaintext[9..17]
        .try_into()
        .map_err(|_| Error::InvalidValue)?;
    if recovered_un != un_ode {
        return Err(Error::InvalidValue);
    }

    let pin_block: [u8; 8] = plaintext[1..9]
        .try_into()
        .map_err(|_| Error::InvalidValue)?;
    Ok(pin_block)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::ec_sdsa::{constrain_long_term_private_key_p256, public_key_x_from_private};

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

    fn icc_ode_private_key() -> [u8; 32] {
        // §B2.2.4 long-term-key constraint: `Q.y < (p+1)/2` so that
        // the lower-y Point4x recovery in `decode_q_p256`
        // reconstructs the right Q.
        constrain_long_term_private_key_p256(&h32(
            "c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721",
        ))
        .unwrap()
    }

    fn ephemeral_d() -> [u8; 32] {
        // Ephemeral; per §B2.2.4 last paragraph no y-constraint
        // needed. We still wrap to make the test deterministic.
        constrain_long_term_private_key_p256(&h32(
            "a6e3c57dd01abe90086538398355dd4c3b17aa873382b0f24d6129493d8aad60",
        ))
        .unwrap()
    }

    #[test]
    fn enciphered_data_layout_matches_table_40() {
        // Output is R_x (32) || C* (17) || MAC (8) = 57 bytes.
        let icc_d = icc_ode_private_key();
        let icc_q = public_key_x_from_private(&icc_d).unwrap();
        let pin_block = [0x24, 0x12, 0x34, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF];
        let un_ode = [0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF];

        let enciphered =
            enciphered_pin_data_ecc_p256(pin_block, un_ode, &icc_q, &ephemeral_d()).unwrap();

        assert_eq!(enciphered.len(), 32 + 17 + 8);

        // R_x (first 32 bytes) must equal the public key of the
        // ephemeral private (§13.2 step 3a).
        let r_x: [u8; 32] = enciphered[..32].try_into().unwrap();
        let expected_r_x = public_key_x_from_private(&ephemeral_d()).unwrap();
        assert_eq!(r_x, expected_r_x);
    }

    #[test]
    fn end_to_end_terminal_then_icc_round_trip() {
        // Terminal builds Enciphered Data; ICC decrypts and recovers
        // the PIN block. Exercises the entire §13.2 + §13.3 flow on
        // host code (without a real card).
        let icc_d = icc_ode_private_key();
        let icc_q = public_key_x_from_private(&icc_d).unwrap();
        let pin_block = [0x24, 0x12, 0x34, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF];
        let un_ode = [0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF];

        let enciphered =
            enciphered_pin_data_ecc_p256(pin_block, un_ode, &icc_q, &ephemeral_d()).unwrap();

        let recovered = decipher_pin_data_ecc_p256(&enciphered, un_ode, &icc_d).unwrap();
        assert_eq!(recovered, pin_block);
    }

    #[test]
    fn end_to_end_distinct_ephemerals_distinct_outputs() {
        // Two different ephemeral keys against the same ICC ODE pub
        // key must yield different Enciphered Data - the freshness
        // property §13.2 relies on.
        let icc_q = public_key_x_from_private(&icc_ode_private_key()).unwrap();
        let pin = [0u8; 8];
        let un = [0u8; 8];
        let d1 = ephemeral_d();
        let d2 = constrain_long_term_private_key_p256(&h32(
            "1111111111111111111111111111111111111111111111111111111111111111",
        ))
        .unwrap();
        let e1 = enciphered_pin_data_ecc_p256(pin, un, &icc_q, &d1).unwrap();
        let e2 = enciphered_pin_data_ecc_p256(pin, un, &icc_q, &d2).unwrap();
        assert_ne!(e1, e2);
    }

    #[test]
    fn icc_decipher_rejects_tampered_ciphertext() {
        let icc_d = icc_ode_private_key();
        let icc_q = public_key_x_from_private(&icc_d).unwrap();
        let pin = [0x24, 0x12, 0x34, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF];
        let un = [0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF];
        let mut enciphered = enciphered_pin_data_ecc_p256(pin, un, &icc_q, &ephemeral_d()).unwrap();
        // Flip a bit in C* (between R_x and MAC).
        enciphered[40] ^= 0x01;
        assert!(decipher_pin_data_ecc_p256(&enciphered, un, &icc_d).is_err());
    }

    #[test]
    fn icc_decipher_rejects_tampered_mac() {
        let icc_d = icc_ode_private_key();
        let icc_q = public_key_x_from_private(&icc_d).unwrap();
        let pin = [0u8; 8];
        let un = [0u8; 8];
        let mut enciphered = enciphered_pin_data_ecc_p256(pin, un, &icc_q, &ephemeral_d()).unwrap();
        let len = enciphered.len();
        enciphered[len - 1] ^= 0x01;
        assert!(decipher_pin_data_ecc_p256(&enciphered, un, &icc_d).is_err());
    }

    #[test]
    fn icc_decipher_rejects_un_mismatch() {
        // §13.3 step 6: recovered UN must match the GET CHALLENGE one.
        let icc_d = icc_ode_private_key();
        let icc_q = public_key_x_from_private(&icc_d).unwrap();
        let pin = [0u8; 8];
        let un_signed = [0x01u8; 8];
        let un_other = [0x02u8; 8];
        let enciphered =
            enciphered_pin_data_ecc_p256(pin, un_signed, &icc_q, &ephemeral_d()).unwrap();
        // Caller passes a mismatched UN - should fail.
        assert!(decipher_pin_data_ecc_p256(&enciphered, un_other, &icc_d).is_err());
    }

    #[test]
    fn icc_decipher_rejects_short_input() {
        let icc_d = icc_ode_private_key();
        // Less than R_x (32) + MAC (8) = 40 bytes.
        assert!(decipher_pin_data_ecc_p256(&[0u8; 39], [0u8; 8], &icc_d).is_err());
    }

    #[test]
    fn icc_decipher_rejects_wrong_icc_private_key() {
        // ICC decrypts with a different private key → DH gives a
        // different shared secret → MAC fails.
        let icc_d_real = icc_ode_private_key();
        let icc_q_real = public_key_x_from_private(&icc_d_real).unwrap();
        let pin = [0u8; 8];
        let un = [0u8; 8];
        let enciphered =
            enciphered_pin_data_ecc_p256(pin, un, &icc_q_real, &ephemeral_d()).unwrap();

        let icc_d_bad = constrain_long_term_private_key_p256(&h32(
            "1111111111111111111111111111111111111111111111111111111111111111",
        ))
        .unwrap();
        assert!(decipher_pin_data_ecc_p256(&enciphered, un, &icc_d_bad).is_err());
    }

    // ── P-521 (Suite '01') ───────────────────────────────────────────

    use crate::core::ec_sdsa::constrain_long_term_private_key_p521;

    fn h66(s: &str) -> [u8; 66] {
        h(s).try_into().unwrap()
    }

    fn icc_ode_private_key_p521() -> [u8; 66] {
        constrain_long_term_private_key_p521(&h66("00C9 AFA9 D845 BA75 166B 5C21 5767 B1D6\
             934E 50C3 DB36 E89B 127B 8A62 2B12 0F67\
             21AB CDEF 0123 4567 89AB CDEF 0123 4567\
             89AB CDEF 0123 4567 89AB CDEF 0123 4567\
             8901"))
        .unwrap()
    }

    fn ephemeral_d_p521() -> [u8; 66] {
        constrain_long_term_private_key_p521(&h66("00A6 E3C5 7DD0 1ABE 9008 6538 3983 55DD\
             4C3B 17AA 8733 82B0 F24D 6129 493D 8AAD\
             6011 2233 4455 6677 8899 AABB CCDD EEFF\
             0011 2233 4455 6677 8899 AABB CCDD EEFF\
             0011"))
        .unwrap()
    }

    #[test]
    fn p521_enciphered_data_layout() {
        // Output is R_x (66) || C* (17) || MAC (8) = 91 bytes.
        let icc_d = icc_ode_private_key_p521();
        let icc_q = public_key_x_from_private_p521(&icc_d).unwrap();
        let pin = [0x24, 0x12, 0x34, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF];
        let un = [0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF];
        let enciphered =
            enciphered_pin_data_ecc_p521(pin, un, &icc_q, &ephemeral_d_p521()).unwrap();
        assert_eq!(enciphered.len(), 66 + 17 + 8);
        let r_x: [u8; 66] = enciphered[..66].try_into().unwrap();
        let expected_r_x = public_key_x_from_private_p521(&ephemeral_d_p521()).unwrap();
        assert_eq!(r_x, expected_r_x);
    }

    #[test]
    fn p521_end_to_end_round_trip() {
        let icc_d = icc_ode_private_key_p521();
        let icc_q = public_key_x_from_private_p521(&icc_d).unwrap();
        let pin = [0x24, 0x12, 0x34, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF];
        let un = [0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF];
        let enciphered =
            enciphered_pin_data_ecc_p521(pin, un, &icc_q, &ephemeral_d_p521()).unwrap();
        let recovered = decipher_pin_data_ecc_p521(&enciphered, un, &icc_d).unwrap();
        assert_eq!(recovered, pin);
    }

    #[test]
    fn p521_icc_decipher_rejects_tampered_ciphertext() {
        let icc_d = icc_ode_private_key_p521();
        let icc_q = public_key_x_from_private_p521(&icc_d).unwrap();
        let pin = [0u8; 8];
        let un = [0u8; 8];
        let mut enciphered =
            enciphered_pin_data_ecc_p521(pin, un, &icc_q, &ephemeral_d_p521()).unwrap();
        enciphered[70] ^= 0x01;
        assert!(decipher_pin_data_ecc_p521(&enciphered, un, &icc_d).is_err());
    }

    #[test]
    fn p521_icc_decipher_rejects_un_mismatch() {
        let icc_d = icc_ode_private_key_p521();
        let icc_q = public_key_x_from_private_p521(&icc_d).unwrap();
        let pin = [0u8; 8];
        let un_signed = [0x01u8; 8];
        let un_other = [0x02u8; 8];
        let enciphered =
            enciphered_pin_data_ecc_p521(pin, un_signed, &icc_q, &ephemeral_d_p521()).unwrap();
        assert!(decipher_pin_data_ecc_p521(&enciphered, un_other, &icc_d).is_err());
    }

    #[test]
    fn p521_icc_decipher_rejects_short_input() {
        let icc_d = icc_ode_private_key_p521();
        // Less than R_x (66) + MAC (8) = 74 bytes.
        assert!(decipher_pin_data_ecc_p521(&[0u8; 73], [0u8; 8], &icc_d).is_err());
    }
}
