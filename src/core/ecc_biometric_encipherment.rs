//! Book 2 §13.4 / §13.5 - ECC Offline Enciphered Biometric data construction.

use crate::core::ec_encryption::{
    decrypt_etm_p256, decrypt_etm_p521, derive_keys_p256, derive_keys_p521, encrypt_etm_p256,
    encrypt_etm_p521,
};
use crate::core::ec_sdsa::{public_key_x_from_private, public_key_x_from_private_p521};
use crate::core::ecc_primitives::{P256_FIELD_BYTES, P521_FIELD_BYTES, algorithm_suite};
use crate::core::error::{Error, Result};
use crate::core::tag::Tag;
use crate::core::tlv::{Tlv, Value};

/// BER-TLV tag for Biometric Type (Table 42 row 1).
pub const TAG_BIOMETRIC_TYPE: u32 = 0x81;
/// BER-TLV tag for Biometric Solution ID (Table 42 row 2).
pub const TAG_BIOMETRIC_SOLUTION_ID: u32 = 0x90;
/// BER-TLV tag for Enciphered Biometric Data (Table 42 row 3).
pub const TAG_ENCIPHERED_BIOMETRIC_DATA: u32 = 0xDF51;

/// Recovered fields handed to the Biometric Processing Application
/// after a successful §13.5 deciphering. The §13.5 step 6/7/8 checks
/// (`UN_ODE`, Solution ID against tag `'90'`, Type against tag `'81'`)
/// have already passed; the caller compares the BDB against the
/// reference template.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveredBiometric {
    /// Biometric Subtype (Book 3 Table 50). 1 byte.
    pub subtype: u8,
    /// Biometric Data Block.
    pub bdb: Vec<u8>,
}

/// Build the §13.4 Biometric Verification Data Template value field
/// for ODE Algorithm Suite `'00'` (P-256 + DH + AES).
///
/// Returns the BVDT value bytes - a concatenation of three primitive
/// BER-TLV objects (`'81'` || `'90'` || `'DF51'`). The caller wraps
/// this in the VERIFY data field, splitting across chained commands
/// per Book 3 §6.5.13 if it exceeds 255 bytes.
///
/// Arguments:
///
/// - `un_ode` - 8-byte response to GET CHALLENGE (§13.4 step 2).
/// - `solution_id` - Biometric Solution ID (Book 3 Table 48). Length
///   must fit in one byte (≤ 255).
/// - `biometric_type` - Biometric Type (Book 3 Table 49). Length
///   must fit in one byte (≤ 255).
/// - `subtype` - Biometric Subtype (Book 3 Table 50).
/// - `bdb` - Biometric Data Block produced by the Biometric
///   Processing Application. Length must fit in two bytes (≤ 65535).
/// - `icc_ode_pk_x` - 32-byte x-coordinate of the ICC's ODE public
///   key, recovered from the ICC PK Cert for ODE (tag `'9F2D'`).
/// - `ephemeral_d` - 32-byte ephemeral private key (`1 ≤ d ≤ n-1`).
///   Caller-supplied for testability.
#[allow(clippy::too_many_arguments)]
pub fn enciphered_biometric_data_ecc_p256(
    un_ode: [u8; 8],
    solution_id: &[u8],
    biometric_type: &[u8],
    subtype: u8,
    bdb: &[u8],
    icc_ode_pk_x: &[u8; P256_FIELD_BYTES],
    ephemeral_d: &[u8; P256_FIELD_BYTES],
) -> Result<Vec<u8>> {
    if solution_id.len() > 0xFF || biometric_type.len() > 0xFF || bdb.len() > 0xFFFF {
        return Err(Error::InvalidValue);
    }
    let suite = algorithm_suite::ODE_P256_DH_AES;

    // §13.4 step 3a: ephemeral pair, R_x = x-coord of R.
    let r_x = public_key_x_from_private(ephemeral_d)?;

    // §13.4 step 3b: derive session keys with UN_KD = UN_ODE.
    let keys = derive_keys_p256(&un_ode, suite, ephemeral_d, icc_ode_pk_x)?;

    // §13.4 step 4: encrypt the Table 41 plaintext under (K_1, K_2).
    let plaintext = build_table_41(un_ode, solution_id, biometric_type, subtype, bdb);
    let (c, _) = encrypt_etm_p256(suite, &keys.k1, &keys.k2, &plaintext, &[], keys.counter)?;

    // §13.4 step 5: Enciphered Data := R_x || C.
    let mut enciphered_data = Vec::with_capacity(r_x.len() + c.len());
    enciphered_data.extend_from_slice(&r_x);
    enciphered_data.extend_from_slice(&c);

    // §13.4 step 6: BVDT (Table 42) - three primitive BER-TLVs in
    // order ('81', '90', 'DF51'). The spec note rules out '00'
    // padding before/between/after, which the encoder honors.
    let mut bvdt = Vec::new();
    bvdt.extend(Tlv::primitive(Tag(TAG_BIOMETRIC_TYPE), biometric_type.to_vec()).encode());
    bvdt.extend(Tlv::primitive(Tag(TAG_BIOMETRIC_SOLUTION_ID), solution_id.to_vec()).encode());
    bvdt.extend(Tlv::primitive(Tag(TAG_ENCIPHERED_BIOMETRIC_DATA), enciphered_data).encode());
    Ok(bvdt)
}

/// ICC-side §13.5 deciphering for ODE Algorithm Suite `'00'`.
///
/// Provided for symmetry / host-side round-tripping; a real ICC
/// implementation lives in card firmware. Returns the
/// [`RecoveredBiometric`] (Subtype + BDB) ready for the Biometric
/// Processing Application.
///
/// `bvdt_value` is the BVDT value-field bytes the ICC reassembles
/// from one or more chained VERIFY commands. The function performs
/// the §13.5 checks:
///
/// - Step 1: `|Enciphered Data| ≥ N_FIELD + 8 = 40`.
/// - Step 4 / §A2.3.4 step i: MAC verifies.
/// - Step 6: recovered UN equals `un_ode`.
/// - Step 7: recovered Solution ID equals BVDT tag `'90'`.
/// - Step 8: recovered Type equals BVDT tag `'81'`.
///
/// Errors with `InvalidValue` for any failed check or malformed
/// BVDT / Table 41 layout.
pub fn decipher_biometric_data_ecc_p256(
    bvdt_value: &[u8],
    un_ode: [u8; 8],
    icc_ode_private_key: &[u8; P256_FIELD_BYTES],
) -> Result<RecoveredBiometric> {
    let suite = algorithm_suite::ODE_P256_DH_AES;

    // Parse the three BER-TLV objects from BVDT.
    let mut tlvs = Tlv::parse_all(bvdt_value)?;
    let tag_81 = Tag(TAG_BIOMETRIC_TYPE);
    let tag_90 = Tag(TAG_BIOMETRIC_SOLUTION_ID);
    let tag_df51 = Tag(TAG_ENCIPHERED_BIOMETRIC_DATA);

    let bvdt_type = take_primitive(&mut tlvs, tag_81)?;
    let bvdt_solution_id = take_primitive(&mut tlvs, tag_90)?;
    let enciphered_data = take_primitive(&mut tlvs, tag_df51)?;

    // §13.5 step 1.
    if enciphered_data.len() < P256_FIELD_BYTES + 8 {
        return Err(Error::InvalidValue);
    }

    // §13.5 step 2: extract R_x and C.
    let r_x: [u8; P256_FIELD_BYTES] = enciphered_data[..P256_FIELD_BYTES]
        .try_into()
        .map_err(|_| Error::InvalidValue)?;
    let c = &enciphered_data[P256_FIELD_BYTES..];

    // §13.5 step 3: derive session keys with d = ICC private, Q = R.
    let keys = derive_keys_p256(&un_ode, suite, icc_ode_private_key, &r_x)?;

    // §13.5 step 4: decrypt under (K_1, K_2) with A = null.
    let (plaintext, _) = decrypt_etm_p256(suite, &keys.k1, &keys.k2, c, &[], keys.counter)?;

    // §13.5 steps 6-8: parse Table 41 and run the field checks.
    let parsed = parse_table_41(&plaintext)?;
    if parsed.un != un_ode {
        return Err(Error::InvalidValue);
    }
    if parsed.solution_id != bvdt_solution_id {
        return Err(Error::InvalidValue);
    }
    if parsed.biometric_type != bvdt_type {
        return Err(Error::InvalidValue);
    }

    Ok(RecoveredBiometric {
        subtype: parsed.subtype,
        bdb: parsed.bdb,
    })
}

// ── Table 41 plaintext encoding / decoding ───────────────────────────

fn build_table_41(
    un_ode: [u8; 8],
    solution_id: &[u8],
    biometric_type: &[u8],
    subtype: u8,
    bdb: &[u8],
) -> Vec<u8> {
    // Lengths already validated by the public API.
    debug_assert!(solution_id.len() <= 0xFF);
    debug_assert!(biometric_type.len() <= 0xFF);
    debug_assert!(bdb.len() <= 0xFFFF);

    let mut out = Vec::with_capacity(
        8 + 1 + solution_id.len() + 1 + biometric_type.len() + 1 + 2 + bdb.len(),
    );
    out.extend_from_slice(&un_ode);
    out.push(solution_id.len() as u8);
    out.extend_from_slice(solution_id);
    out.push(biometric_type.len() as u8);
    out.extend_from_slice(biometric_type);
    out.push(subtype);
    out.extend_from_slice(&(bdb.len() as u16).to_be_bytes());
    out.extend_from_slice(bdb);
    out
}

struct ParsedTable41 {
    un: [u8; 8],
    solution_id: Vec<u8>,
    biometric_type: Vec<u8>,
    subtype: u8,
    bdb: Vec<u8>,
}

fn parse_table_41(data: &[u8]) -> Result<ParsedTable41> {
    let mut i = 0;
    if data.len() < 8 {
        return Err(Error::InvalidValue);
    }
    let un: [u8; 8] = data[0..8].try_into().map_err(|_| Error::InvalidValue)?;
    i += 8;

    let sol_id_len = read_u8(data, &mut i)? as usize;
    let solution_id = read_n(data, &mut i, sol_id_len)?;
    let type_len = read_u8(data, &mut i)? as usize;
    let biometric_type = read_n(data, &mut i, type_len)?;
    let subtype = read_u8(data, &mut i)?;
    let bdb_len = read_u16_be(data, &mut i)? as usize;
    let bdb = read_n(data, &mut i, bdb_len)?;

    if i != data.len() {
        return Err(Error::InvalidValue);
    }

    Ok(ParsedTable41 {
        un,
        solution_id,
        biometric_type,
        subtype,
        bdb,
    })
}

fn read_u8(data: &[u8], i: &mut usize) -> Result<u8> {
    let b = *data.get(*i).ok_or(Error::InvalidValue)?;
    *i += 1;
    Ok(b)
}

fn read_u16_be(data: &[u8], i: &mut usize) -> Result<u16> {
    if *i + 2 > data.len() {
        return Err(Error::InvalidValue);
    }
    let v = u16::from_be_bytes([data[*i], data[*i + 1]]);
    *i += 2;
    Ok(v)
}

fn read_n(data: &[u8], i: &mut usize, n: usize) -> Result<Vec<u8>> {
    if *i + n > data.len() {
        return Err(Error::InvalidValue);
    }
    let out = data[*i..*i + n].to_vec();
    *i += n;
    Ok(out)
}

/// Pop the first TLV with `tag` from `tlvs`, returning its primitive
/// bytes. Errors if the tag is missing or its value is constructed.
fn take_primitive(tlvs: &mut Vec<Tlv>, tag: Tag) -> Result<Vec<u8>> {
    let pos = tlvs
        .iter()
        .position(|t| t.tag() == tag)
        .ok_or(Error::InvalidValue)?;
    let tlv = tlvs.remove(pos);
    match tlv.value() {
        Value::Primitive(b) => Ok(b.clone()),
        Value::Constructed(_) => Err(Error::InvalidValue),
    }
}

// ── P-521 (Suite '01') variants ──────────────────────────────────────

/// Suite-`'01'` (P-521 + DH + AES) variant of
/// [`enciphered_biometric_data_ecc_p256`]. Same BVDT layout
/// (Table 42), but `'DF51'` carries 66-byte `R_x` plus the §A2.3
/// ciphertext.
#[allow(clippy::too_many_arguments)]
pub fn enciphered_biometric_data_ecc_p521(
    un_ode: [u8; 8],
    solution_id: &[u8],
    biometric_type: &[u8],
    subtype: u8,
    bdb: &[u8],
    icc_ode_pk_x: &[u8; P521_FIELD_BYTES],
    ephemeral_d: &[u8; P521_FIELD_BYTES],
) -> Result<Vec<u8>> {
    if solution_id.len() > 0xFF || biometric_type.len() > 0xFF || bdb.len() > 0xFFFF {
        return Err(Error::InvalidValue);
    }
    let suite = algorithm_suite::ODE_P521_DH_AES;

    let r_x = public_key_x_from_private_p521(ephemeral_d)?;
    let keys = derive_keys_p521(&un_ode, suite, ephemeral_d, icc_ode_pk_x)?;

    // Table 41 plaintext is curve-independent.
    let plaintext = build_table_41(un_ode, solution_id, biometric_type, subtype, bdb);
    let (c, _) = encrypt_etm_p521(suite, &keys.k1, &keys.k2, &plaintext, &[], keys.counter)?;

    let mut enciphered_data = Vec::with_capacity(r_x.len() + c.len());
    enciphered_data.extend_from_slice(&r_x);
    enciphered_data.extend_from_slice(&c);

    let mut bvdt = Vec::new();
    bvdt.extend(Tlv::primitive(Tag(TAG_BIOMETRIC_TYPE), biometric_type.to_vec()).encode());
    bvdt.extend(Tlv::primitive(Tag(TAG_BIOMETRIC_SOLUTION_ID), solution_id.to_vec()).encode());
    bvdt.extend(Tlv::primitive(Tag(TAG_ENCIPHERED_BIOMETRIC_DATA), enciphered_data).encode());
    Ok(bvdt)
}

/// Suite-`'01'` variant of [`decipher_biometric_data_ecc_p256`].
pub fn decipher_biometric_data_ecc_p521(
    bvdt_value: &[u8],
    un_ode: [u8; 8],
    icc_ode_private_key: &[u8; P521_FIELD_BYTES],
) -> Result<RecoveredBiometric> {
    let suite = algorithm_suite::ODE_P521_DH_AES;

    let mut tlvs = Tlv::parse_all(bvdt_value)?;
    let tag_81 = Tag(TAG_BIOMETRIC_TYPE);
    let tag_90 = Tag(TAG_BIOMETRIC_SOLUTION_ID);
    let tag_df51 = Tag(TAG_ENCIPHERED_BIOMETRIC_DATA);

    let bvdt_type = take_primitive(&mut tlvs, tag_81)?;
    let bvdt_solution_id = take_primitive(&mut tlvs, tag_90)?;
    let enciphered_data = take_primitive(&mut tlvs, tag_df51)?;

    // §13.5 step 1.
    if enciphered_data.len() < P521_FIELD_BYTES + 8 {
        return Err(Error::InvalidValue);
    }

    let r_x: [u8; P521_FIELD_BYTES] = enciphered_data[..P521_FIELD_BYTES]
        .try_into()
        .map_err(|_| Error::InvalidValue)?;
    let c = &enciphered_data[P521_FIELD_BYTES..];

    let keys = derive_keys_p521(&un_ode, suite, icc_ode_private_key, &r_x)?;
    let (plaintext, _) = decrypt_etm_p521(suite, &keys.k1, &keys.k2, c, &[], keys.counter)?;

    let parsed = parse_table_41(&plaintext)?;
    if parsed.un != un_ode {
        return Err(Error::InvalidValue);
    }
    if parsed.solution_id != bvdt_solution_id {
        return Err(Error::InvalidValue);
    }
    if parsed.biometric_type != bvdt_type {
        return Err(Error::InvalidValue);
    }

    Ok(RecoveredBiometric {
        subtype: parsed.subtype,
        bdb: parsed.bdb,
    })
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
        constrain_long_term_private_key_p256(&h32(
            "c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721",
        ))
        .unwrap()
    }

    fn ephemeral_d() -> [u8; 32] {
        constrain_long_term_private_key_p256(&h32(
            "a6e3c57dd01abe90086538398355dd4c3b17aa873382b0f24d6129493d8aad60",
        ))
        .unwrap()
    }

    // ── Table 41 round-trip ──────────────────────────────────────────

    #[test]
    fn table_41_round_trip() {
        let un = [0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF];
        let sol_id = b"FAC".to_vec();
        let bio_type = b"FACE".to_vec();
        let bdb = vec![0xAAu8; 100];
        let encoded = build_table_41(un, &sol_id, &bio_type, 0x05, &bdb);
        let parsed = parse_table_41(&encoded).unwrap();
        assert_eq!(parsed.un, un);
        assert_eq!(parsed.solution_id, sol_id);
        assert_eq!(parsed.biometric_type, bio_type);
        assert_eq!(parsed.subtype, 0x05);
        assert_eq!(parsed.bdb, bdb);
    }

    #[test]
    fn table_41_round_trip_empty_fields() {
        // Solution ID, Type, BDB all empty - minimum is 8+1+1+1+2 = 13.
        let un = [0u8; 8];
        let encoded = build_table_41(un, &[], &[], 0, &[]);
        assert_eq!(encoded.len(), 13);
        let parsed = parse_table_41(&encoded).unwrap();
        assert!(parsed.solution_id.is_empty());
        assert!(parsed.biometric_type.is_empty());
        assert!(parsed.bdb.is_empty());
    }

    #[test]
    fn table_41_parse_rejects_truncated() {
        // 8-byte UN only - no length bytes.
        assert!(parse_table_41(&[0u8; 8]).is_err());
        // Sol ID length says 5 but no Sol ID bytes follow.
        let mut bad = vec![0u8; 8];
        bad.push(5); // sol_id_len
        assert!(parse_table_41(&bad).is_err());
    }

    #[test]
    fn table_41_parse_rejects_trailing_bytes() {
        let un = [0u8; 8];
        let mut encoded = build_table_41(un, &[], &[], 0, &[]);
        encoded.push(0x99); // junk
        assert!(parse_table_41(&encoded).is_err());
    }

    // ── BVDT (Table 42) layout ───────────────────────────────────────

    #[test]
    fn bvdt_contains_three_tlvs_in_order() {
        let icc_q = public_key_x_from_private(&icc_ode_private_key()).unwrap();
        let bvdt = enciphered_biometric_data_ecc_p256(
            [0u8; 8],
            b"FAC",
            b"FACE",
            0,
            &[0xAAu8; 32],
            &icc_q,
            &ephemeral_d(),
        )
        .unwrap();

        let parsed = Tlv::parse_all(&bvdt).unwrap();
        assert_eq!(parsed.len(), 3);
        assert_eq!(parsed[0].tag(), Tag(TAG_BIOMETRIC_TYPE));
        assert_eq!(parsed[1].tag(), Tag(TAG_BIOMETRIC_SOLUTION_ID));
        assert_eq!(parsed[2].tag(), Tag(TAG_ENCIPHERED_BIOMETRIC_DATA));

        // Type and Solution ID values match the inputs (plaintext in BVDT).
        assert_eq!(parsed[0].value().as_primitive().unwrap(), b"FACE");
        assert_eq!(parsed[1].value().as_primitive().unwrap(), b"FAC");

        // Enciphered Data length: R_x (32) + C* (Table 41 plaintext
        // length = 8 + 1 + 3 + 1 + 4 + 1 + 2 + 32 = 52 bytes) + MAC (8).
        let enc = parsed[2].value().as_primitive().unwrap();
        assert_eq!(enc.len(), 32 + 52 + 8);
    }

    // ── End-to-end encrypt/decrypt round-trip ────────────────────────

    #[test]
    fn end_to_end_terminal_then_icc_round_trip() {
        let icc_d = icc_ode_private_key();
        let icc_q = public_key_x_from_private(&icc_d).unwrap();
        let un = [0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF];
        let sol_id = b"FAC";
        let bio_type = b"FACE";
        let subtype = 0x07;
        let bdb = (0u8..200).collect::<Vec<_>>();

        let bvdt = enciphered_biometric_data_ecc_p256(
            un,
            sol_id,
            bio_type,
            subtype,
            &bdb,
            &icc_q,
            &ephemeral_d(),
        )
        .unwrap();

        let recovered = decipher_biometric_data_ecc_p256(&bvdt, un, &icc_d).unwrap();
        assert_eq!(recovered.subtype, subtype);
        assert_eq!(recovered.bdb, bdb);
    }

    #[test]
    fn end_to_end_round_trip_with_empty_bdb() {
        // §13.4 doesn't forbid empty BDB; a Subtype-only verification
        // is rare but allowed.
        let icc_d = icc_ode_private_key();
        let icc_q = public_key_x_from_private(&icc_d).unwrap();
        let bvdt = enciphered_biometric_data_ecc_p256(
            [0u8; 8],
            b"X",
            b"Y",
            0x42,
            &[],
            &icc_q,
            &ephemeral_d(),
        )
        .unwrap();
        let recovered = decipher_biometric_data_ecc_p256(&bvdt, [0u8; 8], &icc_d).unwrap();
        assert_eq!(recovered.subtype, 0x42);
        assert!(recovered.bdb.is_empty());
    }

    #[test]
    fn end_to_end_round_trip_large_bdb() {
        // A 1024-byte BDB exercises the multi-block CTR path and the
        // 2-byte BDB-Length encoding (>255).
        let icc_d = icc_ode_private_key();
        let icc_q = public_key_x_from_private(&icc_d).unwrap();
        let bdb: Vec<u8> = (0..1024).map(|i| (i % 251) as u8).collect();
        let bvdt = enciphered_biometric_data_ecc_p256(
            [0u8; 8],
            b"FAC",
            b"FACE",
            0,
            &bdb,
            &icc_q,
            &ephemeral_d(),
        )
        .unwrap();
        let recovered = decipher_biometric_data_ecc_p256(&bvdt, [0u8; 8], &icc_d).unwrap();
        assert_eq!(recovered.bdb, bdb);
    }

    #[test]
    fn end_to_end_distinct_ephemerals_distinct_outputs() {
        let icc_q = public_key_x_from_private(&icc_ode_private_key()).unwrap();
        let d1 = ephemeral_d();
        let d2 = constrain_long_term_private_key_p256(&h32(
            "1111111111111111111111111111111111111111111111111111111111111111",
        ))
        .unwrap();
        let bvdt1 =
            enciphered_biometric_data_ecc_p256([0u8; 8], b"X", b"Y", 0, &[1, 2, 3], &icc_q, &d1)
                .unwrap();
        let bvdt2 =
            enciphered_biometric_data_ecc_p256([0u8; 8], b"X", b"Y", 0, &[1, 2, 3], &icc_q, &d2)
                .unwrap();
        assert_ne!(bvdt1, bvdt2);
    }

    // ── §13.5 step-6/7/8 rejections ──────────────────────────────────

    #[test]
    fn icc_decipher_rejects_un_mismatch() {
        let icc_d = icc_ode_private_key();
        let icc_q = public_key_x_from_private(&icc_d).unwrap();
        let un_signed = [0x01u8; 8];
        let un_other = [0x02u8; 8];
        let bvdt = enciphered_biometric_data_ecc_p256(
            un_signed,
            b"X",
            b"Y",
            0,
            &[],
            &icc_q,
            &ephemeral_d(),
        )
        .unwrap();
        // The wrong UN both flips SV (MAC fails) and would fail the
        // §13.5 step 6 check - either way, error.
        assert!(decipher_biometric_data_ecc_p256(&bvdt, un_other, &icc_d).is_err());
    }

    #[test]
    fn icc_decipher_rejects_tampered_bvdt_solution_id() {
        // §13.5 step 7: BVDT '90' must equal recovered Solution ID.
        // Construct a malformed BVDT where '90' has a wrong value.
        let icc_d = icc_ode_private_key();
        let icc_q = public_key_x_from_private(&icc_d).unwrap();
        let un = [0u8; 8];

        // Build legitimate BVDT.
        let bvdt = enciphered_biometric_data_ecc_p256(
            un,
            b"FAC",
            b"FACE",
            0,
            &[0xAAu8; 32],
            &icc_q,
            &ephemeral_d(),
        )
        .unwrap();

        // Mutate: replace the '90' value bytes (3 bytes "FAC" → "BAD").
        // Find the '90' TLV and rewrite its value.
        let mut tlvs = Tlv::parse_all(&bvdt).unwrap();
        let pos = tlvs
            .iter()
            .position(|t| t.tag() == Tag(TAG_BIOMETRIC_SOLUTION_ID))
            .unwrap();
        tlvs[pos] = Tlv::primitive(Tag(TAG_BIOMETRIC_SOLUTION_ID), b"BAD".to_vec());
        let tampered: Vec<u8> = tlvs.into_iter().flat_map(|t| t.encode()).collect();

        assert!(decipher_biometric_data_ecc_p256(&tampered, un, &icc_d).is_err());
    }

    #[test]
    fn icc_decipher_rejects_tampered_bvdt_type() {
        // §13.5 step 8: BVDT '81' must equal recovered Type.
        let icc_d = icc_ode_private_key();
        let icc_q = public_key_x_from_private(&icc_d).unwrap();
        let un = [0u8; 8];
        let bvdt = enciphered_biometric_data_ecc_p256(
            un,
            b"FAC",
            b"FACE",
            0,
            &[0xAAu8; 32],
            &icc_q,
            &ephemeral_d(),
        )
        .unwrap();

        let mut tlvs = Tlv::parse_all(&bvdt).unwrap();
        let pos = tlvs
            .iter()
            .position(|t| t.tag() == Tag(TAG_BIOMETRIC_TYPE))
            .unwrap();
        tlvs[pos] = Tlv::primitive(Tag(TAG_BIOMETRIC_TYPE), b"FINGER".to_vec());
        let tampered: Vec<u8> = tlvs.into_iter().flat_map(|t| t.encode()).collect();

        assert!(decipher_biometric_data_ecc_p256(&tampered, un, &icc_d).is_err());
    }

    #[test]
    fn icc_decipher_rejects_tampered_ciphertext() {
        let icc_d = icc_ode_private_key();
        let icc_q = public_key_x_from_private(&icc_d).unwrap();
        let un = [0u8; 8];
        let mut bvdt = enciphered_biometric_data_ecc_p256(
            un,
            b"FAC",
            b"FACE",
            0,
            &[0xAAu8; 32],
            &icc_q,
            &ephemeral_d(),
        )
        .unwrap();
        // Flip a bit somewhere in the middle (inside the 'DF51' value).
        let len = bvdt.len();
        bvdt[len - 20] ^= 0x01;
        assert!(decipher_biometric_data_ecc_p256(&bvdt, un, &icc_d).is_err());
    }

    #[test]
    fn icc_decipher_rejects_missing_bvdt_tag() {
        // No '81' / '90' / 'DF51' at all.
        let icc_d = icc_ode_private_key();
        assert!(decipher_biometric_data_ecc_p256(&[], [0u8; 8], &icc_d).is_err());
    }

    #[test]
    fn icc_decipher_rejects_short_enciphered_data() {
        // Build a malformed BVDT where 'DF51' is too short.
        let mut bvdt = Vec::new();
        bvdt.extend(Tlv::primitive(Tag(TAG_BIOMETRIC_TYPE), b"FACE".to_vec()).encode());
        bvdt.extend(Tlv::primitive(Tag(TAG_BIOMETRIC_SOLUTION_ID), b"FAC".to_vec()).encode());
        bvdt.extend(Tlv::primitive(Tag(TAG_ENCIPHERED_BIOMETRIC_DATA), vec![0u8; 39]).encode());
        let icc_d = icc_ode_private_key();
        assert!(decipher_biometric_data_ecc_p256(&bvdt, [0u8; 8], &icc_d).is_err());
    }

    // ── Length-bound rejections on the encipher side ─────────────────

    #[test]
    fn encipher_rejects_oversized_solution_id() {
        let icc_q = public_key_x_from_private(&icc_ode_private_key()).unwrap();
        let big = vec![0u8; 256]; // Sol-ID-Length is 1 byte → max 255
        assert!(
            enciphered_biometric_data_ecc_p256(
                [0u8; 8],
                &big,
                b"Y",
                0,
                &[],
                &icc_q,
                &ephemeral_d(),
            )
            .is_err()
        );
    }

    #[test]
    fn encipher_rejects_oversized_biometric_type() {
        let icc_q = public_key_x_from_private(&icc_ode_private_key()).unwrap();
        let big = vec![0u8; 256];
        assert!(
            enciphered_biometric_data_ecc_p256(
                [0u8; 8],
                b"X",
                &big,
                0,
                &[],
                &icc_q,
                &ephemeral_d(),
            )
            .is_err()
        );
    }

    #[test]
    fn encipher_rejects_oversized_bdb() {
        let icc_q = public_key_x_from_private(&icc_ode_private_key()).unwrap();
        let big = vec![0u8; 0x10000]; // BDB-Length is 2 bytes → max 65535
        assert!(
            enciphered_biometric_data_ecc_p256(
                [0u8; 8],
                b"X",
                b"Y",
                0,
                &big,
                &icc_q,
                &ephemeral_d(),
            )
            .is_err()
        );
    }

    #[test]
    fn encipher_accepts_max_lengths() {
        // Boundary check: 255-byte Solution ID and Type, and a BDB
        // that fits in 2 bytes.
        let icc_d = icc_ode_private_key();
        let icc_q = public_key_x_from_private(&icc_d).unwrap();
        let sol = vec![0xAAu8; 255];
        let typ = vec![0xBBu8; 255];
        let bdb = vec![0xCCu8; 1000];
        let bvdt = enciphered_biometric_data_ecc_p256(
            [0u8; 8],
            &sol,
            &typ,
            0,
            &bdb,
            &icc_q,
            &ephemeral_d(),
        )
        .unwrap();
        let rec = decipher_biometric_data_ecc_p256(&bvdt, [0u8; 8], &icc_d).unwrap();
        assert_eq!(rec.bdb, bdb);
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
    fn p521_bvdt_layout() {
        let icc_q = public_key_x_from_private_p521(&icc_ode_private_key_p521()).unwrap();
        let bvdt = enciphered_biometric_data_ecc_p521(
            [0u8; 8],
            b"FAC",
            b"FACE",
            0,
            &[0xAAu8; 32],
            &icc_q,
            &ephemeral_d_p521(),
        )
        .unwrap();

        let parsed = Tlv::parse_all(&bvdt).unwrap();
        assert_eq!(parsed.len(), 3);
        assert_eq!(parsed[0].tag(), Tag(TAG_BIOMETRIC_TYPE));
        assert_eq!(parsed[1].tag(), Tag(TAG_BIOMETRIC_SOLUTION_ID));
        assert_eq!(parsed[2].tag(), Tag(TAG_ENCIPHERED_BIOMETRIC_DATA));

        // Enciphered Data length: R_x (66) + Table 41 (52) + MAC (8).
        let enc = parsed[2].value().as_primitive().unwrap();
        assert_eq!(enc.len(), 66 + 52 + 8);
    }

    #[test]
    fn p521_end_to_end_round_trip() {
        let icc_d = icc_ode_private_key_p521();
        let icc_q = public_key_x_from_private_p521(&icc_d).unwrap();
        let un = [0x01u8; 8];
        let sol_id = b"FAC";
        let bio_type = b"FACE";
        let subtype = 0x07;
        let bdb = (0u8..200).collect::<Vec<_>>();
        let bvdt = enciphered_biometric_data_ecc_p521(
            un,
            sol_id,
            bio_type,
            subtype,
            &bdb,
            &icc_q,
            &ephemeral_d_p521(),
        )
        .unwrap();
        let recovered = decipher_biometric_data_ecc_p521(&bvdt, un, &icc_d).unwrap();
        assert_eq!(recovered.subtype, subtype);
        assert_eq!(recovered.bdb, bdb);
    }

    #[test]
    fn p521_decipher_rejects_tampered_ciphertext() {
        let icc_d = icc_ode_private_key_p521();
        let icc_q = public_key_x_from_private_p521(&icc_d).unwrap();
        let mut bvdt = enciphered_biometric_data_ecc_p521(
            [0u8; 8],
            b"X",
            b"Y",
            0,
            &[0xAAu8; 32],
            &icc_q,
            &ephemeral_d_p521(),
        )
        .unwrap();
        let len = bvdt.len();
        bvdt[len - 20] ^= 0x01;
        assert!(decipher_biometric_data_ecc_p521(&bvdt, [0u8; 8], &icc_d).is_err());
    }

    #[test]
    fn p521_decipher_rejects_un_mismatch() {
        let icc_d = icc_ode_private_key_p521();
        let icc_q = public_key_x_from_private_p521(&icc_d).unwrap();
        let bvdt = enciphered_biometric_data_ecc_p521(
            [0x01u8; 8],
            b"X",
            b"Y",
            0,
            &[],
            &icc_q,
            &ephemeral_d_p521(),
        )
        .unwrap();
        assert!(decipher_biometric_data_ecc_p521(&bvdt, [0x02u8; 8], &icc_d).is_err());
    }
}
