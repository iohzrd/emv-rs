//! Book 2 §12 - ECC Offline Data Authentication (XDA).

use crate::core::compressed_numeric;
use crate::core::ec_sdsa::{ec_sdsa_p256_verify, ec_sdsa_p521_verify};
use crate::core::ecc_primitives::{
    P256_FIELD_BYTES, P521_FIELD_BYTES, algorithm_suite, hash_algorithm, hash_for_ecc,
    recover_y_p256, recover_y_p521,
};
use crate::core::error::{Error, Result};

/// Curve / hash / signature byte-lengths for an Algorithm Suite per
/// Table 48 / 47. Returns `(N_FIELD, N_HASH, N_SIG)`.
///
/// `N_SIG = N_HASH + N_FIELD` for EC-SDSA per §A2.2.2 step f.
fn suite_lengths(suite: u8) -> Result<(usize, usize, usize)> {
    match suite {
        algorithm_suite::SIGNATURE_EC_SDSA_SHA256_P256 => Ok((32, 32, 64)),
        algorithm_suite::SIGNATURE_EC_SDSA_SHA512_P521 => Ok((66, 64, 130)),
        _ => Err(Error::InvalidValue),
    }
}

/// Dispatch EC-SDSA verification to the right curve primitive based
/// on the Algorithm Suite Indicator. The x-coordinate's length must
/// match the suite's `N_FIELD`; otherwise returns `InvalidValue`.
fn verify_ec_sdsa(suite: u8, x_coord: &[u8], message: &[u8], signature: &[u8]) -> Result<bool> {
    match suite {
        algorithm_suite::SIGNATURE_EC_SDSA_SHA256_P256 => {
            let x: [u8; P256_FIELD_BYTES] = x_coord.try_into().map_err(|_| Error::InvalidValue)?;
            ec_sdsa_p256_verify(suite, &x, message, signature)
        }
        algorithm_suite::SIGNATURE_EC_SDSA_SHA512_P521 => {
            let x: [u8; P521_FIELD_BYTES] = x_coord.try_into().map_err(|_| Error::InvalidValue)?;
            ec_sdsa_p521_verify(suite, &x, message, signature)
        }
        _ => Err(Error::InvalidValue),
    }
}

/// Dispatch x-coordinate y-recovery (sanity check that `x` is on the
/// curve) based on suite.
fn validate_x_on_curve(suite: u8, x_coord: &[u8]) -> Result<()> {
    match suite {
        algorithm_suite::SIGNATURE_EC_SDSA_SHA256_P256 => {
            let x: [u8; P256_FIELD_BYTES] = x_coord.try_into().map_err(|_| Error::InvalidValue)?;
            let _ = recover_y_p256(&x)?;
            Ok(())
        }
        algorithm_suite::SIGNATURE_EC_SDSA_SHA512_P521 => {
            let x: [u8; P521_FIELD_BYTES] = x_coord.try_into().map_err(|_| Error::InvalidValue)?;
            let _ = recover_y_p521(&x)?;
            Ok(())
        }
        _ => Err(Error::InvalidValue),
    }
}

// ── Types ────────────────────────────────────────────────────────────

/// Certification Authority ECC public key entry stored on the
/// terminal, indexed by RID + CA Public Key Index.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EccCaPublicKey {
    /// 5-byte AID prefix.
    pub rid: [u8; 5],
    /// `'8F'` value disambiguating CA keys for this RID.
    pub index: u8,
    /// X-coordinate of the CA public key point (length per
    /// `algorithm_suite`'s N_FIELD; 32 bytes for P-256).
    pub x_coord: Vec<u8>,
    /// Algorithm Suite Indicator per §B2.4.1 (Table 48). Determines
    /// curve, hash, and signature length used when verifying Issuer
    /// PK Certificates signed by this CA.
    pub algorithm_suite: u8,
}

/// Issuer ECC public key recovered from an Issuer PK Certificate
/// (Table 35).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EccIssuerPublicKey {
    /// X-coordinate of the Issuer PK point.
    pub x_coord: Vec<u8>,
    /// Algorithm Suite Indicator for the Issuer PK (cert field 4).
    /// Determines the curve / hash / sig sizes used when verifying
    /// ICC PK Certificates signed by this Issuer.
    pub algorithm_suite: u8,
    /// Issuer Identifier - leftmost 3-10 PAN digits, F-padded to 5
    /// bytes.
    pub issuer_identifier: [u8; 5],
    /// Certificate Expiration Date YYYYMMDD UTC (BCD).
    pub expiration_yyyymmdd: [u8; 4],
    /// Certificate Serial Number assigned by the CA (3 bytes), the
    /// value to look up in a Certificate Revocation List per §12.1.1.
    pub serial_number: [u8; 3],
}

/// ICC ECC public key recovered from an ICC PK Certificate
/// (Table 36).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EccIccPublicKey {
    /// X-coordinate of the ICC PK point.
    pub x_coord: Vec<u8>,
    /// Algorithm Suite Indicator (cert field 3) - XDA suite for
    /// `'9F46'`, ODE suite for `'9F2D'`.
    pub algorithm_suite: u8,
    /// Certificate Expiration Date YYYYMMDD UTC (BCD).
    pub expiration_yyyymmdd: [u8; 4],
    /// Certificate Expiration Time HHMM UTC (BCD).
    pub expiration_hhmm: [u8; 2],
    /// Certificate Serial Number (6 bytes).
    pub serial_number: [u8; 6],
    /// ICCD Hash Algorithm Indicator (cert field 8) - per §B2.3.
    pub iccd_hash_algorithm: u8,
}

// ── Issuer PK Certificate (§12.3 / Table 35) ─────────────────────────

/// Recover the Issuer ECC Public Key from its certificate per Book 2
/// §12.3 (Table 35).
///
/// Performs §12.3 numbered steps 1-6 + 8-12 (skipping the optional
/// CRL check in step 7 - see [`crate::core::crl::is_revoked`]).
///
/// Layout of `issuer_pk_cert` (cert is in plaintext on the wire - no
/// outer signature recovery, since EMV ECC certs concatenate the
/// signed data with the signature rather than wrapping per ISO 9796):
///
/// ```text
///   [1] Issuer Cert Format       1 byte    '12'
///   [2] Issuer Cert Encoding     1 byte    '00'
///   [3] Issuer Identifier        5 bytes   leftmost 3-10 PAN digits, F-padded
///   [4] Issuer PK Suite Indicator 1 byte
///   [5] Issuer Cert Expiration   4 bytes   YYYYMMDD UTC
///   [6] Issuer Cert Serial       3 bytes
///   [7] RID                      5 bytes
///   [8] CA PK Index              1 byte
///   [9] Issuer Public Key x      N_FIELD bytes (per suite [4])
///   [10] Issuer PK Cert Sig      N_SIG bytes (per CA's suite)
/// ```
///
/// The signature in field \[10\] is EC-SDSA over the concatenation of
/// fields \[1..9\] using the CA's algorithm suite (in `ca_pk`).
pub fn recover_issuer_public_key_ecc(
    ca_pk: &EccCaPublicKey,
    issuer_pk_cert: &[u8],
    pan: &[u8],
    today_yyyymmdd: [u8; 4],
) -> Result<EccIssuerPublicKey> {
    let (_n_field_ca, _n_hash_ca, n_sig_ca) = suite_lengths(ca_pk.algorithm_suite)?;

    // Step 1: minimum length 21 (header + signature is at least 21
    // before the variable-length issuer pk x-coord).
    if issuer_pk_cert.len() < 21 {
        return Err(Error::InvalidValue);
    }
    // Step 2: format byte = '12'.
    if issuer_pk_cert[0] != 0x12 {
        return Err(Error::InvalidValue);
    }
    // Step 3: encoding byte = '00'.
    if issuer_pk_cert[1] != 0x00 {
        return Err(Error::InvalidValue);
    }

    let issuer_identifier: [u8; 5] = issuer_pk_cert[2..7].try_into().unwrap();
    let issuer_pk_suite = issuer_pk_cert[7];
    let expiration_yyyymmdd: [u8; 4] = issuer_pk_cert[8..12].try_into().unwrap();
    let serial_number: [u8; 3] = issuer_pk_cert[12..15].try_into().unwrap();
    let cert_rid: [u8; 5] = issuer_pk_cert[15..20].try_into().unwrap();
    let cert_ca_index = issuer_pk_cert[20];

    // Step 4: Issuer Identifier prefix-matches PAN's leftmost 3-10
    // digits.
    if !issuer_identifier_matches_pan_ecc(&issuer_identifier, pan) {
        return Err(Error::InvalidValue);
    }
    // Step 5: expiration date in or after today (YYYYMMDD lexicographic).
    if !yyyymmdd_not_expired(expiration_yyyymmdd, today_yyyymmdd) {
        return Err(Error::InvalidValue);
    }
    // Step 6: RID / CA PK Index match.
    if cert_rid != ca_pk.rid || cert_ca_index != ca_pk.index {
        return Err(Error::InvalidValue);
    }
    // Step 8: Issuer PK suite is recognised.
    let (n_field_issuer, _n_hash_issuer, _n_sig_issuer) = suite_lengths(issuer_pk_suite)?;

    // Step 9: total length match.
    let expected_len = 21 + n_field_issuer + n_sig_ca;
    if issuer_pk_cert.len() != expected_len {
        return Err(Error::InvalidValue);
    }

    let issuer_pk_x = &issuer_pk_cert[21..21 + n_field_issuer];
    let signature = &issuer_pk_cert[21 + n_field_issuer..];
    debug_assert_eq!(signature.len(), n_sig_ca);

    // Steps 10-11: verify EC-SDSA signature over the first 9 fields
    // (= bytes [0..21 + n_field_issuer]) using the CA public key.
    let signed_data = &issuer_pk_cert[..21 + n_field_issuer];
    let ok = verify_ec_sdsa(
        ca_pk.algorithm_suite,
        &ca_pk.x_coord,
        signed_data,
        signature,
    )?;
    if !ok {
        return Err(Error::InvalidValue);
    }

    // Step 12: y-recovery is implicit - caller can recover y from
    // the stored x via [`recover_y_p256`] / [`recover_y_p521`] when
    // needed. Validate now that the x is on the curve.
    validate_x_on_curve(issuer_pk_suite, issuer_pk_x)?;

    Ok(EccIssuerPublicKey {
        x_coord: issuer_pk_x.to_vec(),
        algorithm_suite: issuer_pk_suite,
        issuer_identifier,
        expiration_yyyymmdd,
        serial_number,
    })
}

// ── ICC PK Certificate (§12.4 / Table 36) ────────────────────────────

/// Recover the ICC ECC Public Key from its certificate per Book 2
/// §12.4 (Table 36).
///
/// Layout of `icc_pk_cert`:
///
/// ```text
///   [1]  ICC Cert Format         1 byte    '14'
///   [2]  ICC Cert Encoding       1 byte    '00'
///   [3]  ICC PK Suite Indicator  1 byte
///   [4]  ICC Cert Expiration     4 bytes   YYYYMMDD UTC
///   [5]  ICC Cert Expiration Time 2 bytes  HHMM UTC
///   [6]  ICC Cert Serial         6 bytes
///   [7]  ICCD Hash Encoding      1 byte    '00'
///   [8]  ICCD Hash Alg Indicator 1 byte
///   [9]  ICCD Hash               N_HASH bytes (per [8])
///   [10] ICC Public Key x        N_FIELD bytes (per [3])
///   [11] ICC PK Cert Signature   N_SIG bytes (per Issuer's suite)
/// ```
///
/// `static_data` is the Issuer Certified Card Data (ICCD) from
/// Book 3 §10.3 - the concatenation of AFL records, the AIP TLV,
/// the AID TLV, and the PDOL TLV per §12.4 "ICCD Hash" bullet. The
/// terminal recomputes the hash and checks it matches field 9 of
/// the certificate.
pub fn recover_icc_public_key_ecc(
    issuer_pk: &EccIssuerPublicKey,
    icc_pk_cert: &[u8],
    static_data: &[u8],
    today_yyyymmdd: [u8; 4],
    now_hhmm: [u8; 2],
) -> Result<EccIccPublicKey> {
    let (_n_field_issuer, _n_hash_issuer, n_sig_issuer) = suite_lengths(issuer_pk.algorithm_suite)?;

    // Step 1: minimum length 17.
    if icc_pk_cert.len() < 17 {
        return Err(Error::InvalidValue);
    }
    // Step 2: format byte = '14'.
    if icc_pk_cert[0] != 0x14 {
        return Err(Error::InvalidValue);
    }
    // Step 3: encoding byte = '00'.
    if icc_pk_cert[1] != 0x00 {
        return Err(Error::InvalidValue);
    }

    let icc_pk_suite = icc_pk_cert[2];
    let expiration_yyyymmdd: [u8; 4] = icc_pk_cert[3..7].try_into().unwrap();
    let expiration_hhmm: [u8; 2] = icc_pk_cert[7..9].try_into().unwrap();
    let serial_number: [u8; 6] = icc_pk_cert[9..15].try_into().unwrap();
    let iccd_hash_encoding = icc_pk_cert[15];
    let iccd_hash_alg = icc_pk_cert[16];

    if iccd_hash_encoding != 0x00 {
        return Err(Error::InvalidValue);
    }

    // Step 4: expiration date+time ≥ now.
    if !yyyymmddhhmm_not_expired(
        expiration_yyyymmdd,
        expiration_hhmm,
        today_yyyymmdd,
        now_hhmm,
    ) {
        return Err(Error::InvalidValue);
    }
    // Step 5: ICC PK suite is recognised.
    let (n_field_icc, _, _) = suite_lengths(icc_pk_suite)?;
    // Step 6: ICCD hash alg is recognised. We only support SHA-256
    // and SHA-512 (the §B2.3 EMVCo-specified set this crate covers).
    let n_hash_iccd = match iccd_hash_alg {
        hash_algorithm::SHA_256 => 32usize,
        hash_algorithm::SHA_512 => 64usize,
        _ => return Err(Error::InvalidValue),
    };

    // Step 7: total length match.
    let expected_len = 17 + n_hash_iccd + n_field_icc + n_sig_issuer;
    if icc_pk_cert.len() != expected_len {
        return Err(Error::InvalidValue);
    }

    let iccd_hash = &icc_pk_cert[17..17 + n_hash_iccd];
    let icc_pk_x = &icc_pk_cert[17 + n_hash_iccd..17 + n_hash_iccd + n_field_icc];
    let signature = &icc_pk_cert[17 + n_hash_iccd + n_field_icc..];
    debug_assert_eq!(signature.len(), n_sig_issuer);

    // Step 8: ICCD Hash matches hash of static_data.
    let computed_hash = hash_for_ecc(iccd_hash_alg, static_data)?;
    if computed_hash.as_slice() != iccd_hash {
        return Err(Error::InvalidValue);
    }

    // Steps 9-10: verify EC-SDSA signature over fields [1..10].
    let signed_data = &icc_pk_cert[..17 + n_hash_iccd + n_field_icc];
    let ok = verify_ec_sdsa(
        issuer_pk.algorithm_suite,
        &issuer_pk.x_coord,
        signed_data,
        signature,
    )?;
    if !ok {
        return Err(Error::InvalidValue);
    }

    // Step 11: y-recovery - validate x is on the curve.
    validate_x_on_curve(icc_pk_suite, icc_pk_x)?;

    Ok(EccIccPublicKey {
        x_coord: icc_pk_x.to_vec(),
        algorithm_suite: icc_pk_suite,
        expiration_yyyymmdd,
        expiration_hhmm,
        serial_number,
        iccd_hash_algorithm: iccd_hash_alg,
    })
}

// ── XDA SDAD Verification (§12.5.3 / Tables 37, 38) ──────────────────

/// Verify the Signed Dynamic Application Data (`'9F4B'`) returned in
/// the GENERATE AC response per Book 2 §12.5.3 (Tables 37, 38).
///
/// Layout of `sdad`:
///
/// ```text
///   [1] Signed Data Format    1 byte    '15'
///   [2] Digital Signature     N_SIG bytes (EC-SDSA per icc_pk's suite)
/// ```
///
/// `transaction_data` is the byte concatenation §12.5.2 / Table 37
/// requires the terminal to hash through the EC-SDSA verification.
/// For the **first** GENERATE AC it is:
///
/// ```text
///   '15' || PDOL_data || CDOL1_data || (TLV response objects, less SDAD)
/// ```
///
/// For the **second** GENERATE AC, `CDOL2_data` is inserted between
/// `CDOL1_data` and the response-object TLVs. The leading `'15'`
/// byte (= the Signed Data Format) is included in the signed input
/// per Table 37 row 1.
///
/// Per §12.5.1, the terminal must skip XDA verification entirely if
/// the GENERATE AC response was an AAC - this function should not
/// be called in that case.
pub fn verify_xda(icc_pk: &EccIccPublicKey, sdad: &[u8], transaction_data: &[u8]) -> Result<()> {
    let (_n_field, _n_hash, n_sig) = suite_lengths(icc_pk.algorithm_suite)?;

    // Step 1: parse SDAD.
    if sdad.len() != 1 + n_sig {
        return Err(Error::InvalidValue);
    }
    // Step 2: format byte = '15'.
    if sdad[0] != 0x15 {
        return Err(Error::InvalidValue);
    }

    let signature = &sdad[1..];

    // Step 3: verify EC-SDSA signature on the Table 37 transaction data.
    let ok = verify_ec_sdsa(
        icc_pk.algorithm_suite,
        &icc_pk.x_coord,
        transaction_data,
        signature,
    )?;
    if !ok {
        return Err(Error::InvalidValue);
    }
    Ok(())
}

// ── Helpers ──────────────────────────────────────────────────────────

/// Check whether the 5-byte F-padded Issuer Identifier matches the
/// leftmost 3-10 digits of the BCD-encoded PAN.
fn issuer_identifier_matches_pan_ecc(issuer_id: &[u8; 5], pan: &[u8]) -> bool {
    let id_digits = match compressed_numeric::decode(issuer_id) {
        Ok(d) => d,
        Err(_) => return false,
    };
    let pan_digits = match compressed_numeric::decode(pan) {
        Ok(d) => d,
        Err(_) => return false,
    };
    if !(3..=10).contains(&id_digits.len()) {
        return false;
    }
    if id_digits.len() > pan_digits.len() {
        return false;
    }
    pan_digits.starts_with(&id_digits)
}

/// Lexicographic YYYYMMDD (BCD) comparison: cert is non-expired iff
/// `cert ≥ today`.
fn yyyymmdd_not_expired(cert: [u8; 4], today: [u8; 4]) -> bool {
    cert >= today
}

/// Combined YYYYMMDD + HHMM comparison: non-expired iff `(cert_date,
/// cert_time) ≥ (today, now)`.
fn yyyymmddhhmm_not_expired(
    cert_date: [u8; 4],
    cert_time: [u8; 2],
    today: [u8; 4],
    now: [u8; 2],
) -> bool {
    match cert_date.cmp(&today) {
        std::cmp::Ordering::Greater => true,
        std::cmp::Ordering::Less => false,
        std::cmp::Ordering::Equal => cert_time >= now,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::ec_sdsa::{
        constrain_long_term_private_key_p256, ec_sdsa_p256_sign, public_key_x_from_private,
    };

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

    fn ca_private() -> [u8; 32] {
        constrain_long_term_private_key_p256(&h32(
            "c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721",
        ))
        .unwrap()
    }
    fn issuer_private() -> [u8; 32] {
        constrain_long_term_private_key_p256(&h32(
            "a6e3c57dd01abe90086538398355dd4c3b17aa873382b0f24d6129493d8aad60",
        ))
        .unwrap()
    }
    fn icc_private() -> [u8; 32] {
        constrain_long_term_private_key_p256(&h32(
            "4b7c8e9f0a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5",
        ))
        .unwrap()
    }
    fn ca_k() -> [u8; 32] {
        h32("1111111111111111111111111111111111111111111111111111111111111111")
    }
    fn issuer_k() -> [u8; 32] {
        h32("2222222222222222222222222222222222222222222222222222222222222222")
    }
    fn icc_k() -> [u8; 32] {
        h32("3333333333333333333333333333333333333333333333333333333333333333")
    }

    fn test_ca_pk() -> EccCaPublicKey {
        EccCaPublicKey {
            rid: [0xA0, 0x00, 0x00, 0x00, 0x03],
            index: 0x01,
            x_coord: public_key_x_from_private(&ca_private()).unwrap().to_vec(),
            algorithm_suite: algorithm_suite::SIGNATURE_EC_SDSA_SHA256_P256,
        }
    }

    fn build_issuer_pk_cert(
        ca_priv: &[u8; 32],
        ca_k: &[u8; 32],
        ca_pk: &EccCaPublicKey,
        issuer_pk_x: &[u8; 32],
        issuer_id: [u8; 5],
        expiration_yyyymmdd: [u8; 4],
        serial: [u8; 3],
    ) -> Vec<u8> {
        let mut signed = Vec::new();
        signed.push(0x12); // format
        signed.push(0x00); // encoding
        signed.extend_from_slice(&issuer_id);
        signed.push(algorithm_suite::SIGNATURE_EC_SDSA_SHA256_P256); // issuer suite
        signed.extend_from_slice(&expiration_yyyymmdd);
        signed.extend_from_slice(&serial);
        signed.extend_from_slice(&ca_pk.rid);
        signed.push(ca_pk.index);
        signed.extend_from_slice(issuer_pk_x);

        let sig = ec_sdsa_p256_sign(ca_pk.algorithm_suite, ca_priv, ca_k, &signed).unwrap();

        let mut cert = signed;
        cert.extend_from_slice(&sig);
        cert
    }

    #[allow(clippy::too_many_arguments)]
    fn build_icc_pk_cert(
        issuer_priv: &[u8; 32],
        issuer_k: &[u8; 32],
        issuer_pk: &EccIssuerPublicKey,
        icc_pk_x: &[u8; 32],
        expiration_yyyymmdd: [u8; 4],
        expiration_hhmm: [u8; 2],
        serial: [u8; 6],
        iccd_hash_alg: u8,
        static_data: &[u8],
    ) -> Vec<u8> {
        let iccd_hash = hash_for_ecc(iccd_hash_alg, static_data).unwrap();
        let mut signed = Vec::new();
        signed.push(0x14); // format
        signed.push(0x00); // encoding
        signed.push(algorithm_suite::SIGNATURE_EC_SDSA_SHA256_P256); // ICC suite
        signed.extend_from_slice(&expiration_yyyymmdd);
        signed.extend_from_slice(&expiration_hhmm);
        signed.extend_from_slice(&serial);
        signed.push(0x00); // iccd hash encoding
        signed.push(iccd_hash_alg); // iccd hash alg
        signed.extend_from_slice(&iccd_hash);
        signed.extend_from_slice(icc_pk_x);

        let sig =
            ec_sdsa_p256_sign(issuer_pk.algorithm_suite, issuer_priv, issuer_k, &signed).unwrap();

        let mut cert = signed;
        cert.extend_from_slice(&sig);
        cert
    }

    fn build_sdad(
        icc_priv: &[u8; 32],
        icc_k: &[u8; 32],
        icc_pk: &EccIccPublicKey,
        transaction_data: &[u8],
    ) -> Vec<u8> {
        let sig =
            ec_sdsa_p256_sign(icc_pk.algorithm_suite, icc_priv, icc_k, transaction_data).unwrap();
        let mut sdad = Vec::with_capacity(1 + sig.len());
        sdad.push(0x15);
        sdad.extend_from_slice(&sig);
        sdad
    }

    // ── recover_issuer_public_key_ecc ────────────────────────────────

    #[test]
    fn recover_issuer_pk_happy_path() {
        let ca_pk = test_ca_pk();
        let issuer_pk_x = public_key_x_from_private(&issuer_private()).unwrap();
        let pan = [0x12, 0x34, 0x56, 0x78, 0x90, 0x12, 0x34, 0x56];
        let issuer_id = [0x12, 0x34, 0x56, 0xFF, 0xFF];
        let expiration = [0x20, 0x30, 0x12, 0x31];
        let serial = [0x00, 0x00, 0x42];
        let cert = build_issuer_pk_cert(
            &ca_private(),
            &ca_k(),
            &ca_pk,
            &issuer_pk_x,
            issuer_id,
            expiration,
            serial,
        );

        let result =
            recover_issuer_public_key_ecc(&ca_pk, &cert, &pan, [0x20, 0x26, 0x04, 0x28]).unwrap();

        assert_eq!(result.x_coord, issuer_pk_x.to_vec());
        assert_eq!(result.issuer_identifier, issuer_id);
        assert_eq!(result.expiration_yyyymmdd, expiration);
        assert_eq!(result.serial_number, serial);
    }

    #[test]
    fn recover_issuer_pk_rejects_bad_format_byte() {
        let ca_pk = test_ca_pk();
        let mut cert = build_issuer_pk_cert(
            &ca_private(),
            &ca_k(),
            &ca_pk,
            &public_key_x_from_private(&issuer_private()).unwrap(),
            [0x12, 0x34, 0x56, 0xFF, 0xFF],
            [0x20, 0x30, 0x12, 0x31],
            [0, 0, 0],
        );
        cert[0] = 0x13; // not '12'
        assert!(
            recover_issuer_public_key_ecc(
                &ca_pk,
                &cert,
                &[0x12, 0x34, 0x56, 0x78],
                [0x20, 0x26, 0x04, 0x28],
            )
            .is_err()
        );
    }

    #[test]
    fn recover_issuer_pk_rejects_pan_mismatch() {
        let ca_pk = test_ca_pk();
        let cert = build_issuer_pk_cert(
            &ca_private(),
            &ca_k(),
            &ca_pk,
            &public_key_x_from_private(&issuer_private()).unwrap(),
            [0x12, 0x34, 0x56, 0xFF, 0xFF],
            [0x20, 0x30, 0x12, 0x31],
            [0, 0, 0],
        );
        // PAN starts with 999... not 123...
        assert!(
            recover_issuer_public_key_ecc(
                &ca_pk,
                &cert,
                &[0x99, 0x99, 0x99, 0x99],
                [0x20, 0x26, 0x04, 0x28],
            )
            .is_err()
        );
    }

    #[test]
    fn recover_issuer_pk_rejects_expired_cert() {
        let ca_pk = test_ca_pk();
        let cert = build_issuer_pk_cert(
            &ca_private(),
            &ca_k(),
            &ca_pk,
            &public_key_x_from_private(&issuer_private()).unwrap(),
            [0x12, 0x34, 0x56, 0xFF, 0xFF],
            [0x20, 0x20, 0x01, 0x01], // expired in Jan 2020
            [0, 0, 0],
        );
        assert!(
            recover_issuer_public_key_ecc(
                &ca_pk,
                &cert,
                &[0x12, 0x34, 0x56, 0x78],
                [0x20, 0x26, 0x04, 0x28],
            )
            .is_err()
        );
    }

    #[test]
    fn recover_issuer_pk_rejects_rid_mismatch() {
        let ca_pk = test_ca_pk();
        let mut other_ca = ca_pk.clone();
        other_ca.rid = [0xA0, 0x00, 0x00, 0x00, 0x04]; // Mastercard
        let cert = build_issuer_pk_cert(
            &ca_private(),
            &ca_k(),
            &other_ca, // signed with the wrong RID embedded
            &public_key_x_from_private(&issuer_private()).unwrap(),
            [0x12, 0x34, 0x56, 0xFF, 0xFF],
            [0x20, 0x30, 0x12, 0x31],
            [0, 0, 0],
        );
        assert!(
            recover_issuer_public_key_ecc(
                &ca_pk, // expects A000000003
                &cert,
                &[0x12, 0x34, 0x56, 0x78],
                [0x20, 0x26, 0x04, 0x28],
            )
            .is_err()
        );
    }

    #[test]
    fn recover_issuer_pk_rejects_corrupted_signature() {
        let ca_pk = test_ca_pk();
        let mut cert = build_issuer_pk_cert(
            &ca_private(),
            &ca_k(),
            &ca_pk,
            &public_key_x_from_private(&issuer_private()).unwrap(),
            [0x12, 0x34, 0x56, 0xFF, 0xFF],
            [0x20, 0x30, 0x12, 0x31],
            [0, 0, 0],
        );
        // Corrupt last byte of signature.
        let last = cert.len() - 1;
        cert[last] ^= 0x01;
        assert!(
            recover_issuer_public_key_ecc(
                &ca_pk,
                &cert,
                &[0x12, 0x34, 0x56, 0x78],
                [0x20, 0x26, 0x04, 0x28],
            )
            .is_err()
        );
    }

    // ── recover_icc_public_key_ecc ───────────────────────────────────

    fn recovered_issuer_pk() -> EccIssuerPublicKey {
        EccIssuerPublicKey {
            x_coord: public_key_x_from_private(&issuer_private())
                .unwrap()
                .to_vec(),
            algorithm_suite: algorithm_suite::SIGNATURE_EC_SDSA_SHA256_P256,
            issuer_identifier: [0x12, 0x34, 0x56, 0xFF, 0xFF],
            expiration_yyyymmdd: [0x20, 0x30, 0x12, 0x31],
            serial_number: [0, 0, 0],
        }
    }

    #[test]
    fn recover_icc_pk_happy_path() {
        let issuer_pk = recovered_issuer_pk();
        let icc_pk_x = public_key_x_from_private(&icc_private()).unwrap();
        let static_data = b"static card data goes here";
        let cert = build_icc_pk_cert(
            &issuer_private(),
            &issuer_k(),
            &issuer_pk,
            &icc_pk_x,
            [0x20, 0x30, 0x12, 0x31],
            [0x23, 0x59],
            [0, 0, 0, 0, 0, 7],
            hash_algorithm::SHA_256,
            static_data,
        );

        let result = recover_icc_public_key_ecc(
            &issuer_pk,
            &cert,
            static_data,
            [0x20, 0x26, 0x04, 0x28],
            [0x10, 0x00],
        )
        .unwrap();

        assert_eq!(result.x_coord, icc_pk_x.to_vec());
        assert_eq!(result.iccd_hash_algorithm, hash_algorithm::SHA_256);
    }

    #[test]
    fn recover_icc_pk_rejects_modified_static_data() {
        let issuer_pk = recovered_issuer_pk();
        let cert = build_icc_pk_cert(
            &issuer_private(),
            &issuer_k(),
            &issuer_pk,
            &public_key_x_from_private(&icc_private()).unwrap(),
            [0x20, 0x30, 0x12, 0x31],
            [0x23, 0x59],
            [0, 0, 0, 0, 0, 7],
            hash_algorithm::SHA_256,
            b"original static data",
        );
        // Verify with different static data → ICCD hash mismatch.
        assert!(
            recover_icc_public_key_ecc(
                &issuer_pk,
                &cert,
                b"tampered static data",
                [0x20, 0x26, 0x04, 0x28],
                [0x10, 0x00],
            )
            .is_err()
        );
    }

    #[test]
    fn recover_icc_pk_rejects_expired_date() {
        let issuer_pk = recovered_issuer_pk();
        let cert = build_icc_pk_cert(
            &issuer_private(),
            &issuer_k(),
            &issuer_pk,
            &public_key_x_from_private(&icc_private()).unwrap(),
            [0x20, 0x20, 0x01, 0x01],
            [0x12, 0x00],
            [0, 0, 0, 0, 0, 7],
            hash_algorithm::SHA_256,
            b"data",
        );
        assert!(
            recover_icc_public_key_ecc(
                &issuer_pk,
                &cert,
                b"data",
                [0x20, 0x26, 0x04, 0x28],
                [0x10, 0x00],
            )
            .is_err()
        );
    }

    #[test]
    fn recover_icc_pk_rejects_expired_time_same_day() {
        // Cert expires 2026-04-28 09:00; now is 2026-04-28 10:00 →
        // expired by 1 hour.
        let issuer_pk = recovered_issuer_pk();
        let cert = build_icc_pk_cert(
            &issuer_private(),
            &issuer_k(),
            &issuer_pk,
            &public_key_x_from_private(&icc_private()).unwrap(),
            [0x20, 0x26, 0x04, 0x28],
            [0x09, 0x00],
            [0, 0, 0, 0, 0, 7],
            hash_algorithm::SHA_256,
            b"data",
        );
        assert!(
            recover_icc_public_key_ecc(
                &issuer_pk,
                &cert,
                b"data",
                [0x20, 0x26, 0x04, 0x28],
                [0x10, 0x00],
            )
            .is_err()
        );
    }

    #[test]
    fn recover_icc_pk_accepts_same_minute() {
        // Cert expires 2026-04-28 10:00; now is 2026-04-28 10:00 →
        // still valid (cert ≥ now).
        let issuer_pk = recovered_issuer_pk();
        let cert = build_icc_pk_cert(
            &issuer_private(),
            &issuer_k(),
            &issuer_pk,
            &public_key_x_from_private(&icc_private()).unwrap(),
            [0x20, 0x26, 0x04, 0x28],
            [0x10, 0x00],
            [0, 0, 0, 0, 0, 7],
            hash_algorithm::SHA_256,
            b"data",
        );
        assert!(
            recover_icc_public_key_ecc(
                &issuer_pk,
                &cert,
                b"data",
                [0x20, 0x26, 0x04, 0x28],
                [0x10, 0x00],
            )
            .is_ok()
        );
    }

    // ── verify_xda ───────────────────────────────────────────────────

    fn recovered_icc_pk() -> EccIccPublicKey {
        EccIccPublicKey {
            x_coord: public_key_x_from_private(&icc_private()).unwrap().to_vec(),
            algorithm_suite: algorithm_suite::SIGNATURE_EC_SDSA_SHA256_P256,
            expiration_yyyymmdd: [0x20, 0x30, 0x12, 0x31],
            expiration_hhmm: [0x23, 0x59],
            serial_number: [0, 0, 0, 0, 0, 7],
            iccd_hash_algorithm: hash_algorithm::SHA_256,
        }
    }

    #[test]
    fn verify_xda_happy_path() {
        let icc_pk = recovered_icc_pk();
        // Per Table 37, transaction_data starts with the format byte
        // '15' followed by PDOL || CDOL1 || response TLVs.
        let mut tx_data = vec![0x15];
        tx_data.extend_from_slice(b"PDOL data || CDOL1 || response TLVs without 9F4B");
        let sdad = build_sdad(&icc_private(), &icc_k(), &icc_pk, &tx_data);
        assert!(verify_xda(&icc_pk, &sdad, &tx_data).is_ok());
    }

    #[test]
    fn verify_xda_rejects_bad_format_byte() {
        let icc_pk = recovered_icc_pk();
        let tx_data = b"some data";
        let mut sdad = build_sdad(&icc_private(), &icc_k(), &icc_pk, tx_data);
        sdad[0] = 0x16; // not '15'
        assert!(verify_xda(&icc_pk, &sdad, tx_data).is_err());
    }

    #[test]
    fn verify_xda_rejects_wrong_length() {
        let icc_pk = recovered_icc_pk();
        let sdad = vec![0x15; 32]; // 1 + 31 ≠ 1 + 64
        assert!(verify_xda(&icc_pk, &sdad, b"data").is_err());
    }

    #[test]
    fn verify_xda_rejects_modified_transaction_data() {
        let icc_pk = recovered_icc_pk();
        let sdad = build_sdad(&icc_private(), &icc_k(), &icc_pk, b"original");
        assert!(verify_xda(&icc_pk, &sdad, b"modified").is_err());
    }

    #[test]
    fn verify_xda_rejects_signature_under_wrong_icc_key() {
        let icc_pk = recovered_icc_pk();
        let other_icc_priv =
            h32("1111111111111111111111111111111111111111111111111111111111111111");
        let sdad = {
            let sig = ec_sdsa_p256_sign(icc_pk.algorithm_suite, &other_icc_priv, &icc_k(), b"data")
                .unwrap();
            let mut s = vec![0x15];
            s.extend_from_slice(&sig);
            s
        };
        assert!(verify_xda(&icc_pk, &sdad, b"data").is_err());
    }

    // ── End-to-end XDA chain ─────────────────────────────────────────

    // ── P-521 (Suite '11') end-to-end ────────────────────────────────

    use crate::core::ec_sdsa::{
        constrain_long_term_private_key_p521, ec_sdsa_p521_sign, public_key_x_from_private_p521,
    };

    fn h66(s: &str) -> [u8; 66] {
        h(s).try_into().unwrap()
    }

    fn ca_private_p521() -> [u8; 66] {
        constrain_long_term_private_key_p521(&h66("00C9 AFA9 D845 BA75 166B 5C21 5767 B1D6\
             934E 50C3 DB36 E89B 127B 8A62 2B12 0F67\
             21AB CDEF 0123 4567 89AB CDEF 0123 4567\
             89AB CDEF 0123 4567 89AB CDEF 0123 4567\
             8901"))
        .unwrap()
    }
    fn issuer_private_p521() -> [u8; 66] {
        constrain_long_term_private_key_p521(&h66("00A6 E3C5 7DD0 1ABE 9008 6538 3983 55DD\
             4C3B 17AA 8733 82B0 F24D 6129 493D 8AAD\
             6011 2233 4455 6677 8899 AABB CCDD EEFF\
             0011 2233 4455 6677 8899 AABB CCDD EEFF\
             0011"))
        .unwrap()
    }
    fn icc_private_p521() -> [u8; 66] {
        constrain_long_term_private_key_p521(&h66("0033 3333 3333 3333 3333 3333 3333 3333\
             3333 3333 3333 3333 3333 3333 3333 3333\
             3333 3333 3333 3333 3333 3333 3333 3333\
             3333 3333 3333 3333 3333 3333 3333 3333\
             3333"))
        .unwrap()
    }
    fn ca_k_p521() -> [u8; 66] {
        h66("0011 1111 1111 1111 1111 1111 1111 1111\
             1111 1111 1111 1111 1111 1111 1111 1111\
             1111 1111 1111 1111 1111 1111 1111 1111\
             1111 1111 1111 1111 1111 1111 1111 1111\
             1111")
    }
    fn issuer_k_p521() -> [u8; 66] {
        h66("0022 2222 2222 2222 2222 2222 2222 2222\
             2222 2222 2222 2222 2222 2222 2222 2222\
             2222 2222 2222 2222 2222 2222 2222 2222\
             2222 2222 2222 2222 2222 2222 2222 2222\
             2222")
    }
    fn icc_k_p521() -> [u8; 66] {
        h66("0044 4444 4444 4444 4444 4444 4444 4444\
             4444 4444 4444 4444 4444 4444 4444 4444\
             4444 4444 4444 4444 4444 4444 4444 4444\
             4444 4444 4444 4444 4444 4444 4444 4444\
             4444")
    }

    #[test]
    fn end_to_end_ca_to_xda_signature_p521() {
        // Mirror of end_to_end_ca_to_xda_signature using Suite '11'
        // (P-521 + SHA-512). All three layers use P-521.
        let suite = algorithm_suite::SIGNATURE_EC_SDSA_SHA512_P521;
        let ca_pk = EccCaPublicKey {
            rid: [0xA0, 0x00, 0x00, 0x00, 0x03],
            index: 0x01,
            x_coord: public_key_x_from_private_p521(&ca_private_p521())
                .unwrap()
                .to_vec(),
            algorithm_suite: suite,
        };
        let pan = [0x12, 0x34, 0x56, 0x78, 0x90, 0x12, 0x34, 0x56];
        let issuer_id = [0x12, 0x34, 0x56, 0xFF, 0xFF];
        let static_data = b"ICCD static data over P-521";

        // Build Issuer PK Certificate signed by the CA (Table 35).
        let issuer_x = public_key_x_from_private_p521(&issuer_private_p521()).unwrap();
        let issuer_cert = {
            let mut signed = Vec::new();
            signed.push(0x12);
            signed.push(0x00);
            signed.extend_from_slice(&issuer_id);
            signed.push(suite); // issuer suite
            signed.extend_from_slice(&[0x20, 0x30, 0x12, 0x31]);
            signed.extend_from_slice(&[0, 0, 0]);
            signed.extend_from_slice(&ca_pk.rid);
            signed.push(ca_pk.index);
            signed.extend_from_slice(&issuer_x);
            let sig = ec_sdsa_p521_sign(suite, &ca_private_p521(), &ca_k_p521(), &signed).unwrap();
            signed.extend(sig);
            signed
        };
        let issuer_pk =
            recover_issuer_public_key_ecc(&ca_pk, &issuer_cert, &pan, [0x20, 0x26, 0x04, 0x28])
                .unwrap();
        assert_eq!(issuer_pk.x_coord, issuer_x);

        // Build ICC PK Certificate signed by the Issuer (Table 36).
        let icc_x = public_key_x_from_private_p521(&icc_private_p521()).unwrap();
        let iccd_hash = hash_for_ecc(hash_algorithm::SHA_512, static_data).unwrap();
        let icc_cert = {
            let mut signed = Vec::new();
            signed.push(0x14);
            signed.push(0x00);
            signed.push(suite);
            signed.extend_from_slice(&[0x20, 0x30, 0x12, 0x31]);
            signed.extend_from_slice(&[0x23, 0x59]);
            signed.extend_from_slice(&[0, 0, 0, 0, 0, 7]);
            signed.push(0x00);
            signed.push(hash_algorithm::SHA_512);
            signed.extend_from_slice(&iccd_hash);
            signed.extend_from_slice(&icc_x);
            let sig = ec_sdsa_p521_sign(suite, &issuer_private_p521(), &issuer_k_p521(), &signed)
                .unwrap();
            signed.extend(sig);
            signed
        };
        let icc_pk = recover_icc_public_key_ecc(
            &issuer_pk,
            &icc_cert,
            static_data,
            [0x20, 0x26, 0x04, 0x28],
            [0x10, 0x00],
        )
        .unwrap();
        assert_eq!(icc_pk.x_coord, icc_x);

        // Build and verify SDAD (Table 38).
        let mut tx_data = vec![0x15];
        tx_data.extend_from_slice(b"transaction data for XDA over P-521");
        let sdad = {
            let sig =
                ec_sdsa_p521_sign(suite, &icc_private_p521(), &icc_k_p521(), &tx_data).unwrap();
            let mut s = vec![0x15];
            s.extend(sig);
            s
        };
        assert!(verify_xda(&icc_pk, &sdad, &tx_data).is_ok());
    }

    #[test]
    fn end_to_end_ca_to_xda_signature() {
        // Drive the full chain: CA → Issuer PK Cert → ICC PK Cert →
        // SDAD verification.
        let ca_pk = test_ca_pk();
        let pan = [0x12, 0x34, 0x56, 0x78, 0x90, 0x12, 0x34, 0x56];
        let issuer_id = [0x12, 0x34, 0x56, 0xFF, 0xFF];
        let static_data = b"ICCD static data";

        let issuer_x = public_key_x_from_private(&issuer_private()).unwrap();
        let issuer_cert = build_issuer_pk_cert(
            &ca_private(),
            &ca_k(),
            &ca_pk,
            &issuer_x,
            issuer_id,
            [0x20, 0x30, 0x12, 0x31],
            [0, 0, 0],
        );
        let issuer_pk =
            recover_issuer_public_key_ecc(&ca_pk, &issuer_cert, &pan, [0x20, 0x26, 0x04, 0x28])
                .unwrap();

        let icc_x = public_key_x_from_private(&icc_private()).unwrap();
        let icc_cert = build_icc_pk_cert(
            &issuer_private(),
            &issuer_k(),
            &issuer_pk,
            &icc_x,
            [0x20, 0x30, 0x12, 0x31],
            [0x23, 0x59],
            [0, 0, 0, 0, 0, 7],
            hash_algorithm::SHA_256,
            static_data,
        );
        let icc_pk = recover_icc_public_key_ecc(
            &issuer_pk,
            &icc_cert,
            static_data,
            [0x20, 0x26, 0x04, 0x28],
            [0x10, 0x00],
        )
        .unwrap();

        let mut tx_data = vec![0x15];
        tx_data.extend_from_slice(b"transaction data for XDA");
        let sdad = build_sdad(&icc_private(), &icc_k(), &icc_pk, &tx_data);

        assert!(verify_xda(&icc_pk, &sdad, &tx_data).is_ok());
    }

    // ── Helper unit tests ────────────────────────────────────────────

    #[test]
    fn issuer_id_match_5_bytes_with_padding() {
        let id = [0x12, 0x34, 0x56, 0xFF, 0xFF]; // 6 digits + F padding
        let pan = [0x12, 0x34, 0x56, 0x78, 0x90, 0x12, 0xF];
        // PAN digits: 1 2 3 4 5 6 7 8 9 0 1 2; ID prefix: 1 2 3 4 5 6
        // Wait - id digits are 1, 2, 3, 4, 5, 6 (6 digits) and the
        // PAN starts with 1, 2, 3, 4, 5, 6.
        assert!(issuer_identifier_matches_pan_ecc(&id, &pan));
    }

    #[test]
    fn issuer_id_full_10_digits() {
        let id = [0x12, 0x34, 0x56, 0x78, 0x90];
        let pan = [0x12, 0x34, 0x56, 0x78, 0x90, 0x12];
        assert!(issuer_identifier_matches_pan_ecc(&id, &pan));
    }

    #[test]
    fn issuer_id_too_few_digits() {
        let id = [0x12, 0xFF, 0xFF, 0xFF, 0xFF]; // only 2 digits - below min 3
        let pan = [0x12, 0xFF];
        assert!(!issuer_identifier_matches_pan_ecc(&id, &pan));
    }

    #[test]
    fn yyyymmdd_lex_compares_correctly() {
        assert!(yyyymmdd_not_expired(
            [0x20, 0x26, 0x04, 0x28],
            [0x20, 0x26, 0x04, 0x28]
        ));
        assert!(yyyymmdd_not_expired(
            [0x20, 0x26, 0x04, 0x29],
            [0x20, 0x26, 0x04, 0x28]
        ));
        assert!(!yyyymmdd_not_expired(
            [0x20, 0x26, 0x04, 0x27],
            [0x20, 0x26, 0x04, 0x28]
        ));
        assert!(!yyyymmdd_not_expired(
            [0x20, 0x25, 0x12, 0x31],
            [0x20, 0x26, 0x01, 0x01]
        ));
    }
}
