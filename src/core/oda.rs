//! Book 3 §10.3 / Book 2 §5 / §6.5 / §6.6 - RSA-based Offline Data Authentication.

use crate::core::compressed_numeric;
use crate::core::error::{Error, Result};
use crate::core::iso9796_2;
use sha1::{Digest, Sha1};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OdaMethod {
    Sda,
    Dda,
    Cda,
    Xda,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OdaOutcome {
    NotPerformed,
    SdaSuccess { dac: [u8; 2] },
    SdaFailed,
    DdaSuccess { icc_dynamic_number: Vec<u8> },
    DdaFailed,
    CdaArmed,
    CdaFailed,
    XdaArmed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct XdaArming {
    pub state: XdaArmingState,
    pub cdol1_data: Vec<u8>,
    pub cdol2_data: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum XdaArmingState {
    Armed {
        icc_public_key: crate::core::ecc_oda::EccIccPublicKey,
    },
    CaMissing,
    RecoveryFailed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CdaArming {
    pub icc_public_key: IccPublicKey,
    pub cdol1_data: Vec<u8>,
    pub cdol2_data: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CaPublicKey {
    pub rid: [u8; 5],
    pub index: u8,
    pub modulus: Vec<u8>,
    pub exponent: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IssuerPublicKey {
    pub modulus: Vec<u8>,
    pub exponent: Vec<u8>,
    pub hash_algorithm_indicator: u8,
    pub algorithm_indicator: u8,
    pub issuer_identifier: [u8; 4],
    pub expiration_mmyy: [u8; 2],
    pub serial_number: [u8; 3],
}

pub fn recover_issuer_public_key(
    ca_pk: &CaPublicKey,
    issuer_pk_cert: &[u8],
    issuer_pk_remainder: Option<&[u8]>,
    issuer_pk_exponent: &[u8],
    pan: &[u8],
    today_mmyy: [u8; 2],
) -> Result<IssuerPublicKey> {
    let n_ca = ca_pk.modulus.len();
    if n_ca < 36 + 1 {
        return Err(Error::InvalidValue);
    }
    // §5.3 step 1.
    if issuer_pk_cert.len() != n_ca {
        return Err(Error::WrongLength {
            expected: n_ca,
            got: issuer_pk_cert.len(),
        });
    }
    // §5.3 step 2.
    let x = iso9796_2::rsa_recover(issuer_pk_cert, &ca_pk.exponent, &ca_pk.modulus)?;
    // §5.3 step 3 + Table 6 trailer.
    if x[0] != 0x6A || x[n_ca - 1] != 0xBC {
        return Err(Error::InvalidValue);
    }
    // §5.3 step 4.
    if x[1] != 0x02 {
        return Err(Error::InvalidValue);
    }

    // Table 6 field offsets.
    let issuer_id: [u8; 4] = x[2..6].try_into().unwrap();
    let exp_mmyy: [u8; 2] = x[6..8].try_into().unwrap();
    let serial: [u8; 3] = x[8..11].try_into().unwrap();
    let hash_alg = x[11];
    let pk_alg = x[12];
    let n_i = x[13] as usize;
    let pk_exp_len = x[14] as usize;
    let leftmost_digits_end = n_ca - 21;
    let leftmost_digits = &x[15..leftmost_digits_end];
    let recovered_hash = &x[leftmost_digits_end..(n_ca - 1)];

    if pk_exp_len != issuer_pk_exponent.len() {
        return Err(Error::WrongLength {
            expected: pk_exp_len,
            got: issuer_pk_exponent.len(),
        });
    }
    // §5.3 step 12.
    let issuer_modulus = if n_i <= n_ca - 36 {
        if issuer_pk_remainder.is_some() {
            return Err(Error::InvalidValue);
        }
        if !leftmost_digits[n_i..].iter().all(|&b| b == 0xBB) {
            return Err(Error::InvalidValue);
        }
        leftmost_digits[..n_i].to_vec()
    } else {
        let remainder = issuer_pk_remainder.ok_or(Error::InvalidValue)?;
        let expected_remainder_len = n_i - (n_ca - 36);
        if remainder.len() != expected_remainder_len {
            return Err(Error::WrongLength {
                expected: expected_remainder_len,
                got: remainder.len(),
            });
        }
        let mut full = Vec::with_capacity(n_i);
        full.extend_from_slice(leftmost_digits);
        full.extend_from_slice(remainder);
        full
    };

    // §5.3 steps 5–7.
    let mut hasher = Sha1::new();
    hasher.update(&x[1..leftmost_digits_end]);
    if let Some(r) = issuer_pk_remainder {
        hasher.update(r);
    }
    hasher.update(issuer_pk_exponent);
    let computed = hasher.finalize();
    if recovered_hash != computed.as_slice() {
        return Err(Error::InvalidValue);
    }

    // §5.3 step 8.
    if !issuer_identifier_matches_pan(&issuer_id, pan) {
        return Err(Error::InvalidValue);
    }
    // §5.3 step 9.
    if !mmyy_not_expired(exp_mmyy, today_mmyy) {
        return Err(Error::InvalidValue);
    }

    Ok(IssuerPublicKey {
        modulus: issuer_modulus,
        exponent: issuer_pk_exponent.to_vec(),
        hash_algorithm_indicator: hash_alg,
        algorithm_indicator: pk_alg,
        issuer_identifier: issuer_id,
        expiration_mmyy: exp_mmyy,
        serial_number: serial,
    })
}

/// Verify Signed Static Application Data per Book 2 §5.4 (Table 7).
///
/// Returns the 2-byte Data Authentication Code recovered from the
/// signature - the caller stores it in tag `'9F45'` per the closing
/// paragraph of §5.4.
///
/// `static_data` is the input string from Book 3 §10.3:
/// records-identified-by-AFL (with SFI-based inclusion rules) plus
/// the AIP value if `'9F4A'` is present and contains tag `'82'`.
/// This function does not validate the construction of that input -
/// it just hashes the bytes the caller supplies.
pub fn verify_sda(issuer_pk: &IssuerPublicKey, ssad: &[u8], static_data: &[u8]) -> Result<[u8; 2]> {
    let n_i = issuer_pk.modulus.len();
    if n_i < 26 {
        // N_I must accommodate Header + Format + Hash Alg + DAC + 0+
        // pad pattern + Hash + Trailer = at least 26 bytes (N_I - 26
        // pad bytes can be zero).
        return Err(Error::InvalidValue);
    }
    // §5.4 step 1.
    if ssad.len() != n_i {
        return Err(Error::WrongLength {
            expected: n_i,
            got: ssad.len(),
        });
    }
    // §5.4 step 2.
    let x = iso9796_2::rsa_recover(ssad, &issuer_pk.exponent, &issuer_pk.modulus)?;
    // Header + Trailer.
    if x[0] != 0x6A || x[n_i - 1] != 0xBC {
        return Err(Error::InvalidValue);
    }
    // §5.4 step 4.
    if x[1] != 0x03 {
        return Err(Error::InvalidValue);
    }

    // Table 7 fields.
    // x[2]               Hash Algorithm Indicator
    // x[3..5]            Data Authentication Code (2 bytes)
    // x[5..(n_i - 21)]   Pad Pattern (BB bytes, length N_I - 26)
    // x[(n_i - 21)..(n_i - 1)]  Hash Result (20 bytes)
    let dac: [u8; 2] = x[3..5].try_into().unwrap();
    let pad_pattern = &x[5..(n_i - 21)];
    let recovered_hash = &x[(n_i - 21)..(n_i - 1)];

    if !pad_pattern.iter().all(|&b| b == 0xBB) {
        return Err(Error::InvalidValue);
    }

    // §5.4 steps 5–7: hash and compare.
    let mut hasher = Sha1::new();
    hasher.update(&x[1..(n_i - 21)]);
    hasher.update(static_data);
    let computed = hasher.finalize();
    if recovered_hash != computed.as_slice() {
        return Err(Error::InvalidValue);
    }

    Ok(dac)
}

// ── ICC Public Key recovery (Book 2 §6.4, Table 14) ──────────────────

/// ICC Public Key recovered from the ICC PK Certificate (`'9F46'`)
/// plus (optional) ICC PK Remainder (`'9F48'`) and ICC PK Exponent
/// (`'9F47'`).
///
/// Used by Dynamic Data Authentication (§6.5) and Combined DDA
/// (§6.6) - the key under which the card signs dynamic application
/// data with `INTERNAL AUTHENTICATE` (DDA) or with the response to
/// `GENERATE AC` (CDA).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IccPublicKey {
    /// Big-endian modulus, length `N_IC` bytes.
    pub modulus: Vec<u8>,
    /// Big-endian exponent (1 or 3 bytes).
    pub exponent: Vec<u8>,
    /// Hash Algorithm Indicator (Book 2 Table 14 field).
    pub hash_algorithm_indicator: u8,
    /// ICC PK Algorithm Indicator (Book 2 Table 14 field).
    pub algorithm_indicator: u8,
    /// Application PAN, BCD-packed and `'F'`-padded to 10 bytes
    /// (cn 20 - up to 20 digits).
    pub application_pan: [u8; 10],
    /// Certificate Expiration Date as MMYY (BCD, 2 bytes).
    pub expiration_mmyy: [u8; 2],
    /// Certificate Serial Number assigned by the issuer (3 bytes).
    pub serial_number: [u8; 3],
}

/// Recover the ICC Public Key from its certificate per Book 2 §6.4
/// (Table 14).
///
/// Steps 1-11 of §6.4:
///
/// 1. Validates `icc_pk_cert.len() == issuer_pk.modulus.len()`.
/// 2. RSA-recovers the certificate via [`iso9796_2::verify`], which
///    handles the `'6A'` header / `'BC'` trailer / hash checks
///    against `Hash(MSG_1 || msg2)` where
///    `msg2 = remainder || exponent || static_data`.
///    3-4. Header / Format byte (`'04'`) checks.
///    5-7. Hash check (handled by [`iso9796_2::verify`]).
/// 8. Verifies the recovered Application PAN matches the `pan`
///    parameter exactly (after `'F'`-padding strip).
/// 9. Verifies the Certificate Expiration Date is on or after
///    `today_mmyy`.
/// 11. Concatenates the Leftmost Digits with the Remainder (if any)
///     to form the ICC PK Modulus.
///
/// Step 10 (algorithm indicator validation) is caller-side; the
/// recovered struct exposes both indicators on
/// [`IccPublicKey::hash_algorithm_indicator`] and
/// [`IccPublicKey::algorithm_indicator`].
///
/// `static_data` is the same byte string used for SDA (Book 3 §10.3:
/// records-by-AFL plus optional AIP from `'9F4A'`); it is included in
/// the hash input per Table 11 / §6.4 step 5.
pub fn recover_icc_public_key(
    issuer_pk: &IssuerPublicKey,
    icc_pk_cert: &[u8],
    icc_pk_remainder: Option<&[u8]>,
    icc_pk_exponent: &[u8],
    static_data: &[u8],
    pan: &[u8],
    today_mmyy: [u8; 2],
) -> Result<IccPublicKey> {
    let n_i = issuer_pk.modulus.len();
    if n_i < 42 + 1 {
        // N_I must accommodate at least 1 byte of ICC PK material.
        return Err(Error::InvalidValue);
    }
    // §6.4 step 1.
    if icc_pk_cert.len() != n_i {
        return Err(Error::WrongLength {
            expected: n_i,
            got: icc_pk_cert.len(),
        });
    }

    // Build msg2 = remainder || exponent || static_data per §6.4 step 5.
    let mut msg2 = Vec::with_capacity(
        icc_pk_remainder.map_or(0, |r| r.len()) + icc_pk_exponent.len() + static_data.len(),
    );
    if let Some(r) = icc_pk_remainder {
        msg2.extend_from_slice(r);
    }
    msg2.extend_from_slice(icc_pk_exponent);
    msg2.extend_from_slice(static_data);

    // §6.4 step 2 + steps 3, 5-7: RSA recovery, header / trailer
    // / hash checks all in one shot via iso9796_2::verify.
    let msg1 = iso9796_2::verify(icc_pk_cert, &issuer_pk.exponent, &issuer_pk.modulus, &msg2)?;

    // §6.4 step 4: Cert Format = '04'.
    if msg1[0] != 0x04 {
        return Err(Error::InvalidValue);
    }

    // Parse Table 14 fields. msg1 = X[1..N_I-21], so msg1 indexes are
    // shifted left by 1 from X indexes.
    //   msg1[0]      Cert Format
    //   msg1[1..11]  Application PAN (10 bytes)
    //   msg1[11..13] Cert Expiration Date (MMYY)
    //   msg1[13..16] Cert Serial Number (3 bytes)
    //   msg1[16]     Hash Algorithm Indicator
    //   msg1[17]     ICC PK Algorithm Indicator
    //   msg1[18]     ICC PK Length N_IC
    //   msg1[19]     ICC PK Exponent Length
    //   msg1[20..(20 + N_I - 42)]  Leftmost Digits of ICC PK
    let app_pan: [u8; 10] = msg1[1..11].try_into().unwrap();
    let exp_mmyy: [u8; 2] = msg1[11..13].try_into().unwrap();
    let serial: [u8; 3] = msg1[13..16].try_into().unwrap();
    let hash_alg = msg1[16];
    let pk_alg = msg1[17];
    let n_ic = msg1[18] as usize;
    let pk_exp_len = msg1[19] as usize;
    let leftmost_field_len = n_i - 42;
    let leftmost_digits = &msg1[20..(20 + leftmost_field_len)];

    if pk_exp_len != icc_pk_exponent.len() {
        return Err(Error::WrongLength {
            expected: pk_exp_len,
            got: icc_pk_exponent.len(),
        });
    }

    // §6.4 step 11: assemble the modulus.
    let icc_modulus = if n_ic <= leftmost_field_len {
        if icc_pk_remainder.is_some() {
            return Err(Error::InvalidValue);
        }
        if !leftmost_digits[n_ic..].iter().all(|&b| b == 0xBB) {
            return Err(Error::InvalidValue);
        }
        leftmost_digits[..n_ic].to_vec()
    } else {
        let remainder = icc_pk_remainder.ok_or(Error::InvalidValue)?;
        let expected_remainder_len = n_ic - leftmost_field_len;
        if remainder.len() != expected_remainder_len {
            return Err(Error::WrongLength {
                expected: expected_remainder_len,
                got: remainder.len(),
            });
        }
        let mut full = Vec::with_capacity(n_ic);
        full.extend_from_slice(leftmost_digits);
        full.extend_from_slice(remainder);
        full
    };

    // §6.4 step 8: PAN equality.
    if !app_pan_matches(&app_pan, pan) {
        return Err(Error::InvalidValue);
    }
    // §6.4 step 9: expiration.
    if !mmyy_not_expired(exp_mmyy, today_mmyy) {
        return Err(Error::InvalidValue);
    }

    Ok(IccPublicKey {
        modulus: icc_modulus,
        exponent: icc_pk_exponent.to_vec(),
        hash_algorithm_indicator: hash_alg,
        algorithm_indicator: pk_alg,
        application_pan: app_pan,
        expiration_mmyy: exp_mmyy,
        serial_number: serial,
    })
}

// ── Dynamic Data Authentication (Book 2 §6.5) ────────────────────────

/// Verify the Signed Dynamic Application Data (`'9F4B'`) returned by
/// the ICC in response to `INTERNAL AUTHENTICATE` per Book 2 §6.5.2
/// (Table 17).
///
/// `ddol_data` is the byte string the terminal supplied in the
/// command's data field - the concatenation of the data elements
/// specified by the DDOL (`'9F49'`, mandatory tag `'9F37'` Unpredictable
/// Number per §6.5.1). The card hashes the same DDOL data when
/// generating the signature, so the terminal must keep it byte-for-byte
/// identical for verification.
///
/// Steps per §6.5.2:
///
/// 1. Validates `sdad.len() == icc_pk.modulus.len()`.
/// 2. RSA-recovers via [`iso9796_2::verify`] (header / trailer / hash
///    checks).
///    3-4. Recovered header `'6A'` and Signed Data Format `'05'` checks.
///    5-7. Hash check handled by [`iso9796_2::verify`] with
///    `msg2 = ddol_data`.
///
/// Returns the **ICC Dynamic Number** (the value the spec says shall
/// be stored in tag `'9F4C'`): its length byte and bytes are the first
/// 3-9 leftmost bytes of the recovered ICC Dynamic Data per §6.5.1
/// (1-byte length followed by 2-8 bytes of value).
pub fn verify_dda(icc_pk: &IccPublicKey, sdad: &[u8], ddol_data: &[u8]) -> Result<Vec<u8>> {
    let n_ic = icc_pk.modulus.len();
    if n_ic < 25 + 22 {
        // N_IC must accommodate B + Format + Hash Alg + L_DD (≥3) +
        // pad + Hash + E. Minimum N_IC ≈ 47.
        return Err(Error::InvalidValue);
    }
    // §6.5.2 step 1.
    if sdad.len() != n_ic {
        return Err(Error::WrongLength {
            expected: n_ic,
            got: sdad.len(),
        });
    }

    // §6.5.2 steps 2 + 3 + 5-7: header / trailer / hash all in one.
    let msg1 = iso9796_2::verify(sdad, &icc_pk.exponent, &icc_pk.modulus, ddol_data)?;

    // Table 17 layout (msg1 = X[1..N_IC-21]):
    //   msg1[0]                  Signed Data Format = '05'
    //   msg1[1]                  Hash Algorithm Indicator
    //   msg1[2]                  L_DD (ICC Dynamic Data length)
    //   msg1[3..(3 + L_DD)]      ICC Dynamic Data
    //   msg1[(3 + L_DD)..end]    Pad Pattern ('BB' bytes)
    if msg1[0] != 0x05 {
        return Err(Error::InvalidValue);
    }
    let l_dd = msg1[2] as usize;
    if 3 + l_dd > msg1.len() {
        return Err(Error::InvalidValue);
    }
    let icc_dynamic_data = &msg1[3..(3 + l_dd)];
    let pad_pattern = &msg1[(3 + l_dd)..];
    if !pad_pattern.iter().all(|&b| b == 0xBB) {
        return Err(Error::InvalidValue);
    }

    // Per §6.5.1, the leftmost 3-9 bytes of ICC Dynamic Data are
    // {1-byte L} || {L-byte ICC Dynamic Number}, where L ∈ 2..=8.
    if icc_dynamic_data.is_empty() {
        return Err(Error::InvalidValue);
    }
    let dn_len = icc_dynamic_data[0] as usize;
    if !(2..=8).contains(&dn_len) || 1 + dn_len > icc_dynamic_data.len() {
        return Err(Error::InvalidValue);
    }
    Ok(icc_dynamic_data[1..(1 + dn_len)].to_vec())
}

/// Recover the ICC PIN Encipherment Public Key from its certificate
/// per Book 2 §7.1 (Table 23).
///
/// Per the §7.1 case-1 footnote, the data recovered from this
/// certificate has the same format as Table 14 (the regular ICC PK
/// certificate format byte `'04'`, App PAN, expiration, hash, modulus
/// fields), and the only difference from [`recover_icc_public_key`]
/// is that the issuer-signed hash input does **not** include the
/// Static Data to be Authenticated. Hence this function delegates
/// with an empty `static_data`.
///
/// The §7.1 case-2 path - where the card has no separate PIN
/// Encipherment key and the regular ICC Public Key is used for
/// PIN encipherment - does not need this function: callers reuse
/// the [`IccPublicKey`] from [`recover_icc_public_key`] directly.
pub fn recover_icc_pin_encipherment_public_key(
    issuer_pk: &IssuerPublicKey,
    icc_pin_pk_cert: &[u8],
    icc_pin_pk_remainder: Option<&[u8]>,
    icc_pin_pk_exponent: &[u8],
    pan: &[u8],
    today_mmyy: [u8; 2],
) -> Result<IccPublicKey> {
    recover_icc_public_key(
        issuer_pk,
        icc_pin_pk_cert,
        icc_pin_pk_remainder,
        icc_pin_pk_exponent,
        &[],
        pan,
        today_mmyy,
    )
}

// ── Combined DDA/Application Cryptogram Generation (Book 2 §6.6) ─────

/// Outcome of a successful CDA verification.
///
/// Per §6.6.2 the terminal stores `icc_dynamic_number` in tag `'9F4C'`
/// and `application_cryptogram` in tag `'9F26'` once the signature has
/// been validated.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CdaVerified {
    /// 2-8 byte ICC Dynamic Number (value to be stored in tag `'9F4C'`).
    pub icc_dynamic_number: Vec<u8>,
    /// 8-byte TC or ARQC recovered from inside the signature (value to
    /// be stored in tag `'9F26'`).
    pub application_cryptogram: [u8; 8],
    /// Bytes inside ICC Dynamic Data after the standard Table 19 fields
    /// (`1 + L_dyn + 1 + 8 + 20`). Kernels that extend the layout
    /// recover their own fields here - e.g. Book C-6 §3.6.1 appends a
    /// 20-byte Data Storage Directory Hash (`DSD_Hash`).
    pub trailing_dynamic_data: Vec<u8>,
}

/// Verify the Signed Dynamic Application Data (`'9F4B'`) returned in a
/// CDA-enabled `GENERATE AC` response per Book 2 §6.6.2 (Tables 18,
/// 19, 22).
///
/// CDA differs from DDA on two points:
///
/// 1. The signed appendix (msg2 in [`iso9796_2::verify`]) is the
///    4-byte terminal-generated **Unpredictable Number** (`'9F37'`)
///    rather than the full DDOL data.
/// 2. The recoverable ICC Dynamic Data field starts with a fixed 32-38
///    byte structure (Table 19) carrying the ICC Dynamic Number, a
///    repeated copy of the Cryptogram Information Data, the TC or
///    ARQC itself, and a 20-byte SHA-1 **Transaction Data Hash Code**
///    that binds the signature to the GET PROCESSING OPTIONS / CDOL /
///    GENERATE AC interaction.
///
/// `transaction_data` is the byte concatenation §6.6.2 step 10
/// requires the terminal to hash. Assembling it correctly is the
/// caller's job - for the **first** GENERATE AC it is:
///
/// ```text
///   PDOL_data || CDOL1_data || (TLV of response objects, less SDAD)
/// ```
///
/// For the **second** GENERATE AC, `CDOL2_data` is inserted between
/// `CDOL1_data` and the response-object TLVs. The "less SDAD" wording
/// means the `'9F4B'` TLV is omitted from the response part; the
/// other Table 20 tags (`'9F27'`, `'9F36'`, optionally `'9F10'`) are
/// included as-returned, in order.
///
/// `expected_cid` is the cleartext Cryptogram Information Data
/// (`'9F27'`) the terminal already extracted from the GENERATE AC
/// response. §6.6.2 step 6 requires it to match the CID embedded
/// inside the signature.
///
/// Steps performed (mapping to §6.6.2):
///
/// 1. Validates `sdad.len() == icc_pk.modulus.len()`.
/// 2. RSA-recovers via [`iso9796_2::verify`] (header / trailer /
///    inner-hash checks against `unpredictable_number`).
///    3-4. Recovered header `'6A'` and Signed Data Format `'05'`.
/// 5. Parses the leading 32-38 bytes of ICC Dynamic Data per Table 19
///    (any trailing proprietary bytes are accepted but ignored, since
///    `L_DD` may be larger than 32-38).
/// 6. Checks the embedded CID matches `expected_cid`.
///    7-9. Inner hash check is folded into [`iso9796_2::verify`].
///    10-12. SHA-1(`transaction_data`) is compared against the
///    Transaction Data Hash Code recovered from the signature.
///
/// Per §6.6.2 the terminal must decline up-front if the GENERATE AC
/// response was an AAC (Table 21 - cleartext `'9F26'` and no SDAD);
/// there is no signature to verify in that case and this function
/// must not be called.
pub fn verify_cda(
    icc_pk: &IccPublicKey,
    sdad: &[u8],
    unpredictable_number: [u8; 4],
    transaction_data: &[u8],
    expected_cid: u8,
) -> Result<CdaVerified> {
    let n_ic = icc_pk.modulus.len();
    if n_ic < 25 + 22 {
        // Same lower bound as DDA - N_IC ≥ 47 just to admit the fixed
        // structural overhead (B + Format + Hash Alg + L_DD + pad +
        // Hash + E with L_DD ≥ 0).
        return Err(Error::InvalidValue);
    }
    // §6.6.2 step 1.
    if sdad.len() != n_ic {
        return Err(Error::WrongLength {
            expected: n_ic,
            got: sdad.len(),
        });
    }

    // §6.6.2 steps 2 + 3 + 7-9: header / trailer / inner hash.
    let msg1 = iso9796_2::verify(
        sdad,
        &icc_pk.exponent,
        &icc_pk.modulus,
        &unpredictable_number,
    )?;

    // Table 22 layout (msg1 = X[1..N_IC-21]):
    //   msg1[0]                  Signed Data Format = '05'
    //   msg1[1]                  Hash Algorithm Indicator
    //   msg1[2]                  L_DD (ICC Dynamic Data length)
    //   msg1[3..(3 + L_DD)]      ICC Dynamic Data
    //   msg1[(3 + L_DD)..end]    Pad Pattern ('BB' bytes)
    //
    // §6.6.2 step 4.
    if msg1[0] != 0x05 {
        return Err(Error::InvalidValue);
    }
    let l_dd = msg1[2] as usize;
    if 3 + l_dd > msg1.len() {
        return Err(Error::InvalidValue);
    }
    let icc_dynamic_data = &msg1[3..(3 + l_dd)];
    let pad_pattern = &msg1[(3 + l_dd)..];
    if !pad_pattern.iter().all(|&b| b == 0xBB) {
        return Err(Error::InvalidValue);
    }

    // §6.6.2 step 5 - Table 19 layout of the leading bytes of ICC
    // Dynamic Data:
    //   [0]              ICC Dynamic Number Length L (2..=8)
    //   [1..1+L]         ICC Dynamic Number
    //   [1+L]            Cryptogram Information Data (CID)
    //   [2+L..10+L]      TC or ARQC (8 bytes)
    //   [10+L..30+L]     Transaction Data Hash Code (20 bytes)
    //   [30+L..]         (proprietary trailing data - accepted)
    if icc_dynamic_data.is_empty() {
        return Err(Error::InvalidValue);
    }
    let dn_len = icc_dynamic_data[0] as usize;
    if !(2..=8).contains(&dn_len) {
        return Err(Error::InvalidValue);
    }
    let table19_len = 1 + dn_len + 1 + 8 + 20;
    if icc_dynamic_data.len() < table19_len {
        return Err(Error::InvalidValue);
    }
    let icc_dynamic_number = icc_dynamic_data[1..(1 + dn_len)].to_vec();
    let recovered_cid = icc_dynamic_data[1 + dn_len];
    let application_cryptogram: [u8; 8] = icc_dynamic_data[(2 + dn_len)..(10 + dn_len)]
        .try_into()
        .unwrap();
    let recovered_tx_hash = &icc_dynamic_data[(10 + dn_len)..(30 + dn_len)];
    let trailing_dynamic_data = icc_dynamic_data[(30 + dn_len)..].to_vec();

    // §6.6.2 step 6.
    if recovered_cid != expected_cid {
        return Err(Error::InvalidValue);
    }

    // §6.6.2 steps 10-12.
    let mut hasher = Sha1::new();
    hasher.update(transaction_data);
    let computed_tx_hash = hasher.finalize();
    if recovered_tx_hash != computed_tx_hash.as_slice() {
        return Err(Error::InvalidValue);
    }

    Ok(CdaVerified {
        icc_dynamic_number,
        application_cryptogram,
        trailing_dynamic_data,
    })
}

// ── Helpers ──────────────────────────────────────────────────────────

/// True iff `issuer_id` (4 bytes BCD-packed, `'F'`-padded to 8 nibbles)
/// matches the leftmost 3-8 digits of `pan` (any-length BCD,
/// `'F'`-padded). Per Book 2 §5.3 step 8.
fn issuer_identifier_matches_pan(issuer_id: &[u8; 4], pan: &[u8]) -> bool {
    let id_digits = match compressed_numeric::decode(issuer_id) {
        Ok(d) => d,
        Err(_) => return false,
    };
    if !(3..=8).contains(&id_digits.len()) {
        return false;
    }
    let pan_digits = match compressed_numeric::decode(pan) {
        Ok(d) => d,
        Err(_) => return false,
    };
    pan_digits.starts_with(&id_digits)
}

/// True iff `app_pan` (10 bytes BCD-packed, `'F'`-padded to 20 nibbles)
/// decodes to the same digit sequence as `pan` (any-length BCD,
/// `'F'`-padded). Per Book 2 §6.4 step 8: the recovered Application
/// PAN must match the PAN read from the ICC exactly, after stripping
/// trailing `'F'` padding.
fn app_pan_matches(app_pan: &[u8; 10], pan: &[u8]) -> bool {
    let app_digits = match compressed_numeric::decode(app_pan) {
        Ok(d) => d,
        Err(_) => return false,
    };
    let pan_digits = match compressed_numeric::decode(pan) {
        Ok(d) => d,
        Err(_) => return false,
    };
    app_digits == pan_digits
}

/// True iff `cert_mmyy` (BCD month / BCD year) is on or after
/// `today_mmyy` (same encoding). Per Book 2 §5.3 step 9 a certificate
/// with expiration "MMYY" remains valid through the last day of that
/// month.
fn mmyy_not_expired(cert_mmyy: [u8; 2], today_mmyy: [u8; 2]) -> bool {
    let cert = (bcd_byte_to_u8(cert_mmyy[1]), bcd_byte_to_u8(cert_mmyy[0]));
    let today = (bcd_byte_to_u8(today_mmyy[1]), bcd_byte_to_u8(today_mmyy[0]));
    cert >= today
}

fn bcd_byte_to_u8(byte: u8) -> u8 {
    (byte >> 4) * 10 + (byte & 0x0F)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build an "identity" CA Public Key: `n = 0xFF × N_CA`, `e = 1`.
    /// `rsa_recover(s, e, n) = s` for any `s` whose first byte is
    /// not `0xFF`. Lets us test the parsing/hash logic without a real
    /// RSA keypair (the recovered X is just the input cert bytes).
    fn identity_ca(n_ca: usize) -> CaPublicKey {
        CaPublicKey {
            rid: [0xA0, 0x00, 0x00, 0x00, 0x03],
            index: 0x01,
            modulus: vec![0xFF; n_ca],
            exponent: vec![1],
        }
    }

    /// Build an Issuer PK Certificate per Table 6 with the layout
    /// already in plaintext form (i.e. what RSA recovery would yield).
    /// Suitable for use as the on-wire certificate when the CA "key"
    /// is the identity key from [`identity_ca`].
    #[allow(clippy::too_many_arguments)]
    fn build_issuer_pk_cert(
        n_ca: usize,
        issuer_id: [u8; 4],
        cert_mmyy: [u8; 2],
        serial: [u8; 3],
        hash_alg: u8,
        pk_alg: u8,
        n_i: usize,
        pk_exp_len: usize,
        issuer_modulus: &[u8],
        issuer_remainder_when_split: Option<&[u8]>,
        issuer_exponent: &[u8],
    ) -> Vec<u8> {
        assert_eq!(issuer_modulus.len(), n_i);
        // Build leftmost-digits field (length n_ca - 36).
        let leftmost_field_len = n_ca - 36;
        let mut leftmost = vec![0xBBu8; leftmost_field_len];
        let leftmost_data_len;
        if n_i <= leftmost_field_len {
            // Full modulus fits - copy it then trailing 'BB' padding.
            leftmost[..n_i].copy_from_slice(issuer_modulus);
            leftmost_data_len = n_i;
        } else {
            // Split case - copy first leftmost_field_len bytes.
            leftmost.copy_from_slice(&issuer_modulus[..leftmost_field_len]);
            leftmost_data_len = leftmost_field_len;
            // The remainder is in tag '92' supplied by the caller.
            assert_eq!(
                issuer_remainder_when_split.unwrap(),
                &issuer_modulus[leftmost_field_len..],
            );
        }
        let _ = leftmost_data_len; // silence unused warning

        // Build the bytes 1..(n_ca - 21) of X, plus what feeds into the hash.
        let mut middle = Vec::new();
        middle.push(0x02); // Cert Format
        middle.extend_from_slice(&issuer_id);
        middle.extend_from_slice(&cert_mmyy);
        middle.extend_from_slice(&serial);
        middle.push(hash_alg);
        middle.push(pk_alg);
        middle.push(n_i as u8);
        middle.push(pk_exp_len as u8);
        middle.extend_from_slice(&leftmost);
        assert_eq!(middle.len(), n_ca - 22);

        // Hash input = middle || (remainder if split) || exponent.
        let mut hasher = Sha1::new();
        hasher.update(&middle);
        if let Some(r) = issuer_remainder_when_split {
            hasher.update(r);
        }
        hasher.update(issuer_exponent);
        let h = hasher.finalize();

        // Assemble X.
        let mut x = Vec::with_capacity(n_ca);
        x.push(0x6A); // header
        x.extend_from_slice(&middle);
        x.extend_from_slice(&h);
        x.push(0xBC); // trailer
        assert_eq!(x.len(), n_ca);
        x
    }

    /// Build SSAD per Table 7, again in plaintext layout suitable for
    /// the identity-key trick.
    fn build_ssad(n_i: usize, hash_alg: u8, dac: [u8; 2], static_data: &[u8]) -> Vec<u8> {
        // X = '6A' || '03' || hash_alg || DAC(2) || 'BB'×(N_I - 26) || H(20) || 'BC'
        let mut middle = Vec::new();
        middle.push(0x03); // Signed Data Format
        middle.push(hash_alg);
        middle.extend_from_slice(&dac);
        middle.extend(std::iter::repeat_n(0xBBu8, n_i - 26));
        assert_eq!(middle.len(), n_i - 22);
        let mut hasher = Sha1::new();
        hasher.update(&middle);
        hasher.update(static_data);
        let h = hasher.finalize();
        let mut x = Vec::with_capacity(n_i);
        x.push(0x6A);
        x.extend_from_slice(&middle);
        x.extend_from_slice(&h);
        x.push(0xBC);
        x
    }

    /// Identity Issuer PK that mirrors the construction in
    /// [`identity_ca`], for the SDA verification step.
    fn identity_issuer_pk(n_i: usize) -> IssuerPublicKey {
        IssuerPublicKey {
            modulus: vec![0xFF; n_i],
            exponent: vec![1],
            hash_algorithm_indicator: 0x01,
            algorithm_indicator: 0x01,
            issuer_identifier: [0x12, 0x34, 0xFF, 0xFF],
            expiration_mmyy: [0x12, 0x99],
            serial_number: [0, 0, 0],
        }
    }

    // ── BCD helpers ──────────────────────────────────────────────────

    #[test]
    fn issuer_id_matches_pan_with_f_padding() {
        // Issuer ID = "1234FFFF", PAN = "1234567890123456FFFF" (10 bytes).
        let issuer_id = [0x12, 0x34, 0xFF, 0xFF];
        let pan = [0x12, 0x34, 0x56, 0x78, 0x90, 0x12, 0x34, 0x56];
        assert!(issuer_identifier_matches_pan(&issuer_id, &pan));
    }

    #[test]
    fn issuer_id_full_8_digits() {
        // Full 8-digit issuer ID, no padding.
        let issuer_id = [0x12, 0x34, 0x56, 0x78];
        let pan = [0x12, 0x34, 0x56, 0x78, 0x90, 0xFF];
        assert!(issuer_identifier_matches_pan(&issuer_id, &pan));
    }

    #[test]
    fn issuer_id_mismatches_pan() {
        let issuer_id = [0x12, 0x34, 0xFF, 0xFF];
        let pan = [0x99, 0x99, 0x99, 0x99];
        assert!(!issuer_identifier_matches_pan(&issuer_id, &pan));
    }

    #[test]
    fn issuer_id_too_few_digits() {
        // Just "12FFFFFF" → 2 digits, below the 3-digit minimum.
        let issuer_id = [0x12, 0xFF, 0xFF, 0xFF];
        let pan = [0x12, 0xFF];
        assert!(!issuer_identifier_matches_pan(&issuer_id, &pan));
    }

    #[test]
    fn mmyy_not_expired_same_month() {
        // Cert exp 03/26, today 03/26 - still valid.
        assert!(mmyy_not_expired([0x03, 0x26], [0x03, 0x26]));
    }

    #[test]
    fn mmyy_not_expired_future() {
        assert!(mmyy_not_expired([0x12, 0x30], [0x03, 0x26]));
    }

    #[test]
    fn mmyy_expired() {
        // Cert exp 03/26, today 04/26 - expired.
        assert!(!mmyy_not_expired([0x03, 0x26], [0x04, 0x26]));
    }

    #[test]
    fn mmyy_expired_year() {
        // Cert exp 12/25, today 01/26 - expired.
        assert!(!mmyy_not_expired([0x12, 0x25], [0x01, 0x26]));
    }

    // ── recover_issuer_public_key ────────────────────────────────────

    #[test]
    fn recover_issuer_pk_happy_path_modulus_fits_in_leftmost() {
        // N_CA = 64, N_I = 24 (≤ N_CA - 36 = 28), so no Remainder
        // tag '92' present.
        let ca = identity_ca(64);
        let issuer_modulus = vec![0x80; 24];
        let issuer_exponent = vec![0x01, 0x00, 0x01];
        let cert = build_issuer_pk_cert(
            64,
            [0x12, 0x34, 0xFF, 0xFF],
            [0x12, 0x99],
            [0xAA, 0xBB, 0xCC],
            0x01,
            0x01,
            24,
            3,
            &issuer_modulus,
            None,
            &issuer_exponent,
        );
        let pan = [0x12, 0x34, 0x56, 0x78, 0xFF, 0xFF];
        let info =
            recover_issuer_public_key(&ca, &cert, None, &issuer_exponent, &pan, [0x01, 0x26])
                .unwrap();
        assert_eq!(info.modulus, issuer_modulus);
        assert_eq!(info.exponent, issuer_exponent);
        assert_eq!(info.issuer_identifier, [0x12, 0x34, 0xFF, 0xFF]);
        assert_eq!(info.serial_number, [0xAA, 0xBB, 0xCC]);
        assert_eq!(info.expiration_mmyy, [0x12, 0x99]);
        assert_eq!(info.hash_algorithm_indicator, 0x01);
        assert_eq!(info.algorithm_indicator, 0x01);
    }

    #[test]
    fn recover_issuer_pk_happy_path_modulus_split_with_remainder() {
        // N_CA = 64, N_I = 64 (> N_CA - 36 = 28), so 36 bytes of
        // remainder go into tag '92'.
        let ca = identity_ca(64);
        let issuer_modulus = vec![0x80; 64];
        let issuer_exponent = vec![0x03];
        let remainder: Vec<u8> = issuer_modulus[28..].to_vec();
        let cert = build_issuer_pk_cert(
            64,
            [0x12, 0x34, 0xFF, 0xFF],
            [0x12, 0x99],
            [0, 0, 0],
            0x01,
            0x01,
            64,
            1,
            &issuer_modulus,
            Some(&remainder),
            &issuer_exponent,
        );
        let pan = [0x12, 0x34, 0xFF, 0xFF];
        let info = recover_issuer_public_key(
            &ca,
            &cert,
            Some(&remainder),
            &issuer_exponent,
            &pan,
            [0x01, 0x26],
        )
        .unwrap();
        assert_eq!(info.modulus, issuer_modulus);
    }

    #[test]
    fn recover_issuer_pk_rejects_bad_header() {
        let ca = identity_ca(64);
        let issuer_modulus = vec![0x80; 24];
        let issuer_exponent = vec![0x03];
        let mut cert = build_issuer_pk_cert(
            64,
            [0x12, 0x34, 0xFF, 0xFF],
            [0x12, 0x99],
            [0, 0, 0],
            0x01,
            0x01,
            24,
            1,
            &issuer_modulus,
            None,
            &issuer_exponent,
        );
        cert[0] = 0x6B; // not '6A'
        let pan = [0x12, 0x34, 0xFF, 0xFF];
        assert_eq!(
            recover_issuer_public_key(&ca, &cert, None, &issuer_exponent, &pan, [0x01, 0x26]),
            Err(Error::InvalidValue),
        );
    }

    #[test]
    fn recover_issuer_pk_rejects_bad_cert_format() {
        let ca = identity_ca(64);
        let issuer_modulus = vec![0x80; 24];
        let issuer_exponent = vec![0x03];
        let mut cert = build_issuer_pk_cert(
            64,
            [0x12, 0x34, 0xFF, 0xFF],
            [0x12, 0x99],
            [0, 0, 0],
            0x01,
            0x01,
            24,
            1,
            &issuer_modulus,
            None,
            &issuer_exponent,
        );
        cert[1] = 0x05; // not '02'
        let pan = [0x12, 0x34, 0xFF, 0xFF];
        assert_eq!(
            recover_issuer_public_key(&ca, &cert, None, &issuer_exponent, &pan, [0x01, 0x26]),
            Err(Error::InvalidValue),
        );
    }

    #[test]
    fn recover_issuer_pk_rejects_corrupted_hash() {
        let ca = identity_ca(64);
        let issuer_modulus = vec![0x80; 24];
        let issuer_exponent = vec![0x03];
        let mut cert = build_issuer_pk_cert(
            64,
            [0x12, 0x34, 0xFF, 0xFF],
            [0x12, 0x99],
            [0, 0, 0],
            0x01,
            0x01,
            24,
            1,
            &issuer_modulus,
            None,
            &issuer_exponent,
        );
        // Hash field is at offset (n_ca - 21)..(n_ca - 1) = 43..63.
        cert[50] ^= 0x01;
        let pan = [0x12, 0x34, 0xFF, 0xFF];
        assert_eq!(
            recover_issuer_public_key(&ca, &cert, None, &issuer_exponent, &pan, [0x01, 0x26]),
            Err(Error::InvalidValue),
        );
    }

    #[test]
    fn recover_issuer_pk_rejects_pan_mismatch() {
        let ca = identity_ca(64);
        let issuer_modulus = vec![0x80; 24];
        let issuer_exponent = vec![0x03];
        let cert = build_issuer_pk_cert(
            64,
            [0x12, 0x34, 0xFF, 0xFF],
            [0x12, 0x99],
            [0, 0, 0],
            0x01,
            0x01,
            24,
            1,
            &issuer_modulus,
            None,
            &issuer_exponent,
        );
        let pan = [0x99, 0x99, 0xFF, 0xFF]; // doesn't start with '1234'
        assert_eq!(
            recover_issuer_public_key(&ca, &cert, None, &issuer_exponent, &pan, [0x01, 0x26]),
            Err(Error::InvalidValue),
        );
    }

    #[test]
    fn recover_issuer_pk_rejects_expired_certificate() {
        let ca = identity_ca(64);
        let issuer_modulus = vec![0x80; 24];
        let issuer_exponent = vec![0x03];
        let cert = build_issuer_pk_cert(
            64,
            [0x12, 0x34, 0xFF, 0xFF],
            [0x03, 0x25], // March 2025
            [0, 0, 0],
            0x01,
            0x01,
            24,
            1,
            &issuer_modulus,
            None,
            &issuer_exponent,
        );
        let pan = [0x12, 0x34, 0xFF, 0xFF];
        // Today: April 2026 - cert is expired.
        assert_eq!(
            recover_issuer_public_key(&ca, &cert, None, &issuer_exponent, &pan, [0x04, 0x26]),
            Err(Error::InvalidValue),
        );
    }

    #[test]
    fn recover_issuer_pk_rejects_length_mismatch() {
        let ca = identity_ca(64);
        let cert = vec![0u8; 32]; // wrong length
        assert_eq!(
            recover_issuer_public_key(&ca, &cert, None, &[0x03], &[0x12, 0x34], [0x01, 0x26]),
            Err(Error::WrongLength {
                expected: 64,
                got: 32
            }),
        );
    }

    #[test]
    fn recover_issuer_pk_rejects_remainder_when_unsplit() {
        // N_I fits - caller wrongly supplies a Remainder.
        let ca = identity_ca(64);
        let issuer_modulus = vec![0x80; 24];
        let issuer_exponent = vec![0x03];
        let cert = build_issuer_pk_cert(
            64,
            [0x12, 0x34, 0xFF, 0xFF],
            [0x12, 0x99],
            [0, 0, 0],
            0x01,
            0x01,
            24,
            1,
            &issuer_modulus,
            None,
            &issuer_exponent,
        );
        let pan = [0x12, 0x34, 0xFF, 0xFF];
        let stray_remainder = vec![0xCC; 4];
        assert_eq!(
            recover_issuer_public_key(
                &ca,
                &cert,
                Some(&stray_remainder),
                &issuer_exponent,
                &pan,
                [0x01, 0x26],
            ),
            Err(Error::InvalidValue),
        );
    }

    #[test]
    fn recover_issuer_pk_rejects_missing_remainder_when_split() {
        // N_I = N_CA, so a Remainder is required.
        let ca = identity_ca(64);
        let issuer_modulus = vec![0x80; 64];
        let issuer_exponent = vec![0x03];
        let remainder: Vec<u8> = issuer_modulus[28..].to_vec();
        let cert = build_issuer_pk_cert(
            64,
            [0x12, 0x34, 0xFF, 0xFF],
            [0x12, 0x99],
            [0, 0, 0],
            0x01,
            0x01,
            64,
            1,
            &issuer_modulus,
            Some(&remainder),
            &issuer_exponent,
        );
        let pan = [0x12, 0x34, 0xFF, 0xFF];
        assert_eq!(
            recover_issuer_public_key(&ca, &cert, None, &issuer_exponent, &pan, [0x01, 0x26]),
            Err(Error::InvalidValue),
        );
    }

    // ── verify_sda ───────────────────────────────────────────────────

    #[test]
    fn verify_sda_happy_path() {
        let pk = identity_issuer_pk(64);
        let static_data = b"AFL records || AIP value goes here";
        let dac = [0xAB, 0xCD];
        let ssad = build_ssad(64, 0x01, dac, static_data);
        let recovered_dac = verify_sda(&pk, &ssad, static_data).unwrap();
        assert_eq!(recovered_dac, dac);
    }

    #[test]
    fn verify_sda_empty_static_data() {
        // Degenerate but valid case (e.g. empty AFL).
        let pk = identity_issuer_pk(64);
        let dac = [0xAB, 0xCD];
        let ssad = build_ssad(64, 0x01, dac, b"");
        assert_eq!(verify_sda(&pk, &ssad, b"").unwrap(), dac);
    }

    #[test]
    fn verify_sda_rejects_modified_static_data() {
        let pk = identity_issuer_pk(64);
        let ssad = build_ssad(64, 0x01, [0xAB, 0xCD], b"original static data");
        assert_eq!(
            verify_sda(&pk, &ssad, b"tampered static data"),
            Err(Error::InvalidValue),
        );
    }

    #[test]
    fn verify_sda_rejects_bad_signed_data_format() {
        let pk = identity_issuer_pk(64);
        let mut ssad = build_ssad(64, 0x01, [0xAB, 0xCD], b"data");
        ssad[1] = 0x02; // not '03'
        assert_eq!(verify_sda(&pk, &ssad, b"data"), Err(Error::InvalidValue));
    }

    #[test]
    fn verify_sda_rejects_bad_pad_pattern() {
        let pk = identity_issuer_pk(64);
        let mut ssad = build_ssad(64, 0x01, [0xAB, 0xCD], b"data");
        // Pad pattern at offset 5..(64-21) = 5..43.
        ssad[10] = 0xCC; // not 'BB'
        assert_eq!(verify_sda(&pk, &ssad, b"data"), Err(Error::InvalidValue));
    }

    #[test]
    fn verify_sda_rejects_length_mismatch() {
        let pk = identity_issuer_pk(64);
        let ssad = vec![0u8; 32]; // wrong length
        assert_eq!(
            verify_sda(&pk, &ssad, b""),
            Err(Error::WrongLength {
                expected: 64,
                got: 32
            }),
        );
    }

    // ── ICC PK recovery + DDA ────────────────────────────────────────

    /// Build an ICC PK Certificate per Table 14, in plaintext layout
    /// suitable for the identity-key trick.
    #[allow(clippy::too_many_arguments)]
    fn build_icc_pk_cert(
        n_i: usize,
        app_pan: [u8; 10],
        cert_mmyy: [u8; 2],
        serial: [u8; 3],
        hash_alg: u8,
        pk_alg: u8,
        n_ic: usize,
        pk_exp_len: usize,
        icc_modulus: &[u8],
        icc_remainder_when_split: Option<&[u8]>,
        icc_exponent: &[u8],
        static_data: &[u8],
    ) -> Vec<u8> {
        assert_eq!(icc_modulus.len(), n_ic);
        let leftmost_field_len = n_i - 42;
        let mut leftmost = vec![0xBBu8; leftmost_field_len];
        if n_ic <= leftmost_field_len {
            leftmost[..n_ic].copy_from_slice(icc_modulus);
        } else {
            leftmost.copy_from_slice(&icc_modulus[..leftmost_field_len]);
            assert_eq!(
                icc_remainder_when_split.unwrap(),
                &icc_modulus[leftmost_field_len..],
            );
        }

        let mut middle = Vec::new();
        middle.push(0x04);
        middle.extend_from_slice(&app_pan);
        middle.extend_from_slice(&cert_mmyy);
        middle.extend_from_slice(&serial);
        middle.push(hash_alg);
        middle.push(pk_alg);
        middle.push(n_ic as u8);
        middle.push(pk_exp_len as u8);
        middle.extend_from_slice(&leftmost);
        assert_eq!(middle.len(), n_i - 22);

        let mut hasher = Sha1::new();
        hasher.update(&middle);
        if let Some(r) = icc_remainder_when_split {
            hasher.update(r);
        }
        hasher.update(icc_exponent);
        hasher.update(static_data);
        let h = hasher.finalize();

        let mut x = Vec::with_capacity(n_i);
        x.push(0x6A);
        x.extend_from_slice(&middle);
        x.extend_from_slice(&h);
        x.push(0xBC);
        assert_eq!(x.len(), n_i);
        x
    }

    /// Build a Signed Dynamic Application Data per Table 17.
    /// `icc_dynamic_data` is the L_DD-byte ICC Dynamic Data field
    /// (which itself starts with the 1-byte length of the ICC Dynamic
    /// Number followed by the value).
    fn build_sdad(n_ic: usize, hash_alg: u8, icc_dynamic_data: &[u8], ddol_data: &[u8]) -> Vec<u8> {
        let l_dd = icc_dynamic_data.len();
        let pad_len = n_ic - l_dd - 25;
        let mut middle = Vec::new();
        middle.push(0x05); // Signed Data Format
        middle.push(hash_alg);
        middle.push(l_dd as u8);
        middle.extend_from_slice(icc_dynamic_data);
        middle.extend(std::iter::repeat_n(0xBBu8, pad_len));
        assert_eq!(middle.len(), n_ic - 22);

        let mut hasher = Sha1::new();
        hasher.update(&middle);
        hasher.update(ddol_data);
        let h = hasher.finalize();

        let mut x = Vec::with_capacity(n_ic);
        x.push(0x6A);
        x.extend_from_slice(&middle);
        x.extend_from_slice(&h);
        x.push(0xBC);
        x
    }

    /// Identity ICC PK matching the `n_ic = 0xFF × N_IC, e = 1` trick.
    fn identity_icc_pk(n_ic: usize) -> IccPublicKey {
        IccPublicKey {
            modulus: vec![0xFF; n_ic],
            exponent: vec![1],
            hash_algorithm_indicator: 0x01,
            algorithm_indicator: 0x01,
            application_pan: [0x12, 0x34, 0x56, 0x78, 0x90, 0x12, 0x34, 0x56, 0x78, 0x9F],
            expiration_mmyy: [0x12, 0x99],
            serial_number: [0, 0, 0],
        }
    }

    #[test]
    fn app_pan_match_strips_f_padding() {
        let app_pan = [0x12, 0x34, 0x56, 0x78, 0x90, 0x12, 0x34, 0x56, 0x78, 0x9F];
        // PAN read from ICC: 19 digits "1234567890123456789", F-padded
        // to 10 bytes (last nibble is F).
        let pan = [0x12, 0x34, 0x56, 0x78, 0x90, 0x12, 0x34, 0x56, 0x78, 0x9F];
        assert!(app_pan_matches(&app_pan, &pan));
    }

    #[test]
    fn app_pan_match_works_for_short_pan() {
        // 7-digit PAN.
        let app_pan = [0x12, 0x34, 0x56, 0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF];
        let pan = [0x12, 0x34, 0x56, 0x7F];
        assert!(app_pan_matches(&app_pan, &pan));
    }

    #[test]
    fn app_pan_mismatch() {
        let app_pan = [0x12, 0x34, 0x56, 0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF];
        let pan = [0x99, 0x99, 0x99, 0x9F];
        assert!(!app_pan_matches(&app_pan, &pan));
    }

    #[test]
    fn recover_icc_pk_happy_path_modulus_fits() {
        // N_I = 80, N_IC = 32 (≤ N_I - 42 = 38), no Remainder.
        let issuer_pk = IssuerPublicKey {
            modulus: vec![0xFF; 80],
            exponent: vec![1],
            hash_algorithm_indicator: 0x01,
            algorithm_indicator: 0x01,
            issuer_identifier: [0x12, 0x34, 0xFF, 0xFF],
            expiration_mmyy: [0x12, 0x99],
            serial_number: [0, 0, 0],
        };
        let app_pan = [0x12, 0x34, 0x56, 0x78, 0x90, 0x12, 0x34, 0x56, 0x78, 0x9F];
        let icc_modulus = vec![0x80; 32];
        let icc_exponent = vec![0x01, 0x00, 0x01];
        let static_data = b"records-by-AFL || AIP";
        let cert = build_icc_pk_cert(
            80,
            app_pan,
            [0x12, 0x99],
            [0xDE, 0xAD, 0xBE],
            0x01,
            0x01,
            32,
            3,
            &icc_modulus,
            None,
            &icc_exponent,
            static_data,
        );
        let icc_pk = recover_icc_public_key(
            &issuer_pk,
            &cert,
            None,
            &icc_exponent,
            static_data,
            &app_pan,
            [0x01, 0x26],
        )
        .unwrap();
        assert_eq!(icc_pk.modulus, icc_modulus);
        assert_eq!(icc_pk.exponent, icc_exponent);
        assert_eq!(icc_pk.application_pan, app_pan);
        assert_eq!(icc_pk.serial_number, [0xDE, 0xAD, 0xBE]);
    }

    #[test]
    fn recover_icc_pk_happy_path_modulus_split_with_remainder() {
        // N_I = 80, N_IC = 64 (> N_I - 42 = 38), so 26-byte remainder.
        let issuer_pk = IssuerPublicKey {
            modulus: vec![0xFF; 80],
            exponent: vec![1],
            hash_algorithm_indicator: 0x01,
            algorithm_indicator: 0x01,
            issuer_identifier: [0x12, 0x34, 0xFF, 0xFF],
            expiration_mmyy: [0x12, 0x99],
            serial_number: [0, 0, 0],
        };
        let app_pan = [0x12, 0x34, 0x56, 0x78, 0x90, 0x12, 0x34, 0x56, 0x78, 0x9F];
        let icc_modulus = vec![0x80; 64];
        let icc_exponent = vec![0x03];
        let remainder: Vec<u8> = icc_modulus[38..].to_vec();
        let cert = build_icc_pk_cert(
            80,
            app_pan,
            [0x12, 0x99],
            [0, 0, 0],
            0x01,
            0x01,
            64,
            1,
            &icc_modulus,
            Some(&remainder),
            &icc_exponent,
            b"static",
        );
        let icc_pk = recover_icc_public_key(
            &issuer_pk,
            &cert,
            Some(&remainder),
            &icc_exponent,
            b"static",
            &app_pan,
            [0x01, 0x26],
        )
        .unwrap();
        assert_eq!(icc_pk.modulus, icc_modulus);
    }

    #[test]
    fn recover_icc_pk_rejects_bad_format_byte() {
        let issuer_pk = IssuerPublicKey {
            modulus: vec![0xFF; 80],
            exponent: vec![1],
            hash_algorithm_indicator: 0x01,
            algorithm_indicator: 0x01,
            issuer_identifier: [0x12, 0x34, 0xFF, 0xFF],
            expiration_mmyy: [0x12, 0x99],
            serial_number: [0, 0, 0],
        };
        let app_pan = [0x12, 0x34, 0x56, 0x78, 0x90, 0x12, 0x34, 0x56, 0x78, 0x9F];
        let icc_modulus = vec![0x80; 32];
        let icc_exponent = vec![0x03];
        let mut cert = build_icc_pk_cert(
            80,
            app_pan,
            [0x12, 0x99],
            [0, 0, 0],
            0x01,
            0x01,
            32,
            1,
            &icc_modulus,
            None,
            &icc_exponent,
            b"",
        );
        cert[1] = 0x02; // not '04' - Issuer cert format, not ICC.
        assert_eq!(
            recover_icc_public_key(
                &issuer_pk,
                &cert,
                None,
                &icc_exponent,
                b"",
                &app_pan,
                [0x01, 0x26],
            ),
            Err(Error::InvalidValue),
        );
    }

    #[test]
    fn recover_icc_pk_rejects_pan_mismatch() {
        let issuer_pk = IssuerPublicKey {
            modulus: vec![0xFF; 80],
            exponent: vec![1],
            hash_algorithm_indicator: 0x01,
            algorithm_indicator: 0x01,
            issuer_identifier: [0x12, 0x34, 0xFF, 0xFF],
            expiration_mmyy: [0x12, 0x99],
            serial_number: [0, 0, 0],
        };
        let app_pan = [0x12, 0x34, 0x56, 0x78, 0x90, 0x12, 0x34, 0x56, 0x78, 0x9F];
        let icc_modulus = vec![0x80; 32];
        let icc_exponent = vec![0x03];
        let cert = build_icc_pk_cert(
            80,
            app_pan,
            [0x12, 0x99],
            [0, 0, 0],
            0x01,
            0x01,
            32,
            1,
            &icc_modulus,
            None,
            &icc_exponent,
            b"",
        );
        let wrong_pan = [0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x9F];
        assert_eq!(
            recover_icc_public_key(
                &issuer_pk,
                &cert,
                None,
                &icc_exponent,
                b"",
                &wrong_pan,
                [0x01, 0x26],
            ),
            Err(Error::InvalidValue),
        );
    }

    #[test]
    fn recover_icc_pk_rejects_modified_static_data() {
        let issuer_pk = IssuerPublicKey {
            modulus: vec![0xFF; 80],
            exponent: vec![1],
            hash_algorithm_indicator: 0x01,
            algorithm_indicator: 0x01,
            issuer_identifier: [0x12, 0x34, 0xFF, 0xFF],
            expiration_mmyy: [0x12, 0x99],
            serial_number: [0, 0, 0],
        };
        let app_pan = [0x12, 0x34, 0x56, 0x78, 0x90, 0x12, 0x34, 0x56, 0x78, 0x9F];
        let icc_modulus = vec![0x80; 32];
        let icc_exponent = vec![0x03];
        let cert = build_icc_pk_cert(
            80,
            app_pan,
            [0x12, 0x99],
            [0, 0, 0],
            0x01,
            0x01,
            32,
            1,
            &icc_modulus,
            None,
            &icc_exponent,
            b"original static",
        );
        // Hash was over "original static" - supplying "different"
        // here changes the hash input → should fail.
        assert_eq!(
            recover_icc_public_key(
                &issuer_pk,
                &cert,
                None,
                &icc_exponent,
                b"different static",
                &app_pan,
                [0x01, 0x26],
            ),
            Err(Error::InvalidValue),
        );
    }

    #[test]
    fn recover_icc_pk_rejects_length_mismatch() {
        let issuer_pk = IssuerPublicKey {
            modulus: vec![0xFF; 80],
            exponent: vec![1],
            hash_algorithm_indicator: 0x01,
            algorithm_indicator: 0x01,
            issuer_identifier: [0x12, 0x34, 0xFF, 0xFF],
            expiration_mmyy: [0x12, 0x99],
            serial_number: [0, 0, 0],
        };
        let cert = vec![0u8; 32]; // wrong length
        assert_eq!(
            recover_icc_public_key(
                &issuer_pk,
                &cert,
                None,
                &[0x03],
                b"",
                &[0x12, 0x34, 0x56, 0x78, 0x90, 0x12, 0x34, 0x56, 0x78, 0x9F],
                [0x01, 0x26],
            ),
            Err(Error::WrongLength {
                expected: 80,
                got: 32
            }),
        );
    }

    #[test]
    fn verify_dda_happy_path() {
        let icc_pk = identity_icc_pk(64);
        // ICC Dynamic Data: 1-byte length + 4-byte ICC Dynamic Number
        // + nothing else (L_DD = 5).
        let icc_dynamic_data = vec![4, 0xCA, 0xFE, 0xBA, 0xBE];
        let ddol_data = b"\x9F\x37\x04UNPR";
        let sdad = build_sdad(64, 0x01, &icc_dynamic_data, ddol_data);
        let recovered = verify_dda(&icc_pk, &sdad, ddol_data).unwrap();
        assert_eq!(recovered, vec![0xCA, 0xFE, 0xBA, 0xBE]);
    }

    #[test]
    fn verify_dda_extracts_2_byte_minimum_dyn_number() {
        let icc_pk = identity_icc_pk(64);
        let icc_dynamic_data = vec![2, 0x12, 0x34];
        let sdad = build_sdad(64, 0x01, &icc_dynamic_data, b"");
        assert_eq!(verify_dda(&icc_pk, &sdad, b"").unwrap(), vec![0x12, 0x34]);
    }

    #[test]
    fn verify_dda_extracts_8_byte_maximum_dyn_number() {
        let icc_pk = identity_icc_pk(64);
        let dn = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
        let mut icc_dynamic_data = vec![8u8];
        icc_dynamic_data.extend_from_slice(&dn);
        let sdad = build_sdad(64, 0x01, &icc_dynamic_data, b"");
        assert_eq!(verify_dda(&icc_pk, &sdad, b"").unwrap(), dn.to_vec());
    }

    #[test]
    fn verify_dda_dynamic_data_with_proprietary_suffix() {
        // ICC Dynamic Data may extend beyond the 3-9 leftmost bytes.
        // The recovered Dynamic Number is just the first L bytes after
        // the length byte; trailing data is preserved in the ICC
        // Dynamic Data field but not returned here.
        let icc_pk = identity_icc_pk(64);
        let mut icc_dynamic_data = vec![3, 0xAA, 0xBB, 0xCC]; // dn length 3
        icc_dynamic_data.extend_from_slice(b"proprietary trailing data");
        let sdad = build_sdad(64, 0x01, &icc_dynamic_data, b"");
        assert_eq!(
            verify_dda(&icc_pk, &sdad, b"").unwrap(),
            vec![0xAA, 0xBB, 0xCC],
        );
    }

    #[test]
    fn verify_dda_rejects_bad_signed_data_format() {
        let icc_pk = identity_icc_pk(64);
        let icc_dynamic_data = vec![4, 0xCA, 0xFE, 0xBA, 0xBE];
        let mut sdad = build_sdad(64, 0x01, &icc_dynamic_data, b"");
        sdad[1] = 0x03; // not '05' - would be SAD format.
        assert_eq!(verify_dda(&icc_pk, &sdad, b""), Err(Error::InvalidValue));
    }

    #[test]
    fn verify_dda_rejects_bad_pad_pattern() {
        let icc_pk = identity_icc_pk(64);
        let icc_dynamic_data = vec![4, 0xCA, 0xFE, 0xBA, 0xBE];
        let mut sdad = build_sdad(64, 0x01, &icc_dynamic_data, b"");
        // Corrupt one pad byte. Pad pattern starts at offset 1 + 1 +
        // 1 + 1 + L_DD = 8, ends at offset N_IC - 21 = 43.
        sdad[10] = 0xCC;
        assert_eq!(verify_dda(&icc_pk, &sdad, b""), Err(Error::InvalidValue));
    }

    #[test]
    fn verify_dda_rejects_modified_ddol_data() {
        let icc_pk = identity_icc_pk(64);
        let icc_dynamic_data = vec![4, 0xCA, 0xFE, 0xBA, 0xBE];
        let sdad = build_sdad(64, 0x01, &icc_dynamic_data, b"original UN");
        // Hash was over msg1 || "original UN"; verifying with
        // "modified UN" → hash mismatch.
        assert_eq!(
            verify_dda(&icc_pk, &sdad, b"modified UN"),
            Err(Error::InvalidValue),
        );
    }

    #[test]
    fn verify_dda_rejects_dn_length_too_small() {
        let icc_pk = identity_icc_pk(64);
        // Dynamic Number length = 1 (below the spec minimum of 2).
        let icc_dynamic_data = vec![1, 0xAA];
        let sdad = build_sdad(64, 0x01, &icc_dynamic_data, b"");
        assert_eq!(verify_dda(&icc_pk, &sdad, b""), Err(Error::InvalidValue));
    }

    #[test]
    fn verify_dda_rejects_dn_length_too_large() {
        let icc_pk = identity_icc_pk(64);
        // Dynamic Number length = 9 (above the spec maximum of 8).
        let mut icc_dynamic_data = vec![9u8];
        icc_dynamic_data.extend_from_slice(&[0xAA; 9]);
        let sdad = build_sdad(64, 0x01, &icc_dynamic_data, b"");
        assert_eq!(verify_dda(&icc_pk, &sdad, b""), Err(Error::InvalidValue));
    }

    #[test]
    fn verify_dda_rejects_length_mismatch() {
        let icc_pk = identity_icc_pk(64);
        let sdad = vec![0u8; 32]; // wrong length
        assert_eq!(
            verify_dda(&icc_pk, &sdad, b""),
            Err(Error::WrongLength {
                expected: 64,
                got: 32
            }),
        );
    }

    // ── verify_cda ───────────────────────────────────────────────────

    /// Build a Table 19 ICC Dynamic Data structure.
    fn build_table19(
        dn: &[u8],
        cid: u8,
        ac: [u8; 8],
        tx_hash: [u8; 20],
        proprietary: &[u8],
    ) -> Vec<u8> {
        let mut v = Vec::with_capacity(1 + dn.len() + 1 + 8 + 20 + proprietary.len());
        v.push(dn.len() as u8);
        v.extend_from_slice(dn);
        v.push(cid);
        v.extend_from_slice(&ac);
        v.extend_from_slice(&tx_hash);
        v.extend_from_slice(proprietary);
        v
    }

    /// Build a CDA Signed Dynamic Application Data per Table 22, in
    /// plaintext layout suitable for the identity-key trick.
    fn build_cda_sdad(
        n_ic: usize,
        hash_alg: u8,
        icc_dynamic_data: &[u8],
        unpredictable_number: [u8; 4],
    ) -> Vec<u8> {
        // Same outer layout as build_sdad, but msg2 (hashed appendix)
        // is the 4-byte UN rather than full DDOL data.
        let l_dd = icc_dynamic_data.len();
        let pad_len = n_ic - l_dd - 25;
        let mut middle = Vec::new();
        middle.push(0x05);
        middle.push(hash_alg);
        middle.push(l_dd as u8);
        middle.extend_from_slice(icc_dynamic_data);
        middle.extend(std::iter::repeat_n(0xBBu8, pad_len));
        assert_eq!(middle.len(), n_ic - 22);

        let mut hasher = Sha1::new();
        hasher.update(&middle);
        hasher.update(unpredictable_number);
        let h = hasher.finalize();

        let mut x = Vec::with_capacity(n_ic);
        x.push(0x6A);
        x.extend_from_slice(&middle);
        x.extend_from_slice(&h);
        x.push(0xBC);
        x
    }

    fn sha1_of(data: &[u8]) -> [u8; 20] {
        let mut h = Sha1::new();
        h.update(data);
        h.finalize().into()
    }

    #[test]
    fn verify_cda_happy_path() {
        let icc_pk = identity_icc_pk(128);
        let un = [0x11, 0x22, 0x33, 0x44];
        let tx_data = b"PDOL || CDOL1 || response TLVs without 9F4B";
        let dn = [0xAA, 0xBB, 0xCC, 0xDD];
        let cid: u8 = 0x40; // TC
        let ac = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
        let icc_dynamic_data = build_table19(&dn, cid, ac, sha1_of(tx_data), &[]);
        let sdad = build_cda_sdad(128, 0x01, &icc_dynamic_data, un);

        let result = verify_cda(&icc_pk, &sdad, un, tx_data, cid).unwrap();
        assert_eq!(result.icc_dynamic_number, dn);
        assert_eq!(result.application_cryptogram, ac);
    }

    #[test]
    fn verify_cda_min_dn_length_2() {
        let icc_pk = identity_icc_pk(128);
        let un = [0; 4];
        let tx_data = b"";
        let dn = [0x12, 0x34];
        let cid: u8 = 0x80; // ARQC
        let ac = [0x55; 8];
        let dyn_data = build_table19(&dn, cid, ac, sha1_of(tx_data), &[]);
        let sdad = build_cda_sdad(128, 0x01, &dyn_data, un);

        let result = verify_cda(&icc_pk, &sdad, un, tx_data, cid).unwrap();
        assert_eq!(result.icc_dynamic_number, dn);
    }

    #[test]
    fn verify_cda_max_dn_length_8() {
        let icc_pk = identity_icc_pk(128);
        let un = [0; 4];
        let tx_data = b"x";
        let dn = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
        let cid: u8 = 0x40;
        let ac = [0xFF; 8];
        let dyn_data = build_table19(&dn, cid, ac, sha1_of(tx_data), &[]);
        let sdad = build_cda_sdad(128, 0x01, &dyn_data, un);

        let result = verify_cda(&icc_pk, &sdad, un, tx_data, cid).unwrap();
        assert_eq!(result.icc_dynamic_number, dn);
    }

    #[test]
    fn verify_cda_accepts_proprietary_trailing_bytes() {
        // §6.6.1 / Table 18: L_DD may be larger than 32-38; the
        // structure in Table 19 only describes the *leftmost* bytes.
        let icc_pk = identity_icc_pk(128);
        let un = [0; 4];
        let tx_data = b"";
        let dn = [0x12, 0x34, 0x56, 0x78];
        let cid: u8 = 0x40;
        let ac = [0x77; 8];
        let proprietary = b"\xCA\xFE\xBA\xBE proprietary";
        let dyn_data = build_table19(&dn, cid, ac, sha1_of(tx_data), proprietary);
        let sdad = build_cda_sdad(128, 0x01, &dyn_data, un);

        let result = verify_cda(&icc_pk, &sdad, un, tx_data, cid).unwrap();
        assert_eq!(result.icc_dynamic_number, dn);
        assert_eq!(result.application_cryptogram, ac);
    }

    #[test]
    fn verify_cda_rejects_bad_signed_data_format() {
        let icc_pk = identity_icc_pk(128);
        let un = [0; 4];
        let dyn_data = build_table19(&[0xAA, 0xBB], 0x40, [0; 8], sha1_of(b""), &[]);
        let mut sdad = build_cda_sdad(128, 0x01, &dyn_data, un);
        sdad[2] = 0x06; // not '05'
        // Patching the format byte invalidates the inner hash, so the
        // signature check fails before the format-byte check - either
        // outcome is a structural rejection.
        assert_eq!(
            verify_cda(&icc_pk, &sdad, un, b"", 0x40),
            Err(Error::InvalidValue),
        );
    }

    #[test]
    fn verify_cda_rejects_bad_pad_pattern() {
        let icc_pk = identity_icc_pk(128);
        let un = [0; 4];
        let dyn_data = build_table19(&[0xAA, 0xBB], 0x40, [0; 8], sha1_of(b""), &[]);
        let mut sdad = build_cda_sdad(128, 0x01, &dyn_data, un);
        // Find a pad byte near the end of msg1 and corrupt it.
        // msg1 ends at offset (n_ic - 21); pad runs up to that.
        sdad[100] = 0x00;
        assert_eq!(
            verify_cda(&icc_pk, &sdad, un, b"", 0x40),
            Err(Error::InvalidValue),
        );
    }

    #[test]
    fn verify_cda_rejects_modified_unpredictable_number() {
        let icc_pk = identity_icc_pk(128);
        let un = [0x11, 0x22, 0x33, 0x44];
        let tx_data = b"";
        let dyn_data = build_table19(&[0xAA, 0xBB], 0x40, [0; 8], sha1_of(tx_data), &[]);
        let sdad = build_cda_sdad(128, 0x01, &dyn_data, un);
        // Card signed with `un`; terminal verifies with a different UN.
        let bad_un = [0xFF; 4];
        assert_eq!(
            verify_cda(&icc_pk, &sdad, bad_un, tx_data, 0x40),
            Err(Error::InvalidValue),
        );
    }

    #[test]
    fn verify_cda_rejects_modified_transaction_data() {
        let icc_pk = identity_icc_pk(128);
        let un = [0; 4];
        let signed_tx_data = b"original";
        let dyn_data = build_table19(&[0xAA, 0xBB], 0x40, [0; 8], sha1_of(signed_tx_data), &[]);
        let sdad = build_cda_sdad(128, 0x01, &dyn_data, un);
        assert_eq!(
            verify_cda(&icc_pk, &sdad, un, b"modified", 0x40),
            Err(Error::InvalidValue),
        );
    }

    #[test]
    fn verify_cda_rejects_cid_mismatch() {
        let icc_pk = identity_icc_pk(128);
        let un = [0; 4];
        let tx_data = b"";
        // CID embedded in signature is 0x40 (TC); terminal expects
        // 0x80 (ARQC) from the cleartext response.
        let dyn_data = build_table19(&[0xAA, 0xBB], 0x40, [0; 8], sha1_of(tx_data), &[]);
        let sdad = build_cda_sdad(128, 0x01, &dyn_data, un);
        assert_eq!(
            verify_cda(&icc_pk, &sdad, un, tx_data, 0x80),
            Err(Error::InvalidValue),
        );
    }

    #[test]
    fn verify_cda_rejects_dn_length_too_small() {
        let icc_pk = identity_icc_pk(128);
        let un = [0; 4];
        // dn_len = 1 (below the spec minimum of 2).
        let mut dyn_data = vec![1u8, 0xAA];
        dyn_data.push(0x40); // CID
        dyn_data.extend_from_slice(&[0u8; 8]); // AC
        dyn_data.extend_from_slice(&sha1_of(b"")); // tx hash
        let sdad = build_cda_sdad(128, 0x01, &dyn_data, un);
        assert_eq!(
            verify_cda(&icc_pk, &sdad, un, b"", 0x40),
            Err(Error::InvalidValue),
        );
    }

    #[test]
    fn verify_cda_rejects_dn_length_too_large() {
        let icc_pk = identity_icc_pk(128);
        let un = [0; 4];
        // dn_len = 9 (above the spec maximum of 8).
        let mut dyn_data = vec![9u8];
        dyn_data.extend_from_slice(&[0xAA; 9]);
        dyn_data.push(0x40);
        dyn_data.extend_from_slice(&[0u8; 8]);
        dyn_data.extend_from_slice(&sha1_of(b""));
        let sdad = build_cda_sdad(128, 0x01, &dyn_data, un);
        assert_eq!(
            verify_cda(&icc_pk, &sdad, un, b"", 0x40),
            Err(Error::InvalidValue),
        );
    }

    #[test]
    fn verify_cda_rejects_truncated_table19() {
        let icc_pk = identity_icc_pk(128);
        let un = [0; 4];
        // dn_len claims 4 but icc_dynamic_data is only 1+4+1+4 = 10
        // bytes long - well short of the 32 needed for full Table 19.
        let mut dyn_data = vec![4u8];
        dyn_data.extend_from_slice(&[0xAA; 4]);
        dyn_data.push(0x40);
        dyn_data.extend_from_slice(&[0u8; 4]);
        let sdad = build_cda_sdad(128, 0x01, &dyn_data, un);
        assert_eq!(
            verify_cda(&icc_pk, &sdad, un, b"", 0x40),
            Err(Error::InvalidValue),
        );
    }

    #[test]
    fn verify_cda_rejects_length_mismatch() {
        let icc_pk = identity_icc_pk(128);
        let sdad = vec![0u8; 64]; // not equal to N_IC = 128
        assert_eq!(
            verify_cda(&icc_pk, &sdad, [0; 4], b"", 0x40),
            Err(Error::WrongLength {
                expected: 128,
                got: 64
            }),
        );
    }
}
