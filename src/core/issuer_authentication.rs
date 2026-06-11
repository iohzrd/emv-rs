//! Book 2 §8.2 - Issuer Authentication (ARPC) primitives.

use crate::core::aes_primitives::{aes_cmac_truncated, aes_encrypt_block};
use crate::core::error::{Error, Result};
use crate::core::secure_messaging::{mac_truncated, tdes_encrypt_block};

/// Compute an 8-byte ARPC using ARPC Method 1 (Triple-DES) per
/// Book 2 §8.2.1.
///
/// `arc` is the 2-byte Authorisation Response Code (the issuer's
/// `'00'`/`'01'`/etc. action code as defined per payment system).
///
/// ```text
///   Y = ARQC ⊕ (ARC || '00' × 6)
///   ARPC = TDES_EDE(SK_AC)[Y]
/// ```
pub fn arpc_method1(arqc: [u8; 8], arc: [u8; 2], sk_ac: &[u8; 16]) -> [u8; 8] {
    let mut y = [0u8; 8];
    y[0] = arqc[0] ^ arc[0];
    y[1] = arqc[1] ^ arc[1];
    // bytes 2..8: ARQC[i] ⊕ 0x00 = ARQC[i].
    y[2..].copy_from_slice(&arqc[2..]);
    tdes_encrypt_block(sk_ac, y)
}

/// Compute the 4-byte ARPC using ARPC Method 2 (Triple-DES) per
/// Book 2 §8.2.2.
///
/// `pcad` is the 0-8 byte Proprietary Authentication Data - `&[]` if
/// the issuer does not return one. `csu` is the 4-byte binary Card
/// Status Update.
///
/// ```text
///   Y = ARQC || CSU || PCAD
///   ARPC = leftmost 4 bytes of Retail MAC(SK_AC)[Y]   (s = 4)
/// ```
///
/// Errors:
///
/// - `InvalidValue` if `pcad.len() > 8`.
pub fn arpc_method2(arqc: [u8; 8], csu: [u8; 4], pcad: &[u8], sk_ac: &[u8; 16]) -> Result<[u8; 4]> {
    if pcad.len() > 8 {
        return Err(Error::InvalidValue);
    }
    let mut y = Vec::with_capacity(8 + 4 + pcad.len());
    y.extend_from_slice(&arqc);
    y.extend_from_slice(&csu);
    y.extend_from_slice(pcad);
    let mac = mac_truncated(sk_ac, &y, 4)?;
    let mut arpc = [0u8; 4];
    arpc.copy_from_slice(&mac);
    Ok(arpc)
}

/// AES variant of [`arpc_method1`] per Book 2 §8.2.1 final paragraph:
///
/// ```text
///   Y = ARQC ⊕ (ARC || '00' × 6)         (same as TDES)
///   ARPC = leftmost 8 bytes of AES(SK_AC)[Y || '00' × 8]
/// ```
///
/// `sk_ac` is the AES Application Cryptogram Session Key - 16, 24,
/// or 32 bytes for AES-128/192/256 respectively. Errors with
/// `InvalidValue` for any other key length.
pub fn arpc_method1_aes(arqc: [u8; 8], arc: [u8; 2], sk_ac: &[u8]) -> Result<[u8; 8]> {
    let mut y_padded = [0u8; 16];
    y_padded[0] = arqc[0] ^ arc[0];
    y_padded[1] = arqc[1] ^ arc[1];
    y_padded[2..8].copy_from_slice(&arqc[2..]);
    // bytes 8..16 are the trailing zero pad Y_0.
    let block = aes_encrypt_block(sk_ac, y_padded)?;
    let mut arpc = [0u8; 8];
    arpc.copy_from_slice(&block[..8]);
    Ok(arpc)
}

/// AES variant of [`arpc_method2`] per Book 2 §8.2.2 final paragraph:
///
/// ```text
///   Y = ARQC || CSU || PCAD              (same as TDES)
///   ARPC = leftmost 4 bytes of CMAC(SK_AC)[Y]   (s = 4)
/// ```
///
/// `sk_ac` is the AES Application Cryptogram Session Key - 16, 24,
/// or 32 bytes for AES-128/192/256 respectively.
///
/// Errors:
///
/// - `InvalidValue` if `pcad.len() > 8` or `sk_ac.len()` is not 16,
///   24, or 32.
pub fn arpc_method2_aes(arqc: [u8; 8], csu: [u8; 4], pcad: &[u8], sk_ac: &[u8]) -> Result<[u8; 4]> {
    if pcad.len() > 8 {
        return Err(Error::InvalidValue);
    }
    let mut y = Vec::with_capacity(8 + 4 + pcad.len());
    y.extend_from_slice(&arqc);
    y.extend_from_slice(&csu);
    y.extend_from_slice(pcad);
    let mac = aes_cmac_truncated(sk_ac, &y, 4)?;
    let mut arpc = [0u8; 4];
    arpc.copy_from_slice(&mac);
    Ok(arpc)
}

/// Build the Issuer Authentication Data (tag `'91'`) for ARPC
/// Method 2 per §8.2.2 step 3:
///
/// ```text
///   IAD = ARPC || CSU || PCAD
/// ```
///
/// The result has length `8 + pcad.len()` bytes (8 to 16). It is
/// the value field of tag `'91'` and the data field for EXTERNAL
/// AUTHENTICATE per Book 3 §6.5.4 (built via
/// [`crate::online_processing::external_authenticate`]).
///
/// Errors:
///
/// - `InvalidValue` if `pcad.len() > 8`.
pub fn issuer_authentication_data_method2(
    arpc: [u8; 4],
    csu: [u8; 4],
    pcad: &[u8],
) -> Result<Vec<u8>> {
    if pcad.len() > 8 {
        return Err(Error::InvalidValue);
    }
    let mut iad = Vec::with_capacity(8 + pcad.len());
    iad.extend_from_slice(&arpc);
    iad.extend_from_slice(&csu);
    iad.extend_from_slice(pcad);
    Ok(iad)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::secure_messaging::{pad_iso9797_method2, retail_mac_no_pad};

    // ── Method 1 ─────────────────────────────────────────────────────

    #[test]
    fn arpc_method1_xor_then_tdes_encrypt() {
        let arqc = [0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE];
        let arc = [0x00, 0x10]; // example ARC value
        let sk_ac = [
            0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54,
            0x32, 0x10,
        ];
        // Recompute by hand: Y = ARQC ⊕ (ARC || zeros).
        let y = [
            arqc[0] ^ arc[0],
            arqc[1] ^ arc[1],
            arqc[2],
            arqc[3],
            arqc[4],
            arqc[5],
            arqc[6],
            arqc[7],
        ];
        let expected = tdes_encrypt_block(&sk_ac, y);
        assert_eq!(arpc_method1(arqc, arc, &sk_ac), expected);
    }

    #[test]
    fn arpc_method1_zero_arc_returns_tdes_of_arqc() {
        // ARC = 00 00 → Y = ARQC, so ARPC = TDES(ARQC).
        let arqc = [1, 2, 3, 4, 5, 6, 7, 8];
        let sk_ac = [0xAA; 16];
        let expected = tdes_encrypt_block(&sk_ac, arqc);
        assert_eq!(arpc_method1(arqc, [0, 0], &sk_ac), expected);
    }

    #[test]
    fn arpc_method1_arc_xors_only_top_two_bytes() {
        // Differing ARC values change only bytes 0 and 1 of Y.
        let arqc = [0x10; 8];
        let sk_ac = [0xAA; 16];
        let a = arpc_method1(arqc, [0x00, 0x00], &sk_ac);
        let b = arpc_method1(arqc, [0x01, 0x00], &sk_ac);
        let c = arpc_method1(arqc, [0x00, 0x01], &sk_ac);
        // All three should differ.
        assert_ne!(a, b);
        assert_ne!(a, c);
        assert_ne!(b, c);
    }

    #[test]
    fn arpc_method1_changes_with_session_key() {
        // 0xAA and 0x54 differ in every bit → distinct DES keys.
        let arqc = [1, 2, 3, 4, 5, 6, 7, 8];
        let arc = [0x00, 0x00];
        let a = arpc_method1(arqc, arc, &[0xAA; 16]);
        let b = arpc_method1(arqc, arc, &[0x54; 16]);
        assert_ne!(a, b);
    }

    // ── Method 2 ─────────────────────────────────────────────────────

    #[test]
    fn arpc_method2_matches_retail_mac_first_4_bytes() {
        let arqc = [0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE];
        let csu = [0x00, 0x10, 0x20, 0x30];
        let pcad = [0x01, 0x02];
        let sk_ac = [
            0xAB, 0xCD, 0xEF, 0x01, 0x23, 0x45, 0x67, 0x89, 0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC,
            0xDE, 0xF0,
        ];
        // Expected: leftmost 4 bytes of Retail MAC over ARQC||CSU||PCAD.
        let mut y = Vec::new();
        y.extend_from_slice(&arqc);
        y.extend_from_slice(&csu);
        y.extend_from_slice(&pcad);
        let padded = pad_iso9797_method2(&y, 8);
        let full = retail_mac_no_pad(&sk_ac, &padded).unwrap();

        let arpc = arpc_method2(arqc, csu, &pcad, &sk_ac).unwrap();
        assert_eq!(&arpc[..], &full[..4]);
    }

    #[test]
    fn arpc_method2_no_pcad() {
        let arqc = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88];
        let csu = [0xAA, 0xBB, 0xCC, 0xDD];
        let sk_ac = [0x42; 16];
        // With empty PCAD, Y = ARQC || CSU = 12 bytes.
        let arpc = arpc_method2(arqc, csu, &[], &sk_ac).unwrap();
        let mut y = Vec::new();
        y.extend_from_slice(&arqc);
        y.extend_from_slice(&csu);
        let full = retail_mac_no_pad(&sk_ac, &pad_iso9797_method2(&y, 8)).unwrap();
        assert_eq!(&arpc[..], &full[..4]);
    }

    #[test]
    fn arpc_method2_max_8_byte_pcad_accepted() {
        let pcad = [0u8; 8];
        let result = arpc_method2([0; 8], [0; 4], &pcad, &[0xAA; 16]);
        assert!(result.is_ok());
    }

    #[test]
    fn arpc_method2_rejects_pcad_over_8_bytes() {
        // 9-byte PCAD exceeds the spec maximum.
        let pcad = [0u8; 9];
        let result = arpc_method2([0; 8], [0; 4], &pcad, &[0xAA; 16]);
        assert_eq!(result, Err(Error::InvalidValue));
    }

    #[test]
    fn arpc_method2_changes_with_csu() {
        let arqc = [0x11; 8];
        let sk_ac = [0xAA; 16];
        let a = arpc_method2(arqc, [0; 4], &[], &sk_ac).unwrap();
        let b = arpc_method2(arqc, [0xFF; 4], &[], &sk_ac).unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn arpc_method2_changes_with_pcad() {
        let arqc = [0x11; 8];
        let csu = [0x10; 4];
        let sk_ac = [0xAA; 16];
        let a = arpc_method2(arqc, csu, &[], &sk_ac).unwrap();
        let b = arpc_method2(arqc, csu, &[0x01], &sk_ac).unwrap();
        let c = arpc_method2(arqc, csu, &[0x02], &sk_ac).unwrap();
        assert_ne!(a, b);
        assert_ne!(a, c);
        assert_ne!(b, c);
    }

    // ── Method 1 AES ─────────────────────────────────────────────────

    #[test]
    fn arpc_method1_aes_is_first_8_bytes_of_aes_y_padded() {
        use crate::core::aes_primitives::aes_encrypt_block;
        let arqc = [0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE];
        let arc = [0x00, 0x10];
        let sk_ac = [0xAA; 16];
        // Manual: build Y = ARQC ⊕ (ARC || 0×6), pad with 0×8.
        let mut y_padded = [0u8; 16];
        y_padded[0] = arqc[0] ^ arc[0];
        y_padded[1] = arqc[1] ^ arc[1];
        y_padded[2..8].copy_from_slice(&arqc[2..]);
        let block = aes_encrypt_block(&sk_ac, y_padded).unwrap();
        let expected: [u8; 8] = block[..8].try_into().unwrap();
        assert_eq!(arpc_method1_aes(arqc, arc, &sk_ac).unwrap(), expected);
    }

    #[test]
    fn arpc_method1_aes_supports_all_three_key_sizes() {
        let arqc = [1, 2, 3, 4, 5, 6, 7, 8];
        let arc = [0x00, 0x10];
        let a128 = arpc_method1_aes(arqc, arc, &[0xAA; 16]).unwrap();
        let a192 = arpc_method1_aes(arqc, arc, &[0xAA; 24]).unwrap();
        let a256 = arpc_method1_aes(arqc, arc, &[0xAA; 32]).unwrap();
        assert_ne!(a128, a192);
        assert_ne!(a128, a256);
        assert_ne!(a192, a256);
    }

    #[test]
    fn arpc_method1_aes_rejects_bad_key_length() {
        let arqc = [0; 8];
        assert!(arpc_method1_aes(arqc, [0; 2], &[0; 8]).is_err());
        assert!(arpc_method1_aes(arqc, [0; 2], &[0; 17]).is_err());
    }

    #[test]
    fn arpc_method1_aes_differs_from_tdes() {
        let arqc = [0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE];
        let arc = [0x00, 0x10];
        let key = [0xAA; 16];
        let tdes = arpc_method1(arqc, arc, &key);
        let aes = arpc_method1_aes(arqc, arc, &key).unwrap();
        assert_ne!(tdes, aes);
    }

    // ── Method 2 AES ─────────────────────────────────────────────────

    #[test]
    fn arpc_method2_aes_matches_aes_cmac_first_4_bytes() {
        use crate::core::aes_primitives::aes_cmac_truncated;
        let arqc = [0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE];
        let csu = [0x00, 0x10, 0x20, 0x30];
        let pcad = [0x01, 0x02];
        let sk_ac = [0xAB; 16];
        let mut y = Vec::new();
        y.extend_from_slice(&arqc);
        y.extend_from_slice(&csu);
        y.extend_from_slice(&pcad);
        let expected = aes_cmac_truncated(&sk_ac, &y, 4).unwrap();
        let arpc = arpc_method2_aes(arqc, csu, &pcad, &sk_ac).unwrap();
        assert_eq!(&arpc[..], expected.as_slice());
    }

    #[test]
    fn arpc_method2_aes_supports_all_three_key_sizes() {
        let arqc = [0x11; 8];
        let csu = [0x10; 4];
        let a128 = arpc_method2_aes(arqc, csu, &[], &[0xAA; 16]).unwrap();
        let a192 = arpc_method2_aes(arqc, csu, &[], &[0xAA; 24]).unwrap();
        let a256 = arpc_method2_aes(arqc, csu, &[], &[0xAA; 32]).unwrap();
        assert_ne!(a128, a192);
        assert_ne!(a128, a256);
        assert_ne!(a192, a256);
    }

    #[test]
    fn arpc_method2_aes_rejects_pcad_over_8_bytes() {
        let pcad = [0u8; 9];
        assert_eq!(
            arpc_method2_aes([0; 8], [0; 4], &pcad, &[0xAA; 16]),
            Err(Error::InvalidValue),
        );
    }

    #[test]
    fn arpc_method2_aes_rejects_bad_key_length() {
        assert!(arpc_method2_aes([0; 8], [0; 4], &[], &[0; 8]).is_err());
        assert!(arpc_method2_aes([0; 8], [0; 4], &[], &[0; 17]).is_err());
    }

    #[test]
    fn arpc_method2_aes_differs_from_tdes() {
        let arqc = [0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE];
        let csu = [0x00, 0x10, 0x20, 0x30];
        let key = [0xAA; 16];
        let tdes = arpc_method2(arqc, csu, &[], &key).unwrap();
        let aes = arpc_method2_aes(arqc, csu, &[], &key).unwrap();
        assert_ne!(tdes, aes);
    }

    // ── Issuer Authentication Data (tag '91') ────────────────────────

    #[test]
    fn iad_method2_minimum_8_bytes_no_pcad() {
        let arpc = [0x11, 0x22, 0x33, 0x44];
        let csu = [0xAA, 0xBB, 0xCC, 0xDD];
        let iad = issuer_authentication_data_method2(arpc, csu, &[]).unwrap();
        assert_eq!(iad, vec![0x11, 0x22, 0x33, 0x44, 0xAA, 0xBB, 0xCC, 0xDD]);
    }

    #[test]
    fn iad_method2_maximum_16_bytes_8_byte_pcad() {
        let arpc = [0x11; 4];
        let csu = [0x22; 4];
        let pcad = [0x33; 8];
        let iad = issuer_authentication_data_method2(arpc, csu, &pcad).unwrap();
        assert_eq!(iad.len(), 16);
        assert_eq!(&iad[..4], &arpc);
        assert_eq!(&iad[4..8], &csu);
        assert_eq!(&iad[8..], &pcad);
    }

    #[test]
    fn iad_method2_rejects_pcad_over_8_bytes() {
        let pcad = [0u8; 9];
        let result = issuer_authentication_data_method2([0; 4], [0; 4], &pcad);
        assert_eq!(result, Err(Error::InvalidValue));
    }

    #[test]
    fn iad_method2_intermediate_pcad_lengths() {
        for len in 0..=8 {
            let pcad = vec![0xCC; len];
            let iad = issuer_authentication_data_method2([0; 4], [0; 4], &pcad).unwrap();
            assert_eq!(iad.len(), 8 + len);
        }
    }

    // ── Round-trip: compute ARPC then build IAD ──────────────────────

    #[test]
    fn method2_end_to_end_arqc_to_iad() {
        // Drive a full Method 2 round trip from inputs to the IAD
        // bytes that would go on the wire to EXTERNAL AUTHENTICATE.
        let arqc = [0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE];
        let csu = [0x00, 0x10, 0x00, 0x00];
        let pcad = [0xDA, 0x7A];
        let sk_ac = [0x55; 16];

        let arpc = arpc_method2(arqc, csu, &pcad, &sk_ac).unwrap();
        let iad = issuer_authentication_data_method2(arpc, csu, &pcad).unwrap();

        // IAD = 4 + 4 + 2 = 10 bytes.
        assert_eq!(iad.len(), 10);
        assert_eq!(&iad[..4], &arpc);
        assert_eq!(&iad[4..8], &csu);
        assert_eq!(&iad[8..], &pcad);
    }
}
