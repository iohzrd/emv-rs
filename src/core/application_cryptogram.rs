//! Book 2 §8.1 - Application Cryptogram generation.

use crate::core::aes_primitives::aes_cmac_truncated;
use crate::core::error::Result;
use crate::core::secure_messaging::retail_mac;

pub fn application_cryptogram(sk_ac: &[u8; 16], selected_data: &[u8]) -> [u8; 8] {
    retail_mac(sk_ac, selected_data)
}

pub fn verify_application_cryptogram(
    sk_ac: &[u8; 16],
    selected_data: &[u8],
    candidate: [u8; 8],
) -> bool {
    application_cryptogram(sk_ac, selected_data) == candidate
}

pub fn application_cryptogram_aes(sk_ac: &[u8], selected_data: &[u8]) -> Result<[u8; 8]> {
    let mac = aes_cmac_truncated(sk_ac, selected_data, 8)?;
    let mut ac = [0u8; 8];
    ac.copy_from_slice(&mac);
    Ok(ac)
}

pub fn verify_application_cryptogram_aes(
    sk_ac: &[u8],
    selected_data: &[u8],
    candidate: [u8; 8],
) -> Result<bool> {
    Ok(application_cryptogram_aes(sk_ac, selected_data)? == candidate)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::secure_messaging::{
        derive_session_key_tdes, diversification_for_ac_session_key, mac_truncated,
        pad_iso9797_method2, retail_mac_no_pad,
    };

    #[test]
    fn ac_matches_full_retail_mac() {
        let sk_ac = [
            0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54,
            0x32, 0x10,
        ];
        let data = b"selected CDOL data bytes";
        let ac = application_cryptogram(&sk_ac, data);
        let expected = mac_truncated(&sk_ac, data, 8).unwrap();
        assert_eq!(&ac[..], expected.as_slice());
    }

    #[test]
    fn ac_matches_manually_computed_retail_mac() {
        let sk_ac = [0xAA; 16];
        let data = b"hello, EMV";
        let ac = application_cryptogram(&sk_ac, data);
        let padded = pad_iso9797_method2(data, 8);
        let manual = retail_mac_no_pad(&sk_ac, &padded).unwrap();
        assert_eq!(ac, manual);
    }

    #[test]
    fn ac_changes_with_data() {
        let sk_ac = [0xAA; 16];
        let a = application_cryptogram(&sk_ac, b"transaction A");
        let b = application_cryptogram(&sk_ac, b"transaction B");
        assert_ne!(a, b);
    }

    #[test]
    fn ac_changes_with_session_key() {
        let data = b"same data, different key";
        let a = application_cryptogram(&[0xAA; 16], data);
        let b = application_cryptogram(&[0x54; 16], data);
        assert_ne!(a, b);
    }

    #[test]
    fn ac_is_deterministic() {
        let sk_ac = [0x11; 16];
        let data = b"deterministic input";
        let a = application_cryptogram(&sk_ac, data);
        let b = application_cryptogram(&sk_ac, data);
        assert_eq!(a, b);
    }

    #[test]
    fn ac_handles_empty_data() {
        let sk_ac = [0x42; 16];
        let ac = application_cryptogram(&sk_ac, &[]);
        let pad_only = [0x80, 0, 0, 0, 0, 0, 0, 0];
        let manual = retail_mac_no_pad(&sk_ac, &pad_only).unwrap();
        assert_eq!(ac, manual);
    }

    #[test]
    fn ac_handles_block_aligned_data() {
        let sk_ac = [0x42; 16];
        let data = [0xAB; 8];
        let ac = application_cryptogram(&sk_ac, &data);
        let padded = pad_iso9797_method2(&data, 8);
        assert_eq!(padded.len(), 16);
        let manual = retail_mac_no_pad(&sk_ac, &padded).unwrap();
        assert_eq!(ac, manual);
    }

    // ── verify_application_cryptogram ────────────────────────────────

    #[test]
    fn verify_accepts_correct_ac() {
        let sk_ac = [0xAA; 16];
        let data = b"transaction data";
        let ac = application_cryptogram(&sk_ac, data);
        assert!(verify_application_cryptogram(&sk_ac, data, ac));
    }

    #[test]
    fn verify_rejects_wrong_ac() {
        let sk_ac = [0xAA; 16];
        let data = b"transaction data";
        let mut ac = application_cryptogram(&sk_ac, data);
        ac[0] ^= 0x01;
        assert!(!verify_application_cryptogram(&sk_ac, data, ac));
    }

    #[test]
    fn verify_rejects_wrong_data() {
        let sk_ac = [0xAA; 16];
        let ac = application_cryptogram(&sk_ac, b"original");
        assert!(!verify_application_cryptogram(&sk_ac, b"tampered", ac));
    }

    #[test]
    fn verify_rejects_wrong_session_key() {
        let data = b"transaction data";
        let ac = application_cryptogram(&[0xAA; 16], data);
        assert!(!verify_application_cryptogram(&[0x54; 16], data, ac));
    }

    // ── End-to-end with session key derivation ───────────────────────

    // ── AES variant ──────────────────────────────────────────────────

    #[test]
    fn ac_aes_matches_aes_cmac_truncated_to_8() {
        use crate::core::aes_primitives::aes_cmac_truncated;
        let sk_ac = [0xAA; 16];
        let data = b"selected CDOL data";
        let ac = application_cryptogram_aes(&sk_ac, data).unwrap();
        let expected = aes_cmac_truncated(&sk_ac, data, 8).unwrap();
        assert_eq!(&ac[..], expected.as_slice());
    }

    #[test]
    fn ac_aes_supports_all_three_key_sizes() {
        let data = b"transaction data";
        let ac128 = application_cryptogram_aes(&[0xAA; 16], data).unwrap();
        let ac192 = application_cryptogram_aes(&[0xAA; 24], data).unwrap();
        let ac256 = application_cryptogram_aes(&[0xAA; 32], data).unwrap();
        assert_ne!(ac128, ac192);
        assert_ne!(ac128, ac256);
        assert_ne!(ac192, ac256);
    }

    #[test]
    fn ac_aes_rejects_bad_key_length() {
        let data = b"x";
        assert!(application_cryptogram_aes(&[0xAA; 8], data).is_err());
        assert!(application_cryptogram_aes(&[0xAA; 17], data).is_err());
        assert!(application_cryptogram_aes(&[0xAA; 31], data).is_err());
    }

    #[test]
    fn ac_aes_differs_from_tdes_for_same_inputs() {
        let key = [0xAA; 16];
        let data = b"transaction data";
        let tdes_ac = application_cryptogram(&key, data);
        let aes_ac = application_cryptogram_aes(&key, data).unwrap();
        assert_ne!(tdes_ac, aes_ac);
    }

    #[test]
    fn verify_ac_aes_accepts_correct_value() {
        let sk_ac = [0xAA; 16];
        let data = b"transaction data";
        let ac = application_cryptogram_aes(&sk_ac, data).unwrap();
        assert!(verify_application_cryptogram_aes(&sk_ac, data, ac).unwrap());
    }

    #[test]
    fn verify_ac_aes_rejects_wrong_value() {
        let sk_ac = [0xAA; 16];
        let data = b"transaction data";
        let mut ac = application_cryptogram_aes(&sk_ac, data).unwrap();
        ac[0] ^= 0x01;
        assert!(!verify_application_cryptogram_aes(&sk_ac, data, ac).unwrap());
    }

    // ── End-to-end ───────────────────────────────────────────────────

    #[test]
    fn end_to_end_arqc_verification_via_session_key_derivation() {
        let mk_ac = [
            0xAB, 0xCD, 0xEF, 0x01, 0x23, 0x45, 0x67, 0x89, 0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC,
            0xDE, 0xF0,
        ];
        let atc: u16 = 0x0042;
        let r = diversification_for_ac_session_key(atc);
        let sk_ac = derive_session_key_tdes(&mk_ac, &r);

        let selected_data = [
            0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x40,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x40, 0x26, 0x04, 0x27, 0x00, 0xCA, 0xFE, 0xBA,
            0xBE, 0x5C, 0x00, 0x00, 0x42,
        ];
        let arqc = application_cryptogram(&sk_ac, &selected_data);
        assert!(verify_application_cryptogram(&sk_ac, &selected_data, arqc));
        let mut tampered = selected_data;
        tampered[14] ^= 0x01;
        assert!(!verify_application_cryptogram(&sk_ac, &tampered, arqc));
    }
}
