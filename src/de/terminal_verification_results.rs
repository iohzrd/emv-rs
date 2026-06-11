//! Terminal Verification Results (tag 95) - Book 3 Annex C5, Table 46.

use crate::core::error::{Error, Result};

const BYTE_2_RFU_MASK: u8 = 0b0000_0100;
const BYTE_5_RFU_MASK: u8 = 0b0000_1001;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct TerminalVerificationResults {
    // Byte 1 (leftmost)
    pub offline_data_authentication_was_not_performed: bool,
    pub sda_failed: bool,
    pub icc_data_missing: bool,
    pub card_appears_on_terminal_exception_file: bool,
    pub dda_failed: bool,
    pub cda_failed: bool,
    pub sda_selected: bool,
    pub xda_selected: bool,

    // Byte 2
    pub icc_and_terminal_have_different_application_versions: bool,
    pub expired_application: bool,
    pub application_not_yet_effective: bool,
    pub requested_service_not_allowed_for_card_product: bool,
    pub new_card: bool,
    pub biometric_performed_and_successful: bool,
    pub biometric_template_format_not_supported: bool,
    pub rfu_byte_2: u8,

    // Byte 3
    pub cardholder_verification_was_not_successful: bool,
    pub unrecognised_cvm: bool,
    pub pin_try_limit_exceeded: bool,
    pub pin_entry_required_and_pin_pad_not_present_or_not_working: bool,
    pub pin_entry_required_pin_pad_present_but_pin_was_not_entered: bool,
    pub online_cvm_captured: bool,
    pub biometric_required_but_biometric_capture_device_not_working: bool,
    pub biometric_required_biometric_capture_device_present_but_biometric_subtype_entry_was_bypassed:
        bool,

    // Byte 4
    pub transaction_exceeds_floor_limit: bool,
    pub lower_consecutive_offline_limit_exceeded: bool,
    pub upper_consecutive_offline_limit_exceeded: bool,
    pub transaction_selected_randomly_for_online_processing: bool,
    pub merchant_forced_transaction_online: bool,
    pub biometric_try_limit_exceeded: bool,
    pub a_selected_biometric_type_not_supported: bool,
    pub xda_signature_verification_failed: bool,

    // Byte 5 (rightmost)
    pub default_tdol_used: bool,
    pub issuer_authentication_failed: bool,
    pub script_processing_failed_before_final_generate_ac: bool,
    pub script_processing_failed_after_final_generate_ac: bool,
    pub ca_ecc_key_missing: bool,
    pub ecc_key_recovery_failed: bool,
    pub rfu_byte_5: u8,
}

impl TerminalVerificationResults {
    pub fn parse(data: &[u8]) -> Result<Self> {
        if data.len() != 5 {
            return Err(Error::WrongLength {
                expected: 5,
                got: data.len(),
            });
        }
        let b1 = data[0];
        let b2 = data[1];
        let b3 = data[2];
        let b4 = data[3];
        let b5 = data[4];
        Ok(TerminalVerificationResults {
            offline_data_authentication_was_not_performed: b1 & 0b1000_0000 != 0,
            sda_failed: b1 & 0b0100_0000 != 0,
            icc_data_missing: b1 & 0b0010_0000 != 0,
            card_appears_on_terminal_exception_file: b1 & 0b0001_0000 != 0,
            dda_failed: b1 & 0b0000_1000 != 0,
            cda_failed: b1 & 0b0000_0100 != 0,
            sda_selected: b1 & 0b0000_0010 != 0,
            xda_selected: b1 & 0b0000_0001 != 0,

            icc_and_terminal_have_different_application_versions: b2 & 0b1000_0000 != 0,
            expired_application: b2 & 0b0100_0000 != 0,
            application_not_yet_effective: b2 & 0b0010_0000 != 0,
            requested_service_not_allowed_for_card_product: b2 & 0b0001_0000 != 0,
            new_card: b2 & 0b0000_1000 != 0,
            biometric_performed_and_successful: b2 & 0b0000_0010 != 0,
            biometric_template_format_not_supported: b2 & 0b0000_0001 != 0,
            rfu_byte_2: b2 & BYTE_2_RFU_MASK,

            cardholder_verification_was_not_successful: b3 & 0b1000_0000 != 0,
            unrecognised_cvm: b3 & 0b0100_0000 != 0,
            pin_try_limit_exceeded: b3 & 0b0010_0000 != 0,
            pin_entry_required_and_pin_pad_not_present_or_not_working: b3 & 0b0001_0000 != 0,
            pin_entry_required_pin_pad_present_but_pin_was_not_entered: b3 & 0b0000_1000 != 0,
            online_cvm_captured: b3 & 0b0000_0100 != 0,
            biometric_required_but_biometric_capture_device_not_working: b3 & 0b0000_0010 != 0,
            biometric_required_biometric_capture_device_present_but_biometric_subtype_entry_was_bypassed:
                b3 & 0b0000_0001 != 0,

            transaction_exceeds_floor_limit: b4 & 0b1000_0000 != 0,
            lower_consecutive_offline_limit_exceeded: b4 & 0b0100_0000 != 0,
            upper_consecutive_offline_limit_exceeded: b4 & 0b0010_0000 != 0,
            transaction_selected_randomly_for_online_processing: b4 & 0b0001_0000 != 0,
            merchant_forced_transaction_online: b4 & 0b0000_1000 != 0,
            biometric_try_limit_exceeded: b4 & 0b0000_0100 != 0,
            a_selected_biometric_type_not_supported: b4 & 0b0000_0010 != 0,
            xda_signature_verification_failed: b4 & 0b0000_0001 != 0,

            default_tdol_used: b5 & 0b1000_0000 != 0,
            issuer_authentication_failed: b5 & 0b0100_0000 != 0,
            script_processing_failed_before_final_generate_ac: b5 & 0b0010_0000 != 0,
            script_processing_failed_after_final_generate_ac: b5 & 0b0001_0000 != 0,
            ca_ecc_key_missing: b5 & 0b0000_0100 != 0,
            ecc_key_recovery_failed: b5 & 0b0000_0010 != 0,
            rfu_byte_5: b5 & BYTE_5_RFU_MASK,
        })
    }

    pub fn to_bytes(&self) -> [u8; 5] {
        let b1 = (self.offline_data_authentication_was_not_performed as u8) << 7
            | (self.sda_failed as u8) << 6
            | (self.icc_data_missing as u8) << 5
            | (self.card_appears_on_terminal_exception_file as u8) << 4
            | (self.dda_failed as u8) << 3
            | (self.cda_failed as u8) << 2
            | (self.sda_selected as u8) << 1
            | (self.xda_selected as u8);

        let b2 = (self.icc_and_terminal_have_different_application_versions as u8) << 7
            | (self.expired_application as u8) << 6
            | (self.application_not_yet_effective as u8) << 5
            | (self.requested_service_not_allowed_for_card_product as u8) << 4
            | (self.new_card as u8) << 3
            | (self.biometric_performed_and_successful as u8) << 1
            | (self.biometric_template_format_not_supported as u8)
            | (self.rfu_byte_2 & BYTE_2_RFU_MASK);

        let b3 = (self.cardholder_verification_was_not_successful as u8) << 7
            | (self.unrecognised_cvm as u8) << 6
            | (self.pin_try_limit_exceeded as u8) << 5
            | (self.pin_entry_required_and_pin_pad_not_present_or_not_working as u8) << 4
            | (self.pin_entry_required_pin_pad_present_but_pin_was_not_entered as u8) << 3
            | (self.online_cvm_captured as u8) << 2
            | (self.biometric_required_but_biometric_capture_device_not_working as u8) << 1
            | (self
                .biometric_required_biometric_capture_device_present_but_biometric_subtype_entry_was_bypassed
                as u8);

        let b4 = (self.transaction_exceeds_floor_limit as u8) << 7
            | (self.lower_consecutive_offline_limit_exceeded as u8) << 6
            | (self.upper_consecutive_offline_limit_exceeded as u8) << 5
            | (self.transaction_selected_randomly_for_online_processing as u8) << 4
            | (self.merchant_forced_transaction_online as u8) << 3
            | (self.biometric_try_limit_exceeded as u8) << 2
            | (self.a_selected_biometric_type_not_supported as u8) << 1
            | (self.xda_signature_verification_failed as u8);

        let b5 = (self.default_tdol_used as u8) << 7
            | (self.issuer_authentication_failed as u8) << 6
            | (self.script_processing_failed_before_final_generate_ac as u8) << 5
            | (self.script_processing_failed_after_final_generate_ac as u8) << 4
            | (self.ca_ecc_key_missing as u8) << 2
            | (self.ecc_key_recovery_failed as u8) << 1
            | (self.rfu_byte_5 & BYTE_5_RFU_MASK);

        [b1, b2, b3, b4, b5]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn struct_literal_construction() {
        let t = TerminalVerificationResults {
            offline_data_authentication_was_not_performed: true,
            icc_and_terminal_have_different_application_versions: true,
            cardholder_verification_was_not_successful: true,
            transaction_exceeds_floor_limit: true,
            default_tdol_used: true,
            ..Default::default()
        };
        assert_eq!(
            t.to_bytes(),
            [
                0b1000_0000,
                0b1000_0000,
                0b1000_0000,
                0b1000_0000,
                0b1000_0000
            ]
        );
    }

    #[test]
    fn roundtrip_preserves_rfu() {
        let bytes = [0xFFu8, 0xFF, 0xFF, 0xFF, 0xFF];
        let t = TerminalVerificationResults::parse(&bytes).unwrap();
        assert_eq!(t.rfu_byte_2, BYTE_2_RFU_MASK);
        assert_eq!(t.rfu_byte_5, BYTE_5_RFU_MASK);
        assert_eq!(t.to_bytes(), bytes);
    }

    #[test]
    fn roundtrip_exhaustive() {
        for bytes in [
            [0x00u8, 0x00, 0x00, 0x00, 0x00],
            [0xFF, 0xFF, 0xFF, 0xFF, 0xFF],
            [0x80, 0x40, 0x20, 0x10, 0x08],
            [0x12, 0x34, 0x56, 0x78, 0x9A],
            [0xAA, 0x55, 0xAA, 0x55, 0xAA],
            [0x00, 0x04, 0x00, 0x00, 0x09],
        ] {
            let t = TerminalVerificationResults::parse(&bytes).unwrap();
            assert_eq!(t.to_bytes(), bytes);
        }
    }

    #[test]
    fn parse_wrong_length() {
        assert_eq!(
            TerminalVerificationResults::parse(&[]),
            Err(Error::WrongLength {
                expected: 5,
                got: 0
            })
        );
        assert_eq!(
            TerminalVerificationResults::parse(&[0; 4]),
            Err(Error::WrongLength {
                expected: 5,
                got: 4
            })
        );
        assert_eq!(
            TerminalVerificationResults::parse(&[0; 6]),
            Err(Error::WrongLength {
                expected: 5,
                got: 6
            })
        );
    }
}
