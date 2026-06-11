//! Card Verification Results (CCD) - Book 3 Annex C9.3, Table CCD 10.

use crate::core::application_cryptogram_type::ApplicationCryptogramType;
use crate::core::error::{Error, Result};

const BYTE_5_RFU_MASK: u8 = 0xFF;

/// CVR byte 1 b8–b7 - Application Cryptogram Type Returned in Second GENERATE AC.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SecondGenerateApplicationCryptogramType {
    /// 0 0
    #[default]
    Aac,
    /// 0 1
    Tc,
    /// 1 0
    SecondGenerateAcNotRequested,
    /// 1 1
    Rfu,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct CardVerificationResults {
    pub application_cryptogram_type_returned_in_second_generate_ac:
        SecondGenerateApplicationCryptogramType,
    pub application_cryptogram_type_returned_in_first_generate_ac: ApplicationCryptogramType,
    pub cda_performed: bool,
    pub offline_dda_performed: bool,
    pub issuer_authentication_not_performed: bool,
    pub issuer_authentication_failed: bool,

    /// Byte 2 b8–b5.
    pub low_order_nibble_of_pin_try_counter: u8,
    pub offline_pin_verification_performed: bool,
    pub offline_pin_verification_performed_and_pin_not_successfully_verified: bool,
    pub pin_try_limit_exceeded: bool,
    pub last_online_transaction_not_completed: bool,

    pub lower_offline_transaction_count_limit_exceeded: bool,
    pub upper_offline_transaction_count_limit_exceeded: bool,
    pub lower_cumulative_offline_amount_limit_exceeded: bool,
    pub upper_cumulative_offline_amount_limit_exceeded: bool,
    pub issuer_discretionary_bit_1: bool,
    pub issuer_discretionary_bit_2: bool,
    pub issuer_discretionary_bit_3: bool,
    pub issuer_discretionary_bit_4: bool,

    /// Byte 4 b8–b5.
    pub number_of_successfully_processed_issuer_script_commands_containing_secure_messaging: u8,
    pub issuer_script_processing_failed: bool,
    pub offline_data_authentication_failed_on_previous_transaction: bool,
    pub go_online_on_next_transaction_was_set: bool,
    pub unable_to_go_online: bool,

    // Byte 5 - all bits RFU.
    pub rfu_byte_5: u8,
}

impl CardVerificationResults {
    pub fn new() -> Self {
        Self::default()
    }

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

        let second_gen = match (b1 >> 6) & 0b11 {
            0b00 => SecondGenerateApplicationCryptogramType::Aac,
            0b01 => SecondGenerateApplicationCryptogramType::Tc,
            0b10 => SecondGenerateApplicationCryptogramType::SecondGenerateAcNotRequested,
            0b11 => SecondGenerateApplicationCryptogramType::Rfu,
            _ => unreachable!(),
        };
        let first_gen = ApplicationCryptogramType::from_bits((b1 >> 4) & 0b11);

        Ok(CardVerificationResults {
            application_cryptogram_type_returned_in_second_generate_ac: second_gen,
            application_cryptogram_type_returned_in_first_generate_ac: first_gen,
            cda_performed: b1 & 0b0000_1000 != 0,
            offline_dda_performed: b1 & 0b0000_0100 != 0,
            issuer_authentication_not_performed: b1 & 0b0000_0010 != 0,
            issuer_authentication_failed: b1 & 0b0000_0001 != 0,

            low_order_nibble_of_pin_try_counter: (b2 >> 4) & 0x0F,
            offline_pin_verification_performed: b2 & 0b0000_1000 != 0,
            offline_pin_verification_performed_and_pin_not_successfully_verified: b2 & 0b0000_0100
                != 0,
            pin_try_limit_exceeded: b2 & 0b0000_0010 != 0,
            last_online_transaction_not_completed: b2 & 0b0000_0001 != 0,

            lower_offline_transaction_count_limit_exceeded: b3 & 0b1000_0000 != 0,
            upper_offline_transaction_count_limit_exceeded: b3 & 0b0100_0000 != 0,
            lower_cumulative_offline_amount_limit_exceeded: b3 & 0b0010_0000 != 0,
            upper_cumulative_offline_amount_limit_exceeded: b3 & 0b0001_0000 != 0,
            issuer_discretionary_bit_1: b3 & 0b0000_1000 != 0,
            issuer_discretionary_bit_2: b3 & 0b0000_0100 != 0,
            issuer_discretionary_bit_3: b3 & 0b0000_0010 != 0,
            issuer_discretionary_bit_4: b3 & 0b0000_0001 != 0,

            number_of_successfully_processed_issuer_script_commands_containing_secure_messaging: (b4
                >> 4)
                & 0x0F,
            issuer_script_processing_failed: b4 & 0b0000_1000 != 0,
            offline_data_authentication_failed_on_previous_transaction: b4 & 0b0000_0100 != 0,
            go_online_on_next_transaction_was_set: b4 & 0b0000_0010 != 0,
            unable_to_go_online: b4 & 0b0000_0001 != 0,

            rfu_byte_5: b5 & BYTE_5_RFU_MASK,
        })
    }

    pub fn to_bytes(&self) -> [u8; 5] {
        let second_gen_bits: u8 =
            match self.application_cryptogram_type_returned_in_second_generate_ac {
                SecondGenerateApplicationCryptogramType::Aac => 0b00,
                SecondGenerateApplicationCryptogramType::Tc => 0b01,
                SecondGenerateApplicationCryptogramType::SecondGenerateAcNotRequested => 0b10,
                SecondGenerateApplicationCryptogramType::Rfu => 0b11,
            };
        let first_gen_bits: u8 = self
            .application_cryptogram_type_returned_in_first_generate_ac
            .to_bits();

        let b1 = (second_gen_bits << 6)
            | (first_gen_bits << 4)
            | (self.cda_performed as u8) << 3
            | (self.offline_dda_performed as u8) << 2
            | (self.issuer_authentication_not_performed as u8) << 1
            | (self.issuer_authentication_failed as u8);

        let b2 = ((self.low_order_nibble_of_pin_try_counter & 0x0F) << 4)
            | (self.offline_pin_verification_performed as u8) << 3
            | (self.offline_pin_verification_performed_and_pin_not_successfully_verified as u8)
                << 2
            | (self.pin_try_limit_exceeded as u8) << 1
            | (self.last_online_transaction_not_completed as u8);

        let b3 = (self.lower_offline_transaction_count_limit_exceeded as u8) << 7
            | (self.upper_offline_transaction_count_limit_exceeded as u8) << 6
            | (self.lower_cumulative_offline_amount_limit_exceeded as u8) << 5
            | (self.upper_cumulative_offline_amount_limit_exceeded as u8) << 4
            | (self.issuer_discretionary_bit_1 as u8) << 3
            | (self.issuer_discretionary_bit_2 as u8) << 2
            | (self.issuer_discretionary_bit_3 as u8) << 1
            | (self.issuer_discretionary_bit_4 as u8);

        let b4 = ((self
            .number_of_successfully_processed_issuer_script_commands_containing_secure_messaging
            & 0x0F)
            << 4)
            | (self.issuer_script_processing_failed as u8) << 3
            | (self.offline_data_authentication_failed_on_previous_transaction as u8) << 2
            | (self.go_online_on_next_transaction_was_set as u8) << 1
            | (self.unable_to_go_online as u8);

        let b5 = self.rfu_byte_5 & BYTE_5_RFU_MASK;

        [b1, b2, b3, b4, b5]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_wrong_length() {
        assert_eq!(
            CardVerificationResults::parse(&[]),
            Err(Error::WrongLength {
                expected: 5,
                got: 0
            })
        );
        assert_eq!(
            CardVerificationResults::parse(&[0; 4]),
            Err(Error::WrongLength {
                expected: 5,
                got: 4
            })
        );
        assert_eq!(
            CardVerificationResults::parse(&[0; 6]),
            Err(Error::WrongLength {
                expected: 5,
                got: 6
            })
        );
    }

    #[test]
    fn struct_literal_construction() {
        let c = CardVerificationResults {
            application_cryptogram_type_returned_in_second_generate_ac:
                SecondGenerateApplicationCryptogramType::Tc,
            application_cryptogram_type_returned_in_first_generate_ac:
                ApplicationCryptogramType::Arqc,
            cda_performed: true,
            low_order_nibble_of_pin_try_counter: 0x3,
            pin_try_limit_exceeded: true,
            issuer_discretionary_bit_2: true,
            number_of_successfully_processed_issuer_script_commands_containing_secure_messaging:
                0x5,
            unable_to_go_online: true,
            ..Default::default()
        };
        assert_eq!(c.to_bytes(), [0x68, 0x32, 0x04, 0x51, 0x00]);
    }

    #[test]
    fn roundtrip_preserves_rfu() {
        let bytes = [0xFFu8, 0xFF, 0xFF, 0xFF, 0xFF];
        let c = CardVerificationResults::parse(&bytes).unwrap();
        assert_eq!(c.rfu_byte_5, BYTE_5_RFU_MASK);
        assert_eq!(c.to_bytes(), bytes);

        let bytes = [0x00, 0x00, 0x00, 0x00, 0xA5];
        let c = CardVerificationResults::parse(&bytes).unwrap();
        assert_eq!(c.rfu_byte_5, 0xA5);
        assert_eq!(c.to_bytes(), bytes);
    }

    #[test]
    fn roundtrip_exhaustive() {
        for bytes in [
            [0x00u8, 0x00, 0x00, 0x00, 0x00],
            [0xFF, 0xFF, 0xFF, 0xFF, 0xFF],
            [0x52, 0x39, 0xC0, 0x20, 0x00],
            [0x68, 0x32, 0x04, 0x51, 0xA5],
            [0xAA, 0x55, 0xAA, 0x55, 0xAA],
            [0x55, 0xAA, 0x55, 0xAA, 0x55],
        ] {
            let c = CardVerificationResults::parse(&bytes).unwrap();
            assert_eq!(c.to_bytes(), bytes, "roundtrip failed for {:02X?}", bytes);
        }
    }

    #[test]
    fn byte1_second_gen_ac_aac() {
        let c = CardVerificationResults::parse(&[0b0000_0000, 0, 0, 0, 0]).unwrap();
        assert_eq!(
            c.application_cryptogram_type_returned_in_second_generate_ac,
            SecondGenerateApplicationCryptogramType::Aac
        );
    }

    #[test]
    fn byte1_second_gen_ac_tc() {
        let c = CardVerificationResults::parse(&[0b0100_0000, 0, 0, 0, 0]).unwrap();
        assert_eq!(
            c.application_cryptogram_type_returned_in_second_generate_ac,
            SecondGenerateApplicationCryptogramType::Tc
        );
    }

    #[test]
    fn byte1_second_gen_ac_not_requested() {
        let c = CardVerificationResults::parse(&[0b1000_0000, 0, 0, 0, 0]).unwrap();
        assert_eq!(
            c.application_cryptogram_type_returned_in_second_generate_ac,
            SecondGenerateApplicationCryptogramType::SecondGenerateAcNotRequested
        );
    }

    #[test]
    fn byte1_second_gen_ac_rfu() {
        let c = CardVerificationResults::parse(&[0b1100_0000, 0, 0, 0, 0]).unwrap();
        assert_eq!(
            c.application_cryptogram_type_returned_in_second_generate_ac,
            SecondGenerateApplicationCryptogramType::Rfu
        );
    }

    #[test]
    fn byte1_first_gen_ac_aac() {
        let c = CardVerificationResults::parse(&[0b0000_0000, 0, 0, 0, 0]).unwrap();
        assert_eq!(
            c.application_cryptogram_type_returned_in_first_generate_ac,
            ApplicationCryptogramType::Aac
        );
    }

    #[test]
    fn byte1_first_gen_ac_tc() {
        let c = CardVerificationResults::parse(&[0b0001_0000, 0, 0, 0, 0]).unwrap();
        assert_eq!(
            c.application_cryptogram_type_returned_in_first_generate_ac,
            ApplicationCryptogramType::Tc
        );
    }

    #[test]
    fn byte1_first_gen_ac_arqc() {
        let c = CardVerificationResults::parse(&[0b0010_0000, 0, 0, 0, 0]).unwrap();
        assert_eq!(
            c.application_cryptogram_type_returned_in_first_generate_ac,
            ApplicationCryptogramType::Arqc
        );
    }

    #[test]
    fn byte1_first_gen_ac_rfu() {
        let c = CardVerificationResults::parse(&[0b0011_0000, 0, 0, 0, 0]).unwrap();
        assert_eq!(
            c.application_cryptogram_type_returned_in_first_generate_ac,
            ApplicationCryptogramType::Rfu(0b11)
        );
    }

    #[test]
    fn byte1_cda_performed() {
        let c = CardVerificationResults::parse(&[0b0000_1000, 0, 0, 0, 0]).unwrap();
        assert!(c.cda_performed);
    }

    #[test]
    fn byte1_offline_dda_performed() {
        let c = CardVerificationResults::parse(&[0b0000_0100, 0, 0, 0, 0]).unwrap();
        assert!(c.offline_dda_performed);
    }

    #[test]
    fn byte1_issuer_authentication_not_performed() {
        let c = CardVerificationResults::parse(&[0b0000_0010, 0, 0, 0, 0]).unwrap();
        assert!(c.issuer_authentication_not_performed);
    }

    #[test]
    fn byte1_issuer_authentication_failed() {
        let c = CardVerificationResults::parse(&[0b0000_0001, 0, 0, 0, 0]).unwrap();
        assert!(c.issuer_authentication_failed);
    }

    #[test]
    fn byte2_pin_try_counter_nibble() {
        let c = CardVerificationResults::parse(&[0, 0b1010_0000, 0, 0, 0]).unwrap();
        assert_eq!(c.low_order_nibble_of_pin_try_counter, 0b1010);
        assert!(!c.offline_pin_verification_performed);
    }

    #[test]
    fn byte2_offline_pin_verification_performed() {
        let c = CardVerificationResults::parse(&[0, 0b0000_1000, 0, 0, 0]).unwrap();
        assert!(c.offline_pin_verification_performed);
    }

    #[test]
    fn byte2_offline_pin_verification_performed_and_pin_not_successfully_verified() {
        let c = CardVerificationResults::parse(&[0, 0b0000_0100, 0, 0, 0]).unwrap();
        assert!(c.offline_pin_verification_performed_and_pin_not_successfully_verified);
    }

    #[test]
    fn byte2_pin_try_limit_exceeded() {
        let c = CardVerificationResults::parse(&[0, 0b0000_0010, 0, 0, 0]).unwrap();
        assert!(c.pin_try_limit_exceeded);
    }

    #[test]
    fn byte2_last_online_transaction_not_completed() {
        let c = CardVerificationResults::parse(&[0, 0b0000_0001, 0, 0, 0]).unwrap();
        assert!(c.last_online_transaction_not_completed);
    }

    #[test]
    fn byte3_lower_offline_transaction_count_limit_exceeded() {
        let c = CardVerificationResults::parse(&[0, 0, 0b1000_0000, 0, 0]).unwrap();
        assert!(c.lower_offline_transaction_count_limit_exceeded);
    }

    #[test]
    fn byte3_upper_offline_transaction_count_limit_exceeded() {
        let c = CardVerificationResults::parse(&[0, 0, 0b0100_0000, 0, 0]).unwrap();
        assert!(c.upper_offline_transaction_count_limit_exceeded);
    }

    #[test]
    fn byte3_lower_cumulative_offline_amount_limit_exceeded() {
        let c = CardVerificationResults::parse(&[0, 0, 0b0010_0000, 0, 0]).unwrap();
        assert!(c.lower_cumulative_offline_amount_limit_exceeded);
    }

    #[test]
    fn byte3_upper_cumulative_offline_amount_limit_exceeded() {
        let c = CardVerificationResults::parse(&[0, 0, 0b0001_0000, 0, 0]).unwrap();
        assert!(c.upper_cumulative_offline_amount_limit_exceeded);
    }

    #[test]
    fn byte3_issuer_discretionary_bit_1() {
        let c = CardVerificationResults::parse(&[0, 0, 0b0000_1000, 0, 0]).unwrap();
        assert!(c.issuer_discretionary_bit_1);
    }

    #[test]
    fn byte3_issuer_discretionary_bit_2() {
        let c = CardVerificationResults::parse(&[0, 0, 0b0000_0100, 0, 0]).unwrap();
        assert!(c.issuer_discretionary_bit_2);
    }

    #[test]
    fn byte3_issuer_discretionary_bit_3() {
        let c = CardVerificationResults::parse(&[0, 0, 0b0000_0010, 0, 0]).unwrap();
        assert!(c.issuer_discretionary_bit_3);
    }

    #[test]
    fn byte3_issuer_discretionary_bit_4() {
        let c = CardVerificationResults::parse(&[0, 0, 0b0000_0001, 0, 0]).unwrap();
        assert!(c.issuer_discretionary_bit_4);
    }

    #[test]
    fn byte4_issuer_script_commands_nibble() {
        let c = CardVerificationResults::parse(&[0, 0, 0, 0b0110_0000, 0]).unwrap();
        assert_eq!(
            c.number_of_successfully_processed_issuer_script_commands_containing_secure_messaging,
            0b0110
        );
    }

    #[test]
    fn byte4_issuer_script_processing_failed() {
        let c = CardVerificationResults::parse(&[0, 0, 0, 0b0000_1000, 0]).unwrap();
        assert!(c.issuer_script_processing_failed);
    }

    #[test]
    fn byte4_offline_data_authentication_failed_on_previous_transaction() {
        let c = CardVerificationResults::parse(&[0, 0, 0, 0b0000_0100, 0]).unwrap();
        assert!(c.offline_data_authentication_failed_on_previous_transaction);
    }

    #[test]
    fn byte4_go_online_on_next_transaction_was_set() {
        let c = CardVerificationResults::parse(&[0, 0, 0, 0b0000_0010, 0]).unwrap();
        assert!(c.go_online_on_next_transaction_was_set);
    }

    #[test]
    fn byte4_unable_to_go_online() {
        let c = CardVerificationResults::parse(&[0, 0, 0, 0b0000_0001, 0]).unwrap();
        assert!(c.unable_to_go_online);
    }

    #[test]
    fn byte5_rfu_preserved() {
        for v in [0x00u8, 0x01, 0x7F, 0x80, 0xA5, 0xFF] {
            let c = CardVerificationResults::parse(&[0, 0, 0, 0, v]).unwrap();
            assert_eq!(c.rfu_byte_5, v);
            assert_eq!(c.to_bytes(), [0, 0, 0, 0, v]);
        }
    }
}
