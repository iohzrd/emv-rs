//! Transaction Status Information (tag 9B) - Book 3 Annex C6, Table 47.

use crate::core::error::{Error, Result};

const BYTE_1_RFU_MASK: u8 = 0b0000_0011;
const BYTE_2_RFU_MASK: u8 = 0b1111_1111;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct TransactionStatusInformation {
    // Byte 1 (leftmost)
    pub offline_data_authentication_was_performed: bool,
    pub cardholder_verification_was_performed: bool,
    pub card_risk_management_was_performed: bool,
    pub issuer_authentication_was_performed: bool,
    pub terminal_risk_management_was_performed: bool,
    pub script_processing_was_performed: bool,
    pub rfu_byte_1: u8,

    pub rfu_byte_2: u8,
}

impl TransactionStatusInformation {
    pub fn parse(data: &[u8]) -> Result<Self> {
        if data.len() != 2 {
            return Err(Error::WrongLength {
                expected: 2,
                got: data.len(),
            });
        }
        let b1 = data[0];
        let b2 = data[1];
        Ok(TransactionStatusInformation {
            offline_data_authentication_was_performed: b1 & 0b1000_0000 != 0,
            cardholder_verification_was_performed: b1 & 0b0100_0000 != 0,
            card_risk_management_was_performed: b1 & 0b0010_0000 != 0,
            issuer_authentication_was_performed: b1 & 0b0001_0000 != 0,
            terminal_risk_management_was_performed: b1 & 0b0000_1000 != 0,
            script_processing_was_performed: b1 & 0b0000_0100 != 0,
            rfu_byte_1: b1 & BYTE_1_RFU_MASK,

            rfu_byte_2: b2 & BYTE_2_RFU_MASK,
        })
    }

    pub fn to_bytes(&self) -> [u8; 2] {
        let b1 = (self.offline_data_authentication_was_performed as u8) << 7
            | (self.cardholder_verification_was_performed as u8) << 6
            | (self.card_risk_management_was_performed as u8) << 5
            | (self.issuer_authentication_was_performed as u8) << 4
            | (self.terminal_risk_management_was_performed as u8) << 3
            | (self.script_processing_was_performed as u8) << 2
            | (self.rfu_byte_1 & BYTE_1_RFU_MASK);

        let b2 = self.rfu_byte_2 & BYTE_2_RFU_MASK;

        [b1, b2]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn struct_literal_construction() {
        let t = TransactionStatusInformation {
            offline_data_authentication_was_performed: true,
            cardholder_verification_was_performed: true,
            terminal_risk_management_was_performed: true,
            ..Default::default()
        };
        assert_eq!(t.to_bytes(), [0b1100_1000, 0b0000_0000]);
    }

    #[test]
    fn roundtrip_preserves_rfu() {
        let bytes = [0xFFu8, 0xFF];
        let t = TransactionStatusInformation::parse(&bytes).unwrap();
        assert_eq!(t.rfu_byte_1, BYTE_1_RFU_MASK);
        assert_eq!(t.rfu_byte_2, BYTE_2_RFU_MASK);
        assert_eq!(t.to_bytes(), bytes);
    }

    #[test]
    fn roundtrip_exhaustive() {
        for bytes in [
            [0x00u8, 0x00],
            [0xFC, 0x00],
            [0x84, 0x55],
            [0x80, 0xFF],
            [0xFF, 0xFF],
        ] {
            let t = TransactionStatusInformation::parse(&bytes).unwrap();
            assert_eq!(t.to_bytes(), bytes);
        }
    }

    #[test]
    fn parse_wrong_length() {
        assert_eq!(
            TransactionStatusInformation::parse(&[]),
            Err(Error::WrongLength {
                expected: 2,
                got: 0
            })
        );
        assert_eq!(
            TransactionStatusInformation::parse(&[0x00, 0x00, 0x00]),
            Err(Error::WrongLength {
                expected: 2,
                got: 3
            })
        );
    }
}
