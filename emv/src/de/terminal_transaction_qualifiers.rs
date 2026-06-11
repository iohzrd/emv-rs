//! Terminal Transaction Qualifiers (tag 9F66) - Book A v2.11 §5.7, Table 5-4.

use crate::core::error::{Error, Result};

const BYTE_1_RFU_MASK: u8 = 0b0100_0000;
const BYTE_2_RFU_MASK: u8 = 0b0001_1111;
const BYTE_3_RFU_MASK: u8 = 0b0011_1111;
const BYTE_4_RFU_MASK: u8 = 0b1111_1111;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct TerminalTransactionQualifiers {
    // Byte 1
    pub mag_stripe_mode_supported: bool,
    pub rfu_byte_1: u8,
    pub emv_mode_supported: bool,
    pub emv_contact_chip_supported: bool,
    /// b4. `true` = offline-only reader; `false` = online-capable.
    pub offline_only_reader: bool,
    pub online_pin_supported: bool,
    pub signature_supported: bool,
    pub offline_data_authentication_for_online_authorizations_supported: bool,

    // Byte 2
    pub online_cryptogram_required: bool,
    pub cvm_required: bool,
    pub contact_chip_offline_pin_supported: bool,
    pub rfu_byte_2: u8,

    // Byte 3
    pub issuer_update_processing_supported: bool,
    pub consumer_device_cvm_supported: bool,
    pub rfu_byte_3: u8,

    pub rfu_byte_4: u8,
}

impl TerminalTransactionQualifiers {
    pub fn parse(data: &[u8]) -> Result<Self> {
        if data.len() != 4 {
            return Err(Error::WrongLength {
                expected: 4,
                got: data.len(),
            });
        }
        let b1 = data[0];
        let b2 = data[1];
        let b3 = data[2];
        let b4 = data[3];
        Ok(TerminalTransactionQualifiers {
            mag_stripe_mode_supported: b1 & 0b1000_0000 != 0,
            rfu_byte_1: b1 & BYTE_1_RFU_MASK,
            emv_mode_supported: b1 & 0b0010_0000 != 0,
            emv_contact_chip_supported: b1 & 0b0001_0000 != 0,
            offline_only_reader: b1 & 0b0000_1000 != 0,
            online_pin_supported: b1 & 0b0000_0100 != 0,
            signature_supported: b1 & 0b0000_0010 != 0,
            offline_data_authentication_for_online_authorizations_supported: b1 & 0b0000_0001 != 0,

            online_cryptogram_required: b2 & 0b1000_0000 != 0,
            cvm_required: b2 & 0b0100_0000 != 0,
            contact_chip_offline_pin_supported: b2 & 0b0010_0000 != 0,
            rfu_byte_2: b2 & BYTE_2_RFU_MASK,

            issuer_update_processing_supported: b3 & 0b1000_0000 != 0,
            consumer_device_cvm_supported: b3 & 0b0100_0000 != 0,
            rfu_byte_3: b3 & BYTE_3_RFU_MASK,

            rfu_byte_4: b4 & BYTE_4_RFU_MASK,
        })
    }

    pub fn to_bytes(&self) -> [u8; 4] {
        let b1 = (self.mag_stripe_mode_supported as u8) << 7
            | (self.rfu_byte_1 & BYTE_1_RFU_MASK)
            | (self.emv_mode_supported as u8) << 5
            | (self.emv_contact_chip_supported as u8) << 4
            | (self.offline_only_reader as u8) << 3
            | (self.online_pin_supported as u8) << 2
            | (self.signature_supported as u8) << 1
            | (self.offline_data_authentication_for_online_authorizations_supported as u8);

        let b2 = (self.online_cryptogram_required as u8) << 7
            | (self.cvm_required as u8) << 6
            | (self.contact_chip_offline_pin_supported as u8) << 5
            | (self.rfu_byte_2 & BYTE_2_RFU_MASK);

        let b3 = (self.issuer_update_processing_supported as u8) << 7
            | (self.consumer_device_cvm_supported as u8) << 6
            | (self.rfu_byte_3 & BYTE_3_RFU_MASK);

        let b4 = self.rfu_byte_4 & BYTE_4_RFU_MASK;

        [b1, b2, b3, b4]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn struct_literal_construction() {
        let t = TerminalTransactionQualifiers {
            emv_mode_supported: true,
            online_pin_supported: true,
            ..Default::default()
        };
        assert_eq!(t.to_bytes(), [0b0010_0100, 0, 0, 0]);
    }

    #[test]
    fn roundtrip_preserves_rfu() {
        let bytes = [0xFFu8, 0xFF, 0xFF, 0xFF];
        let t = TerminalTransactionQualifiers::parse(&bytes).unwrap();
        assert_eq!(t.rfu_byte_1, BYTE_1_RFU_MASK);
        assert_eq!(t.rfu_byte_2, BYTE_2_RFU_MASK);
        assert_eq!(t.rfu_byte_3, BYTE_3_RFU_MASK);
        assert_eq!(t.rfu_byte_4, BYTE_4_RFU_MASK);
        assert_eq!(t.to_bytes(), bytes);
    }

    #[test]
    fn roundtrip_exhaustive() {
        for bytes in [
            [0x00u8, 0x00, 0x00, 0x00],
            [0xA0, 0x80, 0x80, 0x00],
            [0x60, 0x55, 0x48, 0x12],
            [0xFF, 0xFF, 0xFF, 0xFF],
        ] {
            let t = TerminalTransactionQualifiers::parse(&bytes).unwrap();
            assert_eq!(t.to_bytes(), bytes);
        }
    }

    #[test]
    fn parse_wrong_length() {
        assert_eq!(
            TerminalTransactionQualifiers::parse(&[]),
            Err(Error::WrongLength {
                expected: 4,
                got: 0
            })
        );
        assert_eq!(
            TerminalTransactionQualifiers::parse(&[0u8; 5]),
            Err(Error::WrongLength {
                expected: 4,
                got: 5
            })
        );
    }
}
