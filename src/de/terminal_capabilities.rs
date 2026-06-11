//! Terminal Capabilities (tag 9F33) - Book 4 Annex A2, Tables 25–27.

use crate::core::error::{Error, Result};

const BYTE_1_RFU_MASK: u8 = 0b0001_1111;
const BYTE_3_RFU_MASK: u8 = 0b0001_0011;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct TerminalCapabilities {
    // Byte 1 - Card Data Input Capability (Table 25)
    pub manual_key_entry: bool,
    pub magnetic_stripe: bool,
    pub ic_with_contacts: bool,
    pub rfu_byte_1: u8,

    // Byte 2 - CVM Capability (Table 26)
    pub plaintext_pin_for_icc_verification: bool,
    pub enciphered_pin_for_online_verification: bool,
    pub signature: bool,
    pub enciphered_pin_for_offline_verification_rsa_ode: bool,
    pub no_cvm_required: bool,
    pub online_biometric: bool,
    pub offline_biometric: bool,
    pub enciphered_pin_for_offline_verification_ecc_ode: bool,

    // Byte 3 - Security Capability (Table 27)
    pub sda: bool,
    pub dda: bool,
    pub card_capture: bool,
    pub cda: bool,
    pub xda: bool,
    pub rfu_byte_3: u8,
}

impl TerminalCapabilities {
    pub fn parse(data: &[u8]) -> Result<Self> {
        if data.len() != 3 {
            return Err(Error::WrongLength {
                expected: 3,
                got: data.len(),
            });
        }
        let b1 = data[0];
        let b2 = data[1];
        let b3 = data[2];
        Ok(TerminalCapabilities {
            manual_key_entry: b1 & 0b1000_0000 != 0,
            magnetic_stripe: b1 & 0b0100_0000 != 0,
            ic_with_contacts: b1 & 0b0010_0000 != 0,
            rfu_byte_1: b1 & BYTE_1_RFU_MASK,

            plaintext_pin_for_icc_verification: b2 & 0b1000_0000 != 0,
            enciphered_pin_for_online_verification: b2 & 0b0100_0000 != 0,
            signature: b2 & 0b0010_0000 != 0,
            enciphered_pin_for_offline_verification_rsa_ode: b2 & 0b0001_0000 != 0,
            no_cvm_required: b2 & 0b0000_1000 != 0,
            online_biometric: b2 & 0b0000_0100 != 0,
            offline_biometric: b2 & 0b0000_0010 != 0,
            enciphered_pin_for_offline_verification_ecc_ode: b2 & 0b0000_0001 != 0,

            sda: b3 & 0b1000_0000 != 0,
            dda: b3 & 0b0100_0000 != 0,
            card_capture: b3 & 0b0010_0000 != 0,
            cda: b3 & 0b0000_1000 != 0,
            xda: b3 & 0b0000_0100 != 0,
            rfu_byte_3: b3 & BYTE_3_RFU_MASK,
        })
    }

    pub fn to_bytes(&self) -> [u8; 3] {
        let b1 = (self.manual_key_entry as u8) << 7
            | (self.magnetic_stripe as u8) << 6
            | (self.ic_with_contacts as u8) << 5
            | (self.rfu_byte_1 & BYTE_1_RFU_MASK);

        let b2 = (self.plaintext_pin_for_icc_verification as u8) << 7
            | (self.enciphered_pin_for_online_verification as u8) << 6
            | (self.signature as u8) << 5
            | (self.enciphered_pin_for_offline_verification_rsa_ode as u8) << 4
            | (self.no_cvm_required as u8) << 3
            | (self.online_biometric as u8) << 2
            | (self.offline_biometric as u8) << 1
            | (self.enciphered_pin_for_offline_verification_ecc_ode as u8);

        let b3 = (self.sda as u8) << 7
            | (self.dda as u8) << 6
            | (self.card_capture as u8) << 5
            | (self.cda as u8) << 3
            | (self.xda as u8) << 2
            | (self.rfu_byte_3 & BYTE_3_RFU_MASK);

        [b1, b2, b3]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn struct_literal_construction() {
        let c = TerminalCapabilities {
            ic_with_contacts: true,
            plaintext_pin_for_icc_verification: true,
            no_cvm_required: true,
            sda: true,
            dda: true,
            cda: true,
            ..Default::default()
        };
        assert_eq!(c.to_bytes(), [0b0010_0000, 0b1000_1000, 0b1100_1000]);
    }

    #[test]
    fn roundtrip_preserves_rfu() {
        let bytes = [0xFFu8, 0xFF, 0xFF];
        let c = TerminalCapabilities::parse(&bytes).unwrap();
        assert_eq!(c.rfu_byte_1, BYTE_1_RFU_MASK);
        assert_eq!(c.rfu_byte_3, BYTE_3_RFU_MASK);
        assert_eq!(c.to_bytes(), bytes);
    }

    #[test]
    fn roundtrip_exhaustive() {
        for bytes in [
            [0x00u8, 0x00, 0x00],
            [0xE0, 0xFF, 0xEC],
            [0xA0, 0x80, 0x80],
            [0x60, 0x55, 0x48],
            [0xFF, 0xFF, 0xFF],
        ] {
            let c = TerminalCapabilities::parse(&bytes).unwrap();
            assert_eq!(c.to_bytes(), bytes);
        }
    }

    #[test]
    fn parse_wrong_length() {
        assert_eq!(
            TerminalCapabilities::parse(&[]),
            Err(Error::WrongLength {
                expected: 3,
                got: 0
            })
        );
        assert_eq!(
            TerminalCapabilities::parse(&[0x00, 0x00, 0x00, 0x00]),
            Err(Error::WrongLength {
                expected: 3,
                got: 4
            })
        );
    }
}
