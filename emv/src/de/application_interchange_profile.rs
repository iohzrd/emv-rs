//! Application Interchange Profile (tag 82) - Book 3 Annex C1, Table 41.

use crate::core::error::{Error, Result};

const BYTE_1_RFU_MASK: u8 = 0b0000_0010;
const BYTE_2_RFU_MASK: u8 = 0b1111_1111;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ApplicationInterchangeProfile {
    // Byte 1 (leftmost)
    pub xda_supported: bool,
    pub sda_supported: bool,
    pub dda_supported: bool,
    pub cardholder_verification_is_supported: bool,
    pub terminal_risk_management_is_to_be_performed: bool,
    pub issuer_authentication_is_supported: bool,
    pub cda_supported: bool,
    pub rfu_byte_1: u8,

    // Byte 2 - Reserved for use by the EMV Contactless Specifications or RFU.
    pub rfu_byte_2: u8,
}

impl ApplicationInterchangeProfile {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn parse(data: &[u8]) -> Result<Self> {
        if data.len() != 2 {
            return Err(Error::WrongLength {
                expected: 2,
                got: data.len(),
            });
        }
        let b1 = data[0];
        let b2 = data[1];
        Ok(ApplicationInterchangeProfile {
            xda_supported: b1 & 0b1000_0000 != 0,
            sda_supported: b1 & 0b0100_0000 != 0,
            dda_supported: b1 & 0b0010_0000 != 0,
            cardholder_verification_is_supported: b1 & 0b0001_0000 != 0,
            terminal_risk_management_is_to_be_performed: b1 & 0b0000_1000 != 0,
            issuer_authentication_is_supported: b1 & 0b0000_0100 != 0,
            cda_supported: b1 & 0b0000_0001 != 0,
            rfu_byte_1: b1 & BYTE_1_RFU_MASK,

            rfu_byte_2: b2 & BYTE_2_RFU_MASK,
        })
    }

    pub fn to_bytes(&self) -> [u8; 2] {
        let b1 = (self.xda_supported as u8) << 7
            | (self.sda_supported as u8) << 6
            | (self.dda_supported as u8) << 5
            | (self.cardholder_verification_is_supported as u8) << 4
            | (self.terminal_risk_management_is_to_be_performed as u8) << 3
            | (self.issuer_authentication_is_supported as u8) << 2
            | (self.cda_supported as u8)
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
        let a = ApplicationInterchangeProfile {
            xda_supported: true,
            dda_supported: true,
            cardholder_verification_is_supported: true,
            cda_supported: true,
            ..Default::default()
        };
        assert_eq!(a.to_bytes(), [0b1011_0001, 0x00]);
    }

    #[test]
    fn roundtrip_preserves_rfu() {
        let bytes = [0xFFu8, 0xFF];
        let a = ApplicationInterchangeProfile::parse(&bytes).unwrap();
        assert_eq!(a.rfu_byte_1, BYTE_1_RFU_MASK);
        assert_eq!(a.rfu_byte_2, BYTE_2_RFU_MASK);
        assert_eq!(a.to_bytes(), bytes);
    }

    #[test]
    fn roundtrip_exhaustive() {
        for bytes in [
            [0x00u8, 0x00],
            [0xFF, 0xFF],
            [0x5C, 0xA3],
            [0xB8, 0x00],
            [0x00, 0x5A],
            [0xFD, 0x01],
        ] {
            let a = ApplicationInterchangeProfile::parse(&bytes).unwrap();
            assert_eq!(a.to_bytes(), bytes);
        }
    }

    #[test]
    fn parse_wrong_length() {
        assert_eq!(
            ApplicationInterchangeProfile::parse(&[]),
            Err(Error::WrongLength {
                expected: 2,
                got: 0
            })
        );
        assert_eq!(
            ApplicationInterchangeProfile::parse(&[0x00]),
            Err(Error::WrongLength {
                expected: 2,
                got: 1
            })
        );
        assert_eq!(
            ApplicationInterchangeProfile::parse(&[0x00, 0x00, 0x00]),
            Err(Error::WrongLength {
                expected: 2,
                got: 3
            })
        );
    }
}
