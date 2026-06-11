//! Application Usage Control (tag 9F07) - Book 3 Annex C2, Table 42.

use crate::core::error::{Error, Result};

const BYTE_2_RFU_MASK: u8 = 0b0011_1111;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ApplicationUsageControl {
    // Byte 1 (leftmost)
    pub valid_for_domestic_cash_transactions: bool,
    pub valid_for_international_cash_transactions: bool,
    pub valid_for_domestic_goods: bool,
    pub valid_for_international_goods: bool,
    pub valid_for_domestic_services: bool,
    pub valid_for_international_services: bool,
    pub valid_at_atms: bool,
    pub valid_at_terminals_other_than_atms: bool,

    // Byte 2 (rightmost)
    pub domestic_cashback_allowed: bool,
    pub international_cashback_allowed: bool,
    pub rfu_byte_2: u8,
}

impl ApplicationUsageControl {
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
        Ok(ApplicationUsageControl {
            valid_for_domestic_cash_transactions: b1 & 0b1000_0000 != 0,
            valid_for_international_cash_transactions: b1 & 0b0100_0000 != 0,
            valid_for_domestic_goods: b1 & 0b0010_0000 != 0,
            valid_for_international_goods: b1 & 0b0001_0000 != 0,
            valid_for_domestic_services: b1 & 0b0000_1000 != 0,
            valid_for_international_services: b1 & 0b0000_0100 != 0,
            valid_at_atms: b1 & 0b0000_0010 != 0,
            valid_at_terminals_other_than_atms: b1 & 0b0000_0001 != 0,

            domestic_cashback_allowed: b2 & 0b1000_0000 != 0,
            international_cashback_allowed: b2 & 0b0100_0000 != 0,
            rfu_byte_2: b2 & BYTE_2_RFU_MASK,
        })
    }

    pub fn to_bytes(&self) -> [u8; 2] {
        let b1 = (self.valid_for_domestic_cash_transactions as u8) << 7
            | (self.valid_for_international_cash_transactions as u8) << 6
            | (self.valid_for_domestic_goods as u8) << 5
            | (self.valid_for_international_goods as u8) << 4
            | (self.valid_for_domestic_services as u8) << 3
            | (self.valid_for_international_services as u8) << 2
            | (self.valid_at_atms as u8) << 1
            | (self.valid_at_terminals_other_than_atms as u8);

        let b2 = (self.domestic_cashback_allowed as u8) << 7
            | (self.international_cashback_allowed as u8) << 6
            | (self.rfu_byte_2 & BYTE_2_RFU_MASK);

        [b1, b2]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn struct_literal_construction() {
        let a = ApplicationUsageControl {
            valid_for_domestic_cash_transactions: true,
            valid_for_domestic_goods: true,
            valid_for_domestic_services: true,
            valid_at_atms: true,
            domestic_cashback_allowed: true,
            ..Default::default()
        };
        assert_eq!(a.to_bytes(), [0b1010_1010, 0b1000_0000]);
    }

    #[test]
    fn roundtrip_preserves_rfu() {
        let bytes = [0xFFu8, 0xFF];
        let a = ApplicationUsageControl::parse(&bytes).unwrap();
        assert_eq!(a.rfu_byte_2, BYTE_2_RFU_MASK);
        assert_eq!(a.to_bytes(), bytes);
    }

    #[test]
    fn roundtrip_exhaustive() {
        for bytes in [
            [0x00u8, 0x00],
            [0xFF, 0xFF],
            [0xAA, 0x80],
            [0x3C, 0x40],
            [0xFF, 0xC0],
            [0x55, 0x3F],
            [0x81, 0xC3],
        ] {
            let a = ApplicationUsageControl::parse(&bytes).unwrap();
            assert_eq!(a.to_bytes(), bytes);
        }
    }

    #[test]
    fn parse_wrong_length() {
        assert_eq!(
            ApplicationUsageControl::parse(&[]),
            Err(Error::WrongLength {
                expected: 2,
                got: 0
            })
        );
        assert_eq!(
            ApplicationUsageControl::parse(&[0x00]),
            Err(Error::WrongLength {
                expected: 2,
                got: 1
            })
        );
        assert_eq!(
            ApplicationUsageControl::parse(&[0x00, 0x00, 0x00]),
            Err(Error::WrongLength {
                expected: 2,
                got: 3
            })
        );
    }
}
