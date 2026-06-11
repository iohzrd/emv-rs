//! Additional Terminal Capabilities (tag 9F40) - Book 4 Annex A3, Tables 28–32.

use crate::core::error::{Error, Result};

const BYTE_2_RFU_MASK: u8 = 0b0111_1111;
const BYTE_3_RFU_MASK: u8 = 0b0000_1111;
const BYTE_4_RFU_MASK: u8 = 0b0000_1100;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct AdditionalTerminalCapabilities {
    // Byte 1 - Transaction Type Capability (Table 28)
    pub cash: bool,
    pub goods: bool,
    pub services: bool,
    pub cashback: bool,
    pub inquiry: bool,
    pub transfer: bool,
    pub payment: bool,
    pub administrative: bool,

    // Byte 2 - Transaction Type Capability cont'd (Table 29)
    pub cash_deposit: bool,
    pub rfu_byte_2: u8,

    // Byte 3 - Terminal Data Input Capability (Table 30)
    pub numeric_keys: bool,
    pub alphabetic_and_special_characters_keys: bool,
    pub command_keys: bool,
    pub function_keys: bool,
    pub rfu_byte_3: u8,

    // Byte 4 - Terminal Data Output Capability (Table 31)
    pub print_attendant: bool,
    pub print_cardholder: bool,
    pub display_attendant: bool,
    pub display_cardholder: bool,
    pub code_table_10: bool,
    pub code_table_9: bool,
    pub rfu_byte_4: u8,

    // Byte 5 - Terminal Data Output Capability cont'd (Table 32)
    pub code_table_8: bool,
    pub code_table_7: bool,
    pub code_table_6: bool,
    pub code_table_5: bool,
    pub code_table_4: bool,
    pub code_table_3: bool,
    pub code_table_2: bool,
    pub code_table_1: bool,
}

impl AdditionalTerminalCapabilities {
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
        Ok(AdditionalTerminalCapabilities {
            cash: b1 & 0b1000_0000 != 0,
            goods: b1 & 0b0100_0000 != 0,
            services: b1 & 0b0010_0000 != 0,
            cashback: b1 & 0b0001_0000 != 0,
            inquiry: b1 & 0b0000_1000 != 0,
            transfer: b1 & 0b0000_0100 != 0,
            payment: b1 & 0b0000_0010 != 0,
            administrative: b1 & 0b0000_0001 != 0,

            cash_deposit: b2 & 0b1000_0000 != 0,
            rfu_byte_2: b2 & BYTE_2_RFU_MASK,

            numeric_keys: b3 & 0b1000_0000 != 0,
            alphabetic_and_special_characters_keys: b3 & 0b0100_0000 != 0,
            command_keys: b3 & 0b0010_0000 != 0,
            function_keys: b3 & 0b0001_0000 != 0,
            rfu_byte_3: b3 & BYTE_3_RFU_MASK,

            print_attendant: b4 & 0b1000_0000 != 0,
            print_cardholder: b4 & 0b0100_0000 != 0,
            display_attendant: b4 & 0b0010_0000 != 0,
            display_cardholder: b4 & 0b0001_0000 != 0,
            code_table_10: b4 & 0b0000_0010 != 0,
            code_table_9: b4 & 0b0000_0001 != 0,
            rfu_byte_4: b4 & BYTE_4_RFU_MASK,

            code_table_8: b5 & 0b1000_0000 != 0,
            code_table_7: b5 & 0b0100_0000 != 0,
            code_table_6: b5 & 0b0010_0000 != 0,
            code_table_5: b5 & 0b0001_0000 != 0,
            code_table_4: b5 & 0b0000_1000 != 0,
            code_table_3: b5 & 0b0000_0100 != 0,
            code_table_2: b5 & 0b0000_0010 != 0,
            code_table_1: b5 & 0b0000_0001 != 0,
        })
    }

    pub fn to_bytes(&self) -> [u8; 5] {
        let b1 = (self.cash as u8) << 7
            | (self.goods as u8) << 6
            | (self.services as u8) << 5
            | (self.cashback as u8) << 4
            | (self.inquiry as u8) << 3
            | (self.transfer as u8) << 2
            | (self.payment as u8) << 1
            | (self.administrative as u8);

        let b2 = (self.cash_deposit as u8) << 7 | (self.rfu_byte_2 & BYTE_2_RFU_MASK);

        let b3 = (self.numeric_keys as u8) << 7
            | (self.alphabetic_and_special_characters_keys as u8) << 6
            | (self.command_keys as u8) << 5
            | (self.function_keys as u8) << 4
            | (self.rfu_byte_3 & BYTE_3_RFU_MASK);

        let b4 = (self.print_attendant as u8) << 7
            | (self.print_cardholder as u8) << 6
            | (self.display_attendant as u8) << 5
            | (self.display_cardholder as u8) << 4
            | (self.code_table_10 as u8) << 1
            | (self.code_table_9 as u8)
            | (self.rfu_byte_4 & BYTE_4_RFU_MASK);

        let b5 = (self.code_table_8 as u8) << 7
            | (self.code_table_7 as u8) << 6
            | (self.code_table_6 as u8) << 5
            | (self.code_table_5 as u8) << 4
            | (self.code_table_4 as u8) << 3
            | (self.code_table_3 as u8) << 2
            | (self.code_table_2 as u8) << 1
            | (self.code_table_1 as u8);

        [b1, b2, b3, b4, b5]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn struct_literal_construction() {
        let c = AdditionalTerminalCapabilities {
            goods: true,
            services: true,
            cash_deposit: true,
            numeric_keys: true,
            print_attendant: true,
            code_table_9: true,
            code_table_1: true,
            ..Default::default()
        };
        assert_eq!(
            c.to_bytes(),
            [
                0b0110_0000,
                0b1000_0000,
                0b1000_0000,
                0b1000_0001,
                0b0000_0001
            ]
        );
    }

    #[test]
    fn roundtrip_preserves_rfu() {
        // All RFU bits set alongside all named bits.
        let bytes = [0xFFu8, 0xFF, 0xFF, 0xFF, 0xFF];
        let c = AdditionalTerminalCapabilities::parse(&bytes).unwrap();
        assert_eq!(c.rfu_byte_2, BYTE_2_RFU_MASK);
        assert_eq!(c.rfu_byte_3, BYTE_3_RFU_MASK);
        assert_eq!(c.rfu_byte_4, BYTE_4_RFU_MASK);
        assert_eq!(c.to_bytes(), bytes);
    }

    #[test]
    fn roundtrip_exhaustive() {
        for bytes in [
            [0x00u8, 0x00, 0x00, 0x00, 0x00],
            [0xFF, 0xFF, 0xFF, 0xFF, 0xFF],
            [0xE0, 0x80, 0xF0, 0xF3, 0xFF],
            [0x5A, 0x80, 0xA5, 0xC3, 0x81],
            [0xAA, 0x55, 0x5A, 0xA5, 0x3C],
        ] {
            let c = AdditionalTerminalCapabilities::parse(&bytes).unwrap();
            assert_eq!(c.to_bytes(), bytes);
        }
    }

    #[test]
    fn parse_wrong_length() {
        assert_eq!(
            AdditionalTerminalCapabilities::parse(&[]),
            Err(Error::WrongLength {
                expected: 5,
                got: 0
            })
        );
        assert_eq!(
            AdditionalTerminalCapabilities::parse(&[0; 4]),
            Err(Error::WrongLength {
                expected: 5,
                got: 4
            })
        );
        assert_eq!(
            AdditionalTerminalCapabilities::parse(&[0; 6]),
            Err(Error::WrongLength {
                expected: 5,
                got: 6
            })
        );
    }
}
