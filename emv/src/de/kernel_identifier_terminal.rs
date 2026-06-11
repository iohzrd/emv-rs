//! Kernel Identifier-Terminal (tag 96) - Book B v2.11 Table 3-7. Always 8 bytes.

use crate::core::error::{Error, Result};
use crate::de::kernel_identifier::KernelType;

const BYTE_4_RFU_MASK: u8 = 0b0011_1111;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KernelIdentifierTerminal {
    pub kernel_type: KernelType,
    /// Byte 1 b6-b1, 0..=63.
    pub short_kernel_id: u8,
    /// Bytes 2-3 - `00 00` when card's 9F2A omits the Extended Kernel ID (§3.4.1.4).
    pub extended_kernel_id: [u8; 2],
    pub kernel_8_supported_by_reader: bool,
    pub kernel_8_supported_for_transaction: bool,
    pub byte_4_rfu: u8,
    pub bytes_5_8_rfu: [u8; 4],
}

impl KernelIdentifierTerminal {
    pub fn parse(data: &[u8]) -> Result<Self> {
        if data.len() != 8 {
            return Err(Error::WrongLength {
                expected: 8,
                got: data.len(),
            });
        }
        let b1 = data[0];
        Ok(Self {
            kernel_type: KernelType::from_bits((b1 >> 6) & 0b11),
            short_kernel_id: b1 & 0x3F,
            extended_kernel_id: [data[1], data[2]],
            kernel_8_supported_by_reader: data[3] & 0b1000_0000 != 0,
            kernel_8_supported_for_transaction: data[3] & 0b0100_0000 != 0,
            byte_4_rfu: data[3] & BYTE_4_RFU_MASK,
            bytes_5_8_rfu: [data[4], data[5], data[6], data[7]],
        })
    }

    pub fn to_bytes(&self) -> [u8; 8] {
        let b1 = (self.kernel_type.to_bits() << 6) | (self.short_kernel_id & 0x3F);
        let b4 = (self.kernel_8_supported_by_reader as u8) << 7
            | (self.kernel_8_supported_for_transaction as u8) << 6
            | (self.byte_4_rfu & BYTE_4_RFU_MASK);
        [
            b1,
            self.extended_kernel_id[0],
            self.extended_kernel_id[1],
            b4,
            self.bytes_5_8_rfu[0],
            self.bytes_5_8_rfu[1],
            self.bytes_5_8_rfu[2],
            self.bytes_5_8_rfu[3],
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_kernel_2_no_extended() {
        let bytes = [0b00_000010, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        let kit = KernelIdentifierTerminal::parse(&bytes).unwrap();
        assert_eq!(kit.kernel_type, KernelType::International);
        assert_eq!(kit.short_kernel_id, 2);
        assert_eq!(kit.extended_kernel_id, [0x00, 0x00]);
        assert!(!kit.kernel_8_supported_by_reader);
        assert!(!kit.kernel_8_supported_for_transaction);
        assert_eq!(kit.to_bytes(), bytes);
    }

    #[test]
    fn parse_kernel_8_flags_set() {
        let bytes = [0b00_001000, 0x00, 0x00, 0b1100_0000, 0x00, 0x00, 0x00, 0x00];
        let kit = KernelIdentifierTerminal::parse(&bytes).unwrap();
        assert_eq!(kit.short_kernel_id, 8);
        assert!(kit.kernel_8_supported_by_reader);
        assert!(kit.kernel_8_supported_for_transaction);
        assert_eq!(kit.to_bytes(), bytes);
    }

    #[test]
    fn parse_rejects_wrong_length() {
        assert!(matches!(
            KernelIdentifierTerminal::parse(&[0u8; 7]),
            Err(Error::WrongLength { expected: 8, got: 7 })
        ));
        assert!(matches!(
            KernelIdentifierTerminal::parse(&[0u8; 9]),
            Err(Error::WrongLength { expected: 8, got: 9 })
        ));
    }

    #[test]
    fn roundtrip_preserves_rfu() {
        let bytes = [0xFFu8; 8];
        let kit = KernelIdentifierTerminal::parse(&bytes).unwrap();
        assert_eq!(kit.byte_4_rfu, BYTE_4_RFU_MASK);
        assert_eq!(kit.bytes_5_8_rfu, [0xFF; 4]);
        assert_eq!(kit.to_bytes(), bytes);
    }
}
