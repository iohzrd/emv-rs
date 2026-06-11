//! Issuer Code Table Index (tag 9F11) - Book 3 Annex C4, Table 45.

use crate::core::error::{Error, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IssuerCodeTableIndex(pub u8);

impl IssuerCodeTableIndex {
    pub fn parse(data: &[u8]) -> Result<Self> {
        if data.len() != 1 {
            return Err(Error::WrongLength {
                expected: 1,
                got: data.len(),
            });
        }
        Ok(IssuerCodeTableIndex(data[0]))
    }

    pub fn to_bytes(&self) -> [u8; 1] {
        [self.0]
    }

    /// ISO/IEC 8859 part number.
    pub fn part(&self) -> u8 {
        self.0
    }
}

impl IssuerCodeTableIndex {
    pub const PART_1: Self = Self(0x01);
    pub const PART_2: Self = Self(0x02);
    pub const PART_3: Self = Self(0x03);
    pub const PART_4: Self = Self(0x04);
    pub const PART_5: Self = Self(0x05);
    pub const PART_6: Self = Self(0x06);
    pub const PART_7: Self = Self(0x07);
    pub const PART_8: Self = Self(0x08);
    pub const PART_9: Self = Self(0x09);
    pub const PART_10: Self = Self(0x10);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_and_to_bytes_roundtrip() {
        for v in [0x01u8, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x10] {
            let idx = IssuerCodeTableIndex::parse(&[v]).unwrap();
            assert_eq!(idx.part(), v);
            assert_eq!(idx.to_bytes(), [v]);
        }
    }

    #[test]
    fn named_constants_match_table_45() {
        assert_eq!(IssuerCodeTableIndex::PART_1.part(), 0x01);
        assert_eq!(IssuerCodeTableIndex::PART_2.part(), 0x02);
        assert_eq!(IssuerCodeTableIndex::PART_3.part(), 0x03);
        assert_eq!(IssuerCodeTableIndex::PART_4.part(), 0x04);
        assert_eq!(IssuerCodeTableIndex::PART_5.part(), 0x05);
        assert_eq!(IssuerCodeTableIndex::PART_6.part(), 0x06);
        assert_eq!(IssuerCodeTableIndex::PART_7.part(), 0x07);
        assert_eq!(IssuerCodeTableIndex::PART_8.part(), 0x08);
        assert_eq!(IssuerCodeTableIndex::PART_9.part(), 0x09);
        assert_eq!(IssuerCodeTableIndex::PART_10.part(), 0x10);
    }

    #[test]
    fn parse_wrong_length() {
        assert_eq!(
            IssuerCodeTableIndex::parse(&[]),
            Err(Error::WrongLength { expected: 1, got: 0 })
        );
        assert_eq!(
            IssuerCodeTableIndex::parse(&[0x01, 0x02]),
            Err(Error::WrongLength { expected: 1, got: 2 })
        );
    }
}
