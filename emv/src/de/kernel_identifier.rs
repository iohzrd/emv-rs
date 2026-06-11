//! Kernel Identifier (tag 9F2A) - Book B v2.11 Tables 3-4 / 3-5.

use crate::core::error::{Error, Result};

/// Byte 1 b8b7.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KernelType {
    /// 00
    International,
    /// 01
    Rfu,
    /// 10
    DomesticEmvco,
    /// 11
    DomesticProprietary,
}

impl KernelType {
    pub fn from_bits(b: u8) -> Self {
        match b {
            0b00 => Self::International,
            0b01 => Self::Rfu,
            0b10 => Self::DomesticEmvco,
            0b11 => Self::DomesticProprietary,
            _ => unreachable!("from_bits called with non-2-bit value"),
        }
    }

    pub fn to_bits(self) -> u8 {
        match self {
            Self::International => 0b00,
            Self::Rfu => 0b01,
            Self::DomesticEmvco => 0b10,
            Self::DomesticProprietary => 0b11,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KernelIdentifier {
    pub kernel_type: KernelType,
    /// Byte 1 b6-b1, 0..=63.
    pub short_kernel_id: u8,
    /// Bytes 2-3 - present iff length >= 3.
    pub extended_kernel_id: Option<[u8; 2]>,
    pub rfu_bytes: Vec<u8>,
}

impl KernelIdentifier {
    /// Footnote 11: encoded length must be 1, 3, or more.
    pub fn parse(data: &[u8]) -> Result<Self> {
        if data.is_empty() || data.len() == 2 {
            return Err(Error::InvalidValue);
        }
        let b1 = data[0];
        let kernel_type = KernelType::from_bits((b1 >> 6) & 0b11);
        let short_kernel_id = b1 & 0x3F;
        let extended_kernel_id = if data.len() >= 3 {
            Some([data[1], data[2]])
        } else {
            None
        };
        let rfu_bytes = if data.len() > 3 {
            data[3..].to_vec()
        } else {
            Vec::new()
        };
        Ok(Self {
            kernel_type,
            short_kernel_id,
            extended_kernel_id,
            rfu_bytes,
        })
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let b1 = (self.kernel_type.to_bits() << 6) | (self.short_kernel_id & 0x3F);
        let mut out = vec![b1];
        if let Some(ext) = self.extended_kernel_id {
            out.extend_from_slice(&ext);
            out.extend_from_slice(&self.rfu_bytes);
        }
        // rfu_bytes without extended_kernel_id would imply length 2, an invalid form - drop them.
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_one_byte_international_kernel_2() {
        let ki = KernelIdentifier::parse(&[0b00_000010]).unwrap();
        assert_eq!(ki.kernel_type, KernelType::International);
        assert_eq!(ki.short_kernel_id, 2);
        assert!(ki.extended_kernel_id.is_none());
        assert!(ki.rfu_bytes.is_empty());
        assert_eq!(ki.to_bytes(), vec![0b00_000010]);
    }

    #[test]
    fn parse_one_byte_short_id_zero_means_use_adf_name_default() {
        let ki = KernelIdentifier::parse(&[0b00_000000]).unwrap();
        assert_eq!(ki.short_kernel_id, 0);
    }

    #[test]
    fn parse_three_byte_domestic_emvco_with_currency_code() {
        // EUR currency code 978 BCD.
        let bytes = [0b10_000001, 0x09, 0x78];
        let ki = KernelIdentifier::parse(&bytes).unwrap();
        assert_eq!(ki.kernel_type, KernelType::DomesticEmvco);
        assert_eq!(ki.short_kernel_id, 1);
        assert_eq!(ki.extended_kernel_id, Some([0x09, 0x78]));
        assert!(ki.rfu_bytes.is_empty());
        assert_eq!(ki.to_bytes(), bytes);
    }

    #[test]
    fn parse_eight_bytes_preserves_rfu_trailer() {
        let bytes = [0b11_111111, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11];
        let ki = KernelIdentifier::parse(&bytes).unwrap();
        assert_eq!(ki.kernel_type, KernelType::DomesticProprietary);
        assert_eq!(ki.short_kernel_id, 0x3F);
        assert_eq!(ki.extended_kernel_id, Some([0xAA, 0xBB]));
        assert_eq!(ki.rfu_bytes, vec![0xCC, 0xDD, 0xEE, 0xFF, 0x11]);
        assert_eq!(ki.to_bytes(), bytes);
    }

    #[test]
    fn parse_rejects_length_zero() {
        assert_eq!(
            KernelIdentifier::parse(&[]),
            Err(Error::InvalidValue),
            "footnote 11: length 0 is invalid"
        );
    }

    #[test]
    fn parse_rejects_length_two() {
        assert_eq!(
            KernelIdentifier::parse(&[0x02, 0x00]),
            Err(Error::InvalidValue),
            "footnote 11: length 2 is invalid"
        );
    }

    #[test]
    fn type_bits_roundtrip() {
        for t in [
            KernelType::International,
            KernelType::Rfu,
            KernelType::DomesticEmvco,
            KernelType::DomesticProprietary,
        ] {
            assert_eq!(KernelType::from_bits(t.to_bits()), t);
        }
    }

    #[test]
    fn roundtrip_all_one_byte_values() {
        for b in 0u8..=u8::MAX {
            let ki = KernelIdentifier::parse(&[b]).unwrap();
            assert_eq!(ki.to_bytes(), vec![b]);
        }
    }
}
