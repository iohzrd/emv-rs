//! Application Priority Indicator (tag 87) - Book 1 Annex B §12.2.3 Table 13.

use crate::core::error::{Error, Result};

const RFU_MASK: u8 = 0b0111_0000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ApplicationPriorityIndicator {
    pub application_cannot_be_selected_without_confirmation_by_the_cardholder: bool,
    /// b4–b1: priority 0..=15 (0 = no priority).
    pub priority: u8,
    pub rfu_byte_1: u8,
}

impl ApplicationPriorityIndicator {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn parse(data: &[u8]) -> Result<Self> {
        if data.len() != 1 {
            return Err(Error::WrongLength {
                expected: 1,
                got: data.len(),
            });
        }
        let b = data[0];
        Ok(ApplicationPriorityIndicator {
            application_cannot_be_selected_without_confirmation_by_the_cardholder: b & 0b1000_0000
                != 0,
            priority: b & 0b0000_1111,
            rfu_byte_1: b & RFU_MASK,
        })
    }

    pub fn to_byte(&self) -> u8 {
        ((self.application_cannot_be_selected_without_confirmation_by_the_cardholder as u8) << 7)
            | (self.rfu_byte_1 & RFU_MASK)
            | (self.priority & 0b0000_1111)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn struct_literal_construction() {
        let api = ApplicationPriorityIndicator {
            application_cannot_be_selected_without_confirmation_by_the_cardholder: true,
            priority: 5,
            ..Default::default()
        };
        assert_eq!(api.to_byte(), 0b1000_0101);
    }

    #[test]
    fn roundtrip_preserves_rfu() {
        let bytes = [0b1111_1010u8];
        let api = ApplicationPriorityIndicator::parse(&bytes).unwrap();
        assert_eq!(api.rfu_byte_1, RFU_MASK);
        assert!(api.application_cannot_be_selected_without_confirmation_by_the_cardholder);
        assert_eq!(api.priority, 0b1010);
        assert_eq!(api.to_byte(), bytes[0]);
    }

    #[test]
    fn roundtrip_exhaustive() {
        for b in 0u8..=u8::MAX {
            let api = ApplicationPriorityIndicator::parse(&[b]).unwrap();
            assert_eq!(api.to_byte(), b);
        }
    }

    #[test]
    fn priority_truncates_on_to_byte() {
        let api = ApplicationPriorityIndicator {
            priority: 0xFF,
            ..Default::default()
        };
        assert_eq!(api.to_byte(), 0x0F);
    }

    #[test]
    fn priority_full_range() {
        for p in 0u8..=15 {
            let api = ApplicationPriorityIndicator::parse(&[p]).unwrap();
            assert_eq!(api.priority, p);
            assert!(!api.application_cannot_be_selected_without_confirmation_by_the_cardholder);
            assert_eq!(api.rfu_byte_1, 0);
        }
    }

    #[test]
    fn confirmation_bit_set() {
        let api = ApplicationPriorityIndicator::parse(&[0b1000_0000]).unwrap();
        assert!(api.application_cannot_be_selected_without_confirmation_by_the_cardholder);
        assert_eq!(api.priority, 0);
    }

    #[test]
    fn confirmation_bit_clear() {
        let api = ApplicationPriorityIndicator::parse(&[0b0000_0001]).unwrap();
        assert!(!api.application_cannot_be_selected_without_confirmation_by_the_cardholder);
        assert_eq!(api.priority, 1);
    }

    #[test]
    fn parse_wrong_length() {
        assert_eq!(
            ApplicationPriorityIndicator::parse(&[]),
            Err(Error::WrongLength {
                expected: 1,
                got: 0
            }),
        );
        assert_eq!(
            ApplicationPriorityIndicator::parse(&[0x01, 0x02]),
            Err(Error::WrongLength {
                expected: 1,
                got: 2
            }),
        );
    }
}
