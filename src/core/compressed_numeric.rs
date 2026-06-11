//! Book 3 §4.3 - format cn: two decimal digits per byte, left justified,
//! trailing 'F' padding.

use crate::core::error::{Error, Result};

pub fn decode(value: &[u8]) -> Result<Vec<u8>> {
    let mut digits = Vec::with_capacity(value.len() * 2);
    let mut padding = false;
    for &byte in value {
        for nibble in [byte >> 4, byte & 0x0F] {
            match nibble {
                0..=9 if !padding => digits.push(nibble),
                0xF => padding = true,
                _ => return Err(Error::InvalidValue),
            }
        }
    }
    Ok(digits)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// §4.3 example: 1234567890123 as '12 34 56 78 90 12 3F FF'.
    #[test]
    fn decode_section_4_3_example() {
        assert_eq!(
            decode(&[0x12, 0x34, 0x56, 0x78, 0x90, 0x12, 0x3F, 0xFF]).unwrap(),
            vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3]
        );
    }

    #[test]
    fn decode_without_padding() {
        assert_eq!(decode(&[0x12, 0x3F]).unwrap(), vec![1, 2, 3]);
        assert_eq!(decode(&[0x12]).unwrap(), vec![1, 2]);
        assert_eq!(decode(&[]).unwrap(), Vec::<u8>::new());
    }

    #[test]
    fn decode_all_padding_yields_no_digits() {
        assert_eq!(decode(&[0xFF, 0xFF]).unwrap(), Vec::<u8>::new());
    }

    #[test]
    fn decode_rejects_non_decimal_nibble() {
        assert_eq!(decode(&[0x1A]), Err(Error::InvalidValue));
        assert_eq!(decode(&[0xB2]), Err(Error::InvalidValue));
    }

    #[test]
    fn decode_rejects_digit_after_padding() {
        assert_eq!(decode(&[0x1F, 0x23]), Err(Error::InvalidValue));
        assert_eq!(decode(&[0xF1]), Err(Error::InvalidValue));
    }
}
