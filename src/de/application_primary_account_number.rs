//! Application Primary Account Number (tag 5A) - Book 3 §4.3, cn up to
//! 10 bytes (19 digits).

use std::fmt;

use crate::core::compressed_numeric;
use crate::core::error::{Error, Result};

/// `Display` and `Debug` are masked (at most the rightmost four digits);
/// the full value is only reachable through [`Self::digits`].
#[derive(Clone, PartialEq, Eq)]
pub struct ApplicationPrimaryAccountNumber(Vec<u8>);

impl ApplicationPrimaryAccountNumber {
    pub fn parse(value: &[u8]) -> Result<Self> {
        if value.is_empty() || value.len() > 10 {
            return Err(Error::WrongLength {
                expected: 10,
                got: value.len(),
            });
        }
        let digits = compressed_numeric::decode(value)?;
        if digits.is_empty() {
            return Err(Error::InvalidValue);
        }
        Ok(Self(digits))
    }

    /// Decimal digit values, `0..=9` each.
    pub fn digits(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Display for ApplicationPrimaryAccountNumber {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let visible = if self.0.len() > 4 {
            f.write_str("••••")?;
            &self.0[self.0.len() - 4..]
        } else {
            &self.0[..]
        };
        for &digit in visible {
            write!(f, "{digit}")?;
        }
        Ok(())
    }
}

impl fmt::Debug for ApplicationPrimaryAccountNumber {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ApplicationPrimaryAccountNumber({self})")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_masks_all_but_rightmost_four() {
        let pan = ApplicationPrimaryAccountNumber::parse(&[
            0x54, 0x13, 0x33, 0x00, 0x89, 0x60, 0x39, 0x4F,
        ])
        .unwrap();
        assert_eq!(pan.to_string(), "••••0394");
    }

    #[test]
    fn display_shows_four_or_fewer_digits_unmasked() {
        let pan = ApplicationPrimaryAccountNumber::parse(&[0x12, 0x3F]).unwrap();
        assert_eq!(pan.to_string(), "123");
    }

    #[test]
    fn debug_is_masked() {
        let pan = ApplicationPrimaryAccountNumber::parse(&[
            0x12, 0x34, 0x56, 0x78, 0x90, 0x12, 0x3F, 0xFF,
        ])
        .unwrap();
        assert_eq!(
            format!("{pan:?}"),
            "ApplicationPrimaryAccountNumber(••••0123)"
        );
    }

    #[test]
    fn digits_expose_full_value() {
        let pan = ApplicationPrimaryAccountNumber::parse(&[0x12, 0x34, 0x5F]).unwrap();
        assert_eq!(pan.digits(), &[1, 2, 3, 4, 5]);
    }

    #[test]
    fn parse_rejects_empty_too_long_and_digitless() {
        assert!(ApplicationPrimaryAccountNumber::parse(&[]).is_err());
        assert!(ApplicationPrimaryAccountNumber::parse(&[0x12; 11]).is_err());
        assert_eq!(
            ApplicationPrimaryAccountNumber::parse(&[0xFF, 0xFF]),
            Err(Error::InvalidValue)
        );
    }

    #[test]
    fn parse_rejects_non_decimal_nibbles() {
        assert!(ApplicationPrimaryAccountNumber::parse(&[0x1A, 0x23]).is_err());
    }
}
