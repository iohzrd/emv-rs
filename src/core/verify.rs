//! Book 3 §6.5.12 - VERIFY.

use crate::core::apdu::{Cla, Command, Ins};
use crate::core::error::{Error, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerifyQualifier {
    PlaintextPin,
    EncipheredPinRsa,
    EncipheredBiometricRsa,
    EncipheredPinEcc,
    EncipheredBiometricEcc,
}

impl VerifyQualifier {
    fn p2(self) -> u8 {
        match self {
            Self::PlaintextPin => 0x80,
            Self::EncipheredPinRsa => 0x88,
            Self::EncipheredBiometricRsa => 0x89,
            Self::EncipheredPinEcc => 0x8A,
            Self::EncipheredBiometricEcc => 0x8B,
        }
    }
}

pub fn command(qualifier: VerifyQualifier, data: Vec<u8>, chained: bool) -> Command {
    let cla = if chained { 0x10 } else { 0x00 };
    Command {
        cla: Cla(cla),
        ins: Ins::VERIFY,
        p1: 0x00,
        p2: qualifier.p2(),
        data,
        le: None,
    }
}

pub fn command_plaintext_pin(pin: &[u8]) -> Result<Command> {
    let block = plaintext_pin_block(pin)?;
    Ok(command(
        VerifyQualifier::PlaintextPin,
        block.to_vec(),
        false,
    ))
}

pub fn plaintext_pin_block(pin: &[u8]) -> Result<[u8; 8]> {
    if !(4..=12).contains(&pin.len()) || pin.iter().any(|&d| d > 9) {
        return Err(Error::InvalidValue);
    }
    let mut nibbles = [0xFu8; 16];
    nibbles[0] = 0x2;
    nibbles[1] = pin.len() as u8;
    for (i, &d) in pin.iter().enumerate() {
        nibbles[2 + i] = d;
    }
    let mut block = [0u8; 8];
    for (i, b) in block.iter_mut().enumerate() {
        *b = (nibbles[2 * i] << 4) | nibbles[2 * i + 1];
    }
    Ok(block)
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- plaintext PIN block --------------------------------------------

    #[test]
    fn pin_block_4_digits() {
        assert_eq!(
            plaintext_pin_block(&[1, 2, 3, 4]).unwrap(),
            [0x24, 0x12, 0x34, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF],
        );
    }

    #[test]
    fn pin_block_6_digits() {
        assert_eq!(
            plaintext_pin_block(&[1, 2, 3, 4, 5, 6]).unwrap(),
            [0x26, 0x12, 0x34, 0x56, 0xFF, 0xFF, 0xFF, 0xFF],
        );
    }

    #[test]
    fn pin_block_12_digits_max() {
        assert_eq!(
            plaintext_pin_block(&[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1]).unwrap(),
            [0x2C, 0x01, 0x23, 0x45, 0x67, 0x89, 0x01, 0xFF],
        );
    }

    #[test]
    fn pin_block_rejects_under_4_digits() {
        assert_eq!(plaintext_pin_block(&[1, 2, 3]), Err(Error::InvalidValue));
    }

    #[test]
    fn pin_block_rejects_over_12_digits() {
        assert_eq!(
            plaintext_pin_block(&[1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3]),
            Err(Error::InvalidValue),
        );
    }

    #[test]
    fn pin_block_rejects_empty() {
        assert_eq!(plaintext_pin_block(&[]), Err(Error::InvalidValue));
    }

    #[test]
    fn pin_block_rejects_non_decimal_digit() {
        assert_eq!(
            plaintext_pin_block(&[1, 2, 0xA, 4]),
            Err(Error::InvalidValue)
        );
    }

    // ---- VERIFY command -------------------------------------------------

    #[test]
    fn verify_plaintext_pin_wire_bytes() {
        let c = command_plaintext_pin(&[1, 2, 3, 4]).unwrap();
        assert_eq!(c.cla.0, 0x00);
        assert_eq!(c.ins, Ins::VERIFY);
        assert_eq!(c.p1, 0x00);
        assert_eq!(c.p2, 0x80);
        assert_eq!(c.data, vec![0x24, 0x12, 0x34, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]);
        assert_eq!(c.le, None);
        assert_eq!(
            c.to_bytes().unwrap(),
            vec![
                0x00, 0x20, 0x00, 0x80, 0x08, 0x24, 0x12, 0x34, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            ],
        );
    }

    #[test]
    fn verify_qualifier_p2_values_match_table_24() {
        for (q, p2) in [
            (VerifyQualifier::PlaintextPin, 0x80),
            (VerifyQualifier::EncipheredPinRsa, 0x88),
            (VerifyQualifier::EncipheredBiometricRsa, 0x89),
            (VerifyQualifier::EncipheredPinEcc, 0x8A),
            (VerifyQualifier::EncipheredBiometricEcc, 0x8B),
        ] {
            let c = command(q, vec![], false);
            assert_eq!(c.p2, p2, "{:?}", q);
        }
    }

    #[test]
    fn verify_chained_sets_cla_to_10() {
        let c = command(VerifyQualifier::EncipheredBiometricRsa, vec![0xAA], true);
        assert_eq!(c.cla.0, 0x10);
        assert_eq!(c.cla.command_chaining(), Some(true));
    }

    #[test]
    fn verify_unchained_cla_is_00() {
        let c = command(VerifyQualifier::EncipheredBiometricRsa, vec![0xAA], false);
        assert_eq!(c.cla.0, 0x00);
        assert_eq!(c.cla.command_chaining(), Some(false));
    }
}
