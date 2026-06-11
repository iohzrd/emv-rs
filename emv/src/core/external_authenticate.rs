//! Book 3 §10.9 / Annex F - EXTERNAL AUTHENTICATE command.
//! Used by both contact (Book 3 §10.9) and contactless K3 §6.2.1.1
//! (Issuer Update Processing).

use crate::core::apdu::{Cla, Command, Ins};
use crate::core::error::{Error, Result};

/// Book 3 Table 9 p.55. Data: 8..=16 bytes (Tag '91' value).
pub fn command(issuer_authentication_data: &[u8]) -> Result<Command> {
    if !(8..=16).contains(&issuer_authentication_data.len()) {
        return Err(Error::InvalidValue);
    }
    Ok(Command {
        cla: Cla(0x00),
        ins: Ins::EXTERNAL_AUTHENTICATE,
        p1: 0x00,
        p2: 0x00,
        data: issuer_authentication_data.to_vec(),
        le: None,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    Successful,
    Failed,
    UnsupportedByCardErrorState,
}

/// Book 3 Annex F Table 55.
pub fn interpret_response(sw1: u8, sw2: u8) -> Outcome {
    match u16::from_be_bytes([sw1, sw2]) {
        0x9000 => Outcome::Successful,
        0x6985 => Outcome::UnsupportedByCardErrorState,
        _ => Outcome::Failed,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn minimal_8_byte_cryptogram() {
        let arpc = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88];
        let c = command(&arpc).unwrap();
        assert_eq!(c.cla.0, 0x00);
        assert_eq!(c.ins, Ins::EXTERNAL_AUTHENTICATE);
        assert_eq!(c.p1, 0x00);
        assert_eq!(c.p2, 0x00);
        assert_eq!(c.data, arpc.to_vec());
        assert_eq!(c.le, None);
        assert_eq!(
            c.to_bytes().unwrap(),
            vec![
                0x00, 0x82, 0x00, 0x00, 0x08, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88
            ],
        );
    }

    #[test]
    fn max_16_byte() {
        let data: Vec<u8> = (0u8..16).collect();
        let c = command(&data).unwrap();
        assert_eq!(c.data, data);
    }

    #[test]
    fn rejects_under_8_bytes() {
        assert_eq!(command(&[0u8; 7]), Err(Error::InvalidValue));
    }

    #[test]
    fn rejects_over_16_bytes() {
        assert_eq!(command(&[0u8; 17]), Err(Error::InvalidValue));
    }

    #[test]
    fn interpret_9000_successful() {
        assert_eq!(interpret_response(0x90, 0x00), Outcome::Successful);
    }

    #[test]
    fn interpret_6985_unsupported() {
        assert_eq!(
            interpret_response(0x69, 0x85),
            Outcome::UnsupportedByCardErrorState
        );
    }

    #[test]
    fn interpret_other_failed() {
        for (sw1, sw2) in [(0x6A, 0x82), (0x69, 0x82), (0x67, 0x00), (0x91, 0x99)] {
            assert_eq!(interpret_response(sw1, sw2), Outcome::Failed);
        }
    }
}
