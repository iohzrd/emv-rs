//! Book 1 §11.3 - SELECT.

use crate::core::apdu::{Cla, Command, Ins};
use crate::core::error::{Error, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SelectOccurrence {
    #[default]
    FirstOrOnly,
    NextOccurrence,
}

impl SelectOccurrence {
    fn p2(self) -> u8 {
        match self {
            Self::FirstOrOnly => 0x00,
            Self::NextOccurrence => 0x02,
        }
    }
}

pub fn select_by_name(name: &[u8], occurrence: SelectOccurrence) -> Result<Command> {
    if !(5..=16).contains(&name.len()) {
        return Err(Error::InvalidValue);
    }
    Ok(Command {
        cla: Cla(0x00),
        ins: Ins::SELECT,
        p1: 0x04,
        p2: occurrence.p2(),
        data: name.to_vec(),
        le: Some(0x00),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn select_pse_first_occurrence() {
        let name = b"1PAY.SYS.DDF01";
        let c = select_by_name(name, SelectOccurrence::FirstOrOnly).unwrap();
        assert_eq!(c.cla.0, 0x00);
        assert_eq!(c.ins, Ins::SELECT);
        assert_eq!(c.p1, 0x04);
        assert_eq!(c.p2, 0x00);
        assert_eq!(c.data, name.to_vec());
        assert_eq!(c.le, Some(0x00));
    }

    #[test]
    fn select_aid_5_bytes_minimum() {
        let aid = [0xA0, 0x00, 0x00, 0x00, 0x03];
        let c = select_by_name(&aid, SelectOccurrence::FirstOrOnly).unwrap();
        assert_eq!(c.data, aid.to_vec());
        assert_eq!(
            c.to_bytes().unwrap(),
            vec![
                0x00, 0xA4, 0x04, 0x00, 0x05, 0xA0, 0x00, 0x00, 0x00, 0x03, 0x00
            ],
        );
    }

    #[test]
    fn select_aid_16_bytes_maximum() {
        let aid = [0u8; 16];
        let c = select_by_name(&aid, SelectOccurrence::FirstOrOnly).unwrap();
        assert_eq!(c.data.len(), 16);
    }

    #[test]
    fn select_next_occurrence_sets_p2() {
        let aid = [0xA0, 0x00, 0x00, 0x00, 0x03, 0x10, 0x10];
        let c = select_by_name(&aid, SelectOccurrence::NextOccurrence).unwrap();
        assert_eq!(c.p2, 0x02);
    }

    #[test]
    fn select_rejects_under_5_bytes() {
        assert_eq!(
            select_by_name(&[0; 4], SelectOccurrence::FirstOrOnly),
            Err(Error::InvalidValue),
        );
    }

    #[test]
    fn select_rejects_over_16_bytes() {
        assert_eq!(
            select_by_name(&[0; 17], SelectOccurrence::FirstOrOnly),
            Err(Error::InvalidValue),
        );
    }

    #[test]
    fn select_rejects_empty() {
        assert_eq!(
            select_by_name(&[], SelectOccurrence::FirstOrOnly),
            Err(Error::InvalidValue),
        );
    }
}
