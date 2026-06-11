//! Book 3 §6.5.9 - INTERNAL AUTHENTICATE.

use crate::core::apdu::{Cla, Command, Ins};

pub fn command(data: Vec<u8>) -> Command {
    Command {
        cla: Cla(0x00),
        ins: Ins::INTERNAL_AUTHENTICATE,
        p1: 0x00,
        p2: 0x00,
        data,
        le: Some(0x00),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn internal_authenticate_wire_bytes() {
        let ddol = vec![0x12, 0x34, 0x56, 0x78];
        let c = command(ddol.clone());
        assert_eq!(c.cla.0, 0x00);
        assert_eq!(c.ins, Ins::INTERNAL_AUTHENTICATE);
        assert_eq!(c.p1, 0x00);
        assert_eq!(c.p2, 0x00);
        assert_eq!(c.data, ddol);
        assert_eq!(c.le, Some(0x00));
        assert_eq!(
            c.to_bytes().unwrap(),
            vec![0x00, 0x88, 0x00, 0x00, 0x04, 0x12, 0x34, 0x56, 0x78, 0x00],
        );
    }

    #[test]
    fn internal_authenticate_empty_data_is_case_2() {
        let c = command(Vec::new());
        assert_eq!(c.to_bytes().unwrap(), vec![0x00, 0x88, 0x00, 0x00, 0x00]);
    }
}
