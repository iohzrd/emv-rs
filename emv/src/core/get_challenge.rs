//! Book 3 §6.5.6 - GET CHALLENGE.

use crate::core::apdu::{Cla, Command, Ins};

pub fn command() -> Command {
    Command {
        cla: Cla(0x00),
        ins: Ins::GET_CHALLENGE,
        p1: 0x00,
        p2: 0x00,
        data: Vec::new(),
        le: Some(0x00),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn get_challenge_wire_bytes() {
        let c = command();
        assert_eq!(c.cla.0, 0x00);
        assert_eq!(c.ins, Ins::GET_CHALLENGE);
        assert_eq!(c.p1, 0x00);
        assert_eq!(c.p2, 0x00);
        assert!(c.data.is_empty());
        assert_eq!(c.le, Some(0x00));
        assert_eq!(c.to_bytes().unwrap(), vec![0x00, 0x84, 0x00, 0x00, 0x00]);
    }
}
