//! Book 3 §6.5.3 - CARD BLOCK.

use crate::core::apdu::{Cla, Command, Ins};
use crate::core::secure_messaging::SecureMessagingMode;

pub fn command(mode: SecureMessagingMode, data: Vec<u8>) -> Command {
    Command {
        cla: Cla(mode.cla_byte(false)),
        ins: Ins::CARD_BLOCK,
        p1: 0x00,
        p2: 0x00,
        data,
        le: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn card_block_proprietary_wire_bytes() {
        let mac = vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
        let c = command(SecureMessagingMode::Proprietary, mac.clone());
        assert_eq!(c.cla.0, 0x84);
        assert_eq!(c.ins, Ins::CARD_BLOCK);
        assert_eq!(c.p1, 0x00);
        assert_eq!(c.p2, 0x00);
        assert_eq!(c.data, mac);
        assert_eq!(c.le, None);
        assert_eq!(
            c.to_bytes().unwrap(),
            vec![
                0x84, 0x16, 0x00, 0x00, 0x08, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
            ],
        );
    }

    #[test]
    fn card_block_iso_sm_uses_cla_8c() {
        let c = command(
            SecureMessagingMode::Iso7816HeaderAuthenticated,
            vec![0xAA; 8],
        );
        assert_eq!(c.cla.0, 0x8C);
    }
}
