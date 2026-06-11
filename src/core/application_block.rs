//! Book 3 §6.5.1 - APPLICATION BLOCK.

use crate::core::apdu::{Cla, Command, Ins};
use crate::core::secure_messaging::SecureMessagingMode;

pub fn command(mode: SecureMessagingMode, data: Vec<u8>) -> Command {
    Command {
        cla: Cla(mode.cla_byte(false)),
        ins: Ins::APPLICATION_BLOCK,
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
    fn application_block_proprietary_wire_bytes() {
        let mac = vec![0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88];
        let c = command(SecureMessagingMode::Proprietary, mac.clone());
        assert_eq!(c.cla.0, 0x84);
        assert_eq!(c.ins, Ins::APPLICATION_BLOCK);
        assert_eq!(c.p1, 0x00);
        assert_eq!(c.p2, 0x00);
        assert_eq!(c.data, mac);
        assert_eq!(c.le, None);
        assert_eq!(
            c.to_bytes().unwrap(),
            vec![
                0x84, 0x1E, 0x00, 0x00, 0x08, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
            ],
        );
    }

    #[test]
    fn application_block_iso_sm_uses_cla_8c() {
        let c = command(
            SecureMessagingMode::Iso7816HeaderAuthenticated,
            vec![0xAA; 8],
        );
        assert_eq!(c.cla.0, 0x8C);
    }

    #[test]
    fn application_block_does_not_chain() {
        // Book 3 §6.5.13.
        for mode in [
            SecureMessagingMode::Proprietary,
            SecureMessagingMode::Iso7816HeaderAuthenticated,
        ] {
            let c = command(mode, vec![0; 8]);
            assert_eq!(c.cla.0 & 0x10, 0, "{:?}", mode);
        }
    }
}
