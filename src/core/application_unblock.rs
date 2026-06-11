//! Book 3 §6.5.2 - APPLICATION UNBLOCK.

use crate::core::apdu::{Cla, Command, Ins};
use crate::core::secure_messaging::SecureMessagingMode;

pub fn command(mode: SecureMessagingMode, data: Vec<u8>) -> Command {
    Command {
        cla: Cla(mode.cla_byte(false)),
        ins: Ins::APPLICATION_UNBLOCK,
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
    fn application_unblock_proprietary_wire_bytes() {
        let mac = vec![0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE];
        let c = command(SecureMessagingMode::Proprietary, mac.clone());
        assert_eq!(c.cla.0, 0x84);
        assert_eq!(c.ins, Ins::APPLICATION_UNBLOCK);
        assert_eq!(c.p1, 0x00);
        assert_eq!(c.p2, 0x00);
        assert_eq!(c.data, mac);
        assert_eq!(c.le, None);
        assert_eq!(
            c.to_bytes().unwrap(),
            vec![
                0x84, 0x18, 0x00, 0x00, 0x08, 0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE,
            ],
        );
    }

    #[test]
    fn application_unblock_iso_sm_uses_cla_8c() {
        let c = command(
            SecureMessagingMode::Iso7816HeaderAuthenticated,
            vec![0xAA; 8],
        );
        assert_eq!(c.cla.0, 0x8C);
    }
}
