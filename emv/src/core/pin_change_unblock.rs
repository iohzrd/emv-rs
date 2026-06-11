//! Book 3 §6.5.10 - PIN CHANGE/UNBLOCK.

use crate::core::apdu::{Cla, Command, Ins};
use crate::core::error::{Error, Result};
use crate::core::secure_messaging::SecureMessagingMode;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PinChangeUnblockQualifier {
    Unblock,
    UnblockBiometricType,
    PaymentSystem(u8),
}

impl PinChangeUnblockQualifier {
    fn p2(self) -> Result<u8> {
        match self {
            Self::Unblock => Ok(0x00),
            Self::UnblockBiometricType => Ok(0x03),
            Self::PaymentSystem(v) if matches!(v, 0x01 | 0x02 | 0x04) => Ok(v),
            Self::PaymentSystem(_) => Err(Error::InvalidValue),
        }
    }
}

pub fn command(
    mode: SecureMessagingMode,
    qualifier: PinChangeUnblockQualifier,
    data: Vec<u8>,
    chained: bool,
) -> Result<Command> {
    Ok(Command {
        cla: Cla(mode.cla_byte(chained)),
        ins: Ins::PIN_CHANGE_UNBLOCK,
        p1: 0x00,
        p2: qualifier.p2()?,
        data,
        le: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unblock_pin_proprietary_wire_bytes() {
        let mac = vec![0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88];
        let c = command(
            SecureMessagingMode::Proprietary,
            PinChangeUnblockQualifier::Unblock,
            mac.clone(),
            false,
        )
        .unwrap();
        assert_eq!(c.cla.0, 0x84);
        assert_eq!(c.ins, Ins::PIN_CHANGE_UNBLOCK);
        assert_eq!(c.p1, 0x00);
        assert_eq!(c.p2, 0x00);
        assert_eq!(c.data, mac);
        assert_eq!(c.le, None);
        assert_eq!(
            c.to_bytes().unwrap(),
            vec![
                0x84, 0x24, 0x00, 0x00, 0x08, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
            ],
        );
    }

    #[test]
    fn unblock_biometric_type_p2_is_03() {
        let data = vec![0x01, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11];
        let c = command(
            SecureMessagingMode::Iso7816HeaderAuthenticated,
            PinChangeUnblockQualifier::UnblockBiometricType,
            data.clone(),
            false,
        )
        .unwrap();
        assert_eq!(c.cla.0, 0x8C);
        assert_eq!(c.p2, 0x03);
        assert_eq!(c.data, data);
    }

    #[test]
    fn payment_system_p2_accepts_01_02_04() {
        for p2 in [0x01u8, 0x02, 0x04] {
            let c = command(
                SecureMessagingMode::Proprietary,
                PinChangeUnblockQualifier::PaymentSystem(p2),
                vec![0xAA; 16],
                false,
            )
            .unwrap();
            assert_eq!(c.p2, p2);
        }
    }

    #[test]
    fn payment_system_rejects_other_p2() {
        for bad in [0x00u8, 0x03, 0x05, 0x10, 0xFF] {
            assert_eq!(
                command(
                    SecureMessagingMode::Proprietary,
                    PinChangeUnblockQualifier::PaymentSystem(bad),
                    vec![],
                    false,
                ),
                Err(Error::InvalidValue),
                "{:#04x}",
                bad,
            );
        }
    }

    #[test]
    fn chained_intermediate_uses_94() {
        let c = command(
            SecureMessagingMode::Proprietary,
            PinChangeUnblockQualifier::PaymentSystem(0x02),
            vec![0xAA; 200],
            true,
        )
        .unwrap();
        assert_eq!(c.cla.0, 0x94);
    }

    #[test]
    fn chained_intermediate_iso_sm_uses_9c() {
        let c = command(
            SecureMessagingMode::Iso7816HeaderAuthenticated,
            PinChangeUnblockQualifier::PaymentSystem(0x01),
            vec![0xAA; 200],
            true,
        )
        .unwrap();
        assert_eq!(c.cla.0, 0x9C);
    }

    #[test]
    fn last_command_of_chain_clears_b5() {
        let c = command(
            SecureMessagingMode::Proprietary,
            PinChangeUnblockQualifier::PaymentSystem(0x02),
            vec![0xAA; 16],
            false,
        )
        .unwrap();
        assert_eq!(c.cla.0, 0x84);
        assert_eq!(c.cla.0 & 0x10, 0);
    }

    #[test]
    fn p1_always_zero() {
        for q in [
            PinChangeUnblockQualifier::Unblock,
            PinChangeUnblockQualifier::UnblockBiometricType,
            PinChangeUnblockQualifier::PaymentSystem(0x01),
            PinChangeUnblockQualifier::PaymentSystem(0x02),
            PinChangeUnblockQualifier::PaymentSystem(0x04),
        ] {
            let c = command(SecureMessagingMode::Proprietary, q, vec![0xAA; 8], false).unwrap();
            assert_eq!(c.p1, 0x00);
        }
    }

    #[test]
    fn ins_is_24() {
        let c = command(
            SecureMessagingMode::Proprietary,
            PinChangeUnblockQualifier::Unblock,
            vec![0xAA; 8],
            false,
        )
        .unwrap();
        assert_eq!(c.ins.0, 0x24);
    }
}
