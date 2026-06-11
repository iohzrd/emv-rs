//! Terminal Type (tag 9F35) - Book 4 Annex A1, Table 24.

use crate::core::error::{Error, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TerminalType(pub u8);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OperationalControl {
    FinancialInstitution,
    Merchant,
    Cardholder,
    Rfu(u8),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Environment {
    Attended,
    Unattended,
    Rfu(u8),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttendanceCapability {
    OnlineOnly,
    OfflineWithOnlineCapability,
    OfflineOnly,
    Rfu(u8),
}

impl TerminalType {
    pub fn parse(data: &[u8]) -> Result<Self> {
        if data.len() != 1 {
            return Err(Error::WrongLength {
                expected: 1,
                got: data.len(),
            });
        }
        Ok(TerminalType(data[0]))
    }

    pub fn to_byte(&self) -> u8 {
        self.0
    }

    fn tens(&self) -> u8 {
        self.0 >> 4
    }

    fn ones(&self) -> u8 {
        self.0 & 0x0F
    }

    pub fn operational_control(&self) -> OperationalControl {
        match self.tens() {
            1 => OperationalControl::FinancialInstitution,
            2 => OperationalControl::Merchant,
            3 => OperationalControl::Cardholder,
            other => OperationalControl::Rfu(other),
        }
    }

    pub fn environment(&self) -> Environment {
        match self.ones() {
            1 | 2 | 3 => Environment::Attended,
            4 | 5 | 6 => Environment::Unattended,
            other => Environment::Rfu(other),
        }
    }

    pub fn attendance_capability(&self) -> AttendanceCapability {
        match self.ones() {
            1 | 4 => AttendanceCapability::OnlineOnly,
            2 | 5 => AttendanceCapability::OfflineWithOnlineCapability,
            3 | 6 => AttendanceCapability::OfflineOnly,
            other => AttendanceCapability::Rfu(other),
        }
    }

    /// Book 4 Annex A1 p. 109 - ATM precondition (combine with Additional Terminal
    /// Capabilities byte 1 'cash' bit to classify as ATM).
    pub fn is_unattended_financial_institution(&self) -> bool {
        matches!(self.0, 0x14 | 0x15 | 0x16)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn attended_financial_institution_variants() {
        for (b, cap) in [
            (0x11u8, AttendanceCapability::OnlineOnly),
            (0x12, AttendanceCapability::OfflineWithOnlineCapability),
            (0x13, AttendanceCapability::OfflineOnly),
        ] {
            let t = TerminalType::parse(&[b]).unwrap();
            assert_eq!(
                t.operational_control(),
                OperationalControl::FinancialInstitution
            );
            assert_eq!(t.environment(), Environment::Attended);
            assert_eq!(t.attendance_capability(), cap);
        }
    }

    #[test]
    fn attended_merchant_variants() {
        for (b, cap) in [
            (0x21u8, AttendanceCapability::OnlineOnly),
            (0x22, AttendanceCapability::OfflineWithOnlineCapability),
            (0x23, AttendanceCapability::OfflineOnly),
        ] {
            let t = TerminalType::parse(&[b]).unwrap();
            assert_eq!(t.operational_control(), OperationalControl::Merchant);
            assert_eq!(t.environment(), Environment::Attended);
            assert_eq!(t.attendance_capability(), cap);
        }
    }

    #[test]
    fn unattended_financial_institution_variants() {
        for (b, cap) in [
            (0x14u8, AttendanceCapability::OnlineOnly),
            (0x15, AttendanceCapability::OfflineWithOnlineCapability),
            (0x16, AttendanceCapability::OfflineOnly),
        ] {
            let t = TerminalType::parse(&[b]).unwrap();
            assert_eq!(
                t.operational_control(),
                OperationalControl::FinancialInstitution
            );
            assert_eq!(t.environment(), Environment::Unattended);
            assert_eq!(t.attendance_capability(), cap);
            assert!(t.is_unattended_financial_institution());
        }
    }

    #[test]
    fn unattended_merchant_variants() {
        for (b, cap) in [
            (0x24u8, AttendanceCapability::OnlineOnly),
            (0x25, AttendanceCapability::OfflineWithOnlineCapability),
            (0x26, AttendanceCapability::OfflineOnly),
        ] {
            let t = TerminalType::parse(&[b]).unwrap();
            assert_eq!(t.operational_control(), OperationalControl::Merchant);
            assert_eq!(t.environment(), Environment::Unattended);
            assert_eq!(t.attendance_capability(), cap);
        }
    }

    #[test]
    fn unattended_cardholder_variants() {
        for (b, cap) in [
            (0x34u8, AttendanceCapability::OnlineOnly),
            (0x35, AttendanceCapability::OfflineWithOnlineCapability),
            (0x36, AttendanceCapability::OfflineOnly),
        ] {
            let t = TerminalType::parse(&[b]).unwrap();
            assert_eq!(t.operational_control(), OperationalControl::Cardholder);
            assert_eq!(t.environment(), Environment::Unattended);
            assert_eq!(t.attendance_capability(), cap);
        }
    }

    #[test]
    fn annex_e_examples_match_table_24() {
        let atm = TerminalType::parse(&[0x14]).unwrap();
        assert_eq!(atm.operational_control(), OperationalControl::FinancialInstitution);
        assert_eq!(atm.environment(), Environment::Unattended);
        assert_eq!(atm.attendance_capability(), AttendanceCapability::OnlineOnly);
        assert!(atm.is_unattended_financial_institution());

        let pos = TerminalType::parse(&[0x22]).unwrap();
        assert_eq!(pos.operational_control(), OperationalControl::Merchant);
        assert_eq!(pos.environment(), Environment::Attended);
        assert_eq!(
            pos.attendance_capability(),
            AttendanceCapability::OfflineWithOnlineCapability
        );
        assert!(!pos.is_unattended_financial_institution());

        let vending = TerminalType::parse(&[0x26]).unwrap();
        assert_eq!(vending.operational_control(), OperationalControl::Merchant);
        assert_eq!(vending.environment(), Environment::Unattended);
        assert_eq!(
            vending.attendance_capability(),
            AttendanceCapability::OfflineOnly
        );
        assert!(!vending.is_unattended_financial_institution());
    }

    #[test]
    fn rfu_tens_digit() {
        for tens in [0u8, 4, 5, 6, 7, 8, 9] {
            let b = (tens << 4) | 0x01;
            let t = TerminalType::parse(&[b]).unwrap();
            assert_eq!(t.operational_control(), OperationalControl::Rfu(tens));
        }
    }

    #[test]
    fn rfu_ones_digit() {
        for ones in [0u8, 7, 8, 9] {
            let t = TerminalType::parse(&[0x10 | ones]).unwrap();
            assert_eq!(t.environment(), Environment::Rfu(ones));
            assert_eq!(t.attendance_capability(), AttendanceCapability::Rfu(ones));
        }
    }

    #[test]
    fn parse_wrong_length() {
        assert_eq!(
            TerminalType::parse(&[]),
            Err(Error::WrongLength { expected: 1, got: 0 })
        );
        assert_eq!(
            TerminalType::parse(&[0x11, 0x22]),
            Err(Error::WrongLength { expected: 1, got: 2 })
        );
    }

    #[test]
    fn roundtrip_all_table_24_codes() {
        for b in [
            0x11u8, 0x12, 0x13,
            0x21, 0x22, 0x23,
            0x14, 0x15, 0x16,
            0x24, 0x25, 0x26,
            0x34, 0x35, 0x36,
        ] {
            let t = TerminalType::parse(&[b]).unwrap();
            assert_eq!(t.to_byte(), b);
        }
    }
}
