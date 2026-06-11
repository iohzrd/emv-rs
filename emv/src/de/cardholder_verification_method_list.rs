//! CVM List (tag 8E) - Book 3 Annex C3, Tables 43–44.

use crate::core::error::{Error, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CardholderVerificationMethodRule {
    pub cvm: u8,
    pub condition: u8,
}

impl CardholderVerificationMethodRule {
    pub fn new(cvm: u8, condition: u8) -> Self {
        Self { cvm, condition }
    }

    pub fn to_bytes(&self) -> [u8; 2] {
        [self.cvm, self.condition]
    }

    /// b8 - RFU.
    pub fn rfu_bit(&self) -> bool {
        self.cvm & 0b1000_0000 != 0
    }

    /// b7 = 0 - fail cardholder verification if this CVM is unsuccessful.
    pub fn fail_cardholder_verification_if_unsuccessful(&self) -> bool {
        self.cvm & 0b0100_0000 == 0
    }

    /// b7 = 1 - apply succeeding CV Rule if this CVM is unsuccessful.
    pub fn apply_succeeding_cv_rule_if_unsuccessful(&self) -> bool {
        self.cvm & 0b0100_0000 != 0
    }

    /// 6-bit CVM method (b6..b1).
    pub fn method_code(&self) -> u8 {
        self.cvm & 0b0011_1111
    }

    pub fn method(&self) -> CardholderVerificationMethod {
        CardholderVerificationMethod::from_code(self.method_code())
    }

    pub fn condition(&self) -> CardholderVerificationMethodCondition {
        CardholderVerificationMethodCondition::from_code(self.condition)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CardholderVerificationMethod {
    FailCvmProcessing,
    PlaintextPinVerificationPerformedByIcc,
    EncipheredPinVerifiedOnline,
    PlaintextPinVerificationPerformedByIccAndSignature,
    EncipheredPinVerificationPerformedByIcc,
    EncipheredPinVerificationPerformedByIccAndSignature,
    FacialBiometricVerifiedOfflineByIcc,
    FacialBiometricVerifiedOnline,
    FingerBiometricVerifiedOfflineByIcc,
    FingerBiometricVerifiedOnline,
    PalmBiometricVerifiedOfflineByIcc,
    PalmBiometricVerifiedOnline,
    IrisBiometricVerifiedOfflineByIcc,
    IrisBiometricVerifiedOnline,
    VoiceBiometricVerifiedOfflineByIcc,
    VoiceBiometricVerifiedOnline,
    /// 010000-011101
    Rfu(u8),
    Signature,
    NoCvmRequired,
    /// 100000-101111
    ReservedForIndividualPaymentSystems(u8),
    /// 110000-111110
    ReservedForIssuer(u8),
    /// 111111
    NotAvailableForUse,
}

impl CardholderVerificationMethod {
    pub fn from_code(code: u8) -> Self {
        let c = code & 0b0011_1111;
        match c {
            0b000000 => Self::FailCvmProcessing,
            0b000001 => Self::PlaintextPinVerificationPerformedByIcc,
            0b000010 => Self::EncipheredPinVerifiedOnline,
            0b000011 => Self::PlaintextPinVerificationPerformedByIccAndSignature,
            0b000100 => Self::EncipheredPinVerificationPerformedByIcc,
            0b000101 => Self::EncipheredPinVerificationPerformedByIccAndSignature,
            0b000110 => Self::FacialBiometricVerifiedOfflineByIcc,
            0b000111 => Self::FacialBiometricVerifiedOnline,
            0b001000 => Self::FingerBiometricVerifiedOfflineByIcc,
            0b001001 => Self::FingerBiometricVerifiedOnline,
            0b001010 => Self::PalmBiometricVerifiedOfflineByIcc,
            0b001011 => Self::PalmBiometricVerifiedOnline,
            0b001100 => Self::IrisBiometricVerifiedOfflineByIcc,
            0b001101 => Self::IrisBiometricVerifiedOnline,
            0b001110 => Self::VoiceBiometricVerifiedOfflineByIcc,
            0b001111 => Self::VoiceBiometricVerifiedOnline,
            0b010000..=0b011101 => Self::Rfu(c),
            0b011110 => Self::Signature,
            0b011111 => Self::NoCvmRequired,
            0b100000..=0b101111 => Self::ReservedForIndividualPaymentSystems(c),
            0b110000..=0b111110 => Self::ReservedForIssuer(c),
            0b111111 => Self::NotAvailableForUse,
            _ => unreachable!(),
        }
    }

    pub fn to_code(&self) -> u8 {
        match self {
            Self::FailCvmProcessing => 0b000000,
            Self::PlaintextPinVerificationPerformedByIcc => 0b000001,
            Self::EncipheredPinVerifiedOnline => 0b000010,
            Self::PlaintextPinVerificationPerformedByIccAndSignature => 0b000011,
            Self::EncipheredPinVerificationPerformedByIcc => 0b000100,
            Self::EncipheredPinVerificationPerformedByIccAndSignature => 0b000101,
            Self::FacialBiometricVerifiedOfflineByIcc => 0b000110,
            Self::FacialBiometricVerifiedOnline => 0b000111,
            Self::FingerBiometricVerifiedOfflineByIcc => 0b001000,
            Self::FingerBiometricVerifiedOnline => 0b001001,
            Self::PalmBiometricVerifiedOfflineByIcc => 0b001010,
            Self::PalmBiometricVerifiedOnline => 0b001011,
            Self::IrisBiometricVerifiedOfflineByIcc => 0b001100,
            Self::IrisBiometricVerifiedOnline => 0b001101,
            Self::VoiceBiometricVerifiedOfflineByIcc => 0b001110,
            Self::VoiceBiometricVerifiedOnline => 0b001111,
            Self::Rfu(c) => c & 0b0011_1111,
            Self::Signature => 0b011110,
            Self::NoCvmRequired => 0b011111,
            Self::ReservedForIndividualPaymentSystems(c) => c & 0b0011_1111,
            Self::ReservedForIssuer(c) => c & 0b0011_1111,
            Self::NotAvailableForUse => 0b111111,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CardholderVerificationMethodCondition {
    Always,
    IfUnattendedCash,
    IfNotUnattendedCashAndNotManualCashAndNotPurchaseWithCashback,
    IfTerminalSupportsTheCvm,
    IfManualCash,
    IfPurchaseWithCashback,
    IfTransactionIsInTheApplicationCurrencyAndIsUnderXValue,
    IfTransactionIsInTheApplicationCurrencyAndIsOverXValue,
    IfTransactionIsInTheApplicationCurrencyAndIsUnderYValue,
    IfTransactionIsInTheApplicationCurrencyAndIsOverYValue,
    /// '0A'–'7F'
    Rfu(u8),
    /// '80'–'FF'
    ReservedForIndividualPaymentSystems(u8),
}

impl CardholderVerificationMethodCondition {
    pub fn from_code(code: u8) -> Self {
        match code {
            0x00 => Self::Always,
            0x01 => Self::IfUnattendedCash,
            0x02 => Self::IfNotUnattendedCashAndNotManualCashAndNotPurchaseWithCashback,
            0x03 => Self::IfTerminalSupportsTheCvm,
            0x04 => Self::IfManualCash,
            0x05 => Self::IfPurchaseWithCashback,
            0x06 => Self::IfTransactionIsInTheApplicationCurrencyAndIsUnderXValue,
            0x07 => Self::IfTransactionIsInTheApplicationCurrencyAndIsOverXValue,
            0x08 => Self::IfTransactionIsInTheApplicationCurrencyAndIsUnderYValue,
            0x09 => Self::IfTransactionIsInTheApplicationCurrencyAndIsOverYValue,
            0x0A..=0x7F => Self::Rfu(code),
            0x80..=0xFF => Self::ReservedForIndividualPaymentSystems(code),
        }
    }

    pub fn to_code(&self) -> u8 {
        match self {
            Self::Always => 0x00,
            Self::IfUnattendedCash => 0x01,
            Self::IfNotUnattendedCashAndNotManualCashAndNotPurchaseWithCashback => 0x02,
            Self::IfTerminalSupportsTheCvm => 0x03,
            Self::IfManualCash => 0x04,
            Self::IfPurchaseWithCashback => 0x05,
            Self::IfTransactionIsInTheApplicationCurrencyAndIsUnderXValue => 0x06,
            Self::IfTransactionIsInTheApplicationCurrencyAndIsOverXValue => 0x07,
            Self::IfTransactionIsInTheApplicationCurrencyAndIsUnderYValue => 0x08,
            Self::IfTransactionIsInTheApplicationCurrencyAndIsOverYValue => 0x09,
            Self::Rfu(c) => *c,
            Self::ReservedForIndividualPaymentSystems(c) => *c,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CardholderVerificationMethodList {
    pub amount_x: u32,
    pub amount_y: u32,
    pub rules: Vec<CardholderVerificationMethodRule>,
}

impl CardholderVerificationMethodList {
    pub fn parse(data: &[u8]) -> Result<Self> {
        if data.len() < 8 {
            return Err(Error::UnexpectedEof);
        }
        let rules_bytes = data.len() - 8;
        if rules_bytes % 2 != 0 {
            return Err(Error::InvalidValue);
        }
        let amount_x = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
        let amount_y = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
        let mut rules = Vec::with_capacity(rules_bytes / 2);
        let mut i = 8;
        while i < data.len() {
            rules.push(CardholderVerificationMethodRule {
                cvm: data[i],
                condition: data[i + 1],
            });
            i += 2;
        }
        Ok(CardholderVerificationMethodList {
            amount_x,
            amount_y,
            rules,
        })
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(8 + self.rules.len() * 2);
        out.extend_from_slice(&self.amount_x.to_be_bytes());
        out.extend_from_slice(&self.amount_y.to_be_bytes());
        for r in &self.rules {
            out.push(r.cvm);
            out.push(r.condition);
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rule_bit7_fail_vs_apply_succeeding() {
        let r = CardholderVerificationMethodRule::new(0b0000_0001, 0x00);
        assert!(r.fail_cardholder_verification_if_unsuccessful());
        assert!(!r.apply_succeeding_cv_rule_if_unsuccessful());

        let r = CardholderVerificationMethodRule::new(0b0100_0001, 0x00);
        assert!(!r.fail_cardholder_verification_if_unsuccessful());
        assert!(r.apply_succeeding_cv_rule_if_unsuccessful());
    }

    #[test]
    fn rule_bit8_is_rfu() {
        assert!(!CardholderVerificationMethodRule::new(0b0000_0000, 0x00).rfu_bit());
        assert!(CardholderVerificationMethodRule::new(0b1000_0000, 0x00).rfu_bit());
    }

    #[test]
    fn rule_method_ignores_flag_bits() {
        let r = CardholderVerificationMethodRule::new(0b1101_1111, 0x00);
        assert_eq!(r.method_code(), 0b0011_1111 & 0b0001_1111);
        assert_eq!(r.method(), CardholderVerificationMethod::NoCvmRequired);
    }

    #[test]
    fn method_table_roundtrip() {
        for c in 0u8..=0b0011_1111 {
            let m = CardholderVerificationMethod::from_code(c);
            assert_eq!(m.to_code(), c, "code {:06b} did not round-trip", c);
        }
    }

    #[test]
    fn method_specific_decodings() {
        assert_eq!(CardholderVerificationMethod::from_code(0b000000), CardholderVerificationMethod::FailCvmProcessing);
        assert_eq!(
            CardholderVerificationMethod::from_code(0b000001),
            CardholderVerificationMethod::PlaintextPinVerificationPerformedByIcc
        );
        assert_eq!(
            CardholderVerificationMethod::from_code(0b000010),
            CardholderVerificationMethod::EncipheredPinVerifiedOnline
        );
        assert_eq!(
            CardholderVerificationMethod::from_code(0b000011),
            CardholderVerificationMethod::PlaintextPinVerificationPerformedByIccAndSignature
        );
        assert_eq!(
            CardholderVerificationMethod::from_code(0b000100),
            CardholderVerificationMethod::EncipheredPinVerificationPerformedByIcc
        );
        assert_eq!(
            CardholderVerificationMethod::from_code(0b000101),
            CardholderVerificationMethod::EncipheredPinVerificationPerformedByIccAndSignature
        );
        assert_eq!(
            CardholderVerificationMethod::from_code(0b000110),
            CardholderVerificationMethod::FacialBiometricVerifiedOfflineByIcc
        );
        assert_eq!(
            CardholderVerificationMethod::from_code(0b000111),
            CardholderVerificationMethod::FacialBiometricVerifiedOnline
        );
        assert_eq!(
            CardholderVerificationMethod::from_code(0b001000),
            CardholderVerificationMethod::FingerBiometricVerifiedOfflineByIcc
        );
        assert_eq!(
            CardholderVerificationMethod::from_code(0b001001),
            CardholderVerificationMethod::FingerBiometricVerifiedOnline
        );
        assert_eq!(
            CardholderVerificationMethod::from_code(0b001010),
            CardholderVerificationMethod::PalmBiometricVerifiedOfflineByIcc
        );
        assert_eq!(
            CardholderVerificationMethod::from_code(0b001011),
            CardholderVerificationMethod::PalmBiometricVerifiedOnline
        );
        assert_eq!(
            CardholderVerificationMethod::from_code(0b001100),
            CardholderVerificationMethod::IrisBiometricVerifiedOfflineByIcc
        );
        assert_eq!(
            CardholderVerificationMethod::from_code(0b001101),
            CardholderVerificationMethod::IrisBiometricVerifiedOnline
        );
        assert_eq!(
            CardholderVerificationMethod::from_code(0b001110),
            CardholderVerificationMethod::VoiceBiometricVerifiedOfflineByIcc
        );
        assert_eq!(
            CardholderVerificationMethod::from_code(0b001111),
            CardholderVerificationMethod::VoiceBiometricVerifiedOnline
        );
        assert_eq!(CardholderVerificationMethod::from_code(0b011110), CardholderVerificationMethod::Signature);
        assert_eq!(CardholderVerificationMethod::from_code(0b011111), CardholderVerificationMethod::NoCvmRequired);
        assert_eq!(
            CardholderVerificationMethod::from_code(0b111111),
            CardholderVerificationMethod::NotAvailableForUse
        );
    }

    #[test]
    fn method_reserved_ranges() {
        assert_eq!(CardholderVerificationMethod::from_code(0b010000), CardholderVerificationMethod::Rfu(0b010000));
        assert_eq!(CardholderVerificationMethod::from_code(0b011101), CardholderVerificationMethod::Rfu(0b011101));
        assert_eq!(
            CardholderVerificationMethod::from_code(0b100000),
            CardholderVerificationMethod::ReservedForIndividualPaymentSystems(0b100000)
        );
        assert_eq!(
            CardholderVerificationMethod::from_code(0b101111),
            CardholderVerificationMethod::ReservedForIndividualPaymentSystems(0b101111)
        );
        assert_eq!(
            CardholderVerificationMethod::from_code(0b110000),
            CardholderVerificationMethod::ReservedForIssuer(0b110000)
        );
        assert_eq!(
            CardholderVerificationMethod::from_code(0b111110),
            CardholderVerificationMethod::ReservedForIssuer(0b111110)
        );
    }

    #[test]
    fn condition_table_roundtrip() {
        for c in 0u8..=0xFF {
            let cond = CardholderVerificationMethodCondition::from_code(c);
            assert_eq!(cond.to_code(), c, "code {:02X} did not round-trip", c);
        }
    }

    #[test]
    fn condition_specific_decodings() {
        assert_eq!(CardholderVerificationMethodCondition::from_code(0x00), CardholderVerificationMethodCondition::Always);
        assert_eq!(
            CardholderVerificationMethodCondition::from_code(0x01),
            CardholderVerificationMethodCondition::IfUnattendedCash
        );
        assert_eq!(
            CardholderVerificationMethodCondition::from_code(0x02),
            CardholderVerificationMethodCondition::IfNotUnattendedCashAndNotManualCashAndNotPurchaseWithCashback
        );
        assert_eq!(
            CardholderVerificationMethodCondition::from_code(0x03),
            CardholderVerificationMethodCondition::IfTerminalSupportsTheCvm
        );
        assert_eq!(CardholderVerificationMethodCondition::from_code(0x04), CardholderVerificationMethodCondition::IfManualCash);
        assert_eq!(
            CardholderVerificationMethodCondition::from_code(0x05),
            CardholderVerificationMethodCondition::IfPurchaseWithCashback
        );
        assert_eq!(
            CardholderVerificationMethodCondition::from_code(0x06),
            CardholderVerificationMethodCondition::IfTransactionIsInTheApplicationCurrencyAndIsUnderXValue
        );
        assert_eq!(
            CardholderVerificationMethodCondition::from_code(0x07),
            CardholderVerificationMethodCondition::IfTransactionIsInTheApplicationCurrencyAndIsOverXValue
        );
        assert_eq!(
            CardholderVerificationMethodCondition::from_code(0x08),
            CardholderVerificationMethodCondition::IfTransactionIsInTheApplicationCurrencyAndIsUnderYValue
        );
        assert_eq!(
            CardholderVerificationMethodCondition::from_code(0x09),
            CardholderVerificationMethodCondition::IfTransactionIsInTheApplicationCurrencyAndIsOverYValue
        );
        assert_eq!(CardholderVerificationMethodCondition::from_code(0x0A), CardholderVerificationMethodCondition::Rfu(0x0A));
        assert_eq!(CardholderVerificationMethodCondition::from_code(0x7F), CardholderVerificationMethodCondition::Rfu(0x7F));
        assert_eq!(
            CardholderVerificationMethodCondition::from_code(0x80),
            CardholderVerificationMethodCondition::ReservedForIndividualPaymentSystems(0x80)
        );
        assert_eq!(
            CardholderVerificationMethodCondition::from_code(0xFF),
            CardholderVerificationMethodCondition::ReservedForIndividualPaymentSystems(0xFF)
        );
    }

    #[test]
    fn list_parse_roundtrip() {
        let wire: [u8; 14] = [
            0x00, 0x00, 0x03, 0xE8, 0x00, 0x00, 0x13, 0x88,
            0x42, 0x03,
            0x1E, 0x02,
            0x1F, 0x00,
        ];
        let list = CardholderVerificationMethodList::parse(&wire).unwrap();
        assert_eq!(list.amount_x, 1000);
        assert_eq!(list.amount_y, 5000);
        assert_eq!(list.rules.len(), 3);

        assert_eq!(list.rules[0].cvm, 0x42);
        assert!(list.rules[0].apply_succeeding_cv_rule_if_unsuccessful());
        assert_eq!(
            list.rules[0].method(),
            CardholderVerificationMethod::EncipheredPinVerifiedOnline
        );
        assert_eq!(
            list.rules[0].condition(),
            CardholderVerificationMethodCondition::IfTerminalSupportsTheCvm
        );

        assert_eq!(list.rules[1].method(), CardholderVerificationMethod::Signature);
        assert_eq!(
            list.rules[1].condition(),
            CardholderVerificationMethodCondition::IfNotUnattendedCashAndNotManualCashAndNotPurchaseWithCashback
        );
        assert!(list.rules[1].fail_cardholder_verification_if_unsuccessful());

        assert_eq!(list.rules[2].method(), CardholderVerificationMethod::NoCvmRequired);
        assert_eq!(list.rules[2].condition(), CardholderVerificationMethodCondition::Always);

        assert_eq!(list.to_bytes(), wire);
    }

    #[test]
    fn list_minimum_length_is_eight_bytes_no_rules() {
        let wire = [0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE];
        let list = CardholderVerificationMethodList::parse(&wire).unwrap();
        assert_eq!(list.amount_x, 0xDEAD_BEEF);
        assert_eq!(list.amount_y, 0xCAFE_BABE);
        assert!(list.rules.is_empty());
        assert_eq!(list.to_bytes(), wire);
    }

    #[test]
    fn list_parse_wrong_length() {
        assert_eq!(CardholderVerificationMethodList::parse(&[]), Err(Error::UnexpectedEof));
        assert_eq!(CardholderVerificationMethodList::parse(&[0x00; 7]), Err(Error::UnexpectedEof));

        let mut wire = vec![0u8; 8];
        wire.push(0x1F);
        assert_eq!(CardholderVerificationMethodList::parse(&wire), Err(Error::InvalidValue));

        let mut wire = vec![0u8; 8];
        wire.extend_from_slice(&[0x1F, 0x00, 0x1E]);
        assert_eq!(CardholderVerificationMethodList::parse(&wire), Err(Error::InvalidValue));
    }
}
