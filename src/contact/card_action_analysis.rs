//! Book 3 §10.8 p.127 - Card Action Analysis.

use crate::de::cryptogram_information_data::{
    ApplicationCryptogramType, CryptogramInformationData, ReasonAdviceCode,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CardAction {
    Approve,
    Decline,
    ServiceNotAllowed,
    GoOnline,
    InvalidCryptogramType,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CardActionAnalysis {
    pub action: CardAction,
    pub advice_required: bool,
}

pub fn interpret_card_response(cid: &CryptogramInformationData) -> CardActionAnalysis {
    let action = match cid.cryptogram_type {
        ApplicationCryptogramType::Tc => CardAction::Approve,
        ApplicationCryptogramType::Aac => {
            if matches!(cid.reason_advice_code, ReasonAdviceCode::ServiceNotAllowed) {
                CardAction::ServiceNotAllowed
            } else {
                CardAction::Decline
            }
        }
        ApplicationCryptogramType::Arqc => CardAction::GoOnline,
        ApplicationCryptogramType::Rfu(_) => CardAction::InvalidCryptogramType,
    };
    CardActionAnalysis {
        action,
        advice_required: cid.advice_required,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cid_byte(b: u8) -> CryptogramInformationData {
        CryptogramInformationData::parse(&[b]).unwrap()
    }

    #[test]
    fn interpret_tc_yields_approve() {
        let r = interpret_card_response(&cid_byte(0x40));
        assert_eq!(r.action, CardAction::Approve);
        assert!(!r.advice_required);
    }

    #[test]
    fn interpret_aac_yields_decline() {
        let r = interpret_card_response(&cid_byte(0x00));
        assert_eq!(r.action, CardAction::Decline);
    }

    #[test]
    fn interpret_aac_with_service_not_allowed_yields_terminate() {
        let r = interpret_card_response(&cid_byte(0x01));
        assert_eq!(r.action, CardAction::ServiceNotAllowed);
    }

    #[test]
    fn interpret_aac_with_pin_try_limit_exceeded_is_decline_not_special() {
        // §10.8.1 - only ServiceNotAllowed is special-cased.
        let r = interpret_card_response(&cid_byte(0x02));
        assert_eq!(r.action, CardAction::Decline);
    }

    #[test]
    fn interpret_arqc_yields_go_online() {
        let r = interpret_card_response(&cid_byte(0x80));
        assert_eq!(r.action, CardAction::GoOnline);
    }

    #[test]
    fn interpret_rfu_cryptogram_type_is_invalid() {
        let r = interpret_card_response(&cid_byte(0xC0));
        assert_eq!(r.action, CardAction::InvalidCryptogramType);
    }

    #[test]
    fn interpret_propagates_advice_required() {
        // 0x48 = TC + advice-required.
        let r = interpret_card_response(&cid_byte(0x48));
        assert_eq!(r.action, CardAction::Approve);
        assert!(r.advice_required);
    }
}
