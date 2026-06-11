//! Book 3 §10.9 / §10.11 / Annex F - Online Processing.
//! EXTERNAL AUTHENTICATE primitives moved to [`crate::core::external_authenticate`]
//! (also used by K3 §6 Issuer Update Processing); aliased here for source
//! compatibility.

use crate::contact::transaction::TransactionContext;
use crate::core::apdu::Command;
use crate::core::error::Result;
use crate::core::external_authenticate as core_ea;
use crate::core::generate_ac::GenerateAcResponse;
use crate::core::terminal_action_analysis::ApplicationCryptogramType;
use crate::core::tlv::Tlv;
use crate::de::authorisation_response_code::AuthorisationResponseCode;

pub fn external_authenticate(issuer_authentication_data: &[u8]) -> Result<Command> {
    core_ea::command(issuer_authentication_data)
}

pub use core_ea::Outcome as ExternalAuthenticateOutcome;

pub fn interpret_external_authenticate_response(sw1: u8, sw2: u8) -> ExternalAuthenticateOutcome {
    core_ea::interpret_response(sw1, sw2)
}

// §10.11 - second GENERATE AC selection after online.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OnlineAuthorisationOutcome {
    Approved,
    Declined,
}

/// §10.11.
pub fn second_generate_ac_after_online(
    outcome: OnlineAuthorisationOutcome,
) -> ApplicationCryptogramType {
    match outcome {
        OnlineAuthorisationOutcome::Approved => ApplicationCryptogramType::Tc,
        OnlineAuthorisationOutcome::Declined => ApplicationCryptogramType::Aac,
    }
}

// §10.9 - issuer host abstraction.

pub trait OnlineAuthorisation {
    type Error;

    fn authorise(
        &mut self,
        ctx: &TransactionContext<'_>,
        first_ac: &GenerateAcResponse,
    ) -> std::result::Result<OnlineAuthorisationResponse, Self::Error>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OnlineAuthorisationResponse {
    pub authorisation_response_code: AuthorisationResponseCode,
    /// Tag '91', 8..=16 bytes.
    pub issuer_authentication_data: Option<Vec<u8>>,
    pub issuer_scripts: Vec<Tlv>,
}

#[cfg(test)]
mod tests {
    use super::*;

    // EXTERNAL AUTHENTICATE primitive tests live under
    // `core::external_authenticate::tests` since the move; this module only
    // covers contact-specific second-Gen-AC + OnlineAuthorisation pieces.

    #[test]
    fn second_generate_ac_approved_yields_tc() {
        assert_eq!(
            second_generate_ac_after_online(OnlineAuthorisationOutcome::Approved),
            ApplicationCryptogramType::Tc
        );
    }

    #[test]
    fn second_generate_ac_declined_yields_aac() {
        assert_eq!(
            second_generate_ac_after_online(OnlineAuthorisationOutcome::Declined),
            ApplicationCryptogramType::Aac
        );
    }

    use crate::contact::terminal::{Terminal, TerminalApplication};
    use crate::contact::transaction::{TransactionContext, TransactionInputs};
    use crate::core::generate_ac::{GenerateAcFormat, GenerateAcResponse};
    use crate::core::tag::Tag;
    use crate::core::tlv::{Tlv, Value};
    use crate::de::additional_terminal_capabilities::AdditionalTerminalCapabilities;
    use crate::de::cryptogram_information_data::CryptogramInformationData;
    use crate::de::terminal_capabilities::TerminalCapabilities;
    use crate::de::terminal_type::TerminalType;

    struct MockAuthHost {
        response: OnlineAuthorisationResponse,
    }

    impl OnlineAuthorisation for MockAuthHost {
        type Error = std::convert::Infallible;
        fn authorise(
            &mut self,
            _ctx: &TransactionContext<'_>,
            _first_ac: &GenerateAcResponse,
        ) -> std::result::Result<OnlineAuthorisationResponse, Self::Error> {
            Ok(self.response.clone())
        }
    }

    fn fixture_terminal() -> Terminal {
        Terminal {
            terminal_type: TerminalType(0x22),
            terminal_capabilities: TerminalCapabilities::default(),
            additional_terminal_capabilities: AdditionalTerminalCapabilities::default(),
            terminal_country_code: 840,
            terminal_identification: [0; 8],
            ifd_serial_number: [0; 8],
            merchant_category_code: 5999,
            merchant_identifier: [0; 15],
            merchant_name_and_location: vec![],
            acquirer_identifier: None,
            cardholder_selection_and_confirmation_supported: true,
            applications: vec![TerminalApplication {
                aid: vec![0xA0, 0, 0, 0, 0x03, 0x10, 0x10],
                partial_match_allowed: false,
                application_version_number: [0, 1],
                terminal_floor_limit: 0,
                terminal_risk_management_data: None,
                default_ddol: None,
                default_tdol: None,
                tac_denial: None,
                tac_online: None,
                tac_default: None,
                rts_target_percentage: None,
                rts_max_target_percentage: None,
                rts_threshold_value: None,
            }],
        }
    }

    fn fixture_first_ac() -> GenerateAcResponse {
        GenerateAcResponse {
            format: GenerateAcFormat::Format1,
            cid: CryptogramInformationData::parse(&[0x80]).unwrap(),
            atc: [0x00, 0x07],
            ac: Some([0xCA, 0xFE, 0xBA, 0xBE, 0xDE, 0xAD, 0xBE, 0xEF]),
            iad: None,
            sdad: None,
            proprietary: vec![],
            children_in_order: vec![],
        }
    }

    #[test]
    fn online_authorisation_trait_returns_canned_approved() {
        let canned = OnlineAuthorisationResponse {
            authorisation_response_code: AuthorisationResponseCode(*b"00"),
            issuer_authentication_data: Some(vec![0x11; 8]),
            issuer_scripts: vec![],
        };
        let mut host = MockAuthHost {
            response: canned.clone(),
        };
        let terminal = fixture_terminal();
        let ctx = TransactionContext::new(&terminal, TransactionInputs::default());
        let first_ac = fixture_first_ac();
        let resp = host.authorise(&ctx, &first_ac).unwrap();
        assert_eq!(resp, canned);
        assert_eq!(resp.authorisation_response_code.as_str().unwrap(), "00");
    }

    #[test]
    fn online_authorisation_response_carries_scripts() {
        let script_71 = Tlv::new(
            Tag(0x71),
            Value::Constructed(vec![Tlv::primitive(
                Tag(0x86),
                vec![0x80, 0x18, 0x00, 0x00, 0x05],
            )]),
        )
        .unwrap();
        let script_72 = Tlv::new(
            Tag(0x72),
            Value::Constructed(vec![Tlv::primitive(
                Tag(0x86),
                vec![0x84, 0xFA, 0x00, 0x00, 0x00],
            )]),
        )
        .unwrap();
        let mut host = MockAuthHost {
            response: OnlineAuthorisationResponse {
                authorisation_response_code: AuthorisationResponseCode(*b"00"),
                issuer_authentication_data: None,
                issuer_scripts: vec![script_71.clone(), script_72.clone()],
            },
        };
        let terminal = fixture_terminal();
        let ctx = TransactionContext::new(&terminal, TransactionInputs::default());
        let first_ac = fixture_first_ac();
        let resp = host.authorise(&ctx, &first_ac).unwrap();
        assert_eq!(resp.issuer_scripts.len(), 2);
        assert_eq!(resp.issuer_scripts[0].tag(), Tag(0x71));
        assert_eq!(resp.issuer_scripts[1].tag(), Tag(0x72));
    }

    #[test]
    fn online_authorisation_response_decline_no_aux_data() {
        let mut host = MockAuthHost {
            response: OnlineAuthorisationResponse {
                authorisation_response_code: AuthorisationResponseCode(*b"05"),
                issuer_authentication_data: None,
                issuer_scripts: vec![],
            },
        };
        let terminal = fixture_terminal();
        let ctx = TransactionContext::new(&terminal, TransactionInputs::default());
        let first_ac = fixture_first_ac();
        let resp = host.authorise(&ctx, &first_ac).unwrap();
        assert_eq!(resp.authorisation_response_code.as_str().unwrap(), "05");
        assert!(resp.issuer_authentication_data.is_none());
        assert!(resp.issuer_scripts.is_empty());
    }
}
