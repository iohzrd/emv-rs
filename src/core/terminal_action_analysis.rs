//! Book 3 §10.7 p.122 - Terminal Action Analysis.

use crate::de::terminal_verification_results::TerminalVerificationResults;

pub use crate::core::application_cryptogram_type::ApplicationCryptogramType;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TerminalCapability {
    OnlineCapable,
    OnlineOnly,
    /// §10.7 p.125 option 1 (`use_online_action_codes = true`) vs option 2.
    OfflineOnly {
        use_online_action_codes: bool,
    },
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ActionCodes {
    pub iac_denial: Option<[u8; 5]>,
    pub iac_online: Option<[u8; 5]>,
    pub iac_default: Option<[u8; 5]>,
    pub tac_denial: Option<[u8; 5]>,
    pub tac_online: Option<[u8; 5]>,
    pub tac_default: Option<[u8; 5]>,
}

impl ActionCodes {
    fn effective_iac_denial(&self) -> [u8; 5] {
        self.iac_denial.unwrap_or([0u8; 5])
    }
    fn effective_iac_online(&self) -> [u8; 5] {
        self.iac_online.unwrap_or([0xFFu8; 5])
    }
    fn effective_iac_default(&self) -> [u8; 5] {
        self.iac_default.unwrap_or([0xFFu8; 5])
    }
    fn effective_tac_denial(&self) -> [u8; 5] {
        self.tac_denial.unwrap_or([0u8; 5])
    }
    fn effective_tac_online(&self) -> [u8; 5] {
        self.tac_online.unwrap_or([0u8; 5])
    }
    fn effective_tac_default(&self) -> [u8; 5] {
        self.tac_default.unwrap_or([0u8; 5])
    }
}

fn any_bit_in_tvr_matched(tvr: &[u8; 5], iac: &[u8; 5], tac: &[u8; 5]) -> bool {
    (0..5).any(|i| tvr[i] & (iac[i] | tac[i]) != 0)
}

/// §10.7 first GENERATE AC: Denial → (Online | Default).
pub fn first_generate_ac_decision(
    tvr: &TerminalVerificationResults,
    action_codes: &ActionCodes,
    capability: TerminalCapability,
) -> ApplicationCryptogramType {
    let tvr_bytes = tvr.to_bytes();

    // §10.7 Denial.
    if any_bit_in_tvr_matched(
        &tvr_bytes,
        &action_codes.effective_iac_denial(),
        &action_codes.effective_tac_denial(),
    ) {
        return ApplicationCryptogramType::Aac;
    }

    match capability {
        TerminalCapability::OnlineCapable => {
            if any_bit_in_tvr_matched(
                &tvr_bytes,
                &action_codes.effective_iac_online(),
                &action_codes.effective_tac_online(),
            ) {
                ApplicationCryptogramType::Arqc
            } else {
                ApplicationCryptogramType::Tc
            }
        }
        TerminalCapability::OnlineOnly => ApplicationCryptogramType::Arqc,
        TerminalCapability::OfflineOnly {
            use_online_action_codes,
        } => {
            if use_online_action_codes
                && any_bit_in_tvr_matched(
                    &tvr_bytes,
                    &action_codes.effective_iac_online(),
                    &action_codes.effective_tac_online(),
                )
            {
                ApplicationCryptogramType::Arqc
            } else if any_bit_in_tvr_matched(
                &tvr_bytes,
                &action_codes.effective_iac_default(),
                &action_codes.effective_tac_default(),
            ) {
                ApplicationCryptogramType::Aac
            } else {
                ApplicationCryptogramType::Tc
            }
        }
    }
}

/// Book 4 §6.3.2.2.4 - TAA using only TAC-Denial / IAC-Denial after a first
/// GENERATE AC XDA failure; `true` ⇒ decline.
pub fn denial_decision(
    tvr: &TerminalVerificationResults,
    action_codes: &ActionCodes,
) -> bool {
    any_bit_in_tvr_matched(
        &tvr.to_bytes(),
        &action_codes.effective_iac_denial(),
        &action_codes.effective_tac_denial(),
    )
}

/// §10.7 "unable to process online" - re-runs Default.
pub fn unable_to_go_online_decision(
    tvr: &TerminalVerificationResults,
    action_codes: &ActionCodes,
) -> ApplicationCryptogramType {
    let tvr_bytes = tvr.to_bytes();
    if any_bit_in_tvr_matched(
        &tvr_bytes,
        &action_codes.effective_iac_default(),
        &action_codes.effective_tac_default(),
    ) {
        ApplicationCryptogramType::Aac
    } else {
        ApplicationCryptogramType::Tc
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tvr_with_sda_failed() -> TerminalVerificationResults {
        TerminalVerificationResults {
            sda_failed: true,
            ..Default::default()
        }
    }

    fn tvr_clean() -> TerminalVerificationResults {
        TerminalVerificationResults::default()
    }

    fn ac_byte_with_sda_failed() -> [u8; 5] {
        let mut bytes = [0u8; 5];
        bytes[0] = 0b0100_0000;
        bytes
    }

    #[test]
    fn denial_fires_via_iac_returns_aac() {
        let tvr = tvr_with_sda_failed();
        let action_codes = ActionCodes {
            iac_denial: Some(ac_byte_with_sda_failed()),
            ..Default::default()
        };
        assert_eq!(
            first_generate_ac_decision(&tvr, &action_codes, TerminalCapability::OnlineCapable),
            ApplicationCryptogramType::Aac
        );
    }

    #[test]
    fn denial_fires_via_tac_returns_aac() {
        let tvr = tvr_with_sda_failed();
        let action_codes = ActionCodes {
            tac_denial: Some(ac_byte_with_sda_failed()),
            ..Default::default()
        };
        assert_eq!(
            first_generate_ac_decision(&tvr, &action_codes, TerminalCapability::OnlineCapable),
            ApplicationCryptogramType::Aac
        );
    }

    #[test]
    fn denial_fires_for_online_only_too() {
        let tvr = tvr_with_sda_failed();
        let action_codes = ActionCodes {
            iac_denial: Some(ac_byte_with_sda_failed()),
            ..Default::default()
        };
        assert_eq!(
            first_generate_ac_decision(&tvr, &action_codes, TerminalCapability::OnlineOnly),
            ApplicationCryptogramType::Aac
        );
    }

    #[test]
    fn denial_fires_for_offline_only_too() {
        let tvr = tvr_with_sda_failed();
        let action_codes = ActionCodes {
            iac_denial: Some(ac_byte_with_sda_failed()),
            ..Default::default()
        };
        assert_eq!(
            first_generate_ac_decision(
                &tvr,
                &action_codes,
                TerminalCapability::OfflineOnly {
                    use_online_action_codes: true
                },
            ),
            ApplicationCryptogramType::Aac
        );
    }

    #[test]
    fn denial_decision_fires_on_tac_denial_match() {
        let tvr = TerminalVerificationResults {
            xda_signature_verification_failed: true,
            ..Default::default()
        };
        let mut tac = [0u8; 5];
        tac[3] = 0b0000_0001;
        let action_codes = ActionCodes {
            tac_denial: Some(tac),
            ..Default::default()
        };
        assert!(denial_decision(&tvr, &action_codes));
    }

    #[test]
    fn denial_decision_ignores_online_and_default_codes() {
        let tvr = TerminalVerificationResults {
            xda_signature_verification_failed: true,
            ..Default::default()
        };
        let mut online_and_default = [0u8; 5];
        online_and_default[3] = 0b0000_0001;
        let action_codes = ActionCodes {
            tac_online: Some(online_and_default),
            tac_default: Some(online_and_default),
            iac_online: Some(online_and_default),
            iac_default: Some(online_and_default),
            ..Default::default()
        };
        assert!(!denial_decision(&tvr, &action_codes));
    }

    #[test]
    fn iac_denial_default_is_all_zeros_so_clean_tvr_does_not_fire() {
        let tvr = tvr_with_sda_failed();
        let action_codes = ActionCodes::default();
        assert_ne!(
            first_generate_ac_decision(&tvr, &action_codes, TerminalCapability::OnlineCapable),
            ApplicationCryptogramType::Aac
        );
    }

    #[test]
    fn online_capable_with_no_tvr_bits_returns_tc() {
        let tvr = tvr_clean();
        let action_codes = ActionCodes::default();
        assert_eq!(
            first_generate_ac_decision(&tvr, &action_codes, TerminalCapability::OnlineCapable),
            ApplicationCryptogramType::Tc
        );
    }

    #[test]
    fn online_capable_with_tvr_bit_and_iac_online_default_returns_arqc() {
        let tvr = tvr_with_sda_failed();
        let action_codes = ActionCodes::default();
        assert_eq!(
            first_generate_ac_decision(&tvr, &action_codes, TerminalCapability::OnlineCapable),
            ApplicationCryptogramType::Arqc
        );
    }

    #[test]
    fn online_capable_with_explicit_iac_online_zero_does_not_fire() {
        let tvr = tvr_with_sda_failed();
        let action_codes = ActionCodes {
            iac_online: Some([0u8; 5]),
            ..Default::default()
        };
        assert_eq!(
            first_generate_ac_decision(&tvr, &action_codes, TerminalCapability::OnlineCapable),
            ApplicationCryptogramType::Tc
        );
    }

    #[test]
    fn online_capable_tac_online_alone_can_fire() {
        let tvr = tvr_with_sda_failed();
        let action_codes = ActionCodes {
            iac_online: Some([0u8; 5]),
            tac_online: Some(ac_byte_with_sda_failed()),
            ..Default::default()
        };
        assert_eq!(
            first_generate_ac_decision(&tvr, &action_codes, TerminalCapability::OnlineCapable),
            ApplicationCryptogramType::Arqc
        );
    }

    #[test]
    fn online_only_with_no_denial_always_arqc() {
        let tvr = tvr_clean();
        let action_codes = ActionCodes::default();
        assert_eq!(
            first_generate_ac_decision(&tvr, &action_codes, TerminalCapability::OnlineOnly),
            ApplicationCryptogramType::Arqc
        );
    }

    #[test]
    fn online_only_ignores_online_action_codes() {
        let tvr = tvr_with_sda_failed();
        let action_codes = ActionCodes {
            iac_online: Some([0u8; 5]),
            tac_online: Some([0u8; 5]),
            ..Default::default()
        };
        assert_eq!(
            first_generate_ac_decision(&tvr, &action_codes, TerminalCapability::OnlineOnly),
            ApplicationCryptogramType::Arqc
        );
    }

    #[test]
    fn offline_only_option_1_online_fires_yields_arqc() {
        let tvr = tvr_with_sda_failed();
        let action_codes = ActionCodes::default();
        assert_eq!(
            first_generate_ac_decision(
                &tvr,
                &action_codes,
                TerminalCapability::OfflineOnly {
                    use_online_action_codes: true
                },
            ),
            ApplicationCryptogramType::Arqc
        );
    }

    #[test]
    fn offline_only_option_1_online_quiet_default_fires_yields_aac() {
        let tvr = tvr_with_sda_failed();
        let action_codes = ActionCodes {
            iac_online: Some([0u8; 5]),
            tac_online: Some([0u8; 5]),
            iac_default: Some(ac_byte_with_sda_failed()),
            ..Default::default()
        };
        assert_eq!(
            first_generate_ac_decision(
                &tvr,
                &action_codes,
                TerminalCapability::OfflineOnly {
                    use_online_action_codes: true
                },
            ),
            ApplicationCryptogramType::Aac
        );
    }

    #[test]
    fn offline_only_option_1_online_quiet_default_quiet_yields_tc() {
        let tvr = tvr_with_sda_failed();
        let action_codes = ActionCodes {
            iac_online: Some([0u8; 5]),
            tac_online: Some([0u8; 5]),
            iac_default: Some([0u8; 5]),
            ..Default::default()
        };
        assert_eq!(
            first_generate_ac_decision(
                &tvr,
                &action_codes,
                TerminalCapability::OfflineOnly {
                    use_online_action_codes: true
                },
            ),
            ApplicationCryptogramType::Tc
        );
    }

    #[test]
    fn offline_only_option_2_skips_online_check() {
        let tvr = tvr_with_sda_failed();
        let action_codes = ActionCodes::default();
        assert_eq!(
            first_generate_ac_decision(
                &tvr,
                &action_codes,
                TerminalCapability::OfflineOnly {
                    use_online_action_codes: false
                },
            ),
            ApplicationCryptogramType::Aac
        );
    }

    #[test]
    fn offline_only_option_2_default_quiet_yields_tc() {
        let tvr = tvr_with_sda_failed();
        let action_codes = ActionCodes {
            iac_default: Some([0u8; 5]),
            ..Default::default()
        };
        assert_eq!(
            first_generate_ac_decision(
                &tvr,
                &action_codes,
                TerminalCapability::OfflineOnly {
                    use_online_action_codes: false
                },
            ),
            ApplicationCryptogramType::Tc
        );
    }

    #[test]
    fn unable_to_go_online_default_fires_aac() {
        let tvr = tvr_with_sda_failed();
        let action_codes = ActionCodes::default();
        assert_eq!(
            unable_to_go_online_decision(&tvr, &action_codes),
            ApplicationCryptogramType::Aac
        );
    }

    #[test]
    fn unable_to_go_online_default_quiet_tc() {
        let tvr = tvr_with_sda_failed();
        let action_codes = ActionCodes {
            iac_default: Some([0u8; 5]),
            ..Default::default()
        };
        assert_eq!(
            unable_to_go_online_decision(&tvr, &action_codes),
            ApplicationCryptogramType::Tc
        );
    }

    #[test]
    fn unable_to_go_online_clean_tvr_tc() {
        let tvr = tvr_clean();
        let action_codes = ActionCodes::default();
        assert_eq!(
            unable_to_go_online_decision(&tvr, &action_codes),
            ApplicationCryptogramType::Tc
        );
    }

    #[test]
    fn each_tvr_byte_position_aligns_with_action_codes() {
        for (byte_idx, tvr) in [
            (
                0,
                TerminalVerificationResults {
                    offline_data_authentication_was_not_performed: true,
                    ..Default::default()
                },
            ),
            (
                1,
                TerminalVerificationResults {
                    icc_and_terminal_have_different_application_versions: true,
                    ..Default::default()
                },
            ),
            (
                2,
                TerminalVerificationResults {
                    cardholder_verification_was_not_successful: true,
                    ..Default::default()
                },
            ),
            (
                3,
                TerminalVerificationResults {
                    transaction_exceeds_floor_limit: true,
                    ..Default::default()
                },
            ),
            (
                4,
                TerminalVerificationResults {
                    default_tdol_used: true,
                    ..Default::default()
                },
            ),
        ] {
            let mut iac = [0u8; 5];
            iac[byte_idx] = 0b1000_0000;
            let action_codes = ActionCodes {
                iac_denial: Some(iac),
                ..Default::default()
            };
            assert_eq!(
                first_generate_ac_decision(&tvr, &action_codes, TerminalCapability::OnlineCapable,),
                ApplicationCryptogramType::Aac,
                "TVR byte {} b8 should align with IAC-Denial byte {} b8",
                byte_idx + 1,
                byte_idx + 1,
            );

            let mut iac_offset = [0u8; 5];
            iac_offset[(byte_idx + 1) % 5] = 0b1000_0000;
            let action_codes_offset = ActionCodes {
                iac_denial: Some(iac_offset),
                ..Default::default()
            };
            assert_ne!(
                first_generate_ac_decision(
                    &tvr,
                    &action_codes_offset,
                    TerminalCapability::OnlineCapable,
                ),
                ApplicationCryptogramType::Aac,
            );
        }
    }
}
