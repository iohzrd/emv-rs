//! Book 3 §10 - Transaction-time context.

use crate::contact::card_action_analysis::{self, CardActionAnalysis};
use crate::contact::cardholder_verification::{
    self, CvmContext, CvmExecutionResult, CvmProcessingOutcome, CvmTerminalSupport,
};
use crate::contact::processing_restrictions::{
    self, CountryCode, EmvDate, ProcessingRestrictionsContext, ProcessingRestrictionsOutcome,
    TransactionCategory,
};
use crate::contact::terminal::{Terminal, TerminalApplication};
use crate::core::error::{Error, Result};
use crate::core::generate_ac::GenerateAcResponse;
use crate::core::oda::{CdaArming, XdaArming};
use crate::core::tag_store::TagStore;
use crate::core::tags;
use crate::core::terminal_action_analysis::{
    self, ActionCodes, ApplicationCryptogramType, TerminalCapability,
};
use crate::de::application_file_locator::ApplicationFileLocator;
use crate::de::application_interchange_profile::ApplicationInterchangeProfile;
use crate::de::application_usage_control::ApplicationUsageControl;
use crate::de::cardholder_verification_method_list::{
    CardholderVerificationMethodList, CardholderVerificationMethodRule,
};
use crate::de::issuer_script_results::IssuerScriptResult;
use crate::de::terminal_capabilities::TerminalCapabilities;
use crate::de::terminal_type::AttendanceCapability;
use crate::de::terminal_verification_results::TerminalVerificationResults;
use crate::de::transaction_status_information::TransactionStatusInformation;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct TransactionInputs {
    /// '9F02' / '81' - transaction currency minor units.
    pub amount_authorised: u64,
    /// '9F03' / '9F04'.
    pub amount_other: u64,
    /// '5F2A' - ISO 4217 numeric, BCD.
    pub transaction_currency_code: u16,
    /// '5F36'.
    pub transaction_currency_exponent: u8,
    /// '9A' - YYMMDD BCD.
    pub transaction_date: [u8; 3],
    /// '9F21' - HHMMSS BCD.
    pub transaction_time: [u8; 3],
    /// '9C' - n2.
    pub transaction_type: u8,
    /// '9F41'.
    pub transaction_sequence_counter: u32,
    /// '9F37'.
    pub unpredictable_number: [u8; 4],
}

#[derive(Debug, Clone)]
pub struct SelectedApplication<'t> {
    /// '84' from selected ADF FCI.
    pub df_name: Vec<u8>,
    pub config: &'t TerminalApplication,
}

#[derive(Debug)]
pub struct TransactionContext<'t> {
    pub terminal: &'t Terminal,
    pub selected: Option<SelectedApplication<'t>>,
    pub inputs: TransactionInputs,
    pub tag_store: TagStore,
    /// '82'.
    pub aip: Option<ApplicationInterchangeProfile>,
    /// '94'.
    pub afl: Option<ApplicationFileLocator>,
    /// '95'.
    pub tvr: TerminalVerificationResults,
    /// '9B'.
    pub tsi: TransactionStatusInformation,
    /// PDOL-resolved bytes sent in GPO; empty for `83 00`.
    pub gpo_pdol_data: Vec<u8>,
    pub cda: Option<CdaArming>,
    pub xda: Option<XdaArming>,
    /// '9F5B' - Book 4 §6.3.9 / Annex A5.
    pub issuer_script_results: Vec<IssuerScriptResult>,
    /// '98' - Book 3 §9.2.2; lazy SHA-1 over TDOL resolution.
    pub tc_hash_value: Option<[u8; 20]>,
}

impl<'t> TransactionContext<'t> {
    pub fn new(terminal: &'t Terminal, inputs: TransactionInputs) -> Self {
        Self {
            terminal,
            selected: None,
            inputs,
            tag_store: TagStore::new(),
            aip: None,
            afl: None,
            tvr: TerminalVerificationResults::default(),
            tsi: TransactionStatusInformation::default(),
            gpo_pdol_data: Vec::new(),
            cda: None,
            xda: None,
            issuer_script_results: Vec::new(),
            tc_hash_value: None,
        }
    }

    pub fn select_application(&mut self, df_name: Vec<u8>) -> Option<&TerminalApplication> {
        let terminal: &'t Terminal = self.terminal;
        let config = terminal.find_application(&df_name)?;
        self.selected = Some(SelectedApplication { df_name, config });
        Some(config)
    }

    /// §10.4 - `5F24` mandatory.
    pub fn process_restrictions(
        &mut self,
        transaction_category: TransactionCategory,
        transaction_has_cashback: bool,
    ) -> Result<ProcessingRestrictionsOutcome> {
        let selected = self.selected.as_ref().ok_or(Error::MissingMandatory {
            tag: tags::APPLICATION_DEDICATED_FILE_NAME,
        })?;
        let terminal_avn = &selected.config.application_version_number;
        let icc_avn_bytes = self.tag_store.get(tags::APPLICATION_VERSION_NUMBER_ICC);
        let icc_avn: Option<[u8; 2]> = icc_avn_bytes
            .map(|b| -> Result<[u8; 2]> {
                <[u8; 2]>::try_from(b).map_err(|_| Error::WrongLength {
                    expected: 2,
                    got: b.len(),
                })
            })
            .transpose()?;

        let auc_parsed = self
            .tag_store
            .get(tags::APPLICATION_USAGE_CONTROL)
            .map(ApplicationUsageControl::parse)
            .transpose()?;

        let icc_issuer_cc: Option<CountryCode> = self
            .tag_store
            .get(tags::ISSUER_COUNTRY_CODE)
            .map(|b| -> Result<CountryCode> {
                <[u8; 2]>::try_from(b).map_err(|_| Error::WrongLength {
                    expected: 2,
                    got: b.len(),
                })
            })
            .transpose()?;

        let terminal_cc: CountryCode = bcd_country_code(self.terminal.terminal_country_code);

        let terminal_is_atm = self
            .terminal
            .terminal_type
            .is_unattended_financial_institution()
            && self.terminal.additional_terminal_capabilities.cash;

        let effective: Option<EmvDate> = self
            .tag_store
            .get(tags::APPLICATION_EFFECTIVE_DATE)
            .map(|b| -> Result<EmvDate> {
                <[u8; 3]>::try_from(b).map_err(|_| Error::WrongLength {
                    expected: 3,
                    got: b.len(),
                })
            })
            .transpose()?;

        let expiration_bytes = self
            .tag_store
            .get(tags::APPLICATION_EXPIRATION_DATE)
            .ok_or(Error::MissingMandatory {
                tag: tags::APPLICATION_EXPIRATION_DATE,
            })?;
        let expiration: EmvDate =
            <[u8; 3]>::try_from(expiration_bytes).map_err(|_| Error::WrongLength {
                expected: 3,
                got: expiration_bytes.len(),
            })?;

        let ctx = ProcessingRestrictionsContext {
            icc_application_version_number: icc_avn.as_ref(),
            terminal_application_version_number: terminal_avn,
            application_usage_control: auc_parsed.as_ref(),
            icc_issuer_country_code: icc_issuer_cc.as_ref(),
            terminal_country_code: &terminal_cc,
            terminal_is_atm,
            transaction_category,
            transaction_has_cashback,
            application_effective_date: effective.as_ref(),
            application_expiration_date: &expiration,
            transaction_date: &self.inputs.transaction_date,
        };
        let outcome = processing_restrictions::evaluate(&ctx);

        // §10.4 → TVR Byte 2.
        let tvr = &mut self.tvr;
        tvr.icc_and_terminal_have_different_application_versions |=
            outcome.icc_and_terminal_have_different_application_versions;
        tvr.requested_service_not_allowed_for_card_product |=
            outcome.requested_service_not_allowed_for_card_product;
        tvr.application_not_yet_effective |= outcome.application_not_yet_effective;
        tvr.expired_application |= outcome.expired_application;

        Ok(outcome)
    }
}

impl<'t> TransactionContext<'t> {
    /// Book 3 §10.7 Terminal Action Analysis - first GENERATE AC decision.
    ///
    /// Reads the three Issuer Action Codes (`9F0E` Denial / `9F0F` Online /
    /// `9F0D` Default) from `tag_store` (placed there by Read Application
    /// Data), pulls the matching Terminal Action Codes from the selected
    /// `TerminalApplication`, derives the [`TerminalCapability`] axis from
    /// `terminal.terminal_type` (online-only / online-capable /
    /// offline-only per Book 4 Annex A1 Table 24), and runs the spec's
    /// Denial → (Online | Default) ladder via
    /// [`terminal_action_analysis::first_generate_ac_decision`].
    ///
    /// `offline_consult_online_acs` is the spec's offline-only "option 1"
    /// switch (§10.7 p. 125): when `true` and the terminal is offline-only,
    /// the kernel still consults IAC-Online / TAC-Online (so a card capable
    /// of mediating an "online" exchange internally can do so); when `false`
    /// the Online step is skipped entirely. Has no effect on online-capable
    /// or online-only terminals.
    ///
    /// Errors with [`Error::WrongLength`] if any IAC in the tag store is not
    /// the 5-byte length the spec mandates.
    pub fn terminal_action_analysis(
        &self,
        offline_consult_online_acs: bool,
    ) -> Result<ApplicationCryptogramType> {
        let action_codes = self.action_codes()?;

        let capability = match self.terminal.terminal_type.attendance_capability() {
            AttendanceCapability::OnlineOnly => TerminalCapability::OnlineOnly,
            AttendanceCapability::OfflineWithOnlineCapability => TerminalCapability::OnlineCapable,
            AttendanceCapability::OfflineOnly => TerminalCapability::OfflineOnly {
                use_online_action_codes: offline_consult_online_acs,
            },
            AttendanceCapability::Rfu(_) => TerminalCapability::OnlineCapable,
        };

        Ok(terminal_action_analysis::first_generate_ac_decision(
            &self.tvr,
            &action_codes,
            capability,
        ))
    }

    /// Book 4 §6.3.2.2.4 - TAA using TAC-Denial / IAC-Denial after a first
    /// GENERATE AC XDA failure; `true` ⇒ decline.
    pub fn xda_failure_denial_decision(&self) -> Result<bool> {
        Ok(terminal_action_analysis::denial_decision(
            &self.tvr,
            &self.action_codes()?,
        ))
    }

    /// §10.7 - default-action decision when the terminal was unable to
    /// process the transaction online.
    pub fn unable_to_go_online_decision(&self) -> Result<ApplicationCryptogramType> {
        Ok(terminal_action_analysis::unable_to_go_online_decision(
            &self.tvr,
            &self.action_codes()?,
        ))
    }

    fn action_codes(&self) -> Result<ActionCodes> {
        let selected = self.selected.as_ref().ok_or(Error::MissingMandatory {
            tag: tags::APPLICATION_DEDICATED_FILE_NAME,
        })?;
        let cfg = selected.config;
        Ok(ActionCodes {
            iac_denial: read_optional_action_code(&self.tag_store, tags::IAC_DENIAL)?,
            iac_online: read_optional_action_code(&self.tag_store, tags::IAC_ONLINE)?,
            iac_default: read_optional_action_code(&self.tag_store, tags::IAC_DEFAULT)?,
            tac_denial: cfg.tac_denial,
            tac_online: cfg.tac_online,
            tac_default: cfg.tac_default,
        })
    }
}

impl<'t> TransactionContext<'t> {
    /// §10.8.
    pub fn card_action_analysis(&mut self, first_ac: &GenerateAcResponse) -> CardActionAnalysis {
        let analysis = card_action_analysis::interpret_card_response(&first_ac.cid);
        self.tsi.card_risk_management_was_performed = true;
        analysis
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct CvmFlags {
    pub transaction_in_application_currency: bool,
    pub transaction_is_unattended_cash: bool,
    pub transaction_is_manual_cash: bool,
    pub transaction_is_purchase_with_cashback: bool,
}

impl<'t> TransactionContext<'t> {
    /// §10.5.
    pub fn cardholder_verification<F>(
        &mut self,
        flags: CvmFlags,
        perform: F,
    ) -> Result<CvmProcessingOutcome>
    where
        F: FnMut(&CardholderVerificationMethodRule) -> CvmExecutionResult,
    {
        let support = derive_cvm_support(&self.terminal.terminal_capabilities);
        let cvm_ctx = CvmContext {
            support,
            transaction_in_application_currency: flags.transaction_in_application_currency,
            amount_authorised: u32::try_from(self.inputs.amount_authorised).unwrap_or(u32::MAX),
            transaction_is_unattended_cash: flags.transaction_is_unattended_cash,
            transaction_is_manual_cash: flags.transaction_is_manual_cash,
            transaction_is_purchase_with_cashback: flags.transaction_is_purchase_with_cashback,
        };

        let parsed_list = self
            .tag_store
            .get(tags::CVM_LIST)
            .map(CardholderVerificationMethodList::parse)
            .transpose()?;

        let outcome =
            cardholder_verification::process_cvm_list(parsed_list.as_ref(), &cvm_ctx, perform);

        // Book 4 §6.3.4.5 - store '9F34'.
        self.tag_store.insert_primitive(
            tags::CVM_RESULTS,
            outcome.cvm_results.to_vec(),
            crate::core::tag_store::Source::TerminalGenerated,
        )?;

        let tvr = &mut self.tvr;
        let upd = outcome.tvr_updates;
        tvr.cardholder_verification_was_not_successful |=
            upd.cardholder_verification_was_not_successful;
        tvr.unrecognised_cvm |= upd.unrecognised_cvm;
        tvr.pin_try_limit_exceeded |= upd.pin_try_limit_exceeded;
        tvr.pin_entry_required_and_pin_pad_not_present_or_not_working |=
            upd.pin_entry_required_and_pin_pad_not_present_or_not_working;
        tvr.pin_entry_required_pin_pad_present_but_pin_was_not_entered |=
            upd.pin_entry_required_pin_pad_present_but_pin_was_not_entered;
        tvr.online_cvm_captured |= upd.online_cvm_captured;
        tvr.a_selected_biometric_type_not_supported |= upd.a_selected_biometric_type_not_supported;

        if outcome.tsi_cardholder_verification_was_performed {
            self.tsi.cardholder_verification_was_performed = true;
        }

        Ok(outcome)
    }
}

fn derive_cvm_support(caps: &TerminalCapabilities) -> CvmTerminalSupport {
    let plaintext = caps.plaintext_pin_for_icc_verification;
    let enciphered_offline = caps.enciphered_pin_for_offline_verification_rsa_ode
        || caps.enciphered_pin_for_offline_verification_ecc_ode;
    let signature = caps.signature;
    CvmTerminalSupport {
        plaintext_offline_pin_by_icc: plaintext,
        enciphered_pin_verified_online: caps.enciphered_pin_for_online_verification,
        plaintext_offline_pin_by_icc_and_signature: plaintext && signature,
        enciphered_offline_pin_by_icc: enciphered_offline,
        enciphered_offline_pin_by_icc_and_signature: enciphered_offline && signature,
        signature,
        no_cvm_required: caps.no_cvm_required,
        ..Default::default()
    }
}

fn read_optional_action_code(
    store: &TagStore,
    tag: crate::core::tag::Tag,
) -> Result<Option<[u8; 5]>> {
    store
        .get(tag)
        .map(|b| -> Result<[u8; 5]> {
            <[u8; 5]>::try_from(b).map_err(|_| Error::WrongLength {
                expected: 5,
                got: b.len(),
            })
        })
        .transpose()
}

/// Decimal → 2-byte BCD ('9F1A' / '5F28').
fn bcd_country_code(decimal: u16) -> CountryCode {
    let d = decimal % 10000;
    let thousands = (d / 1000) as u8;
    let hundreds = ((d / 100) % 10) as u8;
    let tens = ((d / 10) % 10) as u8;
    let ones = (d % 10) as u8;
    [(thousands << 4) | hundreds, (tens << 4) | ones]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::de::additional_terminal_capabilities::AdditionalTerminalCapabilities;
    use crate::de::terminal_capabilities::TerminalCapabilities;
    use crate::de::terminal_type::TerminalType;

    fn sample_terminal() -> Terminal {
        Terminal {
            terminal_type: TerminalType(0x22),
            terminal_capabilities: TerminalCapabilities {
                ic_with_contacts: true,
                ..Default::default()
            },
            additional_terminal_capabilities: AdditionalTerminalCapabilities::default(),
            terminal_country_code: 0x0840,
            terminal_identification: [b'T'; 8],
            ifd_serial_number: [b'S'; 8],
            merchant_category_code: 0x5999,
            merchant_identifier: [b'M'; 15],
            merchant_name_and_location: b"Merchant".to_vec(),
            acquirer_identifier: None,
            cardholder_selection_and_confirmation_supported: true,
            applications: vec![TerminalApplication {
                aid: vec![0xA0, 0, 0, 0, 0x03, 0x10, 0x10],
                partial_match_allowed: false,
                application_version_number: [0, 1],
                terminal_floor_limit: 10_000,
                terminal_risk_management_data: None,
                default_ddol: None,
                default_tdol: None,
                tac_denial: Some([0; 5]),
                tac_online: Some([0xFF; 5]),
                tac_default: Some([0; 5]),
                rts_target_percentage: None,
                rts_max_target_percentage: None,
                rts_threshold_value: None,
            }],
        }
    }

    #[test]
    fn new_initialises_tvr_and_tsi_to_zero() {
        let terminal = sample_terminal();
        let ctx = TransactionContext::new(&terminal, TransactionInputs::default());
        assert_eq!(ctx.tvr.to_bytes(), [0, 0, 0, 0, 0]);
        assert_eq!(ctx.tsi.to_bytes(), [0, 0]);
        assert!(ctx.selected.is_none());
        assert!(ctx.aip.is_none());
        assert!(ctx.afl.is_none());
        assert!(ctx.tag_store.is_empty());
    }

    #[test]
    fn select_application_records_match() {
        let terminal = sample_terminal();
        let mut ctx = TransactionContext::new(&terminal, TransactionInputs::default());
        let m = ctx
            .select_application(vec![0xA0, 0, 0, 0, 0x03, 0x10, 0x10])
            .unwrap();
        assert_eq!(m.terminal_floor_limit, 10_000);
        let sel = ctx.selected.as_ref().unwrap();
        assert_eq!(sel.df_name, vec![0xA0, 0, 0, 0, 0x03, 0x10, 0x10]);
        assert_eq!(sel.config.terminal_floor_limit, 10_000);
    }

    #[test]
    fn select_application_returns_none_for_unknown_aid() {
        let terminal = sample_terminal();
        let mut ctx = TransactionContext::new(&terminal, TransactionInputs::default());
        let r = ctx.select_application(vec![0xA0, 0, 0, 0, 0x99, 0x99, 0x99]);
        assert!(r.is_none());
        assert!(ctx.selected.is_none());
    }

    #[test]
    fn fields_are_independently_mutable() {
        let terminal = sample_terminal();
        let mut ctx = TransactionContext::new(&terminal, TransactionInputs::default());
        ctx.tvr.transaction_exceeds_floor_limit = true;
        ctx.tsi.terminal_risk_management_was_performed = true;
        ctx.aip = Some(ApplicationInterchangeProfile {
            cda_supported: true,
            ..Default::default()
        });
        assert!(ctx.tvr.transaction_exceeds_floor_limit);
        assert!(ctx.tsi.terminal_risk_management_was_performed);
        assert!(ctx.aip.unwrap().cda_supported);
    }

    fn terminal_us_purchase() -> Terminal {
        let mut t = sample_terminal();
        t.terminal_country_code = 840;
        t
    }

    fn populate_pr_minimal(ctx: &mut TransactionContext<'_>) {
        ctx.tag_store
            .insert_primitive(
                tags::APPLICATION_EXPIRATION_DATE,
                vec![0x29, 0x12, 0x31],
                crate::core::tag_store::Source::Record { sfi: 1, record: 1 },
            )
            .unwrap();
    }

    #[test]
    fn process_restrictions_clean_path_sets_no_tvr_bits() {
        let terminal = terminal_us_purchase();
        let mut ctx = TransactionContext::new(
            &terminal,
            TransactionInputs {
                transaction_date: [0x26, 0x06, 0x15],
                ..Default::default()
            },
        );
        ctx.select_application(vec![0xA0, 0, 0, 0, 0x03, 0x10, 0x10])
            .unwrap();
        let src = crate::core::tag_store::Source::Record { sfi: 1, record: 1 };
        ctx.tag_store
            .insert_primitive(tags::APPLICATION_VERSION_NUMBER_ICC, vec![0, 1], src)
            .unwrap();
        ctx.tag_store
            .insert_primitive(
                tags::APPLICATION_EFFECTIVE_DATE,
                vec![0x25, 0x01, 0x01],
                src,
            )
            .unwrap();
        populate_pr_minimal(&mut ctx);

        let outcome = ctx
            .process_restrictions(TransactionCategory::Purchase, false)
            .unwrap();
        assert_eq!(outcome, ProcessingRestrictionsOutcome::default());
        assert_eq!(ctx.tvr.to_bytes(), [0, 0, 0, 0, 0]);
    }

    #[test]
    fn process_restrictions_avn_mismatch_sets_tvr_bit() {
        let terminal = terminal_us_purchase();
        let mut ctx = TransactionContext::new(
            &terminal,
            TransactionInputs {
                transaction_date: [0x26, 0x06, 0x15],
                ..Default::default()
            },
        );
        ctx.select_application(vec![0xA0, 0, 0, 0, 0x03, 0x10, 0x10])
            .unwrap();
        let src = crate::core::tag_store::Source::Record { sfi: 1, record: 1 };
        ctx.tag_store
            .insert_primitive(tags::APPLICATION_VERSION_NUMBER_ICC, vec![0, 2], src)
            .unwrap();
        populate_pr_minimal(&mut ctx);

        let outcome = ctx
            .process_restrictions(TransactionCategory::Purchase, false)
            .unwrap();
        assert!(outcome.icc_and_terminal_have_different_application_versions);
        assert!(ctx.tvr.icc_and_terminal_have_different_application_versions);
    }

    #[test]
    fn process_restrictions_expired_application_sets_tvr_bit() {
        let terminal = terminal_us_purchase();
        let mut ctx = TransactionContext::new(
            &terminal,
            TransactionInputs {
                transaction_date: [0x27, 0x01, 0x01],
                ..Default::default()
            },
        );
        ctx.select_application(vec![0xA0, 0, 0, 0, 0x03, 0x10, 0x10])
            .unwrap();
        let src = crate::core::tag_store::Source::Record { sfi: 1, record: 1 };
        ctx.tag_store
            .insert_primitive(
                tags::APPLICATION_EXPIRATION_DATE,
                vec![0x26, 0x12, 0x31],
                src,
            )
            .unwrap();

        let outcome = ctx
            .process_restrictions(TransactionCategory::Purchase, false)
            .unwrap();
        assert!(outcome.expired_application);
        assert!(ctx.tvr.expired_application);
    }

    #[test]
    fn process_restrictions_missing_expiration_date_errors() {
        let terminal = terminal_us_purchase();
        let mut ctx = TransactionContext::new(
            &terminal,
            TransactionInputs {
                transaction_date: [0x26, 0x06, 0x15],
                ..Default::default()
            },
        );
        ctx.select_application(vec![0xA0, 0, 0, 0, 0x03, 0x10, 0x10])
            .unwrap();

        match ctx.process_restrictions(TransactionCategory::Purchase, false) {
            Err(Error::MissingMandatory { tag }) => {
                assert_eq!(tag, tags::APPLICATION_EXPIRATION_DATE);
            }
            other => panic!("expected MissingMandatory(5F24), got {:?}", other),
        }
    }

    #[test]
    fn process_restrictions_auc_domestic_failure_sets_tvr_bit() {
        let terminal = terminal_us_purchase();
        let mut ctx = TransactionContext::new(
            &terminal,
            TransactionInputs {
                transaction_date: [0x26, 0x06, 0x15],
                ..Default::default()
            },
        );
        ctx.select_application(vec![0xA0, 0, 0, 0, 0x03, 0x10, 0x10])
            .unwrap();
        let src = crate::core::tag_store::Source::Record { sfi: 1, record: 1 };
        ctx.tag_store
            .insert_primitive(tags::ISSUER_COUNTRY_CODE, vec![0x08, 0x40], src)
            .unwrap();
        ctx.tag_store
            .insert_primitive(tags::APPLICATION_USAGE_CONTROL, vec![0x40, 0x00], src)
            .unwrap();
        populate_pr_minimal(&mut ctx);

        let outcome = ctx
            .process_restrictions(TransactionCategory::Purchase, false)
            .unwrap();
        assert!(outcome.requested_service_not_allowed_for_card_product);
        assert!(ctx.tvr.requested_service_not_allowed_for_card_product);
    }

    #[test]
    fn process_restrictions_combines_multiple_failures() {
        let terminal = terminal_us_purchase();
        let mut ctx = TransactionContext::new(
            &terminal,
            TransactionInputs {
                transaction_date: [0x26, 0x06, 0x15],
                ..Default::default()
            },
        );
        ctx.select_application(vec![0xA0, 0, 0, 0, 0x03, 0x10, 0x10])
            .unwrap();
        let src = crate::core::tag_store::Source::Record { sfi: 1, record: 1 };
        ctx.tag_store
            .insert_primitive(tags::APPLICATION_VERSION_NUMBER_ICC, vec![0xFF, 0xFF], src)
            .unwrap();
        ctx.tag_store
            .insert_primitive(
                tags::APPLICATION_EFFECTIVE_DATE,
                vec![0x27, 0x01, 0x01],
                src,
            )
            .unwrap();
        populate_pr_minimal(&mut ctx);

        let outcome = ctx
            .process_restrictions(TransactionCategory::Purchase, false)
            .unwrap();
        assert!(outcome.icc_and_terminal_have_different_application_versions);
        assert!(outcome.application_not_yet_effective);
        assert!(ctx.tvr.icc_and_terminal_have_different_application_versions);
        assert!(ctx.tvr.application_not_yet_effective);
    }

    #[test]
    fn process_restrictions_does_not_clear_existing_tvr_bits() {
        let terminal = terminal_us_purchase();
        let mut ctx = TransactionContext::new(
            &terminal,
            TransactionInputs {
                transaction_date: [0x26, 0x06, 0x15],
                ..Default::default()
            },
        );
        ctx.select_application(vec![0xA0, 0, 0, 0, 0x03, 0x10, 0x10])
            .unwrap();
        populate_pr_minimal(&mut ctx);

        ctx.tvr.transaction_exceeds_floor_limit = true;
        ctx.process_restrictions(TransactionCategory::Purchase, false)
            .unwrap();
        assert!(ctx.tvr.transaction_exceeds_floor_limit);
    }

    #[test]
    fn bcd_country_code_packs_decimal_correctly() {
        assert_eq!(bcd_country_code(840), [0x08, 0x40]);
        assert_eq!(bcd_country_code(36), [0x00, 0x36]);
        assert_eq!(bcd_country_code(0), [0x00, 0x00]);
        assert_eq!(bcd_country_code(9999), [0x99, 0x99]);
    }

    // ─── §10.7 Terminal Action Analysis wiring ───────────────────────────

    fn terminal_with_attendance(byte: u8) -> Terminal {
        let mut t = sample_terminal();
        t.terminal_type = TerminalType(byte);
        t
    }

    fn ctx_with_selection<'a>(terminal: &'a Terminal) -> TransactionContext<'a> {
        let mut ctx = TransactionContext::new(terminal, TransactionInputs::default());
        ctx.select_application(vec![0xA0, 0, 0, 0, 0x03, 0x10, 0x10])
            .unwrap();
        ctx
    }

    #[test]
    fn taa_clean_tvr_yields_tc_on_online_capable_terminal() {
        let terminal = terminal_with_attendance(0x22);
        let ctx = ctx_with_selection(&terminal);
        assert_eq!(
            ctx.terminal_action_analysis(false).unwrap(),
            ApplicationCryptogramType::Tc
        );
    }

    #[test]
    fn taa_online_only_terminal_always_arqcs() {
        let terminal = terminal_with_attendance(0x21);
        let ctx = ctx_with_selection(&terminal);
        assert_eq!(
            ctx.terminal_action_analysis(false).unwrap(),
            ApplicationCryptogramType::Arqc
        );
    }

    #[test]
    fn taa_denial_step_via_tac_overrides_capability() {
        let mut terminal = terminal_with_attendance(0x21);
        terminal.applications[0].tac_denial = Some([0xFF; 5]);
        let mut ctx = ctx_with_selection(&terminal);
        ctx.tvr.expired_application = true;
        assert_eq!(
            ctx.terminal_action_analysis(false).unwrap(),
            ApplicationCryptogramType::Aac
        );
    }

    #[test]
    fn taa_online_capable_arqcs_when_iac_online_matches_tvr() {
        let terminal = terminal_with_attendance(0x22);
        let mut ctx = ctx_with_selection(&terminal);
        // IAC-Online TVR Byte 4 b8 ('Transaction exceeds floor limit').
        let src = crate::core::tag_store::Source::Record { sfi: 1, record: 1 };
        ctx.tag_store
            .insert_primitive(tags::IAC_ONLINE, vec![0x00, 0x00, 0x00, 0x80, 0x00], src)
            .unwrap();
        ctx.tvr.transaction_exceeds_floor_limit = true;
        assert_eq!(
            ctx.terminal_action_analysis(false).unwrap(),
            ApplicationCryptogramType::Arqc
        );
    }

    #[test]
    fn taa_offline_only_skips_online_step_by_default() {
        let terminal = terminal_with_attendance(0x23);
        let mut ctx = ctx_with_selection(&terminal);
        let src = crate::core::tag_store::Source::Record { sfi: 1, record: 1 };
        ctx.tag_store
            .insert_primitive(tags::IAC_DEFAULT, vec![0x00; 5], src)
            .unwrap();
        ctx.tag_store
            .insert_primitive(tags::IAC_ONLINE, vec![0xFF; 5], src)
            .unwrap();
        ctx.tvr.transaction_exceeds_floor_limit = true;
        assert_eq!(
            ctx.terminal_action_analysis(false).unwrap(),
            ApplicationCryptogramType::Tc
        );
    }

    #[test]
    fn taa_offline_only_with_option_1_can_arqc() {
        let terminal = terminal_with_attendance(0x23);
        let mut ctx = ctx_with_selection(&terminal);
        let src = crate::core::tag_store::Source::Record { sfi: 1, record: 1 };
        ctx.tag_store
            .insert_primitive(tags::IAC_ONLINE, vec![0xFF; 5], src)
            .unwrap();
        ctx.tvr.transaction_exceeds_floor_limit = true;
        assert_eq!(
            ctx.terminal_action_analysis(true).unwrap(),
            ApplicationCryptogramType::Arqc
        );
    }

    #[test]
    fn taa_iac_default_absent_means_all_ones() {
        let terminal = terminal_with_attendance(0x23);
        let mut ctx = ctx_with_selection(&terminal);
        ctx.tvr.expired_application = true;
        assert_eq!(
            ctx.terminal_action_analysis(false).unwrap(),
            ApplicationCryptogramType::Aac
        );
    }

    #[test]
    fn taa_malformed_iac_returns_wrong_length_error() {
        let terminal = terminal_with_attendance(0x22);
        let mut ctx = ctx_with_selection(&terminal);
        let src = crate::core::tag_store::Source::Record { sfi: 1, record: 1 };
        ctx.tag_store
            .insert_primitive(tags::IAC_DENIAL, vec![0x01, 0x02], src)
            .unwrap();
        match ctx.terminal_action_analysis(false) {
            Err(Error::WrongLength { expected, got }) => {
                assert_eq!(expected, 5);
                assert_eq!(got, 2);
            }
            other => panic!("expected WrongLength, got {:?}", other),
        }
    }

    fn terminal_with_cvm_caps(signature: bool, no_cvm: bool, plaintext_pin: bool) -> Terminal {
        let mut t = sample_terminal();
        t.terminal_capabilities = TerminalCapabilities {
            ic_with_contacts: true,
            signature,
            no_cvm_required: no_cvm,
            plaintext_pin_for_icc_verification: plaintext_pin,
            ..Default::default()
        };
        t
    }

    #[test]
    fn cvm_no_list_returns_default_results_and_no_tsi_bit() {
        let terminal = terminal_with_cvm_caps(true, true, false);
        let mut ctx = TransactionContext::new(&terminal, TransactionInputs::default());
        ctx.select_application(vec![0xA0, 0, 0, 0, 0x03, 0x10, 0x10])
            .unwrap();
        let outcome = ctx
            .cardholder_verification(CvmFlags::default(), |_| CvmExecutionResult::Successful)
            .unwrap();
        assert_eq!(outcome.cvm_results, [0x3F, 0x00, 0x00]);
        assert!(!outcome.tsi_cardholder_verification_was_performed);
        assert!(!ctx.tsi.cardholder_verification_was_performed);
        assert_eq!(
            ctx.tag_store.get(tags::CVM_RESULTS).unwrap(),
            &[0x3F, 0x00, 0x00]
        );
    }

    #[test]
    fn cvm_no_cvm_required_unconditional_succeeds() {
        let terminal = terminal_with_cvm_caps(false, true, false);
        let mut ctx = TransactionContext::new(&terminal, TransactionInputs::default());
        ctx.select_application(vec![0xA0, 0, 0, 0, 0x03, 0x10, 0x10])
            .unwrap();
        let cvm_list_value = vec![0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x1F, 0x00];
        ctx.tag_store
            .insert_primitive(
                tags::CVM_LIST,
                cvm_list_value,
                crate::core::tag_store::Source::Record { sfi: 1, record: 1 },
            )
            .unwrap();

        let mut perform_called = 0;
        let outcome = ctx
            .cardholder_verification(CvmFlags::default(), |_rule| {
                perform_called += 1;
                CvmExecutionResult::Successful
            })
            .unwrap();
        assert_eq!(perform_called, 1);
        assert_eq!(outcome.cvm_results, [0x1F, 0x00, 0x02]);
        assert!(outcome.tsi_cardholder_verification_was_performed);
        assert!(ctx.tsi.cardholder_verification_was_performed);
        assert!(!ctx.tvr.cardholder_verification_was_not_successful);
    }

    #[test]
    fn cvm_signature_returns_unknown_byte_three() {
        let terminal = terminal_with_cvm_caps(true, false, false);
        let mut ctx = TransactionContext::new(&terminal, TransactionInputs::default());
        ctx.select_application(vec![0xA0, 0, 0, 0, 0x03, 0x10, 0x10])
            .unwrap();
        let cvm_list_value = vec![0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x1E, 0x00];
        ctx.tag_store
            .insert_primitive(
                tags::CVM_LIST,
                cvm_list_value,
                crate::core::tag_store::Source::Record { sfi: 1, record: 1 },
            )
            .unwrap();
        let outcome = ctx
            .cardholder_verification(CvmFlags::default(), |_| CvmExecutionResult::Unknown)
            .unwrap();
        assert_eq!(outcome.cvm_results, [0x1E, 0x00, 0x00]);
        assert!(ctx.tsi.cardholder_verification_was_performed);
    }

    #[test]
    fn cvm_pin_pad_absent_sets_tvr_bit_and_continues_via_b7() {
        let terminal = terminal_with_cvm_caps(true, true, true);
        let mut ctx = TransactionContext::new(&terminal, TransactionInputs::default());
        ctx.select_application(vec![0xA0, 0, 0, 0, 0x03, 0x10, 0x10])
            .unwrap();
        let cvm_list_value = vec![
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x41, 0x00, 0x1F, 0x00,
        ];
        ctx.tag_store
            .insert_primitive(
                tags::CVM_LIST,
                cvm_list_value,
                crate::core::tag_store::Source::Record { sfi: 1, record: 1 },
            )
            .unwrap();

        let outcome = ctx
            .cardholder_verification(CvmFlags::default(), |rule| {
                if rule.cvm == 0x41 {
                    CvmExecutionResult::PinPadNotWorkingOrAbsent
                } else {
                    CvmExecutionResult::Successful
                }
            })
            .unwrap();
        assert_eq!(outcome.cvm_results, [0x1F, 0x00, 0x02]);
        assert!(
            ctx.tvr
                .pin_entry_required_and_pin_pad_not_present_or_not_working
        );
        assert!(ctx.tsi.cardholder_verification_was_performed);
        assert!(!ctx.tvr.cardholder_verification_was_not_successful);
    }

    #[test]
    fn cvm_malformed_list_propagates_error() {
        let terminal = terminal_with_cvm_caps(true, true, false);
        let mut ctx = TransactionContext::new(&terminal, TransactionInputs::default());
        ctx.select_application(vec![0xA0, 0, 0, 0, 0x03, 0x10, 0x10])
            .unwrap();
        ctx.tag_store
            .insert_primitive(
                tags::CVM_LIST,
                vec![0x00, 0x00],
                crate::core::tag_store::Source::Record { sfi: 1, record: 1 },
            )
            .unwrap();
        match ctx.cardholder_verification(CvmFlags::default(), |_| CvmExecutionResult::Successful) {
            Err(_) => {}
            Ok(o) => panic!("expected parse error, got {:?}", o),
        }
    }

    // ─── §10.8 Card Action Analysis wiring ───────────────────────────────

    fn fixture_first_ac(cid_byte: u8) -> GenerateAcResponse {
        use crate::core::generate_ac::GenerateAcFormat;
        use crate::de::cryptogram_information_data::CryptogramInformationData;
        GenerateAcResponse {
            format: GenerateAcFormat::Format1,
            cid: CryptogramInformationData::parse(&[cid_byte]).unwrap(),
            atc: [0x00, 0x05],
            ac: Some([0xAA; 8]),
            iad: None,
            sdad: None,
            proprietary: Vec::new(),
            children_in_order: Vec::new(),
        }
    }

    #[test]
    fn caa_tc_returns_approve_and_sets_tsi() {
        let terminal = sample_terminal();
        let mut ctx = TransactionContext::new(&terminal, TransactionInputs::default());
        let first = fixture_first_ac(0x40);
        let analysis = ctx.card_action_analysis(&first);
        assert_eq!(
            analysis.action,
            crate::contact::card_action_analysis::CardAction::Approve
        );
        assert!(!analysis.advice_required);
        assert!(ctx.tsi.card_risk_management_was_performed);
    }

    #[test]
    fn caa_aac_returns_decline_and_sets_tsi() {
        let terminal = sample_terminal();
        let mut ctx = TransactionContext::new(&terminal, TransactionInputs::default());
        let first = fixture_first_ac(0x00);
        let analysis = ctx.card_action_analysis(&first);
        assert_eq!(
            analysis.action,
            crate::contact::card_action_analysis::CardAction::Decline
        );
        assert!(ctx.tsi.card_risk_management_was_performed);
    }

    #[test]
    fn caa_arqc_returns_go_online() {
        let terminal = sample_terminal();
        let mut ctx = TransactionContext::new(&terminal, TransactionInputs::default());
        let first = fixture_first_ac(0x80);
        let analysis = ctx.card_action_analysis(&first);
        assert_eq!(
            analysis.action,
            crate::contact::card_action_analysis::CardAction::GoOnline
        );
        assert!(ctx.tsi.card_risk_management_was_performed);
    }

    #[test]
    fn caa_aac_with_service_not_allowed_distinguished() {
        let terminal = sample_terminal();
        let mut ctx = TransactionContext::new(&terminal, TransactionInputs::default());
        let first = fixture_first_ac(0x01);
        let analysis = ctx.card_action_analysis(&first);
        assert_eq!(
            analysis.action,
            crate::contact::card_action_analysis::CardAction::ServiceNotAllowed
        );
    }

    #[test]
    fn caa_advice_required_bit_propagates() {
        let terminal = sample_terminal();
        let mut ctx = TransactionContext::new(&terminal, TransactionInputs::default());
        let first = fixture_first_ac(0x88);
        let analysis = ctx.card_action_analysis(&first);
        assert_eq!(
            analysis.action,
            crate::contact::card_action_analysis::CardAction::GoOnline
        );
        assert!(analysis.advice_required);
    }

    #[test]
    fn caa_idempotent_does_not_clobber_other_tsi_bits() {
        let terminal = sample_terminal();
        let mut ctx = TransactionContext::new(&terminal, TransactionInputs::default());
        ctx.tsi.cardholder_verification_was_performed = true;
        ctx.tsi.terminal_risk_management_was_performed = true;
        let first = fixture_first_ac(0x40);
        ctx.card_action_analysis(&first);
        assert!(ctx.tsi.card_risk_management_was_performed);
        assert!(ctx.tsi.cardholder_verification_was_performed);
        assert!(ctx.tsi.terminal_risk_management_was_performed);
    }

    #[test]
    fn cvm_amount_authorised_used_for_condition_evaluation() {
        let terminal = terminal_with_cvm_caps(true, true, false);
        let mut ctx = TransactionContext::new(
            &terminal,
            TransactionInputs {
                amount_authorised: 50,
                ..Default::default()
            },
        );
        ctx.select_application(vec![0xA0, 0, 0, 0, 0x03, 0x10, 0x10])
            .unwrap();
        let cvm_list_value = vec![
            0x00, 0x00, 0x00, 0x64, 0x00, 0x00, 0x00, 0x00, 0x1E, 0x06, 0x1F, 0x00,
        ];
        ctx.tag_store
            .insert_primitive(
                tags::CVM_LIST,
                cvm_list_value,
                crate::core::tag_store::Source::Record { sfi: 1, record: 1 },
            )
            .unwrap();

        let outcome = ctx
            .cardholder_verification(
                CvmFlags {
                    transaction_in_application_currency: true,
                    ..Default::default()
                },
                |_| CvmExecutionResult::Unknown,
            )
            .unwrap();
        assert_eq!(outcome.cvm_results, [0x1E, 0x06, 0x00]);
    }

    #[test]
    fn taa_errors_when_no_application_selected() {
        let terminal = terminal_with_attendance(0x22);
        let ctx = TransactionContext::new(&terminal, TransactionInputs::default());
        match ctx.terminal_action_analysis(false) {
            Err(Error::MissingMandatory { tag }) => {
                assert_eq!(tag, tags::APPLICATION_DEDICATED_FILE_NAME);
            }
            other => panic!("expected MissingMandatory, got {:?}", other),
        }
    }
}
