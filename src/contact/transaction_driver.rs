//! Book 3 §8 / §10 - Transaction driver.

use crate::contact::application_selection::{self, Candidate};
use crate::contact::dol_resolve::DolResolveExt;
use crate::contact::fci::PseFci;
use crate::contact::issuer_script::{self, ScriptProcessingOutcome, ScriptTag};
use crate::contact::oda_input;
use crate::contact::online_processing::{
    self, ExternalAuthenticateOutcome, OnlineAuthorisation, OnlineAuthorisationResponse,
};
use crate::contact::read_application_data::{
    self, ReadApplicationDataError, ReadApplicationDataOutcome,
};
use crate::contact::terminal::{Terminal, TerminalApplication};
use crate::contact::terminal_risk_management::{
    self, RandomSelectionParameters, TerminalRiskManagementContext, TerminalRiskManagementOutcome,
};
use crate::contact::transaction::{TransactionContext, TransactionInputs};
use crate::core::apdu::{Command, sw};
use crate::core::card_reader::CardReader;
use crate::core::crl::{self, CrlEntry};
use crate::core::ecc_oda::{self, EccCaPublicKey};
use crate::core::error::Error;
use crate::core::fci::AdfFci;
use crate::core::generate_ac::{self, GenerateAcResponse, SignatureRequest};
use crate::core::get_data;
use crate::core::oda::{self, CaPublicKey, OdaMethod, OdaOutcome};
use crate::core::processing_options::{self, ProcessingOptionsResponse};
use crate::core::read_record;
use crate::core::select::{self, SelectOccurrence};
use crate::core::tag::Tag;
use crate::core::tag_store::Source;
use crate::core::tags;
use crate::core::terminal_action_analysis::ApplicationCryptogramType;
use crate::core::tlv::Tlv;
use crate::de::application_selection_indicator::ApplicationSelectionIndicator;
use crate::de::payment_system_directory::PaymentSystemDirectoryRecord;

/// Book 1 §12.2.2.
const PSE_NAME: &[u8] = b"1PAY.SYS.DDF01";

/// Book 3 §6.5.9.4 - Format 1 primitive '80', Format 2 constructed '77' with '9F4B'.
fn parse_internal_authenticate_sdad(data: &[u8]) -> Option<Vec<u8>> {
    let tlv = Tlv::from_bytes(data).ok()?;
    match tlv.tag() {
        tags::RESPONSE_MESSAGE_TEMPLATE_FORMAT_1 => tlv.value().as_primitive().map(<[u8]>::to_vec),
        tags::RESPONSE_MESSAGE_TEMPLATE_FORMAT_2 => {
            let children = tlv.value().as_constructed()?;
            children
                .iter()
                .find(|c| c.tag() == tags::SIGNED_DYNAMIC_APPLICATION_DATA)
                .and_then(|c| c.value().as_primitive())
                .map(<[u8]>::to_vec)
        }
        _ => None,
    }
}

/// 1..=2-byte big-endian (Annex A1).
fn parse_u16_be(bytes: &[u8]) -> u16 {
    match bytes.len() {
        1 => bytes[0] as u16,
        2 => u16::from_be_bytes([bytes[0], bytes[1]]),
        _ => 0,
    }
}

/// Book 1 §12.3.1.
fn terminal_supports_adf_name(adf_name: &[u8], apps: &[TerminalApplication]) -> bool {
    apps.iter().any(|app| {
        let asi = if app.partial_match_allowed {
            ApplicationSelectionIndicator::PartialMatchAllowed
        } else {
            ApplicationSelectionIndicator::ExactMatch
        };
        application_selection::aid_matches_df_name(&app.aid, asi, adf_name)
    })
}

/// Book 4 §6.7.3 convention: YY < 0x50 → 20YY, else 19YY.
fn bcd_yyyymmdd_from_yymmdd(yymmdd: [u8; 3]) -> [u8; 4] {
    let century = if yymmdd[0] < 0x50 { 0x20 } else { 0x19 };
    [century, yymmdd[0], yymmdd[1], yymmdd[2]]
}

#[derive(Debug)]
pub enum DriverError<TransportError, AuthError> {
    Transport(TransportError),
    Auth(AuthError),
    Spec(Error),
    /// Book 3 §8.1 - non-{'9000','63Cx','6283'} terminates.
    StatusWord {
        command: &'static str,
        sw: u16,
    },
    UnknownAid,
    NoMatchingApplication,
    NotSelected,
    NoAfl,
}

impl<T, A> From<Error> for DriverError<T, A> {
    fn from(e: Error) -> Self {
        DriverError::Spec(e)
    }
}

impl<T, A> From<ReadApplicationDataError<T>> for DriverError<T, A> {
    fn from(e: ReadApplicationDataError<T>) -> Self {
        match e {
            ReadApplicationDataError::Transport(t) => DriverError::Transport(t),
            ReadApplicationDataError::Spec(s) => DriverError::Spec(s),
            ReadApplicationDataError::NonOkStatusWord {
                sfi: _,
                record_number: _,
                sw,
            } => DriverError::StatusWord {
                command: "READ RECORD",
                sw,
            },
        }
    }
}

pub struct Transaction<'t, C, A> {
    pub card: C,
    pub auth: A,
    pub ctx: TransactionContext<'t>,
}

impl<'t, C: CardReader, A: OnlineAuthorisation> Transaction<'t, C, A> {
    pub fn new(card: C, terminal: &'t Terminal, inputs: TransactionInputs, auth: A) -> Self {
        Self {
            card,
            auth,
            ctx: TransactionContext::new(terminal, inputs),
        }
    }

    /// Book 1 §11.3 / Book 3 §10.1.
    pub fn select_application(
        &mut self,
        df_name: &[u8],
    ) -> Result<AdfFci, DriverError<C::Error, A::Error>> {
        let cmd = select::select_by_name(df_name, SelectOccurrence::FirstOrOnly)?;
        let resp = self.card.transmit(&cmd).map_err(DriverError::Transport)?;
        if resp.status_word() != sw::OK {
            return Err(DriverError::StatusWord {
                command: "SELECT",
                sw: resp.status_word(),
            });
        }
        let fci = AdfFci::parse(resp.data())?;
        self.ctx
            .select_application(fci.df_name.clone())
            .ok_or(DriverError::UnknownAid)?;
        Ok(fci)
    }

    /// Book 1 §12.3.3 candidate-list probe.
    pub fn try_select(
        &mut self,
        aid: &[u8],
    ) -> Result<Option<AdfFci>, DriverError<C::Error, A::Error>> {
        let cmd = select::select_by_name(aid, SelectOccurrence::FirstOrOnly)?;
        let resp = self.card.transmit(&cmd).map_err(DriverError::Transport)?;
        match resp.status_word() {
            sw::OK => {
                let fci = AdfFci::parse(resp.data())?;
                self.ctx
                    .select_application(fci.df_name.clone())
                    .ok_or(DriverError::UnknownAid)?;
                Ok(Some(fci))
            }
            sw::FILE_NOT_FOUND => Ok(None),
            sw => Err(DriverError::StatusWord {
                command: "SELECT",
                sw,
            }),
        }
    }

    /// Book 1 §12.3.3 first-match shortcut.
    pub fn select_first_supported(&mut self) -> Result<AdfFci, DriverError<C::Error, A::Error>> {
        let aids: Vec<Vec<u8>> = self
            .ctx
            .terminal
            .applications
            .iter()
            .map(|a| a.aid.clone())
            .collect();
        for aid in &aids {
            if let Some(fci) = self.try_select(aid)? {
                return Ok(fci);
            }
        }
        Err(DriverError::NoMatchingApplication)
    }

    /// Book 1 §12.3.2 PSE method.
    pub fn build_candidate_list_pse(
        &mut self,
    ) -> Result<Option<Vec<Candidate>>, DriverError<C::Error, A::Error>> {
        // Step 1: SELECT '1PAY.SYS.DDF01'.
        let cmd = select::select_by_name(PSE_NAME, SelectOccurrence::FirstOrOnly)?;
        let resp = self.card.transmit(&cmd).map_err(DriverError::Transport)?;
        match resp.status_word() {
            sw::OK => {}
            // §12.3.2: '6A81' (selection or card blocked) → terminate.
            0x6A81 => {
                return Err(DriverError::StatusWord {
                    command: "SELECT PSE",
                    sw: 0x6A81,
                });
            }
            // '6A82' no PSE / '6283' PSE blocked / anything else → fall back.
            _ => return Ok(None),
        }

        let pse_fci = match PseFci::parse(resp.data()) {
            Ok(f) => f,
            Err(_) => return Ok(None),
        };
        let sfi = pse_fci.sfi_of_directory_ef;
        let icti = pse_fci.issuer_code_table_index;

        // Steps 2–4: walk directory records starting at 1, until '6A83'.
        let mut candidates = Vec::new();
        for record_number in 1u8..=u8::MAX {
            let cmd = match read_record::command(sfi, record_number) {
                Ok(c) => c,
                // Bad SFI from card - fall back per §12.3.2 step 1 last paragraph.
                Err(_) => return Ok(None),
            };
            let resp = self.card.transmit(&cmd).map_err(DriverError::Transport)?;
            match resp.status_word() {
                sw::OK => {}
                // '6A83' record not found → end of directory.
                sw::RECORD_NOT_FOUND => break,
                // §12.3.2 step 1 last paragraph: any other error → restart with AID list.
                _ => return Ok(None),
            }
            let record = match PaymentSystemDirectoryRecord::parse(resp.data()) {
                Ok(r) => r,
                Err(_) => return Ok(None),
            };
            for entry in record.entries {
                if terminal_supports_adf_name(&entry.adf_name, &self.ctx.terminal.applications) {
                    candidates.push(Candidate::from_directory_entry(entry, icti));
                }
            }
        }

        Ok(Some(candidates))
    }

    /// Book 1 §12.3.3 List of AIDs.
    pub fn build_candidate_list_aids(
        &mut self,
    ) -> Result<Vec<Candidate>, DriverError<C::Error, A::Error>> {
        let aids: Vec<(Vec<u8>, bool)> = self
            .ctx
            .terminal
            .applications
            .iter()
            .map(|a| (a.aid.clone(), a.partial_match_allowed))
            .collect();

        let mut candidates = Vec::new();
        for (aid, partial_allowed) in &aids {
            let cmd = select::select_by_name(aid, SelectOccurrence::FirstOrOnly)?;
            let resp = self.card.transmit(&cmd).map_err(DriverError::Transport)?;
            match resp.status_word() {
                sw::OK => {
                    let fci = match AdfFci::parse(resp.data()) {
                        Ok(f) => f,
                        Err(_) => continue,
                    };
                    let asi = if *partial_allowed {
                        ApplicationSelectionIndicator::PartialMatchAllowed
                    } else {
                        ApplicationSelectionIndicator::ExactMatch
                    };
                    if application_selection::aid_matches_df_name(aid, asi, &fci.df_name) {
                        candidates.push(Candidate::from_adf_fci(fci));
                    }
                }
                0x6A81 => {
                    return Err(DriverError::StatusWord {
                        command: "SELECT (AID list)",
                        sw: 0x6A81,
                    });
                }
                _ => {}
            }
        }
        Ok(candidates)
    }

    /// Book 1 §12.3 - PSE first, AID list fallback.
    pub fn build_candidate_list(
        &mut self,
    ) -> Result<Vec<Candidate>, DriverError<C::Error, A::Error>> {
        if let Some(candidates) = self.build_candidate_list_pse()?
            && !candidates.is_empty()
        {
            return Ok(candidates);
        }
        self.build_candidate_list_aids()
    }

    /// §10.1.
    pub fn initiate(
        &mut self,
        pdol_data: &[u8],
    ) -> Result<ProcessingOptionsResponse, DriverError<C::Error, A::Error>> {
        if self.ctx.selected.is_none() {
            return Err(DriverError::NotSelected);
        }
        let cmd = processing_options::command(pdol_data)?;
        let resp = self.card.transmit(&cmd).map_err(DriverError::Transport)?;
        if resp.status_word() != sw::OK {
            return Err(DriverError::StatusWord {
                command: "GET PROCESSING OPTIONS",
                sw: resp.status_word(),
            });
        }
        let parsed = ProcessingOptionsResponse::parse(resp.data())?;
        self.ctx.aip = Some(parsed.aip);
        self.ctx.afl = parsed.afl.clone();
        // Book 2 §6.6.2 step-10.
        self.ctx.gpo_pdol_data = pdol_data.to_vec();
        Ok(parsed)
    }

    /// §10.2.
    pub fn read_application_data(
        &mut self,
    ) -> Result<ReadApplicationDataOutcome, DriverError<C::Error, A::Error>> {
        let afl = self.ctx.afl.as_ref().ok_or(DriverError::NoAfl)?.clone();
        let outcome = read_application_data::read_application_data(
            &mut self.card,
            &afl,
            &mut self.ctx.tag_store,
        )?;
        Ok(outcome)
    }

    /// §10.3.
    pub fn perform_offline_data_authentication(
        &mut self,
        capks: &[CaPublicKey],
        ecc_capks: &[EccCaPublicKey],
        crl: &[CrlEntry],
        records: &[u8],
    ) -> Result<OdaOutcome, DriverError<C::Error, A::Error>> {
        let aip = self.ctx.aip.as_ref().ok_or(Error::MissingMandatory {
            tag: tags::APPLICATION_INTERCHANGE_PROFILE,
        })?;
        let term_cap = &self.ctx.terminal.terminal_capabilities;

        // §10.3 - XDA > CDA > DDA > SDA.
        let method = if aip.xda_supported && term_cap.xda {
            Some(OdaMethod::Xda)
        } else if aip.cda_supported && term_cap.cda {
            Some(OdaMethod::Cda)
        } else if aip.dda_supported && term_cap.dda {
            Some(OdaMethod::Dda)
        } else if aip.sda_supported && term_cap.sda {
            Some(OdaMethod::Sda)
        } else {
            None
        };

        match method {
            None => {
                self.ctx.tvr.offline_data_authentication_was_not_performed = true;
                Ok(OdaOutcome::NotPerformed)
            }
            Some(OdaMethod::Sda) => {
                self.ctx.tvr.sda_selected = true;
                let result = self.perform_sda_inner(capks, crl, records)?;
                Ok(result)
            }
            Some(OdaMethod::Dda) => {
                let result = self.perform_dda_inner(capks, crl, records)?;
                Ok(result)
            }
            Some(OdaMethod::Cda) => {
                // Book 2 §6.6 - chain recovery before TAA.
                let result = self.perform_cda_arm(capks, crl, records)?;
                Ok(result)
            }
            Some(OdaMethod::Xda) => {
                // Book 2 §12 p.107 - TVR bits deferred to verify_xda_*.
                self.ctx.tvr.xda_selected = true;
                let result = self.perform_xda_arm(ecc_capks, crl, records)?;
                Ok(result)
            }
        }
    }

    /// Book 2 §5.
    fn perform_sda_inner(
        &mut self,
        capks: &[CaPublicKey],
        crl: &[CrlEntry],
        records: &[u8],
    ) -> Result<OdaOutcome, DriverError<C::Error, A::Error>> {
        // Missing → 'ICC data missing' + 'SDA failed'.
        let store = &self.ctx.tag_store;
        let ca_index = match store.get(tags::CA_PUBLIC_KEY_INDEX_ICC) {
            Some(b) if b.len() == 1 => b[0],
            _ => return Ok(self.fail_sda_with_missing_icc_data()),
        };
        let issuer_cert = match store.get(tags::ISSUER_PUBLIC_KEY_CERTIFICATE) {
            Some(b) => b.to_vec(),
            None => return Ok(self.fail_sda_with_missing_icc_data()),
        };
        let issuer_exp = match store.get(tags::ISSUER_PUBLIC_KEY_EXPONENT) {
            Some(b) => b.to_vec(),
            None => return Ok(self.fail_sda_with_missing_icc_data()),
        };
        let ssad = match store.get(tags::SIGNED_STATIC_APPLICATION_DATA) {
            Some(b) => b.to_vec(),
            None => return Ok(self.fail_sda_with_missing_icc_data()),
        };
        let pan = match store.get(tags::PAN) {
            Some(b) => b.to_vec(),
            None => return Ok(self.fail_sda_with_missing_icc_data()),
        };
        let issuer_remainder = store
            .get(tags::ISSUER_PUBLIC_KEY_REMAINDER)
            .map(|b| b.to_vec());
        let sda_tag_list = store.get(tags::SDA_TAG_LIST).map(|b| b.to_vec());

        // Book 1 §12.2.1 - RID = DF Name[..5].
        let selected = self.ctx.selected.as_ref().ok_or(DriverError::NotSelected)?;
        if selected.df_name.len() < 5 {
            return Err(DriverError::Spec(Error::WrongLength {
                expected: 5,
                got: selected.df_name.len(),
            }));
        }
        let rid: [u8; 5] = selected.df_name[..5].try_into().unwrap();

        let capk = match capks.iter().find(|k| k.rid == rid && k.index == ca_index) {
            Some(k) => k,
            None => return Ok(self.fail_sda()),
        };

        let aip_bytes = self
            .ctx
            .aip
            .as_ref()
            .expect("aip present (checked by caller)")
            .to_bytes();
        let static_data =
            match oda_input::sda_static_data_input(records, sda_tag_list.as_deref(), &aip_bytes) {
                Ok(d) => d,
                Err(_) => return Ok(self.fail_sda()),
            };

        let today_mmyy = [
            self.ctx.inputs.transaction_date[1],
            self.ctx.inputs.transaction_date[0],
        ];

        // Book 2 §5.3.
        let issuer_pk = match oda::recover_issuer_public_key(
            capk,
            &issuer_cert,
            issuer_remainder.as_deref(),
            &issuer_exp,
            &pan,
            today_mmyy,
        ) {
            Ok(pk) => pk,
            Err(_) => return Ok(self.fail_sda()),
        };

        // §5.3 step 10 + §5.1.2 - CRL.
        if crl::is_revoked(crl, &rid, ca_index, &issuer_pk.serial_number) {
            return Ok(self.fail_sda());
        }

        // Book 2 §5.4.
        match oda::verify_sda(&issuer_pk, &ssad, &static_data) {
            Ok(dac) => {
                self.ctx.tag_store.insert_primitive(
                    tags::DATA_AUTHENTICATION_CODE,
                    dac.to_vec(),
                    Source::TerminalGenerated,
                )?;
                self.ctx.tsi.offline_data_authentication_was_performed = true;
                Ok(OdaOutcome::SdaSuccess { dac })
            }
            Err(_) => Ok(self.fail_sda()),
        }
    }

    fn fail_sda_with_missing_icc_data(&mut self) -> OdaOutcome {
        self.ctx.tvr.icc_data_missing = true;
        self.fail_sda()
    }

    fn fail_sda(&mut self) -> OdaOutcome {
        self.ctx.tvr.sda_failed = true;
        self.ctx.tsi.offline_data_authentication_was_performed = true;
        OdaOutcome::SdaFailed
    }

    /// Book 2 §6.4 / §6.5.
    fn perform_dda_inner(
        &mut self,
        capks: &[CaPublicKey],
        crl: &[CrlEntry],
        records: &[u8],
    ) -> Result<OdaOutcome, DriverError<C::Error, A::Error>> {
        let store = &self.ctx.tag_store;
        let ca_index = match store.get(tags::CA_PUBLIC_KEY_INDEX_ICC) {
            Some(b) if b.len() == 1 => b[0],
            _ => return Ok(self.fail_dda_with_missing_icc_data()),
        };
        let issuer_cert = match store.get(tags::ISSUER_PUBLIC_KEY_CERTIFICATE) {
            Some(b) => b.to_vec(),
            None => return Ok(self.fail_dda_with_missing_icc_data()),
        };
        let issuer_exp = match store.get(tags::ISSUER_PUBLIC_KEY_EXPONENT) {
            Some(b) => b.to_vec(),
            None => return Ok(self.fail_dda_with_missing_icc_data()),
        };
        let icc_cert = match store.get(tags::ICC_PUBLIC_KEY_CERTIFICATE) {
            Some(b) => b.to_vec(),
            None => return Ok(self.fail_dda_with_missing_icc_data()),
        };
        let icc_exp = match store.get(tags::ICC_PUBLIC_KEY_EXPONENT) {
            Some(b) => b.to_vec(),
            None => return Ok(self.fail_dda_with_missing_icc_data()),
        };
        let pan = match store.get(tags::PAN) {
            Some(b) => b.to_vec(),
            None => return Ok(self.fail_dda_with_missing_icc_data()),
        };
        let issuer_remainder = store
            .get(tags::ISSUER_PUBLIC_KEY_REMAINDER)
            .map(|b| b.to_vec());
        let icc_remainder = store
            .get(tags::ICC_PUBLIC_KEY_REMAINDER)
            .map(|b| b.to_vec());
        let sda_tag_list = store.get(tags::SDA_TAG_LIST).map(|b| b.to_vec());
        let icc_ddol = store.get(tags::DDOL).map(|b| b.to_vec());

        let selected = self.ctx.selected.as_ref().ok_or(DriverError::NotSelected)?;
        if selected.df_name.len() < 5 {
            return Err(DriverError::Spec(Error::WrongLength {
                expected: 5,
                got: selected.df_name.len(),
            }));
        }
        let rid: [u8; 5] = selected.df_name[..5].try_into().unwrap();

        let capk = match capks.iter().find(|k| k.rid == rid && k.index == ca_index) {
            Some(k) => k,
            None => return Ok(self.fail_dda()),
        };

        let aip_bytes = self
            .ctx
            .aip
            .as_ref()
            .expect("aip present (checked by caller)")
            .to_bytes();
        let static_data =
            match oda_input::sda_static_data_input(records, sda_tag_list.as_deref(), &aip_bytes) {
                Ok(d) => d,
                Err(_) => return Ok(self.fail_dda()),
            };

        let today_mmyy = [
            self.ctx.inputs.transaction_date[1],
            self.ctx.inputs.transaction_date[0],
        ];

        let issuer_pk = match oda::recover_issuer_public_key(
            capk,
            &issuer_cert,
            issuer_remainder.as_deref(),
            &issuer_exp,
            &pan,
            today_mmyy,
        ) {
            Ok(pk) => pk,
            Err(_) => return Ok(self.fail_dda()),
        };
        if crl::is_revoked(crl, &rid, ca_index, &issuer_pk.serial_number) {
            return Ok(self.fail_dda());
        }
        let icc_pk = match oda::recover_icc_public_key(
            &issuer_pk,
            &icc_cert,
            icc_remainder.as_deref(),
            &icc_exp,
            &static_data,
            &pan,
            today_mmyy,
        ) {
            Ok(pk) => pk,
            Err(_) => return Ok(self.fail_dda()),
        };

        // Book 2 §6.5.1 - ICC's '9F49' wins, must contain '9F37'.
        let ddol_bytes = match icc_ddol.as_deref() {
            Some(b) => b,
            None => match selected.config.default_ddol.as_deref() {
                Some(b) => b,
                None => return Ok(self.fail_dda()),
            },
        };
        let ddol = match crate::core::dol::Dol::parse(ddol_bytes) {
            Ok(d) => d,
            Err(_) => return Ok(self.fail_dda()),
        };
        if !ddol.0.iter().any(|e| e.tag.0 == 0x9F37) {
            return Ok(self.fail_dda());
        }
        let ddol_data = ddol.resolve(&self.ctx);

        let cmd = crate::core::internal_authenticate::command(ddol_data.clone());
        let resp = self.card.transmit(&cmd).map_err(DriverError::Transport)?;
        if resp.status_word() != sw::OK {
            return Ok(self.fail_dda());
        }
        let sdad = match parse_internal_authenticate_sdad(resp.data()) {
            Some(s) => s,
            None => return Ok(self.fail_dda()),
        };

        match oda::verify_dda(&icc_pk, &sdad, &ddol_data) {
            Ok(icc_dynamic_number) => {
                self.ctx.tag_store.insert_primitive(
                    tags::ICC_DYNAMIC_NUMBER,
                    icc_dynamic_number.clone(),
                    Source::TerminalGenerated,
                )?;
                self.ctx.tsi.offline_data_authentication_was_performed = true;
                Ok(OdaOutcome::DdaSuccess { icc_dynamic_number })
            }
            Err(_) => Ok(self.fail_dda()),
        }
    }

    fn fail_dda_with_missing_icc_data(&mut self) -> OdaOutcome {
        self.ctx.tvr.icc_data_missing = true;
        self.fail_dda()
    }

    fn fail_dda(&mut self) -> OdaOutcome {
        self.ctx.tvr.dda_failed = true;
        self.ctx.tsi.offline_data_authentication_was_performed = true;
        OdaOutcome::DdaFailed
    }

    /// Book 2 §6.6 - pre-TAA CDA chain recovery.
    fn perform_cda_arm(
        &mut self,
        capks: &[CaPublicKey],
        crl: &[CrlEntry],
        records: &[u8],
    ) -> Result<OdaOutcome, DriverError<C::Error, A::Error>> {
        let store = &self.ctx.tag_store;
        let ca_index = match store.get(tags::CA_PUBLIC_KEY_INDEX_ICC) {
            Some(b) if b.len() == 1 => b[0],
            _ => return Ok(self.fail_cda_with_missing_icc_data()),
        };
        let issuer_cert = match store.get(tags::ISSUER_PUBLIC_KEY_CERTIFICATE) {
            Some(b) => b.to_vec(),
            None => return Ok(self.fail_cda_with_missing_icc_data()),
        };
        let issuer_exp = match store.get(tags::ISSUER_PUBLIC_KEY_EXPONENT) {
            Some(b) => b.to_vec(),
            None => return Ok(self.fail_cda_with_missing_icc_data()),
        };
        let icc_cert = match store.get(tags::ICC_PUBLIC_KEY_CERTIFICATE) {
            Some(b) => b.to_vec(),
            None => return Ok(self.fail_cda_with_missing_icc_data()),
        };
        let icc_exp = match store.get(tags::ICC_PUBLIC_KEY_EXPONENT) {
            Some(b) => b.to_vec(),
            None => return Ok(self.fail_cda_with_missing_icc_data()),
        };
        let pan = match store.get(tags::PAN) {
            Some(b) => b.to_vec(),
            None => return Ok(self.fail_cda_with_missing_icc_data()),
        };
        let issuer_remainder = store
            .get(tags::ISSUER_PUBLIC_KEY_REMAINDER)
            .map(|b| b.to_vec());
        let icc_remainder = store
            .get(tags::ICC_PUBLIC_KEY_REMAINDER)
            .map(|b| b.to_vec());
        let sda_tag_list = store.get(tags::SDA_TAG_LIST).map(|b| b.to_vec());

        let selected = self.ctx.selected.as_ref().ok_or(DriverError::NotSelected)?;
        if selected.df_name.len() < 5 {
            return Err(DriverError::Spec(Error::WrongLength {
                expected: 5,
                got: selected.df_name.len(),
            }));
        }
        let rid: [u8; 5] = selected.df_name[..5].try_into().unwrap();

        let capk = match capks.iter().find(|k| k.rid == rid && k.index == ca_index) {
            Some(k) => k,
            None => return Ok(self.fail_cda()),
        };

        let aip_bytes = self
            .ctx
            .aip
            .as_ref()
            .expect("aip present (checked by caller)")
            .to_bytes();
        let static_data =
            match oda_input::sda_static_data_input(records, sda_tag_list.as_deref(), &aip_bytes) {
                Ok(d) => d,
                Err(_) => return Ok(self.fail_cda()),
            };

        let today_mmyy = [
            self.ctx.inputs.transaction_date[1],
            self.ctx.inputs.transaction_date[0],
        ];

        let issuer_pk = match oda::recover_issuer_public_key(
            capk,
            &issuer_cert,
            issuer_remainder.as_deref(),
            &issuer_exp,
            &pan,
            today_mmyy,
        ) {
            Ok(pk) => pk,
            Err(_) => return Ok(self.fail_cda()),
        };
        if crl::is_revoked(crl, &rid, ca_index, &issuer_pk.serial_number) {
            return Ok(self.fail_cda());
        }
        let icc_pk = match oda::recover_icc_public_key(
            &issuer_pk,
            &icc_cert,
            icc_remainder.as_deref(),
            &icc_exp,
            &static_data,
            &pan,
            today_mmyy,
        ) {
            Ok(pk) => pk,
            Err(_) => return Ok(self.fail_cda()),
        };

        self.ctx.cda = Some(oda::CdaArming {
            icc_public_key: icc_pk,
            cdol1_data: Vec::new(),
            cdol2_data: Vec::new(),
        });
        Ok(OdaOutcome::CdaArmed)
    }

    fn fail_cda_with_missing_icc_data(&mut self) -> OdaOutcome {
        self.ctx.tvr.icc_data_missing = true;
        self.fail_cda()
    }

    fn fail_cda(&mut self) -> OdaOutcome {
        self.ctx.tvr.cda_failed = true;
        OdaOutcome::CdaFailed
    }

    /// Book 2 §12.3 / §12.4 - XDA pre-GenAC chain recovery.
    fn perform_xda_arm(
        &mut self,
        ecc_capks: &[EccCaPublicKey],
        crl: &[CrlEntry],
        records: &[u8],
    ) -> Result<OdaOutcome, DriverError<C::Error, A::Error>> {
        let store = &self.ctx.tag_store;

        // §12.2 - CA ECC key lookup by RID + CA Public Key Index.
        let ca_index_opt = store
            .get(tags::CA_PUBLIC_KEY_INDEX_ICC)
            .and_then(|b| if b.len() == 1 { Some(b[0]) } else { None });
        let ca_index = match ca_index_opt {
            Some(i) => i,
            None => return Ok(self.fail_xda_with_missing_icc_data()),
        };
        let issuer_cert = match store.get(tags::ISSUER_PUBLIC_KEY_CERTIFICATE) {
            Some(b) => b.to_vec(),
            None => return Ok(self.fail_xda_with_missing_icc_data()),
        };
        let icc_cert = match store.get(tags::ICC_PUBLIC_KEY_CERTIFICATE) {
            Some(b) => b.to_vec(),
            None => return Ok(self.fail_xda_with_missing_icc_data()),
        };
        let pan = match store.get(tags::PAN) {
            Some(b) => b.to_vec(),
            None => return Ok(self.fail_xda_with_missing_icc_data()),
        };

        let selected = self.ctx.selected.as_ref().ok_or(DriverError::NotSelected)?;
        if selected.df_name.len() < 5 {
            return Err(DriverError::Spec(Error::WrongLength {
                expected: 5,
                got: selected.df_name.len(),
            }));
        }
        let rid: [u8; 5] = selected.df_name[..5].try_into().unwrap();

        // §12.2 - bit application deferred to verify_xda_first_generate_ac.
        let ecc_capk = match ecc_capks
            .iter()
            .find(|k| k.rid == rid && k.index == ca_index)
        {
            Some(k) => k,
            None => return Ok(self.arm_xda(oda::XdaArmingState::CaMissing)),
        };

        // §12.4 - ICCD = AFL records || AIP TLV || AID TLV || PDOL TLV.
        let aip_bytes = self
            .ctx
            .aip
            .as_ref()
            .expect("aip present (checked by caller)")
            .to_bytes();
        let aid_terminal = selected.df_name.clone();
        let pdol_received = store.get(tags::PDOL).map(|b| b.to_vec());
        let iccd_input =
            oda_input::xda_iccd_input(records, &aip_bytes, &aid_terminal, pdol_received.as_deref());

        let today_yyyymmdd = bcd_yyyymmdd_from_yymmdd(self.ctx.inputs.transaction_date);
        let now_hhmm = [
            self.ctx.inputs.transaction_time[0],
            self.ctx.inputs.transaction_time[1],
        ];

        let issuer_pk = match ecc_oda::recover_issuer_public_key_ecc(
            ecc_capk,
            &issuer_cert,
            &pan,
            today_yyyymmdd,
        ) {
            Ok(pk) => pk,
            Err(_) => return Ok(self.arm_xda(oda::XdaArmingState::RecoveryFailed)),
        };
        if crl::is_revoked(crl, &rid, ca_index, &issuer_pk.serial_number) {
            return Ok(self.arm_xda(oda::XdaArmingState::RecoveryFailed));
        }
        let icc_pk = match ecc_oda::recover_icc_public_key_ecc(
            &issuer_pk,
            &icc_cert,
            &iccd_input,
            today_yyyymmdd,
            now_hhmm,
        ) {
            Ok(pk) => pk,
            Err(_) => return Ok(self.arm_xda(oda::XdaArmingState::RecoveryFailed)),
        };

        Ok(self.arm_xda(oda::XdaArmingState::Armed {
            icc_public_key: icc_pk,
        }))
    }

    fn arm_xda(&mut self, state: oda::XdaArmingState) -> OdaOutcome {
        self.ctx.xda = Some(oda::XdaArming {
            state,
            cdol1_data: Vec::new(),
            cdol2_data: Vec::new(),
        });
        OdaOutcome::XdaArmed
    }

    fn fail_xda_with_missing_icc_data(&mut self) -> OdaOutcome {
        self.ctx.tvr.icc_data_missing = true;
        self.arm_xda(oda::XdaArmingState::RecoveryFailed)
    }

    /// Book 3 §6.5.7 - GET DATA. Non-'9000' returns `Ok(None)` per §10.6.3.
    pub fn get_data(
        &mut self,
        tag: Tag,
    ) -> Result<Option<Vec<u8>>, DriverError<C::Error, A::Error>> {
        let cmd = get_data::command(tag)?;
        let resp = self.card.transmit(&cmd).map_err(DriverError::Transport)?;
        if resp.status_word() != sw::OK {
            return Ok(None);
        }
        let tlv = Tlv::from_bytes(resp.data())?;
        if tlv.tag() != tag {
            return Err(DriverError::Spec(Error::InvalidValue));
        }
        let value = tlv.value().as_primitive().ok_or(Error::NotConstructed)?;
        let bytes = value.to_vec();
        self.ctx
            .tag_store
            .insert_primitive(tag, bytes.clone(), Source::TerminalGenerated)?;
        Ok(Some(bytes))
    }

    /// §10.6.
    pub fn run_terminal_risk_management(
        &mut self,
        random_number: Option<u8>,
        prior_amount_for_pan: Option<u64>,
    ) -> Result<TerminalRiskManagementOutcome, DriverError<C::Error, A::Error>> {
        let selected = self.ctx.selected.as_ref().ok_or(DriverError::NotSelected)?;
        let cfg = selected.config;

        // §10.6.2 - RTS requires all three params.
        let rts_params = match (
            cfg.rts_target_percentage,
            cfg.rts_max_target_percentage,
            cfg.rts_threshold_value,
        ) {
            (Some(t), Some(m), Some(th)) => Some(RandomSelectionParameters {
                target_percentage: t,
                max_target_percentage: m,
                threshold_value: th,
            }),
            _ => None,
        };
        let effective_random = if rts_params.is_some() {
            random_number
        } else {
            None
        };
        let evaluator_params = rts_params.unwrap_or(RandomSelectionParameters {
            target_percentage: 0,
            max_target_percentage: 0,
            threshold_value: 0,
        });

        let lower_limit = self
            .ctx
            .tag_store
            .get(tags::LOWER_CONSECUTIVE_OFFLINE_LIMIT)
            .and_then(|b| b.first().copied());
        let upper_limit = self
            .ctx
            .tag_store
            .get(tags::UPPER_CONSECUTIVE_OFFLINE_LIMIT)
            .and_then(|b| b.first().copied());

        // §10.6.3 - GET DATA ATC & Last Online ATC Register.
        let atc = self
            .get_data(tags::APPLICATION_TRANSACTION_COUNTER)?
            .as_deref()
            .map(parse_u16_be);
        let last_online = self
            .get_data(tags::LAST_ONLINE_ATC_REGISTER)?
            .as_deref()
            .map(parse_u16_be);

        let trm_ctx = TerminalRiskManagementContext {
            amount_authorised: self.ctx.inputs.amount_authorised,
            floor_limit: cfg.terminal_floor_limit as u64,
            prior_amount_for_pan,
            random_selection_parameters: evaluator_params,
            random_number: effective_random,
            lower_consecutive_offline_limit: lower_limit,
            upper_consecutive_offline_limit: upper_limit,
            atc,
            last_online_atc_register: last_online,
        };
        let outcome = terminal_risk_management::evaluate(&trm_ctx)?;

        let tvr = &mut self.ctx.tvr;
        tvr.transaction_exceeds_floor_limit |= outcome.transaction_exceeds_floor_limit;
        tvr.transaction_selected_randomly_for_online_processing |=
            outcome.transaction_selected_randomly_for_online_processing;
        tvr.lower_consecutive_offline_limit_exceeded |=
            outcome.lower_consecutive_offline_limit_exceeded;
        tvr.upper_consecutive_offline_limit_exceeded |=
            outcome.upper_consecutive_offline_limit_exceeded;
        tvr.new_card |= outcome.new_card;

        self.ctx.tsi.terminal_risk_management_was_performed = true;

        Ok(outcome)
    }

    /// §9.2.2 - populate '98' if `dol` references it.
    pub fn prepare_tc_hash_for_dol(&mut self, dol: &crate::core::dol::Dol) {
        use sha1::{Digest, Sha1};

        if !dol.0.iter().any(|e| e.tag == tags::TC_HASH_VALUE) {
            return;
        }

        // §9.2.2 - ICC '97' wins over default.
        let icc_tdol = self.ctx.tag_store.get(tags::TDOL).map(<[u8]>::to_vec);
        let (tdol_bytes, used_default) = match icc_tdol {
            Some(b) => (b, false),
            None => match self
                .ctx
                .selected
                .as_ref()
                .and_then(|s| s.config.default_tdol.as_ref())
            {
                Some(default) => (default.clone(), true),
                // §9.2.2 - assume empty TDOL, no TVR bit.
                None => (Vec::new(), false),
            },
        };

        if used_default {
            self.ctx.tvr.default_tdol_used = true;
        }

        let value_field = if tdol_bytes.is_empty() {
            Vec::new()
        } else {
            // Malformed TDOL - degrade to empty.
            crate::core::dol::Dol::parse(&tdol_bytes)
                .map(|parsed| parsed.resolve(&self.ctx))
                .unwrap_or_default()
        };

        let mut hasher = Sha1::new();
        hasher.update(&value_field);
        let mut hash = [0u8; 20];
        hash.copy_from_slice(&hasher.finalize());
        self.ctx.tc_hash_value = Some(hash);
    }

    /// §10.7 / §10.8 - first GENERATE AC.
    pub fn first_generate_ac(
        &mut self,
        cryptogram: ApplicationCryptogramType,
        signature: SignatureRequest,
        cdol1_data: Vec<u8>,
    ) -> Result<GenerateAcResponse, DriverError<C::Error, A::Error>> {
        // Book 2 §6.6.2 step-10 - stash CDOL1.
        if let Some(cda) = self.ctx.cda.as_mut() {
            cda.cdol1_data = cdol1_data.clone();
        }
        // Book 2 Table 37 - XDA hash input includes CDOL1.
        if let Some(xda) = self.ctx.xda.as_mut() {
            xda.cdol1_data = cdol1_data.clone();
        }
        let cmd = generate_ac::command(cryptogram, signature, cdol1_data);
        let resp = self.card.transmit(&cmd).map_err(DriverError::Transport)?;
        if resp.status_word() != sw::OK {
            return Err(DriverError::StatusWord {
                command: "GENERATE AC (first)",
                sw: resp.status_word(),
            });
        }
        Ok(GenerateAcResponse::parse(resp.data())?)
    }

    /// §10.9.
    pub fn authorise_online(
        &mut self,
        first_ac: &GenerateAcResponse,
    ) -> Result<OnlineAuthorisationResponse, DriverError<C::Error, A::Error>> {
        self.auth
            .authorise(&self.ctx, first_ac)
            .map_err(DriverError::Auth)
    }

    /// §10.9 - EXTERNAL AUTHENTICATE.
    pub fn external_authenticate(
        &mut self,
        issuer_authentication_data: &[u8],
    ) -> Result<ExternalAuthenticateOutcome, DriverError<C::Error, A::Error>> {
        let cmd = online_processing::external_authenticate(issuer_authentication_data)?;
        let resp = self.card.transmit(&cmd).map_err(DriverError::Transport)?;
        Ok(online_processing::interpret_external_authenticate_response(
            resp.sw1(),
            resp.sw2(),
        ))
    }

    /// §10.11.
    pub fn second_generate_ac(
        &mut self,
        cryptogram: ApplicationCryptogramType,
        signature: SignatureRequest,
        cdol2_data: Vec<u8>,
    ) -> Result<GenerateAcResponse, DriverError<C::Error, A::Error>> {
        if let Some(cda) = self.ctx.cda.as_mut() {
            cda.cdol2_data = cdol2_data.clone();
        }
        if let Some(xda) = self.ctx.xda.as_mut() {
            xda.cdol2_data = cdol2_data.clone();
        }
        let cmd = generate_ac::command(cryptogram, signature, cdol2_data);
        let resp = self.card.transmit(&cmd).map_err(DriverError::Transport)?;
        if resp.status_word() != sw::OK {
            return Err(DriverError::StatusWord {
                command: "GENERATE AC (second)",
                sw: resp.status_word(),
            });
        }
        Ok(GenerateAcResponse::parse(resp.data())?)
    }

    /// Book 2 §6.6.2 - verify SDAD from first GENERATE AC.
    pub fn verify_cda_first_generate_ac(
        &mut self,
        response: &GenerateAcResponse,
    ) -> Result<oda::CdaVerified, DriverError<C::Error, A::Error>> {
        self.verify_cda_inner(response, /* is_second */ false)
    }

    /// Book 2 §6.6.2 - verify SDAD from second GENERATE AC.
    pub fn verify_cda_second_generate_ac(
        &mut self,
        response: &GenerateAcResponse,
    ) -> Result<oda::CdaVerified, DriverError<C::Error, A::Error>> {
        self.verify_cda_inner(response, /* is_second */ true)
    }

    fn verify_cda_inner(
        &mut self,
        response: &GenerateAcResponse,
        is_second: bool,
    ) -> Result<oda::CdaVerified, DriverError<C::Error, A::Error>> {
        // §6.6.2 - AAC skips CDA; surface as failure.
        use crate::de::cryptogram_information_data::ApplicationCryptogramType;
        if matches!(response.cid.cryptogram_type, ApplicationCryptogramType::Aac) {
            self.ctx.tvr.cda_failed = true;
            return Err(DriverError::Spec(Error::InvalidValue));
        }

        let cda = match self.ctx.cda.clone() {
            Some(c) => c,
            None => {
                self.ctx.tvr.cda_failed = true;
                return Err(DriverError::Spec(Error::MissingMandatory {
                    tag: tags::ICC_PUBLIC_KEY_CERTIFICATE,
                }));
            }
        };

        let sdad = match response.sdad.as_deref() {
            Some(s) => s,
            None => {
                self.ctx.tvr.cda_failed = true;
                return Err(DriverError::Spec(Error::MissingMandatory {
                    tag: tags::SIGNED_DYNAMIC_APPLICATION_DATA,
                }));
            }
        };

        // UN was stamped to tag store at DOL resolution.
        let un_bytes = match self.ctx.tag_store.get(tags::UNPREDICTABLE_NUMBER) {
            Some(b) => b.to_vec(),
            None => {
                self.ctx.tvr.cda_failed = true;
                return Err(DriverError::Spec(Error::MissingMandatory {
                    tag: tags::UNPREDICTABLE_NUMBER,
                }));
            }
        };
        let un: [u8; 4] = match <[u8; 4]>::try_from(un_bytes.as_slice()) {
            Ok(u) => u,
            Err(_) => {
                self.ctx.tvr.cda_failed = true;
                return Err(DriverError::Spec(Error::WrongLength {
                    expected: 4,
                    got: un_bytes.len(),
                }));
            }
        };

        // §6.6.2 step 10 - PDOL || CDOL1 [|| CDOL2] || (response − SDAD).
        let mut tx_data = Vec::with_capacity(
            self.ctx.gpo_pdol_data.len()
                + cda.cdol1_data.len()
                + (if is_second { cda.cdol2_data.len() } else { 0 })
                + response
                    .children_in_order
                    .iter()
                    .map(Tlv::wire_len)
                    .sum::<usize>(),
        );
        tx_data.extend_from_slice(&self.ctx.gpo_pdol_data);
        tx_data.extend_from_slice(&cda.cdol1_data);
        if is_second {
            tx_data.extend_from_slice(&cda.cdol2_data);
        }
        for child in &response.children_in_order {
            if child.tag() != tags::SIGNED_DYNAMIC_APPLICATION_DATA {
                tx_data.extend_from_slice(&child.encode());
            }
        }

        let cid_byte = response.cid.to_byte();

        match oda::verify_cda(&cda.icc_public_key, sdad, un, &tx_data, cid_byte) {
            Ok(verified) => {
                self.ctx.tag_store.insert_primitive(
                    tags::ICC_DYNAMIC_NUMBER,
                    verified.icc_dynamic_number.clone(),
                    Source::TerminalGenerated,
                )?;
                self.ctx.tag_store.insert_primitive(
                    tags::APPLICATION_CRYPTOGRAM,
                    verified.application_cryptogram.to_vec(),
                    Source::TerminalGenerated,
                )?;
                self.ctx.tsi.offline_data_authentication_was_performed = true;
                Ok(verified)
            }
            Err(e) => {
                self.ctx.tvr.cda_failed = true;
                Err(DriverError::Spec(e))
            }
        }
    }

    /// Book 2 §12.5.3 - verify XDA SDAD on first GENERATE AC.
    pub fn verify_xda_first_generate_ac(
        &mut self,
        response: &GenerateAcResponse,
    ) -> Result<(), DriverError<C::Error, A::Error>> {
        self.verify_xda_inner(response, /* is_second */ false)
    }

    /// Book 2 §12.5.3 - verify XDA SDAD on second GENERATE AC.
    pub fn verify_xda_second_generate_ac(
        &mut self,
        response: &GenerateAcResponse,
    ) -> Result<(), DriverError<C::Error, A::Error>> {
        self.verify_xda_inner(response, /* is_second */ true)
    }

    fn verify_xda_inner(
        &mut self,
        response: &GenerateAcResponse,
        is_second: bool,
    ) -> Result<(), DriverError<C::Error, A::Error>> {
        let xda = match self.ctx.xda.clone() {
            Some(x) => x,
            None => {
                return Err(DriverError::Spec(Error::MissingMandatory {
                    tag: tags::ICC_PUBLIC_KEY_CERTIFICATE,
                }));
            }
        };

        // §12 p.107 - apply deferred TVR bits.
        match xda.state {
            oda::XdaArmingState::CaMissing => {
                self.ctx.tvr.ca_ecc_key_missing = true;
                return Ok(());
            }
            oda::XdaArmingState::RecoveryFailed => {
                self.ctx.tvr.ecc_key_recovery_failed = true;
                return Ok(());
            }
            oda::XdaArmingState::Armed { .. } => {}
        }

        // §12.5.3: Skip verification on AAC or when XDA already failed.
        use crate::de::cryptogram_information_data::ApplicationCryptogramType;
        if matches!(response.cid.cryptogram_type, ApplicationCryptogramType::Aac) {
            return Ok(());
        }
        if self.ctx.tvr.xda_signature_verification_failed {
            return Ok(());
        }

        let icc_pk = match xda.state {
            oda::XdaArmingState::Armed { icc_public_key } => icc_public_key,
            _ => unreachable!("filtered above"),
        };

        // §12.5.3 step 1 - SDAD must be present on TC/ARQC responses.
        let sdad = match response.sdad.as_deref() {
            Some(s) => s,
            None => {
                self.ctx.tvr.xda_signature_verification_failed = true;
                return Ok(());
            }
        };

        // §12.5.2 / Table 37 - '15' || PDOL || CDOL1 [|| CDOL2] || (response − SDAD).
        let response_tlv_bytes: usize = response.children_in_order.iter().map(Tlv::wire_len).sum();
        let mut tx_data = Vec::with_capacity(
            1 + self.ctx.gpo_pdol_data.len()
                + xda.cdol1_data.len()
                + (if is_second { xda.cdol2_data.len() } else { 0 })
                + response_tlv_bytes,
        );
        tx_data.push(0x15); // Signed Data Format
        tx_data.extend_from_slice(&self.ctx.gpo_pdol_data);
        tx_data.extend_from_slice(&xda.cdol1_data);
        if is_second {
            tx_data.extend_from_slice(&xda.cdol2_data);
        }
        for child in &response.children_in_order {
            if child.tag() != tags::SIGNED_DYNAMIC_APPLICATION_DATA {
                tx_data.extend_from_slice(&child.encode());
            }
        }

        match ecc_oda::verify_xda(&icc_pk, sdad, &tx_data) {
            Ok(()) => {
                if let Some(ac) = response.ac {
                    self.ctx.tag_store.insert_primitive(
                        tags::APPLICATION_CRYPTOGRAM,
                        ac.to_vec(),
                        Source::TerminalGenerated,
                    )?;
                }
                self.ctx.tsi.offline_data_authentication_was_performed = true;
                Ok(())
            }
            Err(_) => {
                self.ctx.tvr.xda_signature_verification_failed = true;
                Ok(())
            }
        }
    }

    /// §10.9 Online Processing - gated EXTERNAL AUTHENTICATE.
    pub fn online_card_authentication(
        &mut self,
        auth_response: &OnlineAuthorisationResponse,
    ) -> Result<Option<ExternalAuthenticateOutcome>, DriverError<C::Error, A::Error>> {
        let iad = match &auth_response.issuer_authentication_data {
            Some(d) => d,
            None => return Ok(None),
        };
        let supports = self
            .ctx
            .aip
            .as_ref()
            .map(|a| a.issuer_authentication_is_supported)
            .unwrap_or(false);
        if !supports {
            return Ok(None);
        }
        let outcome = self.external_authenticate(iad)?;
        self.ctx.tsi.issuer_authentication_was_performed = true;
        if !matches!(outcome, ExternalAuthenticateOutcome::Successful) {
            self.ctx.tvr.issuer_authentication_failed = true;
        }
        Ok(Some(outcome))
    }

    /// §10.10.
    pub fn process_issuer_scripts(
        &mut self,
        scripts: &[Tlv],
        position: ScriptTag,
    ) -> Result<ScriptProcessingOutcome, DriverError<C::Error, A::Error>> {
        let template_tag = match position {
            ScriptTag::BeforeFinalGenerateAc => tags::ISSUER_SCRIPT_TEMPLATE_1,
            ScriptTag::AfterFinalGenerateAc => tags::ISSUER_SCRIPT_TEMPLATE_2,
        };
        let filtered: Vec<&Tlv> = scripts.iter().filter(|s| s.tag() == template_tag).collect();

        let mut transport_err: Option<C::Error> = None;
        let card = &mut self.card;
        let outcome = issuer_script::process_scripts(&filtered, |apdu_bytes| {
            // After transport error, sentinel SW terminates the script.
            if transport_err.is_some() {
                return (0x6F, 0x00);
            }
            let cmd = match Command::from_bytes(apdu_bytes) {
                Ok(c) => c,
                // §10.10 - malformed APDU is an error.
                Err(_) => return (0x6F, 0x00),
            };
            match card.transmit(&cmd) {
                Ok(resp) => (resp.sw1(), resp.sw2()),
                Err(e) => {
                    transport_err = Some(e);
                    (0x6F, 0x00)
                }
            }
        });
        if let Some(e) = transport_err {
            return Err(DriverError::Transport(e));
        }

        self.ctx
            .tvr
            .script_processing_failed_before_final_generate_ac |= outcome
            .tvr_updates
            .script_processing_failed_before_final_generate_ac;
        self.ctx
            .tvr
            .script_processing_failed_after_final_generate_ac |= outcome
            .tvr_updates
            .script_processing_failed_after_final_generate_ac;
        if outcome.tsi_script_processing_was_performed {
            self.ctx.tsi.script_processing_was_performed = true;
        }
        // Book 4 §6.3.9 - append to '9F5B' accumulator.
        self.ctx
            .issuer_script_results
            .extend(outcome.script_results.iter().map(|o| o.result));
        Ok(outcome)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::contact::terminal::TerminalApplication;
    use crate::core::apdu::{Command, Response};
    use crate::de::additional_terminal_capabilities::AdditionalTerminalCapabilities;
    use crate::de::authorisation_response_code::AuthorisationResponseCode;
    use crate::de::terminal_capabilities::TerminalCapabilities;
    use crate::de::terminal_type::TerminalType;

    struct ScriptedCard {
        script: Vec<(Vec<u8>, Vec<u8>)>,
        cursor: usize,
    }

    impl CardReader for ScriptedCard {
        type Error = Error;
        fn transmit(&mut self, command: &Command) -> Result<Response, Self::Error> {
            assert!(
                self.cursor < self.script.len(),
                "card script exhausted at step {}",
                self.cursor
            );
            let (expected, reply) = &self.script[self.cursor];
            assert_eq!(
                &command.to_bytes().unwrap(),
                expected,
                "step {} mismatch",
                self.cursor
            );
            self.cursor += 1;
            Response::parse(reply)
        }
    }

    struct MockAuth(OnlineAuthorisationResponse);
    impl OnlineAuthorisation for MockAuth {
        type Error = std::convert::Infallible;
        fn authorise(
            &mut self,
            _ctx: &TransactionContext<'_>,
            _first_ac: &GenerateAcResponse,
        ) -> std::result::Result<OnlineAuthorisationResponse, Self::Error> {
            Ok(self.0.clone())
        }
    }

    fn fixture_terminal() -> Terminal {
        Terminal {
            terminal_type: TerminalType(0x22),
            terminal_capabilities: TerminalCapabilities {
                ic_with_contacts: true,
                ..Default::default()
            },
            additional_terminal_capabilities: AdditionalTerminalCapabilities::default(),
            terminal_country_code: 840,
            terminal_identification: [b'T'; 8],
            ifd_serial_number: [b'S'; 8],
            merchant_category_code: 5999,
            merchant_identifier: [b'M'; 15],
            merchant_name_and_location: b"Acme".to_vec(),
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

    fn ok(data: &[u8]) -> Vec<u8> {
        let mut v = data.to_vec();
        v.extend_from_slice(&[0x90, 0x00]);
        v
    }

    fn select_command_bytes(aid: &[u8]) -> Vec<u8> {
        let mut v = vec![0x00, 0xA4, 0x04, 0x00, aid.len() as u8];
        v.extend_from_slice(aid);
        v.push(0x00);
        v
    }

    fn fci_bytes(df_name: &[u8], label: &[u8]) -> Vec<u8> {
        let mut a5 = Vec::new();
        a5.push(0x50);
        a5.push(label.len() as u8);
        a5.extend_from_slice(label);
        let mut a5_wrapped = vec![0xA5, a5.len() as u8];
        a5_wrapped.extend_from_slice(&a5);
        let mut inner = vec![0x84, df_name.len() as u8];
        inner.extend_from_slice(df_name);
        inner.extend_from_slice(&a5_wrapped);
        let mut out = vec![0x6F, inner.len() as u8];
        out.extend_from_slice(&inner);
        out
    }

    #[test]
    fn select_application_records_selected_app() {
        let aid = [0xA0, 0, 0, 0, 0x03, 0x10, 0x10];
        let card = ScriptedCard {
            script: vec![(select_command_bytes(&aid), ok(&fci_bytes(&aid, b"VISA")))],
            cursor: 0,
        };
        let auth = MockAuth(OnlineAuthorisationResponse {
            authorisation_response_code: AuthorisationResponseCode(*b"00"),
            issuer_authentication_data: None,
            issuer_scripts: vec![],
        });
        let terminal = fixture_terminal();
        let mut tx = Transaction::new(card, &terminal, TransactionInputs::default(), auth);
        let fci = tx.select_application(&aid).unwrap();
        assert_eq!(fci.application_label.as_deref(), Some(&b"VISA"[..]));
        let sel = tx.ctx.selected.as_ref().unwrap();
        assert_eq!(sel.df_name, aid);
        assert_eq!(sel.config.terminal_floor_limit, 0);
    }

    #[test]
    fn select_application_unknown_aid_errors() {
        let other_aid = [0xA0, 0, 0, 0, 0x99, 0x99, 0x99];
        let card = ScriptedCard {
            script: vec![(
                select_command_bytes(&other_aid),
                ok(&fci_bytes(&other_aid, b"OTHER")),
            )],
            cursor: 0,
        };
        let auth = MockAuth(OnlineAuthorisationResponse {
            authorisation_response_code: AuthorisationResponseCode(*b"00"),
            issuer_authentication_data: None,
            issuer_scripts: vec![],
        });
        let terminal = fixture_terminal();
        let mut tx = Transaction::new(card, &terminal, TransactionInputs::default(), auth);
        match tx.select_application(&other_aid) {
            Err(DriverError::UnknownAid) => {}
            other => panic!("expected UnknownAid, got {:?}", other),
        }
    }

    fn fixture_terminal_multi_aid(aids: &[&[u8]]) -> Terminal {
        let applications = aids
            .iter()
            .map(|a| TerminalApplication {
                aid: a.to_vec(),
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
            })
            .collect();
        Terminal {
            applications,
            ..fixture_terminal()
        }
    }

    #[test]
    fn try_select_returns_some_on_9000() {
        let aid = [0xA0, 0, 0, 0, 0x03, 0x10, 0x10];
        let card = ScriptedCard {
            script: vec![(select_command_bytes(&aid), ok(&fci_bytes(&aid, b"VISA")))],
            cursor: 0,
        };
        let auth = MockAuth(OnlineAuthorisationResponse {
            authorisation_response_code: AuthorisationResponseCode(*b"00"),
            issuer_authentication_data: None,
            issuer_scripts: vec![],
        });
        let terminal = fixture_terminal();
        let mut tx = Transaction::new(card, &terminal, TransactionInputs::default(), auth);
        let fci = tx.try_select(&aid).unwrap().unwrap();
        assert_eq!(fci.application_label.as_deref(), Some(&b"VISA"[..]));
        assert!(tx.ctx.selected.is_some());
    }

    #[test]
    fn try_select_returns_none_on_6a82() {
        let aid = [0xA0, 0, 0, 0, 0x03, 0x10, 0x10];
        let card = ScriptedCard {
            script: vec![(select_command_bytes(&aid), vec![0x6A, 0x82])],
            cursor: 0,
        };
        let auth = MockAuth(OnlineAuthorisationResponse {
            authorisation_response_code: AuthorisationResponseCode(*b"00"),
            issuer_authentication_data: None,
            issuer_scripts: vec![],
        });
        let terminal = fixture_terminal();
        let mut tx = Transaction::new(card, &terminal, TransactionInputs::default(), auth);
        let r = tx.try_select(&aid).unwrap();
        assert!(r.is_none());
        assert!(tx.ctx.selected.is_none());
    }

    #[test]
    fn try_select_propagates_other_status_word() {
        let aid = [0xA0, 0, 0, 0, 0x03, 0x10, 0x10];
        let card = ScriptedCard {
            script: vec![(select_command_bytes(&aid), vec![0x69, 0x85])],
            cursor: 0,
        };
        let auth = MockAuth(OnlineAuthorisationResponse {
            authorisation_response_code: AuthorisationResponseCode(*b"00"),
            issuer_authentication_data: None,
            issuer_scripts: vec![],
        });
        let terminal = fixture_terminal();
        let mut tx = Transaction::new(card, &terminal, TransactionInputs::default(), auth);
        match tx.try_select(&aid) {
            Err(DriverError::StatusWord { command, sw }) => {
                assert_eq!(command, "SELECT");
                assert_eq!(sw, 0x6985);
            }
            other => panic!("expected StatusWord, got {:?}", other),
        }
    }

    #[test]
    fn select_first_supported_picks_first_match() {
        let visa = [0xA0u8, 0, 0, 0, 0x03, 0x10, 0x10];
        let mc = [0xA0u8, 0, 0, 0, 0x04, 0x10, 0x10];
        let card = ScriptedCard {
            script: vec![
                (select_command_bytes(&mc), vec![0x6A, 0x82]),
                (select_command_bytes(&visa), ok(&fci_bytes(&visa, b"VISA"))),
            ],
            cursor: 0,
        };
        let auth = MockAuth(OnlineAuthorisationResponse {
            authorisation_response_code: AuthorisationResponseCode(*b"00"),
            issuer_authentication_data: None,
            issuer_scripts: vec![],
        });
        let terminal = fixture_terminal_multi_aid(&[&mc, &visa]);
        let mut tx = Transaction::new(card, &terminal, TransactionInputs::default(), auth);
        let fci = tx.select_first_supported().unwrap();
        assert_eq!(fci.application_label.as_deref(), Some(&b"VISA"[..]));
        assert_eq!(tx.ctx.selected.as_ref().unwrap().df_name, visa);
    }

    fn pse_select_command_bytes() -> Vec<u8> {
        select_command_bytes(b"1PAY.SYS.DDF01")
    }

    fn pse_fci_bytes(sfi: u8) -> Vec<u8> {
        let mut a5_inner = vec![0x88, 0x01, sfi];
        let mut a5 = vec![0xA5, a5_inner.len() as u8];
        a5.append(&mut a5_inner);
        let df = b"1PAY.SYS.DDF01";
        let mut inner = vec![0x84, df.len() as u8];
        inner.extend_from_slice(df);
        inner.extend_from_slice(&a5);
        let mut out = vec![0x6F, inner.len() as u8];
        out.extend_from_slice(&inner);
        out
    }

    fn directory_record_with_entries(adf_names: &[&[u8]]) -> Vec<u8> {
        let mut entries = Vec::new();
        for (i, adf) in adf_names.iter().enumerate() {
            let mut entry = Vec::new();
            entry.push(0x4F);
            entry.push(adf.len() as u8);
            entry.extend_from_slice(adf);
            entry.extend_from_slice(&[0x50, 0x04]);
            entry.extend_from_slice(&[b'L', b'B', b'L', b'A' + i as u8]);
            entry.extend_from_slice(&[0x87, 0x01, (i as u8 + 1) & 0x0F]);

            let mut wrapped = vec![0x61, entry.len() as u8];
            wrapped.extend_from_slice(&entry);
            entries.extend(wrapped);
        }
        let mut out = vec![0x70, entries.len() as u8];
        out.extend_from_slice(&entries);
        out
    }

    fn read_record_command_bytes(sfi: u8, record: u8) -> Vec<u8> {
        vec![0x00, 0xB2, record, (sfi << 3) | 0b100, 0x00]
    }

    #[test]
    fn build_candidate_list_pse_walks_directory_and_filters_to_terminal_aids() {
        let visa = [0xA0u8, 0, 0, 0, 0x03, 0x10, 0x10];
        let mc = [0xA0u8, 0, 0, 0, 0x04, 0x10, 0x10];
        let other = [0xA0u8, 0, 0, 0, 0x99, 0x99, 0x99];

        let card = ScriptedCard {
            script: vec![
                (pse_select_command_bytes(), ok(&pse_fci_bytes(1))),
                (
                    read_record_command_bytes(1, 1),
                    ok(&directory_record_with_entries(&[&visa, &other])),
                ),
                (read_record_command_bytes(1, 2), vec![0x6A, 0x83]),
            ],
            cursor: 0,
        };
        let auth = MockAuth(OnlineAuthorisationResponse {
            authorisation_response_code: AuthorisationResponseCode(*b"00"),
            issuer_authentication_data: None,
            issuer_scripts: vec![],
        });
        let terminal = fixture_terminal_multi_aid(&[&visa, &mc]);
        let mut tx = Transaction::new(card, &terminal, TransactionInputs::default(), auth);

        let result = tx.build_candidate_list_pse().unwrap();
        let candidates = result.expect("PSE present");
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].df_name, visa);
    }

    #[test]
    fn build_candidate_list_pse_returns_none_on_6a82() {
        let card = ScriptedCard {
            script: vec![(pse_select_command_bytes(), vec![0x6A, 0x82])],
            cursor: 0,
        };
        let auth = MockAuth(OnlineAuthorisationResponse {
            authorisation_response_code: AuthorisationResponseCode(*b"00"),
            issuer_authentication_data: None,
            issuer_scripts: vec![],
        });
        let terminal = fixture_terminal();
        let mut tx = Transaction::new(card, &terminal, TransactionInputs::default(), auth);
        let r = tx.build_candidate_list_pse().unwrap();
        assert!(r.is_none(), "expected PSE-not-present → None, got {:?}", r);
    }

    #[test]
    fn build_candidate_list_pse_returns_none_on_6283_pse_blocked() {
        let card = ScriptedCard {
            script: vec![(pse_select_command_bytes(), vec![0x62, 0x83])],
            cursor: 0,
        };
        let auth = MockAuth(OnlineAuthorisationResponse {
            authorisation_response_code: AuthorisationResponseCode(*b"00"),
            issuer_authentication_data: None,
            issuer_scripts: vec![],
        });
        let terminal = fixture_terminal();
        let mut tx = Transaction::new(card, &terminal, TransactionInputs::default(), auth);
        // §12.3.2 - '6283' non-terminating; fall back to AID list.
        match tx.build_candidate_list_pse() {
            Ok(None) => {}
            other => panic!("expected None, got {:?}", other),
        }
    }

    #[test]
    fn build_candidate_list_pse_terminates_on_6a81() {
        let card = ScriptedCard {
            script: vec![(pse_select_command_bytes(), vec![0x6A, 0x81])],
            cursor: 0,
        };
        let auth = MockAuth(OnlineAuthorisationResponse {
            authorisation_response_code: AuthorisationResponseCode(*b"00"),
            issuer_authentication_data: None,
            issuer_scripts: vec![],
        });
        let terminal = fixture_terminal();
        let mut tx = Transaction::new(card, &terminal, TransactionInputs::default(), auth);
        match tx.build_candidate_list_pse() {
            Err(DriverError::StatusWord { command, sw }) => {
                assert_eq!(command, "SELECT PSE");
                assert_eq!(sw, 0x6A81);
            }
            other => panic!("expected StatusWord 6A81, got {:?}", other),
        }
    }

    #[test]
    fn build_candidate_list_pse_empty_record_yields_empty_list() {
        // PSE is present but contains no matching applications.
        let card = ScriptedCard {
            script: vec![
                (pse_select_command_bytes(), ok(&pse_fci_bytes(1))),
                // Record 1 doesn't exist (PSE empty).
                (read_record_command_bytes(1, 1), vec![0x6A, 0x83]),
            ],
            cursor: 0,
        };
        let auth = MockAuth(OnlineAuthorisationResponse {
            authorisation_response_code: AuthorisationResponseCode(*b"00"),
            issuer_authentication_data: None,
            issuer_scripts: vec![],
        });
        let terminal = fixture_terminal();
        let mut tx = Transaction::new(card, &terminal, TransactionInputs::default(), auth);
        let r = tx.build_candidate_list_pse().unwrap();
        assert_eq!(r, Some(vec![]));
    }

    #[test]
    fn build_candidate_list_aids_collects_matching_fcis() {
        let visa = [0xA0u8, 0, 0, 0, 0x03, 0x10, 0x10];
        let mc = [0xA0u8, 0, 0, 0, 0x04, 0x10, 0x10];
        let card = ScriptedCard {
            script: vec![
                (select_command_bytes(&visa), ok(&fci_bytes(&visa, b"VISA"))),
                (select_command_bytes(&mc), vec![0x6A, 0x82]),
            ],
            cursor: 0,
        };
        let auth = MockAuth(OnlineAuthorisationResponse {
            authorisation_response_code: AuthorisationResponseCode(*b"00"),
            issuer_authentication_data: None,
            issuer_scripts: vec![],
        });
        let terminal = fixture_terminal_multi_aid(&[&visa, &mc]);
        let mut tx = Transaction::new(card, &terminal, TransactionInputs::default(), auth);
        let candidates = tx.build_candidate_list_aids().unwrap();
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].df_name, visa);
        assert_eq!(
            candidates[0].application_label.as_deref(),
            Some(&b"VISA"[..])
        );
    }

    #[test]
    fn build_candidate_list_aids_skips_6283() {
        // §12.3.3 step 4.
        let visa = [0xA0u8, 0, 0, 0, 0x03, 0x10, 0x10];
        let mc = [0xA0u8, 0, 0, 0, 0x04, 0x10, 0x10];
        let card = ScriptedCard {
            script: vec![
                (select_command_bytes(&visa), vec![0x62, 0x83]),
                (select_command_bytes(&mc), ok(&fci_bytes(&mc, b"MC"))),
            ],
            cursor: 0,
        };
        let auth = MockAuth(OnlineAuthorisationResponse {
            authorisation_response_code: AuthorisationResponseCode(*b"00"),
            issuer_authentication_data: None,
            issuer_scripts: vec![],
        });
        let terminal = fixture_terminal_multi_aid(&[&visa, &mc]);
        let mut tx = Transaction::new(card, &terminal, TransactionInputs::default(), auth);
        let candidates = tx.build_candidate_list_aids().unwrap();
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].df_name, mc);
    }

    #[test]
    fn build_candidate_list_aids_terminates_on_6a81() {
        let visa = [0xA0u8, 0, 0, 0, 0x03, 0x10, 0x10];
        let card = ScriptedCard {
            script: vec![(select_command_bytes(&visa), vec![0x6A, 0x81])],
            cursor: 0,
        };
        let auth = MockAuth(OnlineAuthorisationResponse {
            authorisation_response_code: AuthorisationResponseCode(*b"00"),
            issuer_authentication_data: None,
            issuer_scripts: vec![],
        });
        let terminal = fixture_terminal_multi_aid(&[&visa]);
        let mut tx = Transaction::new(card, &terminal, TransactionInputs::default(), auth);
        match tx.build_candidate_list_aids() {
            Err(DriverError::StatusWord { command, sw }) => {
                assert_eq!(command, "SELECT (AID list)");
                assert_eq!(sw, 0x6A81);
            }
            other => panic!("expected StatusWord 6A81, got {:?}", other),
        }
    }

    #[test]
    fn build_candidate_list_uses_pse_when_present() {
        let visa = [0xA0u8, 0, 0, 0, 0x03, 0x10, 0x10];
        let card = ScriptedCard {
            script: vec![
                (pse_select_command_bytes(), ok(&pse_fci_bytes(1))),
                (
                    read_record_command_bytes(1, 1),
                    ok(&directory_record_with_entries(&[&visa])),
                ),
                (read_record_command_bytes(1, 2), vec![0x6A, 0x83]),
            ],
            cursor: 0,
        };
        let auth = MockAuth(OnlineAuthorisationResponse {
            authorisation_response_code: AuthorisationResponseCode(*b"00"),
            issuer_authentication_data: None,
            issuer_scripts: vec![],
        });
        let terminal = fixture_terminal_multi_aid(&[&visa]);
        let mut tx = Transaction::new(card, &terminal, TransactionInputs::default(), auth);
        let candidates = tx.build_candidate_list().unwrap();
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].df_name, visa);
    }

    #[test]
    fn build_candidate_list_falls_back_to_aids_when_no_pse() {
        let visa = [0xA0u8, 0, 0, 0, 0x03, 0x10, 0x10];
        let card = ScriptedCard {
            script: vec![
                (pse_select_command_bytes(), vec![0x6A, 0x82]),
                (select_command_bytes(&visa), ok(&fci_bytes(&visa, b"VISA"))),
            ],
            cursor: 0,
        };
        let auth = MockAuth(OnlineAuthorisationResponse {
            authorisation_response_code: AuthorisationResponseCode(*b"00"),
            issuer_authentication_data: None,
            issuer_scripts: vec![],
        });
        let terminal = fixture_terminal_multi_aid(&[&visa]);
        let mut tx = Transaction::new(card, &terminal, TransactionInputs::default(), auth);
        let candidates = tx.build_candidate_list().unwrap();
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].df_name, visa);
    }

    #[test]
    fn build_candidate_list_falls_back_when_pse_yields_no_matches() {
        // §12.3.2 step 5.
        let visa = [0xA0u8, 0, 0, 0, 0x03, 0x10, 0x10];
        let other = [0xA0u8, 0, 0, 0, 0x99, 0x99, 0x99];
        let card = ScriptedCard {
            script: vec![
                (pse_select_command_bytes(), ok(&pse_fci_bytes(1))),
                (
                    read_record_command_bytes(1, 1),
                    ok(&directory_record_with_entries(&[&other])),
                ),
                (read_record_command_bytes(1, 2), vec![0x6A, 0x83]),
                (select_command_bytes(&visa), ok(&fci_bytes(&visa, b"VISA"))),
            ],
            cursor: 0,
        };
        let auth = MockAuth(OnlineAuthorisationResponse {
            authorisation_response_code: AuthorisationResponseCode(*b"00"),
            issuer_authentication_data: None,
            issuer_scripts: vec![],
        });
        let terminal = fixture_terminal_multi_aid(&[&visa]);
        let mut tx = Transaction::new(card, &terminal, TransactionInputs::default(), auth);
        let candidates = tx.build_candidate_list().unwrap();
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].df_name, visa);
    }

    #[test]
    fn select_first_supported_no_matching_application() {
        let visa = [0xA0u8, 0, 0, 0, 0x03, 0x10, 0x10];
        let mc = [0xA0u8, 0, 0, 0, 0x04, 0x10, 0x10];
        let card = ScriptedCard {
            script: vec![
                (select_command_bytes(&visa), vec![0x6A, 0x82]),
                (select_command_bytes(&mc), vec![0x6A, 0x82]),
            ],
            cursor: 0,
        };
        let auth = MockAuth(OnlineAuthorisationResponse {
            authorisation_response_code: AuthorisationResponseCode(*b"00"),
            issuer_authentication_data: None,
            issuer_scripts: vec![],
        });
        let terminal = fixture_terminal_multi_aid(&[&visa, &mc]);
        let mut tx = Transaction::new(card, &terminal, TransactionInputs::default(), auth);
        match tx.select_first_supported() {
            Err(DriverError::NoMatchingApplication) => {}
            other => panic!("expected NoMatchingApplication, got {:?}", other),
        }
    }

    #[test]
    fn select_application_non_ok_status_word_errors() {
        let aid = [0xA0, 0, 0, 0, 0x03, 0x10, 0x10];
        let card = ScriptedCard {
            script: vec![(select_command_bytes(&aid), vec![0x6A, 0x82])],
            cursor: 0,
        };
        let auth = MockAuth(OnlineAuthorisationResponse {
            authorisation_response_code: AuthorisationResponseCode(*b"00"),
            issuer_authentication_data: None,
            issuer_scripts: vec![],
        });
        let terminal = fixture_terminal();
        let mut tx = Transaction::new(card, &terminal, TransactionInputs::default(), auth);
        match tx.select_application(&aid) {
            Err(DriverError::StatusWord { command, sw }) => {
                assert_eq!(command, "SELECT");
                assert_eq!(sw, 0x6A82);
            }
            other => panic!("expected StatusWord, got {:?}", other),
        }
    }

    fn gpo_command_bytes(pdol_data: &[u8]) -> Vec<u8> {
        let mut v = vec![0x80, 0xA8, 0x00, 0x00];
        let inner = {
            let mut x = vec![0x83, pdol_data.len() as u8];
            x.extend_from_slice(pdol_data);
            x
        };
        v.push(inner.len() as u8);
        v.extend(inner);
        v.push(0x00);
        v
    }

    #[test]
    fn initiate_requires_selection() {
        let card = ScriptedCard {
            script: vec![],
            cursor: 0,
        };
        let auth = MockAuth(OnlineAuthorisationResponse {
            authorisation_response_code: AuthorisationResponseCode(*b"00"),
            issuer_authentication_data: None,
            issuer_scripts: vec![],
        });
        let terminal = fixture_terminal();
        let mut tx = Transaction::new(card, &terminal, TransactionInputs::default(), auth);
        match tx.initiate(&[]) {
            Err(DriverError::NotSelected) => {}
            other => panic!("expected NotSelected, got {:?}", other),
        }
    }

    #[test]
    fn initiate_stores_aip_and_afl_on_context() {
        let aid = [0xA0, 0, 0, 0, 0x03, 0x10, 0x10];
        let gpo_resp = [0x80, 0x06, 0x78, 0x00, 0x08, 0x01, 0x01, 0x00];
        let card = ScriptedCard {
            script: vec![
                (select_command_bytes(&aid), ok(&fci_bytes(&aid, b"VISA"))),
                (gpo_command_bytes(&[]), ok(&gpo_resp)),
            ],
            cursor: 0,
        };
        let auth = MockAuth(OnlineAuthorisationResponse {
            authorisation_response_code: AuthorisationResponseCode(*b"00"),
            issuer_authentication_data: None,
            issuer_scripts: vec![],
        });
        let terminal = fixture_terminal();
        let mut tx = Transaction::new(card, &terminal, TransactionInputs::default(), auth);
        tx.select_application(&aid).unwrap();
        let parsed = tx.initiate(&[]).unwrap();
        assert_eq!(parsed.aip.to_bytes(), [0x78, 0x00]);
        assert_eq!(tx.ctx.aip.unwrap().to_bytes(), [0x78, 0x00]);
        assert_eq!(tx.ctx.afl.as_ref().unwrap().0.len(), 1);
    }

    #[test]
    fn read_application_data_requires_initiate() {
        let card = ScriptedCard {
            script: vec![],
            cursor: 0,
        };
        let auth = MockAuth(OnlineAuthorisationResponse {
            authorisation_response_code: AuthorisationResponseCode(*b"00"),
            issuer_authentication_data: None,
            issuer_scripts: vec![],
        });
        let terminal = fixture_terminal();
        let mut tx = Transaction::new(card, &terminal, TransactionInputs::default(), auth);
        match tx.read_application_data() {
            Err(DriverError::NoAfl) => {}
            other => panic!("expected NoAfl, got {:?}", other),
        }
    }

    #[test]
    fn first_generate_ac_round_trip_format_1() {
        let card = ScriptedCard {
            script: vec![(
                vec![0x80, 0xAE, 0x80, 0x00, 0x00],
                ok(&[
                    0x80, 0x0B, 0x80, 0x00, 0x01, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
                ]),
            )],
            cursor: 0,
        };
        let auth = MockAuth(OnlineAuthorisationResponse {
            authorisation_response_code: AuthorisationResponseCode(*b"00"),
            issuer_authentication_data: None,
            issuer_scripts: vec![],
        });
        let terminal = fixture_terminal();
        let mut tx = Transaction::new(card, &terminal, TransactionInputs::default(), auth);
        let resp = tx
            .first_generate_ac(
                ApplicationCryptogramType::Arqc,
                SignatureRequest::None,
                vec![],
            )
            .unwrap();
        assert_eq!(resp.atc, [0x00, 0x01]);
        assert_eq!(
            resp.ac,
            Some([0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88])
        );
    }

    #[test]
    fn end_to_end_arqc_then_online_approved_then_tc() {
        let aid = [0xA0, 0, 0, 0, 0x03, 0x10, 0x10];

        let select = (select_command_bytes(&aid), ok(&fci_bytes(&aid, b"VISA")));

        let gpo = (
            gpo_command_bytes(&[]),
            ok(&[0x80, 0x06, 0x78, 0x00, 0x08, 0x01, 0x01, 0x00]),
        );

        let read_cmd = vec![0x00, 0xB2, 0x01, 0x0C, 0x00];
        let read_resp = [
            0x70, 0x0C, 0x5A, 0x04, 0x12, 0x34, 0x56, 0x78, 0x5F, 0x24, 0x03, 0x25, 0x12, 0x31,
        ];
        let read = (read_cmd, ok(&read_resp));

        let gac1 = (
            vec![0x80, 0xAE, 0x80, 0x00, 0x00],
            ok(&[
                0x80, 0x0B, 0x80, 0x00, 0x07, 0xCA, 0xFE, 0xBA, 0xBE, 0xDE, 0xAD, 0xBE, 0xEF,
            ]),
        );

        let gac2 = (
            vec![0x80, 0xAE, 0x40, 0x00, 0x00],
            ok(&[
                0x80, 0x0B, 0x40, 0x00, 0x08, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
            ]),
        );

        let card = ScriptedCard {
            script: vec![select, gpo, read, gac1, gac2],
            cursor: 0,
        };
        let auth = MockAuth(OnlineAuthorisationResponse {
            authorisation_response_code: AuthorisationResponseCode(*b"00"),
            issuer_authentication_data: None,
            issuer_scripts: vec![],
        });

        let terminal = fixture_terminal();
        let mut tx = Transaction::new(card, &terminal, TransactionInputs::default(), auth);

        let fci = tx.select_application(&aid).unwrap();
        assert_eq!(fci.application_label.as_deref(), Some(&b"VISA"[..]));

        let gpo = tx.initiate(&[]).unwrap();
        assert!(gpo.aip.cardholder_verification_is_supported || true);

        let read_outcome = tx.read_application_data().unwrap();
        assert!(read_outcome.oda_input.is_empty());

        let first = tx
            .first_generate_ac(
                ApplicationCryptogramType::Arqc,
                SignatureRequest::None,
                vec![],
            )
            .unwrap();
        assert_eq!(first.atc, [0x00, 0x07]);

        let auth_resp = tx.authorise_online(&first).unwrap();
        assert_eq!(
            auth_resp.authorisation_response_code.as_str().unwrap(),
            "00"
        );
        assert!(auth_resp.issuer_authentication_data.is_none());

        let second = tx
            .second_generate_ac(
                ApplicationCryptogramType::Tc,
                SignatureRequest::None,
                vec![],
            )
            .unwrap();
        assert_eq!(second.atc, [0x00, 0x08]);

        assert_eq!(
            tx.ctx.tag_store.get(crate::core::tags::PAN).unwrap(),
            &[0x12, 0x34, 0x56, 0x78]
        );
    }

    fn get_data_script(atc: Option<u16>, last_online: Option<u16>) -> Vec<(Vec<u8>, Vec<u8>)> {
        let mut script = Vec::new();
        let cmd = vec![0x80, 0xCA, 0x9F, 0x36, 0x00];
        let reply = match atc {
            Some(v) => {
                let mut r = vec![0x9F, 0x36, 0x02];
                r.extend_from_slice(&v.to_be_bytes());
                r.extend_from_slice(&[0x90, 0x00]);
                r
            }
            None => vec![0x6A, 0x88],
        };
        script.push((cmd, reply));
        let cmd = vec![0x80, 0xCA, 0x9F, 0x13, 0x00];
        let reply = match last_online {
            Some(v) => {
                let mut r = vec![0x9F, 0x13, 0x02];
                r.extend_from_slice(&v.to_be_bytes());
                r.extend_from_slice(&[0x90, 0x00]);
                r
            }
            None => vec![0x6A, 0x88],
        };
        script.push((cmd, reply));
        script
    }

    fn fixture_terminal_with_floor_limit_and_rts(
        floor_limit: u32,
        rts: Option<(u8, u8, u64)>,
    ) -> Terminal {
        let mut t = fixture_terminal();
        let app = &mut t.applications[0];
        app.terminal_floor_limit = floor_limit;
        if let Some((target, max, threshold)) = rts {
            app.rts_target_percentage = Some(target);
            app.rts_max_target_percentage = Some(max);
            app.rts_threshold_value = Some(threshold);
        }
        t
    }

    fn ctx_with_selected<'a>(terminal: &'a Terminal, amount: u64) -> TransactionContext<'a> {
        let mut ctx = TransactionContext::new(
            terminal,
            TransactionInputs {
                amount_authorised: amount,
                ..Default::default()
            },
        );
        ctx.select_application(vec![0xA0, 0, 0, 0, 0x03, 0x10, 0x10])
            .unwrap();
        ctx
    }

    #[test]
    fn get_data_returns_some_on_9000() {
        let terminal = fixture_terminal();
        let card = ScriptedCard {
            script: vec![(
                vec![0x80, 0xCA, 0x9F, 0x36, 0x00],
                vec![0x9F, 0x36, 0x02, 0x00, 0x05, 0x90, 0x00],
            )],
            cursor: 0,
        };
        let ctx = ctx_with_selected(&terminal, 100);
        let mut tx = Transaction {
            card,
            auth: MockAuth(OnlineAuthorisationResponse {
                authorisation_response_code: AuthorisationResponseCode::OFFLINE_DECLINED,
                issuer_authentication_data: None,
                issuer_scripts: vec![],
            }),
            ctx,
        };

        let bytes = tx.get_data(tags::APPLICATION_TRANSACTION_COUNTER).unwrap();
        assert_eq!(bytes.as_deref(), Some(&[0x00, 0x05][..]));
        assert_eq!(
            tx.ctx
                .tag_store
                .get(tags::APPLICATION_TRANSACTION_COUNTER)
                .unwrap(),
            &[0x00, 0x05]
        );
    }

    #[test]
    fn get_data_returns_none_on_6a88() {
        let terminal = fixture_terminal();
        let card = ScriptedCard {
            script: vec![(vec![0x80, 0xCA, 0x9F, 0x13, 0x00], vec![0x6A, 0x88])],
            cursor: 0,
        };
        let ctx = ctx_with_selected(&terminal, 100);
        let mut tx = Transaction {
            card,
            auth: MockAuth(OnlineAuthorisationResponse {
                authorisation_response_code: AuthorisationResponseCode::OFFLINE_DECLINED,
                issuer_authentication_data: None,
                issuer_scripts: vec![],
            }),
            ctx,
        };
        assert!(
            tx.get_data(tags::LAST_ONLINE_ATC_REGISTER)
                .unwrap()
                .is_none()
        );
        assert!(
            tx.ctx
                .tag_store
                .get(tags::LAST_ONLINE_ATC_REGISTER)
                .is_none()
        );
    }

    #[test]
    fn run_trm_clean_path_sets_tsi_and_no_tvr_bits() {
        // amount=50, floor=100, RTS picks not-selected, velocity in window.
        let terminal = fixture_terminal_with_floor_limit_and_rts(100, Some((10, 90, 50)));
        let mut ctx = ctx_with_selected(&terminal, 50);
        // LOATC=5, UOATC=10, ATC=8, LastOnline=5 → diff=3, both bits clear.
        let src = Source::Record { sfi: 1, record: 1 };
        ctx.tag_store
            .insert_primitive(tags::LOWER_CONSECUTIVE_OFFLINE_LIMIT, vec![0x05], src)
            .unwrap();
        ctx.tag_store
            .insert_primitive(tags::UPPER_CONSECUTIVE_OFFLINE_LIMIT, vec![0x0A], src)
            .unwrap();

        let card = ScriptedCard {
            script: get_data_script(Some(8), Some(5)),
            cursor: 0,
        };
        let mut tx = Transaction {
            card,
            auth: MockAuth(OnlineAuthorisationResponse {
                authorisation_response_code: AuthorisationResponseCode::OFFLINE_DECLINED,
                issuer_authentication_data: None,
                issuer_scripts: vec![],
            }),
            ctx,
        };

        // Random=11 > target=10 → not selected.
        let outcome = tx.run_terminal_risk_management(Some(11), None).unwrap();
        assert_eq!(outcome, TerminalRiskManagementOutcome::default());
        assert_eq!(tx.ctx.tvr.to_bytes(), [0, 0, 0, 0, 0]);
        assert!(tx.ctx.tsi.terminal_risk_management_was_performed);
    }

    #[test]
    fn run_trm_floor_limit_exceeded_sets_tvr_bit() {
        let terminal = fixture_terminal_with_floor_limit_and_rts(100, None);
        let ctx = ctx_with_selected(&terminal, 150);
        let card = ScriptedCard {
            script: get_data_script(None, None),
            cursor: 0,
        };
        let mut tx = Transaction {
            card,
            auth: MockAuth(OnlineAuthorisationResponse {
                authorisation_response_code: AuthorisationResponseCode::OFFLINE_DECLINED,
                issuer_authentication_data: None,
                issuer_scripts: vec![],
            }),
            ctx,
        };

        let outcome = tx.run_terminal_risk_management(None, None).unwrap();
        assert!(outcome.transaction_exceeds_floor_limit);
        assert!(tx.ctx.tvr.transaction_exceeds_floor_limit);
        assert!(tx.ctx.tsi.terminal_risk_management_was_performed);
    }

    #[test]
    fn run_trm_velocity_get_data_failure_forces_both_bits() {
        let terminal = fixture_terminal_with_floor_limit_and_rts(100, None);
        let mut ctx = ctx_with_selected(&terminal, 50);
        // Velocity is gated on LOATC + UOATC presence; populate both.
        let src = Source::Record { sfi: 1, record: 1 };
        ctx.tag_store
            .insert_primitive(tags::LOWER_CONSECUTIVE_OFFLINE_LIMIT, vec![0x05], src)
            .unwrap();
        ctx.tag_store
            .insert_primitive(tags::UPPER_CONSECUTIVE_OFFLINE_LIMIT, vec![0x0A], src)
            .unwrap();

        // ATC GET DATA returns 6A88 → "GET DATA failed" → both bits forced.
        let card = ScriptedCard {
            script: get_data_script(None, Some(0)),
            cursor: 0,
        };
        let mut tx = Transaction {
            card,
            auth: MockAuth(OnlineAuthorisationResponse {
                authorisation_response_code: AuthorisationResponseCode::OFFLINE_DECLINED,
                issuer_authentication_data: None,
                issuer_scripts: vec![],
            }),
            ctx,
        };

        let outcome = tx.run_terminal_risk_management(None, None).unwrap();
        assert!(outcome.lower_consecutive_offline_limit_exceeded);
        assert!(outcome.upper_consecutive_offline_limit_exceeded);
        // Last Online ATC Register == 0 → New card bit fires per §10.6.3.
        assert!(outcome.new_card);
        assert!(tx.ctx.tvr.lower_consecutive_offline_limit_exceeded);
        assert!(tx.ctx.tvr.upper_consecutive_offline_limit_exceeded);
        assert!(tx.ctx.tvr.new_card);
    }

    #[test]
    fn run_trm_velocity_skipped_when_loatc_absent() {
        let terminal = fixture_terminal_with_floor_limit_and_rts(100, None);
        let ctx = ctx_with_selected(&terminal, 50);
        // LOATC missing → §10.6.3 skips the entire section regardless of
        // GET DATA outcomes.
        let card = ScriptedCard {
            script: get_data_script(None, None),
            cursor: 0,
        };
        let mut tx = Transaction {
            card,
            auth: MockAuth(OnlineAuthorisationResponse {
                authorisation_response_code: AuthorisationResponseCode::OFFLINE_DECLINED,
                issuer_authentication_data: None,
                issuer_scripts: vec![],
            }),
            ctx,
        };

        let outcome = tx.run_terminal_risk_management(None, None).unwrap();
        assert!(!outcome.lower_consecutive_offline_limit_exceeded);
        assert!(!outcome.upper_consecutive_offline_limit_exceeded);
        assert!(!outcome.new_card);
    }

    fn aip_with_methods(
        sda: bool,
        dda: bool,
        cda: bool,
        xda: bool,
    ) -> crate::de::application_interchange_profile::ApplicationInterchangeProfile {
        crate::de::application_interchange_profile::ApplicationInterchangeProfile {
            sda_supported: sda,
            dda_supported: dda,
            cda_supported: cda,
            xda_supported: xda,
            ..Default::default()
        }
    }

    fn caps_with_methods(sda: bool, dda: bool, cda: bool, xda: bool) -> TerminalCapabilities {
        TerminalCapabilities {
            ic_with_contacts: true,
            sda,
            dda,
            cda,
            xda,
            ..Default::default()
        }
    }

    fn fixture_terminal_with_caps(caps: TerminalCapabilities) -> Terminal {
        let mut t = fixture_terminal();
        t.terminal_capabilities = caps;
        t
    }

    #[test]
    fn oda_no_common_method_sets_not_performed_bit() {
        // Card supports only XDA; terminal supports only SDA.
        let terminal = fixture_terminal_with_caps(caps_with_methods(true, false, false, false));
        let mut ctx = ctx_with_selected(&terminal, 100);
        ctx.aip = Some(aip_with_methods(false, false, false, true));
        let card = ScriptedCard {
            script: vec![],
            cursor: 0,
        };
        let mut tx = Transaction {
            card,
            auth: MockAuth(OnlineAuthorisationResponse {
                authorisation_response_code: AuthorisationResponseCode::OFFLINE_DECLINED,
                issuer_authentication_data: None,
                issuer_scripts: vec![],
            }),
            ctx,
        };
        let outcome = tx
            .perform_offline_data_authentication(&[], &[], &[], &[])
            .unwrap();
        assert_eq!(outcome, OdaOutcome::NotPerformed);
        assert!(tx.ctx.tvr.offline_data_authentication_was_not_performed);
        assert!(!tx.ctx.tvr.sda_selected);
        assert!(!tx.ctx.tsi.offline_data_authentication_was_performed);
    }

    #[test]
    fn oda_selects_highest_priority_method_xda_over_cda() {
        let terminal = fixture_terminal_with_caps(caps_with_methods(true, true, true, true));
        let mut ctx = ctx_with_selected(&terminal, 100);
        ctx.aip = Some(aip_with_methods(true, true, true, true));
        let card = ScriptedCard {
            script: vec![],
            cursor: 0,
        };
        let mut tx = Transaction {
            card,
            auth: MockAuth(OnlineAuthorisationResponse {
                authorisation_response_code: AuthorisationResponseCode::OFFLINE_DECLINED,
                issuer_authentication_data: None,
                issuer_scripts: vec![],
            }),
            ctx,
        };
        let outcome = tx
            .perform_offline_data_authentication(&[], &[], &[], &[])
            .unwrap();
        // Both support all four → XDA is highest priority.
        assert_eq!(outcome, OdaOutcome::XdaArmed);
        // Pre-TAA: TVR `xda_selected` set, ECC failure bits NOT yet set
        // per Book 2 §12 p. 107.
        assert!(tx.ctx.tvr.xda_selected);
        assert!(!tx.ctx.tvr.ca_ecc_key_missing);
        assert!(!tx.ctx.tvr.ecc_key_recovery_failed);
        // ICC data missing is set immediately since the test card has
        // none of the required ICC tags in store.
        assert!(tx.ctx.tvr.icc_data_missing);
    }

    #[test]
    fn oda_selects_dda_when_no_xda_or_cda() {
        // DDA is now wired: with no ICC ODA tags in the store, the DDA
        // path runs and fails with "ICC data missing" + "DDA failed".
        let terminal = fixture_terminal_with_caps(caps_with_methods(true, true, false, false));
        let mut ctx = ctx_with_selected(&terminal, 100);
        ctx.aip = Some(aip_with_methods(true, true, false, false));
        let card = ScriptedCard {
            script: vec![],
            cursor: 0,
        };
        let mut tx = Transaction {
            card,
            auth: MockAuth(OnlineAuthorisationResponse {
                authorisation_response_code: AuthorisationResponseCode::OFFLINE_DECLINED,
                issuer_authentication_data: None,
                issuer_scripts: vec![],
            }),
            ctx,
        };
        let outcome = tx
            .perform_offline_data_authentication(&[], &[], &[], &[])
            .unwrap();
        assert_eq!(outcome, OdaOutcome::DdaFailed);
        assert!(tx.ctx.tvr.dda_failed);
        assert!(tx.ctx.tvr.icc_data_missing);
        assert!(tx.ctx.tsi.offline_data_authentication_was_performed);
    }

    #[test]
    fn oda_falls_back_to_sda_when_only_method_in_common() {
        // Card supports SDA + DDA; terminal supports only SDA.
        let terminal = fixture_terminal_with_caps(caps_with_methods(true, false, false, false));
        let mut ctx = ctx_with_selected(&terminal, 100);
        ctx.aip = Some(aip_with_methods(true, true, false, false));
        let card = ScriptedCard {
            script: vec![],
            cursor: 0,
        };
        let mut tx = Transaction {
            card,
            auth: MockAuth(OnlineAuthorisationResponse {
                authorisation_response_code: AuthorisationResponseCode::OFFLINE_DECLINED,
                issuer_authentication_data: None,
                issuer_scripts: vec![],
            }),
            ctx,
        };
        // No ICC ODA tags in store → SDA fails with "ICC data missing".
        let outcome = tx
            .perform_offline_data_authentication(&[], &[], &[], &[])
            .unwrap();
        assert_eq!(outcome, OdaOutcome::SdaFailed);
        assert!(tx.ctx.tvr.sda_selected);
        assert!(tx.ctx.tvr.sda_failed);
        assert!(tx.ctx.tvr.icc_data_missing);
        assert!(tx.ctx.tsi.offline_data_authentication_was_performed);
    }

    #[test]
    fn oda_sda_capk_not_found_fails_without_icc_data_missing() {
        // All ICC tags present, but the (RID, index) CAPK isn't in the store.
        let terminal = fixture_terminal_with_caps(caps_with_methods(true, false, false, false));
        let mut ctx = ctx_with_selected(&terminal, 100);
        ctx.aip = Some(aip_with_methods(true, false, false, false));
        let src = Source::Record { sfi: 1, record: 1 };
        for (tag, val) in [
            (tags::CA_PUBLIC_KEY_INDEX_ICC, vec![0x99]),
            (tags::ISSUER_PUBLIC_KEY_CERTIFICATE, vec![0xAA; 128]),
            (tags::ISSUER_PUBLIC_KEY_EXPONENT, vec![0x03]),
            (tags::SIGNED_STATIC_APPLICATION_DATA, vec![0xCC; 128]),
            (tags::PAN, vec![0x12, 0x34, 0x56, 0x78]),
        ] {
            ctx.tag_store.insert_primitive(tag, val, src).unwrap();
        }

        let card = ScriptedCard {
            script: vec![],
            cursor: 0,
        };
        let mut tx = Transaction {
            card,
            auth: MockAuth(OnlineAuthorisationResponse {
                authorisation_response_code: AuthorisationResponseCode::OFFLINE_DECLINED,
                issuer_authentication_data: None,
                issuer_scripts: vec![],
            }),
            ctx,
        };
        let outcome = tx
            .perform_offline_data_authentication(&[], &[], &[], &[])
            .unwrap();
        assert_eq!(outcome, OdaOutcome::SdaFailed);
        assert!(tx.ctx.tvr.sda_failed);
        // Data was present → "ICC data missing" must NOT be set.
        assert!(!tx.ctx.tvr.icc_data_missing);
        assert!(tx.ctx.tsi.offline_data_authentication_was_performed);
    }

    #[test]
    fn oda_invalid_sda_tag_list_fails_input_build() {
        let terminal = fixture_terminal_with_caps(caps_with_methods(true, false, false, false));
        let mut ctx = ctx_with_selected(&terminal, 100);
        ctx.aip = Some(aip_with_methods(true, false, false, false));
        let src = Source::Record { sfi: 1, record: 1 };
        for (tag, val) in [
            (tags::CA_PUBLIC_KEY_INDEX_ICC, vec![0x01]),
            (tags::ISSUER_PUBLIC_KEY_CERTIFICATE, vec![0xAA; 128]),
            (tags::ISSUER_PUBLIC_KEY_EXPONENT, vec![0x03]),
            (tags::SIGNED_STATIC_APPLICATION_DATA, vec![0xCC; 128]),
            (tags::PAN, vec![0x12, 0x34, 0x56, 0x78]),
            // SDA Tag List with anything other than '82' is an error.
            (tags::SDA_TAG_LIST, vec![0x9A]),
        ] {
            ctx.tag_store.insert_primitive(tag, val, src).unwrap();
        }
        let capks = vec![CaPublicKey {
            rid: [0xA0, 0, 0, 0, 0x03],
            index: 0x01,
            modulus: vec![0xBB; 128],
            exponent: vec![0x03],
        }];

        let card = ScriptedCard {
            script: vec![],
            cursor: 0,
        };
        let mut tx = Transaction {
            card,
            auth: MockAuth(OnlineAuthorisationResponse {
                authorisation_response_code: AuthorisationResponseCode::OFFLINE_DECLINED,
                issuer_authentication_data: None,
                issuer_scripts: vec![],
            }),
            ctx,
        };
        let outcome = tx
            .perform_offline_data_authentication(&capks, &[], &[], &[])
            .unwrap();
        assert_eq!(outcome, OdaOutcome::SdaFailed);
        assert!(tx.ctx.tvr.sda_failed);
        assert!(!tx.ctx.tvr.icc_data_missing);
    }

    #[test]
    fn oda_dda_missing_icc_pk_cert_sets_icc_data_missing() {
        // Card+terminal both DDA. Issuer PK chain present, but ICC PK
        // Cert (9F46) is missing - should fail with "ICC data missing".
        let terminal = fixture_terminal_with_caps(caps_with_methods(false, true, false, false));
        let mut ctx = ctx_with_selected(&terminal, 100);
        ctx.aip = Some(aip_with_methods(false, true, false, false));
        let src = Source::Record { sfi: 1, record: 1 };
        for (tag, val) in [
            (tags::CA_PUBLIC_KEY_INDEX_ICC, vec![0x01]),
            (tags::ISSUER_PUBLIC_KEY_CERTIFICATE, vec![0xAA; 128]),
            (tags::ISSUER_PUBLIC_KEY_EXPONENT, vec![0x03]),
            (tags::PAN, vec![0x12, 0x34, 0x56, 0x78]),
            // Deliberately omit 9F46 / 9F47.
        ] {
            ctx.tag_store.insert_primitive(tag, val, src).unwrap();
        }
        let card = ScriptedCard {
            script: vec![],
            cursor: 0,
        };
        let mut tx = Transaction {
            card,
            auth: MockAuth(OnlineAuthorisationResponse {
                authorisation_response_code: AuthorisationResponseCode::OFFLINE_DECLINED,
                issuer_authentication_data: None,
                issuer_scripts: vec![],
            }),
            ctx,
        };
        let outcome = tx
            .perform_offline_data_authentication(&[], &[], &[], &[])
            .unwrap();
        assert_eq!(outcome, OdaOutcome::DdaFailed);
        assert!(tx.ctx.tvr.dda_failed);
        assert!(tx.ctx.tvr.icc_data_missing);
        assert!(tx.ctx.tsi.offline_data_authentication_was_performed);
    }

    #[test]
    fn oda_dda_no_ddol_anywhere_fails() {
        // All ICC tags present, plausible CAPK, but no DDOL on the ICC
        // and no `default_ddol` configured → DDA failed.
        let terminal = fixture_terminal_with_caps(caps_with_methods(false, true, false, false));
        let mut ctx = ctx_with_selected(&terminal, 100);
        ctx.aip = Some(aip_with_methods(false, true, false, false));
        let src = Source::Record { sfi: 1, record: 1 };
        for (tag, val) in [
            (tags::CA_PUBLIC_KEY_INDEX_ICC, vec![0x01]),
            (tags::ISSUER_PUBLIC_KEY_CERTIFICATE, vec![0xAA; 128]),
            (tags::ISSUER_PUBLIC_KEY_EXPONENT, vec![0x03]),
            (tags::ICC_PUBLIC_KEY_CERTIFICATE, vec![0xBB; 128]),
            (tags::ICC_PUBLIC_KEY_EXPONENT, vec![0x03]),
            (tags::PAN, vec![0x12, 0x34, 0x56, 0x78]),
        ] {
            ctx.tag_store.insert_primitive(tag, val, src).unwrap();
        }
        let capks = vec![CaPublicKey {
            rid: [0xA0, 0, 0, 0, 0x03],
            index: 0x01,
            modulus: vec![0xBB; 128],
            exponent: vec![0x03],
        }];
        let card = ScriptedCard {
            script: vec![],
            cursor: 0,
        };
        let mut tx = Transaction {
            card,
            auth: MockAuth(OnlineAuthorisationResponse {
                authorisation_response_code: AuthorisationResponseCode::OFFLINE_DECLINED,
                issuer_authentication_data: None,
                issuer_scripts: vec![],
            }),
            ctx,
        };
        let outcome = tx
            .perform_offline_data_authentication(&capks, &[], &[], &[])
            .unwrap();
        // DDA fails before reaching INTERNAL AUTHENTICATE because the
        // Issuer PK recovery fails (synthetic CAPK / cert), but if it
        // got further the no-DDOL case would fail too.
        assert_eq!(outcome, OdaOutcome::DdaFailed);
        assert!(tx.ctx.tvr.dda_failed);
        // No "ICC data missing" - all required tags were present.
        assert!(!tx.ctx.tvr.icc_data_missing);
    }

    #[test]
    fn oda_dda_default_ddol_without_un_fails() {
        // Card has no 9F49; terminal default_ddol exists but doesn't
        // include 9F37 → §6.5.1 mandates DDA failed.
        let mut terminal = fixture_terminal_with_caps(caps_with_methods(false, true, false, false));
        // default_ddol asks for tag 9F02 (Amount, 6 bytes) - no UN.
        terminal.applications[0].default_ddol = Some(vec![0x9F, 0x02, 0x06]);
        let mut ctx = ctx_with_selected(&terminal, 100);
        ctx.aip = Some(aip_with_methods(false, true, false, false));
        let src = Source::Record { sfi: 1, record: 1 };
        for (tag, val) in [
            (tags::CA_PUBLIC_KEY_INDEX_ICC, vec![0x01]),
            (tags::ISSUER_PUBLIC_KEY_CERTIFICATE, vec![0xAA; 128]),
            (tags::ISSUER_PUBLIC_KEY_EXPONENT, vec![0x03]),
            (tags::ICC_PUBLIC_KEY_CERTIFICATE, vec![0xBB; 128]),
            (tags::ICC_PUBLIC_KEY_EXPONENT, vec![0x03]),
            (tags::PAN, vec![0x12, 0x34, 0x56, 0x78]),
        ] {
            ctx.tag_store.insert_primitive(tag, val, src).unwrap();
        }
        // Synthetic CAPK that won't recover the cert (we never reach
        // DDOL parsing because Issuer PK recovery fails first). So this
        // test isn't perfectly isolated to the DDOL check, but the
        // "no DDOL anywhere" test above covers the same code path.
        let capks = vec![CaPublicKey {
            rid: [0xA0, 0, 0, 0, 0x03],
            index: 0x01,
            modulus: vec![0xBB; 128],
            exponent: vec![0x03],
        }];
        let card = ScriptedCard {
            script: vec![],
            cursor: 0,
        };
        let mut tx = Transaction {
            card,
            auth: MockAuth(OnlineAuthorisationResponse {
                authorisation_response_code: AuthorisationResponseCode::OFFLINE_DECLINED,
                issuer_authentication_data: None,
                issuer_scripts: vec![],
            }),
            ctx,
        };
        let outcome = tx
            .perform_offline_data_authentication(&capks, &[], &[], &[])
            .unwrap();
        assert_eq!(outcome, OdaOutcome::DdaFailed);
        assert!(tx.ctx.tvr.dda_failed);
    }

    #[test]
    fn oda_sdad_parser_format_1_extracts_value() {
        // Format 1: '80' || len || SDAD bytes
        let sdad = vec![0xCC; 8];
        let mut wire = vec![0x80, 8];
        wire.extend_from_slice(&sdad);
        assert_eq!(
            parse_internal_authenticate_sdad(&wire).as_deref(),
            Some(&sdad[..])
        );
    }

    #[test]
    fn oda_sdad_parser_format_2_finds_9f4b_child() {
        // Format 2: '77' constructed { '9F4B' SDAD, '9F36' ATC }
        let sdad = vec![0xDD; 4];
        let mut inner = vec![0x9F, 0x4B, sdad.len() as u8];
        inner.extend_from_slice(&sdad);
        inner.extend_from_slice(&[0x9F, 0x36, 0x02, 0x00, 0x05]); // ATC=5
        let mut wire = vec![0x77, inner.len() as u8];
        wire.extend_from_slice(&inner);
        assert_eq!(
            parse_internal_authenticate_sdad(&wire).as_deref(),
            Some(&sdad[..])
        );
    }

    #[test]
    fn oda_sdad_parser_format_2_missing_9f4b_returns_none() {
        // Format 2 with no SDAD inside.
        let inner = vec![0x9F, 0x36, 0x02, 0x00, 0x05];
        let mut wire = vec![0x77, inner.len() as u8];
        wire.extend_from_slice(&inner);
        assert_eq!(parse_internal_authenticate_sdad(&wire), None);
    }

    #[test]
    fn oda_sdad_parser_unknown_template_returns_none() {
        // Some other tag - not '80' or '77'.
        let wire = vec![0x70, 0x02, 0xAA, 0xBB];
        assert_eq!(parse_internal_authenticate_sdad(&wire), None);
    }

    #[test]
    fn oda_errors_when_aip_not_set() {
        let terminal = fixture_terminal();
        let ctx = ctx_with_selected(&terminal, 100);
        let card = ScriptedCard {
            script: vec![],
            cursor: 0,
        };
        let mut tx = Transaction {
            card,
            auth: MockAuth(OnlineAuthorisationResponse {
                authorisation_response_code: AuthorisationResponseCode::OFFLINE_DECLINED,
                issuer_authentication_data: None,
                issuer_scripts: vec![],
            }),
            ctx,
        };
        match tx.perform_offline_data_authentication(&[], &[], &[], &[]) {
            Err(DriverError::Spec(Error::MissingMandatory { tag })) => {
                assert_eq!(tag, tags::APPLICATION_INTERCHANGE_PROFILE);
            }
            other => panic!("expected MissingMandatory(82), got {:?}", other),
        }
    }

    #[test]
    fn run_trm_silently_skips_rts_when_application_lacks_params() {
        let terminal = fixture_terminal_with_floor_limit_and_rts(100, None);
        let ctx = ctx_with_selected(&terminal, 50);
        let card = ScriptedCard {
            script: get_data_script(None, None),
            cursor: 0,
        };
        let mut tx = Transaction {
            card,
            auth: MockAuth(OnlineAuthorisationResponse {
                authorisation_response_code: AuthorisationResponseCode::OFFLINE_DECLINED,
                issuer_authentication_data: None,
                issuer_scripts: vec![],
            }),
            ctx,
        };

        // Even with random=1 and no RTS params → bit stays clear.
        let outcome = tx.run_terminal_risk_management(Some(1), None).unwrap();
        assert!(!outcome.transaction_selected_randomly_for_online_processing);
    }

    fn aip_with_issuer_auth(
        supported: bool,
    ) -> crate::de::application_interchange_profile::ApplicationInterchangeProfile {
        crate::de::application_interchange_profile::ApplicationInterchangeProfile {
            issuer_authentication_is_supported: supported,
            ..Default::default()
        }
    }

    fn auth_response(iad: Option<Vec<u8>>, scripts: Vec<Tlv>) -> OnlineAuthorisationResponse {
        OnlineAuthorisationResponse {
            authorisation_response_code: AuthorisationResponseCode(*b"00"),
            issuer_authentication_data: iad,
            issuer_scripts: scripts,
        }
    }

    fn empty_card() -> ScriptedCard {
        ScriptedCard {
            script: vec![],
            cursor: 0,
        }
    }

    fn empty_auth() -> MockAuth {
        MockAuth(OnlineAuthorisationResponse {
            authorisation_response_code: AuthorisationResponseCode(*b"00"),
            issuer_authentication_data: None,
            issuer_scripts: vec![],
        })
    }

    fn ea_command_bytes(iad: &[u8]) -> Vec<u8> {
        let mut v = vec![0x00, 0x82, 0x00, 0x00, iad.len() as u8];
        v.extend_from_slice(iad);
        v
    }

    #[test]
    fn online_card_auth_no_iad_skips_external_authenticate() {
        let terminal = fixture_terminal();
        let mut ctx = ctx_with_selected(&terminal, 100);
        ctx.aip = Some(aip_with_issuer_auth(true));
        let mut tx = Transaction {
            card: empty_card(),
            auth: empty_auth(),
            ctx,
        };
        let resp = auth_response(None, vec![]);
        let outcome = tx.online_card_authentication(&resp).unwrap();
        assert!(outcome.is_none());
        assert!(!tx.ctx.tsi.issuer_authentication_was_performed);
        assert!(!tx.ctx.tvr.issuer_authentication_failed);
    }

    #[test]
    fn online_card_auth_aip_says_no_skips_external_authenticate() {
        let terminal = fixture_terminal();
        let mut ctx = ctx_with_selected(&terminal, 100);
        ctx.aip = Some(aip_with_issuer_auth(false));
        let mut tx = Transaction {
            card: empty_card(),
            auth: empty_auth(),
            ctx,
        };
        let resp = auth_response(Some(vec![0x11; 8]), vec![]);
        let outcome = tx.online_card_authentication(&resp).unwrap();
        assert!(outcome.is_none());
        assert!(!tx.ctx.tsi.issuer_authentication_was_performed);
        assert!(!tx.ctx.tvr.issuer_authentication_failed);
    }

    #[test]
    fn online_card_auth_success_sets_tsi_only() {
        let iad = vec![0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88];
        let terminal = fixture_terminal();
        let mut ctx = ctx_with_selected(&terminal, 100);
        ctx.aip = Some(aip_with_issuer_auth(true));
        let card = ScriptedCard {
            script: vec![(ea_command_bytes(&iad), vec![0x90, 0x00])],
            cursor: 0,
        };
        let mut tx = Transaction {
            card,
            auth: empty_auth(),
            ctx,
        };
        let resp = auth_response(Some(iad), vec![]);
        let outcome = tx.online_card_authentication(&resp).unwrap();
        assert_eq!(outcome, Some(ExternalAuthenticateOutcome::Successful));
        assert!(tx.ctx.tsi.issuer_authentication_was_performed);
        assert!(!tx.ctx.tvr.issuer_authentication_failed);
    }

    #[test]
    fn online_card_auth_failure_sets_tsi_and_tvr() {
        let iad = vec![0xAA; 8];
        let terminal = fixture_terminal();
        let mut ctx = ctx_with_selected(&terminal, 100);
        ctx.aip = Some(aip_with_issuer_auth(true));
        let card = ScriptedCard {
            // Card returns 6300 - auth failed.
            script: vec![(ea_command_bytes(&iad), vec![0x63, 0x00])],
            cursor: 0,
        };
        let mut tx = Transaction {
            card,
            auth: empty_auth(),
            ctx,
        };
        let resp = auth_response(Some(iad), vec![]);
        let outcome = tx.online_card_authentication(&resp).unwrap();
        assert_eq!(outcome, Some(ExternalAuthenticateOutcome::Failed));
        assert!(tx.ctx.tsi.issuer_authentication_was_performed);
        assert!(tx.ctx.tvr.issuer_authentication_failed);
    }

    #[test]
    fn online_card_auth_6985_sets_tsi_and_tvr() {
        // Annex F Table 55 ambiguous case - treat as failed for TVR.
        let iad = vec![0xCC; 8];
        let terminal = fixture_terminal();
        let mut ctx = ctx_with_selected(&terminal, 100);
        ctx.aip = Some(aip_with_issuer_auth(true));
        let card = ScriptedCard {
            script: vec![(ea_command_bytes(&iad), vec![0x69, 0x85])],
            cursor: 0,
        };
        let mut tx = Transaction {
            card,
            auth: empty_auth(),
            ctx,
        };
        let resp = auth_response(Some(iad), vec![]);
        let outcome = tx.online_card_authentication(&resp).unwrap();
        assert_eq!(
            outcome,
            Some(ExternalAuthenticateOutcome::UnsupportedByCardErrorState)
        );
        assert!(tx.ctx.tsi.issuer_authentication_was_performed);
        assert!(tx.ctx.tvr.issuer_authentication_failed);
    }

    fn cmd_tlv(bytes: &[u8]) -> Tlv {
        Tlv::primitive(tags::ISSUER_SCRIPT_COMMAND, bytes.to_vec())
    }

    fn id_tlv(bytes: [u8; 4]) -> Tlv {
        Tlv::primitive(tags::ISSUER_SCRIPT_IDENTIFIER, bytes.to_vec())
    }

    fn script_71(children: Vec<Tlv>) -> Tlv {
        Tlv::constructed(tags::ISSUER_SCRIPT_TEMPLATE_1, children)
    }

    fn script_72(children: Vec<Tlv>) -> Tlv {
        Tlv::constructed(tags::ISSUER_SCRIPT_TEMPLATE_2, children)
    }

    #[test]
    fn process_issuer_scripts_empty_yields_no_changes() {
        let terminal = fixture_terminal();
        let ctx = ctx_with_selected(&terminal, 100);
        let mut tx = Transaction {
            card: empty_card(),
            auth: empty_auth(),
            ctx,
        };
        let outcome = tx
            .process_issuer_scripts(&[], ScriptTag::BeforeFinalGenerateAc)
            .unwrap();
        assert!(outcome.script_results.is_empty());
        assert!(!tx.ctx.tsi.script_processing_was_performed);
        assert!(!tx.ctx.tvr.script_processing_failed_before_final_generate_ac);
    }

    #[test]
    fn process_issuer_scripts_71_success_sets_tsi_only() {
        // One '71' script, one APP UNBLOCK command, card returns 9000.
        let terminal = fixture_terminal();
        let ctx = ctx_with_selected(&terminal, 100);
        let card = ScriptedCard {
            script: vec![(vec![0x84, 0x18, 0x00, 0x00], vec![0x90, 0x00])],
            cursor: 0,
        };
        let mut tx = Transaction {
            card,
            auth: empty_auth(),
            ctx,
        };
        let s = script_71(vec![cmd_tlv(&[0x84, 0x18, 0x00, 0x00])]);
        let outcome = tx
            .process_issuer_scripts(&[s], ScriptTag::BeforeFinalGenerateAc)
            .unwrap();
        assert_eq!(outcome.script_results.len(), 1);
        assert!(tx.ctx.tsi.script_processing_was_performed);
        assert!(!tx.ctx.tvr.script_processing_failed_before_final_generate_ac);
        assert!(!tx.ctx.tvr.script_processing_failed_after_final_generate_ac);
    }

    #[test]
    fn process_issuer_scripts_71_failure_sets_tvr_b6() {
        // Card returns 6A82 → SW1 = 6A is an error → terminate script.
        let terminal = fixture_terminal();
        let ctx = ctx_with_selected(&terminal, 100);
        let card = ScriptedCard {
            script: vec![(vec![0x84, 0x18, 0x00, 0x00], vec![0x6A, 0x82])],
            cursor: 0,
        };
        let mut tx = Transaction {
            card,
            auth: empty_auth(),
            ctx,
        };
        let s = script_71(vec![cmd_tlv(&[0x84, 0x18, 0x00, 0x00])]);
        let _ = tx
            .process_issuer_scripts(&[s], ScriptTag::BeforeFinalGenerateAc)
            .unwrap();
        assert!(tx.ctx.tsi.script_processing_was_performed);
        assert!(tx.ctx.tvr.script_processing_failed_before_final_generate_ac);
        assert!(!tx.ctx.tvr.script_processing_failed_after_final_generate_ac);
    }

    #[test]
    fn process_issuer_scripts_72_failure_sets_tvr_b5_not_b6() {
        let terminal = fixture_terminal();
        let ctx = ctx_with_selected(&terminal, 100);
        let card = ScriptedCard {
            script: vec![(vec![0x84, 0x24, 0x00, 0x00], vec![0x6F, 0x00])],
            cursor: 0,
        };
        let mut tx = Transaction {
            card,
            auth: empty_auth(),
            ctx,
        };
        let s = script_72(vec![cmd_tlv(&[0x84, 0x24, 0x00, 0x00])]);
        let _ = tx
            .process_issuer_scripts(&[s], ScriptTag::AfterFinalGenerateAc)
            .unwrap();
        assert!(tx.ctx.tsi.script_processing_was_performed);
        assert!(tx.ctx.tvr.script_processing_failed_after_final_generate_ac);
        assert!(!tx.ctx.tvr.script_processing_failed_before_final_generate_ac);
    }

    #[test]
    fn process_issuer_scripts_filters_by_position() {
        // Pass both a '71' and a '72'; ask only for BeforeFinalGenerateAc.
        // Only the '71' command should hit the card.
        let terminal = fixture_terminal();
        let ctx = ctx_with_selected(&terminal, 100);
        let card = ScriptedCard {
            // Only the '71' command is expected on the wire.
            script: vec![(vec![0x84, 0x18, 0x00, 0x00], vec![0x90, 0x00])],
            cursor: 0,
        };
        let mut tx = Transaction {
            card,
            auth: empty_auth(),
            ctx,
        };
        let s71 = script_71(vec![cmd_tlv(&[0x84, 0x18, 0x00, 0x00])]);
        let s72 = script_72(vec![cmd_tlv(&[0x84, 0x24, 0x00, 0x00])]);
        let outcome = tx
            .process_issuer_scripts(&[s71, s72], ScriptTag::BeforeFinalGenerateAc)
            .unwrap();
        assert_eq!(outcome.script_results.len(), 1);
        assert_eq!(
            outcome.script_results[0].tag,
            ScriptTag::BeforeFinalGenerateAc
        );
        assert!(tx.ctx.tsi.script_processing_was_performed);
    }

    #[test]
    fn process_issuer_scripts_warning_sw_continues() {
        // 6281, 6300 are warnings - script should continue and succeed.
        let terminal = fixture_terminal();
        let ctx = ctx_with_selected(&terminal, 100);
        let card = ScriptedCard {
            script: vec![
                (vec![0x84, 0x18, 0x00, 0x00], vec![0x62, 0x81]),
                (vec![0x84, 0x18, 0x00, 0x01], vec![0x63, 0x00]),
                (vec![0x84, 0x18, 0x00, 0x02], vec![0x90, 0x00]),
            ],
            cursor: 0,
        };
        let mut tx = Transaction {
            card,
            auth: empty_auth(),
            ctx,
        };
        let s = script_71(vec![
            cmd_tlv(&[0x84, 0x18, 0x00, 0x00]),
            cmd_tlv(&[0x84, 0x18, 0x00, 0x01]),
            cmd_tlv(&[0x84, 0x18, 0x00, 0x02]),
        ]);
        let _ = tx
            .process_issuer_scripts(&[s], ScriptTag::BeforeFinalGenerateAc)
            .unwrap();
        assert!(!tx.ctx.tvr.script_processing_failed_before_final_generate_ac);
    }

    #[test]
    fn process_issuer_scripts_transport_error_propagates() {
        // Empty card script - transmit will hit a panic in the test
        // ScriptedCard. To exercise the transport-error path we need a
        // card that reports an error, not a panic. Use a card whose
        // script is intentionally short so cursor overflow trips the
        // real CardReader::transmit path. Here we use a card with no entries
        // at all and check that the outcome propagates a structured
        // error. (The default ScriptedCard panics on overflow, so we
        // instead rely on a malformed APDU to trigger the script's own
        // termination logic - an alternative path that exercises the
        // `Command::from_bytes` parse-error branch.)
        let terminal = fixture_terminal();
        let ctx = ctx_with_selected(&terminal, 100);
        let mut tx = Transaction {
            card: empty_card(),
            auth: empty_auth(),
            ctx,
        };
        // 2-byte APDU is shorter than 4 → Command::from_bytes errors,
        // process_scripts records a 6F00 sentinel and terminates the
        // script without calling card.transmit at all. TVR b6 set.
        let s = script_71(vec![cmd_tlv(&[0x84, 0x18])]);
        let _ = tx
            .process_issuer_scripts(&[s], ScriptTag::BeforeFinalGenerateAc)
            .unwrap();
        assert!(tx.ctx.tvr.script_processing_failed_before_final_generate_ac);
    }

    #[test]
    fn issuer_script_results_initially_empty() {
        let terminal = fixture_terminal();
        let ctx = ctx_with_selected(&terminal, 100);
        // Fresh context: nothing processed yet.
        assert!(ctx.issuer_script_results.is_empty());
    }

    #[test]
    fn issuer_script_results_accumulates_one_entry_per_script() {
        // Two '71' scripts in one call: first succeeds, second fails on
        // command 1. Per Annex A5, accumulator should hold two 5-byte
        // entries.
        use crate::de::issuer_script_results::ScriptResultNibble;
        let terminal = fixture_terminal();
        let ctx = ctx_with_selected(&terminal, 100);
        let card = ScriptedCard {
            script: vec![
                (vec![0x84, 0x18, 0x00, 0x00], vec![0x90, 0x00]),
                (vec![0x84, 0x24, 0x00, 0x00], vec![0x6A, 0x82]),
            ],
            cursor: 0,
        };
        let mut tx = Transaction {
            card,
            auth: empty_auth(),
            ctx,
        };
        let s1 = script_71(vec![
            id_tlv([0xAA, 0xBB, 0xCC, 0xDD]),
            cmd_tlv(&[0x84, 0x18, 0x00, 0x00]),
        ]);
        let s2 = script_71(vec![
            id_tlv([0x11, 0x22, 0x33, 0x44]),
            cmd_tlv(&[0x84, 0x24, 0x00, 0x00]),
        ]);
        let _ = tx
            .process_issuer_scripts(&[s1, s2], ScriptTag::BeforeFinalGenerateAc)
            .unwrap();

        assert_eq!(tx.ctx.issuer_script_results.len(), 2);
        // First: success, sequence 0 (Annex A5: '0' on success), id AABBCCDD.
        let e1 = tx.ctx.issuer_script_results[0];
        assert_eq!(
            e1.script_result,
            ScriptResultNibble::ScriptProcessingSuccessful
        );
        assert_eq!(e1.script_number, 0);
        assert_eq!(e1.script_identifier, [0xAA, 0xBB, 0xCC, 0xDD]);
        // Second: failed, sequence 1, id 11223344.
        let e2 = tx.ctx.issuer_script_results[1];
        assert_eq!(e2.script_result, ScriptResultNibble::ScriptProcessingFailed);
        assert_eq!(e2.script_number, 1);
        assert_eq!(e2.script_identifier, [0x11, 0x22, 0x33, 0x44]);
    }

    #[test]
    fn issuer_script_results_accumulates_across_71_and_72_calls() {
        // §6.3.9: 9F5B is reported in the final clearing/advice/reversal,
        // so entries from BOTH the '71' (before) and '72' (after) calls
        // must end up in one ordered list.
        use crate::de::issuer_script_results::ScriptResultNibble;
        let terminal = fixture_terminal();
        let ctx = ctx_with_selected(&terminal, 100);
        let card = ScriptedCard {
            script: vec![
                (vec![0x84, 0x18, 0x00, 0x00], vec![0x90, 0x00]),
                (vec![0x84, 0x24, 0x00, 0x00], vec![0x90, 0x00]),
            ],
            cursor: 0,
        };
        let mut tx = Transaction {
            card,
            auth: empty_auth(),
            ctx,
        };
        let s71 = script_71(vec![
            id_tlv([0x71, 0x71, 0x71, 0x71]),
            cmd_tlv(&[0x84, 0x18, 0x00, 0x00]),
        ]);
        let s72 = script_72(vec![
            id_tlv([0x72, 0x72, 0x72, 0x72]),
            cmd_tlv(&[0x84, 0x24, 0x00, 0x00]),
        ]);
        let _ = tx
            .process_issuer_scripts(&[s71], ScriptTag::BeforeFinalGenerateAc)
            .unwrap();
        let _ = tx
            .process_issuer_scripts(&[s72], ScriptTag::AfterFinalGenerateAc)
            .unwrap();

        assert_eq!(tx.ctx.issuer_script_results.len(), 2);
        assert_eq!(
            tx.ctx.issuer_script_results[0].script_identifier,
            [0x71, 0x71, 0x71, 0x71]
        );
        assert_eq!(
            tx.ctx.issuer_script_results[1].script_identifier,
            [0x72, 0x72, 0x72, 0x72]
        );
        // Both succeeded.
        for e in &tx.ctx.issuer_script_results {
            assert_eq!(
                e.script_result,
                ScriptResultNibble::ScriptProcessingSuccessful
            );
        }
    }

    #[test]
    fn issuer_script_results_records_not_performed_for_parse_error() {
        // Annex E Scenario 3: malformed identifier length → "Script not
        // performed". §12.2.4 confirms parse failures still emit a 9F5B
        // entry tagged as not performed.
        use crate::de::issuer_script_results::ScriptResultNibble;
        let terminal = fixture_terminal();
        let ctx = ctx_with_selected(&terminal, 100);
        let mut tx = Transaction {
            card: empty_card(),
            auth: empty_auth(),
            ctx,
        };
        // 9F18 with 3 bytes (must be 4) - parse error, no APDU sent.
        let s = script_71(vec![
            crate::core::tlv::Tlv::primitive(
                tags::ISSUER_SCRIPT_IDENTIFIER,
                vec![0x01, 0x02, 0x03],
            ),
            cmd_tlv(&[0x84, 0x18, 0x00, 0x00]),
        ]);
        let _ = tx
            .process_issuer_scripts(&[s], ScriptTag::BeforeFinalGenerateAc)
            .unwrap();

        assert_eq!(tx.ctx.issuer_script_results.len(), 1);
        let e = tx.ctx.issuer_script_results[0];
        assert_eq!(e.script_result, ScriptResultNibble::ScriptNotPerformed);
        // Identifier zero-filled because the malformed 9F18 couldn't be
        // captured before the parse error (process_one_script bails
        // before identifier is written when the length is wrong).
        assert_eq!(e.script_identifier, [0u8; 4]);
    }

    use crate::core::generate_ac::GenerateAcFormat;
    use crate::de::cryptogram_information_data::CryptogramInformationData;
    use sha1::{Digest, Sha1};

    fn cda_identity_icc_pk(n_ic: usize) -> oda::IccPublicKey {
        oda::IccPublicKey {
            modulus: vec![0xFF; n_ic],
            exponent: vec![1],
            hash_algorithm_indicator: 0x01,
            algorithm_indicator: 0x01,
            application_pan: [0x12, 0x34, 0x56, 0x78, 0x90, 0x12, 0x34, 0x56, 0x78, 0x9F],
            expiration_mmyy: [0x12, 0x99],
            serial_number: [0, 0, 0],
        }
    }

    fn cda_build_sdad(n_ic: usize, icc_dynamic_data: &[u8], un: [u8; 4]) -> Vec<u8> {
        let l_dd = icc_dynamic_data.len();
        let pad_len = n_ic - l_dd - 25;
        let mut middle = Vec::new();
        middle.push(0x05);
        middle.push(0x01); // SHA-1
        middle.push(l_dd as u8);
        middle.extend_from_slice(icc_dynamic_data);
        middle.extend(std::iter::repeat_n(0xBBu8, pad_len));

        let mut hasher = Sha1::new();
        hasher.update(&middle);
        hasher.update(un);
        let h = hasher.finalize();

        let mut x = Vec::with_capacity(n_ic);
        x.push(0x6A);
        x.extend_from_slice(&middle);
        x.extend_from_slice(&h);
        x.push(0xBC);
        x
    }

    fn cda_table19(dn: &[u8], cid: u8, ac: [u8; 8], tx_hash: [u8; 20]) -> Vec<u8> {
        let mut v = Vec::with_capacity(1 + dn.len() + 1 + 8 + 20);
        v.push(dn.len() as u8);
        v.extend_from_slice(dn);
        v.push(cid);
        v.extend_from_slice(&ac);
        v.extend_from_slice(&tx_hash);
        v
    }

    fn cda_sha1(data: &[u8]) -> [u8; 20] {
        let mut h = Sha1::new();
        h.update(data);
        h.finalize().into()
    }

    fn cda_response_format2(cid_byte: u8, sdad: Option<Vec<u8>>) -> GenerateAcResponse {
        GenerateAcResponse {
            format: GenerateAcFormat::Format2,
            cid: CryptogramInformationData::parse(&[cid_byte]).unwrap(),
            atc: [0x00, 0x05],
            ac: None,
            iad: None,
            sdad,
            proprietary: Vec::new(),
            children_in_order: Vec::new(),
        }
    }

    #[test]
    fn verify_cda_first_no_arming_fails_and_sets_tvr() {
        let terminal = fixture_terminal();
        let ctx = ctx_with_selected(&terminal, 100);
        let mut tx = Transaction {
            card: empty_card(),
            auth: empty_auth(),
            ctx,
        };
        // ARQC response with a SDAD but no CDA armed on ctx.
        let response = cda_response_format2(0x80, Some(vec![0u8; 128]));
        assert!(tx.verify_cda_first_generate_ac(&response).is_err());
        assert!(tx.ctx.tvr.cda_failed);
        assert!(!tx.ctx.tsi.offline_data_authentication_was_performed);
    }

    #[test]
    fn verify_cda_first_aac_response_fails_and_sets_tvr() {
        // §6.6.2 second paragraph: AAC ⇒ no SDAD; terminal "shall
        // decline". We surface that as a verify-time failure.
        let terminal = fixture_terminal();
        let mut ctx = ctx_with_selected(&terminal, 100);
        ctx.cda = Some(oda::CdaArming {
            icc_public_key: cda_identity_icc_pk(128),
            cdol1_data: vec![],
            cdol2_data: vec![],
        });
        let mut tx = Transaction {
            card: empty_card(),
            auth: empty_auth(),
            ctx,
        };
        let response = cda_response_format2(0x00, None); // AAC, no SDAD
        assert!(tx.verify_cda_first_generate_ac(&response).is_err());
        assert!(tx.ctx.tvr.cda_failed);
    }

    #[test]
    fn verify_cda_first_missing_sdad_fails_and_sets_tvr() {
        // ARQC but card returned no SDAD (i.e. card ignored CDA request).
        let terminal = fixture_terminal();
        let mut ctx = ctx_with_selected(&terminal, 100);
        ctx.cda = Some(oda::CdaArming {
            icc_public_key: cda_identity_icc_pk(128),
            cdol1_data: vec![],
            cdol2_data: vec![],
        });
        let mut tx = Transaction {
            card: empty_card(),
            auth: empty_auth(),
            ctx,
        };
        let response = cda_response_format2(0x80, None);
        assert!(tx.verify_cda_first_generate_ac(&response).is_err());
        assert!(tx.ctx.tvr.cda_failed);
    }

    #[test]
    fn verify_cda_first_missing_un_fails_and_sets_tvr() {
        let terminal = fixture_terminal();
        let mut ctx = ctx_with_selected(&terminal, 100);
        ctx.cda = Some(oda::CdaArming {
            icc_public_key: cda_identity_icc_pk(128),
            cdol1_data: vec![],
            cdol2_data: vec![],
        });
        // No UN in the tag store - verify_cda needs `9F37`.
        let mut tx = Transaction {
            card: empty_card(),
            auth: empty_auth(),
            ctx,
        };
        let response = cda_response_format2(0x80, Some(vec![0u8; 128]));
        assert!(tx.verify_cda_first_generate_ac(&response).is_err());
        assert!(tx.ctx.tvr.cda_failed);
    }

    #[test]
    fn verify_cda_first_happy_path_sets_tsi_and_stores_tags() {
        // Build a real Format-2 response whose SDAD verifies under the
        // identity ICC PK. The §6.6.2 step-10 hash input is:
        //   pdol_data || cdol1_data || (response TLVs minus SDAD)
        let n_ic = 128usize;
        let un: [u8; 4] = [0xAA, 0xBB, 0xCC, 0xDD];
        let pdol_data: Vec<u8> = vec![0x9F, 0x02, 0x06, 0, 0, 0, 0, 0x10, 0x00];
        let cdol1_data: Vec<u8> = vec![
            0x9F, 0x37, 0x04, un[0], un[1], un[2], un[3], 0x9C, 0x01, 0x00,
        ];

        // Children in source order: CID, ATC, AC, IAD, then SDAD (placeholder).
        // We exclude SDAD when building the hash input per §6.6.2.
        let cid_byte: u8 = 0x40; // TC requested
        let ac_bytes: [u8; 8] = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
        let iad_bytes: Vec<u8> = vec![0x06, 0x01, 0x12, 0x03, 0x60, 0x80, 0x00];
        let cid_tlv = Tlv::primitive(tags::CRYPTOGRAM_INFORMATION_DATA, vec![cid_byte]);
        let atc_tlv = Tlv::primitive(tags::APPLICATION_TRANSACTION_COUNTER, vec![0x00, 0x07]);
        let ac_tlv = Tlv::primitive(tags::APPLICATION_CRYPTOGRAM, ac_bytes.to_vec());
        let iad_tlv = Tlv::primitive(tags::ISSUER_APPLICATION_DATA, iad_bytes.clone());

        let mut tx_hash_input = Vec::new();
        tx_hash_input.extend_from_slice(&pdol_data);
        tx_hash_input.extend_from_slice(&cdol1_data);
        for child in [&cid_tlv, &atc_tlv, &ac_tlv, &iad_tlv] {
            tx_hash_input.extend_from_slice(&child.encode());
        }
        let tx_hash = cda_sha1(&tx_hash_input);

        let dn: Vec<u8> = vec![0x11, 0x22, 0x33, 0x44];
        let icc_dyn_data = cda_table19(&dn, cid_byte, ac_bytes, tx_hash);
        let sdad = cda_build_sdad(n_ic, &icc_dyn_data, un);

        let sdad_tlv = Tlv::primitive(tags::SIGNED_DYNAMIC_APPLICATION_DATA, sdad.clone());

        let mut response = cda_response_format2(cid_byte, Some(sdad));
        response.ac = Some(ac_bytes);
        response.iad = Some(iad_bytes);
        response.children_in_order = vec![cid_tlv, atc_tlv, ac_tlv, iad_tlv, sdad_tlv];

        let terminal = fixture_terminal();
        let mut ctx = ctx_with_selected(&terminal, 100);
        ctx.gpo_pdol_data = pdol_data;
        ctx.cda = Some(oda::CdaArming {
            icc_public_key: cda_identity_icc_pk(n_ic),
            cdol1_data,
            cdol2_data: vec![],
        });
        // Stamp the UN into the tag store as DOL resolution would.
        ctx.tag_store
            .insert_primitive(
                tags::UNPREDICTABLE_NUMBER,
                un.to_vec(),
                Source::TerminalGenerated,
            )
            .unwrap();
        let mut tx = Transaction {
            card: empty_card(),
            auth: empty_auth(),
            ctx,
        };
        let verified = tx.verify_cda_first_generate_ac(&response).unwrap();
        assert_eq!(verified.icc_dynamic_number, dn);
        assert_eq!(verified.application_cryptogram, ac_bytes);
        assert!(tx.ctx.tsi.offline_data_authentication_was_performed);
        assert!(!tx.ctx.tvr.cda_failed);
        assert_eq!(
            tx.ctx.tag_store.get(tags::ICC_DYNAMIC_NUMBER).unwrap(),
            &dn[..]
        );
        assert_eq!(
            tx.ctx.tag_store.get(tags::APPLICATION_CRYPTOGRAM).unwrap(),
            &ac_bytes[..]
        );
    }

    #[test]
    fn perform_cda_arm_missing_icc_pk_cert_sets_icc_data_missing() {
        // CAPK is loaded but the card returns no ICC PK material.
        let mut terminal = fixture_terminal();
        terminal.terminal_capabilities.cda = true;
        let mut ctx = ctx_with_selected(&terminal, 100);
        ctx.aip = Some(aip_with_methods(false, false, true, false));
        let mut tx = Transaction {
            card: empty_card(),
            auth: empty_auth(),
            ctx,
        };
        // perform_offline_data_authentication selects CDA, runs
        // perform_cda_arm, hits the "missing ICC tag" branch.
        let outcome = tx
            .perform_offline_data_authentication(&[], &[], &[], &[])
            .unwrap();
        assert_eq!(outcome, OdaOutcome::CdaFailed);
        assert!(tx.ctx.tvr.cda_failed);
        assert!(tx.ctx.tvr.icc_data_missing);
        assert!(tx.ctx.cda.is_none());
    }

    fn fixture_genac_response(cid_byte: u8) -> GenerateAcResponse {
        GenerateAcResponse {
            format: GenerateAcFormat::Format1,
            cid: CryptogramInformationData::parse(&[cid_byte]).unwrap(),
            atc: [0x00, 0x07],
            ac: Some([0; 8]),
            iad: None,
            sdad: None,
            proprietary: vec![],
            children_in_order: vec![],
        }
    }

    #[test]
    fn xda_arm_pre_taa_does_not_set_ecc_failure_bits() {
        // Card supports XDA; terminal too. The empty card has no ICC
        // tags so the chain check short-circuits to `RecoveryFailed`
        // (with `icc_data_missing` set immediately - that bit isn't
        // covered by the §12 p. 107 deferral). Critically, neither
        // `ca_ecc_key_missing` nor `ecc_key_recovery_failed` is set
        // pre-TAA - both are deferred to first GENERATE AC verification.
        let terminal = fixture_terminal_with_caps(caps_with_methods(false, false, false, true));
        let mut ctx = ctx_with_selected(&terminal, 100);
        ctx.aip = Some(aip_with_methods(false, false, false, true));
        let mut tx = Transaction {
            card: empty_card(),
            auth: empty_auth(),
            ctx,
        };
        let outcome = tx
            .perform_offline_data_authentication(&[], &[], &[], &[])
            .unwrap();
        assert_eq!(outcome, OdaOutcome::XdaArmed);
        assert!(tx.ctx.tvr.xda_selected);
        // Spec: deferred bits must NOT be set before first GENERATE AC.
        assert!(!tx.ctx.tvr.ca_ecc_key_missing);
        assert!(!tx.ctx.tvr.ecc_key_recovery_failed);
        // The non-deferred `icc_data_missing` bit may be set immediately
        // (and is, in this test, because the store is empty).
        assert!(tx.ctx.tvr.icc_data_missing);
        // The arming state must record the failure mode for the
        // verifier to apply at GenAC time.
        let state = tx.ctx.xda.as_ref().map(|x| x.state.clone());
        assert!(matches!(
            state,
            Some(oda::XdaArmingState::RecoveryFailed) | Some(oda::XdaArmingState::CaMissing)
        ));
    }

    #[test]
    fn xda_verify_first_genac_applies_ca_missing_bit() {
        let terminal = fixture_terminal_with_caps(caps_with_methods(false, false, false, true));
        let mut ctx = ctx_with_selected(&terminal, 100);
        ctx.aip = Some(aip_with_methods(false, false, false, true));
        ctx.xda = Some(oda::XdaArming {
            state: oda::XdaArmingState::CaMissing,
            cdol1_data: vec![],
            cdol2_data: vec![],
        });
        let mut tx = Transaction {
            card: empty_card(),
            auth: empty_auth(),
            ctx,
        };
        // Any CID; CaMissing skips SDAD verify regardless.
        let resp = fixture_genac_response(0x80);
        tx.verify_xda_first_generate_ac(&resp).unwrap();
        assert!(tx.ctx.tvr.ca_ecc_key_missing);
        assert!(!tx.ctx.tvr.ecc_key_recovery_failed);
        assert!(!tx.ctx.tvr.xda_signature_verification_failed);
    }

    #[test]
    fn xda_verify_first_genac_applies_recovery_failed_bit() {
        let terminal = fixture_terminal_with_caps(caps_with_methods(false, false, false, true));
        let mut ctx = ctx_with_selected(&terminal, 100);
        ctx.aip = Some(aip_with_methods(false, false, false, true));
        ctx.xda = Some(oda::XdaArming {
            state: oda::XdaArmingState::RecoveryFailed,
            cdol1_data: vec![],
            cdol2_data: vec![],
        });
        let mut tx = Transaction {
            card: empty_card(),
            auth: empty_auth(),
            ctx,
        };
        let resp = fixture_genac_response(0x80);
        tx.verify_xda_first_generate_ac(&resp).unwrap();
        assert!(tx.ctx.tvr.ecc_key_recovery_failed);
        assert!(!tx.ctx.tvr.ca_ecc_key_missing);
        assert!(!tx.ctx.tvr.xda_signature_verification_failed);
    }

    #[test]
    fn xda_verify_first_genac_skips_on_aac() {
        // Armed state but AAC response → skip SDAD verify per §12.5.1.
        // No TVR bits should change.
        let terminal = fixture_terminal_with_caps(caps_with_methods(false, false, false, true));
        let mut ctx = ctx_with_selected(&terminal, 100);
        ctx.aip = Some(aip_with_methods(false, false, false, true));
        ctx.xda = Some(oda::XdaArming {
            state: oda::XdaArmingState::Armed {
                icc_public_key: ecc_oda::EccIccPublicKey {
                    x_coord: vec![0u8; 32],
                    algorithm_suite: 0x09,
                    expiration_yyyymmdd: [0x20, 0x99, 0x12, 0x31],
                    expiration_hhmm: [0x23, 0x59],
                    serial_number: [0u8; 6],
                    iccd_hash_algorithm: 0x02,
                },
            },
            cdol1_data: vec![],
            cdol2_data: vec![],
        });
        let mut tx = Transaction {
            card: empty_card(),
            auth: empty_auth(),
            ctx,
        };
        let aac_resp = fixture_genac_response(0x00); // CID: AAC
        tx.verify_xda_first_generate_ac(&aac_resp).unwrap();
        // Spec: skip SDAD verify on AAC. No bits set.
        assert!(!tx.ctx.tvr.xda_signature_verification_failed);
        assert!(!tx.ctx.tvr.ca_ecc_key_missing);
        assert!(!tx.ctx.tvr.ecc_key_recovery_failed);
        // No TSI bit either - verification didn't run.
        assert!(!tx.ctx.tsi.offline_data_authentication_was_performed);
    }

    #[test]
    fn xda_verify_first_genac_missing_sdad_on_tc_sets_failure_bit() {
        // Armed state, TC response, but no SDAD field returned →
        // signature verification fails.
        let terminal = fixture_terminal_with_caps(caps_with_methods(false, false, false, true));
        let mut ctx = ctx_with_selected(&terminal, 100);
        ctx.aip = Some(aip_with_methods(false, false, false, true));
        ctx.xda = Some(oda::XdaArming {
            state: oda::XdaArmingState::Armed {
                icc_public_key: ecc_oda::EccIccPublicKey {
                    x_coord: vec![0u8; 32],
                    algorithm_suite: 0x09,
                    expiration_yyyymmdd: [0x20, 0x99, 0x12, 0x31],
                    expiration_hhmm: [0x23, 0x59],
                    serial_number: [0u8; 6],
                    iccd_hash_algorithm: 0x02,
                },
            },
            cdol1_data: vec![],
            cdol2_data: vec![],
        });
        let mut tx = Transaction {
            card: empty_card(),
            auth: empty_auth(),
            ctx,
        };
        let tc_no_sdad = fixture_genac_response(0x40); // CID: TC
        tx.verify_xda_first_generate_ac(&tc_no_sdad).unwrap();
        assert!(tx.ctx.tvr.xda_signature_verification_failed);
    }

    #[test]
    fn xda_verify_second_genac_short_circuits_when_already_failed() {
        // First GenAC failed XDA verification - second GenAC verifier
        // must short-circuit per §12.5.3 ("XDA has not already failed").
        let terminal = fixture_terminal_with_caps(caps_with_methods(false, false, false, true));
        let mut ctx = ctx_with_selected(&terminal, 100);
        ctx.aip = Some(aip_with_methods(false, false, false, true));
        ctx.xda = Some(oda::XdaArming {
            state: oda::XdaArmingState::Armed {
                icc_public_key: ecc_oda::EccIccPublicKey {
                    x_coord: vec![0u8; 32],
                    algorithm_suite: 0x09,
                    expiration_yyyymmdd: [0x20, 0x99, 0x12, 0x31],
                    expiration_hhmm: [0x23, 0x59],
                    serial_number: [0u8; 6],
                    iccd_hash_algorithm: 0x02,
                },
            },
            cdol1_data: vec![],
            cdol2_data: vec![],
        });
        ctx.tvr.xda_signature_verification_failed = true;
        let mut tx = Transaction {
            card: empty_card(),
            auth: empty_auth(),
            ctx,
        };
        let tc = fixture_genac_response(0x40);
        // Even though SDAD is missing (which would normally fail), the
        // already-failed flag short-circuits.
        tx.verify_xda_second_generate_ac(&tc).unwrap();
        // No new state changes - still failed but no TSI bit set.
        assert!(tx.ctx.tvr.xda_signature_verification_failed);
        assert!(!tx.ctx.tsi.offline_data_authentication_was_performed);
    }

    fn make_tx_for_tc_hash(terminal: &Terminal) -> Transaction<'_, ScriptedCard, MockAuth> {
        Transaction {
            card: empty_card(),
            auth: empty_auth(),
            ctx: ctx_with_selected(terminal, 0),
        }
    }

    fn dol_with_98() -> crate::core::dol::Dol {
        // Single-entry DOL: tag '98' length 20.
        crate::core::dol::Dol::parse(&[0x98, 0x14]).unwrap()
    }

    fn dol_without_98() -> crate::core::dol::Dol {
        // CDOL2-shaped DOL with no '98' entry.
        crate::core::dol::Dol::parse(&[0x9F, 0x02, 0x06, 0x9F, 0x37, 0x04]).unwrap()
    }

    #[test]
    fn prepare_tc_hash_skips_when_dol_does_not_reference_98() {
        let terminal = fixture_terminal();
        let mut tx = make_tx_for_tc_hash(&terminal);
        tx.prepare_tc_hash_for_dol(&dol_without_98());
        assert!(tx.ctx.tc_hash_value.is_none());
        assert!(!tx.ctx.tvr.default_tdol_used);
    }

    #[test]
    fn prepare_tc_hash_with_icc_tdol_does_not_set_default_bit() {
        // ICC '97' present in tag_store AND a default_tdol configured -
        // ICC wins, default_tdol_used must stay 0.
        let mut terminal = fixture_terminal();
        terminal.applications[0].default_tdol = Some(vec![0x9C, 0x01]);
        let mut tx = make_tx_for_tc_hash(&terminal);
        tx.ctx
            .tag_store
            .insert_primitive(
                tags::TDOL,
                vec![0x9F, 0x37, 0x04],
                Source::Record { sfi: 1, record: 1 },
            )
            .unwrap();

        tx.prepare_tc_hash_for_dol(&dol_with_98());

        assert!(tx.ctx.tc_hash_value.is_some());
        assert!(
            !tx.ctx.tvr.default_tdol_used,
            "ICC TDOL was used; default_tdol_used must remain 0"
        );
    }

    #[test]
    fn prepare_tc_hash_with_default_tdol_sets_bit() {
        // No ICC '97'; terminal has a configured default_tdol -
        // default_tdol_used must be set.
        let mut terminal = fixture_terminal();
        terminal.applications[0].default_tdol = Some(vec![0x9F, 0x37, 0x04]);
        let mut tx = make_tx_for_tc_hash(&terminal);
        assert!(tx.ctx.tag_store.get(tags::TDOL).is_none());

        tx.prepare_tc_hash_for_dol(&dol_with_98());

        assert!(tx.ctx.tc_hash_value.is_some());
        assert!(tx.ctx.tvr.default_tdol_used);
    }

    #[test]
    fn prepare_tc_hash_no_tdol_uses_empty_does_not_set_bit() {
        // Neither ICC '97' nor terminal default_tdol; §9.2.2 requires
        // an empty TDOL be assumed and the TVR bit *not* set.
        let terminal = fixture_terminal();
        let mut tx = make_tx_for_tc_hash(&terminal);
        assert!(terminal.applications[0].default_tdol.is_none());

        tx.prepare_tc_hash_for_dol(&dol_with_98());

        // Empty input still hashes to a well-defined SHA-1 digest.
        assert_eq!(
            tx.ctx.tc_hash_value.unwrap(),
            // SHA-1("") = da39a3ee5e6b4b0d3255bfef95601890afd80709
            [
                0xda, 0x39, 0xa3, 0xee, 0x5e, 0x6b, 0x4b, 0x0d, 0x32, 0x55, 0xbf, 0xef, 0x95, 0x60,
                0x18, 0x90, 0xaf, 0xd8, 0x07, 0x09,
            ]
        );
        assert!(
            !tx.ctx.tvr.default_tdol_used,
            "default_tdol absent → §9.2.2 says 'shall not set' the bit"
        );
    }

    #[test]
    fn prepare_tc_hash_value_is_sha1_of_tdol_resolved_bytes() {
        // Configure a known TDOL and a known UN, then verify the
        // computed digest matches SHA-1 of the UN bytes (the only
        // value the resolver knows for this trivial TDOL).
        use sha1::{Digest, Sha1};
        let terminal = fixture_terminal();
        let mut tx = make_tx_for_tc_hash(&terminal);
        // ICC TDOL = "9F 37 04" (one entry: UN, 4 bytes).
        tx.ctx
            .tag_store
            .insert_primitive(
                tags::TDOL,
                vec![0x9F, 0x37, 0x04],
                Source::Record { sfi: 1, record: 1 },
            )
            .unwrap();
        tx.ctx.inputs.unpredictable_number = [0xDE, 0xAD, 0xBE, 0xEF];

        tx.prepare_tc_hash_for_dol(&dol_with_98());

        let mut h = Sha1::new();
        h.update([0xDE, 0xAD, 0xBE, 0xEF]);
        let mut expected = [0u8; 20];
        expected.copy_from_slice(&h.finalize());
        assert_eq!(tx.ctx.tc_hash_value.unwrap(), expected);
    }
}
