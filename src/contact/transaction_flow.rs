//! Book 3 §8 Transaction Flow - host-mediated, over Book 1 §12 Application
//! Selection and the Book 3 §10 functions.
//!
//! Stepwise driver for terminals where application selection, PIN entry and
//! online authorisation are mediated by a host: each entry point runs the
//! transaction as far as it can and returns a [`TransactionFlowStep`] saying
//! what the host must provide before the flow can resume.

use std::convert::Infallible;

use crate::contact::application_selection::{Candidate, FinalSelectionOutcome, final_selection};
use crate::contact::card_action_analysis::CardAction;
use crate::contact::cardholder_verification::{
    CvmExecutionResult, OfflinePinError, recover_pin_encipherment_public_key,
    verify_enciphered_offline_pin, verify_plaintext_offline_pin,
};
use crate::contact::dol_resolve::{DolResolveExt, bcd_u64};
use crate::contact::issuer_script::ScriptTag;
use crate::contact::online_processing::{
    OnlineAuthorisation, OnlineAuthorisationOutcome, OnlineAuthorisationResponse,
    second_generate_ac_after_online,
};
use crate::contact::processing_restrictions::TransactionCategory;
use crate::contact::transaction::{CvmFlags, TransactionContext};
use crate::contact::transaction_driver::{DriverError, Transaction};
use crate::core::apdu::sw;
use crate::core::application_cryptogram_type::ApplicationCryptogramType;
use crate::core::card_reader::CardReader;
use crate::core::crl::CrlEntry;
use crate::core::dol::Dol;
use crate::core::ecc_oda::EccCaPublicKey;
use crate::core::error::Error;
use crate::core::generate_ac::{GenerateAcResponse, SignatureRequest};
use crate::core::oda::CaPublicKey;
use crate::core::tag_store::Source;
use crate::core::tags;
use crate::de::authorisation_response_code::AuthorisationResponseCode;
use crate::de::cardholder_verification_method_list::CardholderVerificationMethod;
use crate::de::cardholder_verification_method_results::CardholderVerificationMethodResults;
use crate::de::terminal_type::Environment;
use crate::de::terminal_verification_results::TerminalVerificationResults;

/// Placeholder authoriser: online authorisation surfaces to the host as
/// [`TransactionFlowStep::OnlineRequest`] and resumes via
/// [`submit_authorisation_response`] or [`submit_unable_to_go_online`], so
/// the [`OnlineAuthorisation`] callback is never invoked.
pub struct HostMediated;

impl OnlineAuthorisation for HostMediated {
    type Error = Infallible;

    fn authorise(
        &mut self,
        _ctx: &TransactionContext<'_>,
        _first_ac: &GenerateAcResponse,
    ) -> Result<OnlineAuthorisationResponse, Infallible> {
        unreachable!("host-mediated flow pauses at TransactionFlowStep::OnlineRequest")
    }
}

pub type TransactionFlowResult<T, E> = Result<T, DriverError<E, Infallible>>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PinRequirement {
    OfflinePin,
    OnlinePin,
}

/// Book 4 §6.3 / Book 3 §8.1 terminate conditions surfaced as outcomes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TerminationReason {
    NoMutuallySupportedApplication,
    ServiceNotAllowed,
    InvalidCryptogramType,
}

#[derive(Debug)]
pub enum TransactionFlowStep {
    /// Book 1 §12.4 requires cardholder selection or confirmation; resume via
    /// [`continue_with_application`].
    SelectApplication {
        candidates: Vec<Candidate>,
    },
    /// Book 3 §10.5 selected a PIN CVM; resume via [`submit_pin`].
    CardholderVerification {
        requirement: PinRequirement,
    },
    /// First GENERATE AC returned an ARQC (Book 3 §10.8); Online Processing
    /// (§10.9) resumes via [`submit_authorisation_response`], or
    /// [`submit_unable_to_go_online`] if the authorisation cannot complete.
    OnlineRequest {
        first_generate_ac: GenerateAcResponse,
    },
    Approved {
        generate_ac: GenerateAcResponse,
    },
    Declined {
        generate_ac: GenerateAcResponse,
    },
    Terminated {
        reason: TerminationReason,
    },
}

/// Book 1 §12.3 discovery + §12.4 final selection, auto-continuing into the
/// transaction when selection needs no cardholder input. Stamps the UN into
/// the tag store for later SDAD verification (Book 2 §6.6.2).
pub fn start<C: CardReader>(
    tx: &mut Transaction<'_, C, HostMediated>,
    capks: &[CaPublicKey],
    ecc_capks: &[EccCaPublicKey],
    crl: &[CrlEntry],
    trm_random_selection_number: Option<u8>,
) -> TransactionFlowResult<TransactionFlowStep, C::Error> {
    if tx.ctx.tag_store.get(tags::UNPREDICTABLE_NUMBER).is_none() {
        tx.ctx.tag_store.insert_primitive(
            tags::UNPREDICTABLE_NUMBER,
            tx.ctx.inputs.unpredictable_number.to_vec(),
            Source::TerminalGenerated,
        )?;
    }

    let mut candidates = tx.build_candidate_list()?;
    let selection_supported = tx
        .ctx
        .terminal
        .cardholder_selection_and_confirmation_supported;
    loop {
        return match final_selection(&candidates, selection_supported) {
            FinalSelectionOutcome::Terminate => Ok(TransactionFlowStep::Terminated {
                reason: TerminationReason::NoMutuallySupportedApplication,
            }),
            FinalSelectionOutcome::Select(i) => {
                let df_name = candidates[i].df_name.clone();
                match attempt_application(
                    tx,
                    capks,
                    ecc_capks,
                    crl,
                    trm_random_selection_number,
                    &df_name,
                )? {
                    ApplicationAttempt::Step(step) => Ok(step),
                    ApplicationAttempt::Eliminated => {
                        candidates.remove(i);
                        continue;
                    }
                }
            }
            FinalSelectionOutcome::ConfirmAndSelect(i) => {
                Ok(TransactionFlowStep::SelectApplication {
                    candidates: vec![candidates.swap_remove(i)],
                })
            }
            FinalSelectionOutcome::OfferToCardholder(order) => {
                let mut slots: Vec<Option<Candidate>> = candidates.into_iter().map(Some).collect();
                let candidates = order
                    .into_iter()
                    .filter_map(|i| slots.get_mut(i).and_then(Option::take))
                    .collect();
                Ok(TransactionFlowStep::SelectApplication { candidates })
            }
        };
    }
}

/// Resume after the host selected or confirmed an application. If the
/// application cannot be used it is removed from `candidates` and the
/// remaining list is re-presented (Book 1 §12.4 - once a cardholder-chosen
/// application is removed, no application is selected without the
/// cardholder).
pub fn continue_with_application<C: CardReader>(
    tx: &mut Transaction<'_, C, HostMediated>,
    capks: &[CaPublicKey],
    ecc_capks: &[EccCaPublicKey],
    crl: &[CrlEntry],
    trm_random_selection_number: Option<u8>,
    candidates: &mut Vec<Candidate>,
    df_name: &[u8],
) -> TransactionFlowResult<TransactionFlowStep, C::Error> {
    match attempt_application(
        tx,
        capks,
        ecc_capks,
        crl,
        trm_random_selection_number,
        df_name,
    )? {
        ApplicationAttempt::Step(step) => Ok(step),
        ApplicationAttempt::Eliminated => {
            candidates.retain(|c| c.df_name != df_name);
            Ok(if candidates.is_empty() {
                TransactionFlowStep::Terminated {
                    reason: TerminationReason::NoMutuallySupportedApplication,
                }
            } else {
                TransactionFlowStep::SelectApplication {
                    candidates: candidates.clone(),
                }
            })
        }
    }
}

/// Book 3 §10.5 resume - `pin` as digit values for offline CVMs (ignored for
/// online PIN, which the host captures and forwards with the authorisation
/// request); `fill_random` supplies Book 2 §7.2 padding.
pub fn submit_pin<C: CardReader>(
    tx: &mut Transaction<'_, C, HostMediated>,
    capks: &[CaPublicKey],
    trm_random_selection_number: Option<u8>,
    pin: &[u8],
    fill_random: impl FnMut(&mut [u8]) -> bool,
) -> TransactionFlowResult<TransactionFlowStep, C::Error> {
    run_cardholder_verification(tx, capks, PinEntry::Entered(pin), fill_random)?;
    continue_after_cardholder_verification(tx, trm_random_selection_number)
}

/// Book 4 §6.3.4.3 PIN Entry Bypass; every subsequent PIN-related CVM in
/// this transaction is also bypassed.
pub fn bypass_pin_entry<C: CardReader>(
    tx: &mut Transaction<'_, C, HostMediated>,
    capks: &[CaPublicKey],
    trm_random_selection_number: Option<u8>,
) -> TransactionFlowResult<TransactionFlowStep, C::Error> {
    run_cardholder_verification(tx, capks, PinEntry::Bypassed, |_| false)?;
    continue_after_cardholder_verification(tx, trm_random_selection_number)
}

/// Book 3 §10.9–§10.11: EXTERNAL AUTHENTICATE, issuer scripts, second
/// GENERATE AC. Issuer ARC classification is acquirer-domain (Book 4
/// Annex A6), so the host supplies `outcome`; a first-GENERATE-AC TC
/// (Book 4 §6.3.2.2.4) completes without a second GENERATE AC.
pub fn submit_authorisation_response<C: CardReader>(
    tx: &mut Transaction<'_, C, HostMediated>,
    first_generate_ac: &GenerateAcResponse,
    response: &OnlineAuthorisationResponse,
    outcome: OnlineAuthorisationOutcome,
) -> TransactionFlowResult<TransactionFlowStep, C::Error> {
    use crate::de::cryptogram_information_data::ApplicationCryptogramType as Cid;

    tx.online_card_authentication(response)?;
    tx.process_issuer_scripts(&response.issuer_scripts, ScriptTag::BeforeFinalGenerateAc)?;
    store_authorisation_response_code(tx, response.authorisation_response_code)?;

    let step = if matches!(first_generate_ac.cid.cryptogram_type, Cid::Tc) {
        match outcome {
            OnlineAuthorisationOutcome::Approved => TransactionFlowStep::Approved {
                generate_ac: first_generate_ac.clone(),
            },
            OnlineAuthorisationOutcome::Declined => TransactionFlowStep::Declined {
                generate_ac: first_generate_ac.clone(),
            },
        }
    } else {
        complete_with_second_generate_ac(tx, second_generate_ac_after_online(outcome))?
    };
    tx.process_issuer_scripts(&response.issuer_scripts, ScriptTag::AfterFinalGenerateAc)?;
    Ok(step)
}

/// Book 3 §10.7 - default action when the host was unable to process the
/// transaction online. After an XDA failure the transaction declines
/// (Book 4 §6.3.2.2.4); a first-GENERATE-AC TC completes without a second
/// GENERATE AC.
pub fn submit_unable_to_go_online<C: CardReader>(
    tx: &mut Transaction<'_, C, HostMediated>,
    first_generate_ac: &GenerateAcResponse,
) -> TransactionFlowResult<TransactionFlowStep, C::Error> {
    use crate::de::cryptogram_information_data::ApplicationCryptogramType as Cid;

    if xda_failed(&tx.ctx.tvr) {
        store_authorisation_response_code(
            tx,
            AuthorisationResponseCode::UNABLE_TO_GO_ONLINE_OFFLINE_DECLINED,
        )?;
        if matches!(first_generate_ac.cid.cryptogram_type, Cid::Tc) {
            return Ok(TransactionFlowStep::Declined {
                generate_ac: first_generate_ac.clone(),
            });
        }
        return complete_with_second_generate_ac(tx, ApplicationCryptogramType::Aac);
    }

    let cryptogram = tx.ctx.unable_to_go_online_decision()?;
    let authorisation_response_code = match cryptogram {
        ApplicationCryptogramType::Tc => {
            AuthorisationResponseCode::UNABLE_TO_GO_ONLINE_OFFLINE_APPROVED
        }
        _ => AuthorisationResponseCode::UNABLE_TO_GO_ONLINE_OFFLINE_DECLINED,
    };
    store_authorisation_response_code(tx, authorisation_response_code)?;
    complete_with_second_generate_ac(tx, cryptogram)
}

#[derive(Clone, Copy)]
enum PinEntry<'p> {
    NotCollected,
    Entered(&'p [u8]),
    /// Book 4 §6.3.4.3.
    Bypassed,
}

enum ApplicationAttempt {
    Step(TransactionFlowStep),
    /// Book 1 §12.4 / Book 3 §10.1 - the application is eliminated from
    /// consideration and application selection resumes.
    Eliminated,
}

/// Book 3 §10.1–§10.5: SELECT, GPO, READ, ODA, processing restrictions, CVM.
fn attempt_application<C: CardReader>(
    tx: &mut Transaction<'_, C, HostMediated>,
    capks: &[CaPublicKey],
    ecc_capks: &[EccCaPublicKey],
    crl: &[CrlEntry],
    trm_random_selection_number: Option<u8>,
    df_name: &[u8],
) -> TransactionFlowResult<ApplicationAttempt, C::Error> {
    // Book 1 §12.4 - a failed or malformed final SELECT eliminates the
    // candidate and selection resumes.
    let fci = match tx.select_application(df_name) {
        Ok(fci) => fci,
        Err(DriverError::Transport(e)) => return Err(DriverError::Transport(e)),
        Err(_) => return Ok(ApplicationAttempt::Eliminated),
    };
    let pdol_data = fci
        .pdol
        .as_ref()
        .map(|d| d.resolve(&tx.ctx))
        .unwrap_or_default();
    // Book 3 §10.1 - GPO '6985' eliminates the candidate and selection
    // resumes.
    if let Err(e) = tx.initiate(&pdol_data) {
        return match e {
            DriverError::StatusWord {
                sw: sw::CONDITIONS_OF_USE_NOT_SATISFIED,
                ..
            } => Ok(ApplicationAttempt::Eliminated),
            e => Err(e),
        };
    }
    let read = tx.read_application_data()?;
    tx.perform_offline_data_authentication(capks, ecc_capks, crl, &read.oda_input)?;

    let category = TransactionCategory::from_transaction_type(tx.ctx.inputs.transaction_type);
    let has_cashback = tx.ctx.inputs.amount_other > 0;
    tx.ctx.process_restrictions(category, has_cashback)?;

    match run_cardholder_verification(tx, capks, PinEntry::NotCollected, |_| false)? {
        Some(requirement) => Ok(ApplicationAttempt::Step(
            TransactionFlowStep::CardholderVerification { requirement },
        )),
        None => continue_after_cardholder_verification(tx, trm_random_selection_number)
            .map(ApplicationAttempt::Step),
    }
}

/// Book 3 §10.5, gated on AIP byte 1 bit 5 (with '9F34' = '3F0000' when the
/// card does not support cardholder verification, Book 4 §6.3.4.5). Without a
/// PIN on hand the CVM list runs against a snapshot: if a rule demands a PIN,
/// the CVM mutations are rolled back and the requirement is reported so the
/// host can collect it and resume via [`submit_pin`].
fn run_cardholder_verification<C: CardReader>(
    tx: &mut Transaction<'_, C, HostMediated>,
    capks: &[CaPublicKey],
    pin: PinEntry<'_>,
    mut fill_random: impl FnMut(&mut [u8]) -> bool,
) -> TransactionFlowResult<Option<PinRequirement>, C::Error> {
    let aip_supported = tx
        .ctx
        .aip
        .as_ref()
        .is_some_and(|a| a.cardholder_verification_is_supported);
    if !aip_supported {
        if tx.ctx.tag_store.get(tags::CVM_RESULTS).is_none() {
            tx.ctx.tag_store.insert_primitive(
                tags::CVM_RESULTS,
                CardholderVerificationMethodResults::NO_CVM_PERFORMED
                    .to_bytes()
                    .to_vec(),
                Source::TerminalGenerated,
            )?;
        }
        return Ok(None);
    }

    let flags = cvm_flags(&tx.ctx);
    let pin_encipherment_public_key = recover_pin_encipherment_public_key(&tx.ctx, capks);

    let Transaction { card, ctx, .. } = tx;
    let snapshot = (ctx.tag_store.clone(), ctx.tvr, ctx.tsi);
    let mut required = None;
    let mut pin_failure: Option<OfflinePinError<C::Error>> = None;
    ctx.cardholder_verification(flags, |rule| match rule.method() {
        CardholderVerificationMethod::NoCvmRequired => CvmExecutionResult::Successful,
        CardholderVerificationMethod::Signature => CvmExecutionResult::Unknown,
        CardholderVerificationMethod::PlaintextPinVerificationPerformedByIcc
        | CardholderVerificationMethod::PlaintextPinVerificationPerformedByIccAndSignature => {
            match pin {
                PinEntry::Bypassed => CvmExecutionResult::PinEntryBypassed,
                PinEntry::Entered(pin) => match verify_plaintext_offline_pin(card, pin) {
                    Ok(result) => result,
                    Err(e) => {
                        pin_failure = Some(e);
                        CvmExecutionResult::Failed
                    }
                },
                PinEntry::NotCollected => {
                    required = Some(PinRequirement::OfflinePin);
                    CvmExecutionResult::Failed
                }
            }
        }
        CardholderVerificationMethod::EncipheredPinVerificationPerformedByIcc
        | CardholderVerificationMethod::EncipheredPinVerificationPerformedByIccAndSignature => {
            match (&pin_encipherment_public_key, pin) {
                (_, PinEntry::Bypassed) => CvmExecutionResult::PinEntryBypassed,
                // Book 2 §7.1 rule 3 - no usable key: PIN encipherment failed.
                (None, _) => CvmExecutionResult::Failed,
                (Some(pk), PinEntry::Entered(pin)) => {
                    match verify_enciphered_offline_pin(card, pin, pk, &mut fill_random) {
                        Ok(result) => result,
                        Err(e) => {
                            pin_failure = Some(e);
                            CvmExecutionResult::Failed
                        }
                    }
                }
                (Some(_), PinEntry::NotCollected) => {
                    required = Some(PinRequirement::OfflinePin);
                    CvmExecutionResult::Failed
                }
            }
        }
        CardholderVerificationMethod::EncipheredPinVerifiedOnline => match pin {
            PinEntry::Bypassed => CvmExecutionResult::PinEntryBypassed,
            PinEntry::Entered(_) => CvmExecutionResult::Successful,
            PinEntry::NotCollected => {
                required = Some(PinRequirement::OnlinePin);
                CvmExecutionResult::Failed
            }
        },
        _ => CvmExecutionResult::PinPadNotWorkingOrAbsent,
    })?;

    if let Some(failure) = pin_failure {
        return Err(match failure {
            OfflinePinError::Transport(e) => DriverError::Transport(e),
            // Book 3 §6.3.5 - unallocated status word terminates.
            OfflinePinError::UnallocatedStatusWord(sw) => DriverError::StatusWord {
                command: "VERIFY",
                sw,
            },
        });
    }
    if let Some(requirement) = required {
        (ctx.tag_store, ctx.tvr, ctx.tsi) = snapshot;
        return Ok(Some(requirement));
    }
    Ok(None)
}

/// Book 3 §10.6–§10.8: terminal risk management (always performed, §10.6),
/// terminal action analysis, first GENERATE AC, card action analysis.
fn continue_after_cardholder_verification<C: CardReader>(
    tx: &mut Transaction<'_, C, HostMediated>,
    trm_random_selection_number: Option<u8>,
) -> TransactionFlowResult<TransactionFlowStep, C::Error> {
    tx.run_terminal_risk_management(trm_random_selection_number.map(|n| n.clamp(1, 99)), None)?;

    let cryptogram = tx.ctx.terminal_action_analysis(false)?;
    let cdol1_bytes = tx
        .ctx
        .tag_store
        .get(tags::CDOL1)
        .map(<[u8]>::to_vec)
        .ok_or(Error::MissingMandatory { tag: tags::CDOL1 })?;
    let cdol1 = Dol::parse(&cdol1_bytes)?;
    tx.prepare_tc_hash_for_dol(&cdol1);
    let cdol1_data = cdol1.resolve(&tx.ctx);

    let signature = signature_request(&tx.ctx, cryptogram);
    let first = tx.first_generate_ac(cryptogram, signature, cdol1_data)?;
    let signature_verified = verify_generate_ac_signature(tx, &first, signature, false);

    let action = tx.ctx.card_action_analysis(&first).action;

    // Book 4 §6.3.2.2.4 - Terminal Processing After First GENERATE AC XDA
    // Failure.
    if matches!(signature, SignatureRequest::Xda)
        && xda_failed(&tx.ctx.tvr)
        && matches!(action, CardAction::Approve | CardAction::GoOnline)
    {
        return if tx.ctx.xda_failure_denial_decision()? {
            match action {
                CardAction::Approve => Ok(TransactionFlowStep::Declined { generate_ac: first }),
                _ => {
                    store_authorisation_response_code(
                        tx,
                        AuthorisationResponseCode::OFFLINE_DECLINED,
                    )?;
                    complete_with_second_generate_ac(tx, ApplicationCryptogramType::Aac)
                }
            }
        } else {
            Ok(TransactionFlowStep::OnlineRequest {
                first_generate_ac: first,
            })
        };
    }

    match action {
        // Book 4 §6.3.2.1 - a TC with a failed CDA signature is declined
        // offline without a second GENERATE AC.
        CardAction::Approve if !signature_verified => {
            Ok(TransactionFlowStep::Declined { generate_ac: first })
        }
        CardAction::Approve => Ok(TransactionFlowStep::Approved { generate_ac: first }),
        CardAction::Decline => Ok(TransactionFlowStep::Declined { generate_ac: first }),
        // Book 4 §6.3.2.1 - an ARQC with a failed CDA signature completes
        // with an immediate second GENERATE AC requesting an AAC.
        CardAction::GoOnline if !signature_verified => {
            store_authorisation_response_code(tx, AuthorisationResponseCode::OFFLINE_DECLINED)?;
            complete_with_second_generate_ac(tx, ApplicationCryptogramType::Aac)
        }
        CardAction::GoOnline => Ok(TransactionFlowStep::OnlineRequest {
            first_generate_ac: first,
        }),
        CardAction::ServiceNotAllowed => Ok(TransactionFlowStep::Terminated {
            reason: TerminationReason::ServiceNotAllowed,
        }),
        CardAction::InvalidCryptogramType => Ok(TransactionFlowStep::Terminated {
            reason: TerminationReason::InvalidCryptogramType,
        }),
    }
}

/// Book 4 §6.3.2.2.1–§6.3.2.2.3 - the three XDA failure kinds.
fn xda_failed(tvr: &TerminalVerificationResults) -> bool {
    tvr.ca_ecc_key_missing || tvr.ecc_key_recovery_failed || tvr.xda_signature_verification_failed
}

/// Book 3 §10.11 - second GENERATE AC. CDOL2 is mandatory (§7.2 Table 28);
/// per §9.3 any higher-level or undefined cryptogram in the response is
/// treated as an AAC.
fn complete_with_second_generate_ac<C: CardReader>(
    tx: &mut Transaction<'_, C, HostMediated>,
    cryptogram: ApplicationCryptogramType,
) -> TransactionFlowResult<TransactionFlowStep, C::Error> {
    let cdol2_bytes = tx
        .ctx
        .tag_store
        .get(tags::CDOL2)
        .map(<[u8]>::to_vec)
        .ok_or(Error::MissingMandatory { tag: tags::CDOL2 })?;
    let cdol2 = Dol::parse(&cdol2_bytes)?;
    tx.prepare_tc_hash_for_dol(&cdol2);
    let cdol2_data = cdol2.resolve(&tx.ctx);

    let signature = signature_request(&tx.ctx, cryptogram);
    let second = tx.second_generate_ac(cryptogram, signature, cdol2_data)?;
    let signature_verified = verify_generate_ac_signature(tx, &second, signature, true);

    use crate::de::cryptogram_information_data::ApplicationCryptogramType as Cid;
    match second.cid.cryptogram_type {
        Cid::Tc if signature_verified => Ok(TransactionFlowStep::Approved {
            generate_ac: second,
        }),
        _ => Ok(TransactionFlowStep::Declined {
            generate_ac: second,
        }),
    }
}

/// Book 4 Annex A6 - stamp the '8A' the second GENERATE AC's CDOL2 resolves.
fn store_authorisation_response_code<C: CardReader>(
    tx: &mut Transaction<'_, C, HostMediated>,
    code: AuthorisationResponseCode,
) -> TransactionFlowResult<(), C::Error> {
    if tx
        .ctx
        .tag_store
        .get(tags::AUTHORISATION_RESPONSE_CODE)
        .is_none()
    {
        tx.ctx.tag_store.insert_primitive(
            tags::AUTHORISATION_RESPONSE_CODE,
            code.to_bytes().to_vec(),
            Source::TerminalGenerated,
        )?;
    }
    Ok(())
}

/// CDA Mode 1 (Book 2 Annex D4); XDA always requested when selected (§12.5.1).
fn signature_request(
    ctx: &TransactionContext<'_>,
    cryptogram: ApplicationCryptogramType,
) -> SignatureRequest {
    if ctx.xda.is_some() {
        SignatureRequest::Xda
    } else if ctx.cda.is_some()
        && matches!(
            cryptogram,
            ApplicationCryptogramType::Tc | ApplicationCryptogramType::Arqc
        )
    {
        SignatureRequest::Cda
    } else {
        SignatureRequest::None
    }
}

/// Book 2 §6.6.2 / §12.5.3. Returns false when the dynamic signature failed
/// verification (TVR bits are set by the driver). XDA arming failures
/// (CA key missing / recovery failed) only set TVR bits and the transaction
/// continues (§12.5.1), as does an XDA failure already recorded on the first
/// GENERATE AC (§12.5.3).
fn verify_generate_ac_signature<C: CardReader>(
    tx: &mut Transaction<'_, C, HostMediated>,
    response: &GenerateAcResponse,
    request: SignatureRequest,
    is_second: bool,
) -> bool {
    use crate::de::cryptogram_information_data::ApplicationCryptogramType as Cid;
    match request {
        SignatureRequest::None => true,
        SignatureRequest::Cda => {
            // §6.6.2 - an AAC carries no CDA signature.
            if matches!(response.cid.cryptogram_type, Cid::Aac) {
                return true;
            }
            let verified = if is_second {
                tx.verify_cda_second_generate_ac(response)
            } else {
                tx.verify_cda_first_generate_ac(response)
            };
            verified.is_ok()
        }
        SignatureRequest::Xda => {
            let already_failed = tx.ctx.tvr.xda_signature_verification_failed;
            let _ = if is_second {
                tx.verify_xda_second_generate_ac(response)
            } else {
                tx.verify_xda_first_generate_ac(response)
            };
            already_failed || !tx.ctx.tvr.xda_signature_verification_failed
        }
    }
}

fn cvm_flags(ctx: &TransactionContext<'_>) -> CvmFlags {
    let transaction_currency = bcd_u64(ctx.inputs.transaction_currency_code as u64, 2);
    let category = TransactionCategory::from_transaction_type(ctx.inputs.transaction_type);
    let unattended = matches!(
        ctx.terminal.terminal_type.environment(),
        Environment::Unattended
    );
    CvmFlags {
        transaction_in_application_currency: ctx.tag_store.get(tags::APPLICATION_CURRENCY_CODE)
            == Some(transaction_currency.as_slice()),
        transaction_is_unattended_cash: unattended && matches!(category, TransactionCategory::Cash),
        transaction_is_manual_cash: false,
        transaction_is_purchase_with_cashback: matches!(category, TransactionCategory::Purchase)
            && ctx.inputs.amount_other > 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::contact::terminal::{Terminal, TerminalApplication};
    use crate::contact::transaction::{TransactionContext, TransactionInputs};
    use crate::core::apdu::{Command, Response};
    use crate::de::additional_terminal_capabilities::AdditionalTerminalCapabilities;
    use crate::de::terminal_capabilities::TerminalCapabilities;
    use crate::de::terminal_type::TerminalType;

    /// Replies '6A82' (file not found) to every command.
    struct NoFilesCard;

    impl CardReader for NoFilesCard {
        type Error = Error;

        fn transmit(&mut self, _command: &Command) -> Result<Response, Error> {
            Response::parse(&[0x6A, 0x82])
        }
    }

    /// Accepts SELECT, rejects GET PROCESSING OPTIONS with '6985'.
    struct GpoRefusedCard;

    impl CardReader for GpoRefusedCard {
        type Error = Error;

        fn transmit(&mut self, command: &Command) -> Result<Response, Error> {
            if command.to_bytes()?.get(1) == Some(&0xA4) {
                // Minimal FCI: 6F 07 84 05 <5-byte DF name>.
                return Response::parse(&[0x6F, 0x07, 0x84, 0x05, 0xA0, 0, 0, 0, 0x03, 0x90, 0x00]);
            }
            Response::parse(&[0x69, 0x85])
        }
    }

    fn sample_terminal() -> Terminal {
        Terminal {
            terminal_type: TerminalType(0x25),
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
                aid: vec![0xA0, 0, 0, 0, 0x03],
                partial_match_allowed: true,
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

    fn transaction<C: CardReader>(
        card: C,
        terminal: &Terminal,
    ) -> Transaction<'_, C, HostMediated> {
        let inputs = TransactionInputs {
            unpredictable_number: [1, 2, 3, 4],
            ..Default::default()
        };
        Transaction {
            card,
            auth: HostMediated,
            ctx: TransactionContext::new(terminal, inputs),
        }
    }

    #[test]
    fn start_terminates_when_no_candidates() {
        let terminal = sample_terminal();
        let mut tx = transaction(NoFilesCard, &terminal);
        let step = start(&mut tx, &[], &[], &[], None).unwrap();
        assert!(matches!(
            step,
            TransactionFlowStep::Terminated {
                reason: TerminationReason::NoMutuallySupportedApplication
            }
        ));
        assert_eq!(
            tx.ctx.tag_store.get(tags::UNPREDICTABLE_NUMBER),
            Some(&[1u8, 2, 3, 4][..])
        );
    }

    /// Book 3 §10.1 - GPO '6985' eliminates the candidate; with no other
    /// candidate the transaction terminates instead of erroring.
    #[test]
    fn gpo_conditions_not_satisfied_eliminates_candidate() {
        let terminal = sample_terminal();
        let mut tx = transaction(GpoRefusedCard, &terminal);
        let step = start(&mut tx, &[], &[], &[], None).unwrap();
        assert!(matches!(
            step,
            TransactionFlowStep::Terminated {
                reason: TerminationReason::NoMutuallySupportedApplication
            }
        ));
    }
}
