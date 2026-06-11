//! Book 3 §10.5 p.102 - Cardholder Verification.

use crate::contact::transaction::TransactionContext;
use crate::core::apdu::{Command, sw};
use crate::core::card_reader::CardReader;
use crate::core::oda::{CaPublicKey, IccPublicKey, IssuerPublicKey};
use crate::core::{get_challenge, oda, pin_encipherment, tags, verify};
use crate::de::cardholder_verification_method_list::{
    CardholderVerificationMethod, CardholderVerificationMethodCondition,
    CardholderVerificationMethodList, CardholderVerificationMethodRule,
};
use crate::de::cardholder_verification_method_results::CardholderVerificationMethodResults;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct CvmTerminalSupport {
    pub plaintext_offline_pin_by_icc: bool,
    pub enciphered_pin_verified_online: bool,
    pub plaintext_offline_pin_by_icc_and_signature: bool,
    /// RSA-ODE OR ECC-ODE (Book 4 Table 26 b5|b1).
    pub enciphered_offline_pin_by_icc: bool,
    pub enciphered_offline_pin_by_icc_and_signature: bool,
    pub signature: bool,
    pub no_cvm_required: bool,

    pub offline_facial: bool,
    pub online_facial: bool,
    pub offline_finger: bool,
    pub online_finger: bool,
    pub offline_palm: bool,
    pub online_palm: bool,
    pub offline_iris: bool,
    pub online_iris: bool,
    pub offline_voice: bool,
    pub online_voice: bool,
}

impl CvmTerminalSupport {
    pub fn supports(&self, method: CardholderVerificationMethod) -> bool {
        use CardholderVerificationMethod::*;
        match method {
            FailCvmProcessing => true,
            PlaintextPinVerificationPerformedByIcc => self.plaintext_offline_pin_by_icc,
            EncipheredPinVerifiedOnline => self.enciphered_pin_verified_online,
            PlaintextPinVerificationPerformedByIccAndSignature => {
                self.plaintext_offline_pin_by_icc_and_signature
            }
            EncipheredPinVerificationPerformedByIcc => self.enciphered_offline_pin_by_icc,
            EncipheredPinVerificationPerformedByIccAndSignature => {
                self.enciphered_offline_pin_by_icc_and_signature
            }
            FacialBiometricVerifiedOfflineByIcc => self.offline_facial,
            FacialBiometricVerifiedOnline => self.online_facial,
            FingerBiometricVerifiedOfflineByIcc => self.offline_finger,
            FingerBiometricVerifiedOnline => self.online_finger,
            PalmBiometricVerifiedOfflineByIcc => self.offline_palm,
            PalmBiometricVerifiedOnline => self.online_palm,
            IrisBiometricVerifiedOfflineByIcc => self.offline_iris,
            IrisBiometricVerifiedOnline => self.online_iris,
            VoiceBiometricVerifiedOfflineByIcc => self.offline_voice,
            VoiceBiometricVerifiedOnline => self.online_voice,
            Signature => self.signature,
            NoCvmRequired => self.no_cvm_required,
            Rfu(_)
            | ReservedForIndividualPaymentSystems(_)
            | ReservedForIssuer(_)
            | NotAvailableForUse => false,
        }
    }

    pub fn supports_any_offline_pin(&self) -> bool {
        self.plaintext_offline_pin_by_icc
            || self.enciphered_offline_pin_by_icc
            || self.plaintext_offline_pin_by_icc_and_signature
            || self.enciphered_offline_pin_by_icc_and_signature
    }
}

#[derive(Debug, Clone, Copy)]
pub struct CvmContext {
    pub support: CvmTerminalSupport,

    pub transaction_in_application_currency: bool,
    /// Application-currency minor units.
    pub amount_authorised: u32,

    pub transaction_is_unattended_cash: bool,
    pub transaction_is_manual_cash: bool,
    pub transaction_is_purchase_with_cashback: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CvmExecutionResult {
    Successful,
    Unknown,
    Failed,
    PinEntryBypassed,
    PinPadNotWorkingOrAbsent,
    PinTryLimitExceeded,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct CvmTvrUpdates {
    pub cardholder_verification_was_not_successful: bool,
    pub unrecognised_cvm: bool,
    pub pin_try_limit_exceeded: bool,
    pub pin_entry_required_and_pin_pad_not_present_or_not_working: bool,
    pub pin_entry_required_pin_pad_present_but_pin_was_not_entered: bool,
    pub online_cvm_captured: bool,
    pub a_selected_biometric_type_not_supported: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CvmProcessingOutcome {
    pub cvm_results: [u8; 3],
    pub tvr_updates: CvmTvrUpdates,
    pub tsi_cardholder_verification_was_performed: bool,
}

pub fn process_cvm_list<F>(
    list: Option<&CardholderVerificationMethodList>,
    ctx: &CvmContext,
    mut perform: F,
) -> CvmProcessingOutcome
where
    F: FnMut(&CardholderVerificationMethodRule) -> CvmExecutionResult,
{
    // §10.5 - empty/absent CVM List: no TSI bit, "No CVM performed".
    let list = match list {
        Some(l) if !l.rules.is_empty() => l,
        _ => {
            return CvmProcessingOutcome {
                cvm_results: CardholderVerificationMethodResults::NO_CVM_PERFORMED.to_bytes(),
                tvr_updates: CvmTvrUpdates::default(),
                tsi_cardholder_verification_was_performed: false,
            };
        }
    };

    let mut tvr = CvmTvrUpdates::default();
    let mut last_satisfied: Option<&CardholderVerificationMethodRule> = None;

    for rule in &list.rules {
        let method = rule.method();
        let condition = rule.condition();

        // §10.5 step A - condition.
        let satisfied = evaluate_condition(condition, ctx, list.amount_x, list.amount_y, method);
        if !satisfied {
            continue;
        }
        last_satisfied = Some(rule);

        // §10.5 step B - recognised.
        if !is_method_recognised(method) {
            tvr.unrecognised_cvm = true;
            if rule.apply_succeeding_cv_rule_if_unsuccessful() {
                continue;
            }
            tvr.cardholder_verification_was_not_successful = true;
            return CvmProcessingOutcome {
                cvm_results: [0x3F, 0x00, 0x01],
                tvr_updates: tvr,
                tsi_cardholder_verification_was_performed: true,
            };
        }

        // §10.5 step C - supported. Condition '03' folds support into the condition.
        let supported = matches!(
            condition,
            CardholderVerificationMethodCondition::IfTerminalSupportsTheCvm
        ) || ctx.support.supports(method);
        if !supported {
            apply_unsupported_tvr_bits(method, &ctx.support, &mut tvr);
            if rule.apply_succeeding_cv_rule_if_unsuccessful() {
                continue;
            }
            tvr.cardholder_verification_was_not_successful = true;
            return CvmProcessingOutcome {
                cvm_results: [rule.cvm, rule.condition, 0x01],
                tvr_updates: tvr,
                tsi_cardholder_verification_was_performed: true,
            };
        }

        // §10.5 step D - Fail CVM Processing ignores b7.
        if matches!(method, CardholderVerificationMethod::FailCvmProcessing) {
            tvr.cardholder_verification_was_not_successful = true;
            return CvmProcessingOutcome {
                cvm_results: [rule.cvm, rule.condition, 0x01],
                tvr_updates: tvr,
                tsi_cardholder_verification_was_performed: true,
            };
        }

        // §10.5 step E - perform.
        let result = perform(rule);
        match result {
            CvmExecutionResult::Successful => {
                // Online PIN / signature: byte 3 = '00' Unknown.
                let byte3 = match method {
                    CardholderVerificationMethod::Signature
                    | CardholderVerificationMethod::EncipheredPinVerifiedOnline => 0x00,
                    _ => 0x02,
                };
                if matches!(
                    method,
                    CardholderVerificationMethod::EncipheredPinVerifiedOnline
                ) {
                    tvr.online_cvm_captured = true;
                }
                return CvmProcessingOutcome {
                    cvm_results: [rule.cvm, rule.condition, byte3],
                    tvr_updates: tvr,
                    tsi_cardholder_verification_was_performed: true,
                };
            }
            CvmExecutionResult::Unknown => {
                return CvmProcessingOutcome {
                    cvm_results: [rule.cvm, rule.condition, 0x00],
                    tvr_updates: tvr,
                    tsi_cardholder_verification_was_performed: true,
                };
            }
            CvmExecutionResult::Failed => {
                if rule.apply_succeeding_cv_rule_if_unsuccessful() {
                    continue;
                }
                tvr.cardholder_verification_was_not_successful = true;
                return CvmProcessingOutcome {
                    cvm_results: [rule.cvm, rule.condition, 0x01],
                    tvr_updates: tvr,
                    tsi_cardholder_verification_was_performed: true,
                };
            }
            CvmExecutionResult::PinEntryBypassed => {
                tvr.pin_entry_required_pin_pad_present_but_pin_was_not_entered = true;
                if rule.apply_succeeding_cv_rule_if_unsuccessful() {
                    continue;
                }
                tvr.cardholder_verification_was_not_successful = true;
                return CvmProcessingOutcome {
                    cvm_results: [rule.cvm, rule.condition, 0x01],
                    tvr_updates: tvr,
                    tsi_cardholder_verification_was_performed: true,
                };
            }
            CvmExecutionResult::PinPadNotWorkingOrAbsent => {
                tvr.pin_entry_required_and_pin_pad_not_present_or_not_working = true;
                if rule.apply_succeeding_cv_rule_if_unsuccessful() {
                    continue;
                }
                tvr.cardholder_verification_was_not_successful = true;
                return CvmProcessingOutcome {
                    cvm_results: [rule.cvm, rule.condition, 0x01],
                    tvr_updates: tvr,
                    tsi_cardholder_verification_was_performed: true,
                };
            }
            CvmExecutionResult::PinTryLimitExceeded => {
                tvr.pin_try_limit_exceeded = true;
                if rule.apply_succeeding_cv_rule_if_unsuccessful() {
                    continue;
                }
                tvr.cardholder_verification_was_not_successful = true;
                return CvmProcessingOutcome {
                    cvm_results: [rule.cvm, rule.condition, 0x01],
                    tvr_updates: tvr,
                    tsi_cardholder_verification_was_performed: true,
                };
            }
        }
    }

    tvr.cardholder_verification_was_not_successful = true;
    let cvm_results = match last_satisfied {
        Some(rule) => [rule.cvm, rule.condition, 0x01],
        None => [0x3F, 0x00, 0x01],
    };
    CvmProcessingOutcome {
        cvm_results,
        tvr_updates: tvr,
        tsi_cardholder_verification_was_performed: true,
    }
}

fn evaluate_condition(
    condition: CardholderVerificationMethodCondition,
    ctx: &CvmContext,
    amount_x: u32,
    amount_y: u32,
    method: CardholderVerificationMethod,
) -> bool {
    use CardholderVerificationMethodCondition::*;
    match condition {
        Always => true,
        IfUnattendedCash => ctx.transaction_is_unattended_cash,
        IfNotUnattendedCashAndNotManualCashAndNotPurchaseWithCashback => {
            !ctx.transaction_is_unattended_cash
                && !ctx.transaction_is_manual_cash
                && !ctx.transaction_is_purchase_with_cashback
        }
        IfTerminalSupportsTheCvm => is_method_recognised(method) && ctx.support.supports(method),
        IfManualCash => ctx.transaction_is_manual_cash,
        IfPurchaseWithCashback => ctx.transaction_is_purchase_with_cashback,
        IfTransactionIsInTheApplicationCurrencyAndIsUnderXValue => {
            ctx.transaction_in_application_currency && ctx.amount_authorised < amount_x
        }
        IfTransactionIsInTheApplicationCurrencyAndIsOverXValue => {
            ctx.transaction_in_application_currency && ctx.amount_authorised > amount_x
        }
        IfTransactionIsInTheApplicationCurrencyAndIsUnderYValue => {
            ctx.transaction_in_application_currency && ctx.amount_authorised < amount_y
        }
        IfTransactionIsInTheApplicationCurrencyAndIsOverYValue => {
            ctx.transaction_in_application_currency && ctx.amount_authorised > amount_y
        }
        Rfu(_) | ReservedForIndividualPaymentSystems(_) => false,
    }
}

fn is_method_recognised(method: CardholderVerificationMethod) -> bool {
    use CardholderVerificationMethod::*;
    !matches!(
        method,
        Rfu(_) | ReservedForIndividualPaymentSystems(_) | ReservedForIssuer(_) | NotAvailableForUse
    )
}

fn apply_unsupported_tvr_bits(
    method: CardholderVerificationMethod,
    support: &CvmTerminalSupport,
    tvr: &mut CvmTvrUpdates,
) {
    use CardholderVerificationMethod::*;
    match method {
        EncipheredPinVerifiedOnline => {
            tvr.pin_entry_required_and_pin_pad_not_present_or_not_working = true;
        }
        PlaintextPinVerificationPerformedByIcc
        | EncipheredPinVerificationPerformedByIcc
        | PlaintextPinVerificationPerformedByIccAndSignature
        | EncipheredPinVerificationPerformedByIccAndSignature => {
            if !support.supports_any_offline_pin() {
                tvr.pin_entry_required_and_pin_pad_not_present_or_not_working = true;
            }
        }
        FacialBiometricVerifiedOfflineByIcc
        | FacialBiometricVerifiedOnline
        | FingerBiometricVerifiedOfflineByIcc
        | FingerBiometricVerifiedOnline
        | PalmBiometricVerifiedOfflineByIcc
        | PalmBiometricVerifiedOnline
        | IrisBiometricVerifiedOfflineByIcc
        | IrisBiometricVerifiedOnline
        | VoiceBiometricVerifiedOfflineByIcc
        | VoiceBiometricVerifiedOnline => {
            tvr.a_selected_biometric_type_not_supported = true;
        }
        _ => {}
    }
}

/// Book 3 §6.3.5 - a VERIFY-related failure that is not a CVM outcome.
#[derive(Debug)]
pub enum OfflinePinError<E> {
    Transport(E),
    /// Status word outside the Book 3 Table 5 allocation for VERIFY;
    /// the transaction shall be terminated.
    UnallocatedStatusWord(u16),
}

/// Book 3 §10.5.1 + §6.5.12 - plaintext offline PIN against the ICC.
pub fn verify_plaintext_offline_pin<C: CardReader>(
    card: &mut C,
    pin: &[u8],
) -> Result<CvmExecutionResult, OfflinePinError<C::Error>> {
    let Ok(command) = verify::command_plaintext_pin(pin) else {
        return Ok(CvmExecutionResult::PinPadNotWorkingOrAbsent);
    };
    transmit_verify(card, &command)
}

/// Book 2 §7.2 + Book 3 §10.5.1 - enciphered offline PIN against the ICC.
/// `fill_random` supplies the §7.2 step-3 padding (N−17 unpredictable bytes,
/// ISO/IEC 18031); return false if no randomness is available.
pub fn verify_enciphered_offline_pin<C: CardReader>(
    card: &mut C,
    pin: &[u8],
    pin_encipherment_public_key: &IccPublicKey,
    fill_random: impl FnOnce(&mut [u8]) -> bool,
) -> Result<CvmExecutionResult, OfflinePinError<C::Error>> {
    let Ok(pin_block) = verify::plaintext_pin_block(pin) else {
        return Ok(CvmExecutionResult::PinPadNotWorkingOrAbsent);
    };

    // §7.2 step 2: GET CHALLENGE - anything other than 8 bytes with '9000'
    // means the offline enciphered PIN CVM has failed.
    let challenge = card
        .transmit(&get_challenge::command())
        .map_err(OfflinePinError::Transport)?;
    if challenge.status_word() != sw::OK
        || challenge.data().len() != get_challenge::CHALLENGE_LENGTH
    {
        return Ok(CvmExecutionResult::Failed);
    }
    let mut icc_unpredictable_number = [0u8; get_challenge::CHALLENGE_LENGTH];
    icc_unpredictable_number.copy_from_slice(challenge.data());

    // §7.2 step 3.
    let Some(padding_length) =
        pin_encipherment::random_padding_length(pin_encipherment_public_key.modulus.len())
    else {
        return Ok(CvmExecutionResult::Failed);
    };
    let mut padding = vec![0u8; padding_length];
    if !fill_random(&mut padding) {
        return Ok(CvmExecutionResult::PinPadNotWorkingOrAbsent);
    }

    // §7.2 step 4: RSA-encipher the Table 25 block.
    let Ok(data) = pin_encipherment::enciphered_pin_data(
        pin_block,
        icc_unpredictable_number,
        &padding,
        &pin_encipherment_public_key.modulus,
        &pin_encipherment_public_key.exponent,
    ) else {
        return Ok(CvmExecutionResult::Failed);
    };
    transmit_verify(
        card,
        &verify::command(verify::VerifyQualifier::EncipheredPinRsa, data, false),
    )
}

/// Book 3 §6.5.12 + §10.5.1 - VERIFY status word → CVM execution result.
fn transmit_verify<C: CardReader>(
    card: &mut C,
    command: &Command,
) -> Result<CvmExecutionResult, OfflinePinError<C::Error>> {
    let response = card.transmit(command).map_err(OfflinePinError::Transport)?;
    match response.status_word() {
        sw::OK => Ok(CvmExecutionResult::Successful),
        sw::AUTHENTICATION_METHOD_BLOCKED | sw::REFERENCED_DATA_INVALIDATED => {
            Ok(CvmExecutionResult::PinTryLimitExceeded)
        }
        sw => match sw::counter_provided(sw) {
            Some(0) => Ok(CvmExecutionResult::PinTryLimitExceeded),
            Some(_) => Ok(CvmExecutionResult::Failed),
            None => Err(OfflinePinError::UnallocatedStatusWord(sw)),
        },
    }
}

/// Book 2 §7.1 - ICC PIN Encipherment PK ('9F2D' chain) when all of its data
/// objects were obtained, otherwise the ICC PK already recovered by offline
/// data authentication. `None` means PIN encipherment has failed (rule 3).
pub fn recover_pin_encipherment_public_key(
    ctx: &TransactionContext<'_>,
    capks: &[CaPublicKey],
) -> Option<IccPublicKey> {
    let certificate = ctx.tag_store.get(tags::ICC_PIN_ENCIPHERMENT_PK_CERTIFICATE);
    let exponent = ctx.tag_store.get(tags::ICC_PIN_ENCIPHERMENT_PK_EXPONENT);
    if let (Some(certificate), Some(exponent)) = (certificate, exponent) {
        let certificate = certificate.to_vec();
        let exponent = exponent.to_vec();
        let remainder = ctx
            .tag_store
            .get(tags::ICC_PIN_ENCIPHERMENT_PK_REMAINDER)
            .map(<[u8]>::to_vec);
        let issuer_public_key = recover_issuer_public_key_for_pin(ctx, capks)?;
        let pan = ctx.tag_store.get(tags::PAN)?.to_vec();
        let today_mmyy = [
            ctx.inputs.transaction_date[1],
            ctx.inputs.transaction_date[0],
        ];
        return oda::recover_icc_pin_encipherment_public_key(
            &issuer_public_key,
            &certificate,
            remainder.as_deref(),
            &exponent,
            &pan,
            today_mmyy,
        )
        .ok();
    }
    ctx.cda.as_ref().map(|c| c.icc_public_key.clone())
}

fn recover_issuer_public_key_for_pin(
    ctx: &TransactionContext<'_>,
    capks: &[CaPublicKey],
) -> Option<IssuerPublicKey> {
    let ca_index_bytes = ctx.tag_store.get(tags::CA_PUBLIC_KEY_INDEX_ICC)?;
    if ca_index_bytes.len() != 1 {
        return None;
    }
    let ca_index = ca_index_bytes[0];
    let issuer_certificate = ctx
        .tag_store
        .get(tags::ISSUER_PUBLIC_KEY_CERTIFICATE)?
        .to_vec();
    let issuer_exponent = ctx
        .tag_store
        .get(tags::ISSUER_PUBLIC_KEY_EXPONENT)?
        .to_vec();
    let issuer_remainder = ctx
        .tag_store
        .get(tags::ISSUER_PUBLIC_KEY_REMAINDER)
        .map(<[u8]>::to_vec);
    let pan = ctx.tag_store.get(tags::PAN)?.to_vec();
    let today_mmyy = [
        ctx.inputs.transaction_date[1],
        ctx.inputs.transaction_date[0],
    ];

    let selected = ctx.selected.as_ref()?;
    if selected.df_name.len() < 5 {
        return None;
    }
    let rid: [u8; 5] = selected.df_name[..5].try_into().ok()?;
    let capk = capks.iter().find(|k| k.rid == rid && k.index == ca_index)?;

    oda::recover_issuer_public_key(
        capk,
        &issuer_certificate,
        issuer_remainder.as_deref(),
        &issuer_exponent,
        &pan,
        today_mmyy,
    )
    .ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx_purchase() -> CvmContext {
        CvmContext {
            support: CvmTerminalSupport {
                plaintext_offline_pin_by_icc: true,
                enciphered_pin_verified_online: true,
                enciphered_offline_pin_by_icc: true,
                signature: true,
                no_cvm_required: true,
                ..Default::default()
            },
            transaction_in_application_currency: true,
            amount_authorised: 2_000,
            transaction_is_unattended_cash: false,
            transaction_is_manual_cash: false,
            transaction_is_purchase_with_cashback: false,
        }
    }

    fn list(rules: &[(u8, u8)], amount_x: u32, amount_y: u32) -> CardholderVerificationMethodList {
        CardholderVerificationMethodList {
            amount_x,
            amount_y,
            rules: rules
                .iter()
                .map(|(c, d)| CardholderVerificationMethodRule::new(*c, *d))
                .collect(),
        }
    }

    fn cvm(method_bits: u8, apply_next: bool) -> u8 {
        method_bits | if apply_next { 0b0100_0000 } else { 0 }
    }

    #[test]
    fn absent_list_yields_3f0000_no_tsi() {
        let outcome = process_cvm_list(None, &ctx_purchase(), |_| CvmExecutionResult::Successful);
        assert_eq!(outcome.cvm_results, [0x3F, 0x00, 0x00]);
        assert_eq!(outcome.tvr_updates, CvmTvrUpdates::default());
        assert!(!outcome.tsi_cardholder_verification_was_performed);
    }

    #[test]
    fn empty_rules_treated_as_absent_per_spec_note() {
        let l = list(&[], 0, 0);
        let outcome = process_cvm_list(Some(&l), &ctx_purchase(), |_| {
            CvmExecutionResult::Successful
        });
        assert_eq!(outcome.cvm_results, [0x3F, 0x00, 0x00]);
        assert!(!outcome.tsi_cardholder_verification_was_performed);
    }

    #[test]
    fn first_rule_succeeds_with_offline_pin() {
        let l = list(&[(cvm(0b000001, false), 0x00)], 0, 0);
        let outcome = process_cvm_list(Some(&l), &ctx_purchase(), |_| {
            CvmExecutionResult::Successful
        });
        assert_eq!(outcome.cvm_results, [0x01, 0x00, 0x02]);
        assert_eq!(outcome.tvr_updates, CvmTvrUpdates::default());
        assert!(outcome.tsi_cardholder_verification_was_performed);
    }

    #[test]
    fn online_pin_success_sets_unknown_and_online_cvm_captured() {
        let l = list(&[(cvm(0b000010, false), 0x00)], 0, 0);
        let outcome = process_cvm_list(Some(&l), &ctx_purchase(), |_| {
            CvmExecutionResult::Successful
        });
        assert_eq!(outcome.cvm_results, [0x02, 0x00, 0x00]);
        assert!(outcome.tvr_updates.online_cvm_captured);
        assert!(
            !outcome
                .tvr_updates
                .cardholder_verification_was_not_successful
        );
        assert!(outcome.tsi_cardholder_verification_was_performed);
    }

    #[test]
    fn signature_unknown_yields_byte3_zero() {
        let l = list(&[(cvm(0b011110, false), 0x00)], 0, 0);
        let outcome = process_cvm_list(Some(&l), &ctx_purchase(), |_| CvmExecutionResult::Unknown);
        assert_eq!(outcome.cvm_results, [0x1E, 0x00, 0x00]);
        assert!(
            !outcome
                .tvr_updates
                .cardholder_verification_was_not_successful
        );
        assert!(outcome.tsi_cardholder_verification_was_performed);
    }

    #[test]
    fn no_cvm_required_succeeds() {
        let l = list(&[(cvm(0b011111, false), 0x00)], 0, 0);
        let outcome = process_cvm_list(Some(&l), &ctx_purchase(), |_| {
            CvmExecutionResult::Successful
        });
        assert_eq!(outcome.cvm_results, [0x1F, 0x00, 0x02]);
        assert!(
            !outcome
                .tvr_updates
                .cardholder_verification_was_not_successful
        );
    }

    #[test]
    fn fail_cvm_processing_short_circuits() {
        let l = list(
            &[(cvm(0b000000, true), 0x00), (cvm(0b011111, false), 0x00)],
            0,
            0,
        );
        let outcome = process_cvm_list(Some(&l), &ctx_purchase(), |_| {
            CvmExecutionResult::Successful
        });
        assert_eq!(outcome.cvm_results, [0x40, 0x00, 0x01]);
        assert!(
            outcome
                .tvr_updates
                .cardholder_verification_was_not_successful
        );
        assert!(outcome.tsi_cardholder_verification_was_performed);
    }

    #[test]
    fn failed_with_apply_next_falls_through_to_next_rule() {
        let l = list(
            &[(cvm(0b000001, true), 0x00), (cvm(0b011110, false), 0x00)],
            0,
            0,
        );
        let mut call = 0;
        let outcome = process_cvm_list(Some(&l), &ctx_purchase(), |_| {
            call += 1;
            if call == 1 {
                CvmExecutionResult::Failed
            } else {
                CvmExecutionResult::Unknown
            }
        });
        assert_eq!(call, 2);
        assert_eq!(outcome.cvm_results, [0x1E, 0x00, 0x00]);
        assert!(
            !outcome
                .tvr_updates
                .cardholder_verification_was_not_successful
        );
    }

    #[test]
    fn failed_without_apply_next_terminates() {
        let l = list(
            &[(cvm(0b000001, false), 0x00), (cvm(0b011110, false), 0x00)],
            0,
            0,
        );
        let outcome = process_cvm_list(Some(&l), &ctx_purchase(), |_| CvmExecutionResult::Failed);
        assert_eq!(outcome.cvm_results, [0x01, 0x00, 0x01]);
        assert!(
            outcome
                .tvr_updates
                .cardholder_verification_was_not_successful
        );
    }

    #[test]
    fn exhausted_after_satisfied_rule_records_last_cvm() {
        let l = list(&[(cvm(0b000001, true), 0x00)], 0, 0);
        let outcome = process_cvm_list(Some(&l), &ctx_purchase(), |_| CvmExecutionResult::Failed);
        assert_eq!(outcome.cvm_results, [0x41, 0x00, 0x01]);
        assert!(
            outcome
                .tvr_updates
                .cardholder_verification_was_not_successful
        );
    }

    #[test]
    fn no_conditions_satisfied_yields_3f0001() {
        let l = list(&[(cvm(0b000001, false), 0x01)], 0, 0);
        let outcome = process_cvm_list(Some(&l), &ctx_purchase(), |_| {
            CvmExecutionResult::Successful
        });
        assert_eq!(outcome.cvm_results, [0x3F, 0x00, 0x01]);
        assert!(
            outcome
                .tvr_updates
                .cardholder_verification_was_not_successful
        );
        assert!(outcome.tsi_cardholder_verification_was_performed);
    }

    #[test]
    fn condition_under_x_uses_amount_x() {
        let l = list(
            &[(cvm(0b000010, true), 0x06), (cvm(0b011110, false), 0x00)],
            5_000,
            10_000,
        );
        let outcome = process_cvm_list(Some(&l), &ctx_purchase(), |_| {
            CvmExecutionResult::Successful
        });
        assert_eq!(outcome.cvm_results, [0x42, 0x06, 0x00]);
        assert!(outcome.tvr_updates.online_cvm_captured);
    }

    #[test]
    fn condition_over_x_skips_when_amount_below() {
        let l = list(
            &[(cvm(0b000010, true), 0x07), (cvm(0b011110, false), 0x00)],
            5_000,
            10_000,
        );
        let outcome = process_cvm_list(Some(&l), &ctx_purchase(), |_| CvmExecutionResult::Unknown);
        assert_eq!(outcome.cvm_results, [0x1E, 0x00, 0x00]);
    }

    #[test]
    fn condition_currency_mismatch_skips_x_y_rules() {
        let mut ctx = ctx_purchase();
        ctx.transaction_in_application_currency = false;
        let l = list(
            &[(cvm(0b000010, true), 0x06), (cvm(0b011110, false), 0x00)],
            5_000,
            10_000,
        );
        let outcome = process_cvm_list(Some(&l), &ctx, |_| CvmExecutionResult::Unknown);
        assert_eq!(outcome.cvm_results, [0x1E, 0x00, 0x00]);
    }

    #[test]
    fn condition_03_supported_runs_cvm() {
        let l = list(&[(cvm(0b000010, false), 0x03)], 0, 0);
        let outcome = process_cvm_list(Some(&l), &ctx_purchase(), |_| {
            CvmExecutionResult::Successful
        });
        assert_eq!(outcome.cvm_results, [0x02, 0x03, 0x00]);
        assert!(outcome.tvr_updates.online_cvm_captured);
    }

    #[test]
    fn condition_03_not_supported_silently_skips() {
        let mut ctx = ctx_purchase();
        ctx.support.signature = false;
        let l = list(
            &[(cvm(0b011110, true), 0x03), (cvm(0b011111, false), 0x00)],
            0,
            0,
        );
        let outcome = process_cvm_list(Some(&l), &ctx, |_| CvmExecutionResult::Successful);
        assert_eq!(outcome.cvm_results, [0x1F, 0x00, 0x02]);
        assert_eq!(outcome.tvr_updates, CvmTvrUpdates::default());
    }

    #[test]
    fn condition_unattended_cash() {
        let mut ctx = ctx_purchase();
        ctx.transaction_is_unattended_cash = true;
        let l = list(&[(cvm(0b000001, false), 0x01)], 0, 0);
        let outcome = process_cvm_list(Some(&l), &ctx, |_| CvmExecutionResult::Successful);
        assert_eq!(outcome.cvm_results, [0x01, 0x01, 0x02]);
    }

    #[test]
    fn condition_rfu_treated_as_unsatisfied() {
        let l = list(
            &[(cvm(0b000001, true), 0x0A), (cvm(0b011111, false), 0x00)],
            0,
            0,
        );
        let outcome = process_cvm_list(Some(&l), &ctx_purchase(), |_| {
            CvmExecutionResult::Successful
        });
        assert_eq!(outcome.cvm_results, [0x1F, 0x00, 0x02]);
    }

    #[test]
    fn unrecognised_cvm_sets_bit_and_falls_through() {
        let l = list(
            &[(cvm(0b110000, true), 0x00), (cvm(0b011111, false), 0x00)],
            0,
            0,
        );
        let outcome = process_cvm_list(Some(&l), &ctx_purchase(), |_| {
            CvmExecutionResult::Successful
        });
        assert!(outcome.tvr_updates.unrecognised_cvm);
        assert_eq!(outcome.cvm_results, [0x1F, 0x00, 0x02]);
    }

    #[test]
    fn unrecognised_cvm_without_apply_next_terminates_with_3f() {
        let l = list(&[(cvm(0b110000, false), 0x00)], 0, 0);
        let outcome = process_cvm_list(Some(&l), &ctx_purchase(), |_| {
            CvmExecutionResult::Successful
        });
        assert!(outcome.tvr_updates.unrecognised_cvm);
        assert!(
            outcome
                .tvr_updates
                .cardholder_verification_was_not_successful
        );
        assert_eq!(outcome.cvm_results, [0x3F, 0x00, 0x01]);
    }

    #[test]
    fn unsupported_online_pin_sets_pin_pad_not_present_bit() {
        let mut ctx = ctx_purchase();
        ctx.support.enciphered_pin_verified_online = false;
        let l = list(&[(cvm(0b000010, false), 0x00)], 0, 0);
        let outcome = process_cvm_list(Some(&l), &ctx, |_| CvmExecutionResult::Successful);
        assert!(
            outcome
                .tvr_updates
                .pin_entry_required_and_pin_pad_not_present_or_not_working
        );
        assert!(
            outcome
                .tvr_updates
                .cardholder_verification_was_not_successful
        );
        assert_eq!(outcome.cvm_results, [0x02, 0x00, 0x01]);
    }

    #[test]
    fn unsupported_offline_pin_only_sets_bit_when_no_offline_pin_supported() {
        let mut ctx = ctx_purchase();
        ctx.support.plaintext_offline_pin_by_icc = false;
        ctx.support.enciphered_offline_pin_by_icc = true;
        let l = list(
            &[(cvm(0b000001, true), 0x00), (cvm(0b011111, false), 0x00)],
            0,
            0,
        );
        let outcome = process_cvm_list(Some(&l), &ctx, |_| CvmExecutionResult::Successful);
        assert_eq!(outcome.cvm_results, [0x1F, 0x00, 0x02]);
        assert!(
            !outcome
                .tvr_updates
                .pin_entry_required_and_pin_pad_not_present_or_not_working
        );
    }

    #[test]
    fn unsupported_offline_pin_when_no_offline_pin_at_all_sets_bit() {
        let mut ctx = ctx_purchase();
        ctx.support.plaintext_offline_pin_by_icc = false;
        ctx.support.enciphered_offline_pin_by_icc = false;
        ctx.support.plaintext_offline_pin_by_icc_and_signature = false;
        ctx.support.enciphered_offline_pin_by_icc_and_signature = false;
        let l = list(
            &[(cvm(0b000001, true), 0x00), (cvm(0b011111, false), 0x00)],
            0,
            0,
        );
        let outcome = process_cvm_list(Some(&l), &ctx, |_| CvmExecutionResult::Successful);
        assert!(
            outcome
                .tvr_updates
                .pin_entry_required_and_pin_pad_not_present_or_not_working
        );
    }

    #[test]
    fn unsupported_biometric_sets_a_selected_biometric_type_not_supported() {
        let l = list(
            &[(cvm(0b001000, true), 0x00), (cvm(0b011111, false), 0x00)],
            0,
            0,
        );
        let outcome = process_cvm_list(Some(&l), &ctx_purchase(), |_| {
            CvmExecutionResult::Successful
        });
        assert!(outcome.tvr_updates.a_selected_biometric_type_not_supported);
        assert_eq!(outcome.cvm_results, [0x1F, 0x00, 0x02]);
    }

    #[test]
    fn pin_entry_bypassed_sets_b4_byte3() {
        let l = list(&[(cvm(0b000001, false), 0x00)], 0, 0);
        let outcome = process_cvm_list(Some(&l), &ctx_purchase(), |_| {
            CvmExecutionResult::PinEntryBypassed
        });
        assert!(
            outcome
                .tvr_updates
                .pin_entry_required_pin_pad_present_but_pin_was_not_entered
        );
        assert!(
            outcome
                .tvr_updates
                .cardholder_verification_was_not_successful
        );
        assert_eq!(outcome.cvm_results, [0x01, 0x00, 0x01]);
    }

    #[test]
    fn pin_pad_not_working_sets_b5_byte3_and_falls_through_with_apply_next() {
        let l = list(
            &[(cvm(0b000001, true), 0x00), (cvm(0b011111, false), 0x00)],
            0,
            0,
        );
        let mut call = 0;
        let outcome = process_cvm_list(Some(&l), &ctx_purchase(), |_| {
            call += 1;
            if call == 1 {
                CvmExecutionResult::PinPadNotWorkingOrAbsent
            } else {
                CvmExecutionResult::Successful
            }
        });
        assert!(
            outcome
                .tvr_updates
                .pin_entry_required_and_pin_pad_not_present_or_not_working
        );
        assert_eq!(outcome.cvm_results, [0x1F, 0x00, 0x02]);
    }

    #[test]
    fn pin_try_limit_exceeded_sets_b6_byte3() {
        let l = list(&[(cvm(0b000001, false), 0x00)], 0, 0);
        let outcome = process_cvm_list(Some(&l), &ctx_purchase(), |_| {
            CvmExecutionResult::PinTryLimitExceeded
        });
        assert!(outcome.tvr_updates.pin_try_limit_exceeded);
        assert!(
            outcome
                .tvr_updates
                .cardholder_verification_was_not_successful
        );
    }

    #[test]
    fn typical_cvm_list_high_amount_takes_online_pin() {
        let l = list(
            &[
                (cvm(0b000010, true), 0x09),
                (cvm(0b000001, true), 0x07),
                (cvm(0b011110, true), 0x02),
                (cvm(0b011111, false), 0x00),
            ],
            1_000,
            10_000,
        );
        let mut ctx = ctx_purchase();
        ctx.amount_authorised = 20_000;
        let outcome = process_cvm_list(Some(&l), &ctx, |_| CvmExecutionResult::Successful);
        assert_eq!(outcome.cvm_results, [0x42, 0x09, 0x00]);
        assert!(outcome.tvr_updates.online_cvm_captured);
        assert!(
            !outcome
                .tvr_updates
                .cardholder_verification_was_not_successful
        );
    }

    #[test]
    fn typical_cvm_list_low_amount_takes_signature() {
        let l = list(
            &[
                (cvm(0b000010, true), 0x09),
                (cvm(0b000001, true), 0x07),
                (cvm(0b011110, true), 0x02),
                (cvm(0b011111, false), 0x00),
            ],
            1_000,
            10_000,
        );
        let mut ctx = ctx_purchase();
        ctx.amount_authorised = 500;
        let outcome = process_cvm_list(Some(&l), &ctx, |_| CvmExecutionResult::Unknown);
        assert_eq!(outcome.cvm_results, [0x5E, 0x02, 0x00]);
        assert!(
            !outcome
                .tvr_updates
                .cardholder_verification_was_not_successful
        );
    }

    #[test]
    fn typical_cvm_list_unattended_cash_falls_through_to_no_cvm() {
        let l = list(
            &[
                (cvm(0b000010, true), 0x09),
                (cvm(0b000001, true), 0x07),
                (cvm(0b011110, true), 0x02),
                (cvm(0b011111, false), 0x00),
            ],
            1_000,
            10_000,
        );
        let mut ctx = ctx_purchase();
        ctx.amount_authorised = 500;
        ctx.transaction_is_unattended_cash = true;
        let outcome = process_cvm_list(Some(&l), &ctx, |_| CvmExecutionResult::Successful);
        assert_eq!(outcome.cvm_results, [0x1F, 0x00, 0x02]);
    }
}
