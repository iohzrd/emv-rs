//! Book 3 §10.4 p.100 - Processing Restrictions.

use crate::de::application_usage_control::ApplicationUsageControl;

/// 3-byte BCD `YYMMDD` (`5F24`/`5F25`/`9A`).
pub type EmvDate = [u8; 3];

pub type ApplicationVersionNumber = [u8; 2];

/// ISO 3166-1 numeric.
pub type CountryCode = [u8; 2];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransactionCategory {
    Cash,
    Purchase,
    Other,
}

impl TransactionCategory {
    /// '9C' Transaction Type - first two digits of the ISO 8583:1987
    /// Processing Code ('00' goods/services, '01' cash, '09' purchase with
    /// cashback).
    pub fn from_transaction_type(transaction_type: u8) -> TransactionCategory {
        match transaction_type {
            0x01 => TransactionCategory::Cash,
            0x00 | 0x09 => TransactionCategory::Purchase,
            _ => TransactionCategory::Other,
        }
    }
}

#[derive(Debug, Clone)]
pub struct ProcessingRestrictionsContext<'a> {
    pub icc_application_version_number: Option<&'a ApplicationVersionNumber>,
    pub terminal_application_version_number: &'a ApplicationVersionNumber,

    pub application_usage_control: Option<&'a ApplicationUsageControl>,
    pub icc_issuer_country_code: Option<&'a CountryCode>,
    pub terminal_country_code: &'a CountryCode,
    pub terminal_is_atm: bool,
    pub transaction_category: TransactionCategory,
    pub transaction_has_cashback: bool,

    pub application_effective_date: Option<&'a EmvDate>,
    pub application_expiration_date: &'a EmvDate,
    pub transaction_date: &'a EmvDate,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ProcessingRestrictionsOutcome {
    pub icc_and_terminal_have_different_application_versions: bool,
    pub requested_service_not_allowed_for_card_product: bool,
    pub application_not_yet_effective: bool,
    pub expired_application: bool,
}

/// §10.4.1.
pub fn check_application_version(
    icc: Option<&ApplicationVersionNumber>,
    terminal: &ApplicationVersionNumber,
) -> bool {
    match icc {
        Some(icc_avn) => icc_avn != terminal,
        None => false,
    }
}

/// §10.4.2.
pub fn check_application_usage_control(
    auc: Option<&ApplicationUsageControl>,
    terminal_is_atm: bool,
    icc_issuer_country_code: Option<&CountryCode>,
    terminal_country_code: &CountryCode,
    transaction_category: TransactionCategory,
    transaction_has_cashback: bool,
) -> bool {
    let Some(auc) = auc else { return false };

    // §10.4.2 first paragraph - ATM / non-ATM.
    if terminal_is_atm && !auc.valid_at_atms {
        return true;
    }
    if !terminal_is_atm && !auc.valid_at_terminals_other_than_atms {
        return true;
    }

    // Table 36 - gated on Issuer Country Code presence.
    let Some(icc_cc) = icc_issuer_country_code else {
        return false;
    };
    let domestic = icc_cc == terminal_country_code;

    match transaction_category {
        TransactionCategory::Cash => {
            if domestic && !auc.valid_for_domestic_cash_transactions {
                return true;
            }
            if !domestic && !auc.valid_for_international_cash_transactions {
                return true;
            }
        }
        TransactionCategory::Purchase => {
            // Table 36 - goods AND/OR services suffices.
            if domestic
                && !(auc.valid_for_domestic_goods || auc.valid_for_domestic_services)
            {
                return true;
            }
            if !domestic
                && !(auc.valid_for_international_goods
                    || auc.valid_for_international_services)
            {
                return true;
            }
        }
        TransactionCategory::Other => {}
    }

    if transaction_has_cashback {
        if domestic && !auc.domestic_cashback_allowed {
            return true;
        }
        if !domestic && !auc.international_cashback_allowed {
            return true;
        }
    }

    false
}

/// §10.4.3.
pub fn check_dates(
    effective: Option<&EmvDate>,
    expiration: &EmvDate,
    transaction_date: &EmvDate,
) -> (bool, bool) {
    let not_yet_effective = match effective {
        Some(eff) => transaction_date < eff,
        None => false,
    };
    let expired = transaction_date > expiration;
    (not_yet_effective, expired)
}

pub fn evaluate(ctx: &ProcessingRestrictionsContext<'_>) -> ProcessingRestrictionsOutcome {
    let avn_mismatch = check_application_version(
        ctx.icc_application_version_number,
        ctx.terminal_application_version_number,
    );
    let auc_failure = check_application_usage_control(
        ctx.application_usage_control,
        ctx.terminal_is_atm,
        ctx.icc_issuer_country_code,
        ctx.terminal_country_code,
        ctx.transaction_category,
        ctx.transaction_has_cashback,
    );
    let (not_yet_effective, expired) = check_dates(
        ctx.application_effective_date,
        ctx.application_expiration_date,
        ctx.transaction_date,
    );
    ProcessingRestrictionsOutcome {
        icc_and_terminal_have_different_application_versions: avn_mismatch,
        requested_service_not_allowed_for_card_product: auc_failure,
        application_not_yet_effective: not_yet_effective,
        expired_application: expired,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn avn_match_does_not_set_bit() {
        let term = [0x00, 0x8C];
        let icc = [0x00, 0x8C];
        assert!(!check_application_version(Some(&icc), &term));
    }

    #[test]
    fn avn_mismatch_sets_bit() {
        let term = [0x00, 0x8C];
        let icc = [0x00, 0x96];
        assert!(check_application_version(Some(&icc), &term));
    }

    #[test]
    fn avn_absent_in_icc_presumes_compatible() {
        let term = [0x00, 0x8C];
        assert!(!check_application_version(None, &term));
    }

    fn auc_all_set() -> ApplicationUsageControl {
        ApplicationUsageControl {
            valid_for_domestic_cash_transactions: true,
            valid_for_international_cash_transactions: true,
            valid_for_domestic_goods: true,
            valid_for_international_goods: true,
            valid_for_domestic_services: true,
            valid_for_international_services: true,
            valid_at_atms: true,
            valid_at_terminals_other_than_atms: true,
            domestic_cashback_allowed: true,
            international_cashback_allowed: true,
            rfu_byte_2: 0,
        }
    }

    #[test]
    fn auc_absent_passes() {
        let cc = [0x08, 0x40];
        assert!(!check_application_usage_control(
            None,
            true,
            Some(&cc),
            &cc,
            TransactionCategory::Cash,
            false,
        ));
    }

    #[test]
    fn auc_atm_check_fails_when_not_valid_at_atms() {
        let mut auc = auc_all_set();
        auc.valid_at_atms = false;
        let cc = [0x08, 0x40];
        assert!(check_application_usage_control(
            Some(&auc),
            true,
            Some(&cc),
            &cc,
            TransactionCategory::Cash,
            false,
        ));
    }

    #[test]
    fn auc_non_atm_check_fails_when_not_valid_at_other() {
        let mut auc = auc_all_set();
        auc.valid_at_terminals_other_than_atms = false;
        let cc = [0x08, 0x40];
        assert!(check_application_usage_control(
            Some(&auc),
            false,
            Some(&cc),
            &cc,
            TransactionCategory::Cash,
            false,
        ));
    }

    #[test]
    fn auc_table_36_skipped_when_issuer_cc_absent() {
        let mut auc = auc_all_set();
        auc.valid_for_domestic_cash_transactions = false;
        auc.valid_for_international_cash_transactions = false;
        let cc = [0x08, 0x40];
        assert!(!check_application_usage_control(
            Some(&auc),
            false,
            None,
            &cc,
            TransactionCategory::Cash,
            false,
        ));
    }

    #[test]
    fn auc_domestic_cash_passes_when_bit_set() {
        let auc = auc_all_set();
        let cc = [0x08, 0x40];
        assert!(!check_application_usage_control(
            Some(&auc),
            false,
            Some(&cc),
            &cc,
            TransactionCategory::Cash,
            false,
        ));
    }

    #[test]
    fn auc_domestic_cash_fails_when_bit_clear() {
        let mut auc = auc_all_set();
        auc.valid_for_domestic_cash_transactions = false;
        let cc = [0x08, 0x40];
        assert!(check_application_usage_control(
            Some(&auc),
            false,
            Some(&cc),
            &cc,
            TransactionCategory::Cash,
            false,
        ));
    }

    #[test]
    fn auc_international_cash_uses_other_bit() {
        let mut auc = auc_all_set();
        auc.valid_for_international_cash_transactions = false;
        let term_cc = [0x08, 0x40];
        let icc_cc = [0x02, 0x50];
        assert!(check_application_usage_control(
            Some(&auc),
            false,
            Some(&icc_cc),
            &term_cc,
            TransactionCategory::Cash,
            false,
        ));
    }

    #[test]
    fn auc_purchase_domestic_passes_when_either_goods_or_services() {
        let mut auc = auc_all_set();
        auc.valid_for_domestic_goods = false;
        let cc = [0x08, 0x40];
        assert!(!check_application_usage_control(
            Some(&auc),
            false,
            Some(&cc),
            &cc,
            TransactionCategory::Purchase,
            false,
        ));
    }

    #[test]
    fn auc_purchase_domestic_fails_when_both_goods_and_services_clear() {
        let mut auc = auc_all_set();
        auc.valid_for_domestic_goods = false;
        auc.valid_for_domestic_services = false;
        let cc = [0x08, 0x40];
        assert!(check_application_usage_control(
            Some(&auc),
            false,
            Some(&cc),
            &cc,
            TransactionCategory::Purchase,
            false,
        ));
    }

    #[test]
    fn auc_other_transaction_type_skips_table_36_rows() {
        let mut auc = auc_all_set();
        auc.valid_for_domestic_cash_transactions = false;
        auc.valid_for_domestic_goods = false;
        auc.valid_for_domestic_services = false;
        let cc = [0x08, 0x40];
        assert!(!check_application_usage_control(
            Some(&auc),
            false,
            Some(&cc),
            &cc,
            TransactionCategory::Other,
            false,
        ));
    }

    #[test]
    fn auc_cashback_domestic_fails_when_bit_clear() {
        let mut auc = auc_all_set();
        auc.domestic_cashback_allowed = false;
        let cc = [0x08, 0x40];
        assert!(check_application_usage_control(
            Some(&auc),
            false,
            Some(&cc),
            &cc,
            TransactionCategory::Purchase,
            true,
        ));
    }

    #[test]
    fn auc_cashback_international_fails_when_bit_clear() {
        let mut auc = auc_all_set();
        auc.international_cashback_allowed = false;
        let term_cc = [0x08, 0x40];
        let icc_cc = [0x02, 0x50];
        assert!(check_application_usage_control(
            Some(&auc),
            false,
            Some(&icc_cc),
            &term_cc,
            TransactionCategory::Purchase,
            true,
        ));
    }

    #[test]
    fn auc_cashback_only_evaluated_when_flag_set() {
        let mut auc = auc_all_set();
        auc.domestic_cashback_allowed = false;
        auc.international_cashback_allowed = false;
        let cc = [0x08, 0x40];
        assert!(!check_application_usage_control(
            Some(&auc),
            false,
            Some(&cc),
            &cc,
            TransactionCategory::Purchase,
            false,
        ));
    }

    #[test]
    fn dates_in_window_pass() {
        let eff = [0x25u8, 0x01, 0x01];
        let exp = [0x29u8, 0x12, 0x31];
        let txn = [0x26u8, 0x06, 0x15];
        assert_eq!(check_dates(Some(&eff), &exp, &txn), (false, false));
    }

    #[test]
    fn date_before_effective_sets_not_yet_effective() {
        let eff = [0x26u8, 0x06, 0x01];
        let exp = [0x29u8, 0x12, 0x31];
        let txn = [0x26u8, 0x05, 0x31];
        assert_eq!(check_dates(Some(&eff), &exp, &txn), (true, false));
    }

    #[test]
    fn date_equal_to_effective_passes() {
        let eff = [0x26u8, 0x06, 0x01];
        let exp = [0x29u8, 0x12, 0x31];
        let txn = [0x26u8, 0x06, 0x01];
        assert_eq!(check_dates(Some(&eff), &exp, &txn), (false, false));
    }

    #[test]
    fn date_after_expiration_sets_expired() {
        let eff = [0x25u8, 0x01, 0x01];
        let exp = [0x26u8, 0x06, 0x30];
        let txn = [0x26u8, 0x07, 0x01];
        assert_eq!(check_dates(Some(&eff), &exp, &txn), (false, true));
    }

    #[test]
    fn date_equal_to_expiration_passes() {
        let eff = [0x25u8, 0x01, 0x01];
        let exp = [0x26u8, 0x06, 0x30];
        let txn = [0x26u8, 0x06, 0x30];
        assert_eq!(check_dates(Some(&eff), &exp, &txn), (false, false));
    }

    #[test]
    fn effective_absent_skips_lower_bound() {
        let exp = [0x29u8, 0x12, 0x31];
        let txn = [0x20u8, 0x01, 0x01];
        assert_eq!(check_dates(None, &exp, &txn), (false, false));
    }

    #[test]
    fn both_bits_can_set_simultaneously_is_impossible_in_practice() {
        // Ill-formed ICC: eff > exp.
        let eff = [0x29u8, 0x12, 0x31];
        let exp = [0x20u8, 0x01, 0x01];
        let txn = [0x25u8, 0x06, 0x15];
        assert_eq!(check_dates(Some(&eff), &exp, &txn), (true, true));
    }

    #[test]
    fn evaluate_combines_all_three_checks() {
        let term_avn = [0x00u8, 0x8C];
        let icc_avn = [0x00u8, 0x96];
        let mut auc = auc_all_set();
        auc.valid_for_domestic_cash_transactions = false;
        let cc = [0x08, 0x40];
        let exp = [0x20u8, 0x01, 0x01];
        let txn = [0x25u8, 0x06, 0x15];
        let eff = [0x10u8, 0x01, 0x01];

        let ctx = ProcessingRestrictionsContext {
            icc_application_version_number: Some(&icc_avn),
            terminal_application_version_number: &term_avn,
            application_usage_control: Some(&auc),
            icc_issuer_country_code: Some(&cc),
            terminal_country_code: &cc,
            terminal_is_atm: false,
            transaction_category: TransactionCategory::Cash,
            transaction_has_cashback: false,
            application_effective_date: Some(&eff),
            application_expiration_date: &exp,
            transaction_date: &txn,
        };
        let outcome = evaluate(&ctx);
        assert!(outcome.icc_and_terminal_have_different_application_versions);
        assert!(outcome.requested_service_not_allowed_for_card_product);
        assert!(!outcome.application_not_yet_effective);
        assert!(outcome.expired_application);
    }

    #[test]
    fn evaluate_clean_path_sets_no_bits() {
        let avn = [0x00u8, 0x8C];
        let auc = auc_all_set();
        let cc = [0x08, 0x40];
        let eff = [0x25u8, 0x01, 0x01];
        let exp = [0x29u8, 0x12, 0x31];
        let txn = [0x26u8, 0x06, 0x15];
        let ctx = ProcessingRestrictionsContext {
            icc_application_version_number: Some(&avn),
            terminal_application_version_number: &avn,
            application_usage_control: Some(&auc),
            icc_issuer_country_code: Some(&cc),
            terminal_country_code: &cc,
            terminal_is_atm: false,
            transaction_category: TransactionCategory::Purchase,
            transaction_has_cashback: false,
            application_effective_date: Some(&eff),
            application_expiration_date: &exp,
            transaction_date: &txn,
        };
        assert_eq!(evaluate(&ctx), ProcessingRestrictionsOutcome::default());
    }
}
