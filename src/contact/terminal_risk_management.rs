//! Book 3 §10.6 p.118 - Terminal Risk Management.

use crate::core::error::{Error, Result};

/// §10.6.1.
pub fn check_floor_limit(
    amount_authorised: u64,
    prior_amount_for_pan: Option<u64>,
    floor_limit: u64,
) -> bool {
    let sum = amount_authorised.saturating_add(prior_amount_for_pan.unwrap_or(0));
    sum >= floor_limit
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RandomSelectionParameters {
    pub threshold_value: u64,
    pub target_percentage: u8,
    pub max_target_percentage: u8,
}

/// §10.6.2 - `random_number` ∈ [1, 99].
pub fn check_random_selection(
    amount_authorised: u64,
    floor_limit: u64,
    params: RandomSelectionParameters,
    random_number: u8,
) -> Result<bool> {
    if params.target_percentage > 99
        || params.max_target_percentage > 99
        || params.max_target_percentage < params.target_percentage
    {
        return Err(Error::InvalidValue);
    }
    if random_number == 0 || random_number > 99 {
        return Err(Error::InvalidValue);
    }
    if params.threshold_value >= floor_limit {
        return Err(Error::InvalidValue);
    }

    if amount_authorised >= floor_limit {
        return Ok(false);
    }

    // §10.6.2 footnote 16 - TTP = (Max-Target) * (A-T)/(F-T) + Target.
    let target_pct: u64 = if amount_authorised < params.threshold_value {
        params.target_percentage as u64
    } else {
        let span_amount = amount_authorised - params.threshold_value;
        let span_total = floor_limit - params.threshold_value;
        let pct_span = (params.max_target_percentage - params.target_percentage) as u64;
        let biased_increment = (pct_span * span_amount) / span_total;
        biased_increment + params.target_percentage as u64
    };

    Ok((random_number as u64) <= target_pct)
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct VelocityCheckOutcome {
    pub lower_consecutive_offline_limit_exceeded: bool,
    pub upper_consecutive_offline_limit_exceeded: bool,
    pub new_card: bool,
}

/// §10.6.3 - fires on strict `diff > limit`.
pub fn check_velocity(
    lower_limit: Option<u8>,
    upper_limit: Option<u8>,
    atc: Option<u16>,
    last_online_atc_register: Option<u16>,
) -> VelocityCheckOutcome {
    let (Some(lower_limit), Some(upper_limit)) = (lower_limit, upper_limit) else {
        return VelocityCheckOutcome::default();
    };

    let new_card_from_zero = matches!(last_online_atc_register, Some(0));

    let (Some(atc), Some(last_online)) = (atc, last_online_atc_register) else {
        return VelocityCheckOutcome {
            lower_consecutive_offline_limit_exceeded: true,
            upper_consecutive_offline_limit_exceeded: true,
            new_card: new_card_from_zero,
        };
    };

    if atc <= last_online {
        return VelocityCheckOutcome {
            lower_consecutive_offline_limit_exceeded: true,
            upper_consecutive_offline_limit_exceeded: true,
            new_card: new_card_from_zero,
        };
    }

    let diff = atc - last_online;
    let lower_exceeded = diff > lower_limit as u16;
    // §10.6.3 - upper only checked if lower exceeded.
    let upper_exceeded = lower_exceeded && diff > upper_limit as u16;

    VelocityCheckOutcome {
        lower_consecutive_offline_limit_exceeded: lower_exceeded,
        upper_consecutive_offline_limit_exceeded: upper_exceeded,
        new_card: new_card_from_zero,
    }
}

/// `random_number` = `None` skips RTS.
#[derive(Debug, Clone)]
pub struct TerminalRiskManagementContext {
    pub amount_authorised: u64,
    pub floor_limit: u64,
    pub prior_amount_for_pan: Option<u64>,

    pub random_selection_parameters: RandomSelectionParameters,
    pub random_number: Option<u8>,

    pub lower_consecutive_offline_limit: Option<u8>,
    pub upper_consecutive_offline_limit: Option<u8>,
    pub atc: Option<u16>,
    pub last_online_atc_register: Option<u16>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct TerminalRiskManagementOutcome {
    pub transaction_exceeds_floor_limit: bool,
    pub transaction_selected_randomly_for_online_processing: bool,
    pub lower_consecutive_offline_limit_exceeded: bool,
    pub upper_consecutive_offline_limit_exceeded: bool,
    pub new_card: bool,
}

pub fn evaluate(ctx: &TerminalRiskManagementContext) -> Result<TerminalRiskManagementOutcome> {
    let exceeds_floor = check_floor_limit(
        ctx.amount_authorised,
        ctx.prior_amount_for_pan,
        ctx.floor_limit,
    );
    let rts_selected = match ctx.random_number {
        Some(rn) => check_random_selection(
            ctx.amount_authorised,
            ctx.floor_limit,
            ctx.random_selection_parameters,
            rn,
        )?,
        None => false,
    };
    let velocity = check_velocity(
        ctx.lower_consecutive_offline_limit,
        ctx.upper_consecutive_offline_limit,
        ctx.atc,
        ctx.last_online_atc_register,
    );
    Ok(TerminalRiskManagementOutcome {
        transaction_exceeds_floor_limit: exceeds_floor,
        transaction_selected_randomly_for_online_processing: rts_selected,
        lower_consecutive_offline_limit_exceeded: velocity.lower_consecutive_offline_limit_exceeded,
        upper_consecutive_offline_limit_exceeded: velocity.upper_consecutive_offline_limit_exceeded,
        new_card: velocity.new_card,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn floor_limit_below_does_not_set_bit() {
        assert!(!check_floor_limit(99, None, 100));
    }

    #[test]
    fn floor_limit_equal_sets_bit() {
        assert!(check_floor_limit(100, None, 100));
    }

    #[test]
    fn floor_limit_above_sets_bit() {
        assert!(check_floor_limit(101, None, 100));
    }

    #[test]
    fn floor_limit_with_log_aggregates_amounts() {
        assert!(check_floor_limit(60, Some(50), 100));
        assert!(!check_floor_limit(30, Some(50), 100));
    }

    #[test]
    fn floor_limit_with_no_log_entry_uses_amount_only() {
        assert!(!check_floor_limit(99, None, 100));
        assert!(check_floor_limit(150, None, 100));
    }

    fn rts_params(threshold: u64, target: u8, max: u8) -> RandomSelectionParameters {
        RandomSelectionParameters {
            threshold_value: threshold,
            target_percentage: target,
            max_target_percentage: max,
        }
    }

    #[test]
    fn rts_amount_at_or_above_floor_is_not_applicable() {
        let p = rts_params(20, 10, 90);
        assert_eq!(check_random_selection(100, 100, p, 1), Ok(false));
        assert_eq!(check_random_selection(150, 100, p, 1), Ok(false));
    }

    #[test]
    fn rts_below_threshold_uses_target_percent_uniformly() {
        let p = rts_params(50, 10, 90);
        assert_eq!(check_random_selection(20, 100, p, 10), Ok(true));
        assert_eq!(check_random_selection(20, 100, p, 11), Ok(false));
    }

    #[test]
    fn rts_at_threshold_uses_target_percent() {
        let p = rts_params(50, 10, 90);
        assert_eq!(check_random_selection(50, 100, p, 10), Ok(true));
        assert_eq!(check_random_selection(50, 100, p, 11), Ok(false));
    }

    #[test]
    fn rts_biased_linear_interpolation_midpoint() {
        // TTP = (90-10) * (25/50) + 10 = 50.
        let p = rts_params(50, 10, 90);
        assert_eq!(check_random_selection(75, 100, p, 50), Ok(true));
        assert_eq!(check_random_selection(75, 100, p, 51), Ok(false));
    }

    #[test]
    fn rts_biased_linear_interpolation_just_below_floor() {
        // TTP = (90-10) * (49/50) + 10 = 88 (integer div).
        let p = rts_params(50, 10, 90);
        assert_eq!(check_random_selection(99, 100, p, 88), Ok(true));
        assert_eq!(check_random_selection(99, 100, p, 89), Ok(false));
    }

    #[test]
    fn rts_zero_target_never_selects_below_threshold() {
        let p = rts_params(50, 0, 0);
        for rn in 1u8..=99 {
            assert_eq!(check_random_selection(20, 100, p, rn), Ok(false));
        }
    }

    #[test]
    fn rts_invalid_target_above_99_rejected() {
        let p = rts_params(50, 100, 100);
        assert_eq!(
            check_random_selection(50, 100, p, 1),
            Err(Error::InvalidValue)
        );
    }

    #[test]
    fn rts_invalid_max_below_target_rejected() {
        let p = rts_params(50, 50, 30);
        assert_eq!(
            check_random_selection(50, 100, p, 1),
            Err(Error::InvalidValue)
        );
    }

    #[test]
    fn rts_invalid_threshold_above_floor_rejected() {
        let p = rts_params(150, 10, 90);
        assert_eq!(
            check_random_selection(50, 100, p, 1),
            Err(Error::InvalidValue)
        );
    }

    #[test]
    fn rts_random_zero_or_above_99_rejected() {
        let p = rts_params(50, 10, 90);
        assert_eq!(
            check_random_selection(50, 100, p, 0),
            Err(Error::InvalidValue)
        );
        assert_eq!(
            check_random_selection(50, 100, p, 100),
            Err(Error::InvalidValue)
        );
    }

    #[test]
    fn velocity_skipped_when_lower_limit_absent() {
        let outcome = check_velocity(None, Some(10), Some(5), Some(0));
        assert_eq!(outcome, VelocityCheckOutcome::default());
    }

    #[test]
    fn velocity_skipped_when_upper_limit_absent() {
        let outcome = check_velocity(Some(5), None, Some(5), Some(0));
        assert_eq!(outcome, VelocityCheckOutcome::default());
    }

    #[test]
    fn velocity_get_data_failed_for_atc_forces_both_bits() {
        let outcome = check_velocity(Some(5), Some(10), None, Some(3));
        assert!(outcome.lower_consecutive_offline_limit_exceeded);
        assert!(outcome.upper_consecutive_offline_limit_exceeded);
        assert!(!outcome.new_card);
    }

    #[test]
    fn velocity_get_data_failed_for_last_online_forces_both_bits() {
        let outcome = check_velocity(Some(5), Some(10), Some(7), None);
        assert!(outcome.lower_consecutive_offline_limit_exceeded);
        assert!(outcome.upper_consecutive_offline_limit_exceeded);
        assert!(!outcome.new_card);
    }

    #[test]
    fn velocity_get_data_failed_with_zero_last_online_sets_new_card() {
        let outcome = check_velocity(Some(5), Some(10), None, Some(0));
        assert!(outcome.lower_consecutive_offline_limit_exceeded);
        assert!(outcome.upper_consecutive_offline_limit_exceeded);
        assert!(outcome.new_card);
    }

    #[test]
    fn velocity_atc_less_than_last_online_forces_both_bits() {
        let outcome = check_velocity(Some(5), Some(10), Some(3), Some(7));
        assert!(outcome.lower_consecutive_offline_limit_exceeded);
        assert!(outcome.upper_consecutive_offline_limit_exceeded);
        assert!(!outcome.new_card);
    }

    #[test]
    fn velocity_atc_equal_to_last_online_forces_both_bits() {
        let outcome = check_velocity(Some(5), Some(10), Some(7), Some(7));
        assert!(outcome.lower_consecutive_offline_limit_exceeded);
        assert!(outcome.upper_consecutive_offline_limit_exceeded);
    }

    #[test]
    fn velocity_diff_equal_to_lower_is_not_exceeded() {
        let outcome = check_velocity(Some(5), Some(10), Some(10), Some(5));
        assert!(!outcome.lower_consecutive_offline_limit_exceeded);
        assert!(!outcome.upper_consecutive_offline_limit_exceeded);
        assert!(!outcome.new_card);
    }

    #[test]
    fn velocity_diff_above_lower_below_upper() {
        let outcome = check_velocity(Some(5), Some(10), Some(10), Some(2));
        assert!(outcome.lower_consecutive_offline_limit_exceeded);
        assert!(!outcome.upper_consecutive_offline_limit_exceeded);
    }

    #[test]
    fn velocity_diff_above_both_limits() {
        let outcome = check_velocity(Some(5), Some(10), Some(20), Some(2));
        assert!(outcome.lower_consecutive_offline_limit_exceeded);
        assert!(outcome.upper_consecutive_offline_limit_exceeded);
    }

    #[test]
    fn velocity_diff_equal_to_upper_is_not_exceeded() {
        let outcome = check_velocity(Some(5), Some(10), Some(12), Some(2));
        assert!(outcome.lower_consecutive_offline_limit_exceeded);
        assert!(!outcome.upper_consecutive_offline_limit_exceeded);
    }

    #[test]
    fn velocity_zero_last_online_sets_new_card_in_normal_branch() {
        let outcome = check_velocity(Some(5), Some(10), Some(5), Some(0));
        assert!(!outcome.lower_consecutive_offline_limit_exceeded);
        assert!(!outcome.upper_consecutive_offline_limit_exceeded);
        assert!(outcome.new_card);
    }

    #[test]
    fn evaluate_clean_path_sets_no_bits() {
        let ctx = TerminalRiskManagementContext {
            amount_authorised: 50,
            floor_limit: 100,
            prior_amount_for_pan: None,
            random_selection_parameters: rts_params(50, 10, 90),
            random_number: Some(11),
            lower_consecutive_offline_limit: Some(5),
            upper_consecutive_offline_limit: Some(10),
            atc: Some(10),
            last_online_atc_register: Some(8),
        };
        assert_eq!(
            evaluate(&ctx).unwrap(),
            TerminalRiskManagementOutcome::default()
        );
    }

    #[test]
    fn evaluate_combines_all_three_checks() {
        let ctx = TerminalRiskManagementContext {
            amount_authorised: 150,
            floor_limit: 100,
            prior_amount_for_pan: None,
            random_selection_parameters: rts_params(50, 10, 90),
            random_number: Some(50),
            lower_consecutive_offline_limit: Some(5),
            upper_consecutive_offline_limit: Some(10),
            atc: Some(20),
            last_online_atc_register: Some(2),
        };
        let outcome = evaluate(&ctx).unwrap();
        assert!(outcome.transaction_exceeds_floor_limit);
        assert!(!outcome.transaction_selected_randomly_for_online_processing);
        assert!(outcome.lower_consecutive_offline_limit_exceeded);
        assert!(outcome.upper_consecutive_offline_limit_exceeded);
        assert!(!outcome.new_card);
    }

    #[test]
    fn evaluate_skips_rts_when_no_random_number_provided() {
        let ctx = TerminalRiskManagementContext {
            amount_authorised: 50,
            floor_limit: 100,
            prior_amount_for_pan: None,
            random_selection_parameters: rts_params(0, 99, 99),
            random_number: None,
            lower_consecutive_offline_limit: None,
            upper_consecutive_offline_limit: None,
            atc: None,
            last_online_atc_register: None,
        };
        let outcome = evaluate(&ctx).unwrap();
        assert!(!outcome.transaction_selected_randomly_for_online_processing);
    }

    #[test]
    fn evaluate_propagates_rts_validation_errors() {
        let ctx = TerminalRiskManagementContext {
            amount_authorised: 50,
            floor_limit: 100,
            prior_amount_for_pan: None,
            random_selection_parameters: rts_params(50, 100, 100),
            random_number: Some(1),
            lower_consecutive_offline_limit: None,
            upper_consecutive_offline_limit: None,
            atc: None,
            last_online_atc_register: None,
        };
        assert_eq!(evaluate(&ctx), Err(Error::InvalidValue));
    }
}
