//! Book 1 §12 p.48 - Application Selection.

use crate::de::application_priority_indicator::ApplicationPriorityIndicator;
use crate::de::application_selection_indicator::ApplicationSelectionIndicator;
use crate::de::issuer_code_table_index::IssuerCodeTableIndex;
use crate::de::payment_system_directory::AdfDirectoryEntry;
use crate::core::fci::AdfFci;

/// §12.3.1.
pub fn aid_matches_df_name(
    terminal_aid: &[u8],
    asi: ApplicationSelectionIndicator,
    df_name: &[u8],
) -> bool {
    match asi {
        ApplicationSelectionIndicator::ExactMatch => terminal_aid == df_name,
        ApplicationSelectionIndicator::PartialMatchAllowed => df_name.starts_with(terminal_aid),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Candidate {
    pub df_name: Vec<u8>,
    pub application_label: Option<Vec<u8>>,
    pub application_preferred_name: Option<Vec<u8>>,
    pub application_priority_indicator: Option<ApplicationPriorityIndicator>,
    pub issuer_code_table_index: Option<IssuerCodeTableIndex>,
}

impl Candidate {
    /// §12.3.2 PSE method.
    pub fn from_directory_entry(
        entry: AdfDirectoryEntry,
        icti: Option<IssuerCodeTableIndex>,
    ) -> Self {
        Self {
            df_name: entry.adf_name,
            application_label: entry.application_label,
            application_preferred_name: entry.application_preferred_name,
            application_priority_indicator: entry.application_priority_indicator,
            issuer_code_table_index: icti,
        }
    }

    /// §12.3.3 AID-list method.
    pub fn from_adf_fci(fci: AdfFci) -> Self {
        Self {
            df_name: fci.df_name,
            application_label: fci.application_label,
            application_preferred_name: fci.application_preferred_name,
            application_priority_indicator: fci.application_priority_indicator,
            issuer_code_table_index: fci.issuer_code_table_index,
        }
    }

    fn requires_cardholder_confirmation(&self) -> bool {
        self.application_priority_indicator
            .map(|api| api.application_cannot_be_selected_without_confirmation_by_the_cardholder)
            .unwrap_or(false)
    }

    /// `1..=15`; `None` if API absent or priority == 0 (Table 13).
    fn priority_value(&self) -> Option<u8> {
        self.application_priority_indicator
            .map(|api| api.priority)
            .filter(|&p| p != 0)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FinalSelectionOutcome {
    Terminate,
    Select(usize),
    ConfirmAndSelect(usize),
    OfferToCardholder(Vec<usize>),
}

/// §12.4.
pub fn final_selection(
    candidates: &[Candidate],
    terminal_supports_cardholder_selection_and_confirmation: bool,
) -> FinalSelectionOutcome {
    match candidates.len() {
        0 => FinalSelectionOutcome::Terminate,
        1 => {
            let only = &candidates[0];
            if !only.requires_cardholder_confirmation() {
                // §12.4 rule 2.
                FinalSelectionOutcome::Select(0)
            } else if terminal_supports_cardholder_selection_and_confirmation {
                FinalSelectionOutcome::ConfirmAndSelect(0)
            } else {
                FinalSelectionOutcome::Terminate
            }
        }
        _ => {
            if terminal_supports_cardholder_selection_and_confirmation {
                // §12.4 rule 4.
                FinalSelectionOutcome::OfferToCardholder(priority_sorted_indices(candidates))
            } else {
                // §12.4 rule 5.
                let order = priority_sorted_indices(candidates);
                match order
                    .into_iter()
                    .find(|&i| !candidates[i].requires_cardholder_confirmation())
                {
                    Some(i) => FinalSelectionOutcome::Select(i),
                    None => FinalSelectionOutcome::Terminate,
                }
            }
        }
    }
}

/// §12.4 rule 4 stable-sort.
fn priority_sorted_indices(candidates: &[Candidate]) -> Vec<usize> {
    let mut indices: Vec<usize> = (0..candidates.len()).collect();
    indices.sort_by_key(|&i| match candidates[i].priority_value() {
        Some(p) => (0u8, p),
        None => (1u8, 0),
    });
    indices
}

#[cfg(test)]
mod tests {
    use super::*;

    fn api(priority: u8, b8: bool) -> ApplicationPriorityIndicator {
        ApplicationPriorityIndicator {
            application_cannot_be_selected_without_confirmation_by_the_cardholder: b8,
            priority,
            ..Default::default()
        }
    }

    fn candidate(df_name: &[u8], api_value: Option<ApplicationPriorityIndicator>) -> Candidate {
        Candidate {
            df_name: df_name.to_vec(),
            application_label: None,
            application_preferred_name: None,
            application_priority_indicator: api_value,
            issuer_code_table_index: None,
        }
    }

    #[test]
    fn exact_match_succeeds_only_on_byte_equality() {
        let aid = [0xA0, 0x00, 0x00, 0x00, 0x03];
        assert!(aid_matches_df_name(
            &aid,
            ApplicationSelectionIndicator::ExactMatch,
            &aid,
        ));
        let longer = [0xA0, 0x00, 0x00, 0x00, 0x03, 0x10, 0x10];
        assert!(!aid_matches_df_name(
            &aid,
            ApplicationSelectionIndicator::ExactMatch,
            &longer,
        ));
        assert!(!aid_matches_df_name(
            &aid,
            ApplicationSelectionIndicator::ExactMatch,
            &[0xA0, 0x00, 0x00, 0x00],
        ));
    }

    #[test]
    fn partial_match_allows_longer_df_name_starting_with_aid() {
        let aid = [0xA0, 0x00, 0x00, 0x00, 0x03];
        let longer = [0xA0, 0x00, 0x00, 0x00, 0x03, 0x10, 0x10];
        assert!(aid_matches_df_name(
            &aid,
            ApplicationSelectionIndicator::PartialMatchAllowed,
            &longer,
        ));
        assert!(aid_matches_df_name(
            &aid,
            ApplicationSelectionIndicator::PartialMatchAllowed,
            &aid,
        ));
        assert!(!aid_matches_df_name(
            &aid,
            ApplicationSelectionIndicator::PartialMatchAllowed,
            &[0xA0, 0x00, 0x00, 0x00, 0x04],
        ));
    }

    #[test]
    fn empty_candidates_terminate() {
        assert_eq!(
            final_selection(&[], true),
            FinalSelectionOutcome::Terminate,
        );
        assert_eq!(
            final_selection(&[], false),
            FinalSelectionOutcome::Terminate,
        );
    }

    #[test]
    fn single_candidate_no_confirmation_selects() {
        let c = [candidate(b"AAAAA", Some(api(1, false)))];
        assert_eq!(final_selection(&c, false), FinalSelectionOutcome::Select(0));
        assert_eq!(final_selection(&c, true), FinalSelectionOutcome::Select(0));
    }

    #[test]
    fn single_candidate_no_api_selects_directly() {
        let c = [candidate(b"AAAAA", None)];
        assert_eq!(final_selection(&c, false), FinalSelectionOutcome::Select(0));
    }

    #[test]
    fn single_candidate_b8_set_with_terminal_support_confirms() {
        let c = [candidate(b"AAAAA", Some(api(1, true)))];
        assert_eq!(
            final_selection(&c, true),
            FinalSelectionOutcome::ConfirmAndSelect(0),
        );
    }

    #[test]
    fn single_candidate_b8_set_without_terminal_support_terminates() {
        let c = [candidate(b"AAAAA", Some(api(1, true)))];
        assert_eq!(final_selection(&c, false), FinalSelectionOutcome::Terminate);
    }

    #[test]
    fn multiple_candidates_with_terminal_support_offers_in_priority_order() {
        let c = [
            candidate(b"AAA01", Some(api(3, false))),
            candidate(b"AAA02", Some(api(1, false))),
            candidate(b"AAA03", Some(api(2, false))),
        ];
        assert_eq!(
            final_selection(&c, true),
            FinalSelectionOutcome::OfferToCardholder(vec![1, 2, 0]),
        );
    }

    #[test]
    fn unprioritised_candidates_go_after_prioritised_in_encounter_order() {
        let c = [
            candidate(b"AAA00", None),
            candidate(b"AAA01", Some(api(2, false))),
            candidate(b"AAA02", Some(api(0, false))),
            candidate(b"AAA03", Some(api(1, false))),
        ];
        assert_eq!(
            final_selection(&c, true),
            FinalSelectionOutcome::OfferToCardholder(vec![3, 1, 0, 2]),
        );
    }

    #[test]
    fn equal_priority_ties_resolved_by_encounter_order() {
        let c = [
            candidate(b"AAA01", Some(api(1, false))),
            candidate(b"AAA02", Some(api(1, false))),
        ];
        assert_eq!(
            final_selection(&c, true),
            FinalSelectionOutcome::OfferToCardholder(vec![0, 1]),
        );
    }

    #[test]
    fn multiple_without_terminal_support_picks_highest_with_b8_zero() {
        let c = [
            candidate(b"AAA01", Some(api(1, true))),
            candidate(b"AAA02", Some(api(2, false))),
            candidate(b"AAA03", Some(api(3, false))),
        ];
        assert_eq!(final_selection(&c, false), FinalSelectionOutcome::Select(1));
    }

    #[test]
    fn multiple_without_terminal_support_skips_all_b8_one_candidates() {
        let c = [
            candidate(b"AAA01", Some(api(1, true))),
            candidate(b"AAA02", Some(api(2, true))),
        ];
        assert_eq!(final_selection(&c, false), FinalSelectionOutcome::Terminate);
    }

    #[test]
    fn multiple_without_terminal_support_treats_absent_api_as_b8_zero() {
        let c = [
            candidate(b"AAA01", None),
            candidate(b"AAA02", Some(api(1, true))),
        ];
        assert_eq!(final_selection(&c, false), FinalSelectionOutcome::Select(0));
    }

    #[test]
    fn candidate_from_directory_entry_takes_icti_from_pse() {
        let entry = AdfDirectoryEntry {
            adf_name: vec![0xA0, 0x00, 0x00, 0x00, 0x03],
            application_label: Some(b"VISA".to_vec()),
            application_preferred_name: None,
            application_priority_indicator: Some(api(2, false)),
            directory_discretionary_template: None,
        };
        let icti = IssuerCodeTableIndex(1);
        let c = Candidate::from_directory_entry(entry, Some(icti));
        assert_eq!(c.df_name, [0xA0, 0x00, 0x00, 0x00, 0x03]);
        assert_eq!(c.application_label.as_deref(), Some(&b"VISA"[..]));
        assert_eq!(c.issuer_code_table_index, Some(icti));
        assert_eq!(c.application_priority_indicator.unwrap().priority, 2);
    }
}
