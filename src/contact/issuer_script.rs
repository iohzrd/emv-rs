//! Book 3 §10.10 / Annex E p.193 - Issuer-to-Card Script Processing.

use crate::core::tag::Tag;
use crate::core::tags;
use crate::core::tlv::Tlv;
use crate::de::issuer_script_results::{IssuerScriptResult, ScriptResultNibble};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScriptTag {
    BeforeFinalGenerateAc,
    AfterFinalGenerateAc,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ScriptOutcome {
    pub tag: ScriptTag,
    pub result: IssuerScriptResult,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ScriptTvrUpdates {
    pub script_processing_failed_before_final_generate_ac: bool,
    pub script_processing_failed_after_final_generate_ac: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScriptProcessingOutcome {
    pub script_results: Vec<ScriptOutcome>,
    pub tvr_updates: ScriptTvrUpdates,
    pub tsi_script_processing_was_performed: bool,
}

/// `send` returns `(SW1, SW2)`; only SW1 is examined per §10.10.
pub fn process_scripts<F>(scripts: &[&Tlv], mut send: F) -> ScriptProcessingOutcome
where
    F: FnMut(&[u8]) -> (u8, u8),
{
    let mut results: Vec<ScriptOutcome> = Vec::new();
    let mut tvr = ScriptTvrUpdates::default();
    let mut tsi = false;

    for script_tlv in scripts {
        let script_tag = match classify_script_tag(script_tlv.tag()) {
            Some(t) => t,
            None => continue,
        };

        // §10.10 - set TSI 'Script processing was performed'.
        tsi = true;

        let outcome = process_one_script(script_tag, script_tlv, &mut send);
        match outcome.result.script_result {
            ScriptResultNibble::ScriptProcessingFailed | ScriptResultNibble::ScriptNotPerformed => {
                match script_tag {
                    ScriptTag::BeforeFinalGenerateAc => {
                        tvr.script_processing_failed_before_final_generate_ac = true;
                    }
                    ScriptTag::AfterFinalGenerateAc => {
                        tvr.script_processing_failed_after_final_generate_ac = true;
                    }
                }
            }
            ScriptResultNibble::ScriptProcessingSuccessful | ScriptResultNibble::Rfu(_) => {}
        }
        results.push(outcome);
    }

    ScriptProcessingOutcome {
        script_results: results,
        tvr_updates: tvr,
        tsi_script_processing_was_performed: tsi,
    }
}

fn classify_script_tag(tag: Tag) -> Option<ScriptTag> {
    if tag == tags::ISSUER_SCRIPT_TEMPLATE_1 {
        Some(ScriptTag::BeforeFinalGenerateAc)
    } else if tag == tags::ISSUER_SCRIPT_TEMPLATE_2 {
        Some(ScriptTag::AfterFinalGenerateAc)
    } else {
        None
    }
}

fn process_one_script<F>(tag: ScriptTag, script_tlv: &Tlv, send: &mut F) -> ScriptOutcome
where
    F: FnMut(&[u8]) -> (u8, u8),
{
    // Annex E Scenario 3 - primitive value is a parse error.
    let children = match script_tlv.value().as_constructed() {
        Some(c) => c,
        None => return parse_error(tag, [0u8; 4]),
    };

    let mut identifier = [0u8; 4];
    let mut commands: Vec<&[u8]> = Vec::new();

    for child in children {
        if child.tag() == tags::ISSUER_SCRIPT_IDENTIFIER {
            let bytes = match child.value().as_primitive() {
                Some(b) => b,
                None => return parse_error(tag, [0u8; 4]),
            };
            if bytes.len() != 4 {
                return parse_error(tag, [0u8; 4]);
            }
            identifier.copy_from_slice(bytes);
        } else if child.tag() == tags::ISSUER_SCRIPT_COMMAND {
            let bytes = match child.value().as_primitive() {
                Some(b) => b,
                None => return parse_error(tag, identifier),
            };
            commands.push(bytes);
        }
    }

    let mut last_sequence: u8 = 0;
    for (i, cmd) in commands.iter().enumerate() {
        let seq = encode_sequence(i + 1);
        last_sequence = seq;
        let (sw1, _sw2) = send(cmd);
        if !is_acceptable_sw1(sw1) {
            return ScriptOutcome {
                tag,
                result: IssuerScriptResult {
                    script_result: ScriptResultNibble::ScriptProcessingFailed,
                    script_number: seq,
                    script_identifier: identifier,
                },
            };
        }
    }

    // Annex E Scenario 1 - Book 4 §6.3.9: low nibble = 0 on success.
    let _ = last_sequence;
    ScriptOutcome {
        tag,
        result: IssuerScriptResult {
            script_result: ScriptResultNibble::ScriptProcessingSuccessful,
            script_number: 0,
            script_identifier: identifier,
        },
    }
}

fn parse_error(tag: ScriptTag, identifier: [u8; 4]) -> ScriptOutcome {
    ScriptOutcome {
        tag,
        result: IssuerScriptResult {
            script_result: ScriptResultNibble::ScriptNotPerformed,
            script_number: 0,
            script_identifier: identifier,
        },
    }
}

/// Annex A4 sequence-number nibble: 1..=14 → '1'..='E', ≥15 → 'F'.
fn encode_sequence(n_one_based: usize) -> u8 {
    if n_one_based >= 0x0F {
        0x0F
    } else {
        n_one_based as u8
    }
}

/// §10.10 / Annex E acceptable SW1: '90', '62', '63'.
fn is_acceptable_sw1(sw1: u8) -> bool {
    matches!(sw1, 0x90 | 0x62 | 0x63)
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn no_scripts_yields_no_tsi_no_tvr() {
        let outcome = process_scripts(&[], |_| (0x90, 0x00));
        assert!(outcome.script_results.is_empty());
        assert_eq!(outcome.tvr_updates, ScriptTvrUpdates::default());
        assert!(!outcome.tsi_script_processing_was_performed);
    }

    #[test]
    fn single_command_9000_is_successful() {
        let s = script_71(vec![cmd_tlv(&[0x84, 0x18, 0x00, 0x00])]);
        let mut calls = 0;
        let outcome = process_scripts(&[&s], |cmd| {
            calls += 1;
            assert_eq!(cmd, &[0x84, 0x18, 0x00, 0x00]);
            (0x90, 0x00)
        });
        assert_eq!(calls, 1);
        assert!(outcome.tsi_script_processing_was_performed);
        assert_eq!(outcome.tvr_updates, ScriptTvrUpdates::default());
        assert_eq!(outcome.script_results.len(), 1);
        let r = outcome.script_results[0].result;
        assert_eq!(
            r.script_result,
            ScriptResultNibble::ScriptProcessingSuccessful
        );
        assert_eq!(r.script_number, 0);
        assert_eq!(r.script_identifier, [0u8; 4]);
    }

    #[test]
    fn warning_sw1_62_and_63_are_acceptable() {
        let s = script_71(vec![
            cmd_tlv(&[0x84, 0x18, 0x00, 0x00]),
            cmd_tlv(&[0x84, 0x18, 0x00, 0x01]),
            cmd_tlv(&[0x84, 0x18, 0x00, 0x02]),
        ]);
        let mut idx = 0;
        let outcome = process_scripts(&[&s], |_| {
            idx += 1;
            match idx {
                1 => (0x90, 0x00),
                2 => (0x62, 0x81),
                3 => (0x63, 0x00),
                _ => unreachable!(),
            }
        });
        let r = outcome.script_results[0].result;
        assert_eq!(
            r.script_result,
            ScriptResultNibble::ScriptProcessingSuccessful
        );
        assert_eq!(outcome.tvr_updates, ScriptTvrUpdates::default());
    }

    #[test]
    fn script_with_identifier_records_it_on_success() {
        let s = script_71(vec![
            id_tlv([0x01, 0x02, 0x03, 0x04]),
            cmd_tlv(&[0x84, 0x18, 0x00, 0x00]),
        ]);
        let outcome = process_scripts(&[&s], |_| (0x90, 0x00));
        let r = outcome.script_results[0].result;
        assert_eq!(r.script_identifier, [0x01, 0x02, 0x03, 0x04]);
    }

    #[test]
    fn second_command_fails_terminates_script_with_seq_2() {
        let s = script_71(vec![
            cmd_tlv(&[0x84, 0x18, 0x00, 0x00]),
            cmd_tlv(&[0x84, 0x18, 0x00, 0x01]),
            cmd_tlv(&[0x84, 0x18, 0x00, 0x02]),
        ]);
        let mut idx = 0;
        let outcome = process_scripts(&[&s], |_| {
            idx += 1;
            if idx == 2 { (0x6A, 0x82) } else { (0x90, 0x00) }
        });
        assert_eq!(idx, 2);
        let r = outcome.script_results[0].result;
        assert_eq!(r.script_result, ScriptResultNibble::ScriptProcessingFailed);
        assert_eq!(r.script_number, 2);
        assert!(
            outcome
                .tvr_updates
                .script_processing_failed_before_final_generate_ac
        );
        assert!(
            !outcome
                .tvr_updates
                .script_processing_failed_after_final_generate_ac
        );
    }

    #[test]
    fn fifteenth_command_failing_uses_sequence_f() {
        let mut children = Vec::new();
        for _ in 0..16 {
            children.push(cmd_tlv(&[0x84, 0x18, 0x00, 0x00]));
        }
        let s = script_71(children);
        let mut idx = 0;
        let outcome = process_scripts(&[&s], |_| {
            idx += 1;
            if idx == 15 {
                (0x6A, 0x82)
            } else {
                (0x90, 0x00)
            }
        });
        assert_eq!(idx, 15);
        let r = outcome.script_results[0].result;
        assert_eq!(r.script_result, ScriptResultNibble::ScriptProcessingFailed);
        assert_eq!(r.script_number, 0x0F);
    }

    #[test]
    fn after_final_genac_failure_sets_b5_not_b6() {
        let s = script_72(vec![cmd_tlv(&[0x84, 0x18, 0x00, 0x00])]);
        let outcome = process_scripts(&[&s], |_| (0x6F, 0x00));
        assert!(
            !outcome
                .tvr_updates
                .script_processing_failed_before_final_generate_ac
        );
        assert!(
            outcome
                .tvr_updates
                .script_processing_failed_after_final_generate_ac
        );
    }

    #[test]
    fn malformed_identifier_length_is_scenario_3() {
        let s = script_71(vec![
            Tlv::primitive(tags::ISSUER_SCRIPT_IDENTIFIER, vec![0x01, 0x02, 0x03]),
            cmd_tlv(&[0x84, 0x18, 0x00, 0x00]),
        ]);
        let mut calls = 0;
        let outcome = process_scripts(&[&s], |_| {
            calls += 1;
            (0x90, 0x00)
        });
        assert_eq!(calls, 0);
        let r = outcome.script_results[0].result;
        assert_eq!(r.script_result, ScriptResultNibble::ScriptNotPerformed);
        assert_eq!(r.script_number, 0);
        assert!(
            outcome
                .tvr_updates
                .script_processing_failed_before_final_generate_ac
        );
        assert!(outcome.tsi_script_processing_was_performed);
    }

    #[test]
    fn multiple_scripts_processed_independently() {
        let s1 = script_71(vec![
            id_tlv([0xAA, 0xBB, 0xCC, 0xDD]),
            cmd_tlv(&[0x84, 0x18, 0x00, 0x00]),
        ]);
        let s2 = script_72(vec![
            id_tlv([0x11, 0x22, 0x33, 0x44]),
            cmd_tlv(&[0x84, 0x24, 0x00, 0x00]),
        ]);
        let mut idx = 0;
        let outcome = process_scripts(&[&s1, &s2], |_| {
            idx += 1;
            if idx == 1 { (0x90, 0x00) } else { (0x6A, 0x82) }
        });
        assert_eq!(outcome.script_results.len(), 2);
        assert_eq!(
            outcome.script_results[0].result.script_result,
            ScriptResultNibble::ScriptProcessingSuccessful
        );
        assert_eq!(
            outcome.script_results[1].result.script_result,
            ScriptResultNibble::ScriptProcessingFailed
        );
        assert_eq!(outcome.script_results[1].result.script_number, 1);
        assert!(
            !outcome
                .tvr_updates
                .script_processing_failed_before_final_generate_ac
        );
        assert!(
            outcome
                .tvr_updates
                .script_processing_failed_after_final_generate_ac
        );
    }

    #[test]
    fn second_script_processed_even_if_first_fails() {
        // Annex E E2.
        let s1 = script_71(vec![cmd_tlv(&[0x84, 0x18, 0x00, 0x00])]);
        let s2 = script_71(vec![cmd_tlv(&[0x84, 0x24, 0x00, 0x00])]);
        let mut commands_sent: Vec<Vec<u8>> = Vec::new();
        let outcome = process_scripts(&[&s1, &s2], |cmd| {
            commands_sent.push(cmd.to_vec());
            if commands_sent.len() == 1 {
                (0x6A, 0x82)
            } else {
                (0x90, 0x00)
            }
        });
        assert_eq!(commands_sent.len(), 2);
        assert_eq!(outcome.script_results.len(), 2);
        assert!(
            outcome
                .tvr_updates
                .script_processing_failed_before_final_generate_ac
        );
    }

    #[test]
    fn unrecognized_outer_tag_silently_skipped() {
        let not_a_script = Tlv::constructed(Tag(0x70), vec![]);
        let s = script_71(vec![cmd_tlv(&[0x84, 0x18, 0x00, 0x00])]);
        let outcome = process_scripts(&[&not_a_script, &s], |_| (0x90, 0x00));
        assert_eq!(outcome.script_results.len(), 1);
        assert_eq!(
            outcome.script_results[0].tag,
            ScriptTag::BeforeFinalGenerateAc
        );
    }

    #[test]
    fn empty_script_with_no_commands_is_successful_no_send() {
        let s = script_71(vec![id_tlv([0x01, 0x02, 0x03, 0x04])]);
        let mut calls = 0;
        let outcome = process_scripts(&[&s], |_| {
            calls += 1;
            (0x90, 0x00)
        });
        assert_eq!(calls, 0);
        let r = outcome.script_results[0].result;
        assert_eq!(
            r.script_result,
            ScriptResultNibble::ScriptProcessingSuccessful
        );
        assert_eq!(r.script_identifier, [0x01, 0x02, 0x03, 0x04]);
        assert!(outcome.tsi_script_processing_was_performed);
        assert_eq!(outcome.tvr_updates, ScriptTvrUpdates::default());
    }
}
