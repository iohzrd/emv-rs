//! Book 3 §5.4 - DOL resolver driven by `TransactionContext`.

use crate::core::dol::{Dol, ValueFormat};
use crate::core::tag::Tag;
use crate::contact::transaction::TransactionContext;

pub trait DolResolveExt {
    fn resolve(&self, ctx: &TransactionContext<'_>) -> Vec<u8>;
}

impl DolResolveExt for Dol {
    fn resolve(&self, ctx: &TransactionContext<'_>) -> Vec<u8> {
        self.build(|tag| terminal_value_for(tag, ctx))
    }
}

fn terminal_value_for(tag: Tag, ctx: &TransactionContext<'_>) -> Option<(ValueFormat, Vec<u8>)> {
    match tag.0 {
        // 9F02 Amount Authorised - n12, 6 BCD.
        0x9F02 => Some((
            ValueFormat::Numeric,
            bcd_u64(ctx.inputs.amount_authorised, 6),
        )),
        // 81 Amount Authorised - 4 binary.
        0x81 => Some((ValueFormat::Other, be_u32(ctx.inputs.amount_authorised))),
        // 9F03 Amount Other - n12, 6 BCD.
        0x9F03 => Some((ValueFormat::Numeric, bcd_u64(ctx.inputs.amount_other, 6))),
        // 9F04 Amount Other - 4 binary.
        0x9F04 => Some((ValueFormat::Other, be_u32(ctx.inputs.amount_other))),

        // 5F2A Transaction Currency Code - n3, 2 BCD.
        0x5F2A => Some((
            ValueFormat::Numeric,
            bcd_u64(ctx.inputs.transaction_currency_code as u64, 2),
        )),
        // 5F36 Transaction Currency Exponent - n1, 1 BCD.
        0x5F36 => Some((
            ValueFormat::Numeric,
            bcd_u64(ctx.inputs.transaction_currency_exponent as u64, 1),
        )),

        // 9A Transaction Date - n6 BCD YYMMDD.
        0x9A => Some((ValueFormat::Numeric, ctx.inputs.transaction_date.to_vec())),
        // 9F21 Transaction Time - n6 BCD HHMMSS.
        0x9F21 => Some((ValueFormat::Numeric, ctx.inputs.transaction_time.to_vec())),
        // 9C Transaction Type - n2, 1 BCD.
        0x9C => Some((
            ValueFormat::Numeric,
            vec![ctx.inputs.transaction_type],
        )),
        // 9F41 Transaction Sequence Counter - n4-8 BCD.
        0x9F41 => Some((
            ValueFormat::Numeric,
            bcd_u64(ctx.inputs.transaction_sequence_counter as u64, 4),
        )),
        // 9F37 Unpredictable Number - 4 binary.
        0x9F37 => Some((
            ValueFormat::Other,
            ctx.inputs.unpredictable_number.to_vec(),
        )),

        // 9F1A Terminal Country Code - n3, 2 BCD.
        0x9F1A => Some((
            ValueFormat::Numeric,
            bcd_u64(ctx.terminal.terminal_country_code as u64, 2),
        )),
        // 9F35 Terminal Type.
        0x9F35 => Some((ValueFormat::Numeric, vec![ctx.terminal.terminal_type.0])),
        // 9F33 Terminal Capabilities.
        0x9F33 => Some((
            ValueFormat::Other,
            ctx.terminal.terminal_capabilities.to_bytes().to_vec(),
        )),
        // 9F40 Additional Terminal Capabilities.
        0x9F40 => Some((
            ValueFormat::Other,
            ctx.terminal.additional_terminal_capabilities.to_bytes().to_vec(),
        )),
        // 9F1C Terminal Identification.
        0x9F1C => Some((
            ValueFormat::Other,
            ctx.terminal.terminal_identification.to_vec(),
        )),
        // 9F1E IFD Serial Number.
        0x9F1E => Some((ValueFormat::Other, ctx.terminal.ifd_serial_number.to_vec())),
        // 9F15 Merchant Category Code - n4, 2 BCD.
        0x9F15 => Some((
            ValueFormat::Numeric,
            bcd_u64(ctx.terminal.merchant_category_code as u64, 2),
        )),
        // 9F16 Merchant Identifier.
        0x9F16 => Some((
            ValueFormat::Other,
            ctx.terminal.merchant_identifier.to_vec(),
        )),
        // 9F4E Merchant Name and Location.
        0x9F4E => Some((
            ValueFormat::Other,
            ctx.terminal.merchant_name_and_location.clone(),
        )),
        // 9F01 Acquirer Identifier - n11, 6 BCD.
        0x9F01 => ctx
            .terminal
            .acquirer_identifier
            .map(|a| (ValueFormat::Numeric, a.to_vec())),

        // 9F09 Application Version Number, terminal.
        0x9F09 => ctx.selected.as_ref().map(|s| {
            (
                ValueFormat::Other,
                s.config.application_version_number.to_vec(),
            )
        }),
        // 9F1B Terminal Floor Limit - 4 binary.
        0x9F1B => ctx.selected.as_ref().map(|s| {
            (
                ValueFormat::Other,
                s.config.terminal_floor_limit.to_be_bytes().to_vec(),
            )
        }),
        // 9F1D Terminal Risk Management Data.
        0x9F1D => ctx.selected.as_ref().and_then(|s| {
            s.config
                .terminal_risk_management_data
                .as_ref()
                .map(|v| (ValueFormat::Other, v.clone()))
        }),

        // 95 TVR.
        0x95 => Some((ValueFormat::Other, ctx.tvr.to_bytes().to_vec())),
        // 9B TSI.
        0x9B => Some((ValueFormat::Other, ctx.tsi.to_bytes().to_vec())),
        // 9F5B Issuer Script Results - empty falls through to §5.4 zero-fill.
        0x9F5B if !ctx.issuer_script_results.is_empty() => {
            let mut bytes = Vec::with_capacity(ctx.issuer_script_results.len() * 5);
            for entry in &ctx.issuer_script_results {
                bytes.extend_from_slice(&entry.to_bytes());
            }
            Some((ValueFormat::Other, bytes))
        }

        // 98 TC Hash Value - Book 3 §9.2.2.
        0x98 => ctx.tc_hash_value.map(|h| (ValueFormat::Other, h.to_vec())),

        _ => None,
    }
}

/// Annex B — right-justified BCD with leading zeroes (format n).
pub fn bcd_u64(mut value: u64, byte_len: usize) -> Vec<u8> {
    let n_digits = byte_len * 2;
    let mut digits = vec![0u8; n_digits];
    for slot in digits.iter_mut().rev() {
        *slot = (value % 10) as u8;
        value /= 10;
    }
    digits
        .chunks_exact(2)
        .map(|c| (c[0] << 4) | c[1])
        .collect()
}

fn be_u32(value: u64) -> Vec<u8> {
    (value as u32).to_be_bytes().to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::de::additional_terminal_capabilities::AdditionalTerminalCapabilities;
    use crate::de::terminal_capabilities::TerminalCapabilities;
    use crate::de::terminal_type::TerminalType;
    use crate::core::dol::DolEntry;
    use crate::contact::terminal::{Terminal, TerminalApplication};
    use crate::contact::transaction::{TransactionContext, TransactionInputs};

    fn fixture_terminal() -> Terminal {
        Terminal {
            terminal_type: TerminalType(0x22),
            terminal_capabilities: TerminalCapabilities {
                ic_with_contacts: true,
                plaintext_pin_for_icc_verification: true,
                signature: true,
                cda: true,
                ..Default::default()
            },
            additional_terminal_capabilities: AdditionalTerminalCapabilities {
                goods: true,
                services: true,
                ..Default::default()
            },
            terminal_country_code: 840,
            terminal_identification: *b"TERMID01",
            ifd_serial_number: *b"IFDSN001",
            merchant_category_code: 5999,
            merchant_identifier: *b"MERCHANT0000001",
            merchant_name_and_location: b"Acme Corp / NYC".to_vec(),
            acquirer_identifier: Some([0x12, 0x34, 0x56, 0x78, 0x90, 0x12]),
            cardholder_selection_and_confirmation_supported: true,
            applications: vec![TerminalApplication {
                aid: vec![0xA0, 0, 0, 0, 0x03, 0x10, 0x10],
                partial_match_allowed: false,
                application_version_number: [0x00, 0x8C],
                terminal_floor_limit: 10_000,
                terminal_risk_management_data: Some(vec![0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88]),
                default_ddol: None,
                default_tdol: None,
                tac_denial: None,
                tac_online: Some([0xFF, 0xFF, 0xFF, 0xFF, 0xFF]),
                tac_default: None,
                rts_target_percentage: None,
                rts_max_target_percentage: None,
                rts_threshold_value: None,
            }],
        }
    }

    fn fixture_inputs() -> TransactionInputs {
        TransactionInputs {
            amount_authorised: 12_345,
            amount_other: 0,
            transaction_currency_code: 840,
            transaction_currency_exponent: 2,
            transaction_date: [0x26, 0x04, 0x28],
            transaction_time: [0x14, 0x30, 0x00],
            transaction_type: 0x00,
            transaction_sequence_counter: 1,
            unpredictable_number: [0xDE, 0xAD, 0xBE, 0xEF],
        }
    }

    fn ctx_selected<'t>(t: &'t Terminal) -> TransactionContext<'t> {
        let mut ctx = TransactionContext::new(t, fixture_inputs());
        ctx.select_application(vec![0xA0, 0, 0, 0, 0x03, 0x10, 0x10]);
        ctx
    }

    #[test]
    fn bcd_u64_basic() {
        assert_eq!(bcd_u64(0, 1), vec![0x00]);
        assert_eq!(bcd_u64(9, 1), vec![0x09]);
        assert_eq!(bcd_u64(840, 2), vec![0x08, 0x40]);
        assert_eq!(
            bcd_u64(12_345, 6),
            vec![0x00, 0x00, 0x00, 0x01, 0x23, 0x45]
        );
        assert_eq!(
            bcd_u64(999_999_999_999, 6),
            vec![0x99, 0x99, 0x99, 0x99, 0x99, 0x99]
        );
    }

    fn resolve_one(tag: u32, len: u8, ctx: &TransactionContext) -> Vec<u8> {
        Dol(vec![DolEntry {
            tag: Tag(tag),
            length: len,
        }])
        .resolve(ctx)
    }

    #[test]
    fn amount_authorised_numeric_and_binary() {
        let t = fixture_terminal();
        let ctx = ctx_selected(&t);
        assert_eq!(
            resolve_one(0x9F02, 6, &ctx),
            vec![0x00, 0x00, 0x00, 0x01, 0x23, 0x45]
        );
        assert_eq!(resolve_one(0x81, 4, &ctx), vec![0x00, 0x00, 0x30, 0x39]);
    }

    #[test]
    fn currency_and_exponent() {
        let t = fixture_terminal();
        let ctx = ctx_selected(&t);
        assert_eq!(resolve_one(0x5F2A, 2, &ctx), vec![0x08, 0x40]);
        assert_eq!(resolve_one(0x5F36, 1, &ctx), vec![0x02]);
    }

    #[test]
    fn date_time_type_un_passthrough() {
        let t = fixture_terminal();
        let ctx = ctx_selected(&t);
        assert_eq!(resolve_one(0x9A, 3, &ctx), vec![0x26, 0x04, 0x28]);
        assert_eq!(resolve_one(0x9F21, 3, &ctx), vec![0x14, 0x30, 0x00]);
        assert_eq!(resolve_one(0x9C, 1, &ctx), vec![0x00]);
        assert_eq!(
            resolve_one(0x9F37, 4, &ctx),
            vec![0xDE, 0xAD, 0xBE, 0xEF]
        );
    }

    #[test]
    fn terminal_country_type_capabilities() {
        let t = fixture_terminal();
        let ctx = ctx_selected(&t);
        assert_eq!(resolve_one(0x9F1A, 2, &ctx), vec![0x08, 0x40]);
        assert_eq!(resolve_one(0x9F35, 1, &ctx), vec![0x22]);
        assert_eq!(
            resolve_one(0x9F33, 3, &ctx),
            t.terminal_capabilities.to_bytes().to_vec()
        );
        assert_eq!(
            resolve_one(0x9F40, 5, &ctx),
            t.additional_terminal_capabilities.to_bytes().to_vec()
        );
        assert_eq!(
            resolve_one(0x9F1C, 8, &ctx),
            b"TERMID01".to_vec()
        );
        assert_eq!(
            resolve_one(0x9F1E, 8, &ctx),
            b"IFDSN001".to_vec()
        );
        assert_eq!(resolve_one(0x9F15, 2, &ctx), vec![0x59, 0x99]);
        assert_eq!(
            resolve_one(0x9F16, 15, &ctx),
            b"MERCHANT0000001".to_vec()
        );
        assert_eq!(
            resolve_one(0x9F01, 6, &ctx),
            vec![0x12, 0x34, 0x56, 0x78, 0x90, 0x12]
        );
    }

    #[test]
    fn per_aid_tags_after_selection() {
        let t = fixture_terminal();
        let ctx = ctx_selected(&t);
        assert_eq!(resolve_one(0x9F09, 2, &ctx), vec![0x00, 0x8C]);
        assert_eq!(
            resolve_one(0x9F1B, 4, &ctx),
            vec![0x00, 0x00, 0x27, 0x10]
        );
        assert_eq!(
            resolve_one(0x9F1D, 8, &ctx),
            vec![0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88]
        );
    }

    #[test]
    fn per_aid_tags_zero_fill_before_selection() {
        let t = fixture_terminal();
        let ctx = TransactionContext::new(&t, fixture_inputs());
        assert!(ctx.selected.is_none());
        assert_eq!(resolve_one(0x9F09, 2, &ctx), vec![0x00, 0x00]);
        assert_eq!(
            resolve_one(0x9F1B, 4, &ctx),
            vec![0x00, 0x00, 0x00, 0x00]
        );
        assert_eq!(resolve_one(0x9F1D, 8, &ctx), vec![0x00; 8]);
    }

    #[test]
    fn acquirer_identifier_optional_zero_fills() {
        let mut t = fixture_terminal();
        t.acquirer_identifier = None;
        let ctx = ctx_selected(&t);
        assert_eq!(resolve_one(0x9F01, 6, &ctx), vec![0x00; 6]);
    }

    #[test]
    fn risk_management_data_optional_zero_fills() {
        let mut t = fixture_terminal();
        t.applications[0].terminal_risk_management_data = None;
        let ctx = ctx_selected(&t);
        assert_eq!(resolve_one(0x9F1D, 8, &ctx), vec![0x00; 8]);
    }

    #[test]
    fn tvr_tsi_reflect_runtime_state() {
        let t = fixture_terminal();
        let mut ctx = ctx_selected(&t);
        ctx.tvr.transaction_exceeds_floor_limit = true;
        ctx.tsi.terminal_risk_management_was_performed = true;
        let tvr = resolve_one(0x95, 5, &ctx);
        assert_eq!(tvr, ctx.tvr.to_bytes().to_vec());
        assert_eq!(tvr[3] & 0x80, 0x80);
        let tsi = resolve_one(0x9B, 2, &ctx);
        assert_eq!(tsi, ctx.tsi.to_bytes().to_vec());
        assert_eq!(tsi[0] & 0x08, 0x08);
    }

    #[test]
    fn unknown_tag_zero_fills() {
        let t = fixture_terminal();
        let ctx = ctx_selected(&t);
        assert_eq!(resolve_one(0x9F45, 2, &ctx), vec![0x00, 0x00]);
        assert_eq!(resolve_one(0x9F34, 3, &ctx), vec![0x00; 3]);
    }

    #[test]
    fn issuer_script_results_empty_zero_fills() {
        let t = fixture_terminal();
        let ctx = ctx_selected(&t);
        assert!(ctx.issuer_script_results.is_empty());
        assert_eq!(resolve_one(0x9F5B, 5, &ctx), vec![0x00; 5]);
    }

    #[test]
    fn tc_hash_value_uncomputed_zero_fills() {
        let t = fixture_terminal();
        let ctx = ctx_selected(&t);
        assert!(ctx.tc_hash_value.is_none());
        assert_eq!(resolve_one(0x98, 20, &ctx), vec![0x00; 20]);
    }

    #[test]
    fn tc_hash_value_when_computed_returns_hash() {
        let t = fixture_terminal();
        let mut ctx = ctx_selected(&t);
        let mut digest = [0u8; 20];
        for (i, b) in digest.iter_mut().enumerate() {
            *b = i as u8;
        }
        ctx.tc_hash_value = Some(digest);
        assert_eq!(resolve_one(0x98, 20, &ctx), digest.to_vec());
    }

    #[test]
    fn issuer_script_results_serialises_accumulator() {
        use crate::de::issuer_script_results::{IssuerScriptResult, ScriptResultNibble};
        let t = fixture_terminal();
        let mut ctx = ctx_selected(&t);
        ctx.issuer_script_results = vec![
            IssuerScriptResult {
                script_result: ScriptResultNibble::ScriptProcessingSuccessful,
                script_number: 0,
                script_identifier: [0xAA, 0xBB, 0xCC, 0xDD],
            },
            IssuerScriptResult {
                script_result: ScriptResultNibble::ScriptProcessingFailed,
                script_number: 2,
                script_identifier: [0x11, 0x22, 0x33, 0x44],
            },
        ];
        let bytes = resolve_one(0x9F5B, 10, &ctx);
        assert_eq!(
            bytes,
            vec![
                0x20, 0xAA, 0xBB, 0xCC, 0xDD,
                0x12, 0x11, 0x22, 0x33, 0x44,
            ]
        );
    }

    #[test]
    fn constructed_tag_zero_fills() {
        let t = fixture_terminal();
        let ctx = ctx_selected(&t);
        assert_eq!(resolve_one(0x70, 4, &ctx), vec![0x00; 4]);
    }

    #[test]
    fn typical_pdol_visa_kernel() {
        let pdol = Dol::parse(&[
            0x9F, 0x33, 0x03, 0x9F, 0x1A, 0x02, 0x5F, 0x2A, 0x02, 0x9A, 0x03, 0x9C, 0x01, 0x9F,
            0x37, 0x04,
        ])
        .unwrap();
        let t = fixture_terminal();
        let ctx = ctx_selected(&t);
        let resolved = pdol.resolve(&ctx);

        let mut expected = Vec::new();
        expected.extend_from_slice(&t.terminal_capabilities.to_bytes());
        expected.extend_from_slice(&[0x08, 0x40]);
        expected.extend_from_slice(&[0x08, 0x40]);
        expected.extend_from_slice(&[0x26, 0x04, 0x28]);
        expected.push(0x00);
        expected.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]);
        assert_eq!(resolved, expected);
    }

    #[test]
    fn typical_cdol1_with_card_source_zero_fills() {
        let cdol1 = Dol::parse(&[
            0x9F, 0x02, 0x06, 0x9F, 0x03, 0x06, 0x9F, 0x1A, 0x02, 0x95, 0x05, 0x5F, 0x2A, 0x02,
            0x9A, 0x03, 0x9C, 0x01, 0x9F, 0x37, 0x04, 0x9F, 0x45, 0x02, 0x9F, 0x4C, 0x08, 0x9F,
            0x34, 0x03,
        ])
        .unwrap();
        let t = fixture_terminal();
        let ctx = ctx_selected(&t);
        let resolved = cdol1.resolve(&ctx);

        let total: usize = cdol1.0.iter().map(|e| e.length as usize).sum();
        assert_eq!(resolved.len(), total);
        let tail = &resolved[resolved.len() - 13..];
        assert!(tail.iter().all(|&b| b == 0));
    }
}
