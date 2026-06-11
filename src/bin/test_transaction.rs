//! End-to-end EMV test transaction over PC/SC.

use std::env;
use std::fs::File;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use emv::config::{AidsConfig, CapkConfig, CrlConfig, TerminalConfig, assemble_terminal};
use emv::contact::application_selection::{FinalSelectionOutcome, final_selection};
use emv::contact::card_action_analysis::CardAction;
use emv::contact::cardholder_verification::{self, CvmExecutionResult};
use emv::contact::dol_resolve::DolResolveExt;
use emv::contact::issuer_script::{ScriptOutcome, ScriptProcessingOutcome, ScriptTag};
use emv::contact::online_processing::{
    OnlineAuthorisation, OnlineAuthorisationOutcome, OnlineAuthorisationResponse,
    second_generate_ac_after_online,
};
use emv::contact::processing_restrictions::TransactionCategory;
use emv::contact::terminal::Terminal;
use emv::contact::transaction::CvmFlags;
use emv::contact::transaction::{TransactionContext, TransactionInputs};
use emv::contact::transaction_driver::Transaction;
use emv::core::application_cryptogram_type::ApplicationCryptogramType;
use emv::core::dol::Dol;
use emv::core::generate_ac::{GenerateAcResponse, SignatureRequest};
use emv::core::tag_store::Source;
use emv::core::tags;
use emv::core::tlv::Tlv;
use emv::de::authorisation_response_code::AuthorisationResponseCode;
use emv::de::issuer_script_results::ScriptResultNibble;
use emv::pcsc::PcscCardReader;
use pcsc::{Context, Protocols, ReaderState, Scope, ShareMode, State};

struct Args {
    explicit_aid: Option<Vec<u8>>,
    terminal_path: Option<PathBuf>,
    aids_path: Option<PathBuf>,
    capk_path: Option<PathBuf>,
    crl_path: Option<PathBuf>,
}

fn parse_args() -> Result<Args, String> {
    let mut args = env::args().skip(1);
    let mut out = Args {
        explicit_aid: None,
        terminal_path: None,
        aids_path: None,
        capk_path: None,
        crl_path: None,
    };
    while let Some(a) = args.next() {
        match a.as_str() {
            "-h" | "--help" => return Err("help".into()),
            "--aid" => {
                let v = args.next().ok_or("--aid requires a hex value")?;
                out.explicit_aid = Some(parse_hex(&v).map_err(|e| format!("--aid: {}", e))?);
            }
            "--terminal" => {
                out.terminal_path = Some(PathBuf::from(
                    args.next().ok_or("--terminal requires a path")?,
                ));
            }
            "--aids" => {
                out.aids_path = Some(PathBuf::from(args.next().ok_or("--aids requires a path")?));
            }
            "--capk" => {
                out.capk_path = Some(PathBuf::from(args.next().ok_or("--capk requires a path")?));
            }
            "--crl" => {
                out.crl_path = Some(PathBuf::from(args.next().ok_or("--crl requires a path")?));
            }
            other => return Err(format!("unexpected argument: {}", other)),
        }
    }
    Ok(out)
}

fn print_usage() {
    eprintln!(
        "usage: emv-test-transaction [--aid <HEX>] \
         [--terminal <path>] [--aids <path>] [--capk <path>] [--crl <path>]"
    );
    eprintln!();
    eprintln!("Without flags, probes the AID list from `aids.toml` via PSE then List-of-AIDs");
    eprintln!("(Book 1 §12.3). With --aid, SELECTs only that AID directly.");
    eprintln!();
    eprintln!("Phase 5 prompts at stdin for the online auth response - accepts either a");
    eprintln!("2-character ARC shortcut (e.g. '00', '05', 'Z1') or a full hex BER-TLV blob");
    eprintln!("with tags 8A (ARC), 91 (Issuer Auth Data), 71/72 (Issuer Scripts).");
}

fn main() -> ExitCode {
    let args = match parse_args() {
        Ok(a) => a,
        Err(e) if e == "help" => {
            print_usage();
            return ExitCode::from(2);
        }
        Err(e) => {
            eprintln!("{}", e);
            print_usage();
            return ExitCode::from(2);
        }
    };
    if let Err(e) = run(&args) {
        eprintln!("\nERROR: {}", e);
        return ExitCode::from(1);
    }
    ExitCode::SUCCESS
}

fn run(args: &Args) -> Result<(), Box<dyn std::error::Error>> {
    let terminal_path = resolve_config(args.terminal_path.as_deref(), "terminal.toml")?;
    println!("Loading terminal config from {}", terminal_path.display());
    let terminal_cfg = TerminalConfig::load(&terminal_path)?;

    let aids_path = resolve_config(args.aids_path.as_deref(), "aids.toml")?;
    println!("Loading AIDs from {}", aids_path.display());
    let mut aids_cfg = AidsConfig::load(&aids_path)?;

    if let Some(aid) = &args.explicit_aid {
        aids_cfg.aids.retain(|e| {
            parse_hex(&e.aid)
                .map(|bytes| bytes == *aid)
                .unwrap_or(false)
        });
        if aids_cfg.aids.is_empty() {
            aids_cfg.aids.push(emv::config::AidEntry {
                aid: hex(aid),
                application_version_number: "008C".to_string(),
                partial_match_allowed: Some(true),
                terminal_floor_limit: None,
                tac_denial: Some("0000000000".into()),
                tac_online: Some("FFFFFFFFFF".into()),
                tac_default: Some("0000000000".into()),
                default_ddol: None,
                default_tdol: None,
                terminal_risk_management_data: None,
                rts_target_percentage: None,
                rts_max_target_percentage: None,
                rts_threshold_value: None,
            });
        }
    }
    println!("Loaded {} AID(s)", aids_cfg.aids.len());

    let (rsa_keys, ecc_keys) = match resolve_optional_config(args.capk_path.as_deref(), "capk.toml")
    {
        Ok(Some(p)) => {
            println!("Loading CAPKs from {}", p.display());
            let cfg = CapkConfig::load(&p)?;
            cfg.into_kernel()?
        }
        Ok(None) => {
            println!("No CAPK config found - ODA verification will not be exercised.");
            (vec![], vec![])
        }
        Err(e) => return Err(e),
    };
    println!(
        "Loaded {} RSA CAPK(s) and {} ECC CAPK(s)",
        rsa_keys.len(),
        ecc_keys.len()
    );

    let crl = match resolve_optional_config(args.crl_path.as_deref(), "crl.toml") {
        Ok(Some(p)) => {
            println!("Loading CRL from {}", p.display());
            CrlConfig::load(&p)?.into_kernel()?
        }
        Ok(None) => Vec::new(),
        Err(e) => return Err(e),
    };
    println!("Loaded {} CRL entry/entries", crl.len());

    let currency_code = aids_cfg.defaults.transaction_currency_code.unwrap_or(840);
    let currency_exponent = aids_cfg.defaults.transaction_currency_exponent.unwrap_or(2);

    let terminal: Terminal = assemble_terminal(&terminal_cfg, &aids_cfg)?;
    println!(
        "Terminal: type=0x{:02X}, country={}, {} application(s)",
        terminal.terminal_type.0,
        terminal.terminal_country_code,
        terminal.applications.len()
    );
    println!();

    let pcsc_ctx = Context::establish(Scope::User)?;
    let mut readers_buf = [0u8; 2048];
    let reader_name = pcsc_ctx
        .list_readers(&mut readers_buf)?
        .next()
        .ok_or("no PC/SC readers found")?
        .to_owned();
    println!("Reader: {}", reader_name.to_string_lossy());

    let mut states = vec![ReaderState::new(reader_name.clone(), State::UNAWARE)];
    pcsc_ctx.get_status_change(None, &mut states)?;
    if !states[0].event_state().contains(State::PRESENT) {
        eprintln!("Insert card…");
        loop {
            states[0].sync_current_state();
            pcsc_ctx.get_status_change(None, &mut states)?;
            if states[0].event_state().contains(State::PRESENT) {
                break;
            }
        }
    }

    let raw_card = pcsc_ctx.connect(&reader_name, ShareMode::Shared, Protocols::ANY)?;
    let card = PcscCardReader::from(raw_card);
    println!("Connected to card.");
    println!();

    let inputs = TransactionInputs {
        amount_authorised: 5000,
        amount_other: 0,
        transaction_currency_code: currency_code,
        transaction_currency_exponent: currency_exponent,
        transaction_date: [0x26, 0x04, 0x28],
        transaction_time: [0x12, 0x00, 0x00],
        transaction_type: 0x01,
        transaction_sequence_counter: 1,
        unpredictable_number: random_un()?,
    };

    let mut tx = Transaction::new(card, &terminal, inputs, InteractiveHost);

    // Phase 1: Discovery (Book 1 §12.3) + Final Selection (§12.4)
    let fci = match &args.explicit_aid {
        Some(aid) => {
            println!(
                "Explicit --aid {}: skipping discovery, SELECT directly.",
                hex(aid)
            );
            tx.select_application(aid)
                .map_err(|e| format!("SELECT: {:?}", e))?
        }
        None => {
            println!("Discovering applications via PSE → List-of-AIDs fallback…");
            let candidates = tx
                .build_candidate_list()
                .map_err(|e| format!("discovery: {:?}", e))?;
            if candidates.is_empty() {
                return Err("no application candidates found on this card".into());
            }
            println!("Found {} candidate(s):", candidates.len());
            for (i, c) in candidates.iter().enumerate() {
                let label = c
                    .application_label
                    .as_ref()
                    .map(|b| String::from_utf8_lossy(b).into_owned())
                    .unwrap_or_else(|| "<no label>".to_string());
                let pri = c
                    .application_priority_indicator
                    .map(|api| api.priority.to_string())
                    .unwrap_or_else(|| "-".into());
                println!("  [{}] {} ({}) priority={}", i, hex(&c.df_name), label, pri);
            }

            let chosen_idx = match final_selection(&candidates, false) {
                FinalSelectionOutcome::Select(i) => i,
                FinalSelectionOutcome::Terminate => {
                    return Err("§12.4 final_selection → Terminate".into());
                }
                FinalSelectionOutcome::ConfirmAndSelect(_) => {
                    return Err(
                        "single candidate requires cardholder confirmation; this demo does not perform it".into(),
                    );
                }
                FinalSelectionOutcome::OfferToCardholder(order) => {
                    *order.first().expect("non-empty order")
                }
            };
            let chosen = &candidates[chosen_idx];
            println!("Final selection: [{}] {}", chosen_idx, hex(&chosen.df_name));
            tx.select_application(&chosen.df_name)
                .map_err(|e| format!("final SELECT: {:?}", e))?
        }
    };
    println!("  DF Name:   {}", hex(&fci.df_name));
    println!(
        "  Label:     {}",
        fci.application_label
            .as_deref()
            .map(String::from_utf8_lossy)
            .unwrap_or_else(|| "<no label>".into()),
    );
    if let Some(name) = &fci.application_preferred_name {
        println!("  Pref Name: {}", String::from_utf8_lossy(name));
    }
    if let Some(pdol) = &fci.pdol {
        print!("  PDOL:     ");
        for entry in &pdol.0 {
            print!(" {}({})", hex(&entry.tag.to_bytes()), entry.length);
        }
        println!();
    }
    println!();

    // Phase 2: GET PROCESSING OPTIONS
    let pdol_data = fci
        .pdol
        .as_ref()
        .map(|d| d.resolve(&tx.ctx))
        .unwrap_or_default();
    if let Some(pdol) = &fci.pdol {
        println!(
            "PDOL data: {} ({} bytes from {} entries)",
            hex(&pdol_data),
            pdol_data.len(),
            pdol.0.len()
        );
    }
    let _gpo = tx
        .initiate(&pdol_data)
        .map_err(|e| format!("GPO: {:?}", e))?;
    let aip = tx.ctx.aip.as_ref().expect("aip set after initiate");
    let afl = tx.ctx.afl.as_ref().expect("afl set after initiate");
    println!("GPO");
    println!("  AIP:  {}", hex(&aip.to_bytes()));
    println!("  AFL entries:");
    for entry in &afl.0 {
        println!(
            "    SFI={} records {}..={} (oda count {})",
            entry.sfi, entry.first_record, entry.last_record, entry.oda_record_count,
        );
    }
    println!();

    // Phase 3: READ APPLICATION DATA
    let read = tx
        .read_application_data()
        .map_err(|e| format!("READ: {:?}", e))?;
    println!("READ");
    println!("  TagStore primitives: {}", tx.ctx.tag_store.len());
    println!("  ODA input bytes:     {}", read.oda_input.len());
    if read.oda_record_not_seventy_template {
        println!("  Note: at least one ODA record was not '70'-coded; ODA would fail.");
    }
    println!();

    // Phase 3.3: Offline Data Authentication (B3 §10.3)
    let oda = tx
        .perform_offline_data_authentication(&rsa_keys, &ecc_keys, &crl, &read.oda_input)
        .map_err(|e| format!("ODA: {:?}", e))?;
    println!("Offline Data Authentication → {:?}", oda);
    let cda_armed = matches!(oda, emv::core::oda::OdaOutcome::CdaArmed);
    let xda_armed = matches!(oda, emv::core::oda::OdaOutcome::XdaArmed);
    if cda_armed {
        println!("  CDA armed: ICC PK recovered; SDAD verification deferred to GENERATE AC.");
    }
    if xda_armed {
        match tx.ctx.xda.as_ref().map(|x| &x.state) {
            Some(emv::core::oda::XdaArmingState::Armed { .. }) => {
                println!(
                    "  XDA armed: ECC chain recovered; SDAD verification deferred to GENERATE AC."
                );
            }
            Some(emv::core::oda::XdaArmingState::CaMissing) => {
                println!(
                    "  XDA selected but CA ECC key missing - TVR bit applied after first GenAC."
                );
            }
            Some(emv::core::oda::XdaArmingState::RecoveryFailed) => {
                println!(
                    "  XDA selected but ECC recovery failed - TVR bit applied after first GenAC."
                );
            }
            None => {}
        }
    }
    println!("  TVR now: {}", hex(&tx.ctx.tvr.to_bytes()));
    println!("  TSI now: {}", hex(&tx.ctx.tsi.to_bytes()));
    println!();

    // Phase 3.5: Processing Restrictions (B3 §10.4)
    let category = TransactionCategory::from_transaction_type(tx.ctx.inputs.transaction_type);
    let has_cashback = tx.ctx.inputs.amount_other > 0;
    let pr = tx
        .ctx
        .process_restrictions(category, has_cashback)
        .map_err(|e| format!("Processing Restrictions: {:?}", e))?;
    println!("Processing Restrictions");
    println!(
        "  AVN mismatch:               {}",
        pr.icc_and_terminal_have_different_application_versions
    );
    println!(
        "  Service not allowed (AUC):  {}",
        pr.requested_service_not_allowed_for_card_product
    );
    println!(
        "  Application not yet eff:    {}",
        pr.application_not_yet_effective
    );
    println!("  Expired application:        {}", pr.expired_application);
    println!("  TVR now: {}", hex(&tx.ctx.tvr.to_bytes()));
    println!();

    // Phase 3.55: Cardholder Verification (B3 §10.5)
    let cvm_flags = CvmFlags {
        transaction_in_application_currency: true,
        ..Default::default()
    };
    let pin_encipherment_pk =
        cardholder_verification::recover_pin_encipherment_public_key(&tx.ctx, &rsa_keys);
    if let Some(pk) = &pin_encipherment_pk {
        println!(
            "ICC PIN Encipherment PK ready ({} bytes).",
            pk.modulus.len()
        );
        println!();
    }

    let cvm_card = &mut tx.card;
    let cvm_ctx = &mut tx.ctx;
    let cvm = cvm_ctx
        .cardholder_verification(cvm_flags, |rule| {
            use emv::de::cardholder_verification_method_list::CardholderVerificationMethod::*;
            match rule.method() {
                NoCvmRequired => CvmExecutionResult::Successful,
                Signature => CvmExecutionResult::Unknown,
                PlaintextPinVerificationPerformedByIcc
                | PlaintextPinVerificationPerformedByIccAndSignature => {
                    println!("CVM: plaintext offline PIN required.");
                    run_plaintext_offline_pin(cvm_card)
                }
                EncipheredPinVerificationPerformedByIcc
                | EncipheredPinVerificationPerformedByIccAndSignature => {
                    println!("CVM: enciphered offline PIN required.");
                    match &pin_encipherment_pk {
                        Some(pk) => run_enciphered_offline_pin(cvm_card, pk),
                        None => {
                            eprintln!(
                                "Cannot recover ICC PIN Encipherment PK (no '9F2D' \
                                 and no CDA-armed ICC PK) - failing CVM."
                            );
                            CvmExecutionResult::PinPadNotWorkingOrAbsent
                        }
                    }
                }
                EncipheredPinVerifiedOnline => {
                    println!("CVM: enciphered online PIN required.");
                    run_online_pin_capture()
                }
                _ => CvmExecutionResult::PinPadNotWorkingOrAbsent,
            }
        })
        .map_err(|e| format!("CVM: {:?}", e))?;
    println!("Cardholder Verification");
    println!("  CVM Results: {}", hex(&cvm.cvm_results));
    println!(
        "  TSI 'CVM was performed': {}",
        cvm.tsi_cardholder_verification_was_performed
    );
    println!("  TVR now: {}", hex(&tx.ctx.tvr.to_bytes()));
    println!();

    // Phase 3.6: Terminal Risk Management (B3 §10.6)
    let trm_random: Option<u8> = {
        let mut buf = [0u8; 1];
        File::open("/dev/urandom")?.read_exact(&mut buf)?;
        Some(((buf[0] as u16 % 99) + 1) as u8)
    };
    let trm = tx
        .run_terminal_risk_management(trm_random, None)
        .map_err(|e| format!("TRM: {:?}", e))?;
    println!("Terminal Risk Management");
    println!(
        "  Floor limit exceeded:        {}",
        trm.transaction_exceeds_floor_limit
    );
    println!(
        "  Selected randomly for online: {}",
        trm.transaction_selected_randomly_for_online_processing
    );
    println!(
        "  Lower consec. offline limit:  {}",
        trm.lower_consecutive_offline_limit_exceeded
    );
    println!(
        "  Upper consec. offline limit:  {}",
        trm.upper_consecutive_offline_limit_exceeded
    );
    println!("  New card:                     {}", trm.new_card);
    println!("  TVR now: {}", hex(&tx.ctx.tvr.to_bytes()));
    println!("  TSI now: {}", hex(&tx.ctx.tsi.to_bytes()));
    println!();

    // Phase 3.7: Terminal Action Analysis (B3 §10.7)
    let cryptogram = tx
        .ctx
        .terminal_action_analysis(false)
        .map_err(|e| format!("Terminal Action Analysis: {:?}", e))?;
    println!("Terminal Action Analysis → {:?}", cryptogram);
    println!();

    // Phase 4: First GENERATE AC
    let cdol1_bytes = tx
        .ctx
        .tag_store
        .get(tags::CDOL1)
        .ok_or("no CDOL1 in card data - cannot build first GENERATE AC")?;
    let cdol1 = Dol::parse(cdol1_bytes)?;
    let cdol1_data = cdol1.resolve(&tx.ctx);
    println!(
        "CDOL1: {} entries → {} bytes",
        cdol1.0.len(),
        cdol1_data.len()
    );

    // CDA Mode 1 (Annex D4); XDA always requested when selected (Book 2 §12.5.1).
    let signature_request = if xda_armed {
        SignatureRequest::Xda
    } else if cda_armed
        && matches!(
            cryptogram,
            ApplicationCryptogramType::Tc | ApplicationCryptogramType::Arqc
        )
    {
        SignatureRequest::Cda
    } else {
        SignatureRequest::None
    };
    match signature_request {
        SignatureRequest::Cda => {
            println!("Requesting CDA on first GENERATE AC (P1 b5-b4 = '10').");
        }
        SignatureRequest::Xda => {
            println!("Requesting XDA on first GENERATE AC (P1 b5-b4 = '01').");
        }
        SignatureRequest::None => {}
    }
    let first = tx
        .first_generate_ac(cryptogram, signature_request, cdol1_data)
        .map_err(|e| format!("first GENERATE AC: {:?}", e))?;
    println!("First GENERATE AC ({:?})", cryptogram);
    println!("  CID:  {:?}", first.cid);
    println!("  ATC:  {}", hex(&first.atc));
    if let Some(ac) = first.ac {
        println!("  AC:   {}", hex(&ac));
    }
    if let Some(iad) = &first.iad {
        println!("  IAD:  {}", hex(iad));
    }
    if let Some(sdad) = &first.sdad {
        println!("  SDAD: {} bytes (CDA/XDA)", sdad.len());
    }
    println!();

    // Phase 4.05: CDA verification (B2 §6.6.2)
    if matches!(signature_request, SignatureRequest::Cda)
        && !matches!(first.cid.cryptogram_type, ApplicationCryptogramType::Aac)
    {
        match tx.verify_cda_first_generate_ac(&first) {
            Ok(verified) => {
                println!("CDA verified (first GENERATE AC).");
                println!(
                    "  ICC Dynamic Number: {}",
                    hex(&verified.icc_dynamic_number)
                );
                println!(
                    "  Recovered AC:       {}",
                    hex(&verified.application_cryptogram)
                );
            }
            Err(e) => {
                println!("CDA FAILED on first GENERATE AC: {:?}", e);
                println!("  TVR 'CDA failed' is now set; transaction continues per Annex D4.");
            }
        }
        println!("  TVR now: {}", hex(&tx.ctx.tvr.to_bytes()));
        println!("  TSI now: {}", hex(&tx.ctx.tsi.to_bytes()));
        println!();
    }

    // Phase 4.05b: XDA verification (B2 §12.5.3)
    if xda_armed {
        match tx.verify_xda_first_generate_ac(&first) {
            Ok(()) => {
                if tx.ctx.tvr.xda_signature_verification_failed {
                    println!("XDA SDAD verification FAILED on first GENERATE AC.");
                } else if tx.ctx.tvr.ca_ecc_key_missing {
                    println!("XDA: CA ECC key missing (TVR bit applied).");
                } else if tx.ctx.tvr.ecc_key_recovery_failed {
                    println!("XDA: ECC key recovery failed (TVR bit applied).");
                } else if matches!(first.cid.cryptogram_type, ApplicationCryptogramType::Aac) {
                    println!("XDA: SDAD verification skipped on AAC per §12.5.1.");
                } else {
                    println!("XDA verified (first GENERATE AC).");
                }
            }
            Err(e) => {
                println!("XDA verification driver error: {:?}", e);
            }
        }
        println!("  TVR now: {}", hex(&tx.ctx.tvr.to_bytes()));
        println!("  TSI now: {}", hex(&tx.ctx.tsi.to_bytes()));
        println!();
    }

    // Phase 4.1: Card Action Analysis (B3 §10.8)
    let caa = tx.ctx.card_action_analysis(&first);
    println!("Card Action Analysis → {:?}", caa.action);
    if caa.advice_required {
        println!("  CID b4 'advice required' set (Book 4 §6.3.7).");
    }
    println!("  TSI now: {}", hex(&tx.ctx.tsi.to_bytes()));
    println!();

    match caa.action {
        CardAction::Approve => {
            println!("Final outcome: Approved offline (TC banked).");
        }
        CardAction::Decline => {
            println!("Final outcome: Declined offline.");
        }
        CardAction::ServiceNotAllowed => {
            println!("Final outcome: Terminated - Service Not Allowed (CID reason '001').");
        }
        CardAction::InvalidCryptogramType => {
            println!("Final outcome: Terminated - RFU cryptogram type in CID.");
        }
        CardAction::GoOnline => {
            run_online_completion(&mut tx, &first)?;
        }
    }

    println!();
    println!("Final TVR: {}", hex(&tx.ctx.tvr.to_bytes()));
    println!("Final TSI: {}", hex(&tx.ctx.tsi.to_bytes()));
    Ok(())
}

fn run_online_completion(
    tx: &mut Transaction<'_, PcscCardReader, InteractiveHost>,
    first: &GenerateAcResponse,
) -> Result<(), Box<dyn std::error::Error>> {
    println!("─── Phase 5: Online Processing (B3 §10.9) ─────────────────────");
    let auth_resp = tx
        .authorise_online(first)
        .map_err(|e| format!("authorise_online: {:?}", e))?;
    let arc_str = auth_resp
        .authorisation_response_code
        .as_str()
        .unwrap_or("?");
    println!("Issuer ARC: {:?}", arc_str);
    if let Some(iad) = &auth_resp.issuer_authentication_data {
        println!("  Issuer Authentication Data: {} bytes", iad.len());
    } else {
        println!("  No Issuer Authentication Data returned.");
    }
    println!("  Issuer scripts: {}", auth_resp.issuer_scripts.len());
    println!();

    // §10.9 EXTERNAL AUTHENTICATE - gated on IAD presence + AIP.
    match tx
        .online_card_authentication(&auth_resp)
        .map_err(|e| format!("EXTERNAL AUTHENTICATE: {:?}", e))?
    {
        Some(outcome) => println!("EXTERNAL AUTHENTICATE → {:?}", outcome),
        None => println!("EXTERNAL AUTHENTICATE skipped per §10.9 gates."),
    }
    println!("  TVR now: {}", hex(&tx.ctx.tvr.to_bytes()));
    println!("  TSI now: {}", hex(&tx.ctx.tsi.to_bytes()));
    println!();

    println!("─── Phase 6: Issuer Script Processing '71' (B3 §10.10) ─────────");
    let outcome71 = tx
        .process_issuer_scripts(&auth_resp.issuer_scripts, ScriptTag::BeforeFinalGenerateAc)
        .map_err(|e| format!("process_issuer_scripts (71): {:?}", e))?;
    print_script_outcome("71", &outcome71);
    println!("  TVR now: {}", hex(&tx.ctx.tvr.to_bytes()));
    println!("  TSI now: {}", hex(&tx.ctx.tsi.to_bytes()));
    println!();

    println!("─── Phase 7: Second GENERATE AC (B3 §10.11) ──────────────────");
    // ISO 8583 "00" = Approved.
    let online_outcome = if arc_str == "00" {
        OnlineAuthorisationOutcome::Approved
    } else {
        OnlineAuthorisationOutcome::Declined
    };
    let cryptogram2 = second_generate_ac_after_online(online_outcome);
    println!(
        "  ARC {:?} → {:?} → request {:?}",
        arc_str, online_outcome, cryptogram2
    );

    tx.ctx.tag_store.insert_primitive(
        tags::AUTHORISATION_RESPONSE_CODE,
        auth_resp.authorisation_response_code.to_bytes().to_vec(),
        Source::TerminalGenerated,
    )?;
    let cdol2_data = match tx.ctx.tag_store.get(tags::CDOL2) {
        Some(bytes) => {
            let cdol2 = Dol::parse(bytes)?;
            let data = cdol2.resolve(&tx.ctx);
            println!("  CDOL2: {} entries → {} bytes", cdol2.0.len(), data.len());
            data
        }
        None => {
            println!("  No CDOL2 in card data - sending empty data field.");
            Vec::new()
        }
    };
    let cda_armed = tx.ctx.cda.is_some();
    let xda_armed = tx.ctx.xda.is_some();
    let signature_request2 = if xda_armed {
        SignatureRequest::Xda
    } else if cda_armed && matches!(cryptogram2, ApplicationCryptogramType::Tc) {
        SignatureRequest::Cda
    } else {
        SignatureRequest::None
    };
    match signature_request2 {
        SignatureRequest::Cda => {
            println!("Requesting CDA on second GENERATE AC (P1 b5-b4 = '10').");
        }
        SignatureRequest::Xda => {
            println!("Requesting XDA on second GENERATE AC (P1 b5-b4 = '01').");
        }
        SignatureRequest::None => {}
    }
    let second = tx
        .second_generate_ac(cryptogram2, signature_request2, cdol2_data)
        .map_err(|e| format!("second GENERATE AC: {:?}", e))?;
    println!("Second GENERATE AC ({:?})", cryptogram2);
    println!("  CID:  {:?}", second.cid);
    println!("  ATC:  {}", hex(&second.atc));
    if let Some(ac) = second.ac {
        println!("  AC:   {}", hex(&ac));
    }
    if let Some(iad) = &second.iad {
        println!("  IAD:  {}", hex(iad));
    }
    if let Some(sdad) = &second.sdad {
        println!("  SDAD: {} bytes (CDA)", sdad.len());
    }
    println!();

    if matches!(signature_request2, SignatureRequest::Cda)
        && !matches!(second.cid.cryptogram_type, ApplicationCryptogramType::Aac)
    {
        match tx.verify_cda_second_generate_ac(&second) {
            Ok(verified) => {
                println!("CDA verified (second GENERATE AC).");
                println!(
                    "  ICC Dynamic Number: {}",
                    hex(&verified.icc_dynamic_number)
                );
                println!(
                    "  Recovered AC:       {}",
                    hex(&verified.application_cryptogram)
                );
            }
            Err(e) => {
                println!("CDA FAILED on second GENERATE AC: {:?}", e);
            }
        }
        println!("  TVR now: {}", hex(&tx.ctx.tvr.to_bytes()));
        println!("  TSI now: {}", hex(&tx.ctx.tsi.to_bytes()));
        println!();
    }

    // XDA second-GenAC verification (§12.5.3).
    if matches!(signature_request2, SignatureRequest::Xda) {
        let already_failed = tx.ctx.tvr.xda_signature_verification_failed
            || tx.ctx.tvr.ca_ecc_key_missing
            || tx.ctx.tvr.ecc_key_recovery_failed;
        match tx.verify_xda_second_generate_ac(&second) {
            Ok(()) => {
                if matches!(second.cid.cryptogram_type, ApplicationCryptogramType::Aac) {
                    println!("XDA: SDAD verification skipped on AAC per §12.5.3.");
                } else if already_failed {
                    println!("XDA: SDAD verification skipped - XDA already failed at first GenAC.");
                } else if tx.ctx.tvr.xda_signature_verification_failed {
                    println!("XDA SDAD verification FAILED on second GENERATE AC.");
                } else {
                    println!("XDA verified (second GENERATE AC).");
                }
            }
            Err(e) => {
                println!("XDA verification driver error (2nd GenAC): {:?}", e);
            }
        }
        println!("  TVR now: {}", hex(&tx.ctx.tvr.to_bytes()));
        println!("  TSI now: {}", hex(&tx.ctx.tsi.to_bytes()));
        println!();
    }

    println!("─── Phase 8: Issuer Script Processing '72' (B3 §10.10) ─────────");
    let outcome72 = tx
        .process_issuer_scripts(&auth_resp.issuer_scripts, ScriptTag::AfterFinalGenerateAc)
        .map_err(|e| format!("process_issuer_scripts (72): {:?}", e))?;
    print_script_outcome("72", &outcome72);
    println!("  TVR now: {}", hex(&tx.ctx.tvr.to_bytes()));
    println!("  TSI now: {}", hex(&tx.ctx.tsi.to_bytes()));
    println!();

    let final_label = match second.cid.cryptogram_type {
        ApplicationCryptogramType::Tc => "Approved (TC banked)",
        ApplicationCryptogramType::Aac => "Declined",
        ApplicationCryptogramType::Arqc => "Unexpected ARQC on second GENERATE AC",
        ApplicationCryptogramType::Rfu(_) => "Terminated (RFU cryptogram type)",
    };
    println!("Final outcome: {}", final_label);
    Ok(())
}

fn read_pin_from_stdin() -> Result<Vec<u8>, String> {
    let line = rpassword::prompt_password("Enter PIN (4-12 digits, hidden): ")
        .map_err(|e| format!("PIN read: {}", e))?;
    let trimmed = line.trim();
    if !(4..=12).contains(&trimmed.len()) {
        return Err(format!(
            "PIN must be 4–12 digits, got {} characters",
            trimmed.len()
        ));
    }
    let mut digits = Vec::with_capacity(trimmed.len());
    for ch in trimmed.chars() {
        let d = ch
            .to_digit(10)
            .ok_or_else(|| format!("non-digit in PIN: {:?}", ch))?;
        digits.push(d as u8);
    }
    Ok(digits)
}

// Book 3 §10.5.1 + §6.5.12
fn run_plaintext_offline_pin(card: &mut PcscCardReader) -> CvmExecutionResult {
    let pin = match read_pin_from_stdin() {
        Ok(p) => p,
        Err(e) => {
            eprintln!("PIN entry: {}", e);
            return CvmExecutionResult::PinEntryBypassed;
        }
    };
    let result = match cardholder_verification::verify_plaintext_offline_pin(card, &pin) {
        Ok(r) => r,
        Err(e) => {
            eprintln!(
                "VERIFY: {:?} - transaction shall be terminated (Book 3 §6.3.5).",
                e
            );
            return CvmExecutionResult::Failed;
        }
    };
    println!("VERIFY → {:?}", result);
    result
}

// Book 2 §7.2 + Book 3 §10.5.1
fn run_enciphered_offline_pin(
    card: &mut PcscCardReader,
    pin_pk: &emv::core::oda::IccPublicKey,
) -> CvmExecutionResult {
    let pin = match read_pin_from_stdin() {
        Ok(p) => p,
        Err(e) => {
            eprintln!("PIN entry: {}", e);
            return CvmExecutionResult::PinEntryBypassed;
        }
    };
    let result =
        cardholder_verification::verify_enciphered_offline_pin(card, &pin, pin_pk, |buf| {
            File::open("/dev/urandom")
                .and_then(|mut f| f.read_exact(buf))
                .is_ok()
        });
    let result = match result {
        Ok(r) => r,
        Err(e) => {
            eprintln!(
                "VERIFY (enciphered): {:?} - transaction shall be terminated (Book 3 §6.3.5).",
                e
            );
            return CvmExecutionResult::Failed;
        }
    };
    println!("VERIFY (enciphered) → {:?}", result);
    result
}

// Book 4 §6.3.4.2 - online PIN handling is acquirer-side; this stub only prompts.
fn run_online_pin_capture() -> CvmExecutionResult {
    match read_pin_from_stdin() {
        Ok(_) => {
            println!("Online PIN captured (would be enciphered + sent in auth request).");
            CvmExecutionResult::Successful
        }
        Err(e) => {
            eprintln!("PIN entry: {}", e);
            CvmExecutionResult::PinEntryBypassed
        }
    }
}

struct InteractiveHost;
impl OnlineAuthorisation for InteractiveHost {
    type Error = String;
    fn authorise(
        &mut self,
        _ctx: &TransactionContext<'_>,
        _first_ac: &GenerateAcResponse,
    ) -> Result<OnlineAuthorisationResponse, Self::Error> {
        println!("Enter online auth response - either a 2-char ARC ('00', '05', 'Z1', …) or a hex");
        println!("BER-TLV blob with tags 8A (ARC), 91 (Issuer Auth Data), 71/72 (Issuer Scripts).");
        print!("[default: ARC=00] > ");
        io::stdout()
            .flush()
            .map_err(|e| format!("stdout flush failed: {}", e))?;
        let mut line = String::new();
        io::stdin()
            .read_line(&mut line)
            .map_err(|e| format!("stdin read failed: {}", e))?;
        let input = line.trim();

        if input.is_empty() {
            return Ok(OnlineAuthorisationResponse {
                authorisation_response_code: AuthorisationResponseCode(*b"00"),
                issuer_authentication_data: None,
                issuer_scripts: vec![],
            });
        }

        // 2-char ASCII shortcut for the common decline path.
        let stripped: String = input
            .chars()
            .filter(|c| !c.is_whitespace() && *c != '_')
            .collect();
        if stripped.len() == 2 && !stripped.chars().all(|c| c.is_ascii_hexdigit()) {
            let b = stripped.as_bytes();
            return Ok(OnlineAuthorisationResponse {
                authorisation_response_code: AuthorisationResponseCode([b[0], b[1]]),
                issuer_authentication_data: None,
                issuer_scripts: vec![],
            });
        }

        let bytes = parse_hex(input).map_err(|e| format!("hex decode: {}", e))?;
        let tlvs = Tlv::parse_all(&bytes).map_err(|e| format!("BER-TLV parse: {:?}", e))?;

        let mut arc: Option<[u8; 2]> = None;
        let mut iad: Option<Vec<u8>> = None;
        let mut scripts: Vec<Tlv> = Vec::new();
        for tlv in tlvs {
            if tlv.tag() == tags::AUTHORISATION_RESPONSE_CODE {
                let v = tlv
                    .value()
                    .as_primitive()
                    .ok_or_else(|| "8A must be primitive".to_string())?;
                if v.len() != 2 {
                    return Err(format!("8A (ARC) must be 2 bytes, got {}", v.len()));
                }
                arc = Some([v[0], v[1]]);
            } else if tlv.tag() == tags::ISSUER_AUTHENTICATION_DATA {
                let v = tlv
                    .value()
                    .as_primitive()
                    .ok_or_else(|| "91 must be primitive".to_string())?;
                if !(8..=16).contains(&v.len()) {
                    return Err(format!(
                        "91 (Issuer Auth Data) must be 8..=16 bytes, got {}",
                        v.len()
                    ));
                }
                iad = Some(v.to_vec());
            } else if tlv.tag() == tags::ISSUER_SCRIPT_TEMPLATE_1
                || tlv.tag() == tags::ISSUER_SCRIPT_TEMPLATE_2
            {
                scripts.push(tlv);
            }
        }

        Ok(OnlineAuthorisationResponse {
            authorisation_response_code: AuthorisationResponseCode(arc.unwrap_or(*b"00")),
            issuer_authentication_data: iad,
            issuer_scripts: scripts,
        })
    }
}

fn resolve_config(explicit: Option<&Path>, name: &str) -> Result<PathBuf, String> {
    if let Some(p) = explicit {
        if !p.exists() {
            return Err(format!("config file not found: {}", p.display()));
        }
        return Ok(p.to_path_buf());
    }
    if let Ok(dir) = env::var("EMV_CONFIG_DIR") {
        let p = PathBuf::from(dir).join(name);
        if p.exists() {
            return Ok(p);
        }
    }
    let cwd = PathBuf::from(name);
    if cwd.exists() {
        return Ok(cwd);
    }
    let crate_default = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(name);
    if crate_default.exists() {
        return Ok(crate_default);
    }
    Err(format!(
        "could not find {} (set --terminal/--aids/--capk or EMV_CONFIG_DIR)",
        name
    ))
}

fn resolve_optional_config(
    explicit: Option<&Path>,
    name: &str,
) -> Result<Option<PathBuf>, Box<dyn std::error::Error>> {
    if let Some(p) = explicit {
        if !p.exists() {
            return Err(format!("config file not found: {}", p.display()).into());
        }
        return Ok(Some(p.to_path_buf()));
    }
    if let Ok(dir) = env::var("EMV_CONFIG_DIR") {
        let p = PathBuf::from(dir).join(name);
        if p.exists() {
            return Ok(Some(p));
        }
    }
    let cwd = PathBuf::from(name);
    if cwd.exists() {
        return Ok(Some(cwd));
    }
    let crate_default = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(name);
    if crate_default.exists() {
        return Ok(Some(crate_default));
    }
    Ok(None)
}

fn random_un() -> Result<[u8; 4], Box<dyn std::error::Error>> {
    let mut f = File::open("/dev/urandom")?;
    let mut buf = [0u8; 4];
    f.read_exact(&mut buf)?;
    Ok(buf)
}

fn parse_hex(s: &str) -> Result<Vec<u8>, &'static str> {
    let s = s.trim().replace([' ', '_'], "");
    if !s.len().is_multiple_of(2) {
        return Err("odd number of hex digits");
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    for i in (0..s.len()).step_by(2) {
        let byte = u8::from_str_radix(&s[i..i + 2], 16).map_err(|_| "non-hex character")?;
        out.push(byte);
    }
    Ok(out)
}

fn print_script_outcome(position: &str, outcome: &ScriptProcessingOutcome) {
    if outcome.script_results.is_empty() {
        println!("  No '{}' scripts in authorisation response.", position);
        return;
    }
    println!(
        "  '{}' scripts processed: {} (TSI 'Script processing was performed' = {})",
        position,
        outcome.script_results.len(),
        outcome.tsi_script_processing_was_performed
    );
    for (i, ScriptOutcome { result, .. }) in outcome.script_results.iter().enumerate() {
        let label = match result.script_result {
            ScriptResultNibble::ScriptProcessingSuccessful => "successful",
            ScriptResultNibble::ScriptProcessingFailed => "failed",
            ScriptResultNibble::ScriptNotPerformed => "not performed (parse error)",
            ScriptResultNibble::Rfu(n) => {
                return println!("  [{}] RFU result nibble {:X}", i + 1, n);
            }
        };
        let seq_str = match result.script_number {
            0 => "n/a".to_string(),
            0x0F => "≥15".to_string(),
            n => n.to_string(),
        };
        println!(
            "  [{}] id={} → {} (last command sequence: {})",
            i + 1,
            hex(&result.script_identifier),
            label,
            seq_str
        );
    }
}

fn hex(b: &[u8]) -> String {
    let mut s = String::with_capacity(b.len() * 2);
    for byte in b {
        s.push_str(&format!("{:02X}", byte));
    }
    s
}
