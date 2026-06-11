//! Book 2 §9 + Annexes A1/B1/D2 - Secure messaging primitives.

use crate::core::apdu::{Cla, Command, Ins};
use crate::core::error::{Error, Result};
use crate::core::tlv::encode_length;
use des::Des;
use des::cipher::array::Array;
use des::cipher::{BlockCipherDecrypt, BlockCipherEncrypt, KeyInit};

// ── Secure-messaging mode (CLA encoding) ─────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecureMessagingMode {
    Proprietary,
    Iso7816HeaderAuthenticated,
}

impl SecureMessagingMode {
    /// Encode the CLA byte for a post-issuance command. `chained`
    /// sets bit 5 per Book 3 §6.5.13 / ISO/IEC 7816-4 §5.1.1.1: `false`
    /// = last/only command of a chain, `true` = not the last command.
    /// Chaining is only defined for VERIFY and PIN CHANGE/UNBLOCK; the
    /// three block commands ignore it (callers pass `false`).
    pub fn cla_byte(self, chained: bool) -> u8 {
        let base = match self {
            Self::Proprietary => 0x84,
            Self::Iso7816HeaderAuthenticated => 0x8C,
        };
        if chained { base | 0x10 } else { base }
    }
}

// ── DES / Triple-DES block primitives (§B1.1) ────────────────────────

fn des_encrypt_block(key: &[u8; 8], block: [u8; 8]) -> [u8; 8] {
    let cipher = Des::new_from_slice(key).expect("8-byte key");
    let mut b = Array::from(block);
    cipher.encrypt_block(&mut b);
    b.into()
}

fn des_decrypt_block(key: &[u8; 8], block: [u8; 8]) -> [u8; 8] {
    let cipher = Des::new_from_slice(key).expect("8-byte key");
    let mut b = Array::from(block);
    cipher.decrypt_block(&mut b);
    b.into()
}

fn split_tdes_key(key: &[u8; 16]) -> (&[u8; 8], &[u8; 8]) {
    // Safe: 16-byte slice splits cleanly into two 8-byte halves.
    let kl: &[u8; 8] = key[..8].try_into().unwrap();
    let kr: &[u8; 8] = key[8..].try_into().unwrap();
    (kl, kr)
}

/// Triple-DES (two-key, EDE) encrypt one 8-byte block per Book 2 §B1.1:
/// `Y = DES(K_L)[ DES⁻¹(K_R)[ DES(K_L)[X] ] ]`.
pub fn tdes_encrypt_block(key: &[u8; 16], block: [u8; 8]) -> [u8; 8] {
    let (kl, kr) = split_tdes_key(key);
    let b = des_encrypt_block(kl, block);
    let b = des_decrypt_block(kr, b);
    des_encrypt_block(kl, b)
}

/// Triple-DES (two-key, EDE) decrypt per Book 2 §B1.1:
/// `X = DES⁻¹(K_L)[ DES(K_R)[ DES⁻¹(K_L)[Y] ] ]`.
pub fn tdes_decrypt_block(key: &[u8; 16], block: [u8; 8]) -> [u8; 8] {
    let (kl, kr) = split_tdes_key(key);
    let b = des_decrypt_block(kl, block);
    let b = des_encrypt_block(kr, b);
    des_decrypt_block(kl, b)
}

// ── ISO/IEC 9797-1 Method 2 padding ──────────────────────────────────

/// ISO/IEC 9797-1 Method 2 padding (≡ ISO/IEC 7816-4 padding): append a
/// mandatory `'80'` byte and then the smallest number of `'00'` bytes
/// needed to bring the length to a multiple of `block_size`. Always
/// adds at least one byte - even when `msg.len()` is already a multiple
/// of the block size - matching §A1.2 (MAC) and the §A1.1 / §D2.2
/// "always pad" encipherment rule (padding-indicator byte = `'01'`).
pub fn pad_iso9797_method2(msg: &[u8], block_size: usize) -> Vec<u8> {
    assert!(block_size > 0);
    let target = (msg.len() + 1).next_multiple_of(block_size);
    let mut out = Vec::with_capacity(target);
    out.extend_from_slice(msg);
    out.push(0x80);
    out.resize(target, 0);
    out
}

/// Strip ISO/IEC 9797-1 Method 2 padding by finding the rightmost
/// non-zero byte and verifying it is `'80'`.
pub fn unpad_iso9797_method2(padded: &[u8]) -> Result<&[u8]> {
    let pos = padded
        .iter()
        .rposition(|&b| b != 0)
        .ok_or(Error::InvalidValue)?;
    if padded[pos] != 0x80 {
        return Err(Error::InvalidValue);
    }
    Ok(&padded[..pos])
}

// ── Triple-DES ECB / CBC (§A1.1) ─────────────────────────────────────

/// Triple-DES ECB encrypt of pre-padded `data` (must be a multiple of
/// 8 bytes). Pad first via [`pad_iso9797_method2`] when the caller
/// owns the padding decision.
pub fn tdes_ecb_encrypt(key: &[u8; 16], data: &[u8]) -> Result<Vec<u8>> {
    if data.is_empty() || !data.len().is_multiple_of(8) {
        return Err(Error::InvalidValue);
    }
    let mut out = Vec::with_capacity(data.len());
    for chunk in data.chunks_exact(8) {
        let mut block = [0u8; 8];
        block.copy_from_slice(chunk);
        out.extend_from_slice(&tdes_encrypt_block(key, block));
    }
    Ok(out)
}

/// Triple-DES ECB decrypt (inverse of [`tdes_ecb_encrypt`]).
pub fn tdes_ecb_decrypt(key: &[u8; 16], data: &[u8]) -> Result<Vec<u8>> {
    if data.is_empty() || !data.len().is_multiple_of(8) {
        return Err(Error::InvalidValue);
    }
    let mut out = Vec::with_capacity(data.len());
    for chunk in data.chunks_exact(8) {
        let mut block = [0u8; 8];
        block.copy_from_slice(chunk);
        out.extend_from_slice(&tdes_decrypt_block(key, block));
    }
    Ok(out)
}

/// Triple-DES CBC encrypt of pre-padded `data` (must be a multiple of
/// 8 bytes). `iv` is the initial chaining value - pass an all-zero
/// `iv` for §9.3 confidentiality SM (the encipherment session key
/// already provides per-transaction uniqueness via §A1.3.1).
pub fn tdes_cbc_encrypt(key: &[u8; 16], iv: &[u8; 8], data: &[u8]) -> Result<Vec<u8>> {
    if data.is_empty() || !data.len().is_multiple_of(8) {
        return Err(Error::InvalidValue);
    }
    let mut out = Vec::with_capacity(data.len());
    let mut prev = *iv;
    for chunk in data.chunks_exact(8) {
        let mut block = [0u8; 8];
        for i in 0..8 {
            block[i] = chunk[i] ^ prev[i];
        }
        let enc = tdes_encrypt_block(key, block);
        out.extend_from_slice(&enc);
        prev = enc;
    }
    Ok(out)
}

/// Triple-DES CBC decrypt (inverse of [`tdes_cbc_encrypt`]).
pub fn tdes_cbc_decrypt(key: &[u8; 16], iv: &[u8; 8], data: &[u8]) -> Result<Vec<u8>> {
    if data.is_empty() || !data.len().is_multiple_of(8) {
        return Err(Error::InvalidValue);
    }
    let mut out = Vec::with_capacity(data.len());
    let mut prev = *iv;
    for chunk in data.chunks_exact(8) {
        let mut block = [0u8; 8];
        block.copy_from_slice(chunk);
        let dec = tdes_decrypt_block(key, block);
        for i in 0..8 {
            out.push(dec[i] ^ prev[i]);
        }
        prev = block;
    }
    Ok(out)
}

// ── Retail MAC (§A1.2.1 Algorithm 3) ─────────────────────────────────

/// Retail MAC per Book 2 §A1.2.1 Algorithm 3 - the dominant EMV MAC
/// for issuer-script secure messaging.
///
/// Computes an 8-byte MAC over `msg` under a 16-byte two-key Triple-DES
/// session key:
///
/// 1. Pad `msg` with [`pad_iso9797_method2`] to a multiple of 8 bytes.
/// 2. CBC-MAC the padded message using single DES with `K_L` (the
///    leftmost 8 bytes of `key`) and an all-zero IV.
/// 3. Output transform on the final CBC value `H_B`:
///    `H_{B+1} := DES(K_L)[ DES⁻¹(K_R)[ H_B ] ]`. Combined with the
///    final `DES(K_L)` of step 2 this is "Triple-DES applied to the
///    last block" per the §A1.2.1 footnote.
///
/// The full 8-byte result is returned. Truncate to the on-wire MAC
/// length (4..=8 per §9.2.1.1) via [`mac_truncated`].
///
/// **Pre-padded MAC (Format 1)**: when securing a Format 1 command,
/// Book 2 §9.2.3 requires that the per-step padding inside this
/// function be omitted because the message is already padded per
/// ISO/IEC 7816-4 (header padded to 8 bytes, plaintext/cryptogram
/// data object padded). Passing such a pre-padded message into
/// [`retail_mac`] would result in *double* padding. For Format 1, use
/// [`retail_mac_no_pad`] instead.
pub fn retail_mac(key: &[u8; 16], msg: &[u8]) -> [u8; 8] {
    let padded = pad_iso9797_method2(msg, 8);
    retail_mac_no_pad(key, &padded).expect("padding guarantees multiple of 8")
}

/// Retail MAC over `msg` without applying padding. `msg.len()` must be
/// a positive multiple of 8 bytes; the caller is responsible for
/// padding per the rules of the specific secure-messaging format
/// (Book 2 §9.2.3 for Format 1, payment-system spec for Format 2).
pub fn retail_mac_no_pad(key: &[u8; 16], msg: &[u8]) -> Result<[u8; 8]> {
    if msg.is_empty() || !msg.len().is_multiple_of(8) {
        return Err(Error::InvalidValue);
    }
    let (kl, kr) = split_tdes_key(key);
    let mut h = [0u8; 8];
    for chunk in msg.chunks_exact(8) {
        for i in 0..8 {
            h[i] ^= chunk[i];
        }
        h = des_encrypt_block(kl, h);
    }
    let h = des_decrypt_block(kr, h);
    Ok(des_encrypt_block(kl, h))
}

/// Retail MAC truncated to `s` leftmost bytes per §9.2.1.1, where
/// `s` ∈ `4..=8`.
pub fn mac_truncated(key: &[u8; 16], msg: &[u8], s: usize) -> Result<Vec<u8>> {
    if !(4..=8).contains(&s) {
        return Err(Error::InvalidValue);
    }
    Ok(retail_mac(key, msg)[..s].to_vec())
}

// ── Common Session Key Derivation (§A1.3.1) ──────────────────────────

/// Common Session Key Derivation (Book 2 §A1.3.1) for the 16-byte
/// Triple-DES case - the same formula derives both the AC session key
/// and the SM session key, distinguished only by the diversification
/// value `r`.
///
/// Returns `SK = TDES(MK)[F1] || TDES(MK)[F2]`, where `F1` and `F2`
/// are derived from `r` by replacing byte 2 (zero-indexed) with
/// `'F0'` and `'0F'` respectively per the §A1.3.1 formula
/// `F1 = R₀ R₁ 'F0' R₃ R₄ R₅ R₆ R₇`.
pub fn derive_session_key_tdes(mk: &[u8; 16], r: &[u8; 8]) -> [u8; 16] {
    let mut f1 = *r;
    let mut f2 = *r;
    f1[2] = 0xF0;
    f2[2] = 0x0F;
    let left = tdes_encrypt_block(mk, f1);
    let right = tdes_encrypt_block(mk, f2);
    let mut out = [0u8; 16];
    out[..8].copy_from_slice(&left);
    out[8..].copy_from_slice(&right);
    out
}

/// Diversification value `R` for the AC / ARPC session key
/// (Book 2 §A1.3.1): `R = ATC || 6 zeros` for the 8-byte block case.
/// Pair with [`derive_session_key_tdes`] to derive `SK_AC` from
/// `MK_AC`.
pub fn diversification_for_ac_session_key(atc: u16) -> [u8; 8] {
    let mut r = [0u8; 8];
    r[0] = (atc >> 8) as u8;
    r[1] = atc as u8;
    r
}

/// Diversification value `R` for the secure-messaging session keys
/// (Book 2 §A1.3.1): `R = AC` for the 8-byte block case (the 8-byte
/// Application Cryptogram fills the entire diversification value;
/// no trailing zeros are appended). Pair with
/// [`derive_session_key_tdes`] to derive `SK_MAC` and `SK_ENC` from
/// `MK_MAC` and `MK_ENC` respectively.
pub fn diversification_for_sm_session_key(ac: &[u8; 8]) -> [u8; 8] {
    *ac
}

/// AES variant of [`derive_session_key_tdes`] per §A1.3.1.
///
/// Two cases per §A1.3.1, dispatched by `mk.len()`:
///
/// - `mk.len() == 16` (AES-128, `k = 8n`): single block encrypt,
///   `SK = AES(MK)[R]`, returns 16 bytes.
/// - `mk.len() == 24 / 32` (AES-192/256, `16n ≥ k > 8n`): the §A1.3.1
///   F1/F2 construction with byte 2 set to `'F0'` / `'0F'`,
///   `SK = leftmost k bits of {AES(MK)[F1] || AES(MK)[F2]}`, returns
///   24 or 32 bytes respectively.
///
/// Errors with `InvalidValue` for any other key length. `r` is always
/// the 16-byte AES diversification value - see
/// [`diversification_for_ac_session_key_aes`] /
/// [`diversification_for_sm_session_key_aes`].
pub fn derive_session_key_aes(mk: &[u8], r: &[u8; 16]) -> Result<Vec<u8>> {
    use crate::core::aes_primitives::aes_encrypt_block;
    match mk.len() {
        16 => {
            let block = aes_encrypt_block(mk, *r)?;
            Ok(block.to_vec())
        }
        24 | 32 => {
            let mut f1 = *r;
            let mut f2 = *r;
            f1[2] = 0xF0;
            f2[2] = 0x0F;
            let b1 = aes_encrypt_block(mk, f1)?;
            let b2 = aes_encrypt_block(mk, f2)?;
            let mut full = Vec::with_capacity(32);
            full.extend_from_slice(&b1);
            full.extend_from_slice(&b2);
            full.truncate(mk.len());
            Ok(full)
        }
        _ => Err(Error::InvalidValue),
    }
}

/// AES diversification value for the AC / ARPC session key per
/// §A1.3.1: `R = ATC || 14 zeros` (16 bytes total, the AES block
/// size). Pair with [`derive_session_key_aes`] to derive the AES
/// `SK_AC` from `MK_AC`.
pub fn diversification_for_ac_session_key_aes(atc: u16) -> [u8; 16] {
    let mut r = [0u8; 16];
    r[0] = (atc >> 8) as u8;
    r[1] = atc as u8;
    r
}

/// AES diversification value for the secure-messaging session keys
/// per §A1.3.1: `R = Application Cryptogram || 8 zeros` (16 bytes
/// total). The 8-byte AC fills the leftmost half; the right half is
/// zero-padded to reach the AES block size. Pair with
/// [`derive_session_key_aes`] to derive AES `SK_MAC` and `SK_ENC`.
pub fn diversification_for_sm_session_key_aes(ac: &[u8; 8]) -> [u8; 16] {
    let mut r = [0u8; 16];
    r[..8].copy_from_slice(ac);
    r
}

// ── Format 1 SM composer (§9.2.1.1, §9.2.3, §D2) ─────────────────────

/// Apply Book 2 §9 Format 1 secure messaging (integrity only - no
/// confidentiality) to an issuer-script command, returning the secured
/// [`Command`] ready for transmission.
///
/// Steps per §9.2.1.1, §9.2.3 and §D2.1.1:
///
/// 1. Build the secured CLA: `'8C'` (or `'9C'` if `chained`) - Format 1
///    SM with command header authenticated, per
///    [`SecureMessagingMode::Iso7816HeaderAuthenticated`].
/// 2. Wrap `plaintext_data` (if non-empty) under tag `'81'` per
///    §9.2.1.1: "If the unsecured command data is not BER-TLV encoded,
///    then the data shall be encapsulated under tag '81'." The four
///    issuer-script commands carry raw (non-BER-TLV-encoded) bytes, so
///    tag `'81'` always applies.
/// 3. Build the MAC input: pad the 4-byte secured header with
///    [`pad_iso9797_method2`], then append the same padding applied to
///    the plaintext data object (if any). Per §9.2.3 the per-step
///    padding inside the MAC algorithm is *omitted* because ISO/IEC
///    7816-4 already padded the input.
/// 4. Compute MAC = [`retail_mac_no_pad`]`(sk_mac, mac_input)`,
///    truncated to `mac_length` bytes (4..=8 per §9.2.1.1).
/// 5. Assemble the secured data field: `81 L data` (if any) followed
///    by `8E LL MAC`.
///
/// Errors:
/// - `mac_length` outside `4..=8`.
/// - `plaintext_data.len()` so large that the secured Lc would exceed
///   the 255-byte short-APDU limit (returned later by
///   [`Command::to_bytes`]).
///
/// Format 2 (CLA `'84'`/`'94'`) is payment-system-specific per §9.1
/// and is not handled by this composer; callers using Format 2 should
/// build the data field themselves and use the existing per-command
/// builders ([`crate::core::application_block::command`], etc.) which accept
/// pre-computed MAC bytes.
///
/// ## MAC chaining (§9.2.3.1)
///
/// Optional. When `mac_chain_value` is `Some(v)`, the 8-byte `v` is
/// inserted at the start of the MAC input (before the padded header)
/// per §9.2.3.1. Per spec:
///
/// - For the first or only script command: `v` is the 8-byte
///   Application Cryptogram returned by GENERATE AC.
/// - For each subsequent script command: `v` is the **full
///   pre-truncation 8-byte MAC** of the preceding script command.
///
/// When `mac_chain_value` is `None`, no value is prepended - the
/// caller has chosen not to support MAC chaining (§9.2.3.1 is
/// optional). Both behaviours are spec-compliant; `None` is the
/// default for a single-command session.
#[allow(clippy::too_many_arguments)]
pub fn wrap_format_1_integrity_only(
    ins: Ins,
    p1: u8,
    p2: u8,
    plaintext_data: &[u8],
    chained: bool,
    sk_mac: &[u8; 16],
    mac_length: usize,
    mac_chain_value: Option<&[u8; 8]>,
) -> Result<Command> {
    if !(4..=8).contains(&mac_length) {
        return Err(Error::InvalidValue);
    }

    let cla = SecureMessagingMode::Iso7816HeaderAuthenticated.cla_byte(chained);

    // Plaintext data object per §9.2.1.1 (tag '81' for non-BER-TLV
    // unsecured data).
    let plaintext_object: Vec<u8> = if plaintext_data.is_empty() {
        Vec::new()
    } else {
        let mut v = Vec::with_capacity(2 + plaintext_data.len());
        v.push(0x81);
        v.extend(encode_length(plaintext_data.len()));
        v.extend_from_slice(plaintext_data);
        v
    };

    // MAC input: [chain_value]? || padded(header) || padded(plaintext_object).
    let header = [cla, ins.0, p1, p2];
    let mut mac_input = Vec::new();
    if let Some(v) = mac_chain_value {
        mac_input.extend_from_slice(v);
    }
    mac_input.extend(pad_iso9797_method2(&header, 8));
    if !plaintext_object.is_empty() {
        mac_input.extend(pad_iso9797_method2(&plaintext_object, 8));
    }
    let full_mac = retail_mac_no_pad(sk_mac, &mac_input)?;
    let mac = &full_mac[..mac_length];

    // Secured data field: [81 L data]? 8E LL MAC.
    let mut secured_data = Vec::with_capacity(plaintext_object.len() + 2 + mac_length);
    secured_data.extend_from_slice(&plaintext_object);
    secured_data.push(0x8E);
    secured_data.push(mac_length as u8);
    secured_data.extend_from_slice(mac);

    Ok(Command {
        cla: Cla(cla),
        ins,
        p1,
        p2,
        data: secured_data,
        le: None,
    })
}

/// Wrap a command with Format 1 secure messaging for confidentiality
/// **and** integrity, per Book 2 §9.3.1.1 and Annex D2.1.2 / D2.2.
///
/// Composes the secured data field as:
///
/// ```text
///   '87' || L || ('01' || cryptogram) || '8E' || L || MAC
/// ```
///
/// where:
///
/// - `'87'` is the cryptogram data object for confidentiality (odd
///   tag → included in MAC computation per §9.3.1.1 Note 2 / D2.1.2
///   Note 2).
/// - `'01'` is the ISO/IEC 7816-4 padding-indicator byte for
///   ISO/IEC 9797-1 Method 2 padding (Annex D2.2 first bullet -
///   padding always applied, even when `plaintext_data.len()` is a
///   multiple of 8).
/// - `cryptogram` is `tdes_cbc_encrypt(sk_enc, IV=0×8, pad(plaintext))`
///   per §9.3.3 + §A1.1.
/// - The MAC follows the Annex D2.3 rules: padded header
///   (`pad(CLA||INS||P1||P2)`) followed by the padded enciphered
///   `'87'` TLV, MAC'd with the Retail MAC under `sk_mac`, truncated
///   to `mac_length` bytes.
///
/// Per Annex D2.1.2 last paragraph, when `plaintext_data` is empty
/// "there is no data to be enciphered and so secure messaging for
/// integrity (only) is applied" - this function delegates to
/// [`wrap_format_1_integrity_only`] in that case so the caller can
/// stay on a single API.
///
/// `sk_enc` and `sk_mac` are the 16-byte two-key Triple-DES session
/// keys derived per §A1.3.1 from distinct ICC Encipherment and ICC
/// MAC Master Keys (using the same diversification helper
/// [`diversification_for_sm_session_key`]). The MAC length is
/// `4..=8` per §A1.2.1 step 3.
///
/// Errors:
///
/// - `InvalidValue` if `mac_length` is outside `4..=8`.
/// - Any error propagated from [`tdes_cbc_encrypt`] (data not a
///   multiple of 8 - should not happen here since the input is
///   always padded - or other internal failures).
#[allow(clippy::too_many_arguments)]
pub fn wrap_format_1_with_confidentiality(
    ins: Ins,
    p1: u8,
    p2: u8,
    plaintext_data: &[u8],
    chained: bool,
    sk_enc: &[u8; 16],
    sk_mac: &[u8; 16],
    mac_length: usize,
    mac_chain_value: Option<&[u8; 8]>,
) -> Result<Command> {
    if !(4..=8).contains(&mac_length) {
        return Err(Error::InvalidValue);
    }

    // Annex D2.1.2 last paragraph: empty data → integrity-only.
    if plaintext_data.is_empty() {
        return wrap_format_1_integrity_only(
            ins,
            p1,
            p2,
            plaintext_data,
            chained,
            sk_mac,
            mac_length,
            mac_chain_value,
        );
    }

    let cla = SecureMessagingMode::Iso7816HeaderAuthenticated.cla_byte(chained);

    // §9.3.3 + Annex D2.2: pad with Method 2 (always - even when
    // plaintext_data.len() is a multiple of 8), then TDES-CBC encrypt
    // under sk_enc with zero IV.
    let padded_plaintext = pad_iso9797_method2(plaintext_data, 8);
    let cryptogram = tdes_cbc_encrypt(sk_enc, &[0u8; 8], &padded_plaintext)?;

    // Confidentiality data object: '87' || L || '01' || cryptogram.
    // The value field is `'01' || cryptogram`, so its length is
    // 1 + cryptogram.len().
    let value_len = 1 + cryptogram.len();
    let mut conf_object = Vec::with_capacity(2 + value_len);
    conf_object.push(0x87);
    conf_object.extend(encode_length(value_len));
    conf_object.push(0x01);
    conf_object.extend_from_slice(&cryptogram);

    // MAC input per §9.2.3 / D2.3:
    //   [chain_value]? || padded(header) || padded(conf_object).
    let header = [cla, ins.0, p1, p2];
    let mut mac_input = Vec::new();
    if let Some(v) = mac_chain_value {
        mac_input.extend_from_slice(v);
    }
    mac_input.extend(pad_iso9797_method2(&header, 8));
    mac_input.extend(pad_iso9797_method2(&conf_object, 8));
    let full_mac = retail_mac_no_pad(sk_mac, &mac_input)?;
    let mac = &full_mac[..mac_length];

    let mut secured_data = Vec::with_capacity(conf_object.len() + 2 + mac_length);
    secured_data.extend_from_slice(&conf_object);
    secured_data.push(0x8E);
    secured_data.push(mac_length as u8);
    secured_data.extend_from_slice(mac);

    Ok(Command {
        cla: Cla(cla),
        ins,
        p1,
        p2,
        data: secured_data,
        le: None,
    })
}

/// AES variant of [`wrap_format_1_integrity_only`] per Book 2 §9.2 +
/// §A1.2.2.
///
/// Identical wire structure to the TDES version (`'81' L data ?
/// '8E' L MAC`), but the MAC is computed via §A1.2.2 AES-CMAC under
/// `sk_mac` and the §9.2.3 input is pre-padded to a multiple of 16
/// bytes (the AES block size) rather than 8. The §A1.2.2 footnote 48
/// optimisation ("no padding is added because the message is already
/// a multiple of 16 bytes") then applies inside the CMAC.
///
/// `sk_mac` is the AES MAC session key - 16, 24, or 32 bytes for
/// AES-128/192/256. `mac_length` is `4..=8` per §A1.2.2 footnote.
///
/// `mac_chain_value` enables §9.2.3.1 MAC chaining for AES - the
/// 16-byte block-sized chain value (AC || `'00' × 8` for the first
/// command, full pre-truncation 16-byte CMAC of the preceding
/// command for subsequent commands) is prepended to the MAC input.
/// Pass `None` to skip MAC chaining (single-command session).
#[allow(clippy::too_many_arguments)]
pub fn wrap_format_1_integrity_only_aes(
    ins: Ins,
    p1: u8,
    p2: u8,
    plaintext_data: &[u8],
    chained: bool,
    sk_mac: &[u8],
    mac_length: usize,
    mac_chain_value: Option<&[u8; 16]>,
) -> Result<Command> {
    use crate::core::aes_primitives::aes_cmac_truncated;

    if !(4..=8).contains(&mac_length) {
        return Err(Error::InvalidValue);
    }

    let cla = SecureMessagingMode::Iso7816HeaderAuthenticated.cla_byte(chained);

    let plaintext_object: Vec<u8> = if plaintext_data.is_empty() {
        Vec::new()
    } else {
        let mut v = Vec::with_capacity(2 + plaintext_data.len());
        v.push(0x81);
        v.extend(encode_length(plaintext_data.len()));
        v.extend_from_slice(plaintext_data);
        v
    };

    // §9.2.3 / D2.3.1, AES variant: pre-pad to 16-byte multiple.
    // [chain_value]? || padded(header) || padded(plaintext_object).
    let header = [cla, ins.0, p1, p2];
    let mut mac_input = Vec::new();
    if let Some(v) = mac_chain_value {
        mac_input.extend_from_slice(v);
    }
    mac_input.extend(pad_iso9797_method2(&header, 16));
    if !plaintext_object.is_empty() {
        mac_input.extend(pad_iso9797_method2(&plaintext_object, 16));
    }
    let mac = aes_cmac_truncated(sk_mac, &mac_input, mac_length)?;

    let mut secured_data = Vec::with_capacity(plaintext_object.len() + 2 + mac_length);
    secured_data.extend_from_slice(&plaintext_object);
    secured_data.push(0x8E);
    secured_data.push(mac_length as u8);
    secured_data.extend_from_slice(&mac);

    Ok(Command {
        cla: Cla(cla),
        ins,
        p1,
        p2,
        data: secured_data,
        le: None,
    })
}

/// AES variant of [`wrap_format_1_with_confidentiality`] per Book 2
/// §9.3 + §A1.1 + §A1.2.2.
///
/// Identical wire structure to the TDES version (`'87' L '01'
/// cryptogram '8E' L MAC`), but:
///
/// - Encipherment uses AES-CBC under `sk_enc` with a zero IV per
///   §A1.1; plaintext is padded with Method 2 to a multiple of 16
///   bytes before encryption (§A1.1 step 1, Annex D2.2 - always pad,
///   even when the input is already 16-byte-aligned).
/// - The MAC is AES-CMAC under `sk_mac` with the §9.2.3 input
///   pre-padded to 16-byte multiples.
///
/// Per Annex D2.1.2 last paragraph, an empty `plaintext_data`
/// bypasses encipherment entirely and falls back to
/// [`wrap_format_1_integrity_only_aes`].
///
/// `sk_enc` and `sk_mac` are AES session keys - 16, 24, or 32 bytes
/// each (independently sized). `mac_length` is `4..=8`.
#[allow(clippy::too_many_arguments)]
pub fn wrap_format_1_with_confidentiality_aes(
    ins: Ins,
    p1: u8,
    p2: u8,
    plaintext_data: &[u8],
    chained: bool,
    sk_enc: &[u8],
    sk_mac: &[u8],
    mac_length: usize,
    mac_chain_value: Option<&[u8; 16]>,
) -> Result<Command> {
    use crate::core::aes_primitives::{aes_cbc_encrypt, aes_cmac_truncated};

    if !(4..=8).contains(&mac_length) {
        return Err(Error::InvalidValue);
    }

    if plaintext_data.is_empty() {
        return wrap_format_1_integrity_only_aes(
            ins,
            p1,
            p2,
            plaintext_data,
            chained,
            sk_mac,
            mac_length,
            mac_chain_value,
        );
    }

    let cla = SecureMessagingMode::Iso7816HeaderAuthenticated.cla_byte(chained);

    // §9.3.3 + §A1.1 (16-byte block): pad plaintext with Method 2 to
    // 16-byte multiple, then AES-CBC encrypt under sk_enc with zero
    // IV. Per Annex D2.2 the padding is always applied.
    let padded_plaintext = pad_iso9797_method2(plaintext_data, 16);
    let cryptogram = aes_cbc_encrypt(sk_enc, &[0u8; 16], &padded_plaintext)?;

    // Confidentiality data object: '87' || L || '01' || cryptogram.
    let value_len = 1 + cryptogram.len();
    let mut conf_object = Vec::with_capacity(2 + value_len);
    conf_object.push(0x87);
    conf_object.extend(encode_length(value_len));
    conf_object.push(0x01);
    conf_object.extend_from_slice(&cryptogram);

    // MAC input per §9.2.3 / D2.3 (AES variant):
    //   [chain_value]? || padded(header) || padded(conf_object),
    // each padded to a 16-byte multiple.
    let header = [cla, ins.0, p1, p2];
    let mut mac_input = Vec::new();
    if let Some(v) = mac_chain_value {
        mac_input.extend_from_slice(v);
    }
    mac_input.extend(pad_iso9797_method2(&header, 16));
    mac_input.extend(pad_iso9797_method2(&conf_object, 16));
    let mac = aes_cmac_truncated(sk_mac, &mac_input, mac_length)?;

    let mut secured_data = Vec::with_capacity(conf_object.len() + 2 + mac_length);
    secured_data.extend_from_slice(&conf_object);
    secured_data.push(0x8E);
    secured_data.push(mac_length as u8);
    secured_data.extend_from_slice(&mac);

    Ok(Command {
        cla: Cla(cla),
        ins,
        p1,
        p2,
        data: secured_data,
        le: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── CLA mode ─────────────────────────────────────────────────────

    #[test]
    fn cla_bytes_match_book_3_6_5_10_table_20() {
        assert_eq!(SecureMessagingMode::Proprietary.cla_byte(false), 0x84);
        assert_eq!(SecureMessagingMode::Proprietary.cla_byte(true), 0x94);
        assert_eq!(
            SecureMessagingMode::Iso7816HeaderAuthenticated.cla_byte(false),
            0x8C,
        );
        assert_eq!(
            SecureMessagingMode::Iso7816HeaderAuthenticated.cla_byte(true),
            0x9C,
        );
    }

    #[test]
    fn cla_byte_proprietary_class_bit_set() {
        for mode in [
            SecureMessagingMode::Proprietary,
            SecureMessagingMode::Iso7816HeaderAuthenticated,
        ] {
            for chained in [false, true] {
                assert!(mode.cla_byte(chained) & 0x80 != 0);
            }
        }
    }

    #[test]
    fn cla_byte_chaining_bit_is_b5() {
        for mode in [
            SecureMessagingMode::Proprietary,
            SecureMessagingMode::Iso7816HeaderAuthenticated,
        ] {
            assert_eq!(mode.cla_byte(true) ^ mode.cla_byte(false), 0x10);
        }
    }

    #[test]
    fn cla_byte_sm_indicator_bits_b4_b3() {
        assert_eq!(
            SecureMessagingMode::Proprietary.cla_byte(false) & 0x0C,
            0x04
        );
        assert_eq!(
            SecureMessagingMode::Iso7816HeaderAuthenticated.cla_byte(false) & 0x0C,
            0x0C,
        );
    }

    // ── DES known-answer ─────────────────────────────────────────────

    #[test]
    fn des_known_answer_fips() {
        // FIPS 81 worked example (single DES):
        //   K  = 01 23 45 67 89 AB CD EF
        //   PT = 4E 6F 77 20 69 73 20 74  ("Now is t")
        //   CT = 3F A4 0E 8A 98 4D 48 15
        let key = [0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF];
        let pt = [0x4E, 0x6F, 0x77, 0x20, 0x69, 0x73, 0x20, 0x74];
        let expected = [0x3F, 0xA4, 0x0E, 0x8A, 0x98, 0x4D, 0x48, 0x15];
        assert_eq!(des_encrypt_block(&key, pt), expected);
        assert_eq!(des_decrypt_block(&key, expected), pt);
    }

    // ── TDES round-trip ──────────────────────────────────────────────

    #[test]
    fn tdes_encrypt_decrypt_round_trip() {
        let key = [
            0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54,
            0x32, 0x10,
        ];
        let pt = [0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE];
        assert_eq!(tdes_decrypt_block(&key, tdes_encrypt_block(&key, pt)), pt);
    }

    #[test]
    fn tdes_with_kl_eq_kr_reduces_to_single_des() {
        // EDE with K_L = K_R cancels to a single DES encrypt with K_L.
        let mut key = [0u8; 16];
        let kl = [0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF];
        key[..8].copy_from_slice(&kl);
        key[8..].copy_from_slice(&kl);
        let pt = [0x4E, 0x6F, 0x77, 0x20, 0x69, 0x73, 0x20, 0x74];
        assert_eq!(tdes_encrypt_block(&key, pt), des_encrypt_block(&kl, pt));
    }

    // ── Padding ──────────────────────────────────────────────────────

    #[test]
    fn padding_appends_80_then_zeros_to_block_multiple() {
        // 1-byte input → 8-byte output with 80 then 6×00.
        assert_eq!(
            pad_iso9797_method2(&[0xAA], 8),
            vec![0xAA, 0x80, 0, 0, 0, 0, 0, 0],
        );
    }

    #[test]
    fn padding_always_adds_full_block_when_input_already_aligned() {
        // 8-byte input → 16-byte output; mandatory 80 forces a full
        // extra block per §A1.2 / §D2.2.
        let input = [0xAA; 8];
        let padded = pad_iso9797_method2(&input, 8);
        assert_eq!(padded.len(), 16);
        assert_eq!(&padded[..8], &input);
        assert_eq!(padded[8], 0x80);
        assert!(padded[9..].iter().all(|&b| b == 0));
    }

    #[test]
    fn padding_handles_empty_input() {
        assert_eq!(pad_iso9797_method2(&[], 8), vec![0x80, 0, 0, 0, 0, 0, 0, 0]);
    }

    #[test]
    fn padding_works_for_aes_block_size() {
        let padded = pad_iso9797_method2(&[1, 2, 3], 16);
        assert_eq!(padded.len(), 16);
        assert_eq!(&padded[..3], &[1, 2, 3]);
        assert_eq!(padded[3], 0x80);
    }

    #[test]
    fn unpad_finds_80_and_strips() {
        let padded = pad_iso9797_method2(&[0xAA, 0xBB], 8);
        assert_eq!(unpad_iso9797_method2(&padded).unwrap(), &[0xAA, 0xBB]);
    }

    #[test]
    fn unpad_rejects_no_80_byte() {
        assert_eq!(
            unpad_iso9797_method2(&[0xAA, 0xBB, 0xCC]),
            Err(Error::InvalidValue),
        );
    }

    #[test]
    fn unpad_rejects_all_zero_input() {
        assert_eq!(
            unpad_iso9797_method2(&[0, 0, 0, 0, 0, 0, 0, 0]),
            Err(Error::InvalidValue),
        );
    }

    // ── ECB / CBC round-trip ─────────────────────────────────────────

    #[test]
    fn tdes_ecb_round_trip_multi_block() {
        let key = [0x55; 16];
        let plaintext = pad_iso9797_method2(b"hello, EMV world!", 8);
        let ct = tdes_ecb_encrypt(&key, &plaintext).unwrap();
        let pt = tdes_ecb_decrypt(&key, &ct).unwrap();
        assert_eq!(pt, plaintext);
    }

    #[test]
    fn tdes_ecb_rejects_unaligned_input() {
        let key = [0x55; 16];
        assert_eq!(tdes_ecb_encrypt(&key, &[1, 2, 3]), Err(Error::InvalidValue),);
        assert_eq!(tdes_ecb_encrypt(&key, &[]), Err(Error::InvalidValue));
    }

    #[test]
    fn tdes_cbc_round_trip_multi_block() {
        let key = [0x77; 16];
        let iv = [0x11; 8];
        let plaintext = pad_iso9797_method2(b"the quick brown fox", 8);
        let ct = tdes_cbc_encrypt(&key, &iv, &plaintext).unwrap();
        let pt = tdes_cbc_decrypt(&key, &iv, &ct).unwrap();
        assert_eq!(pt, plaintext);
    }

    #[test]
    fn tdes_cbc_iv_changes_ciphertext() {
        let key = [0x77; 16];
        let plaintext = [0xAA; 8];
        let iv1 = [0; 8];
        let iv2 = [1; 8];
        assert_ne!(
            tdes_cbc_encrypt(&key, &iv1, &plaintext).unwrap(),
            tdes_cbc_encrypt(&key, &iv2, &plaintext).unwrap(),
        );
    }

    #[test]
    fn tdes_cbc_chains_blocks() {
        // Two identical plaintext blocks under CBC produce different
        // ciphertext blocks (vs ECB which would produce identical).
        let key = [0x77; 16];
        let iv = [0; 8];
        let pt = [0xAA; 16];
        let ct = tdes_cbc_encrypt(&key, &iv, &pt).unwrap();
        assert_ne!(&ct[..8], &ct[8..]);
    }

    // ── Retail MAC ───────────────────────────────────────────────────

    #[test]
    fn retail_mac_is_deterministic() {
        let key = [0x42; 16];
        let msg = b"APPLICATION BLOCK header";
        assert_eq!(retail_mac(&key, msg), retail_mac(&key, msg));
    }

    #[test]
    fn retail_mac_changes_with_message() {
        let key = [0x42; 16];
        assert_ne!(retail_mac(&key, b"hello"), retail_mac(&key, b"world"));
    }

    #[test]
    fn retail_mac_changes_with_key() {
        // DES ignores the LSB (parity bit) of each key byte, so any
        // two keys must differ in a non-parity bit to yield different
        // outputs. 0xAA = 10101010 and 0x54 = 01010100 differ in
        // every bit position.
        let msg = b"data";
        assert_ne!(retail_mac(&[0xAA; 16], msg), retail_mac(&[0x54; 16], msg));
    }

    #[test]
    fn retail_mac_with_kl_eq_kr_equals_single_des_cbc_mac_with_pad() {
        // When K_L = K_R the output transform reduces to identity:
        //   DES(K_L)[ DES⁻¹(K_R)[ H_B ] ] = DES(K_L)[ DES⁻¹(K_L)[ H_B ] ] = H_B
        // so retail_mac with such a key is just CBC-MAC under K_L
        // (single DES) over the padded message.
        let kl = [0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF];
        let mut key = [0u8; 16];
        key[..8].copy_from_slice(&kl);
        key[8..].copy_from_slice(&kl);
        let msg = b"hi";
        let padded = pad_iso9797_method2(msg, 8);
        // Compute reference CBC-MAC under K_L manually.
        let mut h = [0u8; 8];
        for chunk in padded.chunks_exact(8) {
            for i in 0..8 {
                h[i] ^= chunk[i];
            }
            h = des_encrypt_block(&kl, h);
        }
        assert_eq!(retail_mac(&key, msg), h);
    }

    #[test]
    fn retail_mac_no_pad_matches_pre_padded_input() {
        let key = [0x99; 16];
        let msg = b"some bytes";
        let padded = pad_iso9797_method2(msg, 8);
        assert_eq!(
            retail_mac(&key, msg),
            retail_mac_no_pad(&key, &padded).unwrap()
        );
    }

    #[test]
    fn retail_mac_no_pad_rejects_unaligned_input() {
        let key = [0x99; 16];
        assert_eq!(
            retail_mac_no_pad(&key, &[1, 2, 3]),
            Err(Error::InvalidValue)
        );
        assert_eq!(retail_mac_no_pad(&key, &[]), Err(Error::InvalidValue));
    }

    #[test]
    fn mac_truncated_takes_leftmost_s_bytes() {
        let key = [0xAA; 16];
        let msg = b"hello";
        let full = retail_mac(&key, msg);
        for s in 4..=8 {
            let truncated = mac_truncated(&key, msg, s).unwrap();
            assert_eq!(truncated, &full[..s]);
        }
    }

    #[test]
    fn mac_truncated_rejects_invalid_lengths() {
        let key = [0xAA; 16];
        for s in [0, 1, 2, 3, 9, 16] {
            assert_eq!(
                mac_truncated(&key, b"hi", s),
                Err(Error::InvalidValue),
                "s={}",
                s,
            );
        }
    }

    // ── Session Key Derivation ───────────────────────────────────────

    #[test]
    fn session_key_derivation_replaces_byte_2_with_f0_and_0f() {
        // Verify the structural property of §A1.3.1: F1 and F2 differ
        // from R only in byte 2, with F1[2]=0xF0 and F2[2]=0x0F. We
        // observe this through the session-key output by inverting:
        // SK_left  = TDES(MK)[F1], SK_right = TDES(MK)[F2].
        let mk = [0x42; 16];
        let r = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88];
        let sk = derive_session_key_tdes(&mk, &r);
        // Reverse: decrypt left half under MK should yield F1.
        let mut left_block = [0u8; 8];
        left_block.copy_from_slice(&sk[..8]);
        let f1 = tdes_decrypt_block(&mk, left_block);
        let mut expected_f1 = r;
        expected_f1[2] = 0xF0;
        assert_eq!(f1, expected_f1);
        // And right half should yield F2.
        let mut right_block = [0u8; 8];
        right_block.copy_from_slice(&sk[8..]);
        let f2 = tdes_decrypt_block(&mk, right_block);
        let mut expected_f2 = r;
        expected_f2[2] = 0x0F;
        assert_eq!(f2, expected_f2);
    }

    #[test]
    fn session_key_changes_with_diversification_value() {
        let mk = [0x42; 16];
        let r1 = [0x11; 8];
        let r2 = [0x22; 8];
        assert_ne!(
            derive_session_key_tdes(&mk, &r1),
            derive_session_key_tdes(&mk, &r2),
        );
    }

    #[test]
    fn ac_diversification_packs_atc_big_endian_and_zero_pads() {
        let r = diversification_for_ac_session_key(0x1234);
        assert_eq!(r, [0x12, 0x34, 0, 0, 0, 0, 0, 0]);
    }

    #[test]
    fn sm_diversification_uses_full_ac() {
        let ac = [0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE];
        assert_eq!(diversification_for_sm_session_key(&ac), ac);
    }

    #[test]
    fn ac_and_sm_diversification_differ_at_zero_bytes() {
        // For ATC = 0xDEAD, the AC-side R has 6 trailing zeros; the
        // SM-side R has the AC's full 8 bytes - they cannot collide
        // unless the AC happens to look like ATC || 6 zeros.
        let r_ac = diversification_for_ac_session_key(0xDEAD);
        let r_sm = diversification_for_sm_session_key(&[0xDE, 0xAD, 0, 0, 0, 0, 0, 0]);
        assert_eq!(r_ac, r_sm); // by construction, same here
        let r_sm_real = diversification_for_sm_session_key(&[0xDE, 0xAD, 1, 2, 3, 4, 5, 6]);
        assert_ne!(r_ac, r_sm_real);
    }

    // ── AES session key derivation (§A1.3.1) ─────────────────────────

    #[test]
    fn aes_sk_derivation_aes128_is_single_block_encrypt() {
        use crate::core::aes_primitives::aes_encrypt_block;
        // For k = 8n (AES-128), §A1.3.1 says SK = AES(MK)[R].
        let mk = [0x42; 16];
        let r = [0xAA; 16];
        let sk = derive_session_key_aes(&mk, &r).unwrap();
        let expected = aes_encrypt_block(&mk, r).unwrap();
        assert_eq!(sk, expected.to_vec());
        assert_eq!(sk.len(), 16);
    }

    #[test]
    fn aes_sk_derivation_aes192_uses_f1_f2_construction() {
        use crate::core::aes_primitives::aes_encrypt_block;
        let mk = [0x42; 24];
        let r = [
            0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE,
            0xFF, 0x00,
        ];
        let sk = derive_session_key_aes(&mk, &r).unwrap();
        // Expected: F1 = R with byte 2 = F0; F2 = R with byte 2 = 0F.
        let mut f1 = r;
        let mut f2 = r;
        f1[2] = 0xF0;
        f2[2] = 0x0F;
        let b1 = aes_encrypt_block(&mk, f1).unwrap();
        let b2 = aes_encrypt_block(&mk, f2).unwrap();
        let mut full = Vec::new();
        full.extend_from_slice(&b1);
        full.extend_from_slice(&b2);
        // Leftmost 24 bytes = first 24 of 32.
        assert_eq!(sk, full[..24]);
        assert_eq!(sk.len(), 24);
    }

    #[test]
    fn aes_sk_derivation_aes256_takes_full_two_blocks() {
        let mk = [0x42; 32];
        let r = [0xAA; 16];
        let sk = derive_session_key_aes(&mk, &r).unwrap();
        assert_eq!(sk.len(), 32);
    }

    #[test]
    fn aes_sk_derivation_rejects_bad_key_length() {
        let r = [0; 16];
        assert!(derive_session_key_aes(&[0; 8], &r).is_err());
        assert!(derive_session_key_aes(&[0; 17], &r).is_err());
        assert!(derive_session_key_aes(&[0; 23], &r).is_err());
        assert!(derive_session_key_aes(&[0; 31], &r).is_err());
    }

    #[test]
    fn aes_sk_derivation_distinct_for_each_key_size() {
        // Same MK *bytes* (truncated/extended) yield distinct SKs in
        // AES-128 vs -192 vs -256 modes (different cipher, different
        // construction).
        let r = [0x10; 16];
        let sk128 = derive_session_key_aes(&[0xAA; 16], &r).unwrap();
        let sk192 = derive_session_key_aes(&[0xAA; 24], &r).unwrap();
        let sk256 = derive_session_key_aes(&[0xAA; 32], &r).unwrap();
        assert_ne!(sk128, sk192[..16]);
        assert_ne!(sk192, sk256[..24]);
    }

    #[test]
    fn aes_sk_derivation_distinct_for_different_diversification() {
        let mk = [0x42; 16];
        let r1 = diversification_for_ac_session_key_aes(0x0001);
        let r2 = diversification_for_ac_session_key_aes(0x0002);
        assert_ne!(
            derive_session_key_aes(&mk, &r1).unwrap(),
            derive_session_key_aes(&mk, &r2).unwrap(),
        );
    }

    #[test]
    fn aes_ac_diversification_packs_atc_into_first_two_bytes() {
        let r = diversification_for_ac_session_key_aes(0x1234);
        let mut expected = [0u8; 16];
        expected[0] = 0x12;
        expected[1] = 0x34;
        assert_eq!(r, expected);
    }

    #[test]
    fn aes_sm_diversification_packs_ac_into_left_half() {
        let ac = [0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE];
        let r = diversification_for_sm_session_key_aes(&ac);
        assert_eq!(&r[..8], &ac);
        assert_eq!(&r[8..], &[0u8; 8]);
    }

    // ── Format 1 SM composer ─────────────────────────────────────────

    #[test]
    fn wrap_format_1_no_data_application_block() {
        // APPLICATION BLOCK (INS=1E, no data) wrapped with Format 1
        // integrity. Secured CLA = 8C, secured data = '8E 08 [MAC8]'.
        let sk_mac = [0xAA; 16];
        let cmd = wrap_format_1_integrity_only(
            Ins::APPLICATION_BLOCK,
            0,
            0,
            &[],
            false,
            &sk_mac,
            8,
            None,
        )
        .unwrap();
        assert_eq!(cmd.cla.0, 0x8C);
        assert_eq!(cmd.ins, Ins::APPLICATION_BLOCK);
        assert_eq!(cmd.p1, 0);
        assert_eq!(cmd.p2, 0);
        assert_eq!(cmd.data.len(), 10);
        assert_eq!(&cmd.data[..2], &[0x8E, 0x08]);
        assert_eq!(cmd.le, None);
        // MAC must equal retail_mac_no_pad over padded header alone.
        let header = [0x8C, 0x1E, 0x00, 0x00];
        let padded = pad_iso9797_method2(&header, 8);
        let expected = retail_mac_no_pad(&sk_mac, &padded).unwrap();
        assert_eq!(&cmd.data[2..], &expected[..]);
    }

    #[test]
    fn wrap_format_1_with_data_pin_change_unblock_biometric() {
        // PIN CHANGE/UNBLOCK with P2=03 and a single Biometric Type
        // byte (Book 3 §6.5.10.2). Secured data should be:
        //   81 01 [BT] 8E LL [MAC]
        let sk_mac = [
            0x42, 0x44, 0x46, 0x48, 0x4A, 0x4C, 0x4E, 0x50, 0x52, 0x54, 0x56, 0x58, 0x5A, 0x5C,
            0x5E, 0x60,
        ];
        let bt = [0x01];
        let cmd = wrap_format_1_integrity_only(
            Ins::PIN_CHANGE_UNBLOCK,
            0x00,
            0x03,
            &bt,
            false,
            &sk_mac,
            8,
            None,
        )
        .unwrap();
        assert_eq!(cmd.cla.0, 0x8C);
        assert_eq!(cmd.ins, Ins::PIN_CHANGE_UNBLOCK);
        assert_eq!(cmd.p2, 0x03);
        // 81 01 BT 8E 08 MAC8 = 13 bytes.
        assert_eq!(cmd.data.len(), 13);
        assert_eq!(&cmd.data[..3], &[0x81, 0x01, 0x01]);
        assert_eq!(&cmd.data[3..5], &[0x8E, 0x08]);
        // MAC over padded(header) || padded(81 01 BT).
        let header = [0x8C, 0x24, 0x00, 0x03];
        let mut input = pad_iso9797_method2(&header, 8);
        input.extend(pad_iso9797_method2(&[0x81, 0x01, 0x01], 8));
        let expected = retail_mac_no_pad(&sk_mac, &input).unwrap();
        assert_eq!(&cmd.data[5..], &expected[..]);
    }

    #[test]
    fn wrap_format_1_chained_uses_cla_9c() {
        let sk_mac = [0xAA; 16];
        let cmd = wrap_format_1_integrity_only(
            Ins::PIN_CHANGE_UNBLOCK,
            0,
            0x01,
            &[0xDE, 0xAD],
            true, // chained
            &sk_mac,
            8,
            None,
        )
        .unwrap();
        assert_eq!(cmd.cla.0, 0x9C);
    }

    #[test]
    fn wrap_format_1_truncated_mac_length() {
        let sk_mac = [0xAA; 16];
        // Same inputs, varying MAC length 4..=8. The truncated MAC
        // should be the prefix of the full MAC.
        let full = wrap_format_1_integrity_only(
            Ins::APPLICATION_BLOCK,
            0,
            0,
            &[],
            false,
            &sk_mac,
            8,
            None,
        )
        .unwrap();
        let full_mac = &full.data[2..];
        for s in 4..=7 {
            let cmd = wrap_format_1_integrity_only(
                Ins::APPLICATION_BLOCK,
                0,
                0,
                &[],
                false,
                &sk_mac,
                s,
                None,
            )
            .unwrap();
            assert_eq!(cmd.data[1] as usize, s, "Lc of MAC TLV");
            assert_eq!(&cmd.data[2..], &full_mac[..s]);
        }
    }

    #[test]
    fn wrap_format_1_rejects_invalid_mac_length() {
        let sk_mac = [0xAA; 16];
        for s in [0, 1, 2, 3, 9, 16] {
            assert_eq!(
                wrap_format_1_integrity_only(
                    Ins::APPLICATION_BLOCK,
                    0,
                    0,
                    &[],
                    false,
                    &sk_mac,
                    s,
                    None
                ),
                Err(Error::InvalidValue),
                "s={}",
                s,
            );
        }
    }

    #[test]
    fn wrap_format_1_is_deterministic() {
        let sk_mac = [0x55; 16];
        let a = wrap_format_1_integrity_only(Ins::CARD_BLOCK, 0, 0, &[], false, &sk_mac, 8, None)
            .unwrap();
        let b = wrap_format_1_integrity_only(Ins::CARD_BLOCK, 0, 0, &[], false, &sk_mac, 8, None)
            .unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn wrap_format_1_long_data_uses_long_form_length() {
        // 200 bytes of plaintext → '81 81 C8 ... data ... 8E 08 MAC8'.
        // Long-form length encoding kicks in at >= 128 bytes (0x80).
        let sk_mac = [0x33; 16];
        let plaintext = vec![0xAA; 200];
        let cmd = wrap_format_1_integrity_only(
            Ins::PIN_CHANGE_UNBLOCK,
            0,
            0x02,
            &plaintext,
            false,
            &sk_mac,
            8,
            None,
        )
        .unwrap();
        // Tag 81, length 81 C8 (200), 200 bytes data, 8E 08 MAC8.
        assert_eq!(&cmd.data[..3], &[0x81, 0x81, 0xC8]);
        assert_eq!(cmd.data.len(), 3 + 200 + 2 + 8);
    }

    // ── Format 1 SM with confidentiality ────────────────────────────

    #[test]
    fn wrap_format_1_conf_8byte_pin_block_layout() {
        // Typical PIN-data path: 8-byte plaintext PIN block under
        // PIN CHANGE/UNBLOCK with payment-system P2='01'.
        // Method 2 padding always applies (Annex D2.2): 8 bytes of
        // plaintext become 16 bytes after padding (8 data + 80 + 7×00).
        // Cryptogram = 16 bytes. '87' value = '01' || 16-byte cipher
        // → length 17. Secured data = 87 11 01 [16] 8E 08 [MAC]
        // = 2 + 17 + 2 + 8 = 29 bytes.
        let sk_enc = [0x11; 16];
        let sk_mac = [0x22; 16];
        let pin_block = [0x24, 0x12, 0x34, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF];
        let cmd = wrap_format_1_with_confidentiality(
            Ins::PIN_CHANGE_UNBLOCK,
            0x00,
            0x01,
            &pin_block,
            false,
            &sk_enc,
            &sk_mac,
            8,
            None,
        )
        .unwrap();
        assert_eq!(cmd.cla.0, 0x8C);
        assert_eq!(cmd.ins, Ins::PIN_CHANGE_UNBLOCK);
        assert_eq!(cmd.p1, 0x00);
        assert_eq!(cmd.p2, 0x01);
        assert_eq!(cmd.data.len(), 29);
        // Tag '87', length 0x11 (17), padding indicator '01'.
        assert_eq!(&cmd.data[..3], &[0x87, 0x11, 0x01]);
        // Bytes 3..19 = ciphertext (16 bytes).
        // Verify ciphertext = TDES-CBC(sk_enc, IV=0, pad(pin_block)).
        let padded = pad_iso9797_method2(&pin_block, 8);
        let expected_ct = tdes_cbc_encrypt(&sk_enc, &[0u8; 8], &padded).unwrap();
        assert_eq!(&cmd.data[3..19], expected_ct.as_slice());
        // '8E' || 0x08 || MAC8.
        assert_eq!(&cmd.data[19..21], &[0x8E, 0x08]);
        // MAC = retail_mac over pad(header) || pad('87' TLV).
        let header = [0x8C, Ins::PIN_CHANGE_UNBLOCK.0, 0x00, 0x01];
        let mut mac_input = pad_iso9797_method2(&header, 8);
        mac_input.extend(pad_iso9797_method2(&cmd.data[..19], 8));
        let expected_mac = retail_mac_no_pad(&sk_mac, &mac_input).unwrap();
        assert_eq!(&cmd.data[21..], &expected_mac[..]);
    }

    #[test]
    fn wrap_format_1_conf_padding_extends_unaligned_input() {
        // 5-byte input → padded to 8 (5 data + '80' + 2×'00') →
        // 8-byte ciphertext. '87' value = '01' || 8-byte cipher = 9.
        // Secured data = 87 09 01 [8] 8E 08 [MAC] = 2 + 9 + 2 + 8 = 21.
        let sk_enc = [0xAA; 16];
        let sk_mac = [0x55; 16];
        let plaintext = [0x01, 0x02, 0x03, 0x04, 0x05];
        let cmd = wrap_format_1_with_confidentiality(
            Ins::PIN_CHANGE_UNBLOCK,
            0,
            0x02,
            &plaintext,
            false,
            &sk_enc,
            &sk_mac,
            8,
            None,
        )
        .unwrap();
        assert_eq!(cmd.data.len(), 21);
        assert_eq!(&cmd.data[..3], &[0x87, 0x09, 0x01]);
        let padded = pad_iso9797_method2(&plaintext, 8);
        assert_eq!(padded.len(), 8);
        let expected_ct = tdes_cbc_encrypt(&sk_enc, &[0u8; 8], &padded).unwrap();
        assert_eq!(&cmd.data[3..11], expected_ct.as_slice());
    }

    #[test]
    fn wrap_format_1_conf_long_data_uses_two_byte_length() {
        // 200-byte plaintext → padded to 200 + 8 (full extra block per
        // Method 2 since 200 is already a multiple of 8) = 208 bytes
        // ciphertext. '87' value = '01' || 208 = 209 bytes → BER
        // length encoded as 81 D1.
        let sk_enc = [0x11; 16];
        let sk_mac = [0x22; 16];
        let plaintext = vec![0xCC; 200];
        let cmd = wrap_format_1_with_confidentiality(
            Ins::PIN_CHANGE_UNBLOCK,
            0,
            0x01,
            &plaintext,
            false,
            &sk_enc,
            &sk_mac,
            8,
            None,
        )
        .unwrap();
        // Header: 87 81 D1 01 [208 bytes ciphertext] 8E 08 [MAC]
        assert_eq!(&cmd.data[..4], &[0x87, 0x81, 0xD1, 0x01]);
        let padded = pad_iso9797_method2(&plaintext, 8);
        assert_eq!(padded.len(), 208);
        assert_eq!(cmd.data.len(), 4 + 208 + 2 + 8);
    }

    #[test]
    fn wrap_format_1_conf_8byte_input_still_pads_full_block() {
        // Annex D2.2 first bullet: "if the length of the unsecured
        // command data field is a multiple of 8 bytes, it is padded
        // with 8 bytes ('80 00 00 00 00 00 00 00') prior to
        // encipherment". So 8-byte input → 16-byte padded → 16-byte
        // ciphertext (NOT 8).
        let sk_enc = [0x11; 16];
        let sk_mac = [0x22; 16];
        let plaintext = [0xAA; 8];
        let cmd = wrap_format_1_with_confidentiality(
            Ins::PIN_CHANGE_UNBLOCK,
            0,
            0x01,
            &plaintext,
            false,
            &sk_enc,
            &sk_mac,
            8,
            None,
        )
        .unwrap();
        // '87' length value = '01' (1) + 16 = 17 = 0x11.
        assert_eq!(&cmd.data[..3], &[0x87, 0x11, 0x01]);
        // 16 bytes of ciphertext follow.
        let padded = pad_iso9797_method2(&plaintext, 8);
        assert_eq!(padded.len(), 16);
        let expected_ct = tdes_cbc_encrypt(&sk_enc, &[0u8; 8], &padded).unwrap();
        assert_eq!(&cmd.data[3..19], expected_ct.as_slice());
    }

    #[test]
    fn wrap_format_1_conf_empty_data_falls_back_to_integrity_only() {
        // Per Annex D2.1.2 last paragraph, an empty unsecured data
        // field bypasses encipherment entirely.
        let sk_enc = [0x11; 16];
        let sk_mac = [0x22; 16];
        let conf = wrap_format_1_with_confidentiality(
            Ins::APPLICATION_BLOCK,
            0,
            0,
            &[],
            false,
            &sk_enc,
            &sk_mac,
            8,
            None,
        )
        .unwrap();
        let integrity = wrap_format_1_integrity_only(
            Ins::APPLICATION_BLOCK,
            0,
            0,
            &[],
            false,
            &sk_mac,
            8,
            None,
        )
        .unwrap();
        assert_eq!(conf.cla.0, integrity.cla.0);
        assert_eq!(conf.data, integrity.data);
        // No '87' object - just '8E 08 MAC8'.
        assert_eq!(&conf.data[..2], &[0x8E, 0x08]);
        assert_eq!(conf.data.len(), 10);
    }

    #[test]
    fn wrap_format_1_conf_chained_uses_cla_9c() {
        let sk_enc = [0xAA; 16];
        let sk_mac = [0x55; 16];
        let cmd = wrap_format_1_with_confidentiality(
            Ins::PIN_CHANGE_UNBLOCK,
            0,
            0x01,
            &[0xDE; 32],
            true, // chained
            &sk_enc,
            &sk_mac,
            8,
            None,
        )
        .unwrap();
        assert_eq!(cmd.cla.0, 0x9C);
    }

    #[test]
    fn wrap_format_1_conf_truncated_mac_length() {
        let sk_enc = [0xAA; 16];
        let sk_mac = [0x55; 16];
        let plaintext = [0x12, 0x34, 0x56, 0x78];
        let full = wrap_format_1_with_confidentiality(
            Ins::PIN_CHANGE_UNBLOCK,
            0,
            0x01,
            &plaintext,
            false,
            &sk_enc,
            &sk_mac,
            8,
            None,
        )
        .unwrap();
        // Strip the trailing '8E LL MAC...' to recover the full MAC.
        let mac_offset = full.data.len() - 8;
        let full_mac = &full.data[mac_offset..];
        for s in 4..=7 {
            let cmd = wrap_format_1_with_confidentiality(
                Ins::PIN_CHANGE_UNBLOCK,
                0,
                0x01,
                &plaintext,
                false,
                &sk_enc,
                &sk_mac,
                s,
                None,
            )
            .unwrap();
            // Last s bytes are the truncated MAC.
            let trunc = &cmd.data[cmd.data.len() - s..];
            assert_eq!(trunc, &full_mac[..s], "s={}", s);
            // The byte before the MAC must be the LL = s.
            assert_eq!(cmd.data[cmd.data.len() - s - 1], s as u8);
        }
    }

    #[test]
    fn wrap_format_1_conf_rejects_invalid_mac_length() {
        let sk_enc = [0xAA; 16];
        let sk_mac = [0x55; 16];
        for s in [0, 1, 2, 3, 9, 16] {
            assert_eq!(
                wrap_format_1_with_confidentiality(
                    Ins::PIN_CHANGE_UNBLOCK,
                    0,
                    0x01,
                    &[0xAA; 8],
                    false,
                    &sk_enc,
                    &sk_mac,
                    s,
                    None
                ),
                Err(Error::InvalidValue),
                "s={}",
                s,
            );
        }
    }

    #[test]
    fn wrap_format_1_conf_distinct_keys_yield_distinct_output() {
        // Sanity: different sk_enc → different ciphertext; different
        // sk_mac → different MAC.
        let plaintext = [0xAB; 8];
        let key_a = [0xAA; 16];
        let key_b = [0x55; 16];

        let a = wrap_format_1_with_confidentiality(
            Ins::PIN_CHANGE_UNBLOCK,
            0,
            1,
            &plaintext,
            false,
            &key_a,
            &key_a,
            8,
            None,
        )
        .unwrap();
        let b = wrap_format_1_with_confidentiality(
            Ins::PIN_CHANGE_UNBLOCK,
            0,
            1,
            &plaintext,
            false,
            &key_b,
            &key_a,
            8,
            None,
        )
        .unwrap();
        let c = wrap_format_1_with_confidentiality(
            Ins::PIN_CHANGE_UNBLOCK,
            0,
            1,
            &plaintext,
            false,
            &key_a,
            &key_b,
            8,
            None,
        )
        .unwrap();
        // Cipher region differs when sk_enc differs.
        assert_ne!(&a.data[3..19], &b.data[3..19]);
        // Cipher region same when sk_mac differs but sk_enc same.
        assert_eq!(&a.data[3..19], &c.data[3..19]);
        // MAC differs when sk_mac differs.
        assert_ne!(&a.data[a.data.len() - 8..], &c.data[c.data.len() - 8..]);
    }

    #[test]
    fn wrap_format_1_serializes_to_wire_bytes() {
        // End-to-end: build, serialize, sanity-check the wire layout.
        let sk_mac = [0xAA; 16];
        let cmd = wrap_format_1_integrity_only(
            Ins::APPLICATION_BLOCK,
            0,
            0,
            &[],
            false,
            &sk_mac,
            8,
            None,
        )
        .unwrap();
        let wire = cmd.to_bytes().unwrap();
        // CLA INS P1 P2 Lc 8E 08 MAC8 = 4 + 1 + 10 = 15 bytes.
        assert_eq!(wire.len(), 15);
        assert_eq!(&wire[..5], &[0x8C, 0x1E, 0x00, 0x00, 0x0A]);
        assert_eq!(&wire[5..7], &[0x8E, 0x08]);
    }

    // ── Format 1 SM composer (AES variants) ──────────────────────────

    #[test]
    fn wrap_format_1_aes_integrity_no_data_application_block() {
        use crate::core::aes_primitives::aes_cmac_truncated;
        let sk_mac = [0xAA; 16];
        let cmd = wrap_format_1_integrity_only_aes(
            Ins::APPLICATION_BLOCK,
            0,
            0,
            &[],
            false,
            &sk_mac,
            8,
            None,
        )
        .unwrap();
        assert_eq!(cmd.cla.0, 0x8C);
        assert_eq!(cmd.data.len(), 10);
        assert_eq!(&cmd.data[..2], &[0x8E, 0x08]);
        // MAC = AES-CMAC over pad(header, 16).
        let header = [0x8C, Ins::APPLICATION_BLOCK.0, 0, 0];
        let padded = pad_iso9797_method2(&header, 16);
        let expected = aes_cmac_truncated(&sk_mac, &padded, 8).unwrap();
        assert_eq!(&cmd.data[2..], expected.as_slice());
    }

    #[test]
    fn wrap_format_1_aes_integrity_with_data_pin_change() {
        use crate::core::aes_primitives::aes_cmac_truncated;
        let sk_mac = [0x42; 16];
        let bt = [0x01];
        let cmd = wrap_format_1_integrity_only_aes(
            Ins::PIN_CHANGE_UNBLOCK,
            0,
            0x03,
            &bt,
            false,
            &sk_mac,
            8,
            None,
        )
        .unwrap();
        assert_eq!(cmd.data.len(), 13);
        assert_eq!(&cmd.data[..3], &[0x81, 0x01, 0x01]);
        assert_eq!(&cmd.data[3..5], &[0x8E, 0x08]);
        // MAC = AES-CMAC over pad(header,16) || pad('81 01 BT', 16).
        let header = [0x8C, Ins::PIN_CHANGE_UNBLOCK.0, 0, 0x03];
        let mut input = pad_iso9797_method2(&header, 16);
        input.extend(pad_iso9797_method2(&[0x81, 0x01, 0x01], 16));
        let expected = aes_cmac_truncated(&sk_mac, &input, 8).unwrap();
        assert_eq!(&cmd.data[5..], expected.as_slice());
    }

    #[test]
    fn wrap_format_1_aes_supports_all_three_key_sizes() {
        let plaintext = [0xAA; 8];
        let c128 = wrap_format_1_integrity_only_aes(
            Ins::PIN_CHANGE_UNBLOCK,
            0,
            1,
            &plaintext,
            false,
            &[0xAA; 16],
            8,
            None,
        )
        .unwrap();
        let c192 = wrap_format_1_integrity_only_aes(
            Ins::PIN_CHANGE_UNBLOCK,
            0,
            1,
            &plaintext,
            false,
            &[0xAA; 24],
            8,
            None,
        )
        .unwrap();
        let c256 = wrap_format_1_integrity_only_aes(
            Ins::PIN_CHANGE_UNBLOCK,
            0,
            1,
            &plaintext,
            false,
            &[0xAA; 32],
            8,
            None,
        )
        .unwrap();
        // Same wire structure modulo the MAC bytes.
        assert_eq!(c128.data[..3], c192.data[..3]);
        assert_eq!(c128.data[..3], c256.data[..3]);
        // Different MAC due to different key.
        let mac_offset = c128.data.len() - 8;
        assert_ne!(&c128.data[mac_offset..], &c192.data[mac_offset..]);
        assert_ne!(&c128.data[mac_offset..], &c256.data[mac_offset..]);
    }

    #[test]
    fn wrap_format_1_aes_rejects_invalid_mac_length() {
        let sk_mac = [0xAA; 16];
        for s in [0, 1, 2, 3, 9, 16] {
            assert_eq!(
                wrap_format_1_integrity_only_aes(
                    Ins::APPLICATION_BLOCK,
                    0,
                    0,
                    &[],
                    false,
                    &sk_mac,
                    s,
                    None
                ),
                Err(Error::InvalidValue),
            );
        }
    }

    #[test]
    fn wrap_format_1_aes_rejects_bad_key_length() {
        // Bad SK length propagates from aes_cmac.
        assert!(
            wrap_format_1_integrity_only_aes(
                Ins::APPLICATION_BLOCK,
                0,
                0,
                &[],
                false,
                &[0xAA; 8],
                8,
                None
            )
            .is_err()
        );
        assert!(
            wrap_format_1_integrity_only_aes(
                Ins::APPLICATION_BLOCK,
                0,
                0,
                &[],
                false,
                &[0xAA; 17],
                8,
                None
            )
            .is_err()
        );
    }

    #[test]
    fn wrap_format_1_aes_chained_uses_cla_9c() {
        let cmd = wrap_format_1_integrity_only_aes(
            Ins::PIN_CHANGE_UNBLOCK,
            0,
            0,
            &[0xDE],
            true,
            &[0xAA; 16],
            8,
            None,
        )
        .unwrap();
        assert_eq!(cmd.cla.0, 0x9C);
    }

    #[test]
    fn wrap_format_1_aes_differs_from_tdes() {
        // Same key bytes used in both modes must produce different
        // MAC bytes (different cipher + different padding block size).
        let sk_mac = [0xAA; 16];
        let plaintext = [0xCC; 8];
        let tdes = wrap_format_1_integrity_only(
            Ins::PIN_CHANGE_UNBLOCK,
            0,
            1,
            &plaintext,
            false,
            &sk_mac,
            8,
            None,
        )
        .unwrap();
        let aes = wrap_format_1_integrity_only_aes(
            Ins::PIN_CHANGE_UNBLOCK,
            0,
            1,
            &plaintext,
            false,
            &sk_mac,
            8,
            None,
        )
        .unwrap();
        assert_eq!(tdes.data[..3], aes.data[..3]); // same wire prefix
        let n = tdes.data.len();
        assert_ne!(&tdes.data[n - 8..], &aes.data[n - 8..]);
    }

    // ── Format 1 SM with confidentiality (AES) ───────────────────────

    #[test]
    fn wrap_format_1_aes_conf_8byte_pin_block_layout() {
        use crate::core::aes_primitives::{aes_cbc_encrypt, aes_cmac_truncated};
        // 8-byte PIN block. Method 2 padding to 16 bytes adds '80' +
        // 7×'00' → 16-byte plaintext → 16-byte ciphertext.
        // '87' value = '01' || 16 cipher = 17 (0x11) bytes.
        // Secured = 87 11 01 [16 cipher] 8E 08 MAC = 2+17+2+8 = 29.
        let sk_enc = [0x11; 16];
        let sk_mac = [0x22; 16];
        let pin_block = [0x24, 0x12, 0x34, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF];
        let cmd = wrap_format_1_with_confidentiality_aes(
            Ins::PIN_CHANGE_UNBLOCK,
            0,
            0x01,
            &pin_block,
            false,
            &sk_enc,
            &sk_mac,
            8,
            None,
        )
        .unwrap();
        assert_eq!(cmd.data.len(), 29);
        assert_eq!(&cmd.data[..3], &[0x87, 0x11, 0x01]);
        // Manual: AES-CBC over Method-2-padded pin block.
        let padded = pad_iso9797_method2(&pin_block, 16);
        let expected_ct = aes_cbc_encrypt(&sk_enc, &[0u8; 16], &padded).unwrap();
        assert_eq!(&cmd.data[3..19], expected_ct.as_slice());
        assert_eq!(&cmd.data[19..21], &[0x8E, 0x08]);
        // MAC over pad(header, 16) || pad('87' TLV, 16).
        let header = [0x8C, Ins::PIN_CHANGE_UNBLOCK.0, 0, 0x01];
        let mut input = pad_iso9797_method2(&header, 16);
        input.extend(pad_iso9797_method2(&cmd.data[..19], 16));
        let expected_mac = aes_cmac_truncated(&sk_mac, &input, 8).unwrap();
        assert_eq!(&cmd.data[21..], expected_mac.as_slice());
    }

    #[test]
    fn wrap_format_1_aes_conf_16byte_input_pads_full_block() {
        // 16-byte input is already a multiple of 16 → §A1.1 / D2.2
        // says always pad → result is 32-byte ciphertext.
        let sk_enc = [0x11; 16];
        let sk_mac = [0x22; 16];
        let plaintext = [0xAA; 16];
        let cmd = wrap_format_1_with_confidentiality_aes(
            Ins::PIN_CHANGE_UNBLOCK,
            0,
            1,
            &plaintext,
            false,
            &sk_enc,
            &sk_mac,
            8,
            None,
        )
        .unwrap();
        // '87' value length = 1 ('01') + 32 cipher = 33 (0x21).
        assert_eq!(&cmd.data[..3], &[0x87, 0x21, 0x01]);
        let padded = pad_iso9797_method2(&plaintext, 16);
        assert_eq!(padded.len(), 32);
    }

    #[test]
    fn wrap_format_1_aes_conf_empty_data_falls_back_to_integrity_only() {
        let sk_enc = [0x11; 16];
        let sk_mac = [0x22; 16];
        let conf = wrap_format_1_with_confidentiality_aes(
            Ins::APPLICATION_BLOCK,
            0,
            0,
            &[],
            false,
            &sk_enc,
            &sk_mac,
            8,
            None,
        )
        .unwrap();
        let integrity = wrap_format_1_integrity_only_aes(
            Ins::APPLICATION_BLOCK,
            0,
            0,
            &[],
            false,
            &sk_mac,
            8,
            None,
        )
        .unwrap();
        assert_eq!(conf.data, integrity.data);
        assert_eq!(&conf.data[..2], &[0x8E, 0x08]);
    }

    #[test]
    fn wrap_format_1_aes_conf_chained_uses_cla_9c() {
        let cmd = wrap_format_1_with_confidentiality_aes(
            Ins::PIN_CHANGE_UNBLOCK,
            0,
            1,
            &[0xDE; 16],
            true,
            &[0xAA; 16],
            &[0x55; 16],
            8,
            None,
        )
        .unwrap();
        assert_eq!(cmd.cla.0, 0x9C);
    }

    #[test]
    fn wrap_format_1_aes_conf_supports_aes192_and_aes256() {
        let plaintext = [0xAA; 8];
        let c192 = wrap_format_1_with_confidentiality_aes(
            Ins::PIN_CHANGE_UNBLOCK,
            0,
            1,
            &plaintext,
            false,
            &[0xAA; 24],
            &[0x55; 24],
            8,
            None,
        )
        .unwrap();
        let c256 = wrap_format_1_with_confidentiality_aes(
            Ins::PIN_CHANGE_UNBLOCK,
            0,
            1,
            &plaintext,
            false,
            &[0xAA; 32],
            &[0x55; 32],
            8,
            None,
        )
        .unwrap();
        // Same wire prefix; different cipher region and MAC.
        assert_eq!(c192.data[..3], c256.data[..3]);
        assert_ne!(c192.data[3..19], c256.data[3..19]);
    }

    #[test]
    fn wrap_format_1_aes_conf_rejects_invalid_mac_length() {
        for s in [0, 1, 2, 3, 9, 16] {
            assert_eq!(
                wrap_format_1_with_confidentiality_aes(
                    Ins::PIN_CHANGE_UNBLOCK,
                    0,
                    1,
                    &[0xAA; 8],
                    false,
                    &[0xAA; 16],
                    &[0x55; 16],
                    s,
                    None
                ),
                Err(Error::InvalidValue),
            );
        }
    }

    #[test]
    fn wrap_format_1_aes_conf_distinct_keys_yield_distinct_output() {
        let plaintext = [0xAB; 8];
        let key_a = [0xAA; 16];
        let key_b = [0x55; 16];
        let a = wrap_format_1_with_confidentiality_aes(
            Ins::PIN_CHANGE_UNBLOCK,
            0,
            1,
            &plaintext,
            false,
            &key_a,
            &key_a,
            8,
            None,
        )
        .unwrap();
        let b = wrap_format_1_with_confidentiality_aes(
            Ins::PIN_CHANGE_UNBLOCK,
            0,
            1,
            &plaintext,
            false,
            &key_b,
            &key_a,
            8,
            None,
        )
        .unwrap();
        let c = wrap_format_1_with_confidentiality_aes(
            Ins::PIN_CHANGE_UNBLOCK,
            0,
            1,
            &plaintext,
            false,
            &key_a,
            &key_b,
            8,
            None,
        )
        .unwrap();
        // Different sk_enc → different cipher region.
        assert_ne!(&a.data[3..19], &b.data[3..19]);
        // Same sk_enc, different sk_mac → same cipher, different MAC.
        assert_eq!(&a.data[3..19], &c.data[3..19]);
        let n = a.data.len();
        assert_ne!(&a.data[n - 8..], &c.data[n - 8..]);
    }

    // ── §9.2.3.1 / D2.3 MAC chaining ─────────────────────────────────

    #[test]
    fn mac_chaining_tdes_first_command_uses_ac() {
        // §9.2.3.1: for the first/only script command, the inserted
        // 8-byte value is the Application Cryptogram. Verify that
        // passing the AC as `mac_chain_value` makes it appear at the
        // start of the MAC input.
        let sk_mac = [0xAA; 16];
        let ac = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
        let bt = [0xDE, 0xAD];
        let cmd = wrap_format_1_integrity_only(
            Ins::PIN_CHANGE_UNBLOCK,
            0,
            0x03,
            &bt,
            false,
            &sk_mac,
            8,
            Some(&ac),
        )
        .unwrap();

        // Recompute: AC || pad(header) || pad('81 02 BT').
        let header = [0x8C, Ins::PIN_CHANGE_UNBLOCK.0, 0x00, 0x03];
        let mut mac_input = ac.to_vec();
        mac_input.extend(pad_iso9797_method2(&header, 8));
        mac_input.extend(pad_iso9797_method2(&[0x81, 0x02, 0xDE, 0xAD], 8));
        let expected = retail_mac_no_pad(&sk_mac, &mac_input).unwrap();
        let mac_offset = cmd.data.len() - 8;
        assert_eq!(&cmd.data[mac_offset..], &expected[..]);
    }

    #[test]
    fn mac_chaining_changes_mac_value() {
        // Without and with a chain value, the same command must
        // produce different MACs.
        let sk_mac = [0x55; 16];
        let bt = [0x00];
        let no_chain = wrap_format_1_integrity_only(
            Ins::PIN_CHANGE_UNBLOCK,
            0,
            0x03,
            &bt,
            false,
            &sk_mac,
            8,
            None,
        )
        .unwrap();
        let with_chain = wrap_format_1_integrity_only(
            Ins::PIN_CHANGE_UNBLOCK,
            0,
            0x03,
            &bt,
            false,
            &sk_mac,
            8,
            Some(&[0xAA; 8]),
        )
        .unwrap();
        // Same wire layout up to the MAC, different MAC bytes.
        let n = no_chain.data.len();
        assert_eq!(&no_chain.data[..n - 8], &with_chain.data[..n - 8]);
        assert_ne!(&no_chain.data[n - 8..], &with_chain.data[n - 8..]);
    }

    #[test]
    fn mac_chaining_tdes_subsequent_uses_previous_full_mac() {
        // Two-script-command flow: command #1 uses the AC as the
        // chain value, command #2 uses command #1's full
        // pre-truncation MAC as the chain value.
        let sk_mac = [0xAA; 16];
        let ac = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];

        let cmd1 = wrap_format_1_integrity_only(
            Ins::PIN_CHANGE_UNBLOCK,
            0,
            0x03,
            &[0xDE, 0xAD],
            false,
            &sk_mac,
            8,
            Some(&ac),
        )
        .unwrap();
        // Command #1's full MAC (no truncation since mac_length = 8).
        let mac1: [u8; 8] = cmd1.data[cmd1.data.len() - 8..].try_into().unwrap();

        let cmd2 = wrap_format_1_integrity_only(
            Ins::APPLICATION_BLOCK,
            0,
            0,
            &[],
            false,
            &sk_mac,
            8,
            Some(&mac1),
        )
        .unwrap();

        // Recompute cmd2 expected: mac1 || pad(header) (no data object).
        let header = [0x8C, Ins::APPLICATION_BLOCK.0, 0x00, 0x00];
        let mut mac_input = mac1.to_vec();
        mac_input.extend(pad_iso9797_method2(&header, 8));
        let expected = retail_mac_no_pad(&sk_mac, &mac_input).unwrap();
        assert_eq!(&cmd2.data[cmd2.data.len() - 8..], &expected[..]);
    }

    #[test]
    fn mac_chaining_aes_first_command_uses_ac_padded() {
        // §9.2.3.1: for AES (16-byte block) the first-command chain
        // value is `AC || '00' × 8` (16 bytes).
        let sk_mac = [0x44u8; 16];
        let ac = [0x01u8, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
        let mut chain = [0u8; 16];
        chain[..8].copy_from_slice(&ac);

        let bt = [0xCAu8, 0xFE];
        let cmd = wrap_format_1_integrity_only_aes(
            Ins::PIN_CHANGE_UNBLOCK,
            0,
            0x03,
            &bt,
            false,
            &sk_mac,
            8,
            Some(&chain),
        )
        .unwrap();

        // Recompute: chain || pad16(header) || pad16('81 02 CA FE').
        use crate::core::aes_primitives::aes_cmac_truncated;
        let header = [0x8C, Ins::PIN_CHANGE_UNBLOCK.0, 0x00, 0x03];
        let mut mac_input = chain.to_vec();
        mac_input.extend(pad_iso9797_method2(&header, 16));
        mac_input.extend(pad_iso9797_method2(&[0x81, 0x02, 0xCA, 0xFE], 16));
        let expected = aes_cmac_truncated(&sk_mac, &mac_input, 8).unwrap();
        assert_eq!(&cmd.data[cmd.data.len() - 8..], &expected[..]);
    }

    #[test]
    fn mac_chaining_aes_subsequent_uses_previous_full_cmac() {
        // For AES the "previous MAC" is the **full 16-byte** CMAC
        // before truncation. Use mac_length 8 for transmission, but
        // the 16-byte full CMAC chains forward.
        let sk_mac = [0x44u8; 16];
        let ac = [0xAAu8; 8];
        let mut chain1 = [0u8; 16];
        chain1[..8].copy_from_slice(&ac);

        let cmd1 = wrap_format_1_integrity_only_aes(
            Ins::PIN_CHANGE_UNBLOCK,
            0,
            0x03,
            &[0xDE, 0xAD],
            false,
            &sk_mac,
            8,
            Some(&chain1),
        )
        .unwrap();
        // Recompute the *full* 16-byte CMAC of cmd1 to use as the
        // next chain value.
        use crate::core::aes_primitives::aes_cmac;
        let header1 = [0x8C, Ins::PIN_CHANGE_UNBLOCK.0, 0x00, 0x03];
        let mut mi1 = chain1.to_vec();
        mi1.extend(pad_iso9797_method2(&header1, 16));
        mi1.extend(pad_iso9797_method2(&[0x81, 0x02, 0xDE, 0xAD], 16));
        let full_cmac1 = aes_cmac(&sk_mac, &mi1).unwrap();

        // Sanity: the wire-truncated MAC matches the leftmost 8 of the
        // full CMAC.
        assert_eq!(&cmd1.data[cmd1.data.len() - 8..], &full_cmac1[..8]);

        let cmd2 = wrap_format_1_integrity_only_aes(
            Ins::APPLICATION_BLOCK,
            0,
            0,
            &[],
            false,
            &sk_mac,
            8,
            Some(&full_cmac1),
        )
        .unwrap();
        let header2 = [0x8C, Ins::APPLICATION_BLOCK.0, 0x00, 0x00];
        let mut mi2 = full_cmac1.to_vec();
        mi2.extend(pad_iso9797_method2(&header2, 16));
        let expected2 = crate::core::aes_primitives::aes_cmac_truncated(&sk_mac, &mi2, 8).unwrap();
        assert_eq!(&cmd2.data[cmd2.data.len() - 8..], &expected2[..]);
    }

    #[test]
    fn mac_chaining_threads_through_confidentiality() {
        // The chain-value path must work for the confidentiality
        // composer too - it's the same MAC input shape, just with
        // a '87' object instead of '81'.
        let sk_enc = [0x11; 16];
        let sk_mac = [0x22; 16];
        let ac = [0xAAu8; 8];
        let plaintext = [0x24u8, 0x12, 0x34, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF];

        let no_chain = wrap_format_1_with_confidentiality(
            Ins::PIN_CHANGE_UNBLOCK,
            0,
            0x01,
            &plaintext,
            false,
            &sk_enc,
            &sk_mac,
            8,
            None,
        )
        .unwrap();
        let with_chain = wrap_format_1_with_confidentiality(
            Ins::PIN_CHANGE_UNBLOCK,
            0,
            0x01,
            &plaintext,
            false,
            &sk_enc,
            &sk_mac,
            8,
            Some(&ac),
        )
        .unwrap();
        // Cipher region (bytes 3..19) unchanged - chain value only
        // affects the MAC.
        assert_eq!(&no_chain.data[..19], &with_chain.data[..19]);
        // MAC region (last 8 bytes) differs.
        assert_ne!(&no_chain.data[19..], &with_chain.data[19..]);
    }

    // ── D2 / §9 structural conformance ───────────────────────────────

    #[test]
    fn d2_data_object_tags_are_odd() {
        // §9.3.1.1 + D2 Note 2: an odd-numbered tag means the data
        // object is included in MAC computation. Both '81' and '87'
        // must satisfy this.
        assert_eq!(0x81 & 1, 1);
        assert_eq!(0x87 & 1, 1);
    }

    #[test]
    fn d2_cla_flip_x0_to_xc_preserves_high_nibble() {
        // §D2.1: unsecured CLA = 'X0' → secured CLA = 'XC'. Verify
        // for the standard EMV inter-industry CLA 0x80 (→ 0x8C) and
        // for the chained variant (→ 0x9C). The mode wrapper enforces
        // the high nibble convention.
        let cla_unchained = SecureMessagingMode::Iso7816HeaderAuthenticated.cla_byte(false);
        let cla_chained = SecureMessagingMode::Iso7816HeaderAuthenticated.cla_byte(true);
        assert_eq!(cla_unchained & 0x0F, 0x0C);
        assert_eq!(cla_chained & 0x0F, 0x0C);
        // Chaining bit is bit 4 (0x10).
        assert_eq!(cla_chained & 0x10, 0x10);
        assert_eq!(cla_unchained & 0x10, 0x00);
    }

    #[test]
    fn d2_padding_indicator_is_always_01_for_tag_87() {
        // §9.3.1.1 + D2.1.2 Note: for tag '87', value field starts
        // with the padding indicator byte. ISO/IEC 7816-4 padding
        // (Method 2 = '80' followed by zeros) corresponds to
        // indicator '01'. Spot-check across both block sizes.
        let plaintext = [0x42u8; 4];
        let tdes = wrap_format_1_with_confidentiality(
            Ins::PIN_CHANGE_UNBLOCK,
            0,
            1,
            &plaintext,
            false,
            &[0x11; 16],
            &[0x22; 16],
            8,
            None,
        )
        .unwrap();
        let aes = wrap_format_1_with_confidentiality_aes(
            Ins::PIN_CHANGE_UNBLOCK,
            0,
            1,
            &plaintext,
            false,
            &[0x11u8; 16][..],
            &[0x22u8; 16][..],
            8,
            None,
        )
        .unwrap();
        // First three bytes = '87' L '01'.
        assert_eq!(tdes.data[0], 0x87);
        assert_eq!(tdes.data[2], 0x01);
        assert_eq!(aes.data[0], 0x87);
        assert_eq!(aes.data[2], 0x01);
    }

    #[test]
    fn d2_new_lc_bounds_match_spec() {
        // §D2.1.1: with 1-byte L encoding, New Lc = 8+Lc to 12+Lc
        // depending on MAC length. Verify across mac_length 4..=8
        // for an arbitrary 4-byte unsecured data field.
        let sk_mac = [0xAA; 16];
        let lc = 4usize;
        for mac_len in 4..=8 {
            let cmd = wrap_format_1_integrity_only(
                Ins::PIN_CHANGE_UNBLOCK,
                0,
                0x03,
                &[0u8; 4],
                false,
                &sk_mac,
                mac_len,
                None,
            )
            .unwrap();
            let new_lc = cmd.data.len();
            // 81 LL data 8E LL MAC = 2 + lc + 2 + mac_len = 4 + lc + mac_len.
            assert_eq!(new_lc, 4 + lc + mac_len);
            // Spec range for 1-byte L: [8+lc, 12+lc].
            assert!(
                new_lc >= 8 + lc - 4 && new_lc <= 12 + lc,
                "new_lc={}",
                new_lc
            );
        }
    }

    #[test]
    fn d2_no_data_command_secured_data_is_only_mac_object() {
        // §D2.1.1 last paragraph: no command data → secured data is
        // just '8E LL MAC'. New Lc = 6..=10 (LL + MAC: 2 + 4..8).
        let sk_mac = [0u8; 16];
        for mac_len in 4..=8 {
            let cmd = wrap_format_1_integrity_only(
                Ins::APPLICATION_BLOCK,
                0,
                0,
                &[],
                false,
                &sk_mac,
                mac_len,
                None,
            )
            .unwrap();
            assert_eq!(cmd.data[0], 0x8E);
            assert_eq!(cmd.data[1] as usize, mac_len);
            assert_eq!(cmd.data.len(), 2 + mac_len);
            assert!((6..=10).contains(&cmd.data.len()));
        }
    }
}
