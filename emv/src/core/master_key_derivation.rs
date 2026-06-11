//! Book 2 §A1.4 - Master Key Derivation.

use crate::core::aes_primitives::aes_encrypt_block;
use crate::core::error::{Error, Result};
use crate::core::secure_messaging::tdes_encrypt_block;
use sha1::{Digest, Sha1};

/// Derive the ICC Master Key per Book 2 §A1.4.1 - Option A.
///
/// Applicable when the underlying block cipher is Triple-DES. The
/// spec restricts Option A to PANs of at most 16 digits, but the
/// algorithm itself works for any length (when PAN || PSN exceeds 16
/// digits the rightmost 16 are taken). For PANs longer than 16
/// digits the issuer should prefer [`derive_master_key_option_b`].
pub fn derive_master_key_option_a(imk: &[u8; 16], pan: &[u8], psn: Option<u8>) -> Result<[u8; 16]> {
    let pan_digits = decode_pan_digits(pan)?;
    let psn_digits = psn_to_digits(psn)?;

    let mut x = Vec::with_capacity(pan_digits.len() + 2);
    x.extend_from_slice(&pan_digits);
    x.extend_from_slice(&psn_digits);

    let y_nibbles = build_y_nibbles_option_a(&x);
    let y = pack_8byte_y(&y_nibbles);
    Ok(finalise_master_key_tdes(imk, y))
}

/// Derive the ICC Master Key per Book 2 §A1.4.2 - Option B.
///
/// Applicable when the underlying block cipher is Triple-DES. Per
/// the §A1.4.2 preamble, this function delegates to
/// [`derive_master_key_option_a`] when the PAN has 16 or fewer
/// decimal digits - making it a safe default for any PAN length.
pub fn derive_master_key_option_b(imk: &[u8; 16], pan: &[u8], psn: Option<u8>) -> Result<[u8; 16]> {
    let pan_digits = decode_pan_digits(pan)?;
    if pan_digits.len() <= 16 {
        return derive_master_key_option_a(imk, pan, psn);
    }
    let psn_digits = psn_to_digits(psn)?;

    // Step 1: build the digit string, prepending '0' if PAN length is
    // odd so that the result is BCD-packable into whole bytes.
    let mut concat = Vec::with_capacity(pan_digits.len() + 3);
    if !pan_digits.len().is_multiple_of(2) {
        concat.push(0);
    }
    concat.extend_from_slice(&pan_digits);
    concat.extend_from_slice(&psn_digits);
    debug_assert!(concat.len().is_multiple_of(2));

    let bcd = pack_bcd(&concat);

    // Step 2: SHA-1.
    let mut hasher = Sha1::new();
    hasher.update(&bcd);
    let hash: [u8; 20] = hasher.finalize().into();

    // Step 3: decimalize 16 nibbles out of the hash.
    let y_nibbles = decimalize_hash_to_y_nibbles(&hash);

    // Step 4: continue with Option A from step 2.
    let y = pack_8byte_y(&y_nibbles);
    Ok(finalise_master_key_tdes(imk, y))
}

/// Derive the ICC Master Key per Book 2 §A1.4.3 - Option C (AES).
///
/// Applicable when the underlying block cipher is AES. The IMK length
/// determines the variant: 16 → AES-128, 24 → AES-192, 32 → AES-256.
///
/// Per §A1.4.3:
///
/// 1. Concatenate decimal digits of PAN with PSN (`'00'` if absent),
///    pad LEFT with hexadecimal zeros to obtain a 16-byte `Y` in BCD
///    numeric format.
/// 2. If `k = 8n` (AES-128): `MK = AES(IMK)[Y]`.
/// 3. If `16n ≥ k > 8n` (AES-192/256): `MK = leftmost k bits of
///    {AES(IMK)[Y] || AES(IMK)[Y*]}` where `Y* = Y ⊕ FF×16` (a
///    bit-wise inversion of `Y`).
///
/// Returns the derived MK as a `Vec<u8>` of length matching `imk.len()`.
///
/// Errors:
///
/// - `InvalidValue` if `imk.len()` is not 16, 24, or 32.
/// - `InvalidValue` if PAN || PSN exceeds 32 decimal digits (the
///   `Y` capacity); a valid 19-digit PAN plus 2-digit PSN comfortably
///   fits, so this only fails on malformed input.
/// - PAN / PSN decoding errors as in [`derive_master_key_option_a`].
pub fn derive_master_key_option_c(imk: &[u8], pan: &[u8], psn: Option<u8>) -> Result<Vec<u8>> {
    if !matches!(imk.len(), 16 | 24 | 32) {
        return Err(Error::InvalidValue);
    }
    let pan_digits = decode_pan_digits(pan)?;
    let psn_digits = psn_to_digits(psn)?;

    let total_digits = pan_digits.len() + 2;
    if total_digits > 32 {
        return Err(Error::InvalidValue);
    }
    let mut y_nibbles = [0u8; 32];
    let pad = 32 - total_digits;
    y_nibbles[pad..pad + pan_digits.len()].copy_from_slice(&pan_digits);
    y_nibbles[pad + pan_digits.len()..].copy_from_slice(&psn_digits);

    let mut y = [0u8; 16];
    for i in 0..16 {
        y[i] = (y_nibbles[2 * i] << 4) | y_nibbles[2 * i + 1];
    }

    if imk.len() == 16 {
        let mk = aes_encrypt_block(imk, y)?;
        return Ok(mk.to_vec());
    }

    // AES-192 / AES-256: dual-block with Y* = Y ⊕ FF×16.
    let mut y_star = [0u8; 16];
    for i in 0..16 {
        y_star[i] = y[i] ^ 0xFF;
    }
    let b1 = aes_encrypt_block(imk, y)?;
    let b2 = aes_encrypt_block(imk, y_star)?;
    let mut mk = Vec::with_capacity(32);
    mk.extend_from_slice(&b1);
    mk.extend_from_slice(&b2);
    mk.truncate(imk.len());
    Ok(mk)
}

// ── helpers ──────────────────────────────────────────────────────────

/// Force odd parity on a single byte: set bit 0 (`0x01`) so the total
/// number of `1` bits in the byte is odd. DES ignores the LSB but the
/// convention encoded into §A1.4 final-step ("…each of the 16 bytes
/// of MK has an odd number of nonzero bits…") is to set it.
fn force_odd_parity_byte(b: u8) -> u8 {
    let high7_ones = (b & 0xFE).count_ones();
    if high7_ones.is_multiple_of(2) {
        (b & 0xFE) | 0x01
    } else {
        b & 0xFE
    }
}

/// Run the §A1.4.1 step-2 tail: `Z_L = TDES(IMK)[Y]`,
/// `Z_R = TDES(IMK)[Y ⊕ 'FF'×8]`, then odd-parity-adjust.
fn finalise_master_key_tdes(imk: &[u8; 16], y: [u8; 8]) -> [u8; 16] {
    let z_l = tdes_encrypt_block(imk, y);
    let mut y_inv = [0u8; 8];
    for i in 0..8 {
        y_inv[i] = y[i] ^ 0xFF;
    }
    let z_r = tdes_encrypt_block(imk, y_inv);

    let mut mk = [0u8; 16];
    mk[..8].copy_from_slice(&z_l);
    mk[8..].copy_from_slice(&z_r);
    for b in &mut mk {
        *b = force_odd_parity_byte(*b);
    }
    mk
}

/// Strip trailing `'F'` nibbles from a BCD-encoded PAN and return the
/// digit values (0-9). Returns `InvalidValue` if a non-decimal nibble
/// appears before the padding, or if a digit follows a `'F'` nibble
/// (interleaved padding is not valid for `cn` format).
fn decode_pan_digits(pan: &[u8]) -> Result<Vec<u8>> {
    let mut digits = Vec::with_capacity(pan.len() * 2);
    let mut padding_started = false;
    for &b in pan {
        for nibble in [b >> 4, b & 0x0F] {
            if nibble == 0xF {
                padding_started = true;
            } else if nibble <= 9 {
                if padding_started {
                    return Err(Error::InvalidValue);
                }
                digits.push(nibble);
            } else {
                return Err(Error::InvalidValue);
            }
        }
    }
    Ok(digits)
}

/// Decode the two PSN digits from the optional 1-byte PSN. Per the
/// §A1.4 preamble, an absent PSN is treated as a `'00'` byte → digits
/// `[0, 0]`. Errors if either nibble is non-decimal (PSN per tag
/// `'5F34'` is `n 2` - exactly two decimal digits, no `'F'` padding).
fn psn_to_digits(psn: Option<u8>) -> Result<[u8; 2]> {
    let b = psn.unwrap_or(0x00);
    let hi = b >> 4;
    let lo = b & 0x0F;
    if hi > 9 || lo > 9 {
        return Err(Error::InvalidValue);
    }
    Ok([hi, lo])
}

/// Build the 16-nibble `Y` for Option A from the digit string `X`:
/// pad-left with `'0'` digits if `X.len() < 16`, take rightmost 16 if
/// `X.len() > 16`.
fn build_y_nibbles_option_a(x: &[u8]) -> [u8; 16] {
    let mut y = [0u8; 16];
    match x.len().cmp(&16) {
        std::cmp::Ordering::Less => {
            let pad = 16 - x.len();
            y[pad..].copy_from_slice(x);
        }
        std::cmp::Ordering::Equal => {
            y.copy_from_slice(x);
        }
        std::cmp::Ordering::Greater => {
            y.copy_from_slice(&x[x.len() - 16..]);
        }
    }
    y
}

/// Decimalize the 20-byte SHA-1 hash `X` into a 16-digit `Y` per
/// §A1.4.2 step 3:
///
/// 1. Scan `X` left-to-right; collect decimal nibbles (`0`-`9`) into
///    `Y` until `Y.len() == 16`.
/// 2. If still short, scan again; convert non-decimal nibbles
///    (`A`-`F`) via the table `A→0, B→1, ..., F→5` and append until
///    `Y.len() == 16`.
fn decimalize_hash_to_y_nibbles(hash: &[u8; 20]) -> [u8; 16] {
    let mut y = Vec::with_capacity(16);
    // First pass: decimal nibbles.
    'outer: for &b in hash {
        for nibble in [b >> 4, b & 0x0F] {
            if y.len() == 16 {
                break 'outer;
            }
            if nibble <= 9 {
                y.push(nibble);
            }
        }
    }
    // Second pass: decimalized non-decimal nibbles.
    if y.len() < 16 {
        'outer: for &b in hash {
            for nibble in [b >> 4, b & 0x0F] {
                if y.len() == 16 {
                    break 'outer;
                }
                if nibble > 9 {
                    y.push(nibble - 0xA);
                }
            }
        }
    }
    debug_assert_eq!(y.len(), 16);
    y.try_into().unwrap()
}

/// BCD-pack a digit string of even length: every two consecutive
/// digits become one byte (`hi << 4 | lo`).
fn pack_bcd(digits: &[u8]) -> Vec<u8> {
    debug_assert!(digits.len().is_multiple_of(2));
    digits.chunks_exact(2).map(|c| (c[0] << 4) | c[1]).collect()
}

/// Pack a 16-nibble `Y` into 8 BCD-encoded bytes.
fn pack_8byte_y(y_nibbles: &[u8; 16]) -> [u8; 8] {
    let mut y = [0u8; 8];
    for i in 0..8 {
        y[i] = (y_nibbles[2 * i] << 4) | y_nibbles[2 * i + 1];
    }
    y
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── force_odd_parity_byte ────────────────────────────────────────

    #[test]
    fn parity_already_odd_clears_lsb() {
        // 0b00000001 = 1 one bit (odd). Result should clear the LSB
        // (since that LSB IS the parity bit) and end up at 0b00000000
        // ... wait that's even. Let me reconsider.
        // 0x01 = 0b00000001: top 7 bits = 0b0000000 = 0 ones (even).
        // We need total to be odd; LSB = 1 → total = 1. OK keep LSB.
        assert_eq!(force_odd_parity_byte(0x01), 0x01);
    }

    #[test]
    fn parity_top7_even_sets_lsb() {
        // 0xAA = 0b10101010 = top 7 bits 0b1010101 = 4 ones (even).
        // Need total odd → set LSB → 0xAB.
        assert_eq!(force_odd_parity_byte(0xAA), 0xAB);
    }

    #[test]
    fn parity_top7_odd_clears_lsb() {
        // 0xAB = top 7 bits 0b1010101 = 4 ones (even).
        // Wait, 0xAB = 0b10101011, top 7 = 0b1010101, 4 ones (even).
        // Same as 0xAA. So LSB stays 1.
        assert_eq!(force_odd_parity_byte(0xAB), 0xAB);
        // 0xAC = 0b10101100, top 7 = 0b1010110, 4 ones (even).
        // Need LSB = 1 → 0xAD.
        assert_eq!(force_odd_parity_byte(0xAC), 0xAD);
        // 0x80 = top 7 bits 0b1000000 = 1 one (odd). LSB cleared → 0x80.
        assert_eq!(force_odd_parity_byte(0x80), 0x80);
        // 0x81 = top 7 bits = 1 one (odd). Clear LSB → 0x80.
        assert_eq!(force_odd_parity_byte(0x81), 0x80);
    }

    #[test]
    fn parity_all_zeros_sets_lsb() {
        // 0x00: top 7 = 0 ones (even). LSB = 1 → 0x01.
        assert_eq!(force_odd_parity_byte(0x00), 0x01);
    }

    #[test]
    fn parity_all_ones_clears_lsb() {
        // 0xFF: top 7 = 7 ones (odd). LSB = 0 → 0xFE.
        assert_eq!(force_odd_parity_byte(0xFF), 0xFE);
    }

    #[test]
    fn parity_makes_each_byte_odd() {
        for b in 0u8..=255 {
            let p = force_odd_parity_byte(b);
            assert!(!p.count_ones().is_multiple_of(2), "byte {:#04x}", p);
        }
    }

    // ── decode_pan_digits ────────────────────────────────────────────

    #[test]
    fn decode_pan_digits_typical_19_digit_pan() {
        // 19-digit PAN: 1234 5678 9012 3456 789, F-padded to 10 bytes.
        let pan = [0x12, 0x34, 0x56, 0x78, 0x90, 0x12, 0x34, 0x56, 0x78, 0x9F];
        let digits = decode_pan_digits(&pan).unwrap();
        assert_eq!(
            digits,
            vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
        );
    }

    #[test]
    fn decode_pan_digits_16_digit_pan_no_padding() {
        let pan = [0x12, 0x34, 0x56, 0x78, 0x90, 0x12, 0x34, 0x56];
        let digits = decode_pan_digits(&pan).unwrap();
        assert_eq!(digits.len(), 16);
    }

    #[test]
    fn decode_pan_digits_rejects_digit_after_padding() {
        let pan = [0x12, 0xF3]; // F in the middle, then digit - invalid.
        assert_eq!(decode_pan_digits(&pan), Err(Error::InvalidValue));
    }

    #[test]
    fn decode_pan_digits_rejects_non_decimal_nibble() {
        let pan = [0x12, 0xA3]; // A is not a decimal digit and not F.
        assert_eq!(decode_pan_digits(&pan), Err(Error::InvalidValue));
    }

    // ── psn_to_digits ────────────────────────────────────────────────

    #[test]
    fn psn_none_yields_zero_zero() {
        assert_eq!(psn_to_digits(None).unwrap(), [0, 0]);
    }

    #[test]
    fn psn_byte_decoded_as_two_digits() {
        assert_eq!(psn_to_digits(Some(0x42)).unwrap(), [4, 2]);
        assert_eq!(psn_to_digits(Some(0x07)).unwrap(), [0, 7]);
        assert_eq!(psn_to_digits(Some(0x99)).unwrap(), [9, 9]);
    }

    #[test]
    fn psn_rejects_non_decimal_nibble() {
        assert_eq!(psn_to_digits(Some(0xA0)), Err(Error::InvalidValue));
        assert_eq!(psn_to_digits(Some(0x0A)), Err(Error::InvalidValue));
        assert_eq!(psn_to_digits(Some(0xFF)), Err(Error::InvalidValue));
    }

    // ── decimalize_hash_to_y_nibbles ─────────────────────────────────

    #[test]
    fn decimalize_spec_example_2() {
        // From §A1.4.2 Example 2:
        //   X = '1B 3C AB CD D6 E8 FA D4 B1 CD F2 CA D4 FD C7 8F A1 7B 6E BB'
        //   Y = '13 68 41 24 78 17 61 20'
        let x: [u8; 20] = [
            0x1B, 0x3C, 0xAB, 0xCD, 0xD6, 0xE8, 0xFA, 0xD4, 0xB1, 0xCD, 0xF2, 0xCA, 0xD4, 0xFD,
            0xC7, 0x8F, 0xA1, 0x7B, 0x6E, 0xBB,
        ];
        let y_nibbles = decimalize_hash_to_y_nibbles(&x);
        assert_eq!(y_nibbles, [1, 3, 6, 8, 4, 1, 2, 4, 7, 8, 1, 7, 6, 1, 2, 0],);
        let y = pack_8byte_y(&y_nibbles);
        assert_eq!(y, [0x13, 0x68, 0x41, 0x24, 0x78, 0x17, 0x61, 0x20],);
    }

    #[test]
    fn decimalize_spec_example_1_takes_first_16_decimals() {
        // From §A1.4.2 Example 1:
        //   X contains 16+ decimal digits, no decimalisation needed.
        //   X = '12 30 AB CD 56 78 42 D4 B1 79 F2 CA 34 5D 67 89 A1 7B 64 BB'
        //   Y = '12 30 56 78 42 41 79 23'
        // Decimal nibbles in order: 1,2,3,0,5,6,7,8,4,2,4,1,7,9,2,3,4,5,6,7,8,9,1,7,6,4
        // First 16: 1,2,3,0,5,6,7,8,4,2,4,1,7,9,2,3
        let x: [u8; 20] = [
            0x12, 0x30, 0xAB, 0xCD, 0x56, 0x78, 0x42, 0xD4, 0xB1, 0x79, 0xF2, 0xCA, 0x34, 0x5D,
            0x67, 0x89, 0xA1, 0x7B, 0x64, 0xBB,
        ];
        let y_nibbles = decimalize_hash_to_y_nibbles(&x);
        assert_eq!(y_nibbles, [1, 2, 3, 0, 5, 6, 7, 8, 4, 2, 4, 1, 7, 9, 2, 3],);
    }

    // ── build_y_nibbles_option_a ─────────────────────────────────────

    #[test]
    fn option_a_y_pads_left_when_x_short() {
        // X = "12345" (5 digits) → Y = "00000000000" + "12345" = 16
        // digits with 11 leading zeros.
        let y = build_y_nibbles_option_a(&[1, 2, 3, 4, 5]);
        assert_eq!(y, [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 2, 3, 4, 5],);
    }

    #[test]
    fn option_a_y_takes_rightmost_when_x_long() {
        // X = 18 digits → Y = rightmost 16.
        let x: Vec<u8> = (0..18).map(|i| (i % 10) as u8).collect();
        let y = build_y_nibbles_option_a(&x);
        assert_eq!(y, &x[2..]);
    }

    #[test]
    fn option_a_y_unchanged_when_x_exactly_16() {
        let x: Vec<u8> = (0..16).map(|i| (i % 10) as u8).collect();
        let y = build_y_nibbles_option_a(&x);
        assert_eq!(&y[..], &x[..]);
    }

    // ── derive_master_key_option_a ───────────────────────────────────

    #[test]
    fn option_a_pan_below_16_pads_with_zeros() {
        // 13-digit PAN (legacy short PAN), PSN = '00'.
        // Y = "0" + "1234567890123" + "00" = "0123456789012300"
        // packed = 01 23 45 67 89 01 23 00.
        let pan = [0x12, 0x34, 0x56, 0x78, 0x90, 0x12, 0x3F]; // 13 digits + F
        let imk = [0xAA; 16];
        let mk = derive_master_key_option_a(&imk, &pan, None).unwrap();

        let expected_y = [0x01, 0x23, 0x45, 0x67, 0x89, 0x01, 0x23, 0x00];
        let expected_mk = finalise_master_key_tdes(&imk, expected_y);
        assert_eq!(mk, expected_mk);
    }

    #[test]
    fn option_a_pan_16_with_psn_takes_rightmost_16() {
        // 16-digit PAN + 2 PSN digits = 18 → take rightmost 16.
        // PAN digits: 1234567890123456
        // PSN = 0x05 → 0,5
        // X = "1234567890123456" + "05" = "123456789012345605"
        // Y = rightmost 16 = "3456789012345605".
        let pan = [0x12, 0x34, 0x56, 0x78, 0x90, 0x12, 0x34, 0x56];
        let imk = [0x42; 16];
        let mk = derive_master_key_option_a(&imk, &pan, Some(0x05)).unwrap();

        let expected_y = [0x34, 0x56, 0x78, 0x90, 0x12, 0x34, 0x56, 0x05];
        let expected_mk = finalise_master_key_tdes(&imk, expected_y);
        assert_eq!(mk, expected_mk);
    }

    #[test]
    fn option_a_psn_changes_master_key() {
        let pan = [0x12, 0x34, 0x56, 0x78, 0x9F]; // 9-digit PAN
        let imk = [0xAA; 16];
        let mk_none = derive_master_key_option_a(&imk, &pan, None).unwrap();
        let mk_one = derive_master_key_option_a(&imk, &pan, Some(0x01)).unwrap();
        assert_ne!(mk_none, mk_one);
    }

    #[test]
    fn option_a_imk_changes_master_key() {
        let pan = [0x12, 0x34, 0x56, 0x78, 0x90, 0x12, 0x34, 0x56];
        let mk_a = derive_master_key_option_a(&[0xAA; 16], &pan, None).unwrap();
        let mk_b = derive_master_key_option_a(&[0x54; 16], &pan, None).unwrap();
        assert_ne!(mk_a, mk_b);
    }

    #[test]
    fn option_a_master_key_has_odd_parity_per_byte() {
        let pan = [0x12, 0x34, 0x56, 0x78, 0x90, 0x12, 0x34, 0x56];
        let mk = derive_master_key_option_a(&[0xAA; 16], &pan, Some(0x01)).unwrap();
        for &b in &mk {
            assert!(!b.count_ones().is_multiple_of(2), "byte {:#04x}", b);
        }
    }

    // ── derive_master_key_option_b ───────────────────────────────────

    #[test]
    fn option_b_pan_at_or_below_16_delegates_to_option_a() {
        // 16-digit PAN - Option B preamble says "use Option A".
        let pan = [0x12, 0x34, 0x56, 0x78, 0x90, 0x12, 0x34, 0x56];
        let imk = [0xAA; 16];
        let mk_a = derive_master_key_option_a(&imk, &pan, Some(0x01)).unwrap();
        let mk_b = derive_master_key_option_b(&imk, &pan, Some(0x01)).unwrap();
        assert_eq!(mk_a, mk_b);
    }

    #[test]
    fn option_b_pan_above_16_differs_from_option_a() {
        // 17-digit PAN. Option A would take the rightmost 16; Option
        // B hashes - outputs must differ.
        let pan = [0x12, 0x34, 0x56, 0x78, 0x90, 0x12, 0x34, 0x56, 0x7F];
        let imk = [0xAA; 16];
        let mk_a = derive_master_key_option_a(&imk, &pan, Some(0x01)).unwrap();
        let mk_b = derive_master_key_option_b(&imk, &pan, Some(0x01)).unwrap();
        assert_ne!(mk_a, mk_b);
    }

    #[test]
    fn option_b_pan_above_16_master_key_has_odd_parity() {
        let pan = [0x12, 0x34, 0x56, 0x78, 0x90, 0x12, 0x34, 0x56, 0x78, 0x9F]; // 19 digits
        let mk = derive_master_key_option_b(&[0xAA; 16], &pan, Some(0x01)).unwrap();
        for &b in &mk {
            assert!(!b.count_ones().is_multiple_of(2));
        }
    }

    #[test]
    fn option_b_pan_above_16_is_deterministic() {
        let pan = [0x12, 0x34, 0x56, 0x78, 0x90, 0x12, 0x34, 0x56, 0x78, 0x9F];
        let mk1 = derive_master_key_option_b(&[0xAA; 16], &pan, None).unwrap();
        let mk2 = derive_master_key_option_b(&[0xAA; 16], &pan, None).unwrap();
        assert_eq!(mk1, mk2);
    }

    #[test]
    fn option_b_odd_pan_length_prepends_zero_for_bcd_packing() {
        // 17-digit PAN (odd). The function's step-1 prepend-'0' logic
        // is exercised; we verify only that the function returns Ok
        // and is deterministic.
        let pan = [0x12, 0x34, 0x56, 0x78, 0x90, 0x12, 0x34, 0x56, 0x7F]; // 17 digits
        let mk = derive_master_key_option_b(&[0xAA; 16], &pan, Some(0x01)).unwrap();
        let mk2 = derive_master_key_option_b(&[0xAA; 16], &pan, Some(0x01)).unwrap();
        assert_eq!(mk, mk2);
    }

    // ── derive_master_key_option_c (AES) ─────────────────────────────

    /// Reproduce the §A1.4.3 step-1 BCD packing for Option C - used
    /// in tests to verify the master key against a manually computed
    /// AES block encrypt of `Y`.
    fn build_y_option_c(pan: &[u8], psn: Option<u8>) -> [u8; 16] {
        let pan_digits = decode_pan_digits(pan).unwrap();
        let psn_digits = psn_to_digits(psn).unwrap();
        let total = pan_digits.len() + 2;
        let mut y_nibbles = [0u8; 32];
        let pad = 32 - total;
        y_nibbles[pad..pad + pan_digits.len()].copy_from_slice(&pan_digits);
        y_nibbles[pad + pan_digits.len()..].copy_from_slice(&psn_digits);
        let mut y = [0u8; 16];
        for i in 0..16 {
            y[i] = (y_nibbles[2 * i] << 4) | y_nibbles[2 * i + 1];
        }
        y
    }

    #[test]
    fn option_c_pads_left_to_16_bytes() {
        // 16-digit PAN + 2 PSN = 18 digits → pad-left with 14 zero
        // nibbles (= 7 zero bytes) to reach 32 nibbles = 16 bytes.
        let pan = [0x12, 0x34, 0x56, 0x78, 0x90, 0x12, 0x34, 0x56];
        let y = build_y_option_c(&pan, Some(0x01));
        assert_eq!(
            y,
            [
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 7 zero bytes
                0x12, 0x34, 0x56, 0x78, 0x90, 0x12, 0x34, 0x56, 0x01,
            ],
        );
    }

    #[test]
    fn option_c_19_digit_pan_pad_correctly() {
        // 19-digit PAN + 2 PSN = 21 digits → 11 zero nibbles padding.
        let pan = [0x12, 0x34, 0x56, 0x78, 0x90, 0x12, 0x34, 0x56, 0x78, 0x9F];
        let y = build_y_option_c(&pan, None);
        // 11 zero nibbles = 5 zero bytes + half a byte. Hard to
        // visualise; verify by inverse: reading 32 nibbles, the
        // leading 11 should be zero, then 19 PAN digits, then 0, 0
        // for absent PSN.
        for nibble in [
            y[0] >> 4,
            y[0] & 0x0F,
            y[1] >> 4,
            y[1] & 0x0F,
            y[2] >> 4,
            y[2] & 0x0F,
            y[3] >> 4,
            y[3] & 0x0F,
            y[4] >> 4,
            y[4] & 0x0F,
            y[5] >> 4,
        ] {
            assert_eq!(nibble, 0);
        }
        // Next 19 nibbles should be 1,2,3,4,5,6,7,8,9,0,1,2,3,4,5,6,7,8,9.
        let nibble_at = |i: usize| -> u8 {
            if i.is_multiple_of(2) {
                y[i / 2] >> 4
            } else {
                y[i / 2] & 0x0F
            }
        };
        let pan_digits = [1u8, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9];
        for (i, &d) in pan_digits.iter().enumerate() {
            assert_eq!(nibble_at(11 + i), d);
        }
        // Last 2 nibbles = PSN '00'.
        assert_eq!(nibble_at(30), 0);
        assert_eq!(nibble_at(31), 0);
    }

    #[test]
    fn option_c_aes128_is_single_block_encrypt_of_y() {
        let pan = [0x12, 0x34, 0x56, 0x78, 0x90, 0x12, 0x34, 0x56];
        let imk = [0x42; 16];
        let y = build_y_option_c(&pan, Some(0x01));
        let expected = aes_encrypt_block(&imk, y).unwrap();
        let mk = derive_master_key_option_c(&imk, &pan, Some(0x01)).unwrap();
        assert_eq!(mk, expected.to_vec());
        assert_eq!(mk.len(), 16);
    }

    #[test]
    fn option_c_aes192_uses_y_and_y_inv() {
        let pan = [0x12, 0x34, 0x56, 0x78, 0x90, 0x12, 0x34, 0x56];
        let imk = [0x42; 24];
        let y = build_y_option_c(&pan, Some(0x01));
        let mut y_inv = [0u8; 16];
        for i in 0..16 {
            y_inv[i] = y[i] ^ 0xFF;
        }
        let b1 = aes_encrypt_block(&imk, y).unwrap();
        let b2 = aes_encrypt_block(&imk, y_inv).unwrap();
        let mut full = Vec::new();
        full.extend_from_slice(&b1);
        full.extend_from_slice(&b2);
        let mk = derive_master_key_option_c(&imk, &pan, Some(0x01)).unwrap();
        assert_eq!(mk, full[..24]);
        assert_eq!(mk.len(), 24);
    }

    #[test]
    fn option_c_aes256_returns_full_two_blocks() {
        let pan = [0x12, 0x34, 0x56, 0x78, 0x90, 0x12, 0x34, 0x56];
        let imk = [0x42; 32];
        let mk = derive_master_key_option_c(&imk, &pan, Some(0x01)).unwrap();
        assert_eq!(mk.len(), 32);
    }

    #[test]
    fn option_c_distinct_for_different_pan() {
        let imk = [0xAA; 16];
        let pan_a = [0x12, 0x34, 0x56, 0x78, 0x90, 0x12, 0x34, 0x56];
        let pan_b = [0x12, 0x34, 0x56, 0x78, 0x90, 0x12, 0x34, 0x57];
        assert_ne!(
            derive_master_key_option_c(&imk, &pan_a, None).unwrap(),
            derive_master_key_option_c(&imk, &pan_b, None).unwrap(),
        );
    }

    #[test]
    fn option_c_distinct_for_different_psn() {
        let imk = [0xAA; 16];
        let pan = [0x12, 0x34, 0x56, 0x78, 0x90, 0x12, 0x34, 0x56];
        assert_ne!(
            derive_master_key_option_c(&imk, &pan, None).unwrap(),
            derive_master_key_option_c(&imk, &pan, Some(0x01)).unwrap(),
        );
    }

    #[test]
    fn option_c_rejects_bad_imk_length() {
        let pan = [0x12, 0x34];
        assert_eq!(
            derive_master_key_option_c(&[0u8; 8], &pan, None),
            Err(Error::InvalidValue),
        );
        assert_eq!(
            derive_master_key_option_c(&[0u8; 17], &pan, None),
            Err(Error::InvalidValue),
        );
    }

    #[test]
    fn option_c_distinct_from_option_a_for_same_inputs() {
        // Option A and Option C use different algorithms (TDES vs AES)
        // and different Y constructions (8-byte vs 16-byte). Same
        // inputs must yield distinct keys.
        let pan = [0x12, 0x34, 0x56, 0x78, 0x90, 0x12, 0x34, 0x56];
        let key = [0xAA; 16];
        let mk_a = derive_master_key_option_a(&key, &pan, Some(0x01)).unwrap();
        let mk_c = derive_master_key_option_c(&key, &pan, Some(0x01)).unwrap();
        assert_ne!(&mk_a[..], &mk_c[..]);
    }

    // ── End-to-end with downstream session-key derivation ────────────

    #[test]
    fn end_to_end_imk_to_session_key_to_arqc() {
        use crate::core::application_cryptogram::application_cryptogram;
        use crate::core::secure_messaging::{
            derive_session_key_tdes, diversification_for_ac_session_key,
        };

        let imk = [
            0xAB, 0xCD, 0xEF, 0x01, 0x23, 0x45, 0x67, 0x89, 0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC,
            0xDE, 0xF0,
        ];
        let pan = [0x12, 0x34, 0x56, 0x78, 0x90, 0x12, 0x34, 0x56];
        let psn = Some(0x01);
        let atc: u16 = 0x0042;

        // (IMK, PAN, PSN) → MK_AC.
        let mk_ac = derive_master_key_option_a(&imk, &pan, psn).unwrap();
        // (MK_AC, ATC) → SK_AC.
        let r = diversification_for_ac_session_key(atc);
        let sk_ac = derive_session_key_tdes(&mk_ac, &r);
        // (SK_AC, selected_data) → ARQC.
        let selected_data = b"selected CDOL data";
        let arqc1 = application_cryptogram(&sk_ac, selected_data);

        // Re-derive on a different transaction (ATC = 0x0043) - must
        // produce a different ARQC.
        let r2 = diversification_for_ac_session_key(0x0043);
        let sk_ac2 = derive_session_key_tdes(&mk_ac, &r2);
        let arqc2 = application_cryptogram(&sk_ac2, selected_data);
        assert_ne!(arqc1, arqc2);

        // Re-derive with the same inputs - must be deterministic.
        let mk_ac_again = derive_master_key_option_a(&imk, &pan, psn).unwrap();
        assert_eq!(mk_ac, mk_ac_again);
    }

    #[test]
    fn end_to_end_aes_imk_to_session_key_to_arqc() {
        use crate::core::application_cryptogram::application_cryptogram_aes;
        use crate::core::secure_messaging::{
            derive_session_key_aes, diversification_for_ac_session_key_aes,
        };

        // AES-128 chain: IMK → MK → SK → AC.
        let imk = [0x55; 16];
        let pan = [0x12, 0x34, 0x56, 0x78, 0x90, 0x12, 0x34, 0x56];
        let psn = Some(0x01);
        let atc: u16 = 0x0042;

        let mk_ac = derive_master_key_option_c(&imk, &pan, psn).unwrap();
        let r = diversification_for_ac_session_key_aes(atc);
        let sk_ac = derive_session_key_aes(&mk_ac, &r).unwrap();
        let arqc1 = application_cryptogram_aes(&sk_ac, b"selected CDOL data").unwrap();

        // Different ATC ⇒ different SK ⇒ different ARQC.
        let r2 = diversification_for_ac_session_key_aes(0x0043);
        let sk_ac2 = derive_session_key_aes(&mk_ac, &r2).unwrap();
        let arqc2 = application_cryptogram_aes(&sk_ac2, b"selected CDOL data").unwrap();
        assert_ne!(arqc1, arqc2);

        // Deterministic.
        let mk_ac_again = derive_master_key_option_c(&imk, &pan, psn).unwrap();
        assert_eq!(mk_ac, mk_ac_again);
    }
}
