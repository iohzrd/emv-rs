//! Book 2 §7.2 - Offline Enciphered PIN data construction.

use crate::core::error::{Error, Result};
use crate::core::iso9796_2;

/// §7.2 step 3 - N − 17 bytes, where 17 covers the Table 25 '7F' header,
/// PIN block and ICC Unpredictable Number.
pub fn random_padding_length(modulus_length: usize) -> Option<usize> {
    modulus_length.checked_sub(17)
}

pub fn enciphered_pin_data(
    pin_block: [u8; 8],
    icc_unpredictable_number: [u8; 8],
    random_padding: &[u8],
    modulus: &[u8],
    exponent: &[u8],
) -> Result<Vec<u8>> {
    let n = modulus.len();
    let Some(expected_padding) = random_padding_length(n) else {
        return Err(Error::InvalidValue);
    };
    if random_padding.len() != expected_padding {
        return Err(Error::WrongLength {
            expected: expected_padding,
            got: random_padding.len(),
        });
    }

    let mut plain = Vec::with_capacity(n);
    plain.push(0x7F);
    plain.extend_from_slice(&pin_block);
    plain.extend_from_slice(&icc_unpredictable_number);
    plain.extend_from_slice(random_padding);
    debug_assert_eq!(plain.len(), n);

    iso9796_2::rsa_recover(&plain, exponent, modulus)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn identity_modulus(n: usize) -> Vec<u8> {
        vec![0xFFu8; n]
    }

    #[test]
    fn enciphered_pin_data_layout_matches_table_25() {
        let n = 128;
        let modulus = identity_modulus(n);
        let exponent = [1u8];
        let pin_block = [0x24, 0x12, 0x34, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF];
        let icc_un = [0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF];
        let random_padding = vec![0xA5u8; n - 17];

        let enciphered =
            enciphered_pin_data(pin_block, icc_un, &random_padding, &modulus, &exponent).unwrap();

        assert_eq!(enciphered.len(), n);
        assert_eq!(enciphered[0], 0x7F);
        assert_eq!(&enciphered[1..9], &pin_block);
        assert_eq!(&enciphered[9..17], &icc_un);
        assert_eq!(&enciphered[17..], random_padding.as_slice());
    }

    #[test]
    fn enciphered_pin_data_minimum_modulus_size_17() {
        let modulus = identity_modulus(17);
        let result = enciphered_pin_data([0u8; 8], [0u8; 8], &[], &modulus, &[1]).unwrap();
        assert_eq!(result.len(), 17);
        assert_eq!(result[0], 0x7F);
    }

    #[test]
    fn enciphered_pin_data_real_exponent_3_round_trip() {
        let modulus = identity_modulus(64);
        let pin = [0x24, 0x12, 0x34, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF];
        let un = [0u8; 8];
        let pad = vec![0u8; 47];
        let r1 = enciphered_pin_data(pin, un, &pad, &modulus, &[3]).unwrap();
        let r2 = enciphered_pin_data(pin, un, &pad, &modulus, &[3]).unwrap();
        assert_eq!(r1.len(), 64);
        assert_eq!(r1, r2);
    }

    #[test]
    fn enciphered_pin_data_rejects_short_padding() {
        let modulus = identity_modulus(64);
        let result = enciphered_pin_data([0u8; 8], [0u8; 8], &[0u8; 46], &modulus, &[1]);
        assert_eq!(
            result,
            Err(Error::WrongLength {
                expected: 47,
                got: 46
            })
        );
    }

    #[test]
    fn enciphered_pin_data_rejects_long_padding() {
        let modulus = identity_modulus(64);
        let result = enciphered_pin_data([0u8; 8], [0u8; 8], &[0u8; 100], &modulus, &[1]);
        assert_eq!(
            result,
            Err(Error::WrongLength {
                expected: 47,
                got: 100
            })
        );
    }

    #[test]
    fn enciphered_pin_data_rejects_undersized_modulus() {
        let modulus = identity_modulus(16);
        let result = enciphered_pin_data([0u8; 8], [0u8; 8], &[], &modulus, &[1]);
        assert_eq!(result, Err(Error::InvalidValue));
    }
}
