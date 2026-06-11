//! Book 2 §B1.2 / §A1.1 / §A1.2.2 - AES block, CBC, CMAC primitives.

use crate::core::error::{Error, Result};
use crate::core::secure_messaging::pad_iso9797_method2;
use aes::cipher::array::Array;
use aes::cipher::{BlockCipherDecrypt, BlockCipherEncrypt, KeyInit};
use aes::{Aes128, Aes192, Aes256};

const BLOCK_SIZE: usize = 16;

pub fn aes_encrypt_block(key: &[u8], block: [u8; BLOCK_SIZE]) -> Result<[u8; BLOCK_SIZE]> {
    let mut arr = Array::from(block);
    match key.len() {
        16 => Aes128::new_from_slice(key)
            .map_err(|_| Error::InvalidValue)?
            .encrypt_block(&mut arr),
        24 => Aes192::new_from_slice(key)
            .map_err(|_| Error::InvalidValue)?
            .encrypt_block(&mut arr),
        32 => Aes256::new_from_slice(key)
            .map_err(|_| Error::InvalidValue)?
            .encrypt_block(&mut arr),
        _ => return Err(Error::InvalidValue),
    }
    Ok(arr.into())
}

pub fn aes_decrypt_block(key: &[u8], block: [u8; BLOCK_SIZE]) -> Result<[u8; BLOCK_SIZE]> {
    let mut arr = Array::from(block);
    match key.len() {
        16 => Aes128::new_from_slice(key)
            .map_err(|_| Error::InvalidValue)?
            .decrypt_block(&mut arr),
        24 => Aes192::new_from_slice(key)
            .map_err(|_| Error::InvalidValue)?
            .decrypt_block(&mut arr),
        32 => Aes256::new_from_slice(key)
            .map_err(|_| Error::InvalidValue)?
            .decrypt_block(&mut arr),
        _ => return Err(Error::InvalidValue),
    }
    Ok(arr.into())
}

pub fn aes_cbc_encrypt(key: &[u8], iv: &[u8; BLOCK_SIZE], data: &[u8]) -> Result<Vec<u8>> {
    if !data.len().is_multiple_of(BLOCK_SIZE) {
        return Err(Error::InvalidValue);
    }
    let mut out = Vec::with_capacity(data.len());
    let mut chain = *iv;
    for chunk in data.chunks_exact(BLOCK_SIZE) {
        let mut block = [0u8; BLOCK_SIZE];
        for i in 0..BLOCK_SIZE {
            block[i] = chunk[i] ^ chain[i];
        }
        chain = aes_encrypt_block(key, block)?;
        out.extend_from_slice(&chain);
    }
    Ok(out)
}

pub fn aes_cbc_decrypt(key: &[u8], iv: &[u8; BLOCK_SIZE], data: &[u8]) -> Result<Vec<u8>> {
    if !data.len().is_multiple_of(BLOCK_SIZE) {
        return Err(Error::InvalidValue);
    }
    let mut out = Vec::with_capacity(data.len());
    let mut prev = *iv;
    for chunk in data.chunks_exact(BLOCK_SIZE) {
        let mut block = [0u8; BLOCK_SIZE];
        block.copy_from_slice(chunk);
        let dec = aes_decrypt_block(key, block)?;
        let mut plain = [0u8; BLOCK_SIZE];
        for i in 0..BLOCK_SIZE {
            plain[i] = dec[i] ^ prev[i];
        }
        out.extend_from_slice(&plain);
        prev = block;
    }
    Ok(out)
}

pub fn aes_cmac(key: &[u8], msg: &[u8]) -> Result<[u8; BLOCK_SIZE]> {
    // §A1.2.2 step 2.
    let l = aes_encrypt_block(key, [0u8; BLOCK_SIZE])?;
    let k1 = cmac_subkey(&l);
    let k2 = cmac_subkey(&k1);

    // §A1.2.2 step 1.
    let padding_added = msg.is_empty() || !msg.len().is_multiple_of(BLOCK_SIZE);
    let padded = if padding_added {
        pad_iso9797_method2(msg, BLOCK_SIZE)
    } else {
        msg.to_vec()
    };
    debug_assert!(padded.len().is_multiple_of(BLOCK_SIZE) && !padded.is_empty());

    // §A1.2.2 step 3.
    let mask = if padding_added { &k2 } else { &k1 };
    let final_offset = padded.len() - BLOCK_SIZE;

    let mut h = [0u8; BLOCK_SIZE];
    for (i, chunk) in padded.chunks_exact(BLOCK_SIZE).enumerate() {
        let mut x = [0u8; BLOCK_SIZE];
        for j in 0..BLOCK_SIZE {
            x[j] = chunk[j] ^ h[j];
        }
        if i * BLOCK_SIZE == final_offset {
            for j in 0..BLOCK_SIZE {
                x[j] ^= mask[j];
            }
        }
        h = aes_encrypt_block(key, x)?;
    }
    Ok(h)
}

pub fn aes_cmac_truncated(key: &[u8], msg: &[u8], s: usize) -> Result<Vec<u8>> {
    if !(4..=8).contains(&s) {
        return Err(Error::InvalidValue);
    }
    let full = aes_cmac(key, msg)?;
    Ok(full[..s].to_vec())
}

// ── helpers ──────────────────────────────────────────────────────────

fn cmac_subkey(input: &[u8; BLOCK_SIZE]) -> [u8; BLOCK_SIZE] {
    let msb = (input[0] & 0x80) != 0;
    let mut output = [0u8; BLOCK_SIZE];
    for i in 0..BLOCK_SIZE - 1 {
        output[i] = (input[i] << 1) | (input[i + 1] >> 7);
    }
    output[BLOCK_SIZE - 1] = input[BLOCK_SIZE - 1] << 1;
    if msb {
        output[BLOCK_SIZE - 1] ^= 0x87;
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h(s: &str) -> Vec<u8> {
        let cleaned: String = s.chars().filter(|c| !c.is_whitespace()).collect();
        (0..cleaned.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&cleaned[i..i + 2], 16).unwrap())
            .collect()
    }

    fn h16(s: &str) -> [u8; 16] {
        h(s).try_into().unwrap()
    }

    // ── AES block primitive (NIST FIPS-197 known-answer tests) ───────

    #[test]
    fn aes128_block_encrypt_known_answer() {
        let key = h("000102030405060708090a0b0c0d0e0f");
        let plain = h16("00112233445566778899aabbccddeeff");
        let expected = h16("69c4e0d86a7b0430d8cdb78070b4c55a");
        assert_eq!(aes_encrypt_block(&key, plain).unwrap(), expected);
    }

    #[test]
    fn aes128_block_round_trip() {
        let key = h("000102030405060708090a0b0c0d0e0f");
        let plain = h16("00112233445566778899aabbccddeeff");
        let ct = aes_encrypt_block(&key, plain).unwrap();
        let pt = aes_decrypt_block(&key, ct).unwrap();
        assert_eq!(pt, plain);
    }

    #[test]
    fn aes192_block_encrypt_known_answer() {
        let key = h("000102030405060708090a0b0c0d0e0f1011121314151617");
        let plain = h16("00112233445566778899aabbccddeeff");
        let expected = h16("dda97ca4864cdfe06eaf70a0ec0d7191");
        assert_eq!(aes_encrypt_block(&key, plain).unwrap(), expected);
    }

    #[test]
    fn aes256_block_encrypt_known_answer() {
        let key = h("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
        let plain = h16("00112233445566778899aabbccddeeff");
        let expected = h16("8ea2b7ca516745bfeafc49904b496089");
        assert_eq!(aes_encrypt_block(&key, plain).unwrap(), expected);
    }

    #[test]
    fn aes_block_rejects_bad_key_length() {
        for bad_len in [0usize, 1, 8, 15, 17, 23, 25, 31, 33, 64] {
            let key = vec![0u8; bad_len];
            assert_eq!(
                aes_encrypt_block(&key, [0; 16]),
                Err(Error::InvalidValue),
                "len={}",
                bad_len,
            );
            assert_eq!(
                aes_decrypt_block(&key, [0; 16]),
                Err(Error::InvalidValue),
                "len={}",
                bad_len,
            );
        }
    }

    // ── CBC ──────────────────────────────────────────────────────────

    #[test]
    fn aes128_cbc_known_answer_nist_sp800_38a() {
        let key = h("2b7e151628aed2a6abf7158809cf4f3c");
        let iv = h16("000102030405060708090a0b0c0d0e0f");
        let plain = h("6bc1bee22e409f96e93d7e117393172a\
             ae2d8a571e03ac9c9eb76fac45af8e51\
             30c81c46a35ce411e5fbc1191a0a52ef\
             f69f2445df4f9b17ad2b417be66c3710");
        let expected = h("7649abac8119b246cee98e9b12e9197d\
             5086cb9b507219ee95db113a917678b2\
             73bed6b8e3c1743b7116e69e22229516\
             3ff1caa1681fac09120eca307586e1a7");
        let ct = aes_cbc_encrypt(&key, &iv, &plain).unwrap();
        assert_eq!(ct, expected);
        let pt = aes_cbc_decrypt(&key, &iv, &ct).unwrap();
        assert_eq!(pt, plain);
    }

    #[test]
    fn aes_cbc_rejects_unaligned_data() {
        let key = [0u8; 16];
        let iv = [0u8; 16];
        let data = [0u8; 17];
        assert_eq!(aes_cbc_encrypt(&key, &iv, &data), Err(Error::InvalidValue),);
        assert_eq!(aes_cbc_decrypt(&key, &iv, &data), Err(Error::InvalidValue),);
    }

    // ── CMAC sub-key derivation ──────────────────────────────────────

    #[test]
    fn cmac_subkey_no_msb_is_pure_left_shift() {
        let input = h16("01000000000000000000000000000000");
        let expected = h16("02000000000000000000000000000000");
        assert_eq!(cmac_subkey(&input), expected);
    }

    #[test]
    fn cmac_subkey_msb_set_xors_in_0x87() {
        let input = h16("80000000000000000000000000000000");
        let expected = h16("00000000000000000000000000000087");
        assert_eq!(cmac_subkey(&input), expected);
    }

    #[test]
    fn cmac_subkey_carry_propagates_across_bytes() {
        let input = h16("00800000000000000000000000000000");
        let expected = h16("01000000000000000000000000000000");
        assert_eq!(cmac_subkey(&input), expected);
    }

    // ── CMAC test vectors (RFC 4493 §A.1, NIST CMAC suite) ───────────

    #[test]
    fn cmac_aes128_rfc4493_empty_message() {
        let key = h("2b7e151628aed2a6abf7158809cf4f3c");
        let expected = h16("bb1d6929e95937287fa37d129b756746");
        assert_eq!(aes_cmac(&key, &[]).unwrap(), expected);
    }

    #[test]
    fn cmac_aes128_rfc4493_one_block_padded() {
        let key = h("2b7e151628aed2a6abf7158809cf4f3c");
        let msg = h("6bc1bee22e409f96e93d7e117393172a");
        let expected = h16("070a16b46b4d4144f79bdd9dd04a287c");
        assert_eq!(aes_cmac(&key, &msg).unwrap(), expected);
    }

    #[test]
    fn cmac_aes128_rfc4493_partial_blocks_padded() {
        let key = h("2b7e151628aed2a6abf7158809cf4f3c");
        let msg = h("6bc1bee22e409f96e93d7e117393172a\
             ae2d8a571e03ac9c9eb76fac45af8e51\
             30c81c46a35ce411");
        let expected = h16("dfa66747de9ae63030ca32611497c827");
        assert_eq!(aes_cmac(&key, &msg).unwrap(), expected);
    }

    #[test]
    fn cmac_aes128_rfc4493_four_blocks_unpadded() {
        let key = h("2b7e151628aed2a6abf7158809cf4f3c");
        let msg = h("6bc1bee22e409f96e93d7e117393172a\
             ae2d8a571e03ac9c9eb76fac45af8e51\
             30c81c46a35ce411e5fbc1191a0a52ef\
             f69f2445df4f9b17ad2b417be66c3710");
        let expected = h16("51f0bebf7e3b9d92fc49741779363cfe");
        assert_eq!(aes_cmac(&key, &msg).unwrap(), expected);
    }

    #[test]
    fn cmac_aes192_nist_empty_message() {
        let key = h("8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b");
        let expected = h16("d17ddf46adaacde531cac483de7a9367");
        assert_eq!(aes_cmac(&key, &[]).unwrap(), expected);
    }

    #[test]
    fn cmac_aes192_nist_one_block() {
        let key = h("8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b");
        let msg = h("6bc1bee22e409f96e93d7e117393172a");
        let expected = h16("9e99a7bf31e710900662f65e617c5184");
        assert_eq!(aes_cmac(&key, &msg).unwrap(), expected);
    }

    #[test]
    fn cmac_aes256_nist_empty_message() {
        let key = h("603deb1015ca71be2b73aef0857d7781\
             1f352c073b6108d72d9810a30914dff4");
        let expected = h16("028962f61b7bf89efc6b551f4667d983");
        assert_eq!(aes_cmac(&key, &[]).unwrap(), expected);
    }

    #[test]
    fn cmac_aes256_nist_one_block() {
        let key = h("603deb1015ca71be2b73aef0857d7781\
             1f352c073b6108d72d9810a30914dff4");
        let msg = h("6bc1bee22e409f96e93d7e117393172a");
        let expected = h16("28a7023f452e8f82bd4bf28d8c37c35c");
        assert_eq!(aes_cmac(&key, &msg).unwrap(), expected);
    }

    // ── Truncated CMAC ───────────────────────────────────────────────

    #[test]
    fn cmac_truncated_returns_leftmost_s_bytes() {
        let key = h("2b7e151628aed2a6abf7158809cf4f3c");
        let msg = h("6bc1bee22e409f96e93d7e117393172a");
        let full = aes_cmac(&key, &msg).unwrap();
        for s in 4..=8 {
            let trunc = aes_cmac_truncated(&key, &msg, s).unwrap();
            assert_eq!(trunc.len(), s);
            assert_eq!(trunc.as_slice(), &full[..s]);
        }
    }

    #[test]
    fn cmac_truncated_rejects_invalid_s() {
        let key = h("2b7e151628aed2a6abf7158809cf4f3c");
        for s in [0, 1, 2, 3, 9, 16] {
            assert_eq!(
                aes_cmac_truncated(&key, b"x", s),
                Err(Error::InvalidValue),
                "s={}",
                s,
            );
        }
    }

    #[test]
    fn cmac_rejects_bad_key_length() {
        for bad_len in [0, 8, 15, 17, 23, 25, 31, 33] {
            let key = vec![0u8; bad_len];
            assert_eq!(aes_cmac(&key, b"x"), Err(Error::InvalidValue));
        }
    }
}
