//! Book 2 §A2.3 - ECC encryption scheme (DH + Encrypt-then-MAC).

use crate::core::aes_primitives::{aes_cmac, aes_cmac_truncated, aes_encrypt_block};
use crate::core::ecc_primitives::{P256_FIELD_BYTES, algorithm_suite, recover_y_p256};
use crate::core::error::{Error, Result};
use p256::elliptic_curve::generic_array::GenericArray;
use p256::elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint};
use p256::elliptic_curve::{Field, PrimeField};
use p256::{AffinePoint, EncodedPoint, ProjectivePoint, Scalar};

const AES_BLOCK: usize = 16;
const SESSION_KEY_LEN: usize = 16; // 128 bits per Table 49.
const MAC_LEN: usize = 8;

/// Output of §A2.3.2 Key Derivation: four 128-bit AES keys plus the
/// initial value of the §A2.3.2 step h counter `N` (always `0` at
/// derivation time).
///
/// Per Table 49 row 0 (Algorithm Suite `'00'`):
///
/// - `K_1` = `K_X` for terminal → ICC encryption.
/// - `K_2` = `K_Y` for terminal → ICC authentication.
/// - `K_3` = `K_X` for ICC → terminal encryption.
/// - `K_4` = `K_Y` for ICC → terminal authentication.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EccKeyMaterial {
    pub k1: [u8; SESSION_KEY_LEN],
    pub k2: [u8; SESSION_KEY_LEN],
    pub k3: [u8; SESSION_KEY_LEN],
    pub k4: [u8; SESSION_KEY_LEN],
    pub counter: u16,
}

/// Perform §A2.3.2 Key Derivation for ODE Algorithm Suite `'00'`
/// (P-256 + DH + AES).
///
/// Computes `Z = x(dQ)` via P-256 PointMultiply, derives the
/// CMAC-based key-derivation key `K_DK = CMAC(0¹²⁸, Z)`, and then the
/// four 128-bit session keys as
///
/// ```text
///   K_i := AES(K_DK)[ '0i' || '01' || '00' || UN_KD ||
///                     'A5 A5 A5' || '02' || '00' ]   for i = 1..4.
/// ```
///
/// Arguments:
///
/// - `un_kd` - 8-byte unpredictable number used for key derivation.
///   In §13.2 / §13.4 this is `UN_ODE` (the GET CHALLENGE response).
/// - `suite` - ICC Public Key Algorithm Suite Indicator from the ICC
///   PK Cert for ODE (tag `'9F2D'`); only
///   [`ODE_P256_DH_AES`](algorithm_suite::ODE_P256_DH_AES) (`'00'`)
///   is currently supported.
/// - `d` - terminal's ephemeral private key. Per §B2.2.4 last
///   paragraph no y-constraint is required for ephemeral keys; only
///   `1 ≤ d ≤ n-1` (enforced via `Scalar::from_repr`).
/// - `q_x` - 32-byte x-coordinate of the ICC's ODE public key,
///   recovered from the ICC PK Cert for ODE.
///
/// Errors with `InvalidValue` for an unsupported suite, a non-canonical
/// or zero `d`, an `q_x` that does not lie on the curve, or a `dQ`
/// that turns out to be the point at infinity.
pub fn derive_keys_p256(
    un_kd: &[u8; 8],
    suite: u8,
    d: &[u8; P256_FIELD_BYTES],
    q_x: &[u8; P256_FIELD_BYTES],
) -> Result<EccKeyMaterial> {
    if suite != algorithm_suite::ODE_P256_DH_AES {
        return Err(Error::InvalidValue);
    }

    let z = compute_z_p256(d, q_x)?;
    let kdk = aes_cmac(&[0u8; SESSION_KEY_LEN], &z)?;

    // §A2.3.2 step g: K_i = AES(K_DK)['0i' || DerData], 16-byte block.
    //   DerData = '01' || '00' || UN_KD (8) || 'A5 A5 A5' || '02' || '00'  (15 bytes)
    //   Total prefixed with '0i' = 16 bytes.
    let mut der_block = [0u8; AES_BLOCK];
    der_block[1] = 0x01; // SKD_VERSION
    der_block[2] = 0x00;
    der_block[3..11].copy_from_slice(un_kd);
    der_block[11] = 0xA5;
    der_block[12] = 0xA5;
    der_block[13] = 0xA5;
    der_block[14] = 0x02;
    der_block[15] = 0x00;

    let derive = |i: u8| -> Result<[u8; SESSION_KEY_LEN]> {
        let mut block = der_block;
        block[0] = i;
        aes_encrypt_block(&kdk, block)
    };

    Ok(EccKeyMaterial {
        k1: derive(0x01)?,
        k2: derive(0x02)?,
        k3: derive(0x03)?,
        k4: derive(0x04)?,
        counter: 0,
    })
}

/// Encrypt-then-MAC per §A2.3.3 with AES-CTR (112-bit counter) and
/// 8-byte CMAC. Returns the ciphertext `C := C* || MAC` and the
/// new value of `N` (caller persists it for the next call).
///
/// Arguments:
///
/// - `suite` - ODE Algorithm Suite Indicator; only `'00'` supported.
/// - `k_x` - encryption key (typically `K_1` for terminal → ICC).
/// - `k_y` - authentication key (typically `K_2`).
/// - `msg` - plaintext payload (`P` in the spec). May be empty
///   (§A2.3.3 step c: `C*` is null and only the MAC over
///   `D || SV` is returned).
/// - `aad` - Additional Authenticated Data (`A`). Pass `&[]` for the
///   §13.2 / §13.4 use-cases where `A` is null.
/// - `counter` - current value of `N` (must be `< 65535` per
///   §A2.3.3 step a).
pub fn encrypt_etm_p256(
    suite: u8,
    k_x: &[u8; SESSION_KEY_LEN],
    k_y: &[u8; SESSION_KEY_LEN],
    msg: &[u8],
    aad: &[u8],
    counter: u16,
) -> Result<(Vec<u8>, u16)> {
    if suite != algorithm_suite::ODE_P256_DH_AES {
        return Err(Error::InvalidValue);
    }
    etm_encrypt(k_x, k_y, msg, aad, counter)
}

/// Suite-`'01'` (P-521 + DH + AES) variant of [`encrypt_etm_p256`].
/// The encryption / authentication core is curve-independent - only
/// the suite check and the upstream Key Derivation differ.
pub fn encrypt_etm_p521(
    suite: u8,
    k_x: &[u8; SESSION_KEY_LEN],
    k_y: &[u8; SESSION_KEY_LEN],
    msg: &[u8],
    aad: &[u8],
    counter: u16,
) -> Result<(Vec<u8>, u16)> {
    if suite != algorithm_suite::ODE_P521_DH_AES {
        return Err(Error::InvalidValue);
    }
    etm_encrypt(k_x, k_y, msg, aad, counter)
}

/// Curve-agnostic Encrypt-then-MAC body shared by
/// [`encrypt_etm_p256`] and [`encrypt_etm_p521`].
fn etm_encrypt(
    k_x: &[u8; SESSION_KEY_LEN],
    k_y: &[u8; SESSION_KEY_LEN],
    msg: &[u8],
    aad: &[u8],
    counter: u16,
) -> Result<(Vec<u8>, u16)> {
    // §A2.3.3 step a: N must not be 65535.
    if counter == 0xFFFF {
        return Err(Error::InvalidValue);
    }

    // §A2.3.3 step b: SV = N (BE, 2 bytes) || zeros(14).
    let mut sv = [0u8; AES_BLOCK];
    sv[..2].copy_from_slice(&counter.to_be_bytes());

    // §A2.3.3 steps c-h: AES-CTR. The pad-then-truncate dance in
    // steps e/h is just plain AES-CTR over `msg` - our chunks-based
    // loop never materialises the padding bytes.
    let c_star = if msg.is_empty() {
        Vec::new()
    } else {
        ctr_xor(k_x, &sv, msg)?
    };

    // §A2.3.3 step j: D = I2BS(len(A)/8, 64) || A. Bit-length-modulo-8
    // checks (steps d, i) are automatic for byte-oriented inputs.
    let mut d = (aad.len() as u64).to_be_bytes().to_vec();
    d.extend_from_slice(aad);

    // §A2.3.3 step k: 8-byte MAC over D || SV || C*.
    let mut mac_input = Vec::with_capacity(d.len() + AES_BLOCK + c_star.len());
    mac_input.extend_from_slice(&d);
    mac_input.extend_from_slice(&sv);
    mac_input.extend_from_slice(&c_star);
    let mac = aes_cmac_truncated(k_y, &mac_input, MAC_LEN)?;

    // §A2.3.3 step l: C = C* || MAC.
    let mut c = c_star;
    c.extend_from_slice(&mac);

    // §A2.3.3 step m: increment N.
    Ok((c, counter + 1))
}

/// Authenticate-then-decrypt per §A2.3.4. Inverse of
/// [`encrypt_etm_p256`]: parses `C = C* || S'`, verifies the 8-byte
/// MAC, AES-CTR-decrypts, and returns the plaintext plus the new
/// value of `N`.
///
/// Errors with `InvalidValue` for a MAC-verification failure, a
/// short ciphertext, an unsupported suite, or `counter == 65535`.
pub fn decrypt_etm_p256(
    suite: u8,
    k_x: &[u8; SESSION_KEY_LEN],
    k_y: &[u8; SESSION_KEY_LEN],
    ciphertext: &[u8],
    aad: &[u8],
    counter: u16,
) -> Result<(Vec<u8>, u16)> {
    if suite != algorithm_suite::ODE_P256_DH_AES {
        return Err(Error::InvalidValue);
    }
    etm_decrypt(k_x, k_y, ciphertext, aad, counter)
}

/// Suite-`'01'` (P-521 + DH + AES) variant of [`decrypt_etm_p256`].
pub fn decrypt_etm_p521(
    suite: u8,
    k_x: &[u8; SESSION_KEY_LEN],
    k_y: &[u8; SESSION_KEY_LEN],
    ciphertext: &[u8],
    aad: &[u8],
    counter: u16,
) -> Result<(Vec<u8>, u16)> {
    if suite != algorithm_suite::ODE_P521_DH_AES {
        return Err(Error::InvalidValue);
    }
    etm_decrypt(k_x, k_y, ciphertext, aad, counter)
}

/// Curve-agnostic authenticate-then-decrypt body shared by
/// [`decrypt_etm_p256`] and [`decrypt_etm_p521`].
fn etm_decrypt(
    k_x: &[u8; SESSION_KEY_LEN],
    k_y: &[u8; SESSION_KEY_LEN],
    ciphertext: &[u8],
    aad: &[u8],
    counter: u16,
) -> Result<(Vec<u8>, u16)> {
    // §A2.3.4 step a.
    if counter == 0xFFFF {
        return Err(Error::InvalidValue);
    }
    // §A2.3.4 step b: |C| ≥ 8 (MAC length).
    if ciphertext.len() < MAC_LEN {
        return Err(Error::InvalidValue);
    }

    // §A2.3.4 step e: split into C* || S'.
    let split = ciphertext.len() - MAC_LEN;
    let c_star = &ciphertext[..split];
    let s_prime = &ciphertext[split..];

    // §A2.3.4 step g: SV.
    let mut sv = [0u8; AES_BLOCK];
    sv[..2].copy_from_slice(&counter.to_be_bytes());

    // §A2.3.4 step d: D = I2BS(len(A)/8, 64) || A.
    let mut d = (aad.len() as u64).to_be_bytes().to_vec();
    d.extend_from_slice(aad);

    // §A2.3.4 step h: recompute 8-byte MAC over D || SV || C*.
    let mut mac_input = Vec::with_capacity(d.len() + AES_BLOCK + c_star.len());
    mac_input.extend_from_slice(&d);
    mac_input.extend_from_slice(&sv);
    mac_input.extend_from_slice(c_star);
    let s = aes_cmac_truncated(k_y, &mac_input, MAC_LEN)?;

    // §A2.3.4 step i: tag compare. Plain equality is sufficient for
    // this code path (the surrounding protocol bounds attempts via
    // PIN-try counters and SW1SW2='6984'); a constant-time compare
    // would be a hardening refinement, not a correctness issue.
    if s != s_prime {
        return Err(Error::InvalidValue);
    }

    // §A2.3.4 steps j-o: decrypt (CTR is symmetric).
    let plaintext = if c_star.is_empty() {
        Vec::new()
    } else {
        ctr_xor(k_x, &sv, c_star)?
    };

    // §A2.3.4 step p.
    Ok((plaintext, counter + 1))
}

// ── helpers ──────────────────────────────────────────────────────────

/// Compute `Z = x(dQ)` per §A2.3.2 step b for P-256.
///
/// Per §B2.2.4 last paragraph, ephemeral DH keys may use either y
/// root for `Q` - the resulting shared-secret x-coordinate is
/// independent of the choice. We use the lower-y root (matching the
/// convention used elsewhere in the kernel) so that ICC long-term
/// keys generated under the §B2.2.4 `y < (p+1)/2` constraint
/// round-trip cleanly.
fn compute_z_p256(
    d: &[u8; P256_FIELD_BYTES],
    q_x: &[u8; P256_FIELD_BYTES],
) -> Result<[u8; P256_FIELD_BYTES]> {
    let d_bytes = GenericArray::clone_from_slice(d);
    let d_scalar: Scalar = Option::from(Scalar::from_repr(d_bytes)).ok_or(Error::InvalidValue)?;
    if bool::from(d_scalar.is_zero()) {
        return Err(Error::InvalidValue);
    }

    let q_point = decode_q_p256(q_x)?;
    let dq = q_point * d_scalar;
    let dq_affine = dq.to_affine();
    if bool::from(dq_affine.is_identity()) {
        return Err(Error::InvalidValue);
    }
    let encoded = dq_affine.to_encoded_point(false);
    let x = encoded.x().ok_or(Error::InvalidValue)?;
    let mut out = [0u8; P256_FIELD_BYTES];
    out.copy_from_slice(x);
    Ok(out)
}

fn decode_q_p256(q_x: &[u8; P256_FIELD_BYTES]) -> Result<ProjectivePoint> {
    let y = recover_y_p256(q_x)?;
    let mut uncompressed = [0u8; 1 + 2 * P256_FIELD_BYTES];
    uncompressed[0] = 0x04;
    uncompressed[1..33].copy_from_slice(q_x);
    uncompressed[33..].copy_from_slice(&y);
    let encoded =
        EncodedPoint::from_bytes(uncompressed.as_slice()).map_err(|_| Error::InvalidValue)?;
    let affine: AffinePoint =
        Option::from(AffinePoint::from_encoded_point(&encoded)).ok_or(Error::InvalidValue)?;
    Ok(affine.into())
}

/// AES-CTR with the §A2.3.3 step g 112-bit counter convention.
/// Curve-agnostic - the same routine is used for both Suite `'00'`
/// and Suite `'01'`.
///
/// `sv` is the 16-byte starting variable (`N` in the leftmost two
/// bytes, zeros elsewhere); the per-block counter is `SV + ((i-1)
/// mod 2¹¹²)` - the 14 rightmost bytes act as a 112-bit big-endian
/// counter that wraps within those bytes, leaving the leftmost 2
/// bytes (containing `N`) unchanged.
///
/// The §A2.3.3 step e/h pad-then-truncate is implicit: a partial
/// final block is XORed with the leading bytes of its keystream and
/// the trailing keystream bytes are discarded.
fn ctr_xor(k_x: &[u8; SESSION_KEY_LEN], sv: &[u8; AES_BLOCK], data: &[u8]) -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity(data.len());
    for (i, chunk) in data.chunks(AES_BLOCK).enumerate() {
        let counter_block = ctr_block(sv, i as u128);
        let stream = aes_encrypt_block(k_x, counter_block)?;
        for j in 0..chunk.len() {
            out.push(chunk[j] ^ stream[j]);
        }
    }
    Ok(out)
}

fn ctr_block(sv: &[u8; AES_BLOCK], offset: u128) -> [u8; AES_BLOCK] {
    // §A2.3.3 step g: counter = SV + (offset mod 2¹¹²). Per step b
    // the 14 rightmost bytes of SV are zero, so the result is
    //   bytes 0..2  = N (unchanged)
    //   bytes 2..16 = (offset mod 2¹¹²) as a 14-byte BE integer.
    let mut block = *sv;
    let off = offset & ((1u128 << 112) - 1);
    let off_bytes = off.to_be_bytes(); // 16 bytes BE
    block[2..].copy_from_slice(&off_bytes[2..]);
    block
}

// ── P-521 (Suite '01') Key Derivation ────────────────────────────────

/// Z-byte-string length for P-521 per §A2.3.2 step c: 640 bits = 80
/// bytes (the rightmost 521 bits hold `x(dQ)`; the leftmost 119 bits
/// are zero padding).
const P521_Z_BYTES: usize = 80;

/// Perform §A2.3.2 Key Derivation for ODE Algorithm Suite `'01'`
/// (P-521 + DH + AES). Mirror of [`derive_keys_p256`] using the
/// `p521` curve and a 80-byte `Z` per §A2.3.2 step c.
///
/// `q_x` is the 66-byte x-coordinate of the ICC's ODE public key
/// (P-521 N_FIELD = 66 per Table 49). `un_kd` is still 8 bytes
/// regardless of curve.
pub fn derive_keys_p521(
    un_kd: &[u8; 8],
    suite: u8,
    d: &[u8; ecc_primitives_p521::P521_FIELD_BYTES],
    q_x: &[u8; ecc_primitives_p521::P521_FIELD_BYTES],
) -> Result<EccKeyMaterial> {
    if suite != algorithm_suite::ODE_P521_DH_AES {
        return Err(Error::InvalidValue);
    }

    // §A2.3.2 step b/c: Z = I2BS(x(dQ), 640) - 80 bytes with the
    // leading 14 zero bytes giving the 119 bit padding.
    let z = compute_z_p521(d, q_x)?;
    let kdk = aes_cmac(&[0u8; SESSION_KEY_LEN], &z)?;

    // §A2.3.2 step g: identical to P-256 - DerData is independent of
    // the curve.
    let mut der_block = [0u8; AES_BLOCK];
    der_block[1] = 0x01;
    der_block[2] = 0x00;
    der_block[3..11].copy_from_slice(un_kd);
    der_block[11] = 0xA5;
    der_block[12] = 0xA5;
    der_block[13] = 0xA5;
    der_block[14] = 0x02;
    der_block[15] = 0x00;

    let derive = |i: u8| -> Result<[u8; SESSION_KEY_LEN]> {
        let mut block = der_block;
        block[0] = i;
        aes_encrypt_block(&kdk, block)
    };

    Ok(EccKeyMaterial {
        k1: derive(0x01)?,
        k2: derive(0x02)?,
        k3: derive(0x03)?,
        k4: derive(0x04)?,
        counter: 0,
    })
}

/// Compute the 80-byte `Z` for P-521 per §A2.3.2 step b/c: 14 zero
/// bytes prepended to the 66-byte BE x-coordinate of `dQ`.
fn compute_z_p521(
    d: &[u8; ecc_primitives_p521::P521_FIELD_BYTES],
    q_x: &[u8; ecc_primitives_p521::P521_FIELD_BYTES],
) -> Result<[u8; P521_Z_BYTES]> {
    let x = ecc_primitives_p521::compute_dq_x(d, q_x)?;
    let mut z = [0u8; P521_Z_BYTES];
    z[14..].copy_from_slice(&x);
    Ok(z)
}

/// Inner module that encapsulates the `p521` crate types - keeps the
/// outer module's namespace clean and keeps the P-256 vs P-521
/// imports separate.
mod ecc_primitives_p521 {
    use crate::core::ecc_primitives::recover_y_p521;
    use crate::core::error::{Error, Result};
    use p521::elliptic_curve::PrimeField;
    use p521::elliptic_curve::generic_array::GenericArray;
    use p521::elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint};
    use p521::{AffinePoint, EncodedPoint, ProjectivePoint, Scalar};

    pub const P521_FIELD_BYTES: usize = 66;

    /// `x(dQ)` for P-521 (66 bytes BE).
    pub fn compute_dq_x(
        d: &[u8; P521_FIELD_BYTES],
        q_x: &[u8; P521_FIELD_BYTES],
    ) -> Result<[u8; P521_FIELD_BYTES]> {
        let d_bytes = GenericArray::clone_from_slice(d);
        let d_scalar: Scalar =
            Option::from(Scalar::from_repr(d_bytes)).ok_or(Error::InvalidValue)?;
        if bool::from(d_scalar.is_zero()) {
            return Err(Error::InvalidValue);
        }

        let q_point = decode_q(q_x)?;
        let dq = q_point * d_scalar;
        let dq_affine: AffinePoint = dq.into();
        if bool::from(dq_affine.is_identity()) {
            return Err(Error::InvalidValue);
        }
        let encoded = dq_affine.to_encoded_point(false);
        let x = encoded.x().ok_or(Error::InvalidValue)?;
        let mut out = [0u8; P521_FIELD_BYTES];
        out.copy_from_slice(x);
        Ok(out)
    }

    fn decode_q(q_x: &[u8; P521_FIELD_BYTES]) -> Result<ProjectivePoint> {
        let y = recover_y_p521(q_x)?;
        let mut uncompressed = [0u8; 1 + 2 * P521_FIELD_BYTES];
        uncompressed[0] = 0x04;
        uncompressed[1..1 + P521_FIELD_BYTES].copy_from_slice(q_x);
        uncompressed[1 + P521_FIELD_BYTES..].copy_from_slice(&y);
        let encoded =
            EncodedPoint::from_bytes(uncompressed.as_slice()).map_err(|_| Error::InvalidValue)?;
        let affine: AffinePoint =
            Option::from(AffinePoint::from_encoded_point(&encoded)).ok_or(Error::InvalidValue)?;
        Ok(affine.into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::ec_sdsa::{constrain_long_term_private_key_p256, public_key_x_from_private};

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

    fn h32(s: &str) -> [u8; 32] {
        h(s).try_into().unwrap()
    }

    fn icc_private_key() -> [u8; 32] {
        // Wrap with §B2.2.4 constraint so the lower-y recovery in
        // decode_q_p256 reconstructs the right Q.
        constrain_long_term_private_key_p256(&h32(
            "c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721",
        ))
        .unwrap()
    }

    fn ephemeral_d() -> [u8; 32] {
        h32("a6e3c57dd01abe90086538398355dd4c3b17aa873382b0f24d6129493d8aad60")
    }

    // ── §A2.3.2 K_DK equivalence to spec's open-coded form ───────────

    #[test]
    fn kdk_matches_open_coded_spec_form() {
        // Reconstruct the spec's open-coded computation and assert it
        // equals our aes_cmac(0¹²⁸, Z) shortcut.
        let zero_key = [0u8; 16];
        let z = h("0102030405060708090A0B0C0D0E0F10\
             1112131415161718191A1B1C1D1E1F20");

        // Open-coded per §A2.3.2 step f for t = 2 (P-256).
        let z0: [u8; 16] = z[0..16].try_into().unwrap();
        let mut z1: [u8; 16] = z[16..32].try_into().unwrap();
        let k1_const = h16("CDD297A9DF1458771099F4B39468565C");
        for i in 0..16 {
            z1[i] ^= k1_const[i];
        }
        let c0 = aes_encrypt_block(&zero_key, z0).unwrap();
        let mut c1_in = [0u8; 16];
        for i in 0..16 {
            c1_in[i] = c0[i] ^ z1[i];
        }
        let kdk_open = aes_encrypt_block(&zero_key, c1_in).unwrap();

        // CMAC shortcut.
        let kdk_cmac = aes_cmac(&zero_key, &z).unwrap();

        assert_eq!(kdk_open, kdk_cmac);
    }

    #[test]
    fn cmac_zero_key_subkey_constant() {
        // Sanity-check that AES(0¹²⁸)[0¹²⁸] << 1 yields the spec's
        // 'CDD297A9DF1458771099F4B39468565C' value. We reconstruct the
        // shift directly to keep the test independent of the
        // (private) cmac_subkey helper.
        let l = aes_encrypt_block(&[0u8; 16], [0u8; 16]).unwrap();
        // L should have MSB 0 - verify so the K1 derivation is just a
        // pure left-shift (no XOR with R_b).
        assert_eq!(l[0] & 0x80, 0);
        let mut k1 = [0u8; 16];
        for i in 0..15 {
            k1[i] = (l[i] << 1) | (l[i + 1] >> 7);
        }
        k1[15] = l[15] << 1;
        assert_eq!(k1, h16("CDD297A9DF1458771099F4B39468565C"));
    }

    // ── Diffie-Hellman key-agreement symmetry ────────────────────────

    #[test]
    fn dh_symmetry_terminal_icc() {
        // Z computed by terminal (d_t * Q_icc) and by ICC (d_icc *
        // Q_t) must agree - that's the whole point of DH.
        let d_term = ephemeral_d();
        let d_icc = icc_private_key();
        let q_term = public_key_x_from_private(&d_term).unwrap();
        let q_icc = public_key_x_from_private(&d_icc).unwrap();

        let z_term = compute_z_p256(&d_term, &q_icc).unwrap();
        let z_icc = compute_z_p256(&d_icc, &q_term).unwrap();
        assert_eq!(z_term, z_icc);
    }

    #[test]
    fn key_derivation_symmetry_terminal_icc() {
        let d_term = ephemeral_d();
        let d_icc = icc_private_key();
        let q_term = public_key_x_from_private(&d_term).unwrap();
        let q_icc = public_key_x_from_private(&d_icc).unwrap();
        let un_kd = h("0102030405060708").try_into().unwrap();

        let suite = algorithm_suite::ODE_P256_DH_AES;
        let from_term = derive_keys_p256(&un_kd, suite, &d_term, &q_icc).unwrap();
        let from_icc = derive_keys_p256(&un_kd, suite, &d_icc, &q_term).unwrap();
        assert_eq!(from_term, from_icc);
        assert_eq!(from_term.counter, 0);
    }

    #[test]
    fn key_derivation_distinct_un_kd_yields_distinct_keys() {
        let d = ephemeral_d();
        let q = public_key_x_from_private(&icc_private_key()).unwrap();
        let suite = algorithm_suite::ODE_P256_DH_AES;
        let a = derive_keys_p256(&[0u8; 8], suite, &d, &q).unwrap();
        let b = derive_keys_p256(&[1u8; 8], suite, &d, &q).unwrap();
        assert_ne!(a.k1, b.k1);
        assert_ne!(a.k2, b.k2);
        assert_ne!(a.k3, b.k3);
        assert_ne!(a.k4, b.k4);
    }

    #[test]
    fn key_derivation_four_keys_distinct() {
        let d = ephemeral_d();
        let q = public_key_x_from_private(&icc_private_key()).unwrap();
        let m = derive_keys_p256(&[0u8; 8], algorithm_suite::ODE_P256_DH_AES, &d, &q).unwrap();
        // K_i differ by the leading '0i' byte feeding into a fixed-key
        // AES - different inputs to a strong PRP must produce
        // different outputs in practice.
        assert_ne!(m.k1, m.k2);
        assert_ne!(m.k1, m.k3);
        assert_ne!(m.k1, m.k4);
        assert_ne!(m.k2, m.k3);
        assert_ne!(m.k2, m.k4);
        assert_ne!(m.k3, m.k4);
    }

    #[test]
    fn key_derivation_rejects_unsupported_suite() {
        let d = ephemeral_d();
        let q = public_key_x_from_private(&icc_private_key()).unwrap();
        for bad in [0x01u8, 0x02, 0x88, 0xFF] {
            assert!(derive_keys_p256(&[0u8; 8], bad, &d, &q).is_err());
        }
    }

    #[test]
    fn key_derivation_rejects_zero_d() {
        let q = public_key_x_from_private(&icc_private_key()).unwrap();
        assert!(
            derive_keys_p256(&[0u8; 8], algorithm_suite::ODE_P256_DH_AES, &[0u8; 32], &q,).is_err()
        );
    }

    // ── §A2.3.3 / §A2.3.4 round-trip ─────────────────────────────────

    fn round_trip_keys() -> EccKeyMaterial {
        let d = ephemeral_d();
        let q = public_key_x_from_private(&icc_private_key()).unwrap();
        derive_keys_p256(
            &h("0102030405060708").try_into().unwrap(),
            algorithm_suite::ODE_P256_DH_AES,
            &d,
            &q,
        )
        .unwrap()
    }

    #[test]
    fn etm_round_trip_short_message() {
        let keys = round_trip_keys();
        let suite = algorithm_suite::ODE_P256_DH_AES;
        let msg = b"hello world";
        let (ct, n_after) = encrypt_etm_p256(suite, &keys.k1, &keys.k2, msg, &[], 0).unwrap();
        assert_eq!(n_after, 1);
        let (pt, n_after_dec) = decrypt_etm_p256(suite, &keys.k1, &keys.k2, &ct, &[], 0).unwrap();
        assert_eq!(pt, msg);
        assert_eq!(n_after_dec, 1);
    }

    #[test]
    fn etm_round_trip_exact_block_message() {
        let keys = round_trip_keys();
        let suite = algorithm_suite::ODE_P256_DH_AES;
        let msg = [0xABu8; 16]; // exactly one block
        let (ct, _) = encrypt_etm_p256(suite, &keys.k1, &keys.k2, &msg, &[], 0).unwrap();
        let (pt, _) = decrypt_etm_p256(suite, &keys.k1, &keys.k2, &ct, &[], 0).unwrap();
        assert_eq!(pt, msg);
    }

    #[test]
    fn etm_round_trip_multi_block_message() {
        let keys = round_trip_keys();
        let suite = algorithm_suite::ODE_P256_DH_AES;
        let msg: Vec<u8> = (0..100u8).collect();
        let (ct, _) = encrypt_etm_p256(suite, &keys.k1, &keys.k2, &msg, &[], 0).unwrap();
        let (pt, _) = decrypt_etm_p256(suite, &keys.k1, &keys.k2, &ct, &[], 0).unwrap();
        assert_eq!(pt, msg);
    }

    #[test]
    fn etm_round_trip_with_aad() {
        let keys = round_trip_keys();
        let suite = algorithm_suite::ODE_P256_DH_AES;
        let msg = b"secret payload";
        let aad = b"public header";
        let (ct, _) = encrypt_etm_p256(suite, &keys.k1, &keys.k2, msg, aad, 0).unwrap();
        let (pt, _) = decrypt_etm_p256(suite, &keys.k1, &keys.k2, &ct, aad, 0).unwrap();
        assert_eq!(pt, msg);
    }

    #[test]
    fn etm_round_trip_empty_message() {
        // §A2.3.3 step c: P null → C* null, MAC computed over D || SV
        // (authenticate-only mode).
        let keys = round_trip_keys();
        let suite = algorithm_suite::ODE_P256_DH_AES;
        let aad = b"only authenticated data";
        let (ct, _) = encrypt_etm_p256(suite, &keys.k1, &keys.k2, &[], aad, 0).unwrap();
        // Ciphertext is just the 8-byte MAC.
        assert_eq!(ct.len(), MAC_LEN);
        let (pt, _) = decrypt_etm_p256(suite, &keys.k1, &keys.k2, &ct, aad, 0).unwrap();
        assert!(pt.is_empty());
    }

    #[test]
    fn etm_decrypt_rejects_tampered_ciphertext() {
        let keys = round_trip_keys();
        let suite = algorithm_suite::ODE_P256_DH_AES;
        let msg = b"some message";
        let (mut ct, _) = encrypt_etm_p256(suite, &keys.k1, &keys.k2, msg, &[], 0).unwrap();
        ct[0] ^= 0x01; // flip a bit in C*
        assert!(decrypt_etm_p256(suite, &keys.k1, &keys.k2, &ct, &[], 0).is_err());
    }

    #[test]
    fn etm_decrypt_rejects_tampered_mac() {
        let keys = round_trip_keys();
        let suite = algorithm_suite::ODE_P256_DH_AES;
        let msg = b"some message";
        let (mut ct, _) = encrypt_etm_p256(suite, &keys.k1, &keys.k2, msg, &[], 0).unwrap();
        let len = ct.len();
        ct[len - 1] ^= 0x01; // flip a bit in MAC
        assert!(decrypt_etm_p256(suite, &keys.k1, &keys.k2, &ct, &[], 0).is_err());
    }

    #[test]
    fn etm_decrypt_rejects_tampered_aad() {
        let keys = round_trip_keys();
        let suite = algorithm_suite::ODE_P256_DH_AES;
        let msg = b"payload";
        let aad = b"correct aad";
        let (ct, _) = encrypt_etm_p256(suite, &keys.k1, &keys.k2, msg, aad, 0).unwrap();
        // Decrypting with a different AAD must fail.
        assert!(decrypt_etm_p256(suite, &keys.k1, &keys.k2, &ct, b"wrong aad", 0).is_err());
    }

    #[test]
    fn etm_decrypt_rejects_wrong_counter() {
        let keys = round_trip_keys();
        let suite = algorithm_suite::ODE_P256_DH_AES;
        let msg = b"payload";
        let (ct, _) = encrypt_etm_p256(suite, &keys.k1, &keys.k2, msg, &[], 5).unwrap();
        // Counter mismatch flips SV → MAC fails.
        assert!(decrypt_etm_p256(suite, &keys.k1, &keys.k2, &ct, &[], 6).is_err());
    }

    #[test]
    fn etm_decrypt_rejects_short_ciphertext() {
        let keys = round_trip_keys();
        let suite = algorithm_suite::ODE_P256_DH_AES;
        // Less than the 8-byte MAC.
        assert!(decrypt_etm_p256(suite, &keys.k1, &keys.k2, &[0u8; 7], &[], 0).is_err());
    }

    #[test]
    fn etm_rejects_counter_at_max() {
        let keys = round_trip_keys();
        let suite = algorithm_suite::ODE_P256_DH_AES;
        assert!(encrypt_etm_p256(suite, &keys.k1, &keys.k2, b"x", &[], 0xFFFF).is_err());
        assert!(decrypt_etm_p256(suite, &keys.k1, &keys.k2, &[0u8; 16], &[], 0xFFFF).is_err());
    }

    #[test]
    fn etm_counter_progression_each_call_distinct_ciphertext() {
        // Same plaintext + same keys, different N → different
        // ciphertexts (and different MACs).
        let keys = round_trip_keys();
        let suite = algorithm_suite::ODE_P256_DH_AES;
        let msg = b"replay protected";
        let (ct0, n0) = encrypt_etm_p256(suite, &keys.k1, &keys.k2, msg, &[], 0).unwrap();
        let (ct1, n1) = encrypt_etm_p256(suite, &keys.k1, &keys.k2, msg, &[], n0).unwrap();
        assert_eq!(n0, 1);
        assert_eq!(n1, 2);
        assert_ne!(ct0, ct1);
    }

    #[test]
    fn etm_rejects_unsupported_suite() {
        let keys = round_trip_keys();
        for bad in [0x01u8, 0x88, 0xFF] {
            assert!(encrypt_etm_p256(bad, &keys.k1, &keys.k2, b"x", &[], 0).is_err());
            assert!(decrypt_etm_p256(bad, &keys.k1, &keys.k2, &[0u8; 9], &[], 0).is_err());
        }
    }

    // ── CTR counter mechanics ────────────────────────────────────────

    #[test]
    fn ctr_block_layout_matches_spec() {
        // SV with N = '1234'; bytes 2..15 zero per §A2.3.3 step b.
        let mut sv = [0u8; 16];
        sv[0] = 0x12;
        sv[1] = 0x34;

        let block0 = ctr_block(&sv, 0);
        // i = 0 → counter == SV.
        assert_eq!(block0, sv);

        let block1 = ctr_block(&sv, 1);
        // i = 1 → bytes 0..2 unchanged, byte 15 = 0x01.
        let mut expected = [0u8; 16];
        expected[0] = 0x12;
        expected[1] = 0x34;
        expected[15] = 0x01;
        assert_eq!(block1, expected);

        let block_ff = ctr_block(&sv, 0xFF);
        let mut expected = [0u8; 16];
        expected[0] = 0x12;
        expected[1] = 0x34;
        expected[15] = 0xFF;
        assert_eq!(block_ff, expected);

        let block_100 = ctr_block(&sv, 0x100);
        let mut expected = [0u8; 16];
        expected[0] = 0x12;
        expected[1] = 0x34;
        expected[14] = 0x01;
        expected[15] = 0x00;
        assert_eq!(block_100, expected);
    }

    #[test]
    fn ctr_block_wraps_at_2_to_112() {
        // offset = 2¹¹² → wraps to zero, leaving N untouched.
        let mut sv = [0u8; 16];
        sv[0] = 0xAA;
        sv[1] = 0xBB;
        let wrapped = ctr_block(&sv, 1u128 << 112);
        assert_eq!(wrapped, sv); // identical to offset 0
    }

    #[test]
    fn ctr_xor_is_symmetric() {
        let key = [0x42u8; 16];
        let mut sv = [0u8; 16];
        sv[0] = 0x00;
        sv[1] = 0x01;
        let plain = b"some plaintext that spans multiple blocks for sure";
        let ct = ctr_xor(&key, &sv, plain).unwrap();
        let pt = ctr_xor(&key, &sv, &ct).unwrap();
        assert_eq!(pt, plain);
    }

    // ── P-521 (Suite '01') ───────────────────────────────────────────

    use crate::core::ec_sdsa::{
        constrain_long_term_private_key_p521, public_key_x_from_private_p521,
    };

    fn h66(s: &str) -> [u8; 66] {
        h(s).try_into().unwrap()
    }

    fn icc_private_key_p521() -> [u8; 66] {
        constrain_long_term_private_key_p521(&h66("00C9 AFA9 D845 BA75 166B 5C21 5767 B1D6\
             934E 50C3 DB36 E89B 127B 8A62 2B12 0F67\
             21AB CDEF 0123 4567 89AB CDEF 0123 4567\
             89AB CDEF 0123 4567 89AB CDEF 0123 4567\
             8901"))
        .unwrap()
    }

    fn ephemeral_d_p521() -> [u8; 66] {
        constrain_long_term_private_key_p521(&h66("00A6 E3C5 7DD0 1ABE 9008 6538 3983 55DD\
             4C3B 17AA 8733 82B0 F24D 6129 493D 8AAD\
             6011 2233 4455 6677 8899 AABB CCDD EEFF\
             0011 2233 4455 6677 8899 AABB CCDD EEFF\
             0011"))
        .unwrap()
    }

    #[test]
    fn p521_dh_symmetry_terminal_icc() {
        let d_term = ephemeral_d_p521();
        let d_icc = icc_private_key_p521();
        let q_term = public_key_x_from_private_p521(&d_term).unwrap();
        let q_icc = public_key_x_from_private_p521(&d_icc).unwrap();

        let z_term = compute_z_p521(&d_term, &q_icc).unwrap();
        let z_icc = compute_z_p521(&d_icc, &q_term).unwrap();
        assert_eq!(z_term, z_icc);

        // Sanity: leftmost 14 bytes are zero (the "119 padding bits"
        // expressed as 14 full zero bytes plus 7 zero bits in byte 14).
        assert_eq!(&z_term[..14], &[0u8; 14]);
    }

    #[test]
    fn p521_key_derivation_symmetry() {
        let d_term = ephemeral_d_p521();
        let d_icc = icc_private_key_p521();
        let q_term = public_key_x_from_private_p521(&d_term).unwrap();
        let q_icc = public_key_x_from_private_p521(&d_icc).unwrap();
        let un_kd = h("0102030405060708").try_into().unwrap();

        let suite = algorithm_suite::ODE_P521_DH_AES;
        let from_term = derive_keys_p521(&un_kd, suite, &d_term, &q_icc).unwrap();
        let from_icc = derive_keys_p521(&un_kd, suite, &d_icc, &q_term).unwrap();
        assert_eq!(from_term, from_icc);
        assert_eq!(from_term.counter, 0);
    }

    #[test]
    fn p521_kdk_uses_5_block_z() {
        // For P-521, Z = 80 bytes (5 × 16). The CMAC therefore runs
        // over 5 input blocks. We verify by manually reconstructing
        // the spec's open-coded form and comparing to our shortcut.
        let d = ephemeral_d_p521();
        let q = public_key_x_from_private_p521(&icc_private_key_p521()).unwrap();
        let z = compute_z_p521(&d, &q).unwrap();
        assert_eq!(z.len(), 80);

        // Spec form: 5 blocks Z_0..Z_4 with K_1 mask on Z_4.
        let zero = [0u8; 16];
        let k1_const = h("CDD297A9DF1458771099F4B39468565C");
        let mut blocks: [[u8; 16]; 5] = Default::default();
        for i in 0..5 {
            blocks[i].copy_from_slice(&z[i * 16..(i + 1) * 16]);
        }
        for j in 0..16 {
            blocks[4][j] ^= k1_const[j];
        }
        let mut state = aes_encrypt_block(&zero, blocks[0]).unwrap();
        for blk in &blocks[1..] {
            let mut x = [0u8; 16];
            for j in 0..16 {
                x[j] = state[j] ^ blk[j];
            }
            state = aes_encrypt_block(&zero, x).unwrap();
        }
        let kdk_open = state;
        let kdk_cmac = aes_cmac(&zero, &z).unwrap();
        assert_eq!(kdk_open, kdk_cmac);
    }

    fn round_trip_keys_p521() -> EccKeyMaterial {
        let d = ephemeral_d_p521();
        let q = public_key_x_from_private_p521(&icc_private_key_p521()).unwrap();
        derive_keys_p521(
            &h("0102030405060708").try_into().unwrap(),
            algorithm_suite::ODE_P521_DH_AES,
            &d,
            &q,
        )
        .unwrap()
    }

    #[test]
    fn p521_etm_round_trip_short_message() {
        let keys = round_trip_keys_p521();
        let suite = algorithm_suite::ODE_P521_DH_AES;
        let msg = b"hello over P-521";
        let (ct, n_after) = encrypt_etm_p521(suite, &keys.k1, &keys.k2, msg, &[], 0).unwrap();
        assert_eq!(n_after, 1);
        let (pt, _) = decrypt_etm_p521(suite, &keys.k1, &keys.k2, &ct, &[], 0).unwrap();
        assert_eq!(pt, msg);
    }

    #[test]
    fn p521_etm_round_trip_with_aad() {
        let keys = round_trip_keys_p521();
        let suite = algorithm_suite::ODE_P521_DH_AES;
        let msg = b"secret payload";
        let aad = b"public header";
        let (ct, _) = encrypt_etm_p521(suite, &keys.k1, &keys.k2, msg, aad, 0).unwrap();
        let (pt, _) = decrypt_etm_p521(suite, &keys.k1, &keys.k2, &ct, aad, 0).unwrap();
        assert_eq!(pt, msg);
    }

    #[test]
    fn p521_etm_decrypt_rejects_tampered_ciphertext() {
        let keys = round_trip_keys_p521();
        let suite = algorithm_suite::ODE_P521_DH_AES;
        let (mut ct, _) = encrypt_etm_p521(suite, &keys.k1, &keys.k2, b"message", &[], 0).unwrap();
        ct[0] ^= 0x01;
        assert!(decrypt_etm_p521(suite, &keys.k1, &keys.k2, &ct, &[], 0).is_err());
    }

    #[test]
    fn p521_etm_rejects_unsupported_suite() {
        let keys = round_trip_keys_p521();
        // Suite '00' (P-256) doesn't apply to the P-521 functions.
        assert!(
            encrypt_etm_p521(
                algorithm_suite::ODE_P256_DH_AES,
                &keys.k1,
                &keys.k2,
                b"x",
                &[],
                0,
            )
            .is_err()
        );
        assert!(
            decrypt_etm_p521(
                algorithm_suite::ODE_P256_DH_AES,
                &keys.k1,
                &keys.k2,
                &[0u8; 16],
                &[],
                0,
            )
            .is_err()
        );
    }

    #[test]
    fn p521_derive_keys_rejects_wrong_suite() {
        let d = ephemeral_d_p521();
        let q = public_key_x_from_private_p521(&icc_private_key_p521()).unwrap();
        assert!(derive_keys_p521(&[0u8; 8], algorithm_suite::ODE_P256_DH_AES, &d, &q,).is_err());
    }
}
