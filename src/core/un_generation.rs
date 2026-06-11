//! Book 2 §11.3 - Terminal Unpredictable Number Generation.

use sha2::{Digest, Sha256};

/// Length of the `P` and `Q` state values (32 bytes - SHA-256 output
/// width).
pub const STATE_LEN: usize = 32;

/// Length of the generated UN per `'9F37'` (4 bytes).
pub const UN_LEN: usize = 4;

/// Length of `RAND` when present (8 bytes per Table 32).
pub const RAND_LEN: usize = 8;

/// Length of `TID` (Terminal ID) and `IFDSN` (IFD Serial Number) per
/// Book 3 Table 33: 8 bytes alpha-numeric.
pub const ID_LEN: usize = 8;

/// Length of an Application Cryptogram (Book 2 §8.1.2) - 8 bytes,
/// truncated CMAC / Retail-MAC for both TDES and AES variants.
pub const AC_LEN: usize = 8;

// ── Pure functions ───────────────────────────────────────────────────

/// Power-up step per §11.3: `Q := SHA(Q || TVP || IFDSN || TID ||
/// RAND?)`, then `P := Q`. Returns `(new_q, new_p)` - both equal
/// after this call.
///
/// The caller persists `new_q` to non-volatile storage (so the next
/// power-up sees the rolled value) and holds `new_p` in volatile
/// memory.
pub fn power_up(
    q: &[u8; STATE_LEN],
    tvp: &[u8],
    ifdsn: &[u8; ID_LEN],
    tid: &[u8; ID_LEN],
    rand: Option<&[u8; RAND_LEN]>,
) -> ([u8; STATE_LEN], [u8; STATE_LEN]) {
    let mut h = Sha256::new();
    h.update(q);
    h.update(tvp);
    h.update(ifdsn);
    h.update(tid);
    if let Some(r) = rand {
        h.update(r);
    }
    let new_q: [u8; STATE_LEN] = h.finalize().into();
    (new_q, new_q)
}

/// Before-transaction step per §11.3: `UN := LS4B(SHA(P || RAND?))`.
/// Returns the 4-byte UN to populate data element `'9F37'`.
///
/// `LS4B` is the **rightmost** 4 bytes of the SHA-256 output (its
/// least-significant 32 bits when the digest is read big-endian).
pub fn generate_un(p: &[u8; STATE_LEN], rand: Option<&[u8; RAND_LEN]>) -> [u8; UN_LEN] {
    let mut h = Sha256::new();
    h.update(p);
    if let Some(r) = rand {
        h.update(r);
    }
    let digest: [u8; STATE_LEN] = h.finalize().into();
    let mut un = [0u8; UN_LEN];
    un.copy_from_slice(&digest[STATE_LEN - UN_LEN..]);
    un
}

/// After-transaction step per §11.3 (must run "even if it fails"):
/// `P := SHA(P || TVP || RAND? || AC?)`. Returns the new `P`.
///
/// `ac` is the Application Cryptogram returned by GENERATE AC for
/// the just-completed transaction (per §8.1.2 always 8 bytes).
/// Pass `None` if no AC was obtained (e.g. the transaction failed
/// before GENERATE AC).
pub fn refresh_after_transaction(
    p: &[u8; STATE_LEN],
    tvp: &[u8],
    rand: Option<&[u8; RAND_LEN]>,
    ac: Option<&[u8; AC_LEN]>,
) -> [u8; STATE_LEN] {
    let mut h = Sha256::new();
    h.update(p);
    h.update(tvp);
    if let Some(r) = rand {
        h.update(r);
    }
    if let Some(a) = ac {
        h.update(a);
    }
    h.finalize().into()
}

/// Power-down step per §11.3: `Q := P`. Trivial copy - exposed as a
/// named function so callers can spell out the lifecycle phase that
/// matches the spec.
pub fn power_down(p: &[u8; STATE_LEN]) -> [u8; STATE_LEN] {
    *p
}

// ── State wrapper ────────────────────────────────────────────────────

/// Stateful wrapper around the §11.3 lifecycle. Holds `P`, `Q`,
/// `TID`, and `IFDSN` so transaction-time call sites don't have to
/// thread them through. The TVP and RAND values, which can change
/// per call, are passed in at each step.
///
/// ## Suggested usage
///
/// ```ignore
/// // At terminal startup (after loading Q from non-volatile):
/// let mut un_gen = UnGenerator::new(persisted_q, tid, ifdsn);
/// un_gen.power_up(&current_tvp(), Some(&hardware_rand()));
///
/// // Before each transaction:
/// let un_9f37 = un_gen.generate_un(Some(&hardware_rand()));
///
/// // After each transaction (success or failure):
/// un_gen.refresh_after_transaction(&current_tvp(), Some(&hw_rand()), Some(&ac));
///
/// // At terminal shutdown (or periodically): persist Q.
/// let new_q = un_gen.power_down();
/// // … write new_q to non-volatile storage …
/// ```
#[derive(Debug, Clone)]
pub struct UnGenerator {
    p: [u8; STATE_LEN],
    q: [u8; STATE_LEN],
    tid: [u8; ID_LEN],
    ifdsn: [u8; ID_LEN],
}

impl UnGenerator {
    /// Construct a new generator from a persisted `Q` value plus the
    /// terminal's `TID` (`'9F1C'`) and `IFDSN` (`'9F1E'`).
    ///
    /// `q` should be the value loaded from non-volatile storage (or
    /// the deployment seed on first boot per Table 32: "shall be
    /// initialised to a terminal-unique random number prior to
    /// deployment"). `P` is set to all-zeros and is overwritten on
    /// the first [`UnGenerator::power_up`] call before any UN is
    /// generated - the no-op initial value is never observed in
    /// output.
    pub fn new(q: [u8; STATE_LEN], tid: [u8; ID_LEN], ifdsn: [u8; ID_LEN]) -> Self {
        Self {
            p: [0u8; STATE_LEN],
            q,
            tid,
            ifdsn,
        }
    }

    /// Run the §11.3 power-up step. Internally rolls `Q` and copies
    /// it to `P`.
    pub fn power_up(&mut self, tvp: &[u8], rand: Option<&[u8; RAND_LEN]>) {
        let (q, p) = power_up(&self.q, tvp, &self.ifdsn, &self.tid, rand);
        self.q = q;
        self.p = p;
    }

    /// Generate the 4-byte UN for the next transaction (`'9F37'`).
    /// Does not advance state - callers run
    /// [`UnGenerator::refresh_after_transaction`] separately when
    /// the transaction completes.
    pub fn generate_un(&self, rand: Option<&[u8; RAND_LEN]>) -> [u8; UN_LEN] {
        generate_un(&self.p, rand)
    }

    /// Refresh `P` after a transaction. Per §11.3, this runs
    /// regardless of transaction outcome.
    pub fn refresh_after_transaction(
        &mut self,
        tvp: &[u8],
        rand: Option<&[u8; RAND_LEN]>,
        ac: Option<&[u8; AC_LEN]>,
    ) {
        self.p = refresh_after_transaction(&self.p, tvp, rand, ac);
    }

    /// Snapshot of `Q` for persistence to non-volatile storage. Per
    /// §11.3 power-down: `Q := P`. Returns the current `P` (which is
    /// the value the caller should persist as the new `Q`).
    pub fn power_down(&self) -> [u8; STATE_LEN] {
        self.p
    }

    /// Read-only view of the current `P` register (for testing and
    /// debugging - production code shouldn't expose this).
    pub fn p(&self) -> [u8; STATE_LEN] {
        self.p
    }

    /// Read-only view of the current `Q` register.
    pub fn q(&self) -> [u8; STATE_LEN] {
        self.q
    }
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

    fn h32(s: &str) -> [u8; 32] {
        h(s).try_into().unwrap()
    }

    fn tid() -> [u8; 8] {
        // Book 3 Table 33: 8 bytes alpha-numeric.
        *b"TERMINL1"
    }

    fn ifdsn() -> [u8; 8] {
        *b"00000001"
    }

    fn deployment_q() -> [u8; 32] {
        h32("0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20")
    }

    // ── LS4B placement ───────────────────────────────────────────────

    #[test]
    fn generate_un_is_last_4_bytes_of_sha_p() {
        // §11.3 LS4B = least-significant 4 bytes = rightmost 4 bytes
        // of the SHA-256 output.
        let p = [0x42u8; 32];
        let mut h = Sha256::new();
        h.update(p);
        let digest: [u8; 32] = h.finalize().into();
        let expected: [u8; 4] = digest[28..32].try_into().unwrap();

        let un = generate_un(&p, None);
        assert_eq!(un, expected);
    }

    #[test]
    fn generate_un_with_rand_includes_rand_in_hash() {
        let p = [0x42u8; 32];
        let rand = [0x99u8; 8];
        // Expected: last 4 bytes of SHA-256(P || RAND).
        let mut h = Sha256::new();
        h.update(p);
        h.update(rand);
        let digest: [u8; 32] = h.finalize().into();
        let expected: [u8; 4] = digest[28..32].try_into().unwrap();

        let un = generate_un(&p, Some(&rand));
        assert_eq!(un, expected);
    }

    // ── Determinism / freshness ──────────────────────────────────────

    #[test]
    fn generate_un_is_deterministic_for_fixed_inputs() {
        let p = [0x42u8; 32];
        let r = [0x33u8; 8];
        assert_eq!(generate_un(&p, None), generate_un(&p, None));
        assert_eq!(generate_un(&p, Some(&r)), generate_un(&p, Some(&r)));
    }

    #[test]
    fn generate_un_changes_with_p() {
        let r = [0u8; 8];
        let un1 = generate_un(&[0x00u8; 32], Some(&r));
        let un2 = generate_un(&[0x01u8; 32], Some(&r));
        assert_ne!(un1, un2);
    }

    #[test]
    fn generate_un_changes_with_rand() {
        let p = [0x42u8; 32];
        let un1 = generate_un(&p, Some(&[0x00u8; 8]));
        let un2 = generate_un(&p, Some(&[0x01u8; 8]));
        assert_ne!(un1, un2);
    }

    #[test]
    fn generate_un_with_no_rand_differs_from_with_zero_rand() {
        // Subtle: feeding zero bytes ≠ omitting the input. SHA-256's
        // length suffix in the padding distinguishes the two.
        let p = [0x42u8; 32];
        assert_ne!(generate_un(&p, None), generate_un(&p, Some(&[0u8; 8])));
    }

    // ── power_up ─────────────────────────────────────────────────────

    #[test]
    fn power_up_returns_q_equal_to_p() {
        // §11.3 power-up: Q := SHA(...); P := Q. The two outputs
        // are equal after a power-up call.
        let (q, p) = power_up(&deployment_q(), &[0x00, 0x01], &ifdsn(), &tid(), None);
        assert_eq!(q, p);
    }

    #[test]
    fn power_up_changes_q_on_each_call() {
        // With different TVPs the Q output changes (the typical
        // operating case - TVP is per-power-up).
        let (q1, _) = power_up(&deployment_q(), b"\x00", &ifdsn(), &tid(), None);
        let (q2, _) = power_up(&deployment_q(), b"\x01", &ifdsn(), &tid(), None);
        assert_ne!(q1, q2);
    }

    #[test]
    fn power_up_with_rand_differs_from_without() {
        let (q_no_rand, _) = power_up(&deployment_q(), b"\x00", &ifdsn(), &tid(), None);
        let (q_with_rand, _) = power_up(
            &deployment_q(),
            b"\x00",
            &ifdsn(),
            &tid(),
            Some(&[0xAAu8; 8]),
        );
        assert_ne!(q_no_rand, q_with_rand);
    }

    #[test]
    fn power_up_is_sha_of_concatenated_inputs() {
        // Direct check that the implementation matches the spec's
        // algebraic form: Q := SHA(Q || TVP || IFDSN || TID || RAND).
        let q_in = deployment_q();
        let tvp = b"\x12\x34\x56";
        let rand = [0xAAu8; 8];

        let mut hasher = Sha256::new();
        hasher.update(q_in);
        hasher.update(tvp);
        hasher.update(ifdsn());
        hasher.update(tid());
        hasher.update(rand);
        let expected: [u8; 32] = hasher.finalize().into();

        let (q_out, p_out) = power_up(&q_in, tvp, &ifdsn(), &tid(), Some(&rand));
        assert_eq!(q_out, expected);
        assert_eq!(p_out, expected);
    }

    // ── refresh_after_transaction ────────────────────────────────────

    #[test]
    fn refresh_after_transaction_changes_p() {
        let p = [0x42u8; 32];
        let p_new = refresh_after_transaction(&p, b"\x00\x01", None, None);
        assert_ne!(p, p_new);
    }

    #[test]
    fn refresh_with_different_ac_yields_different_p() {
        let p = [0x42u8; 32];
        let tvp = b"\x12\x34";
        let p1 = refresh_after_transaction(&p, tvp, None, Some(&[0u8; 8]));
        let p2 = refresh_after_transaction(&p, tvp, None, Some(&[1u8; 8]));
        assert_ne!(p1, p2);
    }

    #[test]
    fn refresh_with_different_rand_yields_different_p() {
        let p = [0x42u8; 32];
        let tvp = b"\x12\x34";
        let p1 = refresh_after_transaction(&p, tvp, Some(&[0u8; 8]), None);
        let p2 = refresh_after_transaction(&p, tvp, Some(&[1u8; 8]), None);
        assert_ne!(p1, p2);
    }

    #[test]
    fn refresh_is_sha_of_concatenated_inputs() {
        let p_in = [0x42u8; 32];
        let tvp = b"\x12";
        let rand = [0xAAu8; 8];
        let ac = [0xBBu8; 8];

        let mut hasher = Sha256::new();
        hasher.update(p_in);
        hasher.update(tvp);
        hasher.update(rand);
        hasher.update(ac);
        let expected: [u8; 32] = hasher.finalize().into();

        let p_out = refresh_after_transaction(&p_in, tvp, Some(&rand), Some(&ac));
        assert_eq!(p_out, expected);
    }

    // ── power_down ───────────────────────────────────────────────────

    #[test]
    fn power_down_returns_p_unchanged() {
        let p = [0x42u8; 32];
        assert_eq!(power_down(&p), p);
    }

    // ── State machine wrapper ────────────────────────────────────────

    #[test]
    fn ungenerator_full_lifecycle() {
        // Deploy → power_up → generate UN → after-tx → power_down →
        // power_up (next session) generates a different UN than the
        // first session did.
        let mut g = UnGenerator::new(deployment_q(), tid(), ifdsn());

        // Power-up session 1.
        g.power_up(b"\x00\x01", Some(&[0xAAu8; 8]));
        let un1 = g.generate_un(Some(&[0x11u8; 8]));

        // Transaction completes; refresh and power down.
        g.refresh_after_transaction(b"\x00\x02", Some(&[0xBBu8; 8]), Some(&[0xCCu8; 8]));
        let q_persisted = g.power_down();

        // Reboot: load persisted Q and power up again.
        let mut g2 = UnGenerator::new(q_persisted, tid(), ifdsn());
        g2.power_up(b"\x00\x03", Some(&[0xDDu8; 8]));
        let un2 = g2.generate_un(Some(&[0x11u8; 8]));

        // Two sessions with the same per-call RAND must produce
        // different UNs because the rolled state differs.
        assert_ne!(un1, un2);
    }

    #[test]
    fn ungenerator_generate_un_does_not_advance_state() {
        // Per §11.3, generating UN is read-only on P. Two calls in a
        // row with the same RAND yield the same UN until the caller
        // explicitly refreshes.
        let mut g = UnGenerator::new(deployment_q(), tid(), ifdsn());
        g.power_up(b"\x00", Some(&[0u8; 8]));
        let r = [0x11u8; 8];
        let un_a = g.generate_un(Some(&r));
        let un_b = g.generate_un(Some(&r));
        assert_eq!(un_a, un_b);
    }

    #[test]
    fn ungenerator_refresh_advances_p() {
        let mut g = UnGenerator::new(deployment_q(), tid(), ifdsn());
        g.power_up(b"\x00", None);
        let p_before = g.p();
        g.refresh_after_transaction(b"\x01", None, None);
        let p_after = g.p();
        assert_ne!(p_before, p_after);
    }

    #[test]
    fn ungenerator_power_up_rolls_q() {
        let mut g = UnGenerator::new(deployment_q(), tid(), ifdsn());
        let q_before = g.q();
        g.power_up(b"\x00", None);
        let q_after = g.q();
        assert_ne!(q_before, q_after);
        // After power-up P == Q.
        assert_eq!(g.p(), g.q());
    }

    #[test]
    fn ungenerator_power_down_returns_current_p() {
        let mut g = UnGenerator::new(deployment_q(), tid(), ifdsn());
        g.power_up(b"\x00", None);
        g.refresh_after_transaction(b"\x01", None, None);
        assert_eq!(g.power_down(), g.p());
    }

    #[test]
    fn un_length_is_4_bytes() {
        // Sanity: the data element '9F37' is exactly 4 bytes.
        let p = [0u8; 32];
        let un = generate_un(&p, None);
        assert_eq!(un.len(), 4);
    }
}
