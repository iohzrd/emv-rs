//! Book 2 §5.1.2 - Certification Revocation List.

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CrlEntry {
    pub rid: [u8; 5],
    pub ca_pk_index: u8,
    pub cert_serial: [u8; 3],
}

impl CrlEntry {
    pub fn matches(&self, rid: &[u8; 5], ca_pk_index: u8, cert_serial: &[u8; 3]) -> bool {
        &self.rid == rid && self.ca_pk_index == ca_pk_index && &self.cert_serial == cert_serial
    }
}

pub fn is_revoked(crl: &[CrlEntry], rid: &[u8; 5], ca_pk_index: u8, cert_serial: &[u8; 3]) -> bool {
    crl.iter().any(|e| e.matches(rid, ca_pk_index, cert_serial))
}

#[cfg(test)]
mod tests {
    use super::*;

    const VISA_RID: [u8; 5] = [0xA0, 0x00, 0x00, 0x00, 0x03];
    const MC_RID: [u8; 5] = [0xA0, 0x00, 0x00, 0x00, 0x04];

    fn entry(rid: [u8; 5], idx: u8, serial: [u8; 3]) -> CrlEntry {
        CrlEntry {
            rid,
            ca_pk_index: idx,
            cert_serial: serial,
        }
    }

    #[test]
    fn empty_crl_revokes_nothing() {
        assert!(!is_revoked(&[], &VISA_RID, 0x01, &[0x12, 0x34, 0x56]));
    }

    #[test]
    fn matching_entry_is_revoked() {
        let crl = [entry(VISA_RID, 0x01, [0x12, 0x34, 0x56])];
        assert!(is_revoked(&crl, &VISA_RID, 0x01, &[0x12, 0x34, 0x56]));
    }

    #[test]
    fn non_matching_serial_is_not_revoked() {
        let crl = [entry(VISA_RID, 0x01, [0x12, 0x34, 0x56])];
        assert!(!is_revoked(&crl, &VISA_RID, 0x01, &[0x12, 0x34, 0x57]));
    }

    #[test]
    fn non_matching_rid_is_not_revoked() {
        let crl = [entry(VISA_RID, 0x01, [0x12, 0x34, 0x56])];
        assert!(!is_revoked(&crl, &MC_RID, 0x01, &[0x12, 0x34, 0x56]));
    }

    #[test]
    fn non_matching_ca_index_is_not_revoked() {
        let crl = [entry(VISA_RID, 0x01, [0x12, 0x34, 0x56])];
        assert!(!is_revoked(&crl, &VISA_RID, 0x02, &[0x12, 0x34, 0x56]));
    }

    #[test]
    fn finds_match_in_middle_of_crl() {
        let crl = [
            entry(VISA_RID, 0x01, [0x11, 0x11, 0x11]),
            entry(VISA_RID, 0x01, [0x22, 0x22, 0x22]),
            entry(VISA_RID, 0x01, [0x33, 0x33, 0x33]),
        ];
        assert!(is_revoked(&crl, &VISA_RID, 0x01, &[0x22, 0x22, 0x22]));
    }

    #[test]
    fn supports_30_entries_per_rid() {
        let mut crl = Vec::new();
        for i in 0..30 {
            crl.push(entry(VISA_RID, 0x01, [0x00, 0x00, i as u8]));
        }
        assert_eq!(crl.len(), 30);
        assert!(is_revoked(&crl, &VISA_RID, 0x01, &[0x00, 0x00, 29]));
        assert!(!is_revoked(&crl, &VISA_RID, 0x01, &[0x00, 0x00, 30]));
    }

    #[test]
    fn entries_for_distinct_rids_coexist() {
        let crl = [
            entry(VISA_RID, 0x01, [0xAA, 0xAA, 0xAA]),
            entry(MC_RID, 0x05, [0xBB, 0xBB, 0xBB]),
        ];
        assert!(is_revoked(&crl, &VISA_RID, 0x01, &[0xAA, 0xAA, 0xAA]));
        assert!(is_revoked(&crl, &MC_RID, 0x05, &[0xBB, 0xBB, 0xBB]));
        assert!(!is_revoked(&crl, &VISA_RID, 0x05, &[0xBB, 0xBB, 0xBB]));
        assert!(!is_revoked(&crl, &MC_RID, 0x01, &[0xAA, 0xAA, 0xAA]));
    }

    #[test]
    fn entry_matches_method_consistent_with_is_revoked() {
        let e = entry(VISA_RID, 0x07, [0xDE, 0xAD, 0xBE]);
        assert!(e.matches(&VISA_RID, 0x07, &[0xDE, 0xAD, 0xBE]));
        assert!(!e.matches(&VISA_RID, 0x07, &[0xDE, 0xAD, 0xBF]));
        assert!(!e.matches(&VISA_RID, 0x08, &[0xDE, 0xAD, 0xBE]));
        assert!(!e.matches(&MC_RID, 0x07, &[0xDE, 0xAD, 0xBE]));
    }
}
