//! Book 4 §5, §10, Annex A - Terminal configuration.

use crate::de::additional_terminal_capabilities::AdditionalTerminalCapabilities;
use crate::de::terminal_capabilities::TerminalCapabilities;
use crate::de::terminal_type::TerminalType;

// Book 4 §10.1 - Application-independent terminal data.

#[derive(Debug, Clone)]
pub struct Terminal {
    pub terminal_type: TerminalType,
    pub terminal_capabilities: TerminalCapabilities,
    pub additional_terminal_capabilities: AdditionalTerminalCapabilities,
    /// '9F1A' n3 packed BCD, ISO 3166-1 numeric.
    pub terminal_country_code: u16,
    /// '9F1C' 8 ANS.
    pub terminal_identification: [u8; 8],
    /// '9F1E' 8 ANS.
    pub ifd_serial_number: [u8; 8],
    /// '9F15' n4 packed BCD.
    pub merchant_category_code: u16,
    /// '9F16' 15 ANS.
    pub merchant_identifier: [u8; 15],
    /// '9F4E' 0..=85 ANS.
    pub merchant_name_and_location: Vec<u8>,
    /// '9F01' n6 packed BCD.
    pub acquirer_identifier: Option<[u8; 6]>,
    pub applications: Vec<TerminalApplication>,
}

impl Terminal {
    /// Longest-prefix match per Book 1 §12.3.1.
    pub fn find_application(&self, df_name: &[u8]) -> Option<&TerminalApplication> {
        let mut best: Option<&TerminalApplication> = None;
        for app in &self.applications {
            if df_name.len() < app.aid.len() || df_name[..app.aid.len()] != app.aid[..] {
                continue;
            }
            if df_name.len() != app.aid.len() && !app.partial_match_allowed {
                continue;
            }
            if best.is_none_or(|b| app.aid.len() > b.aid.len()) {
                best = Some(app);
            }
        }
        best
    }
}

// Book 4 §10.2 Table 7 - Application-dependent terminal data.

#[derive(Debug, Clone)]
pub struct TerminalApplication {
    pub aid: Vec<u8>,
    pub partial_match_allowed: bool,
    /// '9F09' n4 packed BCD.
    pub application_version_number: [u8; 2],
    /// '9F1B' 4 binary, transaction-currency minor units.
    pub terminal_floor_limit: u32,
    pub terminal_risk_management_data: Option<Vec<u8>>,
    pub default_ddol: Option<Vec<u8>>,
    /// '97'. `None` ⇒ §10.2 default empty TDOL.
    pub default_tdol: Option<Vec<u8>>,
    pub tac_denial: Option<[u8; 5]>,
    pub tac_online: Option<[u8; 5]>,
    pub tac_default: Option<[u8; 5]>,

    /// §10.6.2 - range 0..=99.
    pub rts_target_percentage: Option<u8>,
    /// §10.6.2 - range 0..=99, ≥ `rts_target_percentage`.
    pub rts_max_target_percentage: Option<u8>,
    /// §10.6.2 - minor units, < `terminal_floor_limit`.
    pub rts_threshold_value: Option<u64>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_terminal_app(aid: Vec<u8>, partial: bool) -> TerminalApplication {
        TerminalApplication {
            aid,
            partial_match_allowed: partial,
            application_version_number: [0, 1],
            terminal_floor_limit: 0,
            terminal_risk_management_data: None,
            default_ddol: None,
            default_tdol: None,
            tac_denial: None,
            tac_online: None,
            tac_default: None,
            rts_target_percentage: None,
            rts_max_target_percentage: None,
            rts_threshold_value: None,
        }
    }

    fn sample_terminal(apps: Vec<TerminalApplication>) -> Terminal {
        Terminal {
            terminal_type: TerminalType(0x22),
            terminal_capabilities: TerminalCapabilities {
                ic_with_contacts: true,
                ..Default::default()
            },
            additional_terminal_capabilities: AdditionalTerminalCapabilities::default(),
            terminal_country_code: 0x0840,
            terminal_identification: [b'T'; 8],
            ifd_serial_number: [b'S'; 8],
            merchant_category_code: 0x5999,
            merchant_identifier: [b'M'; 15],
            merchant_name_and_location: b"Merchant".to_vec(),
            acquirer_identifier: None,
            applications: apps,
        }
    }

    #[test]
    fn find_application_exact_match() {
        let apps = vec![sample_terminal_app(
            vec![0xA0, 0, 0, 0, 0x03, 0x10, 0x10],
            false,
        )];
        let t = sample_terminal(apps);
        assert!(t.find_application(&[0xA0, 0, 0, 0, 0x03, 0x10, 0x10]).is_some());
        assert!(t.find_application(&[0xA0, 0, 0, 0, 0x03, 0x10, 0x11]).is_none());
    }

    #[test]
    fn find_application_partial_match_when_allowed() {
        let apps = vec![sample_terminal_app(vec![0xA0, 0, 0, 0, 0x03], true)];
        let t = sample_terminal(apps);
        assert!(t.find_application(&[0xA0, 0, 0, 0, 0x03, 0x10, 0x10]).is_some());
    }

    #[test]
    fn find_application_partial_rejected_when_not_allowed() {
        let apps = vec![sample_terminal_app(vec![0xA0, 0, 0, 0, 0x03], false)];
        let t = sample_terminal(apps);
        assert!(t.find_application(&[0xA0, 0, 0, 0, 0x03, 0x10, 0x10]).is_none());
    }

    #[test]
    fn find_application_prefers_longest_match() {
        let apps = vec![
            sample_terminal_app(vec![0xA0, 0, 0, 0, 0x03], true),
            sample_terminal_app(vec![0xA0, 0, 0, 0, 0x03, 0x10, 0x10], false),
        ];
        let t = sample_terminal(apps);
        let m = t
            .find_application(&[0xA0, 0, 0, 0, 0x03, 0x10, 0x10])
            .unwrap();
        assert_eq!(m.aid.len(), 7);
    }

    #[test]
    fn find_application_none_when_df_shorter_than_aid() {
        let apps = vec![sample_terminal_app(vec![0xA0, 0, 0, 0, 0x03, 0x10, 0x10], true)];
        let t = sample_terminal(apps);
        assert!(t.find_application(&[0xA0, 0, 0]).is_none());
    }
}
