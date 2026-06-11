//! TOML-backed configuration for `emv` kernels (Book 4 §10).

use crate::contact::terminal::{Terminal, TerminalApplication};
use crate::core::crl::CrlEntry;
use crate::core::ecc_oda::EccCaPublicKey;
use crate::core::oda::CaPublicKey;
use crate::de::additional_terminal_capabilities::AdditionalTerminalCapabilities;
use crate::de::terminal_capabilities::TerminalCapabilities;
use crate::de::terminal_type::TerminalType;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

#[derive(Debug)]
pub enum ConfigError {
    Io(std::io::Error),
    Toml(toml::de::Error),
    Hex {
        field: &'static str,
        reason: String,
    },
    WrongLength {
        field: &'static str,
        expected: usize,
        got: usize,
    },
    Overflow {
        field: &'static str,
        max: usize,
        got: usize,
    },
    Spec(crate::Error),
}

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "io error: {}", e),
            Self::Toml(e) => write!(f, "toml: {}", e),
            Self::Hex { field, reason } => write!(f, "{}: invalid hex ({})", field, reason),
            Self::WrongLength {
                field,
                expected,
                got,
            } => write!(f, "{}: expected {} bytes, got {}", field, expected, got),
            Self::Overflow { field, max, got } => {
                write!(f, "{}: value too long ({} bytes, max {})", field, got, max)
            }
            Self::Spec(e) => write!(f, "kernel error: {:?}", e),
        }
    }
}

impl std::error::Error for ConfigError {}

impl From<std::io::Error> for ConfigError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

impl From<toml::de::Error> for ConfigError {
    fn from(e: toml::de::Error) -> Self {
        Self::Toml(e)
    }
}

impl From<crate::Error> for ConfigError {
    fn from(e: crate::Error) -> Self {
        Self::Spec(e)
    }
}

// Book 4 §10.1
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TerminalConfig {
    pub ifd_serial_number: String,
    pub terminal_country_code: u16,
    pub terminal_type: String,
    pub terminal_capabilities: String,
    pub additional_terminal_capabilities: String,
}

impl TerminalConfig {
    pub fn load(path: impl AsRef<Path>) -> Result<Self, ConfigError> {
        Ok(toml::from_str(&fs::read_to_string(path)?)?)
    }

    pub fn parse(s: &str) -> Result<Self, ConfigError> {
        Ok(toml::from_str(s)?)
    }
}

// Book 4 §10.2
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AidsConfig {
    #[serde(default)]
    pub defaults: AidDefaults,
    #[serde(default)]
    pub aids: Vec<AidEntry>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AidDefaults {
    pub acquirer_identifier: Option<String>,
    pub merchant_category_code: Option<u16>,
    pub merchant_identifier: Option<String>,
    pub merchant_name_and_location: Option<String>,
    pub terminal_identification: Option<String>,
    pub transaction_currency_code: Option<u16>,
    pub transaction_currency_exponent: Option<u8>,

    pub partial_match_allowed: Option<bool>,
    pub terminal_floor_limit: Option<u32>,
    pub tac_denial: Option<String>,
    pub tac_online: Option<String>,
    pub tac_default: Option<String>,
    pub default_ddol: Option<String>,
    pub default_tdol: Option<String>,
    pub terminal_risk_management_data: Option<String>,

    pub rts_target_percentage: Option<u8>,
    pub rts_max_target_percentage: Option<u8>,
    pub rts_threshold_value: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AidEntry {
    pub aid: String,
    pub application_version_number: String,

    pub partial_match_allowed: Option<bool>,
    pub terminal_floor_limit: Option<u32>,
    pub tac_denial: Option<String>,
    pub tac_online: Option<String>,
    pub tac_default: Option<String>,
    pub default_ddol: Option<String>,
    pub default_tdol: Option<String>,
    pub terminal_risk_management_data: Option<String>,

    pub rts_target_percentage: Option<u8>,
    pub rts_max_target_percentage: Option<u8>,
    pub rts_threshold_value: Option<u64>,
}

impl AidsConfig {
    pub fn load(path: impl AsRef<Path>) -> Result<Self, ConfigError> {
        Ok(toml::from_str(&fs::read_to_string(path)?)?)
    }

    pub fn parse(s: &str) -> Result<Self, ConfigError> {
        Ok(toml::from_str(s)?)
    }

    pub fn into_applications(self) -> Result<Vec<TerminalApplication>, ConfigError> {
        let d = self.defaults;
        self.aids.into_iter().map(|e| merge_aid(&e, &d)).collect()
    }
}

fn merge_aid(entry: &AidEntry, d: &AidDefaults) -> Result<TerminalApplication, ConfigError> {
    let aid = decode_hex("aid", &entry.aid)?;
    if !(5..=16).contains(&aid.len()) {
        return Err(ConfigError::WrongLength {
            field: "aid",
            expected: 5,
            got: aid.len(),
        });
    }
    let avn_bytes = decode_hex(
        "application_version_number",
        &entry.application_version_number,
    )?;
    let application_version_number: [u8; 2] =
        avn_bytes
            .try_into()
            .map_err(|v: Vec<u8>| ConfigError::WrongLength {
                field: "application_version_number",
                expected: 2,
                got: v.len(),
            })?;
    Ok(TerminalApplication {
        aid,
        partial_match_allowed: entry
            .partial_match_allowed
            .or(d.partial_match_allowed)
            .unwrap_or(false),
        application_version_number,
        terminal_floor_limit: entry
            .terminal_floor_limit
            .or(d.terminal_floor_limit)
            .unwrap_or(0),
        terminal_risk_management_data: opt_hex(
            "terminal_risk_management_data",
            entry
                .terminal_risk_management_data
                .as_deref()
                .or(d.terminal_risk_management_data.as_deref()),
        )?,
        default_ddol: opt_hex(
            "default_ddol",
            entry.default_ddol.as_deref().or(d.default_ddol.as_deref()),
        )?,
        default_tdol: opt_hex(
            "default_tdol",
            entry.default_tdol.as_deref().or(d.default_tdol.as_deref()),
        )?,
        tac_denial: opt_tac(
            "tac_denial",
            entry.tac_denial.as_deref().or(d.tac_denial.as_deref()),
        )?,
        tac_online: opt_tac(
            "tac_online",
            entry.tac_online.as_deref().or(d.tac_online.as_deref()),
        )?,
        tac_default: opt_tac(
            "tac_default",
            entry.tac_default.as_deref().or(d.tac_default.as_deref()),
        )?,
        rts_target_percentage: entry.rts_target_percentage.or(d.rts_target_percentage),
        rts_max_target_percentage: entry
            .rts_max_target_percentage
            .or(d.rts_max_target_percentage),
        rts_threshold_value: entry.rts_threshold_value.or(d.rts_threshold_value),
    })
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CapkConfig {
    #[serde(default)]
    pub capk_rsa: Vec<CapkRsaEntry>,
    #[serde(default)]
    pub capk_ecc: Vec<CapkEccEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapkRsaEntry {
    pub rid: String,
    pub index: String,
    pub modulus: String,
    pub exponent: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapkEccEntry {
    pub rid: String,
    pub index: String,
    pub algorithm_suite: String,
    pub x_coord: String,
}

impl CapkConfig {
    pub fn load(path: impl AsRef<Path>) -> Result<Self, ConfigError> {
        Ok(toml::from_str(&fs::read_to_string(path)?)?)
    }

    pub fn parse(s: &str) -> Result<Self, ConfigError> {
        Ok(toml::from_str(s)?)
    }

    #[allow(clippy::type_complexity)]
    pub fn into_kernel(self) -> Result<(Vec<CaPublicKey>, Vec<EccCaPublicKey>), ConfigError> {
        let rsa = self
            .capk_rsa
            .into_iter()
            .map(|e| e.into_kernel())
            .collect::<Result<Vec<_>, _>>()?;
        let ecc = self
            .capk_ecc
            .into_iter()
            .map(|e| e.into_kernel())
            .collect::<Result<Vec<_>, _>>()?;
        Ok((rsa, ecc))
    }
}

impl CapkRsaEntry {
    pub fn into_kernel(self) -> Result<CaPublicKey, ConfigError> {
        let rid = decode_fixed::<5>("rid", &self.rid)?;
        let index = decode_fixed::<1>("index", &self.index)?[0];
        let modulus = decode_hex("modulus", &self.modulus)?;
        let exponent = decode_hex("exponent", &self.exponent)?;
        Ok(CaPublicKey {
            rid,
            index,
            modulus,
            exponent,
        })
    }
}

impl CapkEccEntry {
    pub fn into_kernel(self) -> Result<EccCaPublicKey, ConfigError> {
        let rid = decode_fixed::<5>("rid", &self.rid)?;
        let index = decode_fixed::<1>("index", &self.index)?[0];
        let algorithm_suite = decode_fixed::<1>("algorithm_suite", &self.algorithm_suite)?[0];
        let x_coord = decode_hex("x_coord", &self.x_coord)?;
        Ok(EccCaPublicKey {
            rid,
            index,
            x_coord,
            algorithm_suite,
        })
    }
}

// Book 2 §5.1.2 Table 5
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CrlConfig {
    #[serde(default)]
    pub entries: Vec<CrlEntryConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrlEntryConfig {
    pub rid: String,
    pub ca_pk_index: String,
    pub cert_serial: String,
}

impl CrlConfig {
    pub fn load(path: impl AsRef<Path>) -> Result<Self, ConfigError> {
        Ok(toml::from_str(&fs::read_to_string(path)?)?)
    }

    pub fn parse(s: &str) -> Result<Self, ConfigError> {
        Ok(toml::from_str(s)?)
    }

    pub fn into_kernel(self) -> Result<Vec<CrlEntry>, ConfigError> {
        self.entries.into_iter().map(|e| e.into_kernel()).collect()
    }
}

impl CrlEntryConfig {
    pub fn into_kernel(self) -> Result<CrlEntry, ConfigError> {
        let rid = decode_fixed::<5>("rid", &self.rid)?;
        let ca_pk_index = decode_fixed::<1>("ca_pk_index", &self.ca_pk_index)?[0];
        let cert_serial = decode_fixed::<3>("cert_serial", &self.cert_serial)?;
        Ok(CrlEntry {
            rid,
            ca_pk_index,
            cert_serial,
        })
    }
}

pub fn assemble_terminal(
    terminal: &TerminalConfig,
    aids: &AidsConfig,
) -> Result<Terminal, ConfigError> {
    let terminal_type =
        TerminalType::parse(&decode_hex("terminal_type", &terminal.terminal_type)?)?;
    let terminal_capabilities = TerminalCapabilities::parse(&decode_hex(
        "terminal_capabilities",
        &terminal.terminal_capabilities,
    )?)?;
    let additional_terminal_capabilities = AdditionalTerminalCapabilities::parse(&decode_hex(
        "additional_terminal_capabilities",
        &terminal.additional_terminal_capabilities,
    )?)?;
    let ifd_serial_number =
        pad_or_check_ascii::<8>("ifd_serial_number", &terminal.ifd_serial_number)?;

    let d = &aids.defaults;
    let merchant_identifier = pad_or_check_ascii::<15>(
        "merchant_identifier",
        d.merchant_identifier.as_deref().unwrap_or(""),
    )?;
    let terminal_identification = pad_or_check_ascii::<8>(
        "terminal_identification",
        d.terminal_identification.as_deref().unwrap_or(""),
    )?;
    let merchant_name_and_location = d
        .merchant_name_and_location
        .as_deref()
        .unwrap_or("")
        .as_bytes()
        .to_vec();
    if merchant_name_and_location.len() > 85 {
        return Err(ConfigError::Overflow {
            field: "merchant_name_and_location",
            max: 85,
            got: merchant_name_and_location.len(),
        });
    }
    let acquirer_identifier = d
        .acquirer_identifier
        .as_deref()
        .map(|s| decode_fixed::<6>("acquirer_identifier", s))
        .transpose()?;
    let merchant_category_code = d.merchant_category_code.unwrap_or(0);

    let applications = aids
        .aids
        .iter()
        .map(|e| merge_aid(e, d))
        .collect::<Result<Vec<_>, _>>()?;

    Ok(Terminal {
        terminal_type,
        terminal_capabilities,
        additional_terminal_capabilities,
        terminal_country_code: terminal.terminal_country_code,
        terminal_identification,
        ifd_serial_number,
        merchant_category_code,
        merchant_identifier,
        merchant_name_and_location,
        acquirer_identifier,
        applications,
    })
}

fn decode_hex(field: &'static str, s: &str) -> Result<Vec<u8>, ConfigError> {
    let s = s.trim().replace([' ', '_'], "");
    if !s.len().is_multiple_of(2) {
        return Err(ConfigError::Hex {
            field,
            reason: "odd number of hex digits".into(),
        });
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    for i in (0..s.len()).step_by(2) {
        let byte = u8::from_str_radix(&s[i..i + 2], 16).map_err(|e| ConfigError::Hex {
            field,
            reason: e.to_string(),
        })?;
        out.push(byte);
    }
    Ok(out)
}

fn decode_fixed<const N: usize>(field: &'static str, s: &str) -> Result<[u8; N], ConfigError> {
    let v = decode_hex(field, s)?;
    let got = v.len();
    v.try_into().map_err(|_| ConfigError::WrongLength {
        field,
        expected: N,
        got,
    })
}

fn opt_hex(field: &'static str, s: Option<&str>) -> Result<Option<Vec<u8>>, ConfigError> {
    s.map(|s| decode_hex(field, s)).transpose()
}

fn opt_tac(field: &'static str, s: Option<&str>) -> Result<Option<[u8; 5]>, ConfigError> {
    s.map(|s| decode_fixed::<5>(field, s)).transpose()
}

// Book 4 §4.3 - ANS fields are space-padded.
fn pad_or_check_ascii<const N: usize>(
    field: &'static str,
    s: &str,
) -> Result<[u8; N], ConfigError> {
    let mut buf = [b' '; N];
    let bytes = s.as_bytes();
    if bytes.len() > N {
        return Err(ConfigError::Overflow {
            field,
            max: N,
            got: bytes.len(),
        });
    }
    buf[..bytes.len()].copy_from_slice(bytes);
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_terminal_cfg() -> TerminalConfig {
        TerminalConfig {
            ifd_serial_number: "EMVRSDEM".into(),
            terminal_country_code: 840,
            terminal_type: "22".into(),
            terminal_capabilities: "60A8C8".into(),
            additional_terminal_capabilities: "6000B03000".into(),
        }
    }

    #[test]
    fn terminal_config_parses_and_assembles() {
        let toml = r#"
            ifd_serial_number = "EMVRSDEM"
            terminal_country_code = 840
            terminal_type = "22"
            terminal_capabilities = "60A8C8"
            additional_terminal_capabilities = "6000B03000"
        "#;
        let term = TerminalConfig::parse(toml).unwrap();
        assert_eq!(term.terminal_country_code, 840);
        let aids = AidsConfig::default();
        let kernel = assemble_terminal(&term, &aids).unwrap();
        assert_eq!(kernel.terminal_country_code, 840);
        assert_eq!(&kernel.ifd_serial_number, b"EMVRSDEM");
        assert_eq!(kernel.terminal_type.0, 0x22);
        assert!(kernel.terminal_capabilities.ic_with_contacts);
    }

    #[test]
    fn aids_minimal_inherits_defaults() {
        let toml = r#"
            [defaults]
            partial_match_allowed = true
            tac_denial  = "0000000000"
            tac_online  = "FFFFFFFFFF"
            tac_default = "0000000000"
            default_ddol = "9F3704"

            [[aids]]
            aid = "A0000000031010"
            application_version_number = "008C"
        "#;
        let cfg = AidsConfig::parse(toml).unwrap();
        let apps = cfg.into_applications().unwrap();
        assert_eq!(apps.len(), 1);
        let a = &apps[0];
        assert!(a.partial_match_allowed);
        assert_eq!(a.tac_denial, Some([0; 5]));
        assert_eq!(a.tac_online, Some([0xFF; 5]));
        assert_eq!(a.default_ddol, Some(vec![0x9F, 0x37, 0x04]));
    }

    #[test]
    fn aids_per_row_overrides_defaults() {
        let toml = r#"
            [defaults]
            partial_match_allowed = false
            tac_default = "0000000000"
            terminal_floor_limit = 0

            [[aids]]
            aid = "A0000000031010"
            application_version_number = "008C"
            partial_match_allowed = true
            tac_default = "FFFFFFFFFF"
            terminal_floor_limit = 50000
        "#;
        let cfg = AidsConfig::parse(toml).unwrap();
        let apps = cfg.into_applications().unwrap();
        assert!(apps[0].partial_match_allowed);
        assert_eq!(apps[0].tac_default, Some([0xFF; 5]));
        assert_eq!(apps[0].terminal_floor_limit, 50000);
    }

    #[test]
    fn assemble_pulls_merchant_data_from_aid_defaults() {
        let aids = AidsConfig {
            defaults: AidDefaults {
                merchant_identifier: Some("EMV_RS_DEMO0001".into()),
                merchant_category_code: Some(5999),
                merchant_name_and_location: Some("emv-rs PC/SC test tool".into()),
                terminal_identification: Some("EMVRSDEM".into()),
                acquirer_identifier: Some("000000000001".into()),
                ..Default::default()
            },
            aids: vec![],
        };
        let term = assemble_terminal(&sample_terminal_cfg(), &aids).unwrap();
        assert_eq!(&term.merchant_identifier, b"EMV_RS_DEMO0001");
        assert_eq!(term.merchant_category_code, 5999);
        assert_eq!(&term.terminal_identification, b"EMVRSDEM");
        assert_eq!(term.acquirer_identifier, Some([0, 0, 0, 0, 0, 1]));
    }

    #[test]
    fn assemble_pads_short_ascii_fields_with_spaces() {
        let aids = AidsConfig {
            defaults: AidDefaults {
                merchant_identifier: Some("SHORT".into()),
                terminal_identification: Some("AB".into()),
                ..Default::default()
            },
            aids: vec![],
        };
        let term = assemble_terminal(&sample_terminal_cfg(), &aids).unwrap();
        assert_eq!(&term.merchant_identifier, b"SHORT          ");
        assert_eq!(&term.terminal_identification, b"AB      ");
    }

    #[test]
    fn assemble_rejects_overlong_ascii_field() {
        let aids = AidsConfig {
            defaults: AidDefaults {
                terminal_identification: Some("TOOLONGFIELD".into()),
                ..Default::default()
            },
            aids: vec![],
        };
        match assemble_terminal(&sample_terminal_cfg(), &aids) {
            Err(ConfigError::Overflow { field, max, got }) => {
                assert_eq!(field, "terminal_identification");
                assert_eq!(max, 8);
                assert_eq!(got, 12);
            }
            other => panic!("expected Overflow, got {:?}", other),
        }
    }

    #[test]
    fn aids_aid_too_short_errors() {
        let toml = r#"
            [[aids]]
            aid = "A000"
            application_version_number = "008C"
        "#;
        let cfg = AidsConfig::parse(toml).unwrap();
        match cfg.into_applications() {
            Err(ConfigError::WrongLength {
                field,
                expected,
                got,
            }) => {
                assert_eq!(field, "aid");
                assert_eq!(expected, 5);
                assert_eq!(got, 2);
            }
            other => panic!("expected WrongLength, got {:?}", other),
        }
    }

    #[test]
    fn aids_invalid_hex_errors() {
        let toml = r#"
            [[aids]]
            aid = "A0000000031G10"
            application_version_number = "008C"
        "#;
        let cfg = AidsConfig::parse(toml).unwrap();
        match cfg.into_applications() {
            Err(ConfigError::Hex { field, .. }) => assert_eq!(field, "aid"),
            other => panic!("expected Hex, got {:?}", other),
        }
    }

    #[test]
    fn capk_rsa_roundtrip() {
        let toml = r#"
            [[capk_rsa]]
            rid = "A000000003"
            index = "92"
            modulus = "996AF56F569187D09293"
            exponent = "03"
        "#;
        let cfg = CapkConfig::parse(toml).unwrap();
        let (rsa, ecc) = cfg.into_kernel().unwrap();
        assert_eq!(ecc.len(), 0);
        assert_eq!(rsa.len(), 1);
        assert_eq!(rsa[0].rid, [0xA0, 0, 0, 0, 0x03]);
        assert_eq!(rsa[0].index, 0x92);
        assert_eq!(rsa[0].exponent, vec![0x03]);
        assert_eq!(rsa[0].modulus.len(), 10);
    }

    #[test]
    fn capk_ecc_roundtrip() {
        let toml = r#"
            [[capk_ecc]]
            rid = "A000000003"
            index = "01"
            algorithm_suite = "01"
            x_coord = "0000000000000000000000000000000000000000000000000000000000000001"
        "#;
        let cfg = CapkConfig::parse(toml).unwrap();
        let (rsa, ecc) = cfg.into_kernel().unwrap();
        assert_eq!(rsa.len(), 0);
        assert_eq!(ecc.len(), 1);
        assert_eq!(ecc[0].rid, [0xA0, 0, 0, 0, 0x03]);
        assert_eq!(ecc[0].index, 0x01);
        assert_eq!(ecc[0].algorithm_suite, 0x01);
        assert_eq!(ecc[0].x_coord.len(), 32);
    }

    #[test]
    fn crl_empty_config_yields_empty_list() {
        let cfg = CrlConfig::parse("").unwrap();
        let entries = cfg.into_kernel().unwrap();
        assert!(entries.is_empty());
    }

    #[test]
    fn crl_roundtrip_single_entry() {
        let toml = r#"
            [[entries]]
            rid = "A000000003"
            ca_pk_index = "92"
            cert_serial = "9E11FA"
        "#;
        let cfg = CrlConfig::parse(toml).unwrap();
        let entries = cfg.into_kernel().unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].rid, [0xA0, 0, 0, 0, 0x03]);
        assert_eq!(entries[0].ca_pk_index, 0x92);
        assert_eq!(entries[0].cert_serial, [0x9E, 0x11, 0xFA]);
    }

    #[test]
    fn crl_multiple_entries_preserve_order() {
        let toml = r#"
            [[entries]]
            rid = "A000000003"
            ca_pk_index = "92"
            cert_serial = "111111"

            [[entries]]
            rid = "A000000004"
            ca_pk_index = "FE"
            cert_serial = "222222"
        "#;
        let entries = CrlConfig::parse(toml).unwrap().into_kernel().unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].cert_serial, [0x11, 0x11, 0x11]);
        assert_eq!(entries[1].rid, [0xA0, 0, 0, 0, 0x04]);
        assert_eq!(entries[1].ca_pk_index, 0xFE);
    }

    #[test]
    fn crl_serial_wrong_length_errors() {
        let toml = r#"
            [[entries]]
            rid = "A000000003"
            ca_pk_index = "92"
            cert_serial = "1122"
        "#;
        let err = CrlConfig::parse(toml).unwrap().into_kernel().unwrap_err();
        assert!(matches!(
            err,
            ConfigError::WrongLength {
                field: "cert_serial",
                expected: 3,
                got: 2,
            }
        ));
    }

    #[test]
    fn capk_mixed_rsa_and_ecc() {
        let toml = r#"
            [[capk_rsa]]
            rid = "A000000003"
            index = "92"
            modulus = "AABB"
            exponent = "03"

            [[capk_ecc]]
            rid = "A000000003"
            index = "01"
            algorithm_suite = "01"
            x_coord = "0000000000000000000000000000000000000000000000000000000000000001"
        "#;
        let cfg = CapkConfig::parse(toml).unwrap();
        let (rsa, ecc) = cfg.into_kernel().unwrap();
        assert_eq!(rsa.len(), 1);
        assert_eq!(ecc.len(), 1);
    }

    #[test]
    fn capk_rid_wrong_length_errors() {
        let toml = r#"
            [[capk_rsa]]
            rid = "A0000003"
            index = "92"
            modulus = "AABB"
            exponent = "03"
        "#;
        let cfg = CapkConfig::parse(toml).unwrap();
        match cfg.into_kernel() {
            Err(ConfigError::WrongLength { field, .. }) => assert_eq!(field, "rid"),
            other => panic!("expected WrongLength on rid, got {:?}", other),
        }
    }

    #[test]
    fn empty_capk_config_yields_empty_lists() {
        let cfg = CapkConfig::parse("").unwrap();
        let (rsa, ecc) = cfg.into_kernel().unwrap();
        assert!(rsa.is_empty());
        assert!(ecc.is_empty());
    }

    #[test]
    fn whitespace_in_hex_strings_is_tolerated() {
        let toml = r#"
            [[capk_rsa]]
            rid = "A0 00 00 00 03"
            index = "92"
            modulus = "AA_BB CC DD"
            exponent = "01 00 01"
        "#;
        let cfg = CapkConfig::parse(toml).unwrap();
        let (rsa, _) = cfg.into_kernel().unwrap();
        assert_eq!(rsa[0].rid, [0xA0, 0, 0, 0, 0x03]);
        assert_eq!(rsa[0].modulus, [0xAA, 0xBB, 0xCC, 0xDD]);
        assert_eq!(rsa[0].exponent, vec![0x01, 0x00, 0x01]);
    }
}
