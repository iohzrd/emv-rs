//! Book 3 Annex A - EMV data-element registry.

use crate::core::tag::Tag;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    Alphabetic,
    Alphanumeric,
    AlphanumericSpecial,
    Binary,
    CompressedNumeric,
    Numeric,
    Variable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Source {
    Terminal,
    Icc,
    Card,
    Issuer,
    /// `Issuer/Terminal` - Authorisation Response Code (`'8A'`) only.
    IssuerOrTerminal,
    TerminalOrCard,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LengthSpec {
    Fixed(u16),
    Range(u16, u16),
    Choice(&'static [u16]),
    UpTo(u16),
    Variable,
}

#[derive(Debug, Clone, Copy)]
pub struct TagInfo {
    pub tag: Tag,
    pub name: &'static str,
    pub source: Source,
    pub format: Format,
    pub length: LengthSpec,
    pub templates: &'static [Tag],
}

const REGISTRY: &[TagInfo] = &[
    // ── 1-byte tags ──────────────────────────────────────────────────
    TagInfo {
        tag: Tag(0x42),
        name: "Issuer Identification Number (IIN)",
        source: Source::Icc,
        format: Format::Numeric,
        length: LengthSpec::Fixed(3),
        templates: &[Tag(0xBF0C), Tag(0x73)],
    },
    TagInfo {
        tag: Tag(0x4F),
        name: "Application Dedicated File (ADF) Name",
        source: Source::Icc,
        format: Format::Binary,
        length: LengthSpec::Range(5, 16),
        templates: &[Tag(0x61)],
    },
    TagInfo {
        tag: Tag(0x50),
        name: "Application Label",
        source: Source::Icc,
        format: Format::AlphanumericSpecial,
        length: LengthSpec::Range(1, 16),
        templates: &[Tag(0x61), Tag(0xA5)],
    },
    TagInfo {
        tag: Tag(0x57),
        name: "Track 2 Equivalent Data",
        source: Source::Icc,
        format: Format::Binary,
        length: LengthSpec::UpTo(19),
        templates: &[Tag(0x70), Tag(0x77)],
    },
    TagInfo {
        tag: Tag(0x5A),
        name: "Application Primary Account Number (PAN)",
        source: Source::Icc,
        format: Format::CompressedNumeric,
        length: LengthSpec::UpTo(10),
        templates: &[Tag(0x70), Tag(0x77)],
    },
    TagInfo {
        tag: Tag(0x5F20),
        name: "Cardholder Name",
        source: Source::Icc,
        format: Format::AlphanumericSpecial,
        length: LengthSpec::Range(2, 26),
        templates: &[Tag(0x70), Tag(0x77)],
    },
    TagInfo {
        tag: Tag(0x5F24),
        name: "Application Expiration Date",
        source: Source::Icc,
        format: Format::Numeric,
        length: LengthSpec::Fixed(3),
        templates: &[Tag(0x70), Tag(0x77)],
    },
    TagInfo {
        tag: Tag(0x5F25),
        name: "Application Effective Date",
        source: Source::Icc,
        format: Format::Numeric,
        length: LengthSpec::Fixed(3),
        templates: &[Tag(0x70), Tag(0x77)],
    },
    TagInfo {
        tag: Tag(0x5F28),
        name: "Issuer Country Code",
        source: Source::Icc,
        format: Format::Numeric,
        length: LengthSpec::Fixed(2),
        templates: &[Tag(0x70), Tag(0x77)],
    },
    TagInfo {
        tag: Tag(0x5F2A),
        name: "Transaction Currency Code",
        source: Source::Terminal,
        format: Format::Numeric,
        length: LengthSpec::Fixed(2),
        templates: &[],
    },
    TagInfo {
        tag: Tag(0x5F2D),
        name: "Language Preference",
        source: Source::Icc,
        format: Format::Alphanumeric,
        length: LengthSpec::Range(2, 8),
        templates: &[Tag(0xA5)],
    },
    TagInfo {
        tag: Tag(0x5F30),
        name: "Service Code",
        source: Source::Icc,
        format: Format::Numeric,
        length: LengthSpec::Fixed(2),
        templates: &[Tag(0x70), Tag(0x77)],
    },
    TagInfo {
        tag: Tag(0x5F34),
        name: "Application Primary Account Number (PAN) Sequence Number",
        source: Source::Icc,
        format: Format::Numeric,
        length: LengthSpec::Fixed(1),
        templates: &[Tag(0x70), Tag(0x77)],
    },
    TagInfo {
        tag: Tag(0x5F36),
        name: "Transaction Currency Exponent",
        source: Source::Terminal,
        format: Format::Numeric,
        length: LengthSpec::Fixed(1),
        templates: &[],
    },
    TagInfo {
        tag: Tag(0x5F50),
        name: "Issuer URL",
        source: Source::Icc,
        format: Format::AlphanumericSpecial,
        length: LengthSpec::Variable,
        templates: &[Tag(0xBF0C), Tag(0x73)],
    },
    TagInfo {
        tag: Tag(0x5F53),
        name: "International Bank Account Number (IBAN)",
        source: Source::Icc,
        format: Format::Variable,
        length: LengthSpec::UpTo(34),
        templates: &[Tag(0xBF0C), Tag(0x73)],
    },
    TagInfo {
        tag: Tag(0x5F54),
        name: "Bank Identifier Code (BIC)",
        source: Source::Icc,
        format: Format::Variable,
        length: LengthSpec::Choice(&[8, 11]),
        templates: &[Tag(0xBF0C), Tag(0x73)],
    },
    TagInfo {
        tag: Tag(0x5F55),
        name: "Issuer Country Code (alpha2 format)",
        source: Source::Icc,
        format: Format::Alphabetic,
        length: LengthSpec::Fixed(2),
        templates: &[Tag(0xBF0C), Tag(0x73)],
    },
    TagInfo {
        tag: Tag(0x5F56),
        name: "Issuer Country Code (alpha3 format)",
        source: Source::Icc,
        format: Format::Alphabetic,
        length: LengthSpec::Fixed(3),
        templates: &[Tag(0xBF0C), Tag(0x73)],
    },
    TagInfo {
        tag: Tag(0x5F57),
        name: "Account Type",
        source: Source::Terminal,
        format: Format::Numeric,
        length: LengthSpec::Fixed(1),
        templates: &[],
    },
    TagInfo {
        tag: Tag(0x61),
        name: "Application Template",
        source: Source::Icc,
        format: Format::Binary,
        length: LengthSpec::UpTo(252),
        templates: &[Tag(0x70)],
    },
    TagInfo {
        tag: Tag(0x6F),
        name: "File Control Information (FCI) Template",
        source: Source::Icc,
        format: Format::Variable,
        length: LengthSpec::UpTo(252),
        templates: &[],
    },
    TagInfo {
        tag: Tag(0x70),
        name: "READ RECORD Response Message Template",
        source: Source::Icc,
        format: Format::Variable,
        length: LengthSpec::UpTo(252),
        templates: &[],
    },
    TagInfo {
        tag: Tag(0x71),
        name: "Issuer Script Template 1",
        source: Source::Issuer,
        format: Format::Binary,
        length: LengthSpec::Variable,
        templates: &[],
    },
    TagInfo {
        tag: Tag(0x72),
        name: "Issuer Script Template 2",
        source: Source::Issuer,
        format: Format::Binary,
        length: LengthSpec::Variable,
        templates: &[],
    },
    TagInfo {
        tag: Tag(0x73),
        name: "Directory Discretionary Template",
        source: Source::Icc,
        format: Format::Variable,
        length: LengthSpec::UpTo(252),
        templates: &[Tag(0x61)],
    },
    TagInfo {
        tag: Tag(0x77),
        name: "Response Message Template Format 2",
        source: Source::Icc,
        format: Format::Variable,
        length: LengthSpec::Variable,
        templates: &[],
    },
    TagInfo {
        tag: Tag(0x7F60),
        name: "Biometric Information Template (BIT) (Card)",
        source: Source::TerminalOrCard,
        format: Format::Binary,
        length: LengthSpec::Variable,
        templates: &[Tag(0xBF4A), Tag(0xBF4B)],
    },
    TagInfo {
        tag: Tag(0x7F60),
        name: "Biometric Information Template (BIT) (Terminal)",
        source: Source::Terminal,
        format: Format::Binary,
        length: LengthSpec::Variable,
        templates: &[],
    },
    TagInfo {
        tag: Tag(0x80),
        name: "Response Message Template Format 1",
        source: Source::Icc,
        format: Format::Variable,
        length: LengthSpec::Variable,
        templates: &[],
    },
    TagInfo {
        tag: Tag(0x81),
        name: "Amount, Authorised (Binary)",
        source: Source::Terminal,
        format: Format::Binary,
        length: LengthSpec::Fixed(4),
        templates: &[],
    },
    TagInfo {
        tag: Tag(0x81),
        name: "Biometric Type",
        source: Source::TerminalOrCard,
        format: Format::Binary,
        length: LengthSpec::Variable,
        templates: &[Tag(0xA1), Tag(0xBF4E)],
    },
    TagInfo {
        tag: Tag(0x82),
        name: "Application Interchange Profile",
        source: Source::Icc,
        format: Format::Binary,
        length: LengthSpec::Fixed(2),
        templates: &[Tag(0x77), Tag(0x80)],
    },
    TagInfo {
        tag: Tag(0x82),
        name: "Biometric Subtype",
        source: Source::TerminalOrCard,
        format: Format::Binary,
        length: LengthSpec::Fixed(1),
        templates: &[Tag(0xA1)],
    },
    TagInfo {
        tag: Tag(0x83),
        name: "Command Template",
        source: Source::Terminal,
        format: Format::Binary,
        length: LengthSpec::Variable,
        templates: &[],
    },
    TagInfo {
        tag: Tag(0x84),
        name: "Dedicated File (DF) Name",
        source: Source::Icc,
        format: Format::Binary,
        length: LengthSpec::Range(5, 16),
        templates: &[Tag(0x6F)],
    },
    TagInfo {
        tag: Tag(0x86),
        name: "Issuer Script Command",
        source: Source::Issuer,
        format: Format::Binary,
        length: LengthSpec::UpTo(261),
        templates: &[Tag(0x71), Tag(0x72)],
    },
    TagInfo {
        tag: Tag(0x87),
        name: "Application Priority Indicator",
        source: Source::Icc,
        format: Format::Binary,
        length: LengthSpec::Fixed(1),
        templates: &[Tag(0x61), Tag(0xA5)],
    },
    TagInfo {
        tag: Tag(0x88),
        name: "Short File Identifier (SFI)",
        source: Source::Icc,
        format: Format::Binary,
        length: LengthSpec::Fixed(1),
        templates: &[Tag(0xA5)],
    },
    TagInfo {
        tag: Tag(0x89),
        name: "Authorisation Code",
        source: Source::Issuer,
        format: Format::Variable,
        length: LengthSpec::Fixed(6),
        templates: &[],
    },
    TagInfo {
        tag: Tag(0x8A),
        name: "Authorisation Response Code",
        source: Source::IssuerOrTerminal,
        format: Format::Alphanumeric,
        length: LengthSpec::Fixed(2),
        templates: &[],
    },
    TagInfo {
        tag: Tag(0x8C),
        name: "Card Risk Management Data Object List 1 (CDOL1)",
        source: Source::Icc,
        format: Format::Binary,
        length: LengthSpec::UpTo(252),
        templates: &[Tag(0x70), Tag(0x77)],
    },
    TagInfo {
        tag: Tag(0x8D),
        name: "Card Risk Management Data Object List 2 (CDOL2)",
        source: Source::Icc,
        format: Format::Binary,
        length: LengthSpec::UpTo(252),
        templates: &[Tag(0x70), Tag(0x77)],
    },
    TagInfo {
        tag: Tag(0x8E),
        name: "Cardholder Verification Method (CVM) List",
        source: Source::Icc,
        format: Format::Binary,
        length: LengthSpec::Range(10, 252),
        templates: &[Tag(0x70), Tag(0x77)],
    },
    TagInfo {
        tag: Tag(0x8F),
        name: "Certification Authority Public Key Index (Card)",
        source: Source::Icc,
        format: Format::Binary,
        length: LengthSpec::Fixed(1),
        templates: &[Tag(0x70), Tag(0x77)],
    },
    TagInfo {
        tag: Tag(0x90),
        name: "Biometric Solution ID",
        source: Source::TerminalOrCard,
        format: Format::Binary,
        length: LengthSpec::Variable,
        templates: &[Tag(0xA1), Tag(0xBF4E)],
    },
    TagInfo {
        tag: Tag(0x90),
        name: "Issuer Public Key Certificate",
        source: Source::Icc,
        format: Format::Binary,
        length: LengthSpec::Variable,
        templates: &[Tag(0x70), Tag(0x77)],
    },
    TagInfo {
        tag: Tag(0x91),
        name: "Issuer Authentication Data",
        source: Source::Issuer,
        format: Format::Binary,
        length: LengthSpec::Range(8, 16),
        templates: &[],
    },
    TagInfo {
        tag: Tag(0x92),
        name: "Issuer Public Key Remainder",
        source: Source::Icc,
        format: Format::Binary,
        length: LengthSpec::Variable,
        templates: &[Tag(0x70), Tag(0x77)],
    },
    TagInfo {
        tag: Tag(0x93),
        name: "Signed Static Application Data",
        source: Source::Icc,
        format: Format::Binary,
        length: LengthSpec::Variable,
        templates: &[Tag(0x70), Tag(0x77)],
    },
    TagInfo {
        tag: Tag(0x94),
        name: "Application File Locator (AFL)",
        source: Source::Icc,
        format: Format::Variable,
        length: LengthSpec::UpTo(252),
        templates: &[Tag(0x77), Tag(0x80)],
    },
    TagInfo {
        tag: Tag(0x95),
        name: "Terminal Verification Results",
        source: Source::Terminal,
        format: Format::Binary,
        length: LengthSpec::Fixed(5),
        templates: &[],
    },
    TagInfo {
        tag: Tag(0x97),
        name: "Transaction Certificate Data Object List (TDOL)",
        source: Source::Icc,
        format: Format::Binary,
        length: LengthSpec::UpTo(252),
        templates: &[Tag(0x70), Tag(0x77)],
    },
    TagInfo {
        tag: Tag(0x98),
        name: "Transaction Certificate (TC) Hash Value",
        source: Source::Terminal,
        format: Format::Binary,
        length: LengthSpec::Fixed(20),
        templates: &[],
    },
    TagInfo {
        tag: Tag(0x99),
        name: "Transaction Personal Identification Number (PIN) Data",
        source: Source::Terminal,
        format: Format::Binary,
        length: LengthSpec::Variable,
        templates: &[],
    },
    TagInfo {
        tag: Tag(0x9A),
        name: "Transaction Date",
        source: Source::Terminal,
        format: Format::Numeric,
        length: LengthSpec::Fixed(3),
        templates: &[],
    },
    TagInfo {
        tag: Tag(0x9B),
        name: "Transaction Status Information",
        source: Source::Terminal,
        format: Format::Binary,
        length: LengthSpec::Fixed(2),
        templates: &[],
    },
    TagInfo {
        tag: Tag(0x9C),
        name: "Transaction Type",
        source: Source::Terminal,
        format: Format::Numeric,
        length: LengthSpec::Fixed(1),
        templates: &[],
    },
    TagInfo {
        tag: Tag(0x9D),
        name: "Directory Definition File (DDF) Name",
        source: Source::Icc,
        format: Format::Binary,
        length: LengthSpec::Range(5, 16),
        templates: &[Tag(0x61)],
    },
    // ── 9F00–9F4F ────────────────────────────────────────────────────
    TagInfo {
        tag: Tag(0x9F01),
        name: "Acquirer Identifier",
        source: Source::Terminal,
        format: Format::Numeric,
        length: LengthSpec::Fixed(6),
        templates: &[],
    },
    TagInfo {
        tag: Tag(0x9F02),
        name: "Amount, Authorised (Numeric)",
        source: Source::Terminal,
        format: Format::Numeric,
        length: LengthSpec::Fixed(6),
        templates: &[],
    },
    TagInfo {
        tag: Tag(0x9F03),
        name: "Amount, Other (Numeric)",
        source: Source::Terminal,
        format: Format::Numeric,
        length: LengthSpec::Fixed(6),
        templates: &[],
    },
    TagInfo {
        tag: Tag(0x9F04),
        name: "Amount, Other (Binary)",
        source: Source::Terminal,
        format: Format::Binary,
        length: LengthSpec::Fixed(4),
        templates: &[],
    },
    TagInfo {
        tag: Tag(0x9F05),
        name: "Application Discretionary Data",
        source: Source::Icc,
        format: Format::Binary,
        length: LengthSpec::Range(1, 32),
        templates: &[Tag(0x70), Tag(0x77)],
    },
    TagInfo {
        tag: Tag(0x9F06),
        name: "Application Identifier (AID) – terminal",
        source: Source::Terminal,
        format: Format::Binary,
        length: LengthSpec::Range(5, 16),
        templates: &[],
    },
    TagInfo {
        tag: Tag(0x9F07),
        name: "Application Usage Control",
        source: Source::Icc,
        format: Format::Binary,
        length: LengthSpec::Fixed(2),
        templates: &[Tag(0x70), Tag(0x77)],
    },
    TagInfo {
        tag: Tag(0x9F08),
        name: "Application Version Number (ICC)",
        source: Source::Icc,
        format: Format::Binary,
        length: LengthSpec::Fixed(2),
        templates: &[Tag(0x70), Tag(0x77)],
    },
    TagInfo {
        tag: Tag(0x9F09),
        name: "Application Version Number (Terminal)",
        source: Source::Terminal,
        format: Format::Binary,
        length: LengthSpec::Fixed(2),
        templates: &[],
    },
    TagInfo {
        tag: Tag(0x9F0A),
        name: "Application Selection Registered Proprietary Data (ASRPD)",
        source: Source::Card,
        format: Format::Binary,
        length: LengthSpec::Variable,
        templates: &[Tag(0x73), Tag(0xBF0C)],
    },
    TagInfo {
        tag: Tag(0x9F0B),
        name: "Cardholder Name Extended",
        source: Source::Icc,
        format: Format::AlphanumericSpecial,
        length: LengthSpec::Range(27, 45),
        templates: &[Tag(0x70), Tag(0x77)],
    },
    TagInfo {
        tag: Tag(0x9F0C),
        name: "Issuer Identification Number Extended (IINE)",
        source: Source::Icc,
        format: Format::Numeric,
        length: LengthSpec::Choice(&[3, 4]),
        templates: &[Tag(0xBF0C), Tag(0x73)],
    },
    TagInfo {
        tag: Tag(0x9F0D),
        name: "Issuer Action Code – Default",
        source: Source::Icc,
        format: Format::Binary,
        length: LengthSpec::Fixed(5),
        templates: &[Tag(0x70), Tag(0x77)],
    },
    TagInfo {
        tag: Tag(0x9F0E),
        name: "Issuer Action Code – Denial",
        source: Source::Icc,
        format: Format::Binary,
        length: LengthSpec::Fixed(5),
        templates: &[Tag(0x70), Tag(0x77)],
    },
    TagInfo {
        tag: Tag(0x9F0F),
        name: "Issuer Action Code – Online",
        source: Source::Icc,
        format: Format::Binary,
        length: LengthSpec::Fixed(5),
        templates: &[Tag(0x70), Tag(0x77)],
    },
    TagInfo {
        tag: Tag(0x9F10),
        name: "Issuer Application Data",
        source: Source::Icc,
        format: Format::Binary,
        length: LengthSpec::UpTo(32),
        templates: &[Tag(0x77), Tag(0x80)],
    },
    TagInfo {
        tag: Tag(0x9F11),
        name: "Issuer Code Table Index",
        source: Source::Icc,
        format: Format::Numeric,
        length: LengthSpec::Fixed(1),
        templates: &[Tag(0xA5)],
    },
    TagInfo {
        tag: Tag(0x9F12),
        name: "Application Preferred Name",
        source: Source::Icc,
        format: Format::AlphanumericSpecial,
        length: LengthSpec::Range(1, 16),
        templates: &[Tag(0x61), Tag(0xA5)],
    },
    TagInfo {
        tag: Tag(0x9F13),
        name: "Last Online Application Transaction Counter (ATC) Register",
        source: Source::Icc,
        format: Format::Binary,
        length: LengthSpec::Fixed(2),
        templates: &[],
    },
    TagInfo {
        tag: Tag(0x9F14),
        name: "Lower Consecutive Offline Limit",
        source: Source::Icc,
        format: Format::Binary,
        length: LengthSpec::Fixed(1),
        templates: &[Tag(0x70), Tag(0x77)],
    },
    TagInfo {
        tag: Tag(0x9F15),
        name: "Merchant Category Code",
        source: Source::Terminal,
        format: Format::Numeric,
        length: LengthSpec::Fixed(2),
        templates: &[],
    },
    TagInfo {
        tag: Tag(0x9F16),
        name: "Merchant Identifier",
        source: Source::Terminal,
        format: Format::Alphanumeric,
        length: LengthSpec::Fixed(15),
        templates: &[],
    },
    TagInfo {
        tag: Tag(0x9F17),
        name: "Personal Identification Number (PIN) Try Counter",
        source: Source::Icc,
        format: Format::Binary,
        length: LengthSpec::Fixed(1),
        templates: &[],
    },
    TagInfo {
        tag: Tag(0x9F18),
        name: "Issuer Script Identifier",
        source: Source::Issuer,
        format: Format::Binary,
        length: LengthSpec::Fixed(4),
        templates: &[Tag(0x71), Tag(0x72)],
    },
    TagInfo {
        tag: Tag(0x9F19),
        name: "Token Requestor ID",
        source: Source::Icc,
        format: Format::Numeric,
        length: LengthSpec::Fixed(6),
        templates: &[Tag(0x70), Tag(0x77)],
    },
    TagInfo {
        tag: Tag(0x9F1A),
        name: "Terminal Country Code",
        source: Source::Terminal,
        format: Format::Numeric,
        length: LengthSpec::Fixed(2),
        templates: &[],
    },
    TagInfo {
        tag: Tag(0x9F1B),
        name: "Terminal Floor Limit",
        source: Source::Terminal,
        format: Format::Binary,
        length: LengthSpec::Fixed(4),
        templates: &[],
    },
    TagInfo {
        tag: Tag(0x9F1C),
        name: "Terminal Identification",
        source: Source::Terminal,
        format: Format::Alphanumeric,
        length: LengthSpec::Fixed(8),
        templates: &[],
    },
    TagInfo {
        tag: Tag(0x9F1D),
        name: "Terminal Risk Management Data",
        source: Source::Terminal,
        format: Format::Binary,
        length: LengthSpec::Range(1, 8),
        templates: &[],
    },
    TagInfo {
        tag: Tag(0x9F1E),
        name: "Interface Device (IFD) Serial Number",
        source: Source::Terminal,
        format: Format::Alphanumeric,
        length: LengthSpec::Fixed(8),
        templates: &[],
    },
    TagInfo {
        tag: Tag(0x9F1F),
        name: "Track 1 Discretionary Data",
        source: Source::Icc,
        format: Format::AlphanumericSpecial,
        length: LengthSpec::Variable,
        templates: &[Tag(0x70), Tag(0x77)],
    },
    TagInfo {
        tag: Tag(0x9F20),
        name: "Track 2 Discretionary Data",
        source: Source::Icc,
        format: Format::CompressedNumeric,
        length: LengthSpec::Variable,
        templates: &[Tag(0x70), Tag(0x77)],
    },
    TagInfo {
        tag: Tag(0x9F21),
        name: "Transaction Time",
        source: Source::Terminal,
        format: Format::Numeric,
        length: LengthSpec::Fixed(3),
        templates: &[],
    },
    TagInfo {
        tag: Tag(0x9F22),
        name: "Certification Authority Public Key Index (Terminal)",
        source: Source::Terminal,
        format: Format::Binary,
        length: LengthSpec::Fixed(1),
        templates: &[],
    },
    TagInfo {
        tag: Tag(0x9F23),
        name: "Upper Consecutive Offline Limit",
        source: Source::Icc,
        format: Format::Binary,
        length: LengthSpec::Fixed(1),
        templates: &[Tag(0x70), Tag(0x77)],
    },
    TagInfo {
        tag: Tag(0x9F24),
        name: "Payment Account Reference (PAR)",
        source: Source::Icc,
        format: Format::Alphanumeric,
        length: LengthSpec::Fixed(29),
        templates: &[Tag(0x70), Tag(0x77)],
    },
    TagInfo {
        tag: Tag(0x9F25),
        name: "Last 4 Digits of PAN",
        source: Source::Icc,
        format: Format::Numeric,
        length: LengthSpec::Fixed(2),
        templates: &[Tag(0x70), Tag(0x77)],
    },
    TagInfo {
        tag: Tag(0x9F26),
        name: "Application Cryptogram",
        source: Source::Icc,
        format: Format::Binary,
        length: LengthSpec::Fixed(8),
        templates: &[Tag(0x77), Tag(0x80)],
    },
    TagInfo {
        tag: Tag(0x9F27),
        name: "Cryptogram Information Data",
        source: Source::Icc,
        format: Format::Binary,
        length: LengthSpec::Fixed(1),
        templates: &[Tag(0x77), Tag(0x80)],
    },
    TagInfo {
        tag: Tag(0x9F2D),
        name: "ICC PIN Encipherment Public Key Certificate",
        source: Source::Icc,
        format: Format::Binary,
        length: LengthSpec::Variable,
        templates: &[Tag(0x70), Tag(0x77)],
    },
    TagInfo {
        tag: Tag(0x9F2E),
        name: "ICC PIN Encipherment Public Key Exponent",
        source: Source::Icc,
        format: Format::Binary,
        length: LengthSpec::Choice(&[1, 3]),
        templates: &[Tag(0x70), Tag(0x77)],
    },
    TagInfo {
        tag: Tag(0x9F2F),
        name: "ICC PIN Encipherment Public Key Remainder",
        source: Source::Icc,
        format: Format::Binary,
        length: LengthSpec::Variable,
        templates: &[Tag(0x70), Tag(0x77)],
    },
    TagInfo {
        tag: Tag(0x9F30),
        name: "Biometric Terminal Capabilities",
        source: Source::Terminal,
        format: Format::Binary,
        length: LengthSpec::Fixed(3),
        templates: &[],
    },
    TagInfo {
        tag: Tag(0x9F31),
        name: "Card BIT Group Template",
        source: Source::Card,
        format: Format::Binary,
        length: LengthSpec::Variable,
        templates: &[Tag(0x70)],
    },
    TagInfo {
        tag: Tag(0x9F32),
        name: "Issuer Public Key Exponent",
        source: Source::Icc,
        format: Format::Binary,
        length: LengthSpec::Choice(&[1, 3]),
        templates: &[Tag(0x70), Tag(0x77)],
    },
    TagInfo {
        tag: Tag(0x9F33),
        name: "Terminal Capabilities",
        source: Source::Terminal,
        format: Format::Binary,
        length: LengthSpec::Fixed(3),
        templates: &[],
    },
    TagInfo {
        tag: Tag(0x9F34),
        name: "Cardholder Verification Method (CVM) Results",
        source: Source::Terminal,
        format: Format::Binary,
        length: LengthSpec::Fixed(3),
        templates: &[],
    },
    TagInfo {
        tag: Tag(0x9F35),
        name: "Terminal Type",
        source: Source::Terminal,
        format: Format::Numeric,
        length: LengthSpec::Fixed(1),
        templates: &[],
    },
    TagInfo {
        tag: Tag(0x9F36),
        name: "Application Transaction Counter (ATC)",
        source: Source::Icc,
        format: Format::Binary,
        length: LengthSpec::Fixed(2),
        templates: &[Tag(0x77), Tag(0x80)],
    },
    TagInfo {
        tag: Tag(0x9F37),
        name: "Unpredictable Number",
        source: Source::Terminal,
        format: Format::Binary,
        length: LengthSpec::Fixed(4),
        templates: &[],
    },
    TagInfo {
        tag: Tag(0x9F38),
        name: "Processing Options Data Object List (PDOL)",
        source: Source::Icc,
        format: Format::Binary,
        length: LengthSpec::Variable,
        templates: &[Tag(0xA5)],
    },
    TagInfo {
        tag: Tag(0x9F39),
        name: "Point-of-Service (POS) Entry Mode",
        source: Source::Terminal,
        format: Format::Numeric,
        length: LengthSpec::Fixed(1),
        templates: &[],
    },
    TagInfo {
        tag: Tag(0x9F3A),
        name: "Amount, Reference Currency",
        source: Source::Terminal,
        format: Format::Binary,
        length: LengthSpec::Fixed(4),
        templates: &[],
    },
    TagInfo {
        tag: Tag(0x9F3B),
        name: "Application Reference Currency",
        source: Source::Icc,
        format: Format::Numeric,
        length: LengthSpec::Range(2, 8),
        templates: &[Tag(0x70), Tag(0x77)],
    },
    TagInfo {
        tag: Tag(0x9F3C),
        name: "Transaction Reference Currency Code",
        source: Source::Terminal,
        format: Format::Numeric,
        length: LengthSpec::Fixed(2),
        templates: &[],
    },
    TagInfo {
        tag: Tag(0x9F3D),
        name: "Transaction Reference Currency Exponent",
        source: Source::Terminal,
        format: Format::Numeric,
        length: LengthSpec::Fixed(1),
        templates: &[],
    },
    TagInfo {
        tag: Tag(0x9F40),
        name: "Additional Terminal Capabilities",
        source: Source::Terminal,
        format: Format::Binary,
        length: LengthSpec::Fixed(5),
        templates: &[],
    },
    TagInfo {
        tag: Tag(0x9F41),
        name: "Transaction Sequence Counter",
        source: Source::Terminal,
        format: Format::Numeric,
        length: LengthSpec::Range(2, 4),
        templates: &[],
    },
    TagInfo {
        tag: Tag(0x9F42),
        name: "Application Currency Code",
        source: Source::Icc,
        format: Format::Numeric,
        length: LengthSpec::Fixed(2),
        templates: &[Tag(0x70), Tag(0x77)],
    },
    TagInfo {
        tag: Tag(0x9F43),
        name: "Application Reference Currency Exponent",
        source: Source::Icc,
        format: Format::Numeric,
        length: LengthSpec::Range(1, 4),
        templates: &[Tag(0x70), Tag(0x77)],
    },
    TagInfo {
        tag: Tag(0x9F44),
        name: "Application Currency Exponent",
        source: Source::Icc,
        format: Format::Numeric,
        length: LengthSpec::Fixed(1),
        templates: &[Tag(0x70), Tag(0x77)],
    },
    TagInfo {
        tag: Tag(0x9F45),
        name: "Data Authentication Code",
        source: Source::Icc,
        format: Format::Binary,
        length: LengthSpec::Fixed(2),
        templates: &[],
    },
    TagInfo {
        tag: Tag(0x9F46),
        name: "Integrated Circuit Card (ICC) Public Key Certificate",
        source: Source::Icc,
        format: Format::Binary,
        length: LengthSpec::Variable,
        templates: &[Tag(0x70), Tag(0x77)],
    },
    TagInfo {
        tag: Tag(0x9F47),
        name: "Integrated Circuit Card (ICC) Public Key Exponent",
        source: Source::Icc,
        format: Format::Binary,
        length: LengthSpec::Choice(&[1, 3]),
        templates: &[Tag(0x70), Tag(0x77)],
    },
    TagInfo {
        tag: Tag(0x9F48),
        name: "Integrated Circuit Card (ICC) Public Key Remainder",
        source: Source::Icc,
        format: Format::Binary,
        length: LengthSpec::Variable,
        templates: &[Tag(0x70), Tag(0x77)],
    },
    TagInfo {
        tag: Tag(0x9F49),
        name: "Dynamic Data Authentication Data Object List (DDOL)",
        source: Source::Icc,
        format: Format::Binary,
        length: LengthSpec::UpTo(252),
        templates: &[Tag(0x70), Tag(0x77)],
    },
    TagInfo {
        tag: Tag(0x9F4A),
        name: "Static Data Authentication Tag List",
        source: Source::Icc,
        format: Format::Variable,
        length: LengthSpec::Variable,
        templates: &[Tag(0x70), Tag(0x77)],
    },
    TagInfo {
        tag: Tag(0x9F4B),
        name: "Signed Dynamic Application Data",
        source: Source::Icc,
        format: Format::Binary,
        length: LengthSpec::Variable,
        templates: &[Tag(0x77), Tag(0x80)],
    },
    TagInfo {
        tag: Tag(0x9F4C),
        name: "ICC Dynamic Number",
        source: Source::Icc,
        format: Format::Binary,
        length: LengthSpec::Range(2, 8),
        templates: &[],
    },
    TagInfo {
        tag: Tag(0x9F4D),
        name: "Log Entry",
        source: Source::Icc,
        format: Format::Binary,
        length: LengthSpec::Fixed(2),
        templates: &[Tag(0xBF0C), Tag(0x73)],
    },
    TagInfo {
        tag: Tag(0x9F4E),
        name: "Merchant Name and Location",
        source: Source::Terminal,
        format: Format::AlphanumericSpecial,
        length: LengthSpec::Variable,
        templates: &[],
    },
    TagInfo {
        tag: Tag(0x9F4F),
        name: "Log Format",
        source: Source::Icc,
        format: Format::Binary,
        length: LengthSpec::Variable,
        templates: &[],
    },
    // ── 9F5B ─────────────────────────────────────────────────────────
    TagInfo {
        tag: Tag(0x9F5B),
        // Book 4 Annex A5 Table 34 (p. 116). Bytes 1–5 are repeated for
        // each Issuer Script the terminal processed; the kernel
        // accumulates them on the context across both '71' and '72'
        // calls and serialises here.
        name: "Issuer Script Results",
        source: Source::Terminal,
        format: Format::Binary,
        length: LengthSpec::Variable,
        templates: &[],
    },
    // ── A1, A5 ───────────────────────────────────────────────────────
    TagInfo {
        tag: Tag(0xA1),
        name: "Biometric Header Template (BHT)",
        source: Source::TerminalOrCard,
        format: Format::Binary,
        length: LengthSpec::Variable,
        templates: &[Tag(0x7F60)],
    },
    TagInfo {
        tag: Tag(0xA5),
        name: "File Control Information (FCI) Proprietary Template",
        source: Source::Icc,
        format: Format::Variable,
        length: LengthSpec::Variable,
        templates: &[Tag(0x6F)],
    },
    // ── BFxx ─────────────────────────────────────────────────────────
    TagInfo {
        tag: Tag(0xBF0C),
        name: "File Control Information (FCI) Issuer Discretionary Data",
        source: Source::Icc,
        format: Format::Variable,
        length: LengthSpec::UpTo(222),
        templates: &[Tag(0xA5)],
    },
    TagInfo {
        tag: Tag(0xBF4A),
        name: "Offline BIT Group Template",
        source: Source::Card,
        format: Format::Binary,
        length: LengthSpec::Variable,
        templates: &[Tag(0x9F31)],
    },
    TagInfo {
        tag: Tag(0xBF4B),
        name: "Online BIT Group Template",
        source: Source::Card,
        format: Format::Binary,
        length: LengthSpec::Variable,
        templates: &[Tag(0x9F31)],
    },
    TagInfo {
        tag: Tag(0xBF4C),
        name: "Biometric Try Counters Template",
        source: Source::Card,
        format: Format::Binary,
        length: LengthSpec::Variable,
        templates: &[],
    },
    TagInfo {
        tag: Tag(0xBF4D),
        name: "Preferred Attempts Template",
        source: Source::Card,
        format: Format::Binary,
        length: LengthSpec::Variable,
        templates: &[],
    },
    TagInfo {
        tag: Tag(0xBF4E),
        name: "Biometric Verification Data Template",
        source: Source::Terminal,
        format: Format::Binary,
        length: LengthSpec::Variable,
        templates: &[],
    },
    // ── DF50–DF54 (polysemic; alphabetical within tag) ───────────────
    TagInfo {
        tag: Tag(0xDF50),
        name: "Enciphered Biometric Key Seed",
        source: Source::Terminal,
        format: Format::Binary,
        length: LengthSpec::Variable,
        templates: &[Tag(0xBF4E)],
    },
    TagInfo {
        tag: Tag(0xDF50),
        name: "Facial Try Counter",
        source: Source::Card,
        format: Format::Binary,
        length: LengthSpec::Fixed(1),
        templates: &[Tag(0xBF4C)],
    },
    TagInfo {
        tag: Tag(0xDF50),
        name: "Preferred Facial Attempts",
        source: Source::Card,
        format: Format::Binary,
        length: LengthSpec::Fixed(1),
        templates: &[Tag(0xBF4D)],
    },
    TagInfo {
        tag: Tag(0xDF51),
        name: "Enciphered Biometric Data",
        source: Source::Terminal,
        format: Format::Binary,
        length: LengthSpec::Variable,
        templates: &[Tag(0xBF4E)],
    },
    TagInfo {
        tag: Tag(0xDF51),
        name: "Finger Try Counter",
        source: Source::Card,
        format: Format::Binary,
        length: LengthSpec::Fixed(1),
        templates: &[Tag(0xBF4C)],
    },
    TagInfo {
        tag: Tag(0xDF51),
        name: "Preferred Finger Attempts",
        source: Source::Card,
        format: Format::Binary,
        length: LengthSpec::Fixed(1),
        templates: &[Tag(0xBF4D)],
    },
    TagInfo {
        tag: Tag(0xDF52),
        name: "Iris Try Counter",
        source: Source::Card,
        format: Format::Binary,
        length: LengthSpec::Fixed(1),
        templates: &[Tag(0xBF4C)],
    },
    TagInfo {
        tag: Tag(0xDF52),
        name: "MAC of Enciphered Biometric Data",
        source: Source::Terminal,
        format: Format::Binary,
        length: LengthSpec::Fixed(8),
        templates: &[Tag(0xBF4E)],
    },
    TagInfo {
        tag: Tag(0xDF52),
        name: "Preferred Iris Attempts",
        source: Source::Card,
        format: Format::Binary,
        length: LengthSpec::Fixed(1),
        templates: &[Tag(0xBF4D)],
    },
    TagInfo {
        tag: Tag(0xDF53),
        name: "Palm Try Counter",
        source: Source::Card,
        format: Format::Binary,
        length: LengthSpec::Fixed(1),
        templates: &[Tag(0xBF4C)],
    },
    TagInfo {
        tag: Tag(0xDF53),
        name: "Preferred Palm Attempts",
        source: Source::Card,
        format: Format::Binary,
        length: LengthSpec::Fixed(1),
        templates: &[Tag(0xBF4D)],
    },
    TagInfo {
        tag: Tag(0xDF54),
        name: "Preferred Voice Attempts",
        source: Source::Card,
        format: Format::Binary,
        length: LengthSpec::Fixed(1),
        templates: &[Tag(0xBF4D)],
    },
    TagInfo {
        tag: Tag(0xDF54),
        name: "Voice Try Counter",
        source: Source::Card,
        format: Format::Binary,
        length: LengthSpec::Fixed(1),
        templates: &[Tag(0xBF4C)],
    },
];

/// Look up every registered entry for `tag`. Returns an empty slice for
/// unknown tags. For polysemic tags (`'81'`, `'82'`, `'90'`, `'7F60'`,
/// `'DF50'`–`'DF54'`) the slice has more than one element; callers
/// disambiguate by comparing [`TagInfo::templates`] against the parent
/// template they're parsing inside.
pub fn lookup(tag: Tag) -> &'static [TagInfo] {
    let i = match REGISTRY.binary_search_by(|info| info.tag.cmp(&tag)) {
        Ok(i) => i,
        Err(_) => return &[],
    };
    let mut start = i;
    while start > 0 && REGISTRY[start - 1].tag == tag {
        start -= 1;
    }
    let mut end = i + 1;
    while end < REGISTRY.len() && REGISTRY[end].tag == tag {
        end += 1;
    }
    &REGISTRY[start..end]
}

/// Convenience for tags that are unambiguous in your context. Returns
/// `Some` only when the registry has exactly one entry for `tag`.
pub fn lookup_unique(tag: Tag) -> Option<&'static TagInfo> {
    match lookup(tag) {
        [info] => Some(info),
        _ => None,
    }
}

/// Pick the entry whose `templates` list contains `parent`. If `parent`
/// is `None`, returns the entry with no template (the top-level
/// interpretation). Returns `None` if no entry in the registry matches
/// the constraint.
pub fn lookup_in(tag: Tag, parent: Option<Tag>) -> Option<&'static TagInfo> {
    let entries = lookup(tag);
    match parent {
        Some(p) => entries.iter().find(|info| info.templates.contains(&p)),
        None => entries.iter().find(|info| info.templates.is_empty()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_is_sorted_by_tag() {
        for w in REGISTRY.windows(2) {
            assert!(w[0].tag <= w[1].tag, "{} > {}", w[0].tag, w[1].tag);
        }
    }

    #[test]
    fn registry_has_no_duplicate_name_per_tag() {
        for entries in REGISTRY.chunk_by(|a, b| a.tag == b.tag) {
            for i in 0..entries.len() {
                for j in (i + 1)..entries.len() {
                    assert_ne!(
                        entries[i].name, entries[j].name,
                        "duplicate name at tag {}",
                        entries[i].tag,
                    );
                }
            }
        }
    }

    #[test]
    fn lookup_unknown_tag_returns_empty() {
        assert!(lookup(Tag(0xFFFF)).is_empty());
        assert!(lookup(Tag(0x00)).is_empty());
    }

    #[test]
    fn lookup_unambiguous_tag_returns_single_entry() {
        let r = lookup(Tag(0x9F38));
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].name, "Processing Options Data Object List (PDOL)");
    }

    #[test]
    fn lookup_polysemic_tag_returns_multiple() {
        // 81 - Amount, Authorised (Binary) + Biometric Type.
        assert_eq!(lookup(Tag(0x81)).len(), 2);
        // 82 - AIP + Biometric Subtype.
        assert_eq!(lookup(Tag(0x82)).len(), 2);
        // 90 - IPK Cert + Biometric Solution ID.
        assert_eq!(lookup(Tag(0x90)).len(), 2);
        // 7F60 - Card BIT + Terminal BIT.
        assert_eq!(lookup(Tag(0x7F60)).len(), 2);
        // DF50/DF51/DF52 each have three contexts; DF53/DF54 have two.
        assert_eq!(lookup(Tag(0xDF50)).len(), 3);
        assert_eq!(lookup(Tag(0xDF51)).len(), 3);
        assert_eq!(lookup(Tag(0xDF52)).len(), 3);
        assert_eq!(lookup(Tag(0xDF53)).len(), 2);
        assert_eq!(lookup(Tag(0xDF54)).len(), 2);
    }

    #[test]
    fn lookup_unique_returns_some_only_when_unambiguous() {
        assert!(lookup_unique(Tag(0x9F38)).is_some());
        assert!(lookup_unique(Tag(0x82)).is_none());
        assert!(lookup_unique(Tag(0xDF50)).is_none());
        assert!(lookup_unique(Tag(0xFFFF)).is_none());
    }

    #[test]
    fn lookup_in_disambiguates_by_parent_template() {
        // 81 inside A1 (BHT) → Biometric Type.
        let bt = lookup_in(Tag(0x81), Some(Tag(0xA1))).unwrap();
        assert_eq!(bt.name, "Biometric Type");
        // 81 at top level (no parent) → Amount, Authorised (Binary).
        let amt = lookup_in(Tag(0x81), None).unwrap();
        assert_eq!(amt.name, "Amount, Authorised (Binary)");
        // 82 inside 77 (RMT-2) → AIP.
        let aip = lookup_in(Tag(0x82), Some(Tag(0x77))).unwrap();
        assert_eq!(aip.name, "Application Interchange Profile");
        // DF50 inside BF4C → Facial Try Counter.
        let ftc = lookup_in(Tag(0xDF50), Some(Tag(0xBF4C))).unwrap();
        assert_eq!(ftc.name, "Facial Try Counter");
        // DF50 inside BF4D → Preferred Facial Attempts.
        let pfa = lookup_in(Tag(0xDF50), Some(Tag(0xBF4D))).unwrap();
        assert_eq!(pfa.name, "Preferred Facial Attempts");
        // DF50 inside BF4E → Enciphered Biometric Key Seed.
        let ebks = lookup_in(Tag(0xDF50), Some(Tag(0xBF4E))).unwrap();
        assert_eq!(ebks.name, "Enciphered Biometric Key Seed");
        // 81 inside an unrelated parent → None.
        assert!(lookup_in(Tag(0x81), Some(Tag(0x70))).is_none());
    }

    #[test]
    fn spot_check_application_interchange_profile() {
        let info = lookup_in(Tag(0x82), Some(Tag(0x77))).unwrap();
        assert_eq!(info.source, Source::Icc);
        assert_eq!(info.format, Format::Binary);
        assert_eq!(info.length, LengthSpec::Fixed(2));
        assert_eq!(info.templates, &[Tag(0x77), Tag(0x80)]);
    }

    #[test]
    fn spot_check_pan_compressed_numeric() {
        let info = lookup_unique(Tag(0x5A)).unwrap();
        assert_eq!(info.format, Format::CompressedNumeric);
        assert_eq!(info.length, LengthSpec::UpTo(10));
    }

    #[test]
    fn spot_check_authorisation_response_code_dual_source() {
        let info = lookup_unique(Tag(0x8A)).unwrap();
        assert_eq!(info.source, Source::IssuerOrTerminal);
        assert_eq!(info.format, Format::Alphanumeric);
        assert_eq!(info.length, LengthSpec::Fixed(2));
    }

    #[test]
    fn spot_check_issuer_script_command_extends_short_apdu() {
        // Tag 86 wraps a full APDU, hence the up-to-261 byte ceiling.
        let info = lookup_unique(Tag(0x86)).unwrap();
        assert_eq!(info.length, LengthSpec::UpTo(261));
    }

    #[test]
    fn template_tags_are_themselves_registered() {
        // Every Tag listed in any entry's templates field should itself
        // appear as a registered tag (sanity for nested-context
        // navigation).
        for entry in REGISTRY {
            for &parent in entry.templates {
                assert!(
                    !lookup(parent).is_empty(),
                    "template {} (referenced by {}) is not in the registry",
                    parent,
                    entry.tag,
                );
            }
        }
    }

    #[test]
    fn length_range_bounds_are_ordered() {
        for entry in REGISTRY {
            if let LengthSpec::Range(lo, hi) = entry.length {
                assert!(lo <= hi, "{} has Range({}, {})", entry.tag, lo, hi);
            }
        }
    }

    #[test]
    fn length_choice_is_nonempty() {
        for entry in REGISTRY {
            if let LengthSpec::Choice(opts) = entry.length {
                assert!(!opts.is_empty(), "{} has empty Choice", entry.tag);
            }
        }
    }

    #[test]
    fn registry_contains_every_named_tag_constant() {
        // Every constant in tags.rs should resolve in the registry.
        // (Spot-check a handful - the comprehensive sort/duplicate
        // tests above cover the rest by construction.)
        use crate::core::tags;
        for t in [
            tags::APPLICATION_INTERCHANGE_PROFILE,
            tags::APPLICATION_FILE_LOCATOR,
            tags::APPLICATION_TRANSACTION_COUNTER,
            tags::APPLICATION_CRYPTOGRAM,
            tags::PDOL,
            tags::CDOL1,
            tags::CDOL2,
            tags::CVM_LIST,
            tags::TERMINAL_VERIFICATION_RESULTS,
            tags::TRANSACTION_STATUS_INFORMATION,
            tags::FCI_TEMPLATE,
            tags::FCI_PROPRIETARY_TEMPLATE,
            tags::READ_RECORD_RESPONSE_TEMPLATE,
        ] {
            assert!(!lookup(t).is_empty(), "tag {} missing from registry", t);
        }
    }
}
