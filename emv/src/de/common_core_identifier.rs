//! Common Core Identifier - Book 3 Annex C9.1, Table CCD 8.

use crate::core::error::{Error, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CommonCoreIdentifier(pub u8);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FormatCode {
    /// 1 0 1 0 - 'A'
    CcdVersion41,
    Other(u8),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CryptogramVersion {
    /// 0 1 0 1 - '5' Triple DES
    TripleDes,
    /// 0 1 1 0 - '6' AES
    Aes,
    Other(u8),
}

impl CommonCoreIdentifier {
    pub fn parse(data: &[u8]) -> Result<Self> {
        if data.len() != 1 {
            return Err(Error::WrongLength {
                expected: 1,
                got: data.len(),
            });
        }
        Ok(CommonCoreIdentifier(data[0]))
    }

    pub fn to_byte(&self) -> u8 {
        self.0
    }

    pub fn format_code_nibble(&self) -> u8 {
        (self.0 >> 4) & 0x0F
    }

    pub fn cryptogram_version_nibble(&self) -> u8 {
        self.0 & 0x0F
    }

    pub fn format_code(&self) -> FormatCode {
        match self.format_code_nibble() {
            0b1010 => FormatCode::CcdVersion41,
            n => FormatCode::Other(n),
        }
    }

    pub fn cryptogram_version(&self) -> CryptogramVersion {
        match self.cryptogram_version_nibble() {
            0b0101 => CryptogramVersion::TripleDes,
            0b0110 => CryptogramVersion::Aes,
            n => CryptogramVersion::Other(n),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_wrong_length() {
        assert_eq!(
            CommonCoreIdentifier::parse(&[]),
            Err(Error::WrongLength { expected: 1, got: 0 })
        );
        assert_eq!(
            CommonCoreIdentifier::parse(&[0, 0]),
            Err(Error::WrongLength { expected: 1, got: 2 })
        );
    }

    #[test]
    fn roundtrip() {
        for b in [0x00u8, 0xA5, 0xA6, 0xFF] {
            let cci = CommonCoreIdentifier::parse(&[b]).unwrap();
            assert_eq!(cci.to_byte(), b);
        }
    }

    #[test]
    fn ccd_v41_triple_des() {
        let cci = CommonCoreIdentifier(0xA5);
        assert_eq!(cci.format_code(), FormatCode::CcdVersion41);
        assert_eq!(cci.cryptogram_version(), CryptogramVersion::TripleDes);
        assert_eq!(cci.format_code_nibble(), 0xA);
        assert_eq!(cci.cryptogram_version_nibble(), 0x5);
    }

    #[test]
    fn ccd_v41_aes() {
        let cci = CommonCoreIdentifier(0xA6);
        assert_eq!(cci.format_code(), FormatCode::CcdVersion41);
        assert_eq!(cci.cryptogram_version(), CryptogramVersion::Aes);
    }

    #[test]
    fn other_format_code_and_cv() {
        let cci = CommonCoreIdentifier(0x37);
        assert_eq!(cci.format_code(), FormatCode::Other(0x3));
        assert_eq!(cci.cryptogram_version(), CryptogramVersion::Other(0x7));
    }
}
