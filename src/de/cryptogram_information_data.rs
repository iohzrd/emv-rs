//! Cryptogram Information Data (tag 9F27) - Book 3 §6.5.5, Table 15.

use crate::core::error::{Error, Result};
pub use crate::core::application_cryptogram_type::ApplicationCryptogramType;

const PAYMENT_SYSTEM_SPECIFIC_MASK: u8 = 0b0000_0011;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct CryptogramInformationData {
    pub cryptogram_type: ApplicationCryptogramType,
    /// b6–b5 (Table 15 "Payment System-specific cryptogram"). 0..=3.
    pub payment_system_specific: u8,
    pub advice_required: bool,
    pub reason_advice_code: ReasonAdviceCode,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ReasonAdviceCode {
    /// 0 0 0
    #[default]
    NoInformationGiven,
    /// 0 0 1
    ServiceNotAllowed,
    /// 0 1 0
    PinTryLimitExceeded,
    /// 0 1 1
    IssuerAuthenticationFailed,
    Rfu(u8),
}

impl ReasonAdviceCode {
    fn from_bits(bits: u8) -> Self {
        let code = bits & 0b0000_0111;
        match code {
            0b000 => ReasonAdviceCode::NoInformationGiven,
            0b001 => ReasonAdviceCode::ServiceNotAllowed,
            0b010 => ReasonAdviceCode::PinTryLimitExceeded,
            0b011 => ReasonAdviceCode::IssuerAuthenticationFailed,
            _ => ReasonAdviceCode::Rfu(code),
        }
    }

    fn to_bits(self) -> u8 {
        match self {
            ReasonAdviceCode::NoInformationGiven => 0b000,
            ReasonAdviceCode::ServiceNotAllowed => 0b001,
            ReasonAdviceCode::PinTryLimitExceeded => 0b010,
            ReasonAdviceCode::IssuerAuthenticationFailed => 0b011,
            ReasonAdviceCode::Rfu(v) => v & 0b0000_0111,
        }
    }
}

impl CryptogramInformationData {
    pub fn parse(data: &[u8]) -> Result<Self> {
        if data.len() != 1 {
            return Err(Error::WrongLength {
                expected: 1,
                got: data.len(),
            });
        }
        let b = data[0];
        Ok(CryptogramInformationData {
            cryptogram_type: ApplicationCryptogramType::from_bits((b >> 6) & 0b11),
            payment_system_specific: (b >> 4) & PAYMENT_SYSTEM_SPECIFIC_MASK,
            advice_required: b & 0b0000_1000 != 0,
            reason_advice_code: ReasonAdviceCode::from_bits(b),
        })
    }

    pub fn to_byte(&self) -> u8 {
        (self.cryptogram_type.to_bits() << 6)
            | ((self.payment_system_specific & PAYMENT_SYSTEM_SPECIFIC_MASK) << 4)
            | ((self.advice_required as u8) << 3)
            | self.reason_advice_code.to_bits()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn struct_literal_construction() {
        let cid = CryptogramInformationData {
            cryptogram_type: ApplicationCryptogramType::Tc,
            advice_required: true,
            reason_advice_code: ReasonAdviceCode::IssuerAuthenticationFailed,
            ..Default::default()
        };
        assert_eq!(cid.to_byte(), 0b0100_1011);
    }

    #[test]
    fn roundtrip_preserves_rfu() {
        let bytes = [0b1111_1111u8];
        let cid = CryptogramInformationData::parse(&bytes).unwrap();
        assert_eq!(cid.cryptogram_type, ApplicationCryptogramType::Rfu(0b11));
        assert_eq!(cid.reason_advice_code, ReasonAdviceCode::Rfu(0b111));
        assert_eq!(cid.payment_system_specific, 0b11);
        assert!(cid.advice_required);
        assert_eq!(cid.to_byte(), bytes[0]);
    }

    #[test]
    fn roundtrip_exhaustive() {
        for b in 0u8..=u8::MAX {
            let cid = CryptogramInformationData::parse(&[b]).unwrap();
            assert_eq!(cid.to_byte(), b);
        }
    }

    #[test]
    fn parse_wrong_length() {
        assert_eq!(
            CryptogramInformationData::parse(&[]),
            Err(Error::WrongLength { expected: 1, got: 0 })
        );
        assert_eq!(
            CryptogramInformationData::parse(&[0, 0]),
            Err(Error::WrongLength { expected: 1, got: 2 })
        );
    }

    #[test]
    fn cryptogram_type_variants_roundtrip() {
        for (b, expected) in [
            (0b0000_0000u8, ApplicationCryptogramType::Aac),
            (0b0100_0000, ApplicationCryptogramType::Tc),
            (0b1000_0000, ApplicationCryptogramType::Arqc),
            (0b1100_0000, ApplicationCryptogramType::Rfu(0b11)),
        ] {
            let cid = CryptogramInformationData::parse(&[b]).unwrap();
            assert_eq!(cid.cryptogram_type, expected);
            assert_eq!(cid.to_byte(), b);
        }
    }

    #[test]
    fn reason_advice_code_variants_roundtrip() {
        for (b, expected) in [
            (0b0000_0000u8, ReasonAdviceCode::NoInformationGiven),
            (0b0000_0001, ReasonAdviceCode::ServiceNotAllowed),
            (0b0000_0010, ReasonAdviceCode::PinTryLimitExceeded),
            (0b0000_0011, ReasonAdviceCode::IssuerAuthenticationFailed),
            (0b0000_0100, ReasonAdviceCode::Rfu(0b100)),
            (0b0000_0101, ReasonAdviceCode::Rfu(0b101)),
            (0b0000_0110, ReasonAdviceCode::Rfu(0b110)),
            (0b0000_0111, ReasonAdviceCode::Rfu(0b111)),
        ] {
            let cid = CryptogramInformationData::parse(&[b]).unwrap();
            assert_eq!(cid.reason_advice_code, expected);
            assert_eq!(cid.to_byte(), b);
        }
    }

    #[test]
    fn payment_system_specific_2bits_roundtrip() {
        for v in 0u8..=3 {
            let b = v << 4;
            let cid = CryptogramInformationData::parse(&[b]).unwrap();
            assert_eq!(cid.payment_system_specific, v);
            assert_eq!(cid.to_byte(), b);
        }
    }

    #[test]
    fn advice_required_bit() {
        assert!(
            !CryptogramInformationData::parse(&[0b0000_0000])
                .unwrap()
                .advice_required
        );
        assert!(
            CryptogramInformationData::parse(&[0b0000_1000])
                .unwrap()
                .advice_required
        );
    }

    #[test]
    fn combined_tc_advice_required_issuer_auth_failed() {
        let cid = CryptogramInformationData::parse(&[0b0100_1011]).unwrap();
        assert_eq!(cid.cryptogram_type, ApplicationCryptogramType::Tc);
        assert!(cid.advice_required);
        assert_eq!(
            cid.reason_advice_code,
            ReasonAdviceCode::IssuerAuthenticationFailed
        );
    }
}
