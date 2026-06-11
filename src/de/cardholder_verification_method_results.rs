//! CVM Results (tag 9F34) - Book 4 Annex A4, Table 33.

use crate::core::error::{Error, Result};
use crate::de::cardholder_verification_method_list::{
    CardholderVerificationMethod, CardholderVerificationMethodCondition,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CardholderVerificationMethodResults(pub [u8; 3]);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CardholderVerificationMethodResultCode {
    /// '00'
    Unknown,
    /// '01'
    Failed,
    /// '02'
    Successful,
    Rfu(u8),
}

impl CardholderVerificationMethodResultCode {
    pub fn from_u8(v: u8) -> Self {
        match v {
            0x00 => CardholderVerificationMethodResultCode::Unknown,
            0x01 => CardholderVerificationMethodResultCode::Failed,
            0x02 => CardholderVerificationMethodResultCode::Successful,
            other => CardholderVerificationMethodResultCode::Rfu(other),
        }
    }

    pub const fn to_u8(self) -> u8 {
        match self {
            CardholderVerificationMethodResultCode::Unknown => 0x00,
            CardholderVerificationMethodResultCode::Failed => 0x01,
            CardholderVerificationMethodResultCode::Successful => 0x02,
            CardholderVerificationMethodResultCode::Rfu(v) => v,
        }
    }
}

impl CardholderVerificationMethodResults {
    /// "No CVM performed".
    pub const NO_CVM_PERFORMED: CardholderVerificationMethodResults =
        CardholderVerificationMethodResults([
            CardholderVerificationMethod::NotAvailableForUse.to_code(),
            CardholderVerificationMethodCondition::Always.to_code(),
            CardholderVerificationMethodResultCode::Unknown.to_u8(),
        ]);

    pub fn parse(data: &[u8]) -> Result<Self> {
        if data.len() != 3 {
            return Err(Error::WrongLength {
                expected: 3,
                got: data.len(),
            });
        }
        Ok(CardholderVerificationMethodResults([
            data[0], data[1], data[2],
        ]))
    }

    pub fn to_bytes(&self) -> [u8; 3] {
        self.0
    }

    pub fn cvm_performed(&self) -> u8 {
        self.0[0]
    }

    pub fn cvm_condition(&self) -> u8 {
        self.0[1]
    }

    pub fn result(&self) -> CardholderVerificationMethodResultCode {
        CardholderVerificationMethodResultCode::from_u8(self.0[2])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_cvm_performed_wire_value() {
        assert_eq!(
            CardholderVerificationMethodResults::NO_CVM_PERFORMED.to_bytes(),
            [0x3F, 0x00, 0x00]
        );
    }

    #[test]
    fn roundtrip() {
        for bytes in [
            [0x00, 0x00, 0x00],
            [0x3F, 0x00, 0x01],
            [0x1E, 0x03, 0x02],
            [0xFF, 0xFF, 0xFF],
        ] {
            let r = CardholderVerificationMethodResults::parse(&bytes).unwrap();
            assert_eq!(r.to_bytes(), bytes);
        }
    }

    #[test]
    fn parse_wrong_length() {
        assert_eq!(
            CardholderVerificationMethodResults::parse(&[]),
            Err(Error::WrongLength {
                expected: 3,
                got: 0
            })
        );
        assert_eq!(
            CardholderVerificationMethodResults::parse(&[0; 2]),
            Err(Error::WrongLength {
                expected: 3,
                got: 2
            })
        );
        assert_eq!(
            CardholderVerificationMethodResults::parse(&[0; 4]),
            Err(Error::WrongLength {
                expected: 3,
                got: 4
            })
        );
    }

    #[test]
    fn accessors() {
        let r = CardholderVerificationMethodResults::parse(&[0x1E, 0x03, 0x02]).unwrap();
        assert_eq!(r.cvm_performed(), 0x1E);
        assert_eq!(r.cvm_condition(), 0x03);
        assert_eq!(
            r.result(),
            CardholderVerificationMethodResultCode::Successful
        );
    }

    #[test]
    fn result_unknown() {
        let r = CardholderVerificationMethodResults::parse(&[0x3F, 0x00, 0x00]).unwrap();
        assert_eq!(r.result(), CardholderVerificationMethodResultCode::Unknown);
    }

    #[test]
    fn result_failed() {
        let r = CardholderVerificationMethodResults::parse(&[0x02, 0x00, 0x01]).unwrap();
        assert_eq!(r.result(), CardholderVerificationMethodResultCode::Failed);
    }

    #[test]
    fn result_successful() {
        let r = CardholderVerificationMethodResults::parse(&[0x04, 0x00, 0x02]).unwrap();
        assert_eq!(
            r.result(),
            CardholderVerificationMethodResultCode::Successful
        );
    }

    #[test]
    fn result_rfu() {
        let r = CardholderVerificationMethodResults::parse(&[0x00, 0x00, 0x7F]).unwrap();
        assert_eq!(
            r.result(),
            CardholderVerificationMethodResultCode::Rfu(0x7F)
        );
    }

    #[test]
    fn result_code_roundtrip_u8() {
        for v in 0u8..=0xFF {
            let code = CardholderVerificationMethodResultCode::from_u8(v);
            assert_eq!(code.to_u8(), v);
        }
    }
}
