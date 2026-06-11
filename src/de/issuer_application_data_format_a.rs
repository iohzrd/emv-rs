//! Issuer Application Data, Format Code 'A' (tag 9F10) - Book 3 Annex C9.2, Table CCD 9.

use crate::core::error::{Error, Result};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IssuerApplicationDataFormatA {
    /// Byte 1, fixed '0F'.
    pub length_indicator_emvco: u8,
    pub cci: u8,
    pub dki: u8,
    pub cvr: [u8; 5],
    /// Bytes 9–16, payment-system discretionary.
    pub counters: [u8; 8],
    /// Byte 17, fixed '0F'.
    pub length_indicator_idd: u8,
    /// Bytes 18–32.
    pub issuer_discretionary_data: [u8; 15],
}

impl IssuerApplicationDataFormatA {
    pub fn parse(data: &[u8]) -> Result<Self> {
        if data.len() != 32 {
            return Err(Error::WrongLength {
                expected: 32,
                got: data.len(),
            });
        }
        if data[0] != 0x0F || data[16] != 0x0F {
            return Err(Error::InvalidValue);
        }
        let mut cvr = [0u8; 5];
        cvr.copy_from_slice(&data[3..8]);
        let mut counters = [0u8; 8];
        counters.copy_from_slice(&data[8..16]);
        let mut idd = [0u8; 15];
        idd.copy_from_slice(&data[17..32]);
        Ok(IssuerApplicationDataFormatA {
            length_indicator_emvco: data[0],
            cci: data[1],
            dki: data[2],
            cvr,
            counters,
            length_indicator_idd: data[16],
            issuer_discretionary_data: idd,
        })
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(32);
        out.push(self.length_indicator_emvco);
        out.push(self.cci);
        out.push(self.dki);
        out.extend_from_slice(&self.cvr);
        out.extend_from_slice(&self.counters);
        out.push(self.length_indicator_idd);
        out.extend_from_slice(&self.issuer_discretionary_data);
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> [u8; 32] {
        let mut b = [0u8; 32];
        b[0] = 0x0F;
        b[1] = 0xA5;
        b[2] = 0x01;
        b[3] = 0x40;
        b[4] = 0x00;
        b[5] = 0x00;
        b[6] = 0x00;
        b[7] = 0x00;
        for (i, byte) in b[8..16].iter_mut().enumerate() {
            *byte = i as u8;
        }
        b[16] = 0x0F;
        b[17..32].fill(0xAA);
        b
    }

    #[test]
    fn parse_roundtrip() {
        let bytes = sample();
        let iad = IssuerApplicationDataFormatA::parse(&bytes).unwrap();
        assert_eq!(iad.length_indicator_emvco, 0x0F);
        assert_eq!(iad.cci, 0xA5);
        assert_eq!(iad.dki, 0x01);
        assert_eq!(iad.cvr, [0x40, 0, 0, 0, 0]);
        assert_eq!(iad.counters, [0, 1, 2, 3, 4, 5, 6, 7]);
        assert_eq!(iad.length_indicator_idd, 0x0F);
        assert_eq!(iad.issuer_discretionary_data, [0xAA; 15]);
        assert_eq!(iad.to_bytes(), bytes);
    }

    #[test]
    fn parse_wrong_length() {
        assert_eq!(
            IssuerApplicationDataFormatA::parse(&[]),
            Err(Error::WrongLength {
                expected: 32,
                got: 0
            })
        );
        assert_eq!(
            IssuerApplicationDataFormatA::parse(&[0; 31]),
            Err(Error::WrongLength {
                expected: 32,
                got: 31
            })
        );
        assert_eq!(
            IssuerApplicationDataFormatA::parse(&[0; 33]),
            Err(Error::WrongLength {
                expected: 32,
                got: 33
            })
        );
    }

    #[test]
    fn parse_rejects_wrong_byte1() {
        let mut b = sample();
        b[0] = 0x0E;
        assert_eq!(
            IssuerApplicationDataFormatA::parse(&b),
            Err(Error::InvalidValue)
        );
    }

    #[test]
    fn parse_rejects_wrong_byte17() {
        let mut b = sample();
        b[16] = 0x00;
        assert_eq!(
            IssuerApplicationDataFormatA::parse(&b),
            Err(Error::InvalidValue)
        );
    }
}
