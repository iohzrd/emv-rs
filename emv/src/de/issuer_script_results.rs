//! Issuer Script Results (tag 9F5B) - Book 4 Annex A5, Table 34.

use crate::core::error::{Error, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ScriptResultNibble {
    /// '0'
    #[default]
    ScriptNotPerformed,
    /// '1'
    ScriptProcessingFailed,
    /// '2'
    ScriptProcessingSuccessful,
    Rfu(u8),
}

impl ScriptResultNibble {
    pub fn from_nibble(v: u8) -> Self {
        match v & 0x0F {
            0x0 => ScriptResultNibble::ScriptNotPerformed,
            0x1 => ScriptResultNibble::ScriptProcessingFailed,
            0x2 => ScriptResultNibble::ScriptProcessingSuccessful,
            other => ScriptResultNibble::Rfu(other),
        }
    }

    pub fn to_nibble(self) -> u8 {
        match self {
            ScriptResultNibble::ScriptNotPerformed => 0x0,
            ScriptResultNibble::ScriptProcessingFailed => 0x1,
            ScriptResultNibble::ScriptProcessingSuccessful => 0x2,
            ScriptResultNibble::Rfu(v) => v & 0x0F,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct IssuerScriptResult {
    pub script_result: ScriptResultNibble,
    /// Byte 1 lower nibble. '0' = not specified, '1'..='E' = 1..=14, 'F' = 15+.
    pub script_number: u8,
    /// Bytes 2–5, value of tag 9F18 if available, zero filled otherwise.
    pub script_identifier: [u8; 4],
}

impl IssuerScriptResult {
    pub fn parse(data: &[u8; 5]) -> Self {
        let b1 = data[0];
        IssuerScriptResult {
            script_result: ScriptResultNibble::from_nibble(b1 >> 4),
            script_number: b1 & 0x0F,
            script_identifier: [data[1], data[2], data[3], data[4]],
        }
    }

    pub fn to_bytes(&self) -> [u8; 5] {
        let b1 = (self.script_result.to_nibble() << 4) | (self.script_number & 0x0F);
        [
            b1,
            self.script_identifier[0],
            self.script_identifier[1],
            self.script_identifier[2],
            self.script_identifier[3],
        ]
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct IssuerScriptResults(pub Vec<IssuerScriptResult>);

impl IssuerScriptResults {
    pub fn parse(data: &[u8]) -> Result<Self> {
        if data.len() % 5 != 0 {
            // Round up so the caller sees the nearest valid length > got.
            let expected = data.len().div_ceil(5) * 5;
            return Err(Error::WrongLength {
                expected,
                got: data.len(),
            });
        }
        let mut out = Vec::with_capacity(data.len() / 5);
        for chunk in data.chunks_exact(5) {
            let entry: &[u8; 5] = chunk.try_into().expect("chunks_exact(5) yields [u8; 5]");
            out.push(IssuerScriptResult::parse(entry));
        }
        Ok(IssuerScriptResults(out))
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.0.len() * 5);
        for entry in &self.0 {
            out.extend_from_slice(&entry.to_bytes());
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn struct_literal_construction() {
        let e = IssuerScriptResult {
            script_result: ScriptResultNibble::ScriptProcessingSuccessful,
            script_number: 1,
            script_identifier: [0x01, 0x02, 0x03, 0x04],
        };
        assert_eq!(e.to_bytes(), [0x21, 0x01, 0x02, 0x03, 0x04]);
    }

    #[test]
    fn entry_roundtrip() {
        let wire = [0x21u8, 0x01, 0x02, 0x03, 0x04];
        let e = IssuerScriptResult::parse(&wire);
        assert_eq!(
            e.script_result,
            ScriptResultNibble::ScriptProcessingSuccessful
        );
        assert_eq!(e.script_number, 1);
        assert_eq!(e.script_identifier, [0x01, 0x02, 0x03, 0x04]);
        assert_eq!(e.to_bytes(), wire);
    }

    #[test]
    fn entry_roundtrip_exhaustive() {
        for wire in [
            [0x00u8, 0x00, 0x00, 0x00, 0x00],
            [0x10, 0xAA, 0xBB, 0xCC, 0xDD],
            [0x21, 0x01, 0x02, 0x03, 0x04],
            [0x2F, 0xFF, 0xFF, 0xFF, 0xFF],
            [0x50, 0x12, 0x34, 0x56, 0x78],
            [0xFE, 0xDE, 0xAD, 0xBE, 0xEF],
        ] {
            let e = IssuerScriptResult::parse(&wire);
            assert_eq!(e.to_bytes(), wire);
        }
    }

    #[test]
    fn parse_two_entries_roundtrip() {
        let wire = [
            0x21, 0x01, 0x02, 0x03, 0x04,
            0x12, 0xAA, 0xBB, 0xCC, 0xDD,
        ];
        let parsed = IssuerScriptResults::parse(&wire).unwrap();
        assert_eq!(parsed.0.len(), 2);

        assert_eq!(
            parsed.0[0].script_result,
            ScriptResultNibble::ScriptProcessingSuccessful
        );
        assert_eq!(parsed.0[0].script_number, 1);
        assert_eq!(parsed.0[0].script_identifier, [0x01, 0x02, 0x03, 0x04]);

        assert_eq!(
            parsed.0[1].script_result,
            ScriptResultNibble::ScriptProcessingFailed
        );
        assert_eq!(parsed.0[1].script_number, 2);
        assert_eq!(parsed.0[1].script_identifier, [0xAA, 0xBB, 0xCC, 0xDD]);

        assert_eq!(parsed.to_bytes(), wire.to_vec());
    }

    #[test]
    fn parse_empty() {
        let parsed = IssuerScriptResults::parse(&[]).unwrap();
        assert!(parsed.0.is_empty());
        assert_eq!(parsed.to_bytes(), Vec::<u8>::new());
    }

    #[test]
    fn parse_wrong_length() {
        assert_eq!(
            IssuerScriptResults::parse(&[0x00, 0x00, 0x00]),
            Err(Error::WrongLength { expected: 5, got: 3 })
        );
        assert_eq!(
            IssuerScriptResults::parse(&[0; 6]),
            Err(Error::WrongLength {
                expected: 10,
                got: 6
            })
        );
        assert_eq!(
            IssuerScriptResults::parse(&[0; 11]),
            Err(Error::WrongLength {
                expected: 15,
                got: 11
            })
        );
    }

    #[test]
    fn script_result_not_performed() {
        let e = IssuerScriptResult::parse(&[0x00, 0, 0, 0, 0]);
        assert_eq!(e.script_result, ScriptResultNibble::ScriptNotPerformed);
        assert_eq!(e.script_number, 0);
    }

    #[test]
    fn script_result_failed() {
        let e = IssuerScriptResult::parse(&[0x15, 0, 0, 0, 0]);
        assert_eq!(e.script_result, ScriptResultNibble::ScriptProcessingFailed);
        assert_eq!(e.script_number, 5);
    }

    #[test]
    fn script_result_successful() {
        let e = IssuerScriptResult::parse(&[0x2E, 0, 0, 0, 0]);
        assert_eq!(
            e.script_result,
            ScriptResultNibble::ScriptProcessingSuccessful
        );
        assert_eq!(e.script_number, 0x0E);
    }

    #[test]
    fn script_number_f_means_15_or_above() {
        let e = IssuerScriptResult::parse(&[0x2F, 0, 0, 0, 0]);
        assert_eq!(e.script_number, 0x0F);
    }

    #[test]
    fn script_number_not_specified() {
        let e = IssuerScriptResult::parse(&[0x10, 0, 0, 0, 0]);
        assert_eq!(e.script_number, 0);
    }

    #[test]
    fn script_result_rfu_upper_nibble() {
        let e = IssuerScriptResult::parse(&[0x50, 0, 0, 0, 0]);
        assert_eq!(e.script_result, ScriptResultNibble::Rfu(0x5));
    }

    #[test]
    fn result_nibble_roundtrip() {
        for v in 0u8..=0x0F {
            let n = ScriptResultNibble::from_nibble(v);
            assert_eq!(n.to_nibble(), v);
        }
    }
}
