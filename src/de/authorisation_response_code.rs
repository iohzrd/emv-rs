//! Authorisation Response Code (tag 8A) - Book 4 Annex A6, Table 35.

use crate::core::error::{Error, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuthorisationResponseCode(pub [u8; 2]);

impl AuthorisationResponseCode {
    pub const OFFLINE_APPROVED: AuthorisationResponseCode = AuthorisationResponseCode(*b"Y1");
    pub const OFFLINE_DECLINED: AuthorisationResponseCode = AuthorisationResponseCode(*b"Z1");
    pub const UNABLE_TO_GO_ONLINE_OFFLINE_APPROVED: AuthorisationResponseCode =
        AuthorisationResponseCode(*b"Y3");
    pub const UNABLE_TO_GO_ONLINE_OFFLINE_DECLINED: AuthorisationResponseCode =
        AuthorisationResponseCode(*b"Z3");

    pub fn parse(data: &[u8]) -> Result<Self> {
        if data.len() != 2 {
            return Err(Error::WrongLength {
                expected: 2,
                got: data.len(),
            });
        }
        Ok(AuthorisationResponseCode([data[0], data[1]]))
    }

    pub fn to_bytes(&self) -> [u8; 2] {
        self.0
    }

    pub fn as_str(&self) -> Result<&str> {
        if !self.0[0].is_ascii() || !self.0[1].is_ascii() {
            return Err(Error::InvalidValue);
        }
        // SAFETY: both bytes are ASCII (checked above), so the slice is valid UTF-8.
        Ok(std::str::from_utf8(&self.0).map_err(|_| Error::InvalidValue)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        for bytes in [*b"Y1", *b"Z1", *b"Y3", *b"Z3", *b"00", *b"01", *b"05"] {
            let a = AuthorisationResponseCode::parse(&bytes).unwrap();
            assert_eq!(a.to_bytes(), bytes);
        }
    }

    #[test]
    fn as_str_ascii() {
        assert_eq!(
            AuthorisationResponseCode::parse(b"Y1")
                .unwrap()
                .as_str()
                .unwrap(),
            "Y1"
        );
        assert_eq!(
            AuthorisationResponseCode::parse(b"Z3")
                .unwrap()
                .as_str()
                .unwrap(),
            "Z3"
        );
        assert_eq!(
            AuthorisationResponseCode::parse(b"00")
                .unwrap()
                .as_str()
                .unwrap(),
            "00"
        );
    }

    #[test]
    fn as_str_non_ascii() {
        let a = AuthorisationResponseCode([0xC3, 0x28]);
        assert_eq!(a.as_str(), Err(Error::InvalidValue));
        let a = AuthorisationResponseCode([b'A', 0x80]);
        assert_eq!(a.as_str(), Err(Error::InvalidValue));
    }

    #[test]
    fn parse_wrong_length() {
        assert_eq!(
            AuthorisationResponseCode::parse(&[]),
            Err(Error::WrongLength {
                expected: 2,
                got: 0
            })
        );
        assert_eq!(
            AuthorisationResponseCode::parse(&[b'Y']),
            Err(Error::WrongLength {
                expected: 2,
                got: 1
            })
        );
        assert_eq!(
            AuthorisationResponseCode::parse(b"Y1Z"),
            Err(Error::WrongLength {
                expected: 2,
                got: 3
            })
        );
    }

    #[test]
    fn table_35_constants() {
        assert_eq!(
            AuthorisationResponseCode::OFFLINE_APPROVED.to_bytes(),
            *b"Y1"
        );
        assert_eq!(
            AuthorisationResponseCode::OFFLINE_DECLINED.to_bytes(),
            *b"Z1"
        );
        assert_eq!(
            AuthorisationResponseCode::UNABLE_TO_GO_ONLINE_OFFLINE_APPROVED.to_bytes(),
            *b"Y3"
        );
        assert_eq!(
            AuthorisationResponseCode::UNABLE_TO_GO_ONLINE_OFFLINE_DECLINED.to_bytes(),
            *b"Z3"
        );
    }
}
