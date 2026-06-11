use crate::core::tag::Tag;
use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    UnexpectedEof,
    TagTooLong,
    LengthTooLong,
    IndefiniteLength,
    NotConstructed,
    WrongLength { expected: usize, got: usize },
    InvalidValue,
    /// Book 3 §10.2.
    RedundantPrimitive { tag: Tag },
    /// Book 3 §10.2.
    MissingMandatory { tag: Tag },
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnexpectedEof => write!(f, "unexpected end of input"),
            Self::TagTooLong => write!(f, "tag exceeds 4 bytes"),
            Self::LengthTooLong => write!(f, "length field exceeds 4 subsequent bytes"),
            Self::IndefiniteLength => write!(f, "indefinite length not permitted by EMV"),
            Self::NotConstructed => write!(f, "tag is primitive, has no children"),
            Self::WrongLength { expected, got } => {
                write!(f, "wrong length: expected {}, got {}", expected, got)
            }
            Self::InvalidValue => write!(f, "invalid value for data element"),
            Self::RedundantPrimitive { tag } => {
                write!(f, "redundant primitive data object for tag {:?}", tag)
            }
            Self::MissingMandatory { tag } => {
                write!(f, "missing mandatory tag {:?}", tag)
            }
        }
    }
}

impl std::error::Error for Error {}

pub type Result<T> = std::result::Result<T, Error>;
