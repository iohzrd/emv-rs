//! PC/SC adapter for [`crate::core::card_reader::CardReader`].

use crate::core::apdu::{Command, Response};
use crate::core::card_reader::CardReader;
use crate::core::error::Error as EmvError;
use std::fmt;

#[derive(Debug)]
pub enum PcscError {
    Pcsc(pcsc::Error),
    Spec(EmvError),
}

impl fmt::Display for PcscError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Pcsc(e) => write!(f, "pcsc: {}", e),
            Self::Spec(e) => write!(f, "{}", e),
        }
    }
}

impl std::error::Error for PcscError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Pcsc(e) => Some(e),
            Self::Spec(e) => Some(e),
        }
    }
}

impl From<pcsc::Error> for PcscError {
    fn from(e: pcsc::Error) -> Self {
        Self::Pcsc(e)
    }
}

impl From<EmvError> for PcscError {
    fn from(e: EmvError) -> Self {
        Self::Spec(e)
    }
}

pub struct PcscCardReader {
    pub inner: pcsc::Card,
}

impl PcscCardReader {
    pub fn new(card: pcsc::Card) -> Self {
        Self { inner: card }
    }
}

impl From<pcsc::Card> for PcscCardReader {
    fn from(card: pcsc::Card) -> Self {
        Self { inner: card }
    }
}

impl CardReader for PcscCardReader {
    type Error = PcscError;

    fn transmit(&mut self, command: &Command) -> Result<Response, Self::Error> {
        let send = command.to_bytes()?;
        let mut rx = [0u8; pcsc::MAX_BUFFER_SIZE];
        let recv = self.inner.transmit(&send, &mut rx)?;
        Ok(Response::parse(recv)?)
    }
}
