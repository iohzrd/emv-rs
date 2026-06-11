//! PC/SC adapter for [`crate::core::card_reader::CardReader`].

use crate::core::apdu::{Cla, Command, Ins, Response, sw};
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
        transmit_apdu(command, &mut |send| {
            let mut rx = [0u8; pcsc::MAX_BUFFER_SIZE];
            Ok(self.inner.transmit(send, &mut rx)?.to_vec())
        })
    }
}

/// Book 3 §6.3.5 - '61xx' and '6Cxx' apply to the TPDU and are not
/// returned to the APDU. Under T=0 the card answers '61xx' (SW2
/// response bytes still available, retrieved with GET RESPONSE) and
/// '6Cxx' (wrong length Le; reissue with Le = SW2); complete both
/// here so the application layer receives whole APDU responses
/// (Book 1 §11.1 transport layer).
fn transmit_apdu(
    command: &Command,
    transmit_raw: &mut impl FnMut(&[u8]) -> Result<Vec<u8>, PcscError>,
) -> Result<Response, PcscError> {
    let mut pending = command.clone();
    let mut accumulated: Vec<u8> = Vec::new();
    // Each '61xx' round retrieves at most 256 bytes; 256 rounds bound
    // a card that never stops answering '61xx'.
    for _ in 0..256 {
        let received = transmit_raw(&pending.to_bytes()?)?;
        let response = Response::parse(&received)?;
        match response.status_word() & 0xFF00 {
            sw::BYTES_AVAILABLE_BASE => {
                accumulated.extend_from_slice(response.data());
                pending = Command {
                    cla: Cla(0x00),
                    ins: Ins::GET_RESPONSE,
                    p1: 0x00,
                    p2: 0x00,
                    data: Vec::new(),
                    le: Some(response.sw2()),
                };
            }
            sw::WRONG_LENGTH_LE_BASE => {
                pending.le = Some(response.sw2());
            }
            _ => {
                if accumulated.is_empty() {
                    return Ok(response);
                }
                accumulated.extend_from_slice(response.data());
                return Ok(Response::new(accumulated, response.sw1(), response.sw2())?);
            }
        }
    }
    Err(PcscError::Spec(EmvError::LengthTooLong))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn select_by_name(name: &[u8]) -> Command {
        Command {
            cla: Cla(0x00),
            ins: Ins::SELECT,
            p1: 0x04,
            p2: 0x00,
            data: name.to_vec(),
            le: Some(0x00),
        }
    }

    /// Replays `exchanges` (expected C-APDU, R-APDU) in order,
    /// panicking on any deviation.
    fn scripted(
        exchanges: Vec<(Vec<u8>, Vec<u8>)>,
    ) -> impl FnMut(&[u8]) -> Result<Vec<u8>, PcscError> {
        let mut cursor = 0;
        move |sent: &[u8]| {
            let (expected, reply) = &exchanges[cursor];
            assert_eq!(sent, expected.as_slice(), "exchange {cursor}");
            cursor += 1;
            Ok(reply.clone())
        }
    }

    #[test]
    fn response_without_tpdu_status_passes_through() {
        let command = select_by_name(b"1PAY.SYS.DDF01");
        let mut raw = scripted(vec![(
            command.to_bytes().unwrap(),
            vec![0x6F, 0x02, 0x84, 0x00, 0x90, 0x00],
        )]);
        let response = transmit_apdu(&command, &mut raw).unwrap();
        assert_eq!(response.status_word(), sw::OK);
        assert_eq!(response.data(), &[0x6F, 0x02, 0x84, 0x00]);
    }

    #[test]
    fn error_status_word_passes_through() {
        let command = select_by_name(b"1PAY.SYS.DDF01");
        let mut raw = scripted(vec![(command.to_bytes().unwrap(), vec![0x6A, 0x82])]);
        let response = transmit_apdu(&command, &mut raw).unwrap();
        assert_eq!(response.status_word(), sw::FILE_NOT_FOUND);
        assert!(response.data().is_empty());
    }

    #[test]
    fn bytes_available_triggers_get_response() {
        let command = select_by_name(b"1PAY.SYS.DDF01");
        let fci = vec![0x6F, 0x04, 0x84, 0x02, 0xAA, 0xBB];
        let mut reply = fci.clone();
        reply.extend_from_slice(&[0x90, 0x00]);
        let mut raw = scripted(vec![
            (command.to_bytes().unwrap(), vec![0x61, 0x06]),
            (vec![0x00, 0xC0, 0x00, 0x00, 0x06], reply),
        ]);
        let response = transmit_apdu(&command, &mut raw).unwrap();
        assert_eq!(response.status_word(), sw::OK);
        assert_eq!(response.data(), fci.as_slice());
    }

    #[test]
    fn chained_bytes_available_concatenates_data() {
        let command = select_by_name(b"1PAY.SYS.DDF01");
        let mut raw = scripted(vec![
            (command.to_bytes().unwrap(), vec![0x61, 0x02]),
            (
                vec![0x00, 0xC0, 0x00, 0x00, 0x02],
                vec![0x11, 0x22, 0x61, 0x03],
            ),
            (
                vec![0x00, 0xC0, 0x00, 0x00, 0x03],
                vec![0x33, 0x44, 0x55, 0x90, 0x00],
            ),
        ]);
        let response = transmit_apdu(&command, &mut raw).unwrap();
        assert_eq!(response.status_word(), sw::OK);
        assert_eq!(response.data(), &[0x11, 0x22, 0x33, 0x44, 0x55]);
    }

    #[test]
    fn wrong_length_le_reissues_with_exact_length() {
        let command = select_by_name(b"1PAY.SYS.DDF01");
        let mut corrected = command.clone();
        corrected.le = Some(0x02);
        let mut raw = scripted(vec![
            (command.to_bytes().unwrap(), vec![0x6C, 0x02]),
            (corrected.to_bytes().unwrap(), vec![0xAA, 0xBB, 0x90, 0x00]),
        ]);
        let response = transmit_apdu(&command, &mut raw).unwrap();
        assert_eq!(response.status_word(), sw::OK);
        assert_eq!(response.data(), &[0xAA, 0xBB]);
    }

    #[test]
    fn wrong_length_le_on_get_response_corrects_get_response() {
        let command = select_by_name(b"1PAY.SYS.DDF01");
        let mut raw = scripted(vec![
            (command.to_bytes().unwrap(), vec![0x61, 0x10]),
            (vec![0x00, 0xC0, 0x00, 0x00, 0x10], vec![0x6C, 0x04]),
            (
                vec![0x00, 0xC0, 0x00, 0x00, 0x04],
                vec![0x01, 0x02, 0x03, 0x04, 0x90, 0x00],
            ),
        ]);
        let response = transmit_apdu(&command, &mut raw).unwrap();
        assert_eq!(response.status_word(), sw::OK);
        assert_eq!(response.data(), &[0x01, 0x02, 0x03, 0x04]);
    }

    #[test]
    fn endless_bytes_available_is_bounded() {
        let command = select_by_name(b"1PAY.SYS.DDF01");
        let mut raw = |_sent: &[u8]| Ok(vec![0x61, 0x01]);
        let err = transmit_apdu(&command, &mut raw).unwrap_err();
        assert!(matches!(err, PcscError::Spec(EmvError::LengthTooLong)));
    }
}
