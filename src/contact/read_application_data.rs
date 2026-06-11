//! Book 3 §10.2 p.94 - Read Application Data.

use crate::core::apdu::sw;
use crate::core::card_reader::CardReader;
use crate::core::error::Error;
use crate::core::read_record::{self, ReadRecordResponse};
use crate::core::tag_store::{Source, TagStore};
use crate::de::application_file_locator::ApplicationFileLocator;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ReadApplicationDataOutcome {
    pub oda_input: Vec<u8>,
    pub oda_record_not_seventy_template: bool,
}

#[derive(Debug)]
pub enum ReadApplicationDataError<TransportError> {
    Transport(TransportError),
    Spec(Error),
    NonOkStatusWord { sfi: u8, record_number: u8, sw: u16 },
}

impl<E: std::fmt::Display> std::fmt::Display for ReadApplicationDataError<E> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Transport(e) => write!(f, "card transport error: {}", e),
            Self::Spec(e) => write!(f, "{}", e),
            Self::NonOkStatusWord {
                sfi,
                record_number,
                sw,
            } => write!(
                f,
                "READ RECORD SFI {} record {} returned SW {:04X}",
                sfi, record_number, sw
            ),
        }
    }
}

impl<E: std::error::Error + 'static> std::error::Error for ReadApplicationDataError<E> {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Transport(e) => Some(e),
            Self::Spec(e) => Some(e),
            Self::NonOkStatusWord { .. } => None,
        }
    }
}

pub fn read_application_data<C: CardReader>(
    card: &mut C,
    afl: &ApplicationFileLocator,
    tag_store: &mut TagStore,
) -> std::result::Result<ReadApplicationDataOutcome, ReadApplicationDataError<C::Error>> {
    use ReadApplicationDataError::*;

    let mut outcome = ReadApplicationDataOutcome::default();

    for step in afl.iter_reads() {
        let cmd = read_record::command(step.sfi, step.record_number).map_err(Spec)?;
        let resp = card.transmit(&cmd).map_err(Transport)?;

        if resp.status_word() != sw::OK {
            return Err(NonOkStatusWord {
                sfi: step.sfi,
                record_number: step.record_number,
                sw: resp.status_word(),
            });
        }

        let Ok(record) = ReadRecordResponse::parse(resp.data()) else {
            // §10.2 - non-'70' records do not terminate; §10.3 ODA only.
            if step.in_oda {
                outcome.oda_record_not_seventy_template = true;
            }
            continue;
        };

        let source = Source::Record {
            sfi: step.sfi,
            record: step.record_number,
        };
        for child in record.children() {
            tag_store.insert_tlv(child, source).map_err(Spec)?;
        }

        if step.in_oda {
            let bytes = record.oda_input_bytes(step.sfi).map_err(Spec)?;
            outcome.oda_input.extend_from_slice(bytes);
        }
    }

    Ok(outcome)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::apdu::{Command, Response};
    use crate::core::tag::Tag;
    use crate::core::tags;
    use crate::de::application_file_locator::{
        ApplicationFileLocator, ApplicationFileLocatorEntry,
    };

    struct ScriptedCard {
        script: Vec<(Vec<u8>, Vec<u8>)>,
        cursor: usize,
    }

    impl CardReader for ScriptedCard {
        type Error = Error;
        fn transmit(&mut self, command: &Command) -> std::result::Result<Response, Self::Error> {
            let (expected, reply) = &self.script[self.cursor];
            assert_eq!(
                &command.to_bytes().unwrap(),
                expected,
                "step {}",
                self.cursor
            );
            self.cursor += 1;
            Response::parse(reply)
        }
    }

    fn read_cmd_bytes(sfi: u8, record: u8) -> Vec<u8> {
        // Table 22 - P2 = (sfi << 3) | 0b100.
        vec![0x00, 0xB2, record, (sfi << 3) | 0b100, 0x00]
    }

    fn afl_one(sfi: u8, first: u8, last: u8, oda: u8) -> ApplicationFileLocator {
        ApplicationFileLocator(vec![ApplicationFileLocatorEntry {
            sfi,
            first_record: first,
            last_record: last,
            oda_record_count: oda,
        }])
    }

    fn ok(record_template: &[u8]) -> Vec<u8> {
        let mut v = record_template.to_vec();
        v.extend_from_slice(&[0x90, 0x00]);
        v
    }

    #[test]
    fn single_record_populates_tag_store() {
        let template = [
            0x70, 0x0C, 0x5A, 0x04, 0x12, 0x34, 0x56, 0x78, 0x5F, 0x24, 0x03, 0x25, 0x12, 0x31,
        ];
        let mut card = ScriptedCard {
            script: vec![(read_cmd_bytes(1, 1), ok(&template))],
            cursor: 0,
        };
        let mut store = TagStore::new();
        let afl = afl_one(1, 1, 1, 0);
        let out = read_application_data(&mut card, &afl, &mut store).unwrap();

        assert_eq!(store.len(), 2);
        assert_eq!(store.get(tags::PAN).unwrap(), &[0x12, 0x34, 0x56, 0x78]);
        assert_eq!(
            store.get(tags::APPLICATION_EXPIRATION_DATE).unwrap(),
            &[0x25, 0x12, 0x31]
        );
        let (_, src) = store.get_with_source(tags::PAN).unwrap();
        assert_eq!(src, Source::Record { sfi: 1, record: 1 });
        assert!(out.oda_input.is_empty());
        assert!(!out.oda_record_not_seventy_template);
    }

    #[test]
    fn afl_walk_in_order_and_oda_buffer_assembled() {
        let r1 = [0x70, 0x03, 0x5A, 0x01, 0x11];
        let r2 = [0x70, 0x04, 0x5F, 0x34, 0x01, 0x07];
        let r3 = [0x70, 0x05, 0x9F, 0x36, 0x02, 0x00, 0x01];

        let mut card = ScriptedCard {
            script: vec![
                (read_cmd_bytes(1, 1), ok(&r1)),
                (read_cmd_bytes(1, 2), ok(&r2)),
                (read_cmd_bytes(11, 1), ok(&r3)),
            ],
            cursor: 0,
        };
        let mut store = TagStore::new();
        let afl = ApplicationFileLocator(vec![
            ApplicationFileLocatorEntry {
                sfi: 1,
                first_record: 1,
                last_record: 2,
                oda_record_count: 1,
            },
            ApplicationFileLocatorEntry {
                sfi: 11,
                first_record: 1,
                last_record: 1,
                oda_record_count: 1,
            },
        ]);

        let out = read_application_data(&mut card, &afl, &mut store).unwrap();

        assert_eq!(store.len(), 3);
        assert_eq!(store.get(tags::PAN).unwrap(), &[0x11]);
        assert_eq!(store.get(tags::PAN_SEQUENCE_NUMBER).unwrap(), &[0x07]);
        assert_eq!(
            store.get(tags::APPLICATION_TRANSACTION_COUNTER).unwrap(),
            &[0x00, 0x01]
        );

        let mut expected = Vec::new();
        expected.extend_from_slice(&[0x5A, 0x01, 0x11]);
        expected.extend_from_slice(&r3);
        assert_eq!(out.oda_input, expected);
        assert!(!out.oda_record_not_seventy_template);
    }

    #[test]
    fn non_ok_status_word_returns_error() {
        let mut card = ScriptedCard {
            script: vec![(read_cmd_bytes(1, 1), vec![0x6A, 0x83])],
            cursor: 0,
        };
        let mut store = TagStore::new();
        let afl = afl_one(1, 1, 1, 0);
        let err = read_application_data(&mut card, &afl, &mut store).unwrap_err();
        match err {
            ReadApplicationDataError::NonOkStatusWord {
                sfi,
                record_number,
                sw,
            } => {
                assert_eq!(sfi, 1);
                assert_eq!(record_number, 1);
                assert_eq!(sw, 0x6A83);
            }
            other => panic!("expected NonOkStatusWord, got {:?}", other),
        }
        assert!(store.is_empty());
    }

    #[test]
    fn redundant_primitive_across_records_terminates() {
        let r1 = [0x70, 0x03, 0x5A, 0x01, 0x11];
        let r2 = [0x70, 0x03, 0x5A, 0x01, 0x22];
        let mut card = ScriptedCard {
            script: vec![
                (read_cmd_bytes(1, 1), ok(&r1)),
                (read_cmd_bytes(1, 2), ok(&r2)),
            ],
            cursor: 0,
        };
        let mut store = TagStore::new();
        let afl = afl_one(1, 1, 2, 0);
        let err = read_application_data(&mut card, &afl, &mut store).unwrap_err();
        match err {
            ReadApplicationDataError::Spec(Error::RedundantPrimitive { tag }) => {
                assert_eq!(tag, Tag(0x5A));
            }
            other => panic!("expected RedundantPrimitive, got {:?}", other),
        }
    }

    #[test]
    fn non_seventy_record_in_oda_sets_flag() {
        let bad = [0x77, 0x02, 0x9F, 0x36];
        let mut card = ScriptedCard {
            script: vec![(read_cmd_bytes(1, 1), ok(&bad))],
            cursor: 0,
        };
        let mut store = TagStore::new();
        let afl = afl_one(1, 1, 1, 1);
        let out = read_application_data(&mut card, &afl, &mut store).unwrap();
        assert!(out.oda_record_not_seventy_template);
        assert!(out.oda_input.is_empty());
        assert!(store.is_empty());
    }

    #[test]
    fn non_seventy_record_outside_oda_does_not_set_flag() {
        let bad = [0x77, 0x02, 0x9F, 0x36];
        let mut card = ScriptedCard {
            script: vec![(read_cmd_bytes(1, 1), ok(&bad))],
            cursor: 0,
        };
        let mut store = TagStore::new();
        let afl = afl_one(1, 1, 1, 0);
        let out = read_application_data(&mut card, &afl, &mut store).unwrap();
        assert!(!out.oda_record_not_seventy_template);
        assert!(out.oda_input.is_empty());
    }

    #[test]
    fn empty_afl_yields_empty_outcome() {
        let mut card = ScriptedCard {
            script: vec![],
            cursor: 0,
        };
        let mut store = TagStore::new();
        let afl = ApplicationFileLocator(vec![]);
        let out = read_application_data(&mut card, &afl, &mut store).unwrap();
        assert!(out.oda_input.is_empty());
        assert!(!out.oda_record_not_seventy_template);
        assert!(store.is_empty());
    }

    #[test]
    fn oda_excerpt_sfi_1_to_10_drops_outer_tag_and_length() {
        let template = [0x70, 0x05, 0x9F, 0x36, 0x02, 0x00, 0x42];
        let mut card = ScriptedCard {
            script: vec![(read_cmd_bytes(1, 1), ok(&template))],
            cursor: 0,
        };
        let mut store = TagStore::new();
        let afl = afl_one(1, 1, 1, 1);
        let out = read_application_data(&mut card, &afl, &mut store).unwrap();
        assert_eq!(out.oda_input, vec![0x9F, 0x36, 0x02, 0x00, 0x42]);
    }

    #[test]
    fn oda_excerpt_sfi_11_to_30_includes_full_data_field() {
        let template = [0x70, 0x05, 0x9F, 0x36, 0x02, 0x00, 0x42];
        let mut card = ScriptedCard {
            script: vec![(read_cmd_bytes(11, 1), ok(&template))],
            cursor: 0,
        };
        let mut store = TagStore::new();
        let afl = afl_one(11, 1, 1, 1);
        let out = read_application_data(&mut card, &afl, &mut store).unwrap();
        assert_eq!(out.oda_input, template.to_vec());
    }

    #[test]
    fn record_iteration_walks_entries_left_to_right() {
        let r1 = [0x70, 0x03, 0x5A, 0x01, 0xAA];
        let r2 = [0x70, 0x04, 0x5F, 0x24, 0x01, 0x07];
        let r3 = [0x70, 0x04, 0x9F, 0x36, 0x01, 0x05];

        let mut card = ScriptedCard {
            script: vec![
                (read_cmd_bytes(1, 2), ok(&r1)),
                (read_cmd_bytes(1, 3), ok(&r2)),
                (read_cmd_bytes(2, 1), ok(&r3)),
            ],
            cursor: 0,
        };
        let mut store = TagStore::new();
        let afl = ApplicationFileLocator(vec![
            ApplicationFileLocatorEntry {
                sfi: 1,
                first_record: 2,
                last_record: 3,
                oda_record_count: 0,
            },
            ApplicationFileLocatorEntry {
                sfi: 2,
                first_record: 1,
                last_record: 1,
                oda_record_count: 0,
            },
        ]);
        read_application_data(&mut card, &afl, &mut store).unwrap();
        assert_eq!(card.cursor, 3);
    }
}
