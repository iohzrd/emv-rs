//! Book 1 §11.1 - Card-reader transport abstraction.

use crate::core::apdu::{Command, Response};

pub trait CardReader {
    type Error;

    fn transmit(&mut self, command: &Command) -> Result<Response, Self::Error>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::apdu::{Cla, Ins, sw};
    use crate::core::error::Error;

    struct ScriptedCard {
        script: Vec<(Vec<u8>, Vec<u8>)>,
        cursor: usize,
    }

    impl CardReader for ScriptedCard {
        type Error = Error;

        fn transmit(&mut self, command: &Command) -> Result<Response, Self::Error> {
            let (expected, reply) = &self.script[self.cursor];
            assert_eq!(&command.to_bytes()?, expected);
            self.cursor += 1;
            Response::parse(reply)
        }
    }

    #[test]
    fn transmit_drives_select_then_read_record() {
        let mut card = ScriptedCard {
            script: vec![
                (
                    vec![
                        0x00, 0xA4, 0x04, 0x00, 0x07, 0xA0, 0, 0, 0, 3, 0x10, 0x10, 0x00,
                    ],
                    vec![0x6F, 0x02, 0x84, 0x00, 0x90, 0x00],
                ),
                (
                    vec![0x00, 0xB2, 0x01, 0x0C, 0x00],
                    vec![0x70, 0x00, 0x90, 0x00],
                ),
            ],
            cursor: 0,
        };

        let select = Command {
            cla: Cla::INTER_INDUSTRY,
            ins: Ins::SELECT,
            p1: 0x04,
            data: vec![0xA0, 0, 0, 0, 3, 0x10, 0x10],
            le: Some(0x00),
            ..Default::default()
        };
        let r = card.transmit(&select).unwrap();
        assert_eq!(r.status_word(), sw::OK);
        assert_eq!(r.data(), &[0x6F, 0x02, 0x84, 0x00]);

        let read = Command {
            cla: Cla::INTER_INDUSTRY,
            ins: Ins::READ_RECORD,
            p1: 0x01,
            p2: 0x0C,
            le: Some(0x00),
            ..Default::default()
        };
        let r = card.transmit(&read).unwrap();
        assert_eq!(r.status_word(), sw::OK);
        assert_eq!(r.data(), &[0x70, 0x00]);
    }

    #[test]
    fn transmit_surfaces_error_status_words() {
        let mut card = ScriptedCard {
            script: vec![(
                vec![
                    0x00, 0xA4, 0x04, 0x00, 0x07, 0xA0, 0, 0, 0, 3, 0x10, 0x10, 0x00,
                ],
                vec![0x6A, 0x82],
            )],
            cursor: 0,
        };
        let select = Command {
            cla: Cla::INTER_INDUSTRY,
            ins: Ins::SELECT,
            p1: 0x04,
            data: vec![0xA0, 0, 0, 0, 3, 0x10, 0x10],
            le: Some(0x00),
            ..Default::default()
        };
        let r = card.transmit(&select).unwrap();
        assert!(!r.is_normal());
        assert_eq!(r.status_word(), sw::FILE_NOT_FOUND);
    }
}
