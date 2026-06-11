//! Book 1 §11.1 / Book 3 §6 - APDU command/response handling.

use crate::core::error::{Error, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Cla(pub u8);

impl Cla {
    pub const INTER_INDUSTRY: Self = Self(0x00);
    pub const PROPRIETARY: Self = Self(0x80);

    pub fn is_proprietary(self) -> bool {
        self.0 & 0x80 != 0
    }

    pub fn is_interindustry(self) -> bool {
        self.0 & 0x80 == 0
    }

    pub fn command_chaining(self) -> Option<bool> {
        self.is_interindustry().then(|| self.0 & 0x10 != 0)
    }

    pub fn logical_channel(self) -> u8 {
        if self.0 & 0xC0 == 0x40 {
            4 + (self.0 & 0x0F)
        } else {
            self.0 & 0x03
        }
    }
}

impl From<u8> for Cla {
    fn from(b: u8) -> Self {
        Self(b)
    }
}

impl From<Cla> for u8 {
    fn from(c: Cla) -> Self {
        c.0
    }
}

// Book 3 §6.3.2 Table 3.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Ins(pub u8);

impl Ins {
    pub const APPLICATION_BLOCK: Self = Self(0x1E);
    pub const APPLICATION_UNBLOCK: Self = Self(0x18);
    pub const CARD_BLOCK: Self = Self(0x16);
    // Book C-3 Annex D.4 - EXTENDED GET PROCESSING OPTIONS.
    pub const EXTENDED_GET_PROCESSING_OPTIONS: Self = Self(0xE0);
    pub const EXTERNAL_AUTHENTICATE: Self = Self(0x82);
    pub const GENERATE_APPLICATION_CRYPTOGRAM: Self = Self(0xAE);
    pub const GET_CHALLENGE: Self = Self(0x84);
    pub const GET_DATA: Self = Self(0xCA);
    pub const GET_PROCESSING_OPTIONS: Self = Self(0xA8);
    pub const INTERNAL_AUTHENTICATE: Self = Self(0x88);
    pub const PIN_CHANGE_UNBLOCK: Self = Self(0x24);
    pub const PUT_DATA: Self = Self(0xDA);
    pub const READ_RECORD: Self = Self(0xB2);
    pub const SELECT: Self = Self(0xA4);
    pub const VERIFY: Self = Self(0x20);
    pub const GET_RESPONSE: Self = Self(0xC0);

    pub fn data_field_format_is_ber_tlv(self) -> bool {
        self.0 & 0x01 != 0
    }
}

impl From<u8> for Ins {
    fn from(b: u8) -> Self {
        Self(b)
    }
}

impl From<Ins> for u8 {
    fn from(ins: Ins) -> Self {
        ins.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Command {
    pub cla: Cla,
    pub ins: Ins,
    pub p1: u8,
    pub p2: u8,
    pub data: Vec<u8>,
    pub le: Option<u8>,
}

impl Command {
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        if self.cla.0 == 0xFF {
            return Err(Error::InvalidValue);
        }
        if self.data.len() > 0xFF {
            return Err(Error::LengthTooLong);
        }
        let mut out = Vec::with_capacity(
            4 + (!self.data.is_empty() as usize) + self.data.len() + (self.le.is_some() as usize),
        );
        out.extend_from_slice(&[self.cla.0, self.ins.0, self.p1, self.p2]);
        if !self.data.is_empty() {
            out.push(self.data.len() as u8);
            out.extend_from_slice(&self.data);
        }
        if let Some(le) = self.le {
            out.push(le);
        }
        Ok(out)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < 4 {
            return Err(Error::UnexpectedEof);
        }
        if bytes[0] == 0xFF {
            return Err(Error::InvalidValue);
        }
        let cla = Cla(bytes[0]);
        let ins = Ins(bytes[1]);
        let p1 = bytes[2];
        let p2 = bytes[3];
        match bytes.len() {
            4 => Ok(Command {
                cla,
                ins,
                p1,
                p2,
                data: Vec::new(),
                le: None,
            }),
            5 => Ok(Command {
                cla,
                ins,
                p1,
                p2,
                data: Vec::new(),
                le: Some(bytes[4]),
            }),
            n => {
                let lc = bytes[4] as usize;
                let body_start = 5;
                let body_end = body_start + lc;
                if body_end == n {
                    Ok(Command {
                        cla,
                        ins,
                        p1,
                        p2,
                        data: bytes[body_start..body_end].to_vec(),
                        le: None,
                    })
                } else if body_end + 1 == n {
                    Ok(Command {
                        cla,
                        ins,
                        p1,
                        p2,
                        data: bytes[body_start..body_end].to_vec(),
                        le: Some(bytes[body_end]),
                    })
                } else {
                    Err(Error::InvalidValue)
                }
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Response {
    data: Vec<u8>,
    sw1: u8,
    sw2: u8,
}

impl Response {
    pub fn new(data: Vec<u8>, sw1: u8, sw2: u8) -> Result<Self> {
        if !matches!(sw1, 0x61..=0x6F | 0x90..=0x9F) {
            return Err(Error::InvalidValue);
        }
        Ok(Response { data, sw1, sw2 })
    }

    pub fn parse(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < 2 {
            return Err(Error::UnexpectedEof);
        }
        let split = bytes.len() - 2;
        Self::new(bytes[..split].to_vec(), bytes[split], bytes[split + 1])
    }

    pub fn data(&self) -> &[u8] {
        &self.data
    }

    pub fn sw1(&self) -> u8 {
        self.sw1
    }

    pub fn sw2(&self) -> u8 {
        self.sw2
    }

    pub fn is_normal(&self) -> bool {
        self.sw1 == 0x90 || self.sw1 == 0x61
    }

    pub fn status_word(&self) -> u16 {
        ((self.sw1 as u16) << 8) | (self.sw2 as u16)
    }
}

// Book 3 Table 4 + ISO 7816-4 §5.1.3 Tables 5/6.
pub mod sw {
    // ── Normal processing ──

    pub const OK: u16 = 0x9000;
    pub const BYTES_AVAILABLE_BASE: u16 = 0x6100;

    // ── Warning processing (NV memory unchanged: 62xx) ──

    pub const WARNING_NO_INFORMATION: u16 = 0x6200;
    pub const WARNING_DATA_MAY_BE_CORRUPTED: u16 = 0x6281;
    pub const END_OF_FILE_OR_RECORD: u16 = 0x6282;
    pub const SELECTED_FILE_INVALIDATED: u16 = 0x6283;
    pub const FCI_NOT_FORMATTED: u16 = 0x6284;
    pub const SELECTED_FILE_IN_TERMINATION: u16 = 0x6285;
    pub const NO_INPUT_FROM_SENSOR: u16 = 0x6286;

    // ── Warning processing (NV memory changed: 63xx) ──

    pub const AUTHENTICATION_FAILED: u16 = 0x6300;
    pub const FILE_FILLED_BY_LAST_WRITE: u16 = 0x6381;
    pub const COUNTER_PROVIDED_BASE: u16 = 0x63C0;

    // ── Execution error (NV unchanged: 64xx; NV changed: 65xx; security: 66xx) ──

    pub const EXECUTION_ERROR: u16 = 0x6400;
    pub const IMMEDIATE_RESPONSE_REQUIRED: u16 = 0x6401;
    pub const EXECUTION_ERROR_NV_CHANGED: u16 = 0x6500;
    pub const MEMORY_FAILURE: u16 = 0x6581;
    pub const SECURITY_RELATED_ISSUES: u16 = 0x6600;

    // ── Checking errors (67xx–6Fxx) ──

    pub const WRONG_LENGTH: u16 = 0x6700;

    pub const COMMAND_CHAINING_FAILED: u16 = 0x6800;
    pub const LOGICAL_CHANNEL_NOT_SUPPORTED: u16 = 0x6881;
    pub const SECURE_MESSAGING_NOT_SUPPORTED: u16 = 0x6882;
    pub const LAST_CHAIN_COMMAND_EXPECTED: u16 = 0x6883;
    pub const COMMAND_CHAINING_NOT_SUPPORTED: u16 = 0x6884;

    pub const COMMAND_NOT_ALLOWED: u16 = 0x6900;
    pub const COMMAND_INCOMPATIBLE_WITH_FILE_STRUCTURE: u16 = 0x6981;
    pub const SECURITY_STATUS_NOT_SATISFIED: u16 = 0x6982;
    pub const AUTHENTICATION_METHOD_BLOCKED: u16 = 0x6983;
    pub const REFERENCED_DATA_INVALIDATED: u16 = 0x6984;
    pub const CONDITIONS_OF_USE_NOT_SATISFIED: u16 = 0x6985;
    pub const NO_CURRENT_EF: u16 = 0x6986;
    pub const SM_DATA_OBJECTS_MISSING: u16 = 0x6987;
    pub const SM_DATA_OBJECTS_INCORRECT: u16 = 0x6988;

    pub const WRONG_PARAMETERS_P1_P2: u16 = 0x6A00;
    pub const INCORRECT_PARAMETERS_IN_DATA_FIELD: u16 = 0x6A80;
    pub const FUNCTION_NOT_SUPPORTED: u16 = 0x6A81;
    pub const FILE_NOT_FOUND: u16 = 0x6A82;
    pub const RECORD_NOT_FOUND: u16 = 0x6A83;
    pub const NOT_ENOUGH_MEMORY: u16 = 0x6A84;
    pub const NC_INCONSISTENT_WITH_TLV: u16 = 0x6A85;
    pub const INCORRECT_P1_P2: u16 = 0x6A86;
    pub const NC_INCONSISTENT_WITH_P1_P2: u16 = 0x6A87;
    pub const REFERENCED_DATA_NOT_FOUND: u16 = 0x6A88;
    pub const FILE_ALREADY_EXISTS: u16 = 0x6A89;
    pub const DF_NAME_ALREADY_EXISTS: u16 = 0x6A8A;

    pub const WRONG_P1_P2: u16 = 0x6B00;

    pub const WRONG_LENGTH_LE_BASE: u16 = 0x6C00;

    pub const INS_NOT_SUPPORTED: u16 = 0x6D00;
    pub const CLA_NOT_SUPPORTED: u16 = 0x6E00;
    pub const NO_PRECISE_DIAGNOSIS: u16 = 0x6F00;

    // ── Card-event ranges (ISO §5.1.3 Table 6) ──

    pub fn is_triggering_by_card_warning(sw: u16) -> bool {
        let sw1 = (sw >> 8) as u8;
        let sw2 = sw as u8;
        sw1 == 0x62 && (0x02..=0x80).contains(&sw2)
    }

    pub fn is_triggering_by_card_error(sw: u16) -> bool {
        let sw1 = (sw >> 8) as u8;
        let sw2 = sw as u8;
        sw1 == 0x64 && (0x02..=0x80).contains(&sw2)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ins_constants_match_book_3_table_3() {
        for (ins, byte) in [
            (Ins::APPLICATION_BLOCK, 0x1E),
            (Ins::APPLICATION_UNBLOCK, 0x18),
            (Ins::CARD_BLOCK, 0x16),
            (Ins::EXTERNAL_AUTHENTICATE, 0x82),
            (Ins::GENERATE_APPLICATION_CRYPTOGRAM, 0xAE),
            (Ins::GET_CHALLENGE, 0x84),
            (Ins::GET_DATA, 0xCA),
            (Ins::GET_PROCESSING_OPTIONS, 0xA8),
            (Ins::INTERNAL_AUTHENTICATE, 0x88),
            (Ins::PIN_CHANGE_UNBLOCK, 0x24),
            (Ins::READ_RECORD, 0xB2),
            (Ins::SELECT, 0xA4),
            (Ins::VERIFY, 0x20),
            (Ins::GET_RESPONSE, 0xC0),
        ] {
            assert_eq!(ins.0, byte);
        }
    }

    #[test]
    fn ins_from_into_u8() {
        let ins: Ins = 0xA4.into();
        assert_eq!(ins, Ins::SELECT);
        let b: u8 = Ins::SELECT.into();
        assert_eq!(b, 0xA4);
    }

    #[test]
    fn cla_from_into_u8() {
        let cla: Cla = 0x80.into();
        assert_eq!(cla, Cla::PROPRIETARY);
        let b: u8 = Cla::PROPRIETARY.into();
        assert_eq!(b, 0x80);
    }

    #[test]
    fn ins_data_field_format_per_iso_5_1_2() {
        for ins in [
            Ins::APPLICATION_BLOCK,
            Ins::APPLICATION_UNBLOCK,
            Ins::CARD_BLOCK,
            Ins::EXTERNAL_AUTHENTICATE,
            Ins::GENERATE_APPLICATION_CRYPTOGRAM,
            Ins::GET_CHALLENGE,
            Ins::GET_DATA,
            Ins::GET_PROCESSING_OPTIONS,
            Ins::INTERNAL_AUTHENTICATE,
            Ins::PIN_CHANGE_UNBLOCK,
            Ins::READ_RECORD,
            Ins::SELECT,
            Ins::VERIFY,
            Ins::GET_RESPONSE,
        ] {
            assert!(!ins.data_field_format_is_ber_tlv(), "{:?}", ins);
        }
        assert!(Ins(0x21).data_field_format_is_ber_tlv());
    }

    #[test]
    fn from_bytes_case_1_header_only() {
        let cmd = Command::from_bytes(&[0x00, 0xA4, 0x04, 0x00]).unwrap();
        assert_eq!(cmd.cla.0, 0x00);
        assert_eq!(cmd.ins, Ins::SELECT);
        assert_eq!(cmd.p1, 0x04);
        assert_eq!(cmd.p2, 0x00);
        assert!(cmd.data.is_empty());
        assert_eq!(cmd.le, None);
    }

    #[test]
    fn from_bytes_case_2_header_plus_le() {
        let cmd = Command::from_bytes(&[0x00, 0xB2, 0x01, 0x0C, 0x00]).unwrap();
        assert_eq!(cmd.ins, Ins::READ_RECORD);
        assert!(cmd.data.is_empty());
        assert_eq!(cmd.le, Some(0x00));
    }

    #[test]
    fn from_bytes_case_3_header_plus_data() {
        let cmd =
            Command::from_bytes(&[0x84, 0x18, 0x00, 0x00, 0x04, 0xDE, 0xAD, 0xBE, 0xEF]).unwrap();
        assert_eq!(cmd.cla.0, 0x84);
        assert_eq!(cmd.ins, Ins::APPLICATION_UNBLOCK);
        assert_eq!(cmd.data, vec![0xDE, 0xAD, 0xBE, 0xEF]);
        assert_eq!(cmd.le, None);
    }

    #[test]
    fn from_bytes_case_4_header_plus_data_plus_le() {
        let cmd = Command::from_bytes(&[
            0x00, 0xA4, 0x04, 0x00, 0x07, 0xA0, 0x00, 0x00, 0x00, 0x03, 0x10, 0x10, 0x00,
        ])
        .unwrap();
        assert_eq!(cmd.ins, Ins::SELECT);
        assert_eq!(cmd.data, vec![0xA0, 0x00, 0x00, 0x00, 0x03, 0x10, 0x10]);
        assert_eq!(cmd.le, Some(0x00));
    }

    #[test]
    fn from_bytes_round_trips_to_bytes() {
        for wire in [
            vec![0x00, 0xA4, 0x04, 0x00],
            vec![0x00, 0xB2, 0x01, 0x0C, 0x00],
            vec![0x84, 0x18, 0x00, 0x00, 0x04, 0xDE, 0xAD, 0xBE, 0xEF],
            vec![
                0x00, 0xA4, 0x04, 0x00, 0x07, 0xA0, 0, 0, 0, 3, 0x10, 0x10, 0x00,
            ],
        ] {
            let cmd = Command::from_bytes(&wire).unwrap();
            assert_eq!(cmd.to_bytes().unwrap(), wire);
        }
    }

    #[test]
    fn from_bytes_too_short_rejected() {
        assert_eq!(Command::from_bytes(&[]), Err(Error::UnexpectedEof));
        assert_eq!(Command::from_bytes(&[0x00]), Err(Error::UnexpectedEof));
        assert_eq!(
            Command::from_bytes(&[0x00, 0xA4, 0x04]),
            Err(Error::UnexpectedEof)
        );
    }

    #[test]
    fn from_bytes_lc_inconsistent_rejected() {
        assert_eq!(
            Command::from_bytes(&[0x84, 0x18, 0x00, 0x00, 0x04, 0xDE, 0xAD]),
            Err(Error::InvalidValue),
        );
    }

    #[test]
    fn from_bytes_rejects_cla_ff_per_iso_7816_3() {
        assert_eq!(
            Command::from_bytes(&[0xFF, 0xA4, 0x04, 0x00]),
            Err(Error::InvalidValue),
        );
    }

    #[test]
    fn command_rejects_cla_ff_per_iso_7816_3() {
        let cmd = Command {
            cla: Cla(0xFF),
            ins: Ins::SELECT,
            ..Default::default()
        };
        assert_eq!(cmd.to_bytes(), Err(Error::InvalidValue));
    }

    #[test]
    fn response_rejects_invalid_sw1_per_iso_5_1_3() {
        assert_eq!(Response::parse(&[0x60, 0x00]), Err(Error::InvalidValue));
        assert_eq!(Response::parse(&[0x00, 0x00]), Err(Error::InvalidValue));
        assert_eq!(Response::parse(&[0x70, 0x00]), Err(Error::InvalidValue));
        assert_eq!(Response::parse(&[0x80, 0x00]), Err(Error::InvalidValue));
        assert_eq!(Response::parse(&[0xA0, 0x00]), Err(Error::InvalidValue));
        assert!(Response::parse(&[0x61, 0x00]).is_ok());
        assert!(Response::parse(&[0x6F, 0x00]).is_ok());
        assert!(Response::parse(&[0x90, 0x00]).is_ok());
        assert!(Response::parse(&[0x9F, 0x00]).is_ok());
    }

    #[test]
    fn sw_constants_match_iso_7816_4_table_6() {
        assert_eq!(sw::WRONG_LENGTH, 0x6700);
        assert_eq!(sw::SECURITY_STATUS_NOT_SATISFIED, 0x6982);
        assert_eq!(sw::NO_CURRENT_EF, 0x6986);
        assert_eq!(sw::INCORRECT_P1_P2, 0x6A86);
        assert_eq!(sw::INS_NOT_SUPPORTED, 0x6D00);
        assert_eq!(sw::CLA_NOT_SUPPORTED, 0x6E00);
        assert_eq!(sw::NO_PRECISE_DIAGNOSIS, 0x6F00);
        assert_eq!(sw::MEMORY_FAILURE, 0x6581);
        assert_eq!(sw::SECURITY_RELATED_ISSUES, 0x6600);
        assert_eq!(sw::NO_INPUT_FROM_SENSOR, 0x6286);
        assert_eq!(sw::IMMEDIATE_RESPONSE_REQUIRED, 0x6401);
    }

    #[test]
    fn sw_triggering_by_card_ranges() {
        assert!(sw::is_triggering_by_card_warning(0x6202));
        assert!(sw::is_triggering_by_card_warning(0x6240));
        assert!(sw::is_triggering_by_card_warning(0x6280));
        assert!(!sw::is_triggering_by_card_warning(0x6200));
        assert!(!sw::is_triggering_by_card_warning(0x6201));
        assert!(!sw::is_triggering_by_card_warning(0x6281));
        assert!(!sw::is_triggering_by_card_warning(0x6285));
        assert!(!sw::is_triggering_by_card_warning(0x6402));

        assert!(sw::is_triggering_by_card_error(0x6402));
        assert!(sw::is_triggering_by_card_error(0x6440));
        assert!(sw::is_triggering_by_card_error(0x6480));
        assert!(!sw::is_triggering_by_card_error(0x6400));
        assert!(!sw::is_triggering_by_card_error(0x6401));
        assert!(!sw::is_triggering_by_card_error(0x6481));
        assert!(!sw::is_triggering_by_card_error(0x6202));
    }

    #[test]
    fn cla_class_type() {
        assert!(Cla::INTER_INDUSTRY.is_interindustry());
        assert!(!Cla::INTER_INDUSTRY.is_proprietary());
        assert!(Cla::PROPRIETARY.is_proprietary());
        assert!(!Cla::PROPRIETARY.is_interindustry());
    }

    #[test]
    fn cla_command_chaining() {
        assert_eq!(Cla(0x00).command_chaining(), Some(false));
        assert_eq!(Cla(0x10).command_chaining(), Some(true));
        assert_eq!(Cla(0x80).command_chaining(), None);
    }

    #[test]
    fn cla_logical_channel() {
        assert_eq!(Cla(0x00).logical_channel(), 0);
        assert_eq!(Cla(0x03).logical_channel(), 3);
        assert_eq!(Cla(0x40).logical_channel(), 4);
        assert_eq!(Cla(0x4F).logical_channel(), 19);
        assert_eq!(Cla(0x80).logical_channel(), 0);
    }

    #[test]
    fn command_case_1_header_only() {
        let cmd = Command {
            cla: Cla::INTER_INDUSTRY,
            ins: Ins::SELECT,
            ..Default::default()
        };
        assert_eq!(cmd.to_bytes().unwrap(), vec![0x00, 0xA4, 0x00, 0x00]);
    }

    #[test]
    fn command_case_2_le_only() {
        let cmd = Command {
            cla: Cla::INTER_INDUSTRY,
            ins: Ins::READ_RECORD,
            p1: 0x01,
            p2: 0x0C,
            le: Some(0x00),
            ..Default::default()
        };
        assert_eq!(cmd.to_bytes().unwrap(), vec![0x00, 0xB2, 0x01, 0x0C, 0x00]);
    }

    #[test]
    fn command_case_3_data_no_le() {
        let cmd = Command {
            cla: Cla::PROPRIETARY,
            ins: Ins::GENERATE_APPLICATION_CRYPTOGRAM,
            p1: 0x40,
            data: vec![0xAA, 0xBB, 0xCC],
            ..Default::default()
        };
        assert_eq!(
            cmd.to_bytes().unwrap(),
            vec![0x80, 0xAE, 0x40, 0x00, 0x03, 0xAA, 0xBB, 0xCC]
        );
    }

    #[test]
    fn command_case_4_data_and_le() {
        let cmd = Command {
            cla: Cla::INTER_INDUSTRY,
            ins: Ins::SELECT,
            p1: 0x04,
            data: vec![0xA0, 0x00, 0x00, 0x00, 0x03, 0x10, 0x10],
            le: Some(0x00),
            ..Default::default()
        };
        assert_eq!(
            cmd.to_bytes().unwrap(),
            vec![
                0x00, 0xA4, 0x04, 0x00, 0x07, 0xA0, 0x00, 0x00, 0x00, 0x03, 0x10, 0x10, 0x00,
            ]
        );
    }

    #[test]
    fn command_data_at_short_form_max() {
        let cmd = Command {
            cla: Cla::PROPRIETARY,
            ins: Ins::PIN_CHANGE_UNBLOCK,
            data: vec![0xAA; 255],
            ..Default::default()
        };
        let bytes = cmd.to_bytes().unwrap();
        assert_eq!(bytes[4], 0xFF);
        assert_eq!(bytes.len(), 4 + 1 + 255);
    }

    #[test]
    fn command_data_too_long() {
        let cmd = Command {
            data: vec![0; 256],
            ..Default::default()
        };
        assert_eq!(cmd.to_bytes(), Err(Error::LengthTooLong));
    }

    #[test]
    fn command_can_set_logical_channel_independently_of_ins() {
        let cmd = Command {
            cla: Cla(0x03),
            ins: Ins::SELECT,
            ..Default::default()
        };
        assert_eq!(&cmd.to_bytes().unwrap()[..2], &[0x03, 0xA4]);
        assert_eq!(cmd.cla.logical_channel(), 3);
    }

    #[test]
    fn response_parse_minimum_trailer_only() {
        let r = Response::parse(&[0x90, 0x00]).unwrap();
        assert!(r.data().is_empty());
        assert_eq!(r.sw1(), 0x90);
        assert_eq!(r.sw2(), 0x00);
        assert!(r.is_normal());
        assert_eq!(r.status_word(), sw::OK);
    }

    #[test]
    fn response_parse_with_data() {
        let r = Response::parse(&[0x6F, 0x02, 0x84, 0x00, 0x90, 0x00]).unwrap();
        assert_eq!(r.data(), &[0x6F, 0x02, 0x84, 0x00]);
        assert!(r.is_normal());
    }

    #[test]
    fn response_parse_too_short() {
        assert_eq!(Response::parse(&[]), Err(Error::UnexpectedEof));
        assert_eq!(Response::parse(&[0x90]), Err(Error::UnexpectedEof));
    }

    #[test]
    fn response_match_status_word() {
        let r = Response::parse(&[0x6A, 0x82]).unwrap();
        assert!(!r.is_normal());
        assert_eq!(r.status_word(), sw::FILE_NOT_FOUND);
    }

    #[test]
    fn response_is_normal_covers_61xx_per_iso_5_1_3() {
        let r = Response::parse(&[0xAA, 0xBB, 0x61, 0x10]).unwrap();
        assert!(r.is_normal());
        assert_eq!(r.status_word(), 0x6110);
    }

    #[test]
    fn response_new_validates_sw1() {
        assert_eq!(Response::new(vec![], 0x60, 0x00), Err(Error::InvalidValue));
        assert_eq!(Response::new(vec![], 0x70, 0x00), Err(Error::InvalidValue));
        assert!(Response::new(vec![], 0x90, 0x00).is_ok());
    }

    #[test]
    fn status_word_family_decoding() {
        let r = Response::parse(&[0x63, 0xC7]).unwrap();
        assert_eq!(r.status_word() - sw::COUNTER_PROVIDED_BASE, 7);
        let r = Response::parse(&[0x61, 0x10]).unwrap();
        assert_eq!(r.status_word() - sw::BYTES_AVAILABLE_BASE, 0x10);
        let r = Response::parse(&[0x6C, 0x20]).unwrap();
        assert_eq!(r.status_word() - sw::WRONG_LENGTH_LE_BASE, 0x20);
    }
}
