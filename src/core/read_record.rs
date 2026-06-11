//! Book 3 §6.5.11 - READ RECORD.

use crate::core::apdu::{Cla, Command, Ins};
use crate::core::error::{Error, Result};
use crate::core::tags;
use crate::core::tlv::Tlv;

pub fn command(sfi: u8, record_number: u8) -> Result<Command> {
    if !(1..=30).contains(&sfi) {
        return Err(Error::InvalidValue);
    }
    if record_number == 0 {
        return Err(Error::InvalidValue);
    }
    let p2 = (sfi << 3) | 0b100;
    Ok(Command {
        cla: Cla(0x00),
        ins: Ins::READ_RECORD,
        p1: record_number,
        p2,
        data: Vec::new(),
        le: Some(0x00),
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReadRecordResponse {
    raw: Vec<u8>,
    tlv: Tlv,
}

impl ReadRecordResponse {
    pub fn parse(data: &[u8]) -> Result<Self> {
        let tlv = Tlv::from_bytes(data)?;
        if tlv.tag() != tags::READ_RECORD_RESPONSE_TEMPLATE {
            return Err(Error::InvalidValue);
        }
        Ok(ReadRecordResponse {
            raw: data.to_vec(),
            tlv,
        })
    }

    pub fn raw(&self) -> &[u8] {
        &self.raw
    }

    pub fn tlv(&self) -> &Tlv {
        &self.tlv
    }

    pub fn children(&self) -> &[Tlv] {
        self.tlv
            .value()
            .as_constructed()
            .expect("0x70 is a constructed tag")
    }

    // Book 3 §10.3.
    pub fn oda_input_bytes(&self, sfi: u8) -> Result<&[u8]> {
        match sfi {
            1..=10 => {
                let value_start = self.raw.len() - self.tlv.value_len();
                Ok(&self.raw[value_start..])
            }
            11..=30 => Ok(&self.raw),
            _ => Err(Error::InvalidValue),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::tag::Tag;

    // ---- command builder ---------------------------------------------------

    #[test]
    fn command_builds_per_table_21_and_22() {
        let c = command(1, 1).unwrap();
        assert_eq!(c.to_bytes().unwrap(), vec![0x00, 0xB2, 0x01, 0x0C, 0x00]);
    }

    #[test]
    fn command_p2_encodes_sfi_in_high_5_bits() {
        let c = command(11, 7).unwrap();
        assert_eq!(c.p2, 0x5C);
        assert_eq!(c.p1, 7);
    }

    #[test]
    fn command_max_sfi_30() {
        let c = command(30, 1).unwrap();
        assert_eq!(c.p2, 0xF4);
    }

    #[test]
    fn command_rejects_sfi_zero() {
        assert_eq!(command(0, 1), Err(Error::InvalidValue));
    }

    #[test]
    fn command_rejects_sfi_above_30() {
        assert_eq!(command(31, 1), Err(Error::InvalidValue));
    }

    #[test]
    fn command_rejects_record_zero() {
        assert_eq!(command(1, 0), Err(Error::InvalidValue));
    }

    // ---- response parsing --------------------------------------------------

    fn sample_70_template() -> Vec<u8> {
        vec![
            0x70, 0x0C, 0x5A, 0x04, 0x12, 0x34, 0x56, 0x78, 0x5F, 0x24, 0x03, 0x25, 0x12, 0x31,
        ]
    }

    #[test]
    fn parse_70_template_exposes_children() {
        let wire = sample_70_template();
        let resp = ReadRecordResponse::parse(&wire).unwrap();
        assert_eq!(resp.tlv().tag(), Tag(0x70));
        assert_eq!(resp.children().len(), 2);
        assert_eq!(resp.children()[0].tag(), tags::PAN);
        assert_eq!(resp.children()[1].tag(), tags::APPLICATION_EXPIRATION_DATE);
        assert_eq!(resp.raw(), wire.as_slice());
    }

    #[test]
    fn parse_rejects_wrong_outer_tag() {
        let wire = vec![0x77, 0x02, 0x00, 0x00];
        assert_eq!(ReadRecordResponse::parse(&wire), Err(Error::InvalidValue));
    }

    #[test]
    fn parse_rejects_trailing_bytes() {
        let mut wire = sample_70_template();
        wire.push(0xAA);
        assert!(ReadRecordResponse::parse(&wire).is_err());
    }

    #[test]
    fn parse_empty_record_rejected() {
        assert!(ReadRecordResponse::parse(&[]).is_err());
    }

    // ---- ODA input (§10.3) -------------------------------------------------

    #[test]
    fn oda_input_sfi_1_to_10_excludes_tag_and_length() {
        let wire = sample_70_template();
        let resp = ReadRecordResponse::parse(&wire).unwrap();
        assert_eq!(resp.oda_input_bytes(1).unwrap(), &wire[2..]);
        assert_eq!(resp.oda_input_bytes(10).unwrap(), &wire[2..]);
    }

    #[test]
    fn oda_input_sfi_11_to_30_includes_full_data_field() {
        let wire = sample_70_template();
        let resp = ReadRecordResponse::parse(&wire).unwrap();
        assert_eq!(resp.oda_input_bytes(11).unwrap(), wire.as_slice());
        assert_eq!(resp.oda_input_bytes(30).unwrap(), wire.as_slice());
    }

    #[test]
    fn oda_input_rejects_invalid_sfi() {
        let resp = ReadRecordResponse::parse(&sample_70_template()).unwrap();
        assert_eq!(resp.oda_input_bytes(0), Err(Error::InvalidValue));
        assert_eq!(resp.oda_input_bytes(31), Err(Error::InvalidValue));
    }

    #[test]
    fn oda_input_handles_long_form_length() {
        let mut wire = vec![0x70, 0x81, 0x0C];
        wire.extend_from_slice(&[
            0x5A, 0x04, 0x12, 0x34, 0x56, 0x78, 0x5F, 0x24, 0x03, 0x25, 0x12, 0x31,
        ]);
        let resp = ReadRecordResponse::parse(&wire).unwrap();
        assert_eq!(resp.oda_input_bytes(5).unwrap(), &wire[3..]);
        assert_eq!(resp.oda_input_bytes(11).unwrap(), wire.as_slice());
    }

    #[test]
    fn oda_input_with_two_byte_inner_tag() {
        let mut wire = vec![0x70, 0x05];
        wire.extend_from_slice(&[0x9F, 0x36, 0x02, 0x00, 0x01]);
        let resp = ReadRecordResponse::parse(&wire).unwrap();
        assert_eq!(resp.oda_input_bytes(1).unwrap(), &wire[2..]);
    }
}
