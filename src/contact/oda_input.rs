//! Book 3 §10.3 - Offline Data Authentication input assembly.

use crate::core::error::{Error, Result};
use crate::core::tag::Tag;
use crate::core::tags;
use crate::core::tlv::encode_length;

pub fn sda_static_data_input(
    records: &[u8],
    sda_tag_list_value: Option<&[u8]>,
    aip_value: &[u8],
) -> Result<Vec<u8>> {
    let extra = match sda_tag_list_value {
        None => 0,
        Some(list) => {
            // §10.3 - only tag '82' is legal in the SDA Tag List.
            if list != [tags::APPLICATION_INTERCHANGE_PROFILE.0 as u8].as_slice() {
                return Err(Error::InvalidValue);
            }
            aip_value.len()
        }
    };
    let mut out = Vec::with_capacity(records.len() + extra);
    out.extend_from_slice(records);
    if sda_tag_list_value.is_some() {
        out.extend_from_slice(aip_value);
    }
    Ok(out)
}

pub fn xda_iccd_input(
    records: &[u8],
    aip_value: &[u8],
    aid_terminal: &[u8],
    pdol_received: Option<&[u8]>,
) -> Vec<u8> {
    let aip_tlv_len = wire_tlv_len(tags::APPLICATION_INTERCHANGE_PROFILE, aip_value.len());
    let aid_tlv_len = wire_tlv_len(tags::AID_TERMINAL, aid_terminal.len());
    let pdol_tlv_len = pdol_received
        .map(|p| wire_tlv_len(tags::PDOL, p.len()))
        .unwrap_or(0);

    let mut out = Vec::with_capacity(records.len() + aip_tlv_len + aid_tlv_len + pdol_tlv_len);
    out.extend_from_slice(records);
    append_tlv(&mut out, tags::APPLICATION_INTERCHANGE_PROFILE, aip_value);
    append_tlv(&mut out, tags::AID_TERMINAL, aid_terminal);
    if let Some(pdol) = pdol_received {
        append_tlv(&mut out, tags::PDOL, pdol);
    }
    out
}

fn append_tlv(out: &mut Vec<u8>, tag: Tag, value: &[u8]) {
    out.extend_from_slice(&tag.to_bytes());
    out.extend_from_slice(&encode_length(value.len()));
    out.extend_from_slice(value);
}

fn wire_tlv_len(tag: Tag, value_len: usize) -> usize {
    tag.byte_len() + encode_length(value_len).len() + value_len
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sda_no_tag_list_yields_records_only() {
        let records = [0xAA, 0xBB, 0xCC];
        let aip = [0x12, 0x34];
        let out = sda_static_data_input(&records, None, &aip).unwrap();
        assert_eq!(out, records.to_vec());
    }

    #[test]
    fn sda_tag_list_82_appends_aip_value_only() {
        let records = [0xAA, 0xBB];
        let aip = [0x12, 0x34];
        let out = sda_static_data_input(&records, Some(&[0x82]), &aip).unwrap();
        assert_eq!(out, vec![0xAA, 0xBB, 0x12, 0x34]);
    }

    #[test]
    fn sda_tag_list_with_other_tags_violates_spec() {
        let records = [0xAA];
        let aip = [0x12, 0x34];
        assert_eq!(
            sda_static_data_input(&records, Some(&[0x82, 0x9F]), &aip),
            Err(Error::InvalidValue)
        );
        assert_eq!(
            sda_static_data_input(&records, Some(&[0x9A]), &aip),
            Err(Error::InvalidValue)
        );
        assert_eq!(
            sda_static_data_input(&records, Some(&[]), &aip),
            Err(Error::InvalidValue)
        );
    }

    #[test]
    fn sda_empty_records_with_aip_just_aip() {
        let out = sda_static_data_input(&[], Some(&[0x82]), &[0x5C, 0x00]).unwrap();
        assert_eq!(out, vec![0x5C, 0x00]);
    }

    #[test]
    fn xda_minimum_records_aip_aid_no_pdol() {
        let records = [0xDE, 0xAD];
        let aip = [0x80, 0x00];
        let aid = [0xA0, 0x00, 0x00, 0x00, 0x03, 0x10, 0x10];
        let out = xda_iccd_input(&records, &aip, &aid, None);

        let mut expected = vec![0xDE, 0xAD];
        expected.extend_from_slice(&[0x82, 0x02, 0x80, 0x00]);
        expected.extend_from_slice(&[0x9F, 0x06, 0x07]);
        expected.extend_from_slice(&aid);
        assert_eq!(out, expected);
    }

    #[test]
    fn xda_with_pdol_appended() {
        let records = [0xDE];
        let aip = [0x80, 0x00];
        let aid = [0xA0, 0, 0, 0, 0x03, 0x10, 0x10];
        let pdol = [
            0x9F, 0x33, 0x03, 0x9F, 0x1A, 0x02, 0x5F, 0x2A, 0x02, 0x9A, 0x03, 0x9C, 0x01, 0x9F,
            0x37, 0x04,
        ];
        let out = xda_iccd_input(&records, &aip, &aid, Some(&pdol));

        let mut expected = vec![0xDE];
        expected.extend_from_slice(&[0x82, 0x02, 0x80, 0x00]);
        expected.extend_from_slice(&[0x9F, 0x06, 0x07]);
        expected.extend_from_slice(&aid);
        expected.extend_from_slice(&[0x9F, 0x38, 0x10]);
        expected.extend_from_slice(&pdol);
        assert_eq!(out, expected);
    }

    #[test]
    fn xda_long_aid_uses_short_form_length() {
        let aid = [0u8; 16];
        let out = xda_iccd_input(&[], &[0x00, 0x00], &aid, None);
        assert_eq!(out[..4], [0x82, 0x02, 0x00, 0x00]);
        assert_eq!(out[4..7], [0x9F, 0x06, 0x10]);
        assert_eq!(out[7..], [0u8; 16]);
    }

    #[test]
    fn xda_appends_aip_tlv_unconditionally() {
        let out = xda_iccd_input(&[], &[0x12, 0x34], &[0xA0], None);
        assert_eq!(&out[..4], &[0x82, 0x02, 0x12, 0x34]);
    }

    #[test]
    fn xda_pdol_long_form_length() {
        let aid = [0xA0; 5];
        let pdol = vec![0xAB; 200];
        let out = xda_iccd_input(&[], &[0x00, 0x00], &aid, Some(&pdol));
        let pdol_header_idx = out.len() - (200 + 4);
        assert_eq!(
            &out[pdol_header_idx..pdol_header_idx + 4],
            &[0x9F, 0x38, 0x81, 0xC8]
        );
        assert_eq!(&out[pdol_header_idx + 4..], &vec![0xAB; 200]);
    }

    #[test]
    fn xda_no_pdol_does_not_append_anything() {
        let aid = [0xA0; 5];
        let with_none = xda_iccd_input(&[0xFF], &[0x00, 0x00], &aid, None);
        let with_some_empty = xda_iccd_input(&[0xFF], &[0x00, 0x00], &aid, Some(&[]));
        assert_eq!(with_some_empty.len(), with_none.len() + 3);
        assert_eq!(&with_none[with_none.len() - 5..], &aid);
    }
}
