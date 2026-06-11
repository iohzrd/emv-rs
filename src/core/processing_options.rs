//! Book 3 §6.5.8 / §10.1 - GET PROCESSING OPTIONS.

use crate::core::apdu::{Cla, Command, Ins};
use crate::core::error::{Error, Result};
use crate::core::tags;
use crate::core::tlv::{Tlv, encode_length};
use crate::de::application_file_locator::ApplicationFileLocator;
use crate::de::application_interchange_profile::ApplicationInterchangeProfile;

pub fn command(pdol_data: &[u8]) -> Result<Command> {
    let mut data = Vec::with_capacity(2 + pdol_data.len());
    data.push(0x83);
    data.extend(encode_length(pdol_data.len()));
    data.extend_from_slice(pdol_data);
    if data.len() > 0xFF {
        return Err(Error::LengthTooLong);
    }
    Ok(Command {
        cla: Cla(0x80),
        ins: Ins::GET_PROCESSING_OPTIONS,
        p1: 0x00,
        p2: 0x00,
        data,
        le: Some(0x00),
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcessingOptionsFormat {
    Format1,
    Format2,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessingOptionsResponse {
    pub aip: ApplicationInterchangeProfile,
    /// Format 1 always carries AFL inline; Format 2 may omit it (Book C-7
    /// Tables 4-3/4-4/4-5: ARQC w/o ODA and AAC GPO responses have no AFL).
    pub afl: Option<ApplicationFileLocator>,
    pub proprietary: Vec<Tlv>,
    pub format: ProcessingOptionsFormat,
}

impl ProcessingOptionsResponse {
    pub fn parse(data: &[u8]) -> Result<Self> {
        let tlv = Tlv::from_bytes(data)?;
        Self::from_tlv(&tlv)
    }

    pub fn from_tlv(tlv: &Tlv) -> Result<Self> {
        match tlv.tag() {
            tags::RESPONSE_MESSAGE_TEMPLATE_FORMAT_1 => parse_format_1(tlv),
            tags::RESPONSE_MESSAGE_TEMPLATE_FORMAT_2 => parse_format_2(tlv),
            _ => Err(Error::InvalidValue),
        }
    }

    /// Encode back to wire bytes in the response's original format.
    ///
    /// For Format 2, AIP is emitted first, then AFL, then any `proprietary`
    /// children in the order they were preserved. This is a valid Format 2
    /// encoding, but is not guaranteed to be byte-identical to a parsed input
    /// whose original child ordering differed.
    pub fn to_bytes(&self) -> Vec<u8> {
        self.to_tlv().encode()
    }

    /// Encode back to a TLV in the response's original format.
    pub fn to_tlv(&self) -> Tlv {
        match self.format {
            ProcessingOptionsFormat::Format1 => {
                let aip_bytes = self.aip.to_bytes();
                let afl_bytes = self.afl.as_ref().map(|a| a.to_bytes()).unwrap_or_default();
                let mut value = Vec::with_capacity(aip_bytes.len() + afl_bytes.len());
                value.extend_from_slice(&aip_bytes);
                value.extend_from_slice(&afl_bytes);
                Tlv::primitive(tags::RESPONSE_MESSAGE_TEMPLATE_FORMAT_1, value)
            }
            ProcessingOptionsFormat::Format2 => {
                let mut children = Vec::with_capacity(2 + self.proprietary.len());
                children.push(Tlv::primitive(
                    tags::APPLICATION_INTERCHANGE_PROFILE,
                    self.aip.to_bytes().to_vec(),
                ));
                if let Some(afl) = &self.afl {
                    children.push(Tlv::primitive(
                        tags::APPLICATION_FILE_LOCATOR,
                        afl.to_bytes(),
                    ));
                }
                children.extend(self.proprietary.iter().cloned());
                Tlv::constructed(tags::RESPONSE_MESSAGE_TEMPLATE_FORMAT_2, children)
            }
        }
    }
}

fn parse_format_1(tlv: &Tlv) -> Result<ProcessingOptionsResponse> {
    let bytes = tlv.value().as_primitive().ok_or(Error::InvalidValue)?;
    // AIP is fixed at 2 bytes (Annex C1, Table 41); the rest is AFL.
    if bytes.len() < 2 {
        return Err(Error::UnexpectedEof);
    }
    let (aip_bytes, afl_bytes) = bytes.split_at(2);
    let aip = ApplicationInterchangeProfile::parse(aip_bytes)?;
    // Format 1 always carries AFL inline (Book 3 §6.5.8.4); zero AFL bytes is an error.
    let afl = Some(ApplicationFileLocator::parse(afl_bytes)?);
    Ok(ProcessingOptionsResponse {
        aip,
        afl,
        proprietary: Vec::new(),
        format: ProcessingOptionsFormat::Format1,
    })
}

fn parse_format_2(tlv: &Tlv) -> Result<ProcessingOptionsResponse> {
    let children = tlv.value().as_constructed().ok_or(Error::InvalidValue)?;
    let mut aip = None;
    let mut afl = None;
    let mut proprietary = Vec::new();
    for child in children {
        match child.tag() {
            t if t == tags::APPLICATION_INTERCHANGE_PROFILE => {
                let bytes = child.value().as_primitive().ok_or(Error::InvalidValue)?;
                aip = Some(ApplicationInterchangeProfile::parse(bytes)?);
            }
            t if t == tags::APPLICATION_FILE_LOCATOR => {
                let bytes = child.value().as_primitive().ok_or(Error::InvalidValue)?;
                afl = Some(ApplicationFileLocator::parse(bytes)?);
            }
            _ => proprietary.push(child.clone()),
        }
    }
    let aip = aip.ok_or(Error::InvalidValue)?;
    Ok(ProcessingOptionsResponse {
        aip,
        afl,
        proprietary,
        format: ProcessingOptionsFormat::Format2,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::tag::Tag;

    fn sample_aip_bytes() -> [u8; 2] {
        [0b0111_0000, 0x00]
    }

    fn sample_afl_bytes() -> [u8; 8] {
        [0x08, 0x01, 0x01, 0x01, 0x10, 0x01, 0x01, 0x00]
    }

    // ---- Format 1 ----------------------------------------------------------

    #[test]
    fn parse_format_1_minimal() {
        let mut value = Vec::new();
        value.extend_from_slice(&sample_aip_bytes());
        value.extend_from_slice(&sample_afl_bytes());
        let mut wire = vec![0x80, 0x0A];
        wire.extend_from_slice(&value);

        let resp = ProcessingOptionsResponse::parse(&wire).unwrap();
        assert_eq!(resp.format, ProcessingOptionsFormat::Format1);
        assert_eq!(resp.aip.to_bytes(), sample_aip_bytes());
        assert_eq!(resp.afl.as_ref().unwrap().to_bytes(), sample_afl_bytes());
        assert!(resp.proprietary.is_empty());
        assert_eq!(resp.to_bytes(), wire);
    }

    #[test]
    fn parse_format_1_aip_only_no_afl_rejected() {
        let wire = vec![0x80, 0x02, sample_aip_bytes()[0], sample_aip_bytes()[1]];
        assert_eq!(
            ProcessingOptionsResponse::parse(&wire),
            Err(Error::InvalidValue),
        );
    }

    #[test]
    fn parse_format_1_value_too_short_for_aip() {
        let wire = vec![0x80, 0x01, 0x00];
        assert_eq!(
            ProcessingOptionsResponse::parse(&wire),
            Err(Error::UnexpectedEof)
        );
    }

    #[test]
    fn parse_format_1_afl_misaligned_rejected() {
        let wire = vec![0x80, 0x05, 0x00, 0x00, 0x08, 0x01, 0x01];
        assert_eq!(
            ProcessingOptionsResponse::parse(&wire),
            Err(Error::InvalidValue)
        );
    }

    #[test]
    fn parse_format_1_invalid_afl_entry_rejected() {
        let mut wire = vec![0x80, 0x06];
        wire.extend_from_slice(&sample_aip_bytes());
        wire.extend_from_slice(&[0x08, 0x00, 0x00, 0x00]);
        assert_eq!(
            ProcessingOptionsResponse::parse(&wire),
            Err(Error::InvalidValue)
        );
    }

    // ---- Format 2 ----------------------------------------------------------

    #[test]
    fn parse_format_2_minimal_aip_then_afl() {
        let mut value = Vec::new();
        value.extend_from_slice(&[0x82, 0x02]);
        value.extend_from_slice(&sample_aip_bytes());
        value.extend_from_slice(&[0x94, 0x08]);
        value.extend_from_slice(&sample_afl_bytes());
        let mut wire = vec![0x77, value.len() as u8];
        wire.extend_from_slice(&value);

        let resp = ProcessingOptionsResponse::parse(&wire).unwrap();
        assert_eq!(resp.format, ProcessingOptionsFormat::Format2);
        assert_eq!(resp.aip.to_bytes(), sample_aip_bytes());
        assert_eq!(resp.afl.as_ref().unwrap().to_bytes(), sample_afl_bytes());
        assert!(resp.proprietary.is_empty());
        assert_eq!(resp.to_bytes(), wire);
    }

    #[test]
    fn parse_format_2_afl_before_aip_roundtrip_normalizes_order() {
        let mut value = Vec::new();
        value.extend_from_slice(&[0x94, 0x08]);
        value.extend_from_slice(&sample_afl_bytes());
        value.extend_from_slice(&[0x82, 0x02]);
        value.extend_from_slice(&sample_aip_bytes());
        let mut wire = vec![0x77, value.len() as u8];
        wire.extend_from_slice(&value);

        let resp = ProcessingOptionsResponse::parse(&wire).unwrap();
        assert_eq!(resp.aip.to_bytes(), sample_aip_bytes());
        assert_eq!(resp.afl.as_ref().unwrap().to_bytes(), sample_afl_bytes());

        // to_bytes emits AIP-then-AFL canonically. Re-parse to confirm equivalence.
        let re = ProcessingOptionsResponse::parse(&resp.to_bytes()).unwrap();
        assert_eq!(re, resp);
    }

    #[test]
    fn parse_format_2_with_proprietary_children_preserved() {
        // 77 .. | 82 02 <AIP> 94 08 <AFL> 9F36 02 00 01 (ATC)
        let mut value = Vec::new();
        value.extend_from_slice(&[0x82, 0x02]);
        value.extend_from_slice(&sample_aip_bytes());
        value.extend_from_slice(&[0x94, 0x08]);
        value.extend_from_slice(&sample_afl_bytes());
        value.extend_from_slice(&[0x9F, 0x36, 0x02, 0x00, 0x01]);
        let mut wire = vec![0x77, value.len() as u8];
        wire.extend_from_slice(&value);

        let resp = ProcessingOptionsResponse::parse(&wire).unwrap();
        assert_eq!(resp.proprietary.len(), 1);
        assert_eq!(resp.proprietary[0].tag(), Tag(0x9F36));
        assert_eq!(
            resp.proprietary[0].value().as_primitive().unwrap(),
            &[0x00, 0x01]
        );
        assert_eq!(resp.to_bytes(), wire);
    }

    #[test]
    fn parse_format_2_missing_aip_rejected() {
        // 77 0A | 94 08 <AFL>
        let mut value = vec![0x94, 0x08];
        value.extend_from_slice(&sample_afl_bytes());
        let mut wire = vec![0x77, value.len() as u8];
        wire.extend_from_slice(&value);
        assert_eq!(
            ProcessingOptionsResponse::parse(&wire),
            Err(Error::InvalidValue)
        );
    }

    #[test]
    fn parse_format_2_missing_afl_accepted_as_none() {
        // Book C-7 Tables 4-3 / AAC: ARQC-without-ODA and AAC GPO responses
        // have no AFL. 77 04 | 82 02 <AIP>
        let mut value = vec![0x82, 0x02];
        value.extend_from_slice(&sample_aip_bytes());
        let mut wire = vec![0x77, value.len() as u8];
        wire.extend_from_slice(&value);
        let resp = ProcessingOptionsResponse::parse(&wire).unwrap();
        assert_eq!(resp.format, ProcessingOptionsFormat::Format2);
        assert!(resp.afl.is_none());
        assert_eq!(resp.to_bytes(), wire);
    }

    #[test]
    fn parse_format_2_aip_wrong_length_rejected() {
        // AIP must be exactly 2 bytes (Annex C1).
        let value: Vec<u8> = vec![
            0x82, 0x01, 0x70, // AIP only 1 byte
            0x94, 0x08, 0x08, 0x01, 0x01, 0x01, 0x10, 0x01, 0x01, 0x00,
        ];
        let mut wire = vec![0x77, value.len() as u8];
        wire.extend_from_slice(&value);
        assert_eq!(
            ProcessingOptionsResponse::parse(&wire),
            Err(Error::WrongLength {
                expected: 2,
                got: 1
            })
        );
    }

    // ---- Outer-tag handling ------------------------------------------------

    #[test]
    fn parse_rejects_wrong_outer_tag() {
        // 70 02 00 00 - '70' is not a valid GPO response template.
        let wire = vec![0x70, 0x02, 0x00, 0x00];
        assert_eq!(
            ProcessingOptionsResponse::parse(&wire),
            Err(Error::InvalidValue)
        );
    }

    #[test]
    fn parse_rejects_trailing_bytes() {
        // Tlv::from_bytes is strict; trailing junk must be rejected.
        let mut wire = vec![0x80, 0x02];
        wire.extend_from_slice(&sample_aip_bytes());
        wire.push(0xAA);
        assert!(ProcessingOptionsResponse::parse(&wire).is_err());
    }

    // ---- GPO command builder -----------------------------------------------

    #[test]
    fn command_no_pdol_data() {
        // §6.5.8.3: "the terminal sets the length field of the template to
        // zero" - data field becomes `83 00`.
        let c = command(&[]).unwrap();
        assert_eq!(c.cla.0, 0x80);
        assert_eq!(c.ins, Ins::GET_PROCESSING_OPTIONS);
        assert_eq!(c.p1, 0x00);
        assert_eq!(c.p2, 0x00);
        assert_eq!(c.data, vec![0x83, 0x00]);
        assert_eq!(c.le, Some(0x00));
        assert_eq!(
            c.to_bytes().unwrap(),
            vec![0x80, 0xA8, 0x00, 0x00, 0x02, 0x83, 0x00, 0x00],
        );
    }

    #[test]
    fn command_with_short_pdol_data() {
        // PDOL value-field bytes (e.g. amount, country, currency, TVR, etc.).
        let pdol = vec![0x01, 0x02, 0x03, 0x04];
        let c = command(&pdol).unwrap();
        assert_eq!(c.data, vec![0x83, 0x04, 0x01, 0x02, 0x03, 0x04]);
    }

    #[test]
    fn command_long_form_length_at_128() {
        // BER-TLV length encoding flips to `81 LL` at 128.
        let pdol = vec![0xAB; 128];
        let c = command(&pdol).unwrap();
        assert_eq!(c.data[0], 0x83);
        assert_eq!(c.data[1], 0x81);
        assert_eq!(c.data[2], 0x80);
        assert_eq!(c.data.len(), 3 + 128);
    }

    #[test]
    fn command_rejects_oversized_data() {
        // 254 bytes of PDOL data ⇒ wrapped data = 1 + 2 + 254 = 257 bytes,
        // exceeding the short-APDU 255-byte limit.
        assert_eq!(command(&vec![0; 254]), Err(Error::LengthTooLong));
    }
}
