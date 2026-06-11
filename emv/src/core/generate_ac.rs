//! Book 3 §6.5.5 - GENERATE APPLICATION CRYPTOGRAM.

use crate::core::apdu::{Cla, Command, Ins};
use crate::core::application_cryptogram_type::ApplicationCryptogramType;
use crate::core::error::{Error, Result};
use crate::core::tags;
use crate::core::tlv::Tlv;
use crate::de::cryptogram_information_data::CryptogramInformationData;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignatureRequest {
    None,
    Cda,
    Xda,
}

pub fn command(
    request: ApplicationCryptogramType,
    signature: SignatureRequest,
    data: Vec<u8>,
) -> Command {
    let signature_bits: u8 = match signature {
        SignatureRequest::None => 0b00,
        SignatureRequest::Cda => 0b10,
        SignatureRequest::Xda => 0b01,
    };
    let p1 = (request.to_bits() << 6) | (signature_bits << 3);
    Command {
        cla: Cla(0x80),
        ins: Ins::GENERATE_APPLICATION_CRYPTOGRAM,
        p1,
        p2: 0x00,
        data,
        le: Some(0x00),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GenerateAcFormat {
    Format1,
    Format2,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GenerateAcResponse {
    pub format: GenerateAcFormat,
    pub cid: CryptogramInformationData,
    pub atc: [u8; 2],
    pub ac: Option<[u8; 8]>,
    pub iad: Option<Vec<u8>>,
    pub sdad: Option<Vec<u8>>,
    pub proprietary: Vec<Tlv>,
    pub children_in_order: Vec<Tlv>,
}

impl GenerateAcResponse {
    pub fn parse(data: &[u8]) -> Result<Self> {
        let tlv = Tlv::from_bytes(data)?;
        match tlv.tag() {
            tags::RESPONSE_MESSAGE_TEMPLATE_FORMAT_1 => parse_format_1(&tlv),
            tags::RESPONSE_MESSAGE_TEMPLATE_FORMAT_2 => parse_format_2(&tlv),
            _ => Err(Error::InvalidValue),
        }
    }
}

fn parse_format_1(tlv: &Tlv) -> Result<GenerateAcResponse> {
    let bytes = tlv.value().as_primitive().ok_or(Error::InvalidValue)?;
    if bytes.len() < 11 {
        return Err(Error::UnexpectedEof);
    }
    let cid = CryptogramInformationData::parse(&bytes[0..1])?;
    let atc = [bytes[1], bytes[2]];
    let mut ac = [0u8; 8];
    ac.copy_from_slice(&bytes[3..11]);
    let iad = if bytes.len() > 11 {
        Some(bytes[11..].to_vec())
    } else {
        None
    };
    Ok(GenerateAcResponse {
        format: GenerateAcFormat::Format1,
        cid,
        atc,
        ac: Some(ac),
        iad,
        sdad: None,
        proprietary: Vec::new(),
        children_in_order: Vec::new(),
    })
}

fn parse_format_2(tlv: &Tlv) -> Result<GenerateAcResponse> {
    let children = tlv.value().as_constructed().ok_or(Error::InvalidValue)?;
    let mut cid: Option<CryptogramInformationData> = None;
    let mut atc: Option<[u8; 2]> = None;
    let mut ac: Option<[u8; 8]> = None;
    let mut iad: Option<Vec<u8>> = None;
    let mut sdad: Option<Vec<u8>> = None;
    let mut proprietary: Vec<Tlv> = Vec::new();

    for child in children {
        let tag = child.tag();
        let primitive = child.value().as_primitive();
        if tag == tags::CRYPTOGRAM_INFORMATION_DATA {
            let bytes = primitive.ok_or(Error::InvalidValue)?;
            cid = Some(CryptogramInformationData::parse(bytes)?);
        } else if tag == tags::APPLICATION_TRANSACTION_COUNTER {
            let bytes = primitive.ok_or(Error::InvalidValue)?;
            if bytes.len() != 2 {
                return Err(Error::WrongLength {
                    expected: 2,
                    got: bytes.len(),
                });
            }
            atc = Some([bytes[0], bytes[1]]);
        } else if tag == tags::APPLICATION_CRYPTOGRAM {
            let bytes = primitive.ok_or(Error::InvalidValue)?;
            if bytes.len() != 8 {
                return Err(Error::WrongLength {
                    expected: 8,
                    got: bytes.len(),
                });
            }
            let mut a = [0u8; 8];
            a.copy_from_slice(bytes);
            ac = Some(a);
        } else if tag == tags::ISSUER_APPLICATION_DATA {
            iad = Some(primitive.ok_or(Error::InvalidValue)?.to_vec());
        } else if tag == tags::SIGNED_DYNAMIC_APPLICATION_DATA {
            sdad = Some(primitive.ok_or(Error::InvalidValue)?.to_vec());
        } else {
            proprietary.push(child.clone());
        }
    }

    let cid = cid.ok_or(Error::InvalidValue)?;
    let atc = atc.ok_or(Error::InvalidValue)?;
    // §6.5.5.4: "shall always include the Cryptogram Information Data, the
    // Application Transaction Counter, and the cryptogram computed by the
    // ICC (either an AC or a proprietary cryptogram)." Note 1: AC is
    // absent when CDA/XDA signature is returned (i.e. SDAD present).
    if ac.is_none() && sdad.is_none() {
        return Err(Error::InvalidValue);
    }

    Ok(GenerateAcResponse {
        format: GenerateAcFormat::Format2,
        cid,
        atc,
        ac,
        iad,
        sdad,
        proprietary,
        children_in_order: children.to_vec(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::tag::Tag;
    use crate::de::cryptogram_information_data::ApplicationCryptogramType;

    // ---- command builder ---------------------------------------------------

    #[test]
    fn command_aac_no_signature_p1_is_zero() {
        let c = command(
            ApplicationCryptogramType::Aac,
            SignatureRequest::None,
            vec![],
        );
        assert_eq!(c.cla.0, 0x80);
        assert_eq!(c.ins, Ins::GENERATE_APPLICATION_CRYPTOGRAM);
        assert_eq!(c.p1, 0x00);
        assert_eq!(c.p2, 0x00);
        assert_eq!(c.le, Some(0x00));
    }

    #[test]
    fn command_tc_no_signature_p1_is_0x40() {
        let c = command(
            ApplicationCryptogramType::Tc,
            SignatureRequest::None,
            vec![],
        );
        assert_eq!(c.p1, 0x40);
    }

    #[test]
    fn command_arqc_no_signature_p1_is_0x80() {
        let c = command(
            ApplicationCryptogramType::Arqc,
            SignatureRequest::None,
            vec![],
        );
        assert_eq!(c.p1, 0x80);
    }

    #[test]
    fn command_cda_signature_sets_b5() {
        let c = command(
            ApplicationCryptogramType::Arqc,
            SignatureRequest::Cda,
            vec![],
        );
        assert_eq!(c.p1, 0x90);
    }

    #[test]
    fn command_xda_signature_sets_b4() {
        let c = command(ApplicationCryptogramType::Tc, SignatureRequest::Xda, vec![]);
        assert_eq!(c.p1, 0x48);
    }

    #[test]
    fn command_serializes_with_data_field() {
        let c = command(
            ApplicationCryptogramType::Tc,
            SignatureRequest::None,
            vec![0xAA, 0xBB, 0xCC],
        );
        assert_eq!(
            c.to_bytes().unwrap(),
            vec![0x80, 0xAE, 0x40, 0x00, 0x03, 0xAA, 0xBB, 0xCC, 0x00],
        );
    }

    // ---- Format 1 parsing --------------------------------------------------

    fn sample_format_1_value() -> Vec<u8> {
        let mut v = Vec::new();
        v.push(0x40);
        v.extend_from_slice(&[0x00, 0x05]);
        v.extend_from_slice(&[0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88]);
        v
    }

    #[test]
    fn parse_format_1_minimal_no_iad() {
        let value = sample_format_1_value();
        let mut wire = vec![0x80, value.len() as u8];
        wire.extend_from_slice(&value);

        let resp = GenerateAcResponse::parse(&wire).unwrap();
        assert_eq!(resp.format, GenerateAcFormat::Format1);
        assert_eq!(resp.cid.cryptogram_type, ApplicationCryptogramType::Tc);
        assert_eq!(resp.atc, [0x00, 0x05]);
        assert_eq!(
            resp.ac,
            Some([0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88])
        );
        assert_eq!(resp.iad, None);
        assert_eq!(resp.sdad, None);
        assert!(resp.proprietary.is_empty());
    }

    #[test]
    fn parse_format_1_with_iad() {
        let mut value = sample_format_1_value();
        value.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]);
        let mut wire = vec![0x80, value.len() as u8];
        wire.extend_from_slice(&value);

        let resp = GenerateAcResponse::parse(&wire).unwrap();
        assert_eq!(resp.iad.as_deref(), Some(&[0xDE, 0xAD, 0xBE, 0xEF][..]));
    }

    #[test]
    fn parse_format_1_too_short_rejected() {
        let mut wire = vec![0x80, 0x0A];
        wire.extend_from_slice(&[0; 10]);
        assert_eq!(GenerateAcResponse::parse(&wire), Err(Error::UnexpectedEof));
    }

    // ---- Format 2 parsing --------------------------------------------------

    fn fmt2_with_ac() -> Vec<u8> {
        let mut value = Vec::new();
        value.extend_from_slice(&[0x9F, 0x27, 0x01, 0x80]);
        value.extend_from_slice(&[0x9F, 0x36, 0x02, 0x00, 0x05]);
        value.extend_from_slice(&[0x9F, 0x26, 0x08]);
        value.extend_from_slice(&[0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88]);
        let mut wire = vec![0x77, value.len() as u8];
        wire.extend_from_slice(&value);
        wire
    }

    #[test]
    fn parse_format_2_minimal_with_ac() {
        let wire = fmt2_with_ac();
        let resp = GenerateAcResponse::parse(&wire).unwrap();
        assert_eq!(resp.format, GenerateAcFormat::Format2);
        assert_eq!(resp.cid.cryptogram_type, ApplicationCryptogramType::Arqc);
        assert_eq!(resp.atc, [0x00, 0x05]);
        assert_eq!(
            resp.ac,
            Some([0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88])
        );
        assert_eq!(resp.sdad, None);
    }

    #[test]
    fn parse_format_2_with_iad_and_proprietary() {
        let mut value = Vec::new();
        value.extend_from_slice(&[0x9F, 0x27, 0x01, 0x80]);
        value.extend_from_slice(&[0x9F, 0x36, 0x02, 0x00, 0x05]);
        value.extend_from_slice(&[
            0x9F, 0x26, 0x08, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
        ]);
        value.extend_from_slice(&[0x9F, 0x10, 0x03, 0x12, 0x34, 0x56]);
        value.extend_from_slice(&[0x5F, 0x2A, 0x02, 0x09, 0x78]);
        let mut wire = vec![0x77, value.len() as u8];
        wire.extend_from_slice(&value);

        let resp = GenerateAcResponse::parse(&wire).unwrap();
        assert_eq!(resp.iad.as_deref(), Some(&[0x12, 0x34, 0x56][..]));
        assert_eq!(resp.proprietary.len(), 1);
        assert_eq!(resp.proprietary[0].tag(), Tag(0x5F2A));
    }

    #[test]
    fn parse_format_2_with_sdad_and_no_ac() {
        let mut value = Vec::new();
        value.extend_from_slice(&[0x9F, 0x27, 0x01, 0x40]);
        value.extend_from_slice(&[0x9F, 0x36, 0x02, 0x00, 0x09]);
        value.extend_from_slice(&[0x9F, 0x4B, 0x04, 0xAA, 0xBB, 0xCC, 0xDD]);
        let mut wire = vec![0x77, value.len() as u8];
        wire.extend_from_slice(&value);

        let resp = GenerateAcResponse::parse(&wire).unwrap();
        assert_eq!(resp.cid.cryptogram_type, ApplicationCryptogramType::Tc);
        assert_eq!(resp.ac, None);
        assert_eq!(resp.sdad.as_deref(), Some(&[0xAA, 0xBB, 0xCC, 0xDD][..]));
    }

    #[test]
    fn parse_format_2_children_in_any_order() {
        let mut value = Vec::new();
        value.extend_from_slice(&[0x9F, 0x36, 0x02, 0x00, 0x05]);
        value.extend_from_slice(&[0x9F, 0x27, 0x01, 0x80]);
        value.extend_from_slice(&[
            0x9F, 0x26, 0x08, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
        ]);
        let mut wire = vec![0x77, value.len() as u8];
        wire.extend_from_slice(&value);
        let resp = GenerateAcResponse::parse(&wire).unwrap();
        assert_eq!(resp.cid.cryptogram_type, ApplicationCryptogramType::Arqc);
        assert_eq!(resp.atc, [0x00, 0x05]);
    }

    #[test]
    fn parse_format_2_missing_cid_rejected() {
        let mut value = Vec::new();
        value.extend_from_slice(&[0x9F, 0x36, 0x02, 0x00, 0x05]);
        value.extend_from_slice(&[
            0x9F, 0x26, 0x08, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
        ]);
        let mut wire = vec![0x77, value.len() as u8];
        wire.extend_from_slice(&value);
        assert_eq!(GenerateAcResponse::parse(&wire), Err(Error::InvalidValue));
    }

    #[test]
    fn parse_format_2_missing_atc_rejected() {
        let mut value = Vec::new();
        value.extend_from_slice(&[0x9F, 0x27, 0x01, 0x80]);
        value.extend_from_slice(&[
            0x9F, 0x26, 0x08, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
        ]);
        let mut wire = vec![0x77, value.len() as u8];
        wire.extend_from_slice(&value);
        assert_eq!(GenerateAcResponse::parse(&wire), Err(Error::InvalidValue));
    }

    #[test]
    fn parse_format_2_missing_both_ac_and_sdad_rejected() {
        let mut value = Vec::new();
        value.extend_from_slice(&[0x9F, 0x27, 0x01, 0x80]);
        value.extend_from_slice(&[0x9F, 0x36, 0x02, 0x00, 0x05]);
        let mut wire = vec![0x77, value.len() as u8];
        wire.extend_from_slice(&value);
        assert_eq!(GenerateAcResponse::parse(&wire), Err(Error::InvalidValue));
    }

    #[test]
    fn parse_format_2_atc_wrong_length_rejected() {
        let mut value = Vec::new();
        value.extend_from_slice(&[0x9F, 0x27, 0x01, 0x80]);
        value.extend_from_slice(&[0x9F, 0x36, 0x01, 0x05]);
        value.extend_from_slice(&[
            0x9F, 0x26, 0x08, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
        ]);
        let mut wire = vec![0x77, value.len() as u8];
        wire.extend_from_slice(&value);
        assert_eq!(
            GenerateAcResponse::parse(&wire),
            Err(Error::WrongLength {
                expected: 2,
                got: 1,
            })
        );
    }

    #[test]
    fn parse_format_2_ac_wrong_length_rejected() {
        let mut value = Vec::new();
        value.extend_from_slice(&[0x9F, 0x27, 0x01, 0x80]);
        value.extend_from_slice(&[0x9F, 0x36, 0x02, 0x00, 0x05]);
        value.extend_from_slice(&[0x9F, 0x26, 0x04, 0x11, 0x22, 0x33, 0x44]);
        let mut wire = vec![0x77, value.len() as u8];
        wire.extend_from_slice(&value);
        assert_eq!(
            GenerateAcResponse::parse(&wire),
            Err(Error::WrongLength {
                expected: 8,
                got: 4,
            })
        );
    }

    #[test]
    fn parse_rejects_wrong_outer_tag() {
        let wire = vec![0x70, 0x02, 0x00, 0x00];
        assert_eq!(GenerateAcResponse::parse(&wire), Err(Error::InvalidValue));
    }

    #[test]
    fn parse_rejects_trailing_bytes() {
        let mut wire = fmt2_with_ac();
        wire.push(0xAA);
        assert!(GenerateAcResponse::parse(&wire).is_err());
    }
}
