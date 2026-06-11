//! Book 1 Annex B Table 10 / §11.3.4 - ADF FCI returned by SELECT.

use crate::core::dol::Dol;
use crate::core::error::{Error, Result};
use crate::core::tag::Tag;
use crate::core::tags;
use crate::core::tlv::Tlv;
use crate::de::application_priority_indicator::ApplicationPriorityIndicator;
use crate::de::issuer_code_table_index::IssuerCodeTableIndex;

// Book 1 §12.2.4 makes Application Label optional in ADF FCI.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdfFci {
    pub df_name: Vec<u8>,
    pub application_label: Option<Vec<u8>>,
    pub application_priority_indicator: Option<ApplicationPriorityIndicator>,
    pub pdol: Option<Dol>,
    pub language_preference: Option<Vec<u8>>,
    pub issuer_code_table_index: Option<IssuerCodeTableIndex>,
    pub application_preferred_name: Option<Vec<u8>>,
    pub fci_issuer_discretionary_data: Option<Vec<Tlv>>,
}

impl AdfFci {
    pub fn parse(data: &[u8]) -> Result<Self> {
        let proprietary = parse_outer_template(data)?;
        let df_name = primitive_bytes(take_mandatory(
            &proprietary.outer,
            tags::DEDICATED_FILE_NAME,
        )?)?
        .to_vec();
        let application_label =
            take_optional_primitive(&proprietary.inner, tags::APPLICATION_LABEL)?;

        let application_priority_indicator =
            match find_tag(&proprietary.inner, tags::APPLICATION_PRIORITY_INDICATOR) {
                Some(t) => Some(ApplicationPriorityIndicator::parse(primitive_bytes(t)?)?),
                None => None,
            };
        let pdol = match find_tag(&proprietary.inner, tags::PDOL) {
            Some(t) => Some(Dol::parse(primitive_bytes(t)?)?),
            None => None,
        };
        let application_preferred_name =
            take_optional_primitive(&proprietary.inner, tags::APPLICATION_PREFERRED_NAME)?;

        Ok(AdfFci {
            df_name,
            application_label,
            application_priority_indicator,
            pdol,
            language_preference: take_optional_primitive(
                &proprietary.inner,
                tags::LANGUAGE_PREFERENCE,
            )?,
            issuer_code_table_index: take_optional_icti(&proprietary.inner)?,
            application_preferred_name,
            fci_issuer_discretionary_data: take_optional_constructed(
                &proprietary.inner,
                tags::FCI_ISSUER_DISCRETIONARY_DATA,
            )?,
        })
    }
}

// ── helpers (exposed for contact/fci.rs PseFci / DdfFci) ───────────────

pub(crate) struct Proprietary {
    pub(crate) outer: Vec<Tlv>,
    pub(crate) inner: Vec<Tlv>,
}

pub(crate) fn parse_outer_template(data: &[u8]) -> Result<Proprietary> {
    let (outer_tlv, _) = Tlv::parse(data)?;
    if outer_tlv.tag() != tags::FCI_TEMPLATE {
        return Err(Error::InvalidValue);
    }
    let outer = outer_tlv
        .value()
        .as_constructed()
        .ok_or(Error::NotConstructed)?
        .to_vec();
    let proprietary_tlv = take_mandatory(&outer, tags::FCI_PROPRIETARY_TEMPLATE)?;
    let inner = proprietary_tlv
        .value()
        .as_constructed()
        .ok_or(Error::NotConstructed)?
        .to_vec();
    Ok(Proprietary { outer, inner })
}

pub(crate) fn find_tag(tlvs: &[Tlv], tag: Tag) -> Option<&Tlv> {
    tlvs.iter().find(|t| t.tag() == tag)
}

pub(crate) fn take_mandatory(tlvs: &[Tlv], tag: Tag) -> Result<&Tlv> {
    find_tag(tlvs, tag).ok_or(Error::InvalidValue)
}

pub(crate) fn primitive_bytes(tlv: &Tlv) -> Result<&[u8]> {
    tlv.value().as_primitive().ok_or(Error::InvalidValue)
}

pub(crate) fn take_optional_primitive(tlvs: &[Tlv], tag: Tag) -> Result<Option<Vec<u8>>> {
    match find_tag(tlvs, tag) {
        Some(t) => Ok(Some(primitive_bytes(t)?.to_vec())),
        None => Ok(None),
    }
}

pub(crate) fn take_optional_constructed(tlvs: &[Tlv], tag: Tag) -> Result<Option<Vec<Tlv>>> {
    match find_tag(tlvs, tag) {
        Some(t) => Ok(Some(
            t.value()
                .as_constructed()
                .ok_or(Error::NotConstructed)?
                .to_vec(),
        )),
        None => Ok(None),
    }
}

pub(crate) fn take_optional_icti(tlvs: &[Tlv]) -> Result<Option<IssuerCodeTableIndex>> {
    match find_tag(tlvs, tags::ISSUER_CODE_TABLE_INDEX) {
        Some(t) => Ok(Some(IssuerCodeTableIndex::parse(primitive_bytes(t)?)?)),
        None => Ok(None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fci_envelope(df_name: &[u8], a5_inner: &[u8]) -> Vec<u8> {
        let mut a5 = vec![0xA5, a5_inner.len() as u8];
        a5.extend_from_slice(a5_inner);
        let mut inner = vec![0x84, df_name.len() as u8];
        inner.extend_from_slice(df_name);
        inner.extend_from_slice(&a5);
        let mut out = vec![0x6F, inner.len() as u8];
        out.extend_from_slice(&inner);
        out
    }

    #[test]
    fn parse_adf_minimal_per_table_10() {
        let aid = [0xA0u8, 0x00, 0x00, 0x00, 0x03, 0x10, 0x10];
        let a5 = [0x50, 0x04, b'V', b'I', b'S', b'A', 0x87, 0x01, 0x01];
        let wire = fci_envelope(&aid, &a5);
        let fci = AdfFci::parse(&wire).unwrap();
        assert_eq!(fci.df_name, aid);
        assert_eq!(fci.application_label.as_deref(), Some(&b"VISA"[..]));
        assert_eq!(
            fci.application_priority_indicator.unwrap(),
            ApplicationPriorityIndicator {
                application_cannot_be_selected_without_confirmation_by_the_cardholder: false,
                priority: 1,
                rfu_byte_1: 0,
            }
        );
        assert!(fci.pdol.is_none());
    }

    #[test]
    fn parse_adf_with_pdol() {
        let pdol_bytes = [0x9F, 0x02, 0x06];
        let mut a5 = Vec::new();
        a5.extend_from_slice(&[0x50, 0x04, b'V', b'I', b'S', b'A']);
        a5.push(0x9F);
        a5.push(0x38);
        a5.push(pdol_bytes.len() as u8);
        a5.extend_from_slice(&pdol_bytes);
        let wire = fci_envelope(&[0xA0, 0x00], &a5);
        let fci = AdfFci::parse(&wire).unwrap();
        let dol = fci.pdol.expect("pdol parsed");
        assert_eq!(dol.0.len(), 1);
        assert_eq!(dol.0[0].tag, Tag(0x9F02));
        assert_eq!(dol.0[0].length, 0x06);
    }

    #[test]
    fn parse_adf_full_table_10_fields() {
        let aid = [0xA0u8, 0x00, 0x00, 0x00, 0x03, 0x10, 0x10];
        let pdol = [0x9F, 0x37, 0x04];
        let mut a5 = Vec::new();
        a5.extend_from_slice(&[0x50, 0x04, b'V', b'I', b'S', b'A']);
        a5.extend_from_slice(&[0x87, 0x01, 0b1000_0001]);
        a5.push(0x9F);
        a5.push(0x38);
        a5.push(pdol.len() as u8);
        a5.extend_from_slice(&pdol);
        a5.extend_from_slice(&[0x5F, 0x2D, 0x02, b'e', b'n']);
        a5.extend_from_slice(&[0x9F, 0x11, 0x01, 0x01]);
        a5.extend_from_slice(&[0x9F, 0x12, 0x05, b'V', b'i', b's', b'a', b'C']);
        a5.extend_from_slice(&[0xBF, 0x0C, 0x05, 0x9F, 0x4D, 0x02, 0x0B, 0x0A]);
        let wire = fci_envelope(&aid, &a5);
        let fci = AdfFci::parse(&wire).unwrap();
        assert_eq!(fci.df_name, aid);
        assert_eq!(fci.application_label.as_deref(), Some(&b"VISA"[..]));
        let api = fci.application_priority_indicator.unwrap();
        assert!(api.application_cannot_be_selected_without_confirmation_by_the_cardholder);
        assert_eq!(api.priority, 1);
        assert_eq!(fci.pdol.unwrap().0.len(), 1);
        assert_eq!(fci.language_preference.as_deref(), Some(b"en".as_ref()));
        assert_eq!(
            fci.issuer_code_table_index.unwrap(),
            IssuerCodeTableIndex(0x01)
        );
        assert_eq!(
            fci.application_preferred_name.as_deref(),
            Some(b"VisaC".as_ref())
        );
        let disc = fci.fci_issuer_discretionary_data.unwrap();
        assert_eq!(disc.len(), 1);
        assert_eq!(disc[0].tag(), Tag(0x9F4D));
        assert_eq!(disc[0].value().as_primitive().unwrap(), &[0x0B, 0x0A]);
    }

    #[test]
    fn parse_rejects_wrong_outer_tag() {
        let wire = [0x70, 0x02, 0x84, 0x00];
        assert_eq!(AdfFci::parse(&wire), Err(Error::InvalidValue));
    }

    #[test]
    fn parse_adf_missing_label_is_recoverable() {
        let a5 = [0x87, 0x01, 0x01];
        let wire = fci_envelope(&[0xA0, 0x00], &a5);
        let fci = AdfFci::parse(&wire).unwrap();
        assert!(fci.application_label.is_none());
        assert_eq!(fci.df_name, vec![0xA0, 0x00]);
        assert!(fci.application_priority_indicator.is_some());
    }

    #[test]
    fn parse_adf_missing_dfname_errors() {
        let a5 = [0x50, 0x01, b'X'];
        let mut wrapped_a5 = vec![0xA5, a5.len() as u8];
        wrapped_a5.extend_from_slice(&a5);
        let mut wire = vec![0x6F, wrapped_a5.len() as u8];
        wire.extend_from_slice(&wrapped_a5);
        assert_eq!(AdfFci::parse(&wire), Err(Error::InvalidValue));
    }

    #[test]
    fn parse_adf_unknown_tags_in_a5_are_ignored() {
        let mut a5 = Vec::new();
        a5.extend_from_slice(&[0x50, 0x04, b'V', b'I', b'S', b'A']);
        a5.extend_from_slice(&[0x9F, 0x59, 0x02, 0xAA, 0xBB]);
        let wire = fci_envelope(&[0xA0, 0x00], &a5);
        let fci = AdfFci::parse(&wire).unwrap();
        assert_eq!(fci.application_label.as_deref(), Some(&b"VISA"[..]));
    }
}
