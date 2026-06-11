//! Payment System Directory Record - Book 1 §12.2.3 (Tables 11, 12).

use crate::core::error::{Error, Result};
use crate::core::tags;
use crate::core::tlv::{Tlv, Value};
use crate::de::application_priority_indicator::ApplicationPriorityIndicator;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdfDirectoryEntry {
    pub adf_name: Vec<u8>,
    pub application_label: Option<Vec<u8>>,
    pub application_preferred_name: Option<Vec<u8>>,
    pub application_priority_indicator: Option<ApplicationPriorityIndicator>,
    pub directory_discretionary_template: Option<Vec<Tlv>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PaymentSystemDirectoryRecord {
    pub entries: Vec<AdfDirectoryEntry>,
}

impl PaymentSystemDirectoryRecord {
    pub fn parse(data: &[u8]) -> Result<Self> {
        let outer = Tlv::from_bytes(data)?;
        Self::from_tlv(&outer)
    }

    pub fn from_tlv(tlv: &Tlv) -> Result<Self> {
        if tlv.tag() != tags::READ_RECORD_RESPONSE_TEMPLATE {
            return Err(Error::InvalidValue);
        }
        let children = tlv.value().as_constructed().ok_or(Error::NotConstructed)?;
        let mut entries = Vec::new();
        for child in children {
            // §12.2.3 - non-'61' children inside '70' are ignored.
            if child.tag() != tags::APPLICATION_TEMPLATE {
                continue;
            }
            let entry_children = child
                .value()
                .as_constructed()
                .ok_or(Error::NotConstructed)?;
            if let Some(entry) = parse_application_template(entry_children)? {
                entries.push(entry);
            }
        }
        Ok(PaymentSystemDirectoryRecord { entries })
    }
}

fn parse_application_template(children: &[Tlv]) -> Result<Option<AdfDirectoryEntry>> {
    let mut adf_name: Option<Vec<u8>> = None;
    let mut application_label: Option<Vec<u8>> = None;
    let mut application_preferred_name: Option<Vec<u8>> = None;
    let mut application_priority_indicator: Option<ApplicationPriorityIndicator> = None;
    let mut directory_discretionary_template: Option<Vec<Tlv>> = None;

    for child in children {
        match child.tag() {
            tags::APPLICATION_DEDICATED_FILE_NAME => {
                adf_name = Some(primitive_bytes(child)?.to_vec());
            }
            tags::APPLICATION_LABEL => {
                application_label = Some(primitive_bytes(child)?.to_vec());
            }
            tags::APPLICATION_PREFERRED_NAME => {
                application_preferred_name = Some(primitive_bytes(child)?.to_vec());
            }
            tags::APPLICATION_PRIORITY_INDICATOR => {
                application_priority_indicator = Some(ApplicationPriorityIndicator::parse(
                    primitive_bytes(child)?,
                )?);
            }
            tags::DIRECTORY_DISCRETIONARY_TEMPLATE => {
                let inner = child
                    .value()
                    .as_constructed()
                    .ok_or(Error::NotConstructed)?
                    .to_vec();
                directory_discretionary_template = Some(inner);
            }
            // §12.2.3 - unknown tags inside '61' are ignored.
            _ => {}
        }
    }

    // §12.2.3 - DDF entries (no '4F') may be ignored.
    let Some(adf_name) = adf_name else {
        return Ok(None);
    };

    // ISO/IEC 7816-4 + B1 §12.2.1 - DF Name length 5..=16.
    if !(5..=16).contains(&adf_name.len()) {
        return Err(Error::InvalidValue);
    }

    Ok(Some(AdfDirectoryEntry {
        adf_name,
        application_label,
        application_preferred_name,
        application_priority_indicator,
        directory_discretionary_template,
    }))
}

fn primitive_bytes(tlv: &Tlv) -> Result<&[u8]> {
    match tlv.value() {
        Value::Primitive(b) => Ok(b),
        Value::Constructed(_) => Err(Error::InvalidValue),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry_visa_with_priority() -> Vec<u8> {
        let inner = [
            0x4F, 0x07, 0xA0, 0x00, 0x00, 0x00, 0x03, 0x10, 0x10, 0x50, 0x04, b'V', b'I', b'S',
            b'A', 0x9F, 0x12, 0x04, b'V', b'I', b'S', b'A', 0x87, 0x01, 0x01,
        ];
        let mut out = vec![0x61, inner.len() as u8];
        out.extend_from_slice(&inner);
        out
    }

    fn entry_mc_minimal() -> Vec<u8> {
        let inner = [
            0x4F, 0x07, 0xA0, 0x00, 0x00, 0x00, 0x04, 0x10, 0x10, 0x50, 0x0A, b'M', b'A', b'S',
            b'T', b'E', b'R', b'C', b'A', b'R', b'D',
        ];
        let mut out = vec![0x61, inner.len() as u8];
        out.extend_from_slice(&inner);
        out
    }

    fn wrap_70(entries: &[Vec<u8>]) -> Vec<u8> {
        let mut value = Vec::new();
        for e in entries {
            value.extend_from_slice(e);
        }
        let mut out = vec![0x70, value.len() as u8];
        out.extend_from_slice(&value);
        out
    }

    #[test]
    fn parses_single_entry_with_all_optionals() {
        let wire = wrap_70(&[entry_visa_with_priority()]);
        let r = PaymentSystemDirectoryRecord::parse(&wire).unwrap();
        assert_eq!(r.entries.len(), 1);
        let e = &r.entries[0];
        assert_eq!(e.adf_name, [0xA0, 0x00, 0x00, 0x00, 0x03, 0x10, 0x10]);
        assert_eq!(e.application_label.as_deref(), Some(&b"VISA"[..]));
        assert_eq!(e.application_preferred_name.as_deref(), Some(&b"VISA"[..]),);
        assert_eq!(e.application_priority_indicator.unwrap().priority, 1,);
        assert!(e.directory_discretionary_template.is_none());
    }

    #[test]
    fn parses_multiple_entries_in_order() {
        let wire = wrap_70(&[entry_visa_with_priority(), entry_mc_minimal()]);
        let r = PaymentSystemDirectoryRecord::parse(&wire).unwrap();
        assert_eq!(r.entries.len(), 2);
        assert_eq!(
            r.entries[0].application_label.as_deref(),
            Some(&b"VISA"[..])
        );
        assert_eq!(
            r.entries[1].application_label.as_deref(),
            Some(&b"MASTERCARD"[..]),
        );
        assert!(r.entries[1].application_priority_indicator.is_none());
        assert!(r.entries[1].application_preferred_name.is_none());
    }

    #[test]
    fn parses_minimal_entry_with_only_adf_name() {
        let inner = [0x4F, 0x05, 0xA0, 0x00, 0x00, 0x00, 0x03];
        let mut entry = vec![0x61, inner.len() as u8];
        entry.extend_from_slice(&inner);
        let wire = wrap_70(&[entry]);
        let r = PaymentSystemDirectoryRecord::parse(&wire).unwrap();
        assert_eq!(r.entries.len(), 1);
        assert!(r.entries[0].application_label.is_none());
    }

    #[test]
    fn parses_directory_discretionary_template() {
        let inner = [
            0x4F, 0x05, 0xA0, 0x00, 0x00, 0x00, 0x03, 0x50, 0x04, b'V', b'I', b'S', b'A', 0x73,
            0x05, 0x9F, 0x0A, 0x02, 0x00, 0x01,
        ];
        let mut entry = vec![0x61, inner.len() as u8];
        entry.extend_from_slice(&inner);
        let wire = wrap_70(&[entry]);
        let r = PaymentSystemDirectoryRecord::parse(&wire).unwrap();
        let dd = r.entries[0]
            .directory_discretionary_template
            .as_ref()
            .unwrap();
        assert_eq!(dd.len(), 1);
        assert_eq!(
            dd[0].tag(),
            tags::APPLICATION_SELECTION_REGISTERED_PROPRIETARY_DATA
        );
    }

    #[test]
    fn skips_entry_without_adf_name() {
        let ddf_entry_inner = [0x50, 0x03, b'A', b'B', b'C'];
        let mut ddf_entry = vec![0x61, ddf_entry_inner.len() as u8];
        ddf_entry.extend_from_slice(&ddf_entry_inner);
        let wire = wrap_70(&[ddf_entry, entry_mc_minimal()]);
        let r = PaymentSystemDirectoryRecord::parse(&wire).unwrap();
        assert_eq!(r.entries.len(), 1);
        assert_eq!(
            r.entries[0].application_label.as_deref(),
            Some(&b"MASTERCARD"[..]),
        );
    }

    #[test]
    fn ignores_non_61_children_inside_70() {
        let mut value = vec![0x5A, 0x02, 0x12, 0x34];
        value.extend_from_slice(&entry_mc_minimal());
        let mut wire = vec![0x70, value.len() as u8];
        wire.extend_from_slice(&value);
        let r = PaymentSystemDirectoryRecord::parse(&wire).unwrap();
        assert_eq!(r.entries.len(), 1);
    }

    #[test]
    fn ignores_unknown_tags_inside_61() {
        let inner = [
            0x4F, 0x05, 0xA0, 0x00, 0x00, 0x00, 0x03, 0x5A, 0x02, 0xAB, 0xCD, 0x50, 0x04, b'V',
            b'I', b'S', b'A',
        ];
        let mut entry = vec![0x61, inner.len() as u8];
        entry.extend_from_slice(&inner);
        let wire = wrap_70(&[entry]);
        let r = PaymentSystemDirectoryRecord::parse(&wire).unwrap();
        assert_eq!(
            r.entries[0].application_label.as_deref(),
            Some(&b"VISA"[..])
        );
    }

    #[test]
    fn rejects_wrong_outer_tag() {
        let wire = vec![0x6F, 0x02, 0x00, 0x00];
        assert_eq!(
            PaymentSystemDirectoryRecord::parse(&wire),
            Err(Error::InvalidValue),
        );
    }

    #[test]
    fn rejects_adf_name_too_short() {
        let inner = [0x4F, 0x04, 0xA0, 0x00, 0x00, 0x00];
        let mut entry = vec![0x61, inner.len() as u8];
        entry.extend_from_slice(&inner);
        let wire = wrap_70(&[entry]);
        assert_eq!(
            PaymentSystemDirectoryRecord::parse(&wire),
            Err(Error::InvalidValue),
        );
    }

    #[test]
    fn empty_record_yields_empty_entries() {
        let wire = vec![0x70, 0x00];
        let r = PaymentSystemDirectoryRecord::parse(&wire).unwrap();
        assert!(r.entries.is_empty());
    }
}
