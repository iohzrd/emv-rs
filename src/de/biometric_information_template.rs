//! Biometric Information Template - Book 3 Annex C7 (Table 48) and C8 (Tables 51–52).

use crate::core::error::{Error, Result};
use crate::core::tag::Tag;
use crate::core::tlv::Tlv;

pub const BIT_GROUP_TEMPLATE: Tag = Tag(0x7F60);
pub const BIOMETRIC_INFORMATION_TEMPLATE: Tag = Tag(0x7F2E);
pub const BIOMETRIC_HEADER_TEMPLATE: Tag = Tag(0xA1);
pub const BIOMETRIC_HEADER_TEMPLATE_2: Tag = Tag(0xA2);
pub const PATRON_HEADER_VERSION: Tag = Tag(0x80);
pub const BIOMETRIC_SOLUTION_ID: Tag = Tag(0x90);
pub const BIOMETRIC_TYPE: Tag = Tag(0x81);
pub const BIOMETRIC_SUBTYPE: Tag = Tag(0x82);
pub const CREATION_DATE_AND_TIME: Tag = Tag(0x83);
pub const CREATOR: Tag = Tag(0x84);
pub const VALIDITY_PERIOD: Tag = Tag(0x85);
pub const PRODUCT_IDENTIFIER: Tag = Tag(0x86);
pub const FORMAT_OWNER: Tag = Tag(0x87);
pub const FORMAT_TYPE: Tag = Tag(0x88);
pub const BIOMETRIC_MATCHING_ALGORITHM_PARAMETERS: Tag = Tag(0x91);
pub const BIOMETRIC_MATCHING_ALGORITHM_PARAMETERS_CONSTRUCTED: Tag = Tag(0xB1);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BiometricInformationTemplate(pub Vec<Tlv>);

impl BiometricInformationTemplate {
    pub fn parse(tlv: &Tlv) -> Result<Self> {
        if tlv.tag() != BIOMETRIC_INFORMATION_TEMPLATE {
            return Err(Error::InvalidValue);
        }
        let children = tlv.value().as_constructed().ok_or(Error::NotConstructed)?;
        Ok(BiometricInformationTemplate(children.to_vec()))
    }

    pub fn children(&self) -> &[Tlv] {
        &self.0
    }

    pub fn biometric_header_templates(&self) -> impl Iterator<Item = &Tlv> {
        self.0.iter().filter(|t| t.tag() == BIOMETRIC_HEADER_TEMPLATE)
    }

    pub fn to_tlv(&self) -> Tlv {
        Tlv::constructed(BIOMETRIC_INFORMATION_TEMPLATE, self.0.clone())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BiometricInformationTemplateGroup(pub Vec<Tlv>);

impl BiometricInformationTemplateGroup {
    pub fn parse(tlv: &Tlv) -> Result<Self> {
        if tlv.tag() != BIT_GROUP_TEMPLATE {
            return Err(Error::InvalidValue);
        }
        let children = tlv.value().as_constructed().ok_or(Error::NotConstructed)?;
        Ok(BiometricInformationTemplateGroup(children.to_vec()))
    }

    pub fn bits(&self) -> impl Iterator<Item = &Tlv> {
        self.0
            .iter()
            .filter(|t| t.tag() == BIOMETRIC_INFORMATION_TEMPLATE)
    }

    pub fn children(&self) -> &[Tlv] {
        &self.0
    }

    pub fn to_tlv(&self) -> Tlv {
        Tlv::constructed(BIT_GROUP_TEMPLATE, self.0.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_bit() -> Tlv {
        let bht = Tlv::constructed(
            BIOMETRIC_HEADER_TEMPLATE,
            vec![
                Tlv::primitive(PATRON_HEADER_VERSION, vec![0x01, 0x01]),
                Tlv::primitive(BIOMETRIC_SOLUTION_ID, vec![0xDE, 0xAD, 0xBE, 0xEF]),
                Tlv::primitive(BIOMETRIC_TYPE, vec![0x02]),
                Tlv::primitive(BIOMETRIC_SUBTYPE, vec![0x00]),
            ],
        );
        let format_owner = Tlv::primitive(FORMAT_OWNER, vec![0x00, 0x01]);
        let format_type = Tlv::primitive(FORMAT_TYPE, vec![0x00, 0x02]);
        Tlv::constructed(
            BIOMETRIC_INFORMATION_TEMPLATE,
            vec![bht, format_owner, format_type],
        )
    }

    #[test]
    fn parse_bit_exposes_children() {
        let bit_tlv = sample_bit();
        let bit = BiometricInformationTemplate::parse(&bit_tlv).unwrap();
        assert_eq!(bit.children().len(), 3);
        assert_eq!(bit.children()[0].tag(), BIOMETRIC_HEADER_TEMPLATE);
        assert_eq!(bit.children()[1].tag(), FORMAT_OWNER);
        assert_eq!(bit.children()[2].tag(), FORMAT_TYPE);
        assert_eq!(bit.biometric_header_templates().count(), 1);
    }

    #[test]
    fn bit_wrong_tag_rejected() {
        let tlv = Tlv::constructed(Tag(0x70), vec![]);
        assert_eq!(
            BiometricInformationTemplate::parse(&tlv),
            Err(Error::InvalidValue)
        );
    }

    #[test]
    fn parse_bit_group_with_single_bit_roundtrip() {
        let bit = sample_bit();
        let group = Tlv::constructed(BIT_GROUP_TEMPLATE, vec![bit]);
        let wire = group.encode();

        let (parsed_tlv, n) = Tlv::parse(&wire).unwrap();
        assert_eq!(n, wire.len());
        let bg = BiometricInformationTemplateGroup::parse(&parsed_tlv).unwrap();
        assert_eq!(bg.bits().count(), 1);
        assert_eq!(bg.bits().next().unwrap().tag(), BIOMETRIC_INFORMATION_TEMPLATE);

        let re = bg.to_tlv();
        assert_eq!(re.tag(), BIT_GROUP_TEMPLATE);
        assert_eq!(re.encode(), wire);
    }

    #[test]
    fn bit_group_with_count_prefix_preserves_children() {
        let count = Tlv::primitive(Tag(0x02), vec![0x01]);
        let group = Tlv::constructed(BIT_GROUP_TEMPLATE, vec![count, sample_bit()]);
        let bg = BiometricInformationTemplateGroup::parse(&group).unwrap();
        assert_eq!(bg.children().len(), 2);
        assert_eq!(bg.children()[0].tag(), Tag(0x02));
        assert_eq!(
            bg.children()[0].value().as_primitive().unwrap(),
            &[0x01]
        );
        assert_eq!(bg.bits().count(), 1);
    }

    #[test]
    fn bit_group_wrong_tag_rejected() {
        let tlv = Tlv::constructed(Tag(0x70), vec![]);
        assert_eq!(
            BiometricInformationTemplateGroup::parse(&tlv),
            Err(Error::InvalidValue)
        );
    }

    #[test]
    fn bit_roundtrip_preserves_children() {
        let bit_tlv = sample_bit();
        let wire = bit_tlv.encode();
        let (tlv, _) = Tlv::parse(&wire).unwrap();
        let bit = BiometricInformationTemplate::parse(&tlv).unwrap();
        let re = bit.to_tlv();
        assert_eq!(re.encode(), wire);
    }
}
