//! Book 1 §12.2 / Annex B Tables 8 & 9 - PSE / DDF FCI.

use crate::core::error::{Error, Result};
use crate::core::fci::{
    parse_outer_template, primitive_bytes, take_mandatory, take_optional_constructed,
    take_optional_icti, take_optional_primitive,
};
use crate::core::tags;
use crate::core::tlv::Tlv;
use crate::de::issuer_code_table_index::IssuerCodeTableIndex;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PseFci {
    pub df_name: Vec<u8>,
    pub sfi_of_directory_ef: u8,
    pub language_preference: Option<Vec<u8>>,
    pub issuer_code_table_index: Option<IssuerCodeTableIndex>,
    pub fci_issuer_discretionary_data: Option<Vec<Tlv>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DdfFci {
    pub df_name: Vec<u8>,
    pub sfi_of_directory_ef: u8,
    pub fci_issuer_discretionary_data: Option<Vec<Tlv>>,
}

impl PseFci {
    pub fn parse(data: &[u8]) -> Result<Self> {
        let proprietary = parse_outer_template(data)?;
        let df_name = primitive_bytes(take_mandatory(&proprietary.outer, tags::DEDICATED_FILE_NAME)?)?
            .to_vec();
        let sfi_of_directory_ef =
            single_byte(take_mandatory(&proprietary.inner, tags::SHORT_FILE_IDENTIFIER)?)?;
        Ok(PseFci {
            df_name,
            sfi_of_directory_ef,
            language_preference: take_optional_primitive(
                &proprietary.inner,
                tags::LANGUAGE_PREFERENCE,
            )?,
            issuer_code_table_index: take_optional_icti(&proprietary.inner)?,
            fci_issuer_discretionary_data: take_optional_constructed(
                &proprietary.inner,
                tags::FCI_ISSUER_DISCRETIONARY_DATA,
            )?,
        })
    }
}

impl DdfFci {
    pub fn parse(data: &[u8]) -> Result<Self> {
        let proprietary = parse_outer_template(data)?;
        let df_name = primitive_bytes(take_mandatory(&proprietary.outer, tags::DEDICATED_FILE_NAME)?)?
            .to_vec();
        let sfi_of_directory_ef =
            single_byte(take_mandatory(&proprietary.inner, tags::SHORT_FILE_IDENTIFIER)?)?;
        Ok(DdfFci {
            df_name,
            sfi_of_directory_ef,
            fci_issuer_discretionary_data: take_optional_constructed(
                &proprietary.inner,
                tags::FCI_ISSUER_DISCRETIONARY_DATA,
            )?,
        })
    }
}

fn single_byte(tlv: &Tlv) -> Result<u8> {
    let bytes = primitive_bytes(tlv)?;
    if bytes.len() != 1 {
        return Err(Error::WrongLength {
            expected: 1,
            got: bytes.len(),
        });
    }
    Ok(bytes[0])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::tag::Tag;

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
    fn parse_pse_minimal_per_table_8() {
        let df_name = b"1PAY.SYS.DDF01";
        let a5 = [0x88, 0x01, 0x01];
        let wire = fci_envelope(df_name, &a5);
        let fci = PseFci::parse(&wire).unwrap();
        assert_eq!(fci.df_name, df_name);
        assert_eq!(fci.sfi_of_directory_ef, 0x01);
        assert!(fci.language_preference.is_none());
        assert!(fci.issuer_code_table_index.is_none());
        assert!(fci.fci_issuer_discretionary_data.is_none());
    }

    #[test]
    fn parse_pse_with_optionals() {
        let a5 = [
            0x88, 0x01, 0x01, 0x5F, 0x2D, 0x02, b'e', b'n', 0x9F, 0x11, 0x01, 0x01, 0xBF, 0x0C,
            0x03, 0x50, 0x01, b'X',
        ];
        let wire = fci_envelope(b"1PAY.SYS.DDF01", &a5);
        let fci = PseFci::parse(&wire).unwrap();
        assert_eq!(fci.sfi_of_directory_ef, 0x01);
        assert_eq!(fci.language_preference.as_deref(), Some(b"en".as_ref()));
        assert_eq!(
            fci.issuer_code_table_index.unwrap(),
            IssuerCodeTableIndex(0x01)
        );
        let disc = fci.fci_issuer_discretionary_data.unwrap();
        assert_eq!(disc.len(), 1);
        assert_eq!(disc[0].tag(), Tag(0x50));
        assert_eq!(disc[0].value().as_primitive().unwrap(), b"X");
    }

    #[test]
    fn parse_ddf_minimal_per_table_9() {
        let a5 = [0x88, 0x01, 0x02];
        let wire = fci_envelope(b"DDF.NAME", &a5);
        let fci = DdfFci::parse(&wire).unwrap();
        assert_eq!(fci.df_name, b"DDF.NAME");
        assert_eq!(fci.sfi_of_directory_ef, 0x02);
        assert!(fci.fci_issuer_discretionary_data.is_none());
    }

    #[test]
    fn parse_pse_rejects_wrong_outer_tag() {
        let wire = [0x70, 0x02, 0x84, 0x00];
        assert_eq!(PseFci::parse(&wire), Err(Error::InvalidValue));
    }

    #[test]
    fn parse_pse_missing_mandatory_sfi_errors() {
        let wire = fci_envelope(b"1PAY.SYS.DDF01", &[]);
        assert_eq!(PseFci::parse(&wire), Err(Error::InvalidValue));
    }
}
