//! Book 3 §5.4 - Data Object List (DOL) parsing and field assembly.

use crate::core::error::{Error, Result};
use crate::core::tag::Tag;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DolEntry {
    pub tag: Tag,
    pub length: u8,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Dol(pub Vec<DolEntry>);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValueFormat {
    Numeric,
    CompressedNumeric,
    Other,
}

impl Dol {
    pub fn parse(data: &[u8]) -> Result<Self> {
        let mut entries = Vec::new();
        let mut i = 0;
        while i < data.len() {
            let (tag, tag_len) = Tag::parse(&data[i..])?;
            if tag_len > 2 {
                return Err(Error::InvalidValue);
            }
            i += tag_len;
            let length = *data.get(i).ok_or(Error::UnexpectedEof)?;
            i += 1;
            entries.push(DolEntry { tag, length });
        }
        Ok(Dol(entries))
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.0.len() * 3);
        for entry in &self.0 {
            out.extend(entry.tag.to_bytes());
            out.push(entry.length);
        }
        out
    }

    pub fn build<F>(&self, lookup: F) -> Vec<u8>
    where
        F: Fn(Tag) -> Option<(ValueFormat, Vec<u8>)>,
    {
        let total: usize = self.0.iter().map(|e| e.length as usize).sum();
        let mut out = Vec::with_capacity(total);
        for entry in &self.0 {
            let len = entry.length as usize;
            if entry.tag.is_constructed() {
                out.resize(out.len() + len, 0x00);
                continue;
            }
            match lookup(entry.tag) {
                None => out.resize(out.len() + len, 0x00),
                Some((format, bytes)) => extend_pad_or_truncate(&mut out, &bytes, len, format),
            }
        }
        out
    }
}

fn extend_pad_or_truncate(out: &mut Vec<u8>, value: &[u8], target: usize, format: ValueFormat) {
    let actual = value.len();
    match actual.cmp(&target) {
        std::cmp::Ordering::Equal => out.extend_from_slice(value),
        std::cmp::Ordering::Greater => match format {
            ValueFormat::Numeric => out.extend_from_slice(&value[actual - target..]),
            _ => out.extend_from_slice(&value[..target]),
        },
        std::cmp::Ordering::Less => {
            let pad = target - actual;
            match format {
                ValueFormat::Numeric => {
                    out.resize(out.len() + pad, 0x00);
                    out.extend_from_slice(value);
                }
                ValueFormat::CompressedNumeric => {
                    out.extend_from_slice(value);
                    out.resize(out.len() + pad, 0xFF);
                }
                ValueFormat::Other => {
                    out.extend_from_slice(value);
                    out.resize(out.len() + pad, 0x00);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_typical_cdol1() {
        let wire = [
            0x9F, 0x02, 0x06, 0x9F, 0x03, 0x06, 0x9F, 0x1A, 0x02, 0x95, 0x05, 0x5F, 0x2A, 0x02,
            0x9A, 0x03, 0x9C, 0x01, 0x9F, 0x37, 0x04,
        ];
        let dol = Dol::parse(&wire).unwrap();
        assert_eq!(dol.0.len(), 8);
        assert_eq!(
            dol.0[0],
            DolEntry {
                tag: Tag(0x9F02),
                length: 6
            }
        );
        assert_eq!(
            dol.0[3],
            DolEntry {
                tag: Tag(0x95),
                length: 5
            }
        );
        assert_eq!(
            dol.0[7],
            DolEntry {
                tag: Tag(0x9F37),
                length: 4
            }
        );
    }

    #[test]
    fn parse_encode_roundtrip() {
        let wire = [0x9F, 0x02, 0x06, 0x95, 0x05, 0x5F, 0x2A, 0x02];
        let dol = Dol::parse(&wire).unwrap();
        assert_eq!(dol.encode(), wire);
    }

    #[test]
    fn parse_truncated_after_tag() {
        assert_eq!(Dol::parse(&[0x9F, 0x02]), Err(Error::UnexpectedEof));
    }

    #[test]
    fn parse_rejects_three_byte_tag_per_5_4() {
        assert_eq!(
            Dol::parse(&[0xBF, 0x81, 0x0C, 0x04]),
            Err(Error::InvalidValue)
        );
    }

    #[test]
    fn parse_empty_is_empty_dol() {
        let dol = Dol::parse(&[]).unwrap();
        assert!(dol.0.is_empty());
        assert_eq!(dol.encode(), Vec::<u8>::new());
    }

    #[test]
    fn build_with_all_values_present_exact_length() {
        let dol = Dol::parse(&[0x9F, 0x02, 0x06, 0x9C, 0x01]).unwrap();
        let data = dol.build(|tag| match tag {
            Tag(0x9F02) => Some((ValueFormat::Numeric, vec![0, 0, 0, 0, 0x12, 0x34])),
            Tag(0x9C) => Some((ValueFormat::Numeric, vec![0x00])),
            _ => None,
        });
        assert_eq!(data, vec![0, 0, 0, 0, 0x12, 0x34, 0x00]);
    }

    #[test]
    fn build_missing_value_zero_fills() {
        let dol = Dol::parse(&[0x9F, 0x02, 0x06, 0x9F, 0x37, 0x04]).unwrap();
        let data = dol.build(|tag| match tag {
            Tag(0x9F02) => Some((ValueFormat::Numeric, vec![0, 0, 0, 0, 0x12, 0x34])),
            _ => None,
        });
        assert_eq!(data, vec![0, 0, 0, 0, 0x12, 0x34, 0, 0, 0, 0]);
    }

    #[test]
    fn build_constructed_tag_zero_fills_without_lookup() {
        let dol = Dol(vec![DolEntry {
            tag: Tag(0x70),
            length: 3,
        }]);
        let data = dol.build(|_| Some((ValueFormat::Other, vec![0xAA, 0xBB, 0xCC])));
        assert_eq!(data, vec![0x00, 0x00, 0x00]);
    }

    #[test]
    fn build_numeric_pads_with_leading_zeros() {
        let dol = Dol(vec![DolEntry {
            tag: Tag(0x9F02),
            length: 6,
        }]);
        let data = dol.build(|_| Some((ValueFormat::Numeric, vec![0x12, 0x34, 0x56])));
        assert_eq!(data, vec![0x00, 0x00, 0x00, 0x12, 0x34, 0x56]);
    }

    #[test]
    fn build_numeric_truncates_leftmost() {
        let dol = Dol(vec![DolEntry {
            tag: Tag(0x9F02),
            length: 3,
        }]);
        let data = dol.build(|_| {
            Some((
                ValueFormat::Numeric,
                vec![0x11, 0x22, 0x33, 0x44, 0x55, 0x66],
            ))
        });
        assert_eq!(data, vec![0x44, 0x55, 0x66]);
    }

    #[test]
    fn build_compressed_numeric_pads_with_trailing_ff() {
        let dol = Dol(vec![DolEntry {
            tag: Tag(0x5A),
            length: 5,
        }]);
        let data = dol.build(|_| Some((ValueFormat::CompressedNumeric, vec![0x12, 0x34, 0x56])));
        assert_eq!(data, vec![0x12, 0x34, 0x56, 0xFF, 0xFF]);
    }

    #[test]
    fn build_compressed_numeric_truncates_rightmost() {
        let dol = Dol(vec![DolEntry {
            tag: Tag(0x5A),
            length: 3,
        }]);
        let data = dol.build(|_| {
            Some((
                ValueFormat::CompressedNumeric,
                vec![0x11, 0x22, 0x33, 0x44, 0x55],
            ))
        });
        assert_eq!(data, vec![0x11, 0x22, 0x33]);
    }

    #[test]
    fn build_other_format_pads_with_trailing_zeros() {
        let dol = Dol(vec![DolEntry {
            tag: Tag(0x9F1A),
            length: 4,
        }]);
        let data = dol.build(|_| Some((ValueFormat::Other, vec![0xAA, 0xBB])));
        assert_eq!(data, vec![0xAA, 0xBB, 0x00, 0x00]);
    }

    #[test]
    fn build_other_format_truncates_rightmost() {
        let dol = Dol(vec![DolEntry {
            tag: Tag(0x9F1A),
            length: 2,
        }]);
        let data = dol.build(|_| Some((ValueFormat::Other, vec![0xAA, 0xBB, 0xCC, 0xDD])));
        assert_eq!(data, vec![0xAA, 0xBB]);
    }

    #[test]
    fn build_zero_length_entry() {
        let dol = Dol(vec![DolEntry {
            tag: Tag(0x9F02),
            length: 0,
        }]);
        let data = dol.build(|_| Some((ValueFormat::Numeric, vec![0x12])));
        assert_eq!(data, Vec::<u8>::new());
    }

    #[test]
    fn build_preserves_dol_order() {
        let dol = Dol::parse(&[0x9C, 0x01, 0x9F, 0x02, 0x02]).unwrap();
        let data = dol.build(|tag| match tag {
            Tag(0x9F02) => Some((ValueFormat::Numeric, vec![0xAA, 0xBB])),
            Tag(0x9C) => Some((ValueFormat::Numeric, vec![0x07])),
            _ => None,
        });
        assert_eq!(data, vec![0x07, 0xAA, 0xBB]);
    }
}
