//! Book 3 Annex B - BER-TLV encoding and decoding.

use crate::core::error::{Error, Result};
use crate::core::tag::Tag;
use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tlv {
    tag: Tag,
    value: Value,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Value {
    Primitive(Vec<u8>),
    Constructed(Vec<Tlv>),
}

impl Value {
    pub fn is_constructed(&self) -> bool {
        matches!(self, Self::Constructed(_))
    }

    pub fn as_primitive(&self) -> Option<&[u8]> {
        match self {
            Self::Primitive(b) => Some(b),
            Self::Constructed(_) => None,
        }
    }

    pub fn as_constructed(&self) -> Option<&[Tlv]> {
        match self {
            Self::Constructed(c) => Some(c),
            Self::Primitive(_) => None,
        }
    }

    pub fn encoded_len(&self) -> usize {
        match self {
            Self::Primitive(b) => b.len(),
            Self::Constructed(children) => children.iter().map(|t| t.wire_len()).sum(),
        }
    }

    fn encode_into(&self, out: &mut Vec<u8>) {
        match self {
            Self::Primitive(b) => out.extend_from_slice(b),
            Self::Constructed(children) => {
                for child in children {
                    child.encode_append(out);
                }
            }
        }
    }
}

impl Tlv {
    pub fn new(tag: Tag, value: Value) -> Result<Self> {
        if tag.is_constructed() != value.is_constructed() {
            return Err(Error::InvalidValue);
        }
        Ok(Tlv { tag, value })
    }

    pub fn primitive(tag: Tag, bytes: impl Into<Vec<u8>>) -> Self {
        assert!(
            !tag.is_constructed(),
            "primitive value with constructed tag"
        );
        Tlv {
            tag,
            value: Value::Primitive(bytes.into()),
        }
    }

    pub fn constructed(tag: Tag, children: impl Into<Vec<Tlv>>) -> Self {
        assert!(tag.is_constructed(), "constructed value with primitive tag");
        Tlv {
            tag,
            value: Value::Constructed(children.into()),
        }
    }

    pub fn tag(&self) -> Tag {
        self.tag
    }

    pub fn value(&self) -> &Value {
        &self.value
    }

    pub fn parse(data: &[u8]) -> Result<(Tlv, usize)> {
        let (tag, tag_len) = Tag::parse(data)?;
        let (length, length_len) = parse_length(&data[tag_len..])?;
        let start = tag_len + length_len;
        let end = start.checked_add(length).ok_or(Error::LengthTooLong)?;
        if end > data.len() {
            return Err(Error::UnexpectedEof);
        }
        let value_bytes = &data[start..end];
        let value = if tag.is_constructed() {
            Value::Constructed(Tlv::parse_all(value_bytes)?)
        } else {
            Value::Primitive(value_bytes.to_vec())
        };
        Ok((Tlv { tag, value }, end))
    }

    pub fn from_bytes(data: &[u8]) -> Result<Tlv> {
        let (tlv, n) = Tlv::parse(data)?;
        if n != data.len() {
            return Err(Error::InvalidValue);
        }
        Ok(tlv)
    }

    pub fn parse_all(data: &[u8]) -> Result<Vec<Tlv>> {
        let mut out = Vec::new();
        let mut i = 0;
        while i < data.len() {
            if data[i] == 0x00 {
                i += 1;
                continue;
            }
            let (tlv, consumed) = Tlv::parse(&data[i..])?;
            i += consumed;
            out.push(tlv);
        }
        Ok(out)
    }

    pub fn value_len(&self) -> usize {
        self.value.encoded_len()
    }

    pub fn wire_len(&self) -> usize {
        let v = self.value.encoded_len();
        self.tag.byte_len() + encode_length(v).len() + v
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        self.encode_append(&mut out);
        out
    }

    fn encode_append(&self, out: &mut Vec<u8>) {
        out.extend(self.tag.to_bytes());
        out.extend(encode_length(self.value.encoded_len()));
        self.value.encode_into(out);
    }

    pub fn find(&self, tag: Tag) -> Option<&Tlv> {
        if self.tag == tag {
            return Some(self);
        }
        if let Value::Constructed(children) = &self.value {
            for child in children {
                if let Some(found) = child.find(tag) {
                    return Some(found);
                }
            }
        }
        None
    }

    pub fn find_all(&self, tag: Tag) -> Vec<&Tlv> {
        let mut out = Vec::new();
        self.find_all_into(tag, &mut out);
        out
    }

    fn find_all_into<'a>(&'a self, tag: Tag, out: &mut Vec<&'a Tlv>) {
        if self.tag == tag {
            out.push(self);
        }
        if let Value::Constructed(children) = &self.value {
            for child in children {
                child.find_all_into(tag, out);
            }
        }
    }
}

impl fmt::Display for Tlv {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let indent = f.width().unwrap_or(0);
        match &self.value {
            Value::Primitive(bytes) => {
                write!(f, "{:indent$}{} ({})", "", self.tag, bytes.len())?;
                if !bytes.is_empty() {
                    write!(f, " ")?;
                    for b in bytes {
                        write!(f, "{:02X}", b)?;
                    }
                }
            }
            Value::Constructed(children) => {
                write!(
                    f,
                    "{:indent$}{} ({})",
                    "",
                    self.tag,
                    self.value.encoded_len()
                )?;
                let child_indent = indent + 2;
                for child in children {
                    writeln!(f)?;
                    write!(f, "{:child_indent$}", child)?;
                }
            }
        }
        Ok(())
    }
}

pub fn encode_length(len: usize) -> Vec<u8> {
    if len <= 0x7F {
        vec![len as u8]
    } else if len <= 0xFF {
        vec![0x81, len as u8]
    } else if len <= 0xFFFF {
        let b = (len as u16).to_be_bytes();
        vec![0x82, b[0], b[1]]
    } else if len <= 0xFF_FFFF {
        let b = (len as u32).to_be_bytes();
        vec![0x83, b[1], b[2], b[3]]
    } else {
        let b = (len as u64).to_be_bytes();
        vec![0x84, b[4], b[5], b[6], b[7]]
    }
}

pub fn parse_length(data: &[u8]) -> Result<(usize, usize)> {
    let first = *data.first().ok_or(Error::UnexpectedEof)?;
    if first & 0x80 == 0 {
        return Ok((first as usize, 1));
    }
    let n = (first & 0x7F) as usize;
    if n == 0 {
        return Err(Error::IndefiniteLength);
    }
    if n > 4 {
        return Err(Error::LengthTooLong);
    }
    if data.len() < 1 + n {
        return Err(Error::UnexpectedEof);
    }
    let mut length = 0usize;
    for j in 0..n {
        length = (length << 8) | (data[1 + j] as usize);
    }
    Ok((length, 1 + n))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_length_short() {
        assert_eq!(encode_length(0), vec![0x00]);
        assert_eq!(encode_length(0x7F), vec![0x7F]);
    }

    #[test]
    fn encode_length_long() {
        assert_eq!(encode_length(0x80), vec![0x81, 0x80]);
        assert_eq!(encode_length(0x100), vec![0x82, 0x01, 0x00]);
    }

    #[test]
    fn parse_length_short() {
        assert_eq!(parse_length(&[0x00]).unwrap(), (0, 1));
        assert_eq!(parse_length(&[0x7F]).unwrap(), (0x7F, 1));
    }

    #[test]
    fn parse_length_long() {
        assert_eq!(parse_length(&[0x81, 0x80]).unwrap(), (0x80, 2));
        assert_eq!(parse_length(&[0x82, 0x01, 0x00]).unwrap(), (0x100, 3));
    }

    #[test]
    fn parse_length_rejects_indefinite() {
        assert_eq!(parse_length(&[0x80]), Err(Error::IndefiniteLength));
    }

    #[test]
    fn parse_length_rejects_too_many_bytes() {
        assert_eq!(
            parse_length(&[0x85, 1, 2, 3, 4, 5]),
            Err(Error::LengthTooLong)
        );
    }

    #[test]
    fn parse_length_truncated() {
        assert_eq!(parse_length(&[]), Err(Error::UnexpectedEof));
        assert_eq!(parse_length(&[0x82, 0x01]), Err(Error::UnexpectedEof));
    }

    #[test]
    fn primitive_roundtrip() {
        let wire = [0x9F, 0x02, 0x06, 0x00, 0x00, 0x00, 0x00, 0x01, 0x23];
        let (tlv, n) = Tlv::parse(&wire).unwrap();
        assert_eq!(n, wire.len());
        assert_eq!(tlv.tag(), Tag(0x9F02));
        assert_eq!(
            tlv.value().as_primitive().unwrap(),
            &[0x00, 0x00, 0x00, 0x00, 0x01, 0x23]
        );
        assert_eq!(tlv.encode(), wire);
    }

    #[test]
    fn constructed_recursive_parse() {
        let wire = [
            0x70, 0x0C, 0x5A, 0x04, 0x11, 0x22, 0x33, 0x44, 0x5F, 0x20, 0x03, 0x41, 0x42, 0x43,
        ];
        let (tlv, n) = Tlv::parse(&wire).unwrap();
        assert_eq!(n, wire.len());
        assert_eq!(tlv.tag(), Tag(0x70));
        let kids = tlv.value().as_constructed().unwrap();
        assert_eq!(kids.len(), 2);
        assert_eq!(kids[0].tag(), Tag(0x5A));
        assert_eq!(kids[1].tag(), Tag(0x5F20));
        assert_eq!(tlv.encode(), wire);
    }

    #[test]
    fn nested_constructed_roundtrip() {
        let inner = Tlv::primitive(Tag(0x88), vec![0x01]);
        let proprietary = Tlv::constructed(Tag(0xA5), vec![inner]);
        let outer = Tlv::constructed(Tag(0x6F), vec![proprietary]);
        let wire = outer.encode();
        let (parsed, n) = Tlv::parse(&wire).unwrap();
        assert_eq!(n, wire.len());
        assert_eq!(parsed, outer);
    }

    #[test]
    fn parse_all_skips_padding() {
        let wire = [
            0x00, 0x50, 0x03, 0x41, 0x42, 0x43, 0x00, 0x00, 0x87, 0x01, 0x01,
        ];
        let tlvs = Tlv::parse_all(&wire).unwrap();
        assert_eq!(tlvs.len(), 2);
        assert_eq!(tlvs[0].tag(), Tag(0x50));
        assert_eq!(tlvs[1].tag(), Tag(0x87));
    }

    #[test]
    fn truncated_value_errors() {
        assert_eq!(
            Tlv::parse(&[0x50, 0x0A, 0x41, 0x42, 0x43]),
            Err(Error::UnexpectedEof)
        );
    }

    #[test]
    fn lengths_recursive() {
        let inner = Tlv::primitive(Tag(0x88), vec![0xAA, 0xBB]);
        assert_eq!(inner.value_len(), 2);
        assert_eq!(inner.wire_len(), 4);
        let outer = Tlv::constructed(Tag(0xA5), vec![inner]);
        assert_eq!(outer.value_len(), 4);
        assert_eq!(outer.wire_len(), 6);
    }

    // ── New constructor / accessor / find / display tests ──

    #[test]
    fn new_validates_pc_bit_consistency() {
        assert_eq!(
            Tlv::new(Tag(0x9F02), Value::Constructed(vec![])),
            Err(Error::InvalidValue)
        );
        assert_eq!(
            Tlv::new(Tag(0x70), Value::Primitive(vec![0xAA])),
            Err(Error::InvalidValue)
        );
        assert!(Tlv::new(Tag(0x9F02), Value::Primitive(vec![0xAA])).is_ok());
        assert!(Tlv::new(Tag(0x70), Value::Constructed(vec![])).is_ok());
    }

    #[test]
    #[should_panic(expected = "primitive value with constructed tag")]
    fn primitive_constructor_panics_on_constructed_tag() {
        let _ = Tlv::primitive(Tag(0x70), vec![0xAA]);
    }

    #[test]
    #[should_panic(expected = "constructed value with primitive tag")]
    fn constructed_constructor_panics_on_primitive_tag() {
        let _ = Tlv::constructed(Tag(0x9F02), vec![]);
    }

    #[test]
    fn from_bytes_strict_full_consumption() {
        let wire = [0x9F, 0x02, 0x02, 0xAA, 0xBB];
        assert!(Tlv::from_bytes(&wire).is_ok());
        let trailing = [0x9F, 0x02, 0x02, 0xAA, 0xBB, 0xCC];
        assert_eq!(Tlv::from_bytes(&trailing), Err(Error::InvalidValue));
    }

    #[test]
    fn find_walks_into_constructed_children() {
        let pan = Tlv::primitive(Tag(0x5A), vec![0x11, 0x22, 0x33, 0x44]);
        let name = Tlv::primitive(Tag(0x5F20), b"ABC".to_vec());
        let template = Tlv::constructed(Tag(0x70), vec![pan.clone(), name]);
        assert_eq!(template.find(Tag(0x5A)), Some(&pan));
        assert!(template.find(Tag(0x9F99)).is_none());
        assert_eq!(template.find(Tag(0x70)), Some(&template));
    }

    #[test]
    fn find_descends_through_multiple_levels() {
        let inner = Tlv::primitive(Tag(0x88), vec![0x01]);
        let proprietary = Tlv::constructed(Tag(0xA5), vec![inner]);
        let outer = Tlv::constructed(Tag(0x6F), vec![proprietary]);
        let found = outer.find(Tag(0x88)).unwrap();
        assert_eq!(found.tag(), Tag(0x88));
        assert_eq!(found.value().as_primitive().unwrap(), &[0x01]);
    }

    #[test]
    fn find_all_collects_every_match() {
        let leaf = || Tlv::primitive(Tag(0x5A), vec![0x00]);
        let nested = Tlv::constructed(Tag(0x70), vec![leaf(), leaf()]);
        let outer = Tlv::constructed(Tag(0x70), vec![leaf(), nested]);
        assert_eq!(outer.find_all(Tag(0x5A)).len(), 3);
        assert_eq!(outer.find_all(Tag(0x70)).len(), 2);
    }

    #[test]
    fn display_primitive() {
        let tlv = Tlv::primitive(Tag(0x9F02), vec![0xAA, 0xBB]);
        assert_eq!(format!("{}", tlv), "9F02 (2) AABB");
    }

    #[test]
    fn display_constructed_indents_children() {
        let inner = Tlv::primitive(Tag(0x88), vec![0x01]);
        let outer = Tlv::constructed(Tag(0xA5), vec![inner]);
        let s = format!("{}", outer);
        assert!(s.contains("A5 (3)"));
        assert!(s.contains("\n  88 (1) 01"));
    }
}
