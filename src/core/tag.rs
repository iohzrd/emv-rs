//! Book 3 Annex B1 - BER-TLV tag field.

use crate::core::error::{Error, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Tag(pub u32);

impl Tag {
    // Left-aligned for byte-lexicographic ordering.
    fn sort_key(&self) -> u32 {
        self.0 << ((4 - self.byte_len()) * 8)
    }
}

impl PartialOrd for Tag {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Tag {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.sort_key().cmp(&other.sort_key())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TagClass {
    Universal,
    Application,
    ContextSpecific,
    Private,
}

impl Tag {
    pub fn parse(data: &[u8]) -> Result<(Tag, usize)> {
        let b0 = *data.first().ok_or(Error::UnexpectedEof)?;
        if b0 & 0x1F != 0x1F {
            return Ok((Tag(b0 as u32), 1));
        }
        let mut tag = b0 as u32;
        let mut i = 1;
        loop {
            if i >= 4 {
                return Err(Error::TagTooLong);
            }
            let b = *data.get(i).ok_or(Error::UnexpectedEof)?;
            tag = (tag << 8) | (b as u32);
            i += 1;
            if b & 0x80 == 0 {
                break;
            }
        }
        Ok((Tag(tag), i))
    }

    pub fn byte_len(&self) -> usize {
        match self.0 {
            0..=0xFF => 1,
            0x100..=0xFFFF => 2,
            0x1_0000..=0xFF_FFFF => 3,
            _ => 4,
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let len = self.byte_len();
        let mut out = Vec::with_capacity(len);
        for shift in (0..len).rev() {
            out.push(((self.0 >> (shift * 8)) & 0xFF) as u8);
        }
        out
    }

    fn first_byte(&self) -> u8 {
        let len = self.byte_len();
        ((self.0 >> ((len - 1) * 8)) & 0xFF) as u8
    }

    pub fn is_constructed(&self) -> bool {
        self.first_byte() & 0x20 != 0
    }

    pub fn class(&self) -> TagClass {
        match self.first_byte() >> 6 {
            0b00 => TagClass::Universal,
            0b01 => TagClass::Application,
            0b10 => TagClass::ContextSpecific,
            0b11 => TagClass::Private,
            _ => unreachable!(),
        }
    }
}

impl From<u32> for Tag {
    fn from(v: u32) -> Self {
        Tag(v)
    }
}

impl std::fmt::Display for Tag {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for b in self.to_bytes() {
            write!(f, "{:02X}", b)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn single_byte_tag() {
        let (tag, n) = Tag::parse(&[0x4F]).unwrap();
        assert_eq!(tag, Tag(0x4F));
        assert_eq!(n, 1);
        assert_eq!(tag.byte_len(), 1);
        assert_eq!(tag.to_bytes(), vec![0x4F]);
        assert!(!tag.is_constructed());
        assert_eq!(tag.class(), TagClass::Application);
    }

    #[test]
    fn two_byte_tag() {
        let (tag, n) = Tag::parse(&[0x9F, 0x02]).unwrap();
        assert_eq!(tag, Tag(0x9F02));
        assert_eq!(n, 2);
        assert_eq!(tag.to_bytes(), vec![0x9F, 0x02]);
        assert!(!tag.is_constructed());
        assert_eq!(tag.class(), TagClass::ContextSpecific);
    }

    #[test]
    fn constructed_tag() {
        let tag = Tag(0x70);
        assert!(tag.is_constructed());
        assert!(Tag(0x77).is_constructed());
        assert!(Tag(0xA5).is_constructed());
        assert!(!Tag(0x9F02).is_constructed());
    }

    #[test]
    fn three_byte_tag() {
        let (tag, n) = Tag::parse(&[0xBF, 0x81, 0x0C]).unwrap();
        assert_eq!(tag, Tag(0x00BF_810C));
        assert_eq!(n, 3);
        assert_eq!(tag.to_bytes(), vec![0xBF, 0x81, 0x0C]);
        assert!(tag.is_constructed());
    }

    #[test]
    fn tag_too_long() {
        let data = [0x9F, 0x80, 0x80, 0x80, 0x01];
        assert_eq!(Tag::parse(&data), Err(Error::TagTooLong));
    }

    #[test]
    fn tag_truncated() {
        assert_eq!(Tag::parse(&[0x9F]), Err(Error::UnexpectedEof));
        assert_eq!(Tag::parse(&[]), Err(Error::UnexpectedEof));
    }

    #[test]
    fn byte_lex_ordering() {
        assert!(Tag(0x42) < Tag(0x4F));
        assert!(Tag(0x5A) < Tag(0x5F20));
        assert!(Tag(0x5F57) < Tag(0x61));
        assert!(Tag(0x6F) < Tag(0x70));
        assert!(Tag(0x9F4F) < Tag(0xA1));
        assert!(Tag(0xA5) < Tag(0xBF0C));
    }

    #[test]
    fn display_is_uppercase_hex() {
        assert_eq!(format!("{}", Tag(0x4F)), "4F");
        assert_eq!(format!("{}", Tag(0x9F02)), "9F02");
        assert_eq!(format!("{}", Tag(0x5F20)), "5F20");
    }
}
