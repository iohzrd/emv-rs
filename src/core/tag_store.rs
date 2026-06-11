//! Book 3 §5 / §10.2 - Per-transaction tag-keyed value buffer.

use crate::core::error::{Error, Result};
use crate::core::tag::Tag;
use crate::core::tlv::{Tlv, Value};
use std::collections::HashMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Source {
    TerminalGenerated,
    SelectFci,
    Gpo,
    Record { sfi: u8, record: u8 },
    GenerateAc,
    IssuerResponse,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Element {
    pub value: Vec<u8>,
    pub source: Source,
}

#[derive(Debug, Clone, Default)]
pub struct TagStore {
    inner: HashMap<Tag, Element>,
}

impl TagStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert_primitive(&mut self, tag: Tag, value: Vec<u8>, source: Source) -> Result<()> {
        if tag.is_constructed() {
            return Err(Error::InvalidValue);
        }
        if value.is_empty() {
            return Ok(());
        }
        if self.inner.contains_key(&tag) {
            return Err(Error::RedundantPrimitive { tag });
        }
        self.inner.insert(tag, Element { value, source });
        Ok(())
    }

    pub fn insert_tlv(&mut self, tlv: &Tlv, source: Source) -> Result<()> {
        match tlv.value() {
            Value::Primitive(bytes) => self.insert_primitive(tlv.tag(), bytes.clone(), source),
            Value::Constructed(children) => {
                for child in children {
                    self.insert_tlv(child, source)?;
                }
                Ok(())
            }
        }
    }

    pub fn get(&self, tag: Tag) -> Option<&[u8]> {
        self.inner.get(&tag).map(|e| e.value.as_slice())
    }

    pub fn get_with_source(&self, tag: Tag) -> Option<(&[u8], Source)> {
        self.inner.get(&tag).map(|e| (e.value.as_slice(), e.source))
    }

    pub fn contains(&self, tag: Tag) -> bool {
        self.inner.contains_key(&tag)
    }

    pub fn iter(&self) -> impl Iterator<Item = (Tag, &Element)> {
        self.inner.iter().map(|(t, e)| (*t, e))
    }

    pub fn len(&self) -> usize {
        self.inner.len()
    }

    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn primitive(tag: u32, value: &[u8]) -> Tlv {
        Tlv::primitive(Tag(tag), value.to_vec())
    }

    fn constructed(tag: u32, children: Vec<Tlv>) -> Tlv {
        Tlv::constructed(Tag(tag), children)
    }

    // ── insert_primitive ─────────────────────────────────────────────

    #[test]
    fn insert_and_get_round_trip() {
        let mut store = TagStore::new();
        store
            .insert_primitive(Tag(0x5A), vec![0x12, 0x34], Source::SelectFci)
            .unwrap();
        assert_eq!(store.get(Tag(0x5A)), Some(&[0x12, 0x34][..]));
    }

    #[test]
    fn get_unknown_tag_returns_none() {
        let store = TagStore::new();
        assert_eq!(store.get(Tag(0x9F02)), None);
    }

    #[test]
    fn duplicate_primitive_errors_per_book3_section_10_2() {
        let mut store = TagStore::new();
        store
            .insert_primitive(Tag(0x5A), vec![0x12], Source::SelectFci)
            .unwrap();
        let err = store
            .insert_primitive(Tag(0x5A), vec![0x34], Source::Record { sfi: 1, record: 1 })
            .unwrap_err();
        assert_eq!(err, Error::RedundantPrimitive { tag: Tag(0x5A) });
        assert_eq!(store.get(Tag(0x5A)), Some(&[0x12][..]));
    }

    #[test]
    fn empty_value_is_silently_skipped() {
        let mut store = TagStore::new();
        store
            .insert_primitive(Tag(0x5A), vec![], Source::SelectFci)
            .unwrap();
        assert!(!store.contains(Tag(0x5A)));
        assert!(store.is_empty());
    }

    #[test]
    fn empty_value_does_not_block_later_insert() {
        let mut store = TagStore::new();
        store
            .insert_primitive(Tag(0x5A), vec![], Source::SelectFci)
            .unwrap();
        store
            .insert_primitive(Tag(0x5A), vec![0xFF], Source::Record { sfi: 1, record: 1 })
            .unwrap();
        assert_eq!(store.get(Tag(0x5A)), Some(&[0xFF][..]));
    }

    #[test]
    fn constructed_tag_via_insert_primitive_is_rejected() {
        let mut store = TagStore::new();
        let err = store
            .insert_primitive(Tag(0x70), vec![0xAA], Source::Record { sfi: 1, record: 1 })
            .unwrap_err();
        assert_eq!(err, Error::InvalidValue);
    }

    // ── insert_tlv (constructed flattening) ──────────────────────────

    #[test]
    fn insert_tlv_flattens_70_template() {
        let record = constructed(
            0x70,
            vec![
                primitive(0x5A, &[0x12, 0x34]),
                primitive(0x5F24, &[0x25, 0x12, 0x31]),
                primitive(0x5F34, &[0x01]),
            ],
        );
        let mut store = TagStore::new();
        store
            .insert_tlv(&record, Source::Record { sfi: 1, record: 1 })
            .unwrap();
        assert_eq!(store.get(Tag(0x5A)), Some(&[0x12, 0x34][..]));
        assert_eq!(store.get(Tag(0x5F24)), Some(&[0x25, 0x12, 0x31][..]));
        assert_eq!(store.get(Tag(0x5F34)), Some(&[0x01][..]));
        assert!(!store.contains(Tag(0x70)));
        assert_eq!(store.len(), 3);
    }

    #[test]
    fn insert_tlv_recurses_through_nested_templates() {
        let fci = constructed(
            0x6F,
            vec![
                primitive(0x84, b"DFNAME"),
                constructed(
                    0xA5,
                    vec![constructed(
                        0xBF0C,
                        vec![constructed(
                            0x61,
                            vec![
                                primitive(0x50, b"APPLABEL"),
                                primitive(0x4F, &[0xA0, 0x00, 0x00, 0x00, 0x03]),
                            ],
                        )],
                    )],
                ),
            ],
        );
        let mut store = TagStore::new();
        store.insert_tlv(&fci, Source::SelectFci).unwrap();
        assert_eq!(store.get(Tag(0x84)), Some(&b"DFNAME"[..]));
        assert_eq!(store.get(Tag(0x50)), Some(&b"APPLABEL"[..]));
        assert_eq!(
            store.get(Tag(0x4F)),
            Some(&[0xA0, 0x00, 0x00, 0x00, 0x03][..])
        );
        assert!(!store.contains(Tag(0x6F)));
        assert!(!store.contains(Tag(0xA5)));
        assert!(!store.contains(Tag(0xBF0C)));
        assert!(!store.contains(Tag(0x61)));
        assert_eq!(store.len(), 3);
    }

    #[test]
    fn insert_tlv_skips_zero_length_primitives() {
        let record = constructed(
            0x70,
            vec![primitive(0x5A, &[0x12, 0x34]), primitive(0x5F25, &[])],
        );
        let mut store = TagStore::new();
        store
            .insert_tlv(&record, Source::Record { sfi: 1, record: 1 })
            .unwrap();
        assert!(store.contains(Tag(0x5A)));
        assert!(!store.contains(Tag(0x5F25)));
        assert_eq!(store.len(), 1);
    }

    #[test]
    fn insert_tlv_errors_on_duplicate_across_records() {
        let rec1 = constructed(0x70, vec![primitive(0x5A, &[0x12])]);
        let rec2 = constructed(0x70, vec![primitive(0x5A, &[0x34])]);
        let mut store = TagStore::new();
        store
            .insert_tlv(&rec1, Source::Record { sfi: 1, record: 1 })
            .unwrap();
        let err = store
            .insert_tlv(&rec2, Source::Record { sfi: 1, record: 2 })
            .unwrap_err();
        assert_eq!(err, Error::RedundantPrimitive { tag: Tag(0x5A) });
    }

    #[test]
    fn insert_tlv_errors_on_duplicate_within_one_template() {
        let record = constructed(
            0x70,
            vec![primitive(0x5A, &[0x12]), primitive(0x5A, &[0x34])],
        );
        let mut store = TagStore::new();
        let err = store
            .insert_tlv(&record, Source::Record { sfi: 1, record: 1 })
            .unwrap_err();
        assert_eq!(err, Error::RedundantPrimitive { tag: Tag(0x5A) });
        assert_eq!(store.get(Tag(0x5A)), Some(&[0x12][..]));
    }

    // ── Source attribution ───────────────────────────────────────────

    #[test]
    fn source_is_preserved() {
        let mut store = TagStore::new();
        store
            .insert_primitive(Tag(0x5A), vec![0x12], Source::SelectFci)
            .unwrap();
        store
            .insert_primitive(Tag(0x82), vec![0x39, 0x00], Source::Gpo)
            .unwrap();
        store
            .insert_primitive(
                Tag(0x9F37),
                vec![0xDE, 0xAD, 0xBE, 0xEF],
                Source::TerminalGenerated,
            )
            .unwrap();

        let (_, src) = store.get_with_source(Tag(0x5A)).unwrap();
        assert_eq!(src, Source::SelectFci);
        let (_, src) = store.get_with_source(Tag(0x82)).unwrap();
        assert_eq!(src, Source::Gpo);
        let (_, src) = store.get_with_source(Tag(0x9F37)).unwrap();
        assert_eq!(src, Source::TerminalGenerated);
    }

    #[test]
    fn source_propagates_through_insert_tlv() {
        let record = constructed(
            0x70,
            vec![
                primitive(0x5A, &[0x12]),
                primitive(0x5F24, &[0x25, 0x01, 0x01]),
            ],
        );
        let src = Source::Record { sfi: 2, record: 3 };
        let mut store = TagStore::new();
        store.insert_tlv(&record, src).unwrap();
        let (_, s) = store.get_with_source(Tag(0x5A)).unwrap();
        assert_eq!(s, src);
        let (_, s) = store.get_with_source(Tag(0x5F24)).unwrap();
        assert_eq!(s, src);
    }

    // ── Misc ─────────────────────────────────────────────────────────

    #[test]
    fn iter_returns_all_entries() {
        let mut store = TagStore::new();
        store
            .insert_primitive(Tag(0x5A), vec![0x01], Source::SelectFci)
            .unwrap();
        store
            .insert_primitive(Tag(0x82), vec![0x02], Source::Gpo)
            .unwrap();
        let mut tags: Vec<Tag> = store.iter().map(|(t, _)| t).collect();
        tags.sort();
        assert_eq!(tags, vec![Tag(0x5A), Tag(0x82)]);
    }

    #[test]
    fn len_and_is_empty() {
        let mut store = TagStore::new();
        assert!(store.is_empty());
        assert_eq!(store.len(), 0);
        store
            .insert_primitive(Tag(0x5A), vec![0x01], Source::SelectFci)
            .unwrap();
        assert!(!store.is_empty());
        assert_eq!(store.len(), 1);
    }

    #[test]
    fn default_is_empty() {
        let store: TagStore = Default::default();
        assert!(store.is_empty());
    }
}
