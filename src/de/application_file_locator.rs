//! Application File Locator (tag 94) - Book 3 §10.2.

use crate::core::error::{Error, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ApplicationFileLocatorEntry {
    pub sfi: u8,
    pub first_record: u8,
    pub last_record: u8,
    pub oda_record_count: u8,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApplicationFileLocator(pub Vec<ApplicationFileLocatorEntry>);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReadStep {
    pub sfi: u8,
    pub record_number: u8,
    pub in_oda: bool,
}

impl ApplicationFileLocatorEntry {
    pub fn parse(data: &[u8; 4]) -> Result<Self> {
        // Book 3 §10.2 - byte 1 low 3 bits RFU = 0.
        if data[0] & 0b0000_0111 != 0 {
            return Err(Error::InvalidValue);
        }
        let sfi = data[0] >> 3;
        let first_record = data[1];
        let last_record = data[2];
        let oda_record_count = data[3];

        // Book 3 §7.5 / Book 1 §10.2.2 - SFI in 1..=30.
        if sfi == 0 || sfi == 31 {
            return Err(Error::InvalidValue);
        }
        if first_record == 0 {
            return Err(Error::InvalidValue);
        }
        if first_record > last_record {
            return Err(Error::InvalidValue);
        }
        if oda_record_count > last_record - first_record + 1 {
            return Err(Error::InvalidValue);
        }
        Ok(ApplicationFileLocatorEntry {
            sfi,
            first_record,
            last_record,
            oda_record_count,
        })
    }

    pub fn to_bytes(&self) -> [u8; 4] {
        [
            self.sfi << 3,
            self.first_record,
            self.last_record,
            self.oda_record_count,
        ]
    }
}

impl ApplicationFileLocator {
    pub fn parse(data: &[u8]) -> Result<Self> {
        // Book 3 §7.5 - empty AFL is a format error.
        if data.is_empty() {
            return Err(Error::InvalidValue);
        }
        if data.len() % 4 != 0 {
            return Err(Error::InvalidValue);
        }
        let mut entries = Vec::with_capacity(data.len() / 4);
        for chunk in data.chunks_exact(4) {
            let arr: [u8; 4] = [chunk[0], chunk[1], chunk[2], chunk[3]];
            entries.push(ApplicationFileLocatorEntry::parse(&arr)?);
        }
        Ok(ApplicationFileLocator(entries))
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.0.len() * 4);
        for e in &self.0 {
            out.extend_from_slice(&e.to_bytes());
        }
        out
    }

    pub fn iter_reads(&self) -> impl Iterator<Item = ReadStep> + '_ {
        self.0.iter().flat_map(|entry| {
            let sfi = entry.sfi;
            let first = entry.first_record;
            let last = entry.last_record;
            let oda_end = first.saturating_add(entry.oda_record_count);
            (first..=last).map(move |record_number| ReadStep {
                sfi,
                record_number,
                in_oda: record_number < oda_end,
            })
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn single_entry_roundtrip() {
        let wire = [0x08, 0x01, 0x01, 0x01];
        let afl = ApplicationFileLocator::parse(&wire).unwrap();
        assert_eq!(afl.0.len(), 1);
        assert_eq!(afl.0[0].sfi, 1);
        assert_eq!(afl.0[0].first_record, 1);
        assert_eq!(afl.0[0].last_record, 1);
        assert_eq!(afl.0[0].oda_record_count, 1);
        assert_eq!(afl.to_bytes(), wire);
    }

    #[test]
    fn multi_entry_roundtrip() {
        let wire = [
            0x08, 0x01, 0x03, 0x02, 0x10, 0x01, 0x01, 0x00, 0x18, 0x04, 0x05, 0x00,
        ];
        let afl = ApplicationFileLocator::parse(&wire).unwrap();
        assert_eq!(afl.0.len(), 3);
        assert_eq!(afl.0[0].sfi, 1);
        assert_eq!(afl.0[0].first_record, 1);
        assert_eq!(afl.0[0].last_record, 3);
        assert_eq!(afl.0[0].oda_record_count, 2);
        assert_eq!(afl.0[1].sfi, 2);
        assert_eq!(afl.0[2].sfi, 3);
        assert_eq!(afl.0[2].first_record, 4);
        assert_eq!(afl.0[2].last_record, 5);
        assert_eq!(afl.0[2].oda_record_count, 0);
        assert_eq!(afl.to_bytes(), wire);
    }

    #[test]
    fn max_sfi() {
        let wire = [0xF0, 0x01, 0x01, 0x00];
        let afl = ApplicationFileLocator::parse(&wire).unwrap();
        assert_eq!(afl.0[0].sfi, 30);
        assert_eq!(afl.to_bytes(), wire);
    }

    #[test]
    fn sfi_zero_rejected() {
        assert_eq!(
            ApplicationFileLocator::parse(&[0x00, 0x01, 0x01, 0x00]),
            Err(Error::InvalidValue),
        );
    }

    #[test]
    fn sfi_thirty_one_rejected() {
        assert_eq!(
            ApplicationFileLocator::parse(&[0xF8, 0x01, 0x01, 0x00]),
            Err(Error::InvalidValue),
        );
    }

    #[test]
    fn parse_wrong_length() {
        assert_eq!(
            ApplicationFileLocator::parse(&[0x08, 0x01, 0x01]),
            Err(Error::InvalidValue)
        );
        assert_eq!(
            ApplicationFileLocator::parse(&[0x08, 0x01, 0x01, 0x00, 0x10]),
            Err(Error::InvalidValue),
        );
    }

    #[test]
    fn invalid_low_three_bits() {
        assert_eq!(
            ApplicationFileLocator::parse(&[0x09, 0x01, 0x01, 0x00]),
            Err(Error::InvalidValue),
        );
        assert_eq!(
            ApplicationFileLocator::parse(&[0x0F, 0x01, 0x01, 0x00]),
            Err(Error::InvalidValue),
        );
    }

    #[test]
    fn first_greater_than_last_rejected() {
        assert_eq!(
            ApplicationFileLocator::parse(&[0x08, 0x05, 0x02, 0x00]),
            Err(Error::InvalidValue),
        );
    }

    #[test]
    fn first_record_zero_rejected() {
        assert_eq!(
            ApplicationFileLocator::parse(&[0x08, 0x00, 0x00, 0x00]),
            Err(Error::InvalidValue),
        );
    }

    #[test]
    fn oda_count_out_of_range_rejected() {
        assert_eq!(
            ApplicationFileLocator::parse(&[0x08, 0x01, 0x02, 0x03]),
            Err(Error::InvalidValue),
        );
    }

    #[test]
    fn empty_afl_rejected() {
        assert_eq!(ApplicationFileLocator::parse(&[]), Err(Error::InvalidValue),);
    }

    #[test]
    fn iter_reads_single_entry_no_oda() {
        let afl = ApplicationFileLocator::parse(&[0x08, 0x01, 0x03, 0x00]).unwrap();
        let steps: Vec<_> = afl.iter_reads().collect();
        assert_eq!(steps.len(), 3);
        assert_eq!(
            steps,
            vec![
                ReadStep {
                    sfi: 1,
                    record_number: 1,
                    in_oda: false
                },
                ReadStep {
                    sfi: 1,
                    record_number: 2,
                    in_oda: false
                },
                ReadStep {
                    sfi: 1,
                    record_number: 3,
                    in_oda: false
                },
            ]
        );
    }

    #[test]
    fn iter_reads_single_entry_partial_oda() {
        let afl = ApplicationFileLocator::parse(&[0x10, 0x01, 0x03, 0x02]).unwrap();
        let steps: Vec<_> = afl.iter_reads().collect();
        assert_eq!(
            steps,
            vec![
                ReadStep {
                    sfi: 2,
                    record_number: 1,
                    in_oda: true
                },
                ReadStep {
                    sfi: 2,
                    record_number: 2,
                    in_oda: true
                },
                ReadStep {
                    sfi: 2,
                    record_number: 3,
                    in_oda: false
                },
            ]
        );
    }

    #[test]
    fn iter_reads_single_entry_all_oda() {
        let afl = ApplicationFileLocator::parse(&[0x18, 0x04, 0x05, 0x02]).unwrap();
        let steps: Vec<_> = afl.iter_reads().collect();
        assert_eq!(
            steps,
            vec![
                ReadStep {
                    sfi: 3,
                    record_number: 4,
                    in_oda: true
                },
                ReadStep {
                    sfi: 3,
                    record_number: 5,
                    in_oda: true
                },
            ]
        );
    }

    #[test]
    fn iter_reads_multi_entry_left_to_right() {
        let wire = [0x08, 0x01, 0x02, 0x01, 0x10, 0x01, 0x01, 0x00];
        let afl = ApplicationFileLocator::parse(&wire).unwrap();
        let steps: Vec<_> = afl.iter_reads().collect();
        assert_eq!(
            steps,
            vec![
                ReadStep {
                    sfi: 1,
                    record_number: 1,
                    in_oda: true
                },
                ReadStep {
                    sfi: 1,
                    record_number: 2,
                    in_oda: false
                },
                ReadStep {
                    sfi: 2,
                    record_number: 1,
                    in_oda: false
                },
            ]
        );
    }

    #[test]
    fn iter_reads_constructed_empty_yields_nothing() {
        let afl = ApplicationFileLocator(Vec::new());
        assert_eq!(afl.iter_reads().count(), 0);
    }

    #[test]
    fn iter_reads_single_record_in_oda() {
        let afl = ApplicationFileLocator::parse(&[0x08, 0x05, 0x05, 0x01]).unwrap();
        let steps: Vec<_> = afl.iter_reads().collect();
        assert_eq!(
            steps,
            vec![ReadStep {
                sfi: 1,
                record_number: 5,
                in_oda: true
            }],
        );
    }
}
