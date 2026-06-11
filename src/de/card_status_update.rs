//! Card Status Update - Book 3 Annex C10, Table CCD 11.

use crate::core::error::{Error, Result};

const BYTE_1_RFU_MASK: u8 = 0b0111_0000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum UpdateCounters {
    /// 0 0
    #[default]
    DoNotUpdateOfflineCounters,
    /// 0 1
    SetOfflineCountersToUpperOfflineLimits,
    /// 1 0
    ResetOfflineCountersToZero,
    /// 1 1
    AddTransactionToOfflineCounter,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct CardStatusUpdate {
    // Byte 1
    pub proprietary_authentication_data_included: bool,
    pub rfu_byte_1: u8,
    /// b4–b1
    pub pin_try_counter: u8,

    // Byte 2
    pub issuer_approves_online_transaction: bool,
    pub card_block: bool,
    pub application_block: bool,
    pub update_pin_try_counter: bool,
    pub set_go_online_on_next_transaction: bool,
    pub csu_created_by_proxy_for_the_issuer: bool,
    pub update_counters: UpdateCounters,

    // Byte 3 - all bits RFU.
    pub rfu_byte_3: u8,

    // Byte 4
    pub issuer_discretionary: u8,
}

impl CardStatusUpdate {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn parse(data: &[u8]) -> Result<Self> {
        if data.len() != 4 {
            return Err(Error::WrongLength {
                expected: 4,
                got: data.len(),
            });
        }
        let b1 = data[0];
        let b2 = data[1];
        let b3 = data[2];
        let b4 = data[3];

        let update_counters = match b2 & 0b0000_0011 {
            0b00 => UpdateCounters::DoNotUpdateOfflineCounters,
            0b01 => UpdateCounters::SetOfflineCountersToUpperOfflineLimits,
            0b10 => UpdateCounters::ResetOfflineCountersToZero,
            0b11 => UpdateCounters::AddTransactionToOfflineCounter,
            _ => unreachable!(),
        };

        Ok(CardStatusUpdate {
            proprietary_authentication_data_included: b1 & 0b1000_0000 != 0,
            rfu_byte_1: b1 & BYTE_1_RFU_MASK,
            pin_try_counter: b1 & 0x0F,

            issuer_approves_online_transaction: b2 & 0b1000_0000 != 0,
            card_block: b2 & 0b0100_0000 != 0,
            application_block: b2 & 0b0010_0000 != 0,
            update_pin_try_counter: b2 & 0b0001_0000 != 0,
            set_go_online_on_next_transaction: b2 & 0b0000_1000 != 0,
            csu_created_by_proxy_for_the_issuer: b2 & 0b0000_0100 != 0,
            update_counters,

            rfu_byte_3: b3,

            issuer_discretionary: b4,
        })
    }

    pub fn to_bytes(&self) -> [u8; 4] {
        let b1 = (self.proprietary_authentication_data_included as u8) << 7
            | (self.rfu_byte_1 & BYTE_1_RFU_MASK)
            | (self.pin_try_counter & 0x0F);

        let update_counters_bits: u8 = match self.update_counters {
            UpdateCounters::DoNotUpdateOfflineCounters => 0b00,
            UpdateCounters::SetOfflineCountersToUpperOfflineLimits => 0b01,
            UpdateCounters::ResetOfflineCountersToZero => 0b10,
            UpdateCounters::AddTransactionToOfflineCounter => 0b11,
        };

        let b2 = (self.issuer_approves_online_transaction as u8) << 7
            | (self.card_block as u8) << 6
            | (self.application_block as u8) << 5
            | (self.update_pin_try_counter as u8) << 4
            | (self.set_go_online_on_next_transaction as u8) << 3
            | (self.csu_created_by_proxy_for_the_issuer as u8) << 2
            | update_counters_bits;

        let b3 = self.rfu_byte_3;

        let b4 = self.issuer_discretionary;

        [b1, b2, b3, b4]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn struct_literal_construction() {
        let c = CardStatusUpdate {
            proprietary_authentication_data_included: true,
            pin_try_counter: 3,
            issuer_approves_online_transaction: true,
            update_pin_try_counter: true,
            update_counters: UpdateCounters::ResetOfflineCountersToZero,
            ..Default::default()
        };
        assert_eq!(c.to_bytes(), [0x83, 0b1001_0010, 0x00, 0x00]);
    }

    #[test]
    fn roundtrip_preserves_rfu() {
        let bytes = [0xFFu8, 0xFF, 0xFF, 0xFF];
        let c = CardStatusUpdate::parse(&bytes).unwrap();
        assert_eq!(c.rfu_byte_1, BYTE_1_RFU_MASK);
        assert_eq!(c.rfu_byte_3, 0xFF);
        assert_eq!(c.to_bytes(), bytes);
    }

    #[test]
    fn roundtrip_exhaustive() {
        for bytes in [
            [0x00u8, 0x00, 0x00, 0x00],
            [0xFF, 0xFF, 0xFF, 0xFF],
            [0x83, 0x91, 0x00, 0x42],
            [0x70, 0x00, 0xAB, 0xCD],
            [0x8F, 0xFC, 0x55, 0x00],
        ] {
            let c = CardStatusUpdate::parse(&bytes).unwrap();
            assert_eq!(c.to_bytes(), bytes);
        }
    }

    #[test]
    fn parse_wrong_length() {
        assert_eq!(
            CardStatusUpdate::parse(&[]),
            Err(Error::WrongLength {
                expected: 4,
                got: 0
            })
        );
        assert_eq!(
            CardStatusUpdate::parse(&[0; 3]),
            Err(Error::WrongLength {
                expected: 4,
                got: 3
            })
        );
        assert_eq!(
            CardStatusUpdate::parse(&[0; 5]),
            Err(Error::WrongLength {
                expected: 4,
                got: 5
            })
        );
    }

    #[test]
    fn byte1_proprietary_auth_data_included() {
        assert!(
            CardStatusUpdate::parse(&[0b1000_0000, 0, 0, 0])
                .unwrap()
                .proprietary_authentication_data_included
        );
        assert!(
            !CardStatusUpdate::parse(&[0b0000_0000, 0, 0, 0])
                .unwrap()
                .proprietary_authentication_data_included
        );
    }

    #[test]
    fn byte1_pin_try_counter() {
        assert_eq!(
            CardStatusUpdate::parse(&[0x03, 0, 0, 0])
                .unwrap()
                .pin_try_counter,
            3
        );
        assert_eq!(
            CardStatusUpdate::parse(&[0x8F, 0, 0, 0])
                .unwrap()
                .pin_try_counter,
            0x0F
        );
        assert_eq!(
            CardStatusUpdate::parse(&[0x80, 0, 0, 0])
                .unwrap()
                .pin_try_counter,
            0
        );
    }

    #[test]
    fn byte2_single_bit_flags() {
        assert!(
            CardStatusUpdate::parse(&[0, 0b1000_0000, 0, 0])
                .unwrap()
                .issuer_approves_online_transaction
        );
        assert!(
            CardStatusUpdate::parse(&[0, 0b0100_0000, 0, 0])
                .unwrap()
                .card_block
        );
        assert!(
            CardStatusUpdate::parse(&[0, 0b0010_0000, 0, 0])
                .unwrap()
                .application_block
        );
        assert!(
            CardStatusUpdate::parse(&[0, 0b0001_0000, 0, 0])
                .unwrap()
                .update_pin_try_counter
        );
        assert!(
            CardStatusUpdate::parse(&[0, 0b0000_1000, 0, 0])
                .unwrap()
                .set_go_online_on_next_transaction
        );
        assert!(
            CardStatusUpdate::parse(&[0, 0b0000_0100, 0, 0])
                .unwrap()
                .csu_created_by_proxy_for_the_issuer
        );
    }

    #[test]
    fn byte2_update_counters() {
        assert_eq!(
            CardStatusUpdate::parse(&[0, 0b0000_0000, 0, 0])
                .unwrap()
                .update_counters,
            UpdateCounters::DoNotUpdateOfflineCounters
        );
        assert_eq!(
            CardStatusUpdate::parse(&[0, 0b0000_0001, 0, 0])
                .unwrap()
                .update_counters,
            UpdateCounters::SetOfflineCountersToUpperOfflineLimits
        );
        assert_eq!(
            CardStatusUpdate::parse(&[0, 0b0000_0010, 0, 0])
                .unwrap()
                .update_counters,
            UpdateCounters::ResetOfflineCountersToZero
        );
        assert_eq!(
            CardStatusUpdate::parse(&[0, 0b0000_0011, 0, 0])
                .unwrap()
                .update_counters,
            UpdateCounters::AddTransactionToOfflineCounter
        );
    }

    #[test]
    fn byte4_issuer_discretionary() {
        assert_eq!(
            CardStatusUpdate::parse(&[0, 0, 0, 0xAB])
                .unwrap()
                .issuer_discretionary,
            0xAB
        );
        assert_eq!(
            CardStatusUpdate::parse(&[0, 0, 0, 0x00])
                .unwrap()
                .issuer_discretionary,
            0x00
        );
    }

    #[test]
    fn combined_example() {
        let c = CardStatusUpdate::parse(&[0x83, 0b1001_0010, 0x00, 0x00]).unwrap();
        assert!(c.proprietary_authentication_data_included);
        assert_eq!(c.pin_try_counter, 3);
        assert!(c.issuer_approves_online_transaction);
        assert!(c.update_pin_try_counter);
        assert_eq!(
            c.update_counters,
            UpdateCounters::ResetOfflineCountersToZero
        );
    }
}
