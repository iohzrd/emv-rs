//! Biometric Terminal Capabilities (tag 9F30) - Book 4 Annex A7, Tables 36–38.

use crate::core::error::{Error, Result};

const BYTE_1_RFU_MASK: u8 = 0b0000_0111;
const BYTE_2_RFU_MASK: u8 = 0b0000_0111;
const BYTE_3_RFU_MASK: u8 = 0xFF;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct BiometricTerminalCapabilities {
    // Byte 1 - Offline Biometric Capabilities (Table 36)
    pub facial_biometric_for_offline_verification: bool,
    pub finger_biometric_for_offline_verification: bool,
    pub iris_biometric_for_offline_verification: bool,
    pub palm_biometric_for_offline_verification: bool,
    pub voice_biometric_for_offline_verification: bool,
    pub rfu_byte_1: u8,

    // Byte 2 - Online Biometric Capabilities (Table 37)
    pub facial_biometric_for_online_verification: bool,
    pub finger_biometric_for_online_verification: bool,
    pub iris_biometric_for_online_verification: bool,
    pub palm_biometric_for_online_verification: bool,
    pub voice_biometric_for_online_verification: bool,
    pub rfu_byte_2: u8,

    // Byte 3 - RFU (Table 38)
    pub rfu_byte_3: u8,
}

impl BiometricTerminalCapabilities {
    pub fn parse(data: &[u8]) -> Result<Self> {
        if data.len() != 3 {
            return Err(Error::WrongLength {
                expected: 3,
                got: data.len(),
            });
        }
        let b1 = data[0];
        let b2 = data[1];
        let b3 = data[2];
        Ok(BiometricTerminalCapabilities {
            facial_biometric_for_offline_verification: b1 & 0b1000_0000 != 0,
            finger_biometric_for_offline_verification: b1 & 0b0100_0000 != 0,
            iris_biometric_for_offline_verification: b1 & 0b0010_0000 != 0,
            palm_biometric_for_offline_verification: b1 & 0b0001_0000 != 0,
            voice_biometric_for_offline_verification: b1 & 0b0000_1000 != 0,
            rfu_byte_1: b1 & BYTE_1_RFU_MASK,

            facial_biometric_for_online_verification: b2 & 0b1000_0000 != 0,
            finger_biometric_for_online_verification: b2 & 0b0100_0000 != 0,
            iris_biometric_for_online_verification: b2 & 0b0010_0000 != 0,
            palm_biometric_for_online_verification: b2 & 0b0001_0000 != 0,
            voice_biometric_for_online_verification: b2 & 0b0000_1000 != 0,
            rfu_byte_2: b2 & BYTE_2_RFU_MASK,

            rfu_byte_3: b3 & BYTE_3_RFU_MASK,
        })
    }

    pub fn to_bytes(&self) -> [u8; 3] {
        let b1 = (self.facial_biometric_for_offline_verification as u8) << 7
            | (self.finger_biometric_for_offline_verification as u8) << 6
            | (self.iris_biometric_for_offline_verification as u8) << 5
            | (self.palm_biometric_for_offline_verification as u8) << 4
            | (self.voice_biometric_for_offline_verification as u8) << 3
            | (self.rfu_byte_1 & BYTE_1_RFU_MASK);

        let b2 = (self.facial_biometric_for_online_verification as u8) << 7
            | (self.finger_biometric_for_online_verification as u8) << 6
            | (self.iris_biometric_for_online_verification as u8) << 5
            | (self.palm_biometric_for_online_verification as u8) << 4
            | (self.voice_biometric_for_online_verification as u8) << 3
            | (self.rfu_byte_2 & BYTE_2_RFU_MASK);

        let b3 = self.rfu_byte_3 & BYTE_3_RFU_MASK;

        [b1, b2, b3]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn struct_literal_construction() {
        let c = BiometricTerminalCapabilities {
            facial_biometric_for_offline_verification: true,
            iris_biometric_for_offline_verification: true,
            finger_biometric_for_online_verification: true,
            voice_biometric_for_online_verification: true,
            ..Default::default()
        };
        assert_eq!(c.to_bytes(), [0b1010_0000, 0b0100_1000, 0x00]);
    }

    #[test]
    fn roundtrip_preserves_rfu() {
        let bytes = [0xFFu8, 0xFF, 0xFF];
        let c = BiometricTerminalCapabilities::parse(&bytes).unwrap();
        assert_eq!(c.rfu_byte_1, BYTE_1_RFU_MASK);
        assert_eq!(c.rfu_byte_2, BYTE_2_RFU_MASK);
        assert_eq!(c.rfu_byte_3, BYTE_3_RFU_MASK);
        assert_eq!(c.to_bytes(), bytes);
    }

    #[test]
    fn roundtrip_exhaustive() {
        for bytes in [
            [0x00u8, 0x00, 0x00],
            [0xF8, 0xF8, 0x00],
            [0x80, 0x80, 0x00],
            [0x48, 0x20, 0x00],
            [0xFF, 0xFF, 0xFF],
            [0x07, 0x07, 0xFF],
        ] {
            let c = BiometricTerminalCapabilities::parse(&bytes).unwrap();
            assert_eq!(c.to_bytes(), bytes);
        }
    }

    #[test]
    fn parse_wrong_length() {
        assert_eq!(
            BiometricTerminalCapabilities::parse(&[]),
            Err(Error::WrongLength {
                expected: 3,
                got: 0
            })
        );
        assert_eq!(
            BiometricTerminalCapabilities::parse(&[0, 0]),
            Err(Error::WrongLength {
                expected: 3,
                got: 2
            })
        );
        assert_eq!(
            BiometricTerminalCapabilities::parse(&[0, 0, 0, 0]),
            Err(Error::WrongLength {
                expected: 3,
                got: 4
            })
        );
    }
}
