//! Book B v2.11 Annex C.1 - SEND POI INFORMATION (SPI) command APDU.

use crate::core::apdu::{Cla, Command, Ins};
use crate::core::tlv::encode_length;

const SPI_COMMAND_TEMPLATE_TAG: u8 = 0x83;

pub fn spi_command(template_data: &[u8]) -> Command {
    let mut data = Vec::with_capacity(template_data.len() + 5);
    data.push(SPI_COMMAND_TEMPLATE_TAG);
    data.extend(encode_length(template_data.len()));
    data.extend_from_slice(template_data);
    Command {
        cla: Cla(0x80),
        ins: Ins(0x1A),
        p1: 0x00,
        p2: 0x00,
        data,
        le: Some(0x00),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_template_wraps_zero_length_83() {
        let cmd = spi_command(&[]);
        assert_eq!(cmd.cla.0, 0x80);
        assert_eq!(cmd.ins.0, 0x1A);
        assert_eq!(cmd.p1, 0x00);
        assert_eq!(cmd.p2, 0x00);
        assert_eq!(cmd.le, Some(0x00));
        assert_eq!(cmd.data, vec![0x83, 0x00]);
    }

    #[test]
    fn short_template_uses_short_form_length() {
        let body = [0x00, 0x01, 0x02, 0xAA, 0xBB];
        let cmd = spi_command(&body);
        let mut expected = vec![0x83, 0x05];
        expected.extend_from_slice(&body);
        assert_eq!(cmd.data, expected);
    }

    #[test]
    fn long_template_uses_long_form_length() {
        let body = vec![0xAB; 200];
        let cmd = spi_command(&body);
        // 200 > 0x7F → long form: 0x81 0xC8.
        assert_eq!(&cmd.data[..3], &[0x83, 0x81, 0xC8]);
        assert_eq!(&cmd.data[3..], &body[..]);
    }

    #[test]
    fn full_apdu_encoding() {
        let cmd = spi_command(&[0x00, 0x01, 0x02, 0x00, 0x01]);
        let bytes = cmd.to_bytes().unwrap();
        // CLA INS P1 P2 Lc Data... Le
        assert_eq!(
            bytes,
            vec![
                0x80, 0x1A, 0x00, 0x00, 0x07, 0x83, 0x05, 0x00, 0x01, 0x02, 0x00, 0x01, 0x00
            ],
        );
    }
}
