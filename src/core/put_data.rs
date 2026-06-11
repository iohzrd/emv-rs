//! Book C-2 v2.11 §5.7 - PUT DATA (Tables 5.22 / 5.23).

use crate::core::apdu::{Cla, Command, Ins};
use crate::core::error::{Error, Result};
use crate::core::tag::Tag;

pub fn command(tag: Tag, data: &[u8]) -> Result<Command> {
    let (p1, p2) = match tag.byte_len() {
        1 => (0x00, tag.0 as u8),
        2 => (((tag.0 >> 8) & 0xFF) as u8, (tag.0 & 0xFF) as u8),
        _ => return Err(Error::InvalidValue),
    };
    if data.len() > 0xFF {
        return Err(Error::LengthTooLong);
    }
    Ok(Command {
        cla: Cla(0x80),
        ins: Ins::PUT_DATA,
        p1,
        p2,
        data: data.to_vec(),
        le: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::tags;

    #[test]
    fn put_data_two_byte_tag_wire_bytes() {
        let cmd = command(tags::UNPROTECTED_DATA_ENVELOPE_1, &[0xAB, 0xCD]).unwrap();
        assert_eq!(cmd.cla.0, 0x80);
        assert_eq!(cmd.ins, Ins::PUT_DATA);
        assert_eq!(cmd.p1, 0x9F);
        assert_eq!(cmd.p2, 0x75);
        assert_eq!(cmd.data, vec![0xAB, 0xCD]);
        assert_eq!(cmd.le, None);
        assert_eq!(
            cmd.to_bytes().unwrap(),
            vec![0x80, 0xDA, 0x9F, 0x75, 0x02, 0xAB, 0xCD],
        );
    }

    #[test]
    fn put_data_one_byte_tag_is_zero_padded() {
        let cmd = command(tags::TRANSACTION_TYPE, &[0x00]).unwrap();
        assert_eq!(cmd.p1, 0x00);
        assert_eq!(cmd.p2, 0x9C);
        assert_eq!(
            cmd.to_bytes().unwrap(),
            vec![0x80, 0xDA, 0x00, 0x9C, 0x01, 0x00],
        );
    }

    #[test]
    fn put_data_k2_minimum_supported_tags() {
        for &(tag, p1, p2) in &[
            (tags::UNPROTECTED_DATA_ENVELOPE_1, 0x9F, 0x75),
            (tags::UNPROTECTED_DATA_ENVELOPE_2, 0x9F, 0x76),
            (tags::UNPROTECTED_DATA_ENVELOPE_3, 0x9F, 0x77),
            (tags::UNPROTECTED_DATA_ENVELOPE_4, 0x9F, 0x78),
            (tags::UNPROTECTED_DATA_ENVELOPE_5, 0x9F, 0x79),
        ] {
            let cmd = command(tag, &[0x01]).unwrap();
            assert_eq!((cmd.p1, cmd.p2), (p1, p2), "tag {:?}", tag);
        }
    }

    #[test]
    fn put_data_rejects_oversized_payload() {
        let big = vec![0u8; 0x100];
        assert_eq!(
            command(tags::UNPROTECTED_DATA_ENVELOPE_1, &big),
            Err(Error::LengthTooLong),
        );
    }

    #[test]
    fn put_data_rejects_three_byte_tag() {
        assert_eq!(command(tags::KERNEL_ID, &[0x02]), Err(Error::InvalidValue),);
    }
}
