//! Book 3 §6.5.7 - GET DATA.

use crate::core::apdu::{Cla, Command, Ins};
use crate::core::error::{Error, Result};
use crate::core::tag::Tag;
use crate::core::tags;

const PERMITTED: &[Tag] = &[
    tags::APPLICATION_TRANSACTION_COUNTER,
    tags::LAST_ONLINE_ATC_REGISTER,
    tags::PIN_TRY_COUNTER,
    tags::LOG_FORMAT,
    tags::BIOMETRIC_TRY_COUNTERS_TEMPLATE,
    tags::PREFERRED_ATTEMPTS_TEMPLATE,
];

pub fn command(tag: Tag) -> Result<Command> {
    if !PERMITTED.contains(&tag) {
        return Err(Error::InvalidValue);
    }
    let p1 = ((tag.0 >> 8) & 0xFF) as u8;
    let p2 = (tag.0 & 0xFF) as u8;
    Ok(Command {
        cla: Cla(0x80),
        ins: Ins::GET_DATA,
        p1,
        p2,
        data: Vec::new(),
        le: Some(0x00),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn get_data_atc_wire_bytes() {
        let c = command(tags::APPLICATION_TRANSACTION_COUNTER).unwrap();
        assert_eq!(c.cla.0, 0x80);
        assert_eq!(c.ins, Ins::GET_DATA);
        assert_eq!(c.p1, 0x9F);
        assert_eq!(c.p2, 0x36);
        assert!(c.data.is_empty());
        assert_eq!(c.le, Some(0x00));
        assert_eq!(c.to_bytes().unwrap(), vec![0x80, 0xCA, 0x9F, 0x36, 0x00]);
    }

    #[test]
    fn get_data_all_permitted_tags() {
        for &(tag, p1, p2) in &[
            (tags::APPLICATION_TRANSACTION_COUNTER, 0x9F, 0x36),
            (tags::LAST_ONLINE_ATC_REGISTER, 0x9F, 0x13),
            (tags::PIN_TRY_COUNTER, 0x9F, 0x17),
            (tags::LOG_FORMAT, 0x9F, 0x4F),
            (tags::BIOMETRIC_TRY_COUNTERS_TEMPLATE, 0xBF, 0x4C),
            (tags::PREFERRED_ATTEMPTS_TEMPLATE, 0xBF, 0x4D),
        ] {
            let c = command(tag).unwrap();
            assert_eq!((c.p1, c.p2), (p1, p2), "tag {:?}", tag);
        }
    }

    #[test]
    fn get_data_rejects_other_tag() {
        assert_eq!(
            command(tags::APPLICATION_PRIMARY_ACCOUNT_NUMBER),
            Err(Error::InvalidValue),
        );
        assert_eq!(
            command(tags::APPLICATION_INTERCHANGE_PROFILE),
            Err(Error::InvalidValue),
        );
    }
}
