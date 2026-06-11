//! Book C-3 v2.11 Annex D.4 - EXTENDED GET PROCESSING OPTIONS (EGPO).

use crate::core::apdu::{Cla, Command, Ins};
use crate::core::error::{Error, Result};
use crate::core::tlv::encode_length;

/// Annex D.4.1/2 + Figure D-1 - EGPO command. Data field = PDOL related
/// data (Command Template '83' Length Value) || IDS Record Update
/// Template ('BF60' Length Value). The kernel is *not* required to
/// validate the IDS Record Update Template content (§7.2 + Annex D.4.2),
/// so the BF60 value is appended verbatim - its inner TLV (DFx0…DFx4)
/// is the IDS Operator Application's responsibility.
pub fn command(pdol_data: &[u8], ids_record_update_template_value: &[u8]) -> Result<Command> {
    let mut data = Vec::new();
    data.push(0x83);
    data.extend(encode_length(pdol_data.len()));
    data.extend_from_slice(pdol_data);

    // BF60 header (BER-TLV two-byte tag) + length + value, written without
    // the high-level TLV builder so the constructed-bit check on tag BF60
    // is not a constraint on this opaque payload.
    data.push(0xBF);
    data.push(0x60);
    data.extend(encode_length(ids_record_update_template_value.len()));
    data.extend_from_slice(ids_record_update_template_value);

    if data.len() > 0xFF {
        return Err(Error::LengthTooLong);
    }
    Ok(Command {
        cla: Cla(0x80),
        ins: Ins::EXTENDED_GET_PROCESSING_OPTIONS,
        p1: 0x00,
        p2: 0x00,
        data,
        le: Some(0x00),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn egpo_wraps_pdol_and_bf60_template() {
        // PDOL 'AA BB' + IDS Record Update Template value 'CC DD EE'.
        let cmd = command(&[0xAA, 0xBB], &[0xCC, 0xDD, 0xEE]).unwrap();
        // Data: 83 02 AA BB | BF 60 03 CC DD EE = 10 bytes.
        // APDU: 80 E0 00 00 0A | <data> | 00.
        assert_eq!(
            cmd.to_bytes().unwrap(),
            vec![
                0x80, 0xE0, 0x00, 0x00, 0x0A, 0x83, 0x02, 0xAA, 0xBB, 0xBF, 0x60, 0x03, 0xCC, 0xDD,
                0xEE, 0x00,
            ],
        );
    }

    #[test]
    fn egpo_empty_pdol_emits_zero_length_command_template() {
        let cmd = command(&[], &[0x00]).unwrap();
        // Data: 83 00 | BF 60 01 00 = 6 bytes.
        assert_eq!(
            cmd.to_bytes().unwrap(),
            vec![
                0x80, 0xE0, 0x00, 0x00, 0x06, 0x83, 0x00, 0xBF, 0x60, 0x01, 0x00, 0x00
            ],
        );
    }

    #[test]
    fn egpo_rejects_data_exceeding_short_apdu_limit() {
        let big = vec![0u8; 250];
        // 250 + 4 (83 LL) + 4 (BF60 LL) > 255.
        assert_eq!(command(&big, &big), Err(Error::LengthTooLong));
    }
}
