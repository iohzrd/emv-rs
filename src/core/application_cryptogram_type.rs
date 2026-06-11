//! Book 3 §6.5.5 Table 15 - Application Cryptogram Type (b8/b7).

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ApplicationCryptogramType {
    #[default]
    Aac,
    Tc,
    Arqc,
    Rfu(u8),
}

impl ApplicationCryptogramType {
    pub const fn from_bits(bits: u8) -> Self {
        match bits & 0b11 {
            0b00 => ApplicationCryptogramType::Aac,
            0b01 => ApplicationCryptogramType::Tc,
            0b10 => ApplicationCryptogramType::Arqc,
            0b11 => ApplicationCryptogramType::Rfu(0b11),
            _ => unreachable!(),
        }
    }

    pub const fn to_bits(self) -> u8 {
        match self {
            ApplicationCryptogramType::Aac => 0b00,
            ApplicationCryptogramType::Tc => 0b01,
            ApplicationCryptogramType::Arqc => 0b10,
            ApplicationCryptogramType::Rfu(v) => v & 0b11,
        }
    }

    // Book C-2 §3.5.3 step 5: TC > ARQC > AAC; Rfu lowest.
    pub const fn ids_priority(self) -> u8 {
        match self {
            ApplicationCryptogramType::Aac => 1,
            ApplicationCryptogramType::Arqc => 2,
            ApplicationCryptogramType::Tc => 3,
            ApplicationCryptogramType::Rfu(_) => 0,
        }
    }

    pub const fn select_lower(self, other: ApplicationCryptogramType) -> ApplicationCryptogramType {
        if self.ids_priority() <= other.ids_priority() {
            self
        } else {
            other
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_all_4_encodings() {
        for bits in 0u8..=0b11 {
            assert_eq!(ApplicationCryptogramType::from_bits(bits).to_bits(), bits);
        }
    }

    #[test]
    fn rfu_is_lowest_priority() {
        for ct in [
            ApplicationCryptogramType::Aac,
            ApplicationCryptogramType::Tc,
            ApplicationCryptogramType::Arqc,
        ] {
            assert!(ct.ids_priority() > ApplicationCryptogramType::Rfu(0b11).ids_priority());
        }
    }

    #[test]
    fn ids_priority_matches_tc_arqc_aac_order() {
        assert!(
            ApplicationCryptogramType::Aac.ids_priority()
                < ApplicationCryptogramType::Arqc.ids_priority()
        );
        assert!(
            ApplicationCryptogramType::Arqc.ids_priority()
                < ApplicationCryptogramType::Tc.ids_priority()
        );
    }

    #[test]
    fn select_lower_demotes_kernel_to_ds() {
        assert_eq!(
            ApplicationCryptogramType::Tc.select_lower(ApplicationCryptogramType::Arqc),
            ApplicationCryptogramType::Arqc
        );
        assert_eq!(
            ApplicationCryptogramType::Arqc.select_lower(ApplicationCryptogramType::Tc),
            ApplicationCryptogramType::Arqc
        );
        assert_eq!(
            ApplicationCryptogramType::Arqc.select_lower(ApplicationCryptogramType::Arqc),
            ApplicationCryptogramType::Arqc
        );
    }
}
