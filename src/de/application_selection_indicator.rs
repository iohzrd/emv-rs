//! Application Selection Indicator - Book 1 §12.3.1.

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ApplicationSelectionIndicator {
    #[default]
    ExactMatch,
    PartialMatchAllowed,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_is_exact_match() {
        assert_eq!(
            ApplicationSelectionIndicator::default(),
            ApplicationSelectionIndicator::ExactMatch,
        );
    }

    #[test]
    fn variants_are_distinct() {
        assert_ne!(
            ApplicationSelectionIndicator::ExactMatch,
            ApplicationSelectionIndicator::PartialMatchAllowed,
        );
    }

    #[test]
    #[allow(clippy::clone_on_copy)]
    fn copy_clone_round_trip() {
        let a = ApplicationSelectionIndicator::PartialMatchAllowed;
        let b = a; // Copy
        let c = a.clone(); // Clone
        assert_eq!(a, b);
        assert_eq!(a, c);
    }
}
