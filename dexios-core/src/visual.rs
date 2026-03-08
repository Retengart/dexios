//! This module offers visual functionality within `dexios-core`.
//!
//! It isn't rather populated, nor does `dexios` itself use it, but the option is always there.
//!
//! This can be enabled with the `visual` feature, and you will notice a blue spinner on encryption and decryption - useful for knowing that something is still happening.

#[cfg(feature = "visual")]
use indicatif::{ProgressBar, ProgressStyle};
#[cfg(feature = "visual")]
use std::time::Duration;

#[cfg(feature = "visual")]
fn spinner_style(template: &str) -> ProgressStyle {
    ProgressStyle::with_template(template).unwrap_or_else(|_| ProgressStyle::default_spinner())
}

#[cfg(feature = "visual")]
#[must_use]
/// This creates a visual spinner, which can be enabled with the `visual` feature.
///
/// The spinner is used for both encrypting and decrypting, provided the feature is enabled.
pub fn create_spinner() -> ProgressBar {
    let pb = ProgressBar::new_spinner();
    pb.enable_steady_tick(Duration::from_millis(120));
    pb.set_style(spinner_style("{spinner:.cyan}"));

    pb
}

#[cfg(all(test, feature = "visual"))]
mod tests {
    use super::*;

    #[test]
    fn spinner_style_falls_back_to_default_spinner_for_invalid_template() {
        let style = spinner_style("{spinner:?}");
        let default = ProgressStyle::default_spinner();

        assert_eq!(style.get_final_tick_str(), default.get_final_tick_str());
    }
}
