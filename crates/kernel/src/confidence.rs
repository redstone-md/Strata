use serde::{Deserialize, Serialize};
use std::fmt;

/// Probability-like score in `[0, 1]`.
#[derive(Debug, Clone, Copy, PartialEq, PartialOrd, Default, Serialize, Deserialize)]
pub struct Confidence(f32);

impl Confidence {
    pub const NONE: Confidence = Confidence(0.0);
    pub const LOW: Confidence = Confidence(0.25);
    pub const MEDIUM: Confidence = Confidence(0.5);
    pub const HIGH: Confidence = Confidence(0.8);
    pub const CERTAIN: Confidence = Confidence(1.0);

    pub fn new(value: f32) -> Self {
        Self(if value.is_nan() { 0.0 } else { value.clamp(0.0, 1.0) })
    }

    pub fn get(self) -> f32 {
        self.0
    }

    pub fn scaled(self, factor: f32) -> Self {
        Self::new(self.0 * factor)
    }
}

impl fmt::Display for Confidence {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:.0}%", self.0 * 100.0)
    }
}
