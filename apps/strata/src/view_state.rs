//! What the user was looking at, restored on the next start: the screen, search text,
//! category filter, selected finding, timeline day and selected task (saved in the case),
//! and the window's place and size (saved per user, since it belongs to the screen, not the
//! case). Writes are debounced by the shell.

use gpui::{App, Bounds, Pixels, Window, WindowBounds, point, px, size};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use strata_workbench::{HitCategory, Workbench};

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct ViewState {
    pub screen: Option<String>,
    pub search: String,
    pub category: Option<HitCategory>,
    /// Stored hit id of the selected finding.
    pub finding: Option<i64>,
    /// Timeline day filter, days since the epoch `[from, to)`.
    pub day: Option<(i64, i64)>,
    pub task: Option<u32>,
}

impl ViewState {
    pub fn load(wb: &Workbench) -> Self {
        wb.ui_state().and_then(|s| serde_json::from_str(&s).ok()).unwrap_or_default()
    }

    pub fn save(&self, wb: &Workbench) {
        if let Ok(json) = serde_json::to_string(self) {
            // Losing the view state is harmless; never interrupt the user for it.
            let _ = wb.set_ui_state(&json);
        }
    }
}

/// Window position and size in logical pixels.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct WindowPlacement {
    pub x: f32,
    pub y: f32,
    pub width: f32,
    pub height: f32,
    pub maximized: bool,
}

impl WindowPlacement {
    fn path() -> Option<PathBuf> {
        let base = std::env::var_os("APPDATA").or_else(|| std::env::var_os("XDG_CONFIG_HOME")).map(PathBuf::from)?;
        Some(base.join("Strata").join("window.json"))
    }

    pub fn load() -> Option<Self> {
        let p: Self = serde_json::from_slice(&std::fs::read(Self::path()?).ok()?).ok()?;
        (p.width >= 640.0 && p.height >= 400.0 && p.x.is_finite() && p.y.is_finite()).then_some(p)
    }

    pub fn save(&self) {
        let Some(path) = Self::path() else { return };
        if let (Some(dir), Ok(json)) = (path.parent(), serde_json::to_vec(self)) {
            let _ = std::fs::create_dir_all(dir).and_then(|_| std::fs::write(&path, json));
        }
    }

    pub fn of(window: &Window) -> Self {
        let (bounds, maximized) = match window.window_bounds() {
            WindowBounds::Windowed(b) => (b, false),
            WindowBounds::Maximized(b) | WindowBounds::Fullscreen(b) => (b, true),
        };
        Self {
            x: bounds.origin.x.as_f32(),
            y: bounds.origin.y.as_f32(),
            width: bounds.size.width.as_f32(),
            height: bounds.size.height.as_f32(),
            maximized,
        }
    }

    /// The saved bounds, if they still fall on a connected display.
    pub fn bounds(&self, cx: &App) -> Option<WindowBounds> {
        let b: Bounds<Pixels> = Bounds::new(point(px(self.x), px(self.y)), size(px(self.width), px(self.height)));
        let title_bar = Bounds::new(b.origin, size(b.size.width, px(40.)));
        let visible = cx.displays().iter().any(|d| d.bounds().intersects(&title_bar));
        visible.then_some(if self.maximized { WindowBounds::Maximized(b) } else { WindowBounds::Windowed(b) })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn view_state_survives_json_and_tolerates_missing_fields() {
        let s = ViewState {
            screen: Some("tasks".into()),
            search: "wallet".into(),
            category: Some(HitCategory::PrivateKey),
            finding: Some(42),
            day: Some((16000, 16001)),
            task: Some(7),
        };
        let back: ViewState = serde_json::from_str(&serde_json::to_string(&s).unwrap()).unwrap();
        assert_eq!(back, s);
        let partial: ViewState = serde_json::from_str(r#"{"screen":"timeline"}"#).unwrap();
        assert_eq!(partial.screen.as_deref(), Some("timeline"));
        assert_eq!(partial.finding, None);
    }
}
