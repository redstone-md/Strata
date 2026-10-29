//! Reusable presentation widgets. Every colour, size and radius comes from [`crate::theme`].

mod badge;
mod check;
mod field;
mod section;
mod sector_map;
mod sidebar;
mod text_button;
mod text_table;

pub use badge::Badge;
pub use check::Check;
pub use field::Field;
pub use section::{Section, rule};
pub use sector_map::{DiskMaps, SectorMapView, legend};
pub use sidebar::{NavItem, Sidebar};
pub use text_button::TextButton;
pub use text_table::{Cell, TextTable, flat_table, table_empty, table_header};

pub use gpui_kit_assets::IconName as Glyph;

use crate::theme::tokens;
use gpui::{App, ClickEvent, Div, Hsla, Pixels, Styled, Window, div};
use gpui_component::Icon;

/// Click callback shared by widgets that expose a button.
pub type ClickHandler = std::rc::Rc<dyn Fn(&ClickEvent, &mut Window, &mut App)>;

/// A Lucide line icon at a given size and colour.
pub fn glyph(name: Glyph, size: Pixels, color: Hsla) -> Icon {
    Icon::new(name).size(size).text_color(color)
}

/// Text block in the data face (keys, addresses, offsets, paths).
pub fn mono() -> Div {
    div().font_family(tokens().font_data)
}

/// Secondary-colour text at body size.
pub fn quiet() -> Div {
    let t = tokens();
    div().text_size(t.size_body).text_color(t.text_secondary)
}
