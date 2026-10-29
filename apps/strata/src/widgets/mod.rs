//! Reusable presentation widgets. Every colour and radius comes from [`crate::theme`].

mod backdrop;
mod file_type_tile;
mod glass_card;
mod gradient_bar;
mod icon_rail;
mod pill;
mod progress_row;
mod search_field;
mod stat_number;
mod text_table;

pub use backdrop::Backdrop;
pub use file_type_tile::FileTypeTile;
pub use glass_card::GlassCard;
pub use gradient_bar::GradientBar;
pub use icon_rail::{IconRail, RailItem};
pub use pill::Pill;
pub use progress_row::{ProgressRow, RowStatus};
pub use search_field::SearchField;
pub use stat_number::StatNumber;
pub use text_table::TextTable;

pub use gpui_kit_assets::IconName as Glyph;

use gpui::{App, ClickEvent, Hsla, Pixels, Styled, Window};
use gpui_component::Icon;

/// Click callback shared by widgets that expose a button.
pub type ClickHandler = std::rc::Rc<dyn Fn(&ClickEvent, &mut Window, &mut App)>;

/// A Lucide icon at a given size and colour.
pub fn glyph(name: Glyph, size: Pixels, color: Hsla) -> Icon {
    Icon::new(name).size(size).text_color(color)
}
