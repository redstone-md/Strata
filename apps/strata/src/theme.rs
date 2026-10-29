//! Design tokens: the single source of colours, type, spacing and radii for the whole app.
//!
//! Strictly monochrome. Hierarchy comes from brightness and weight only; warnings use
//! inversion or an outline, never hue. [`install`] projects the same palette onto
//! gpui-component's global `Theme` so its tables, inputs and scrollbars match.

use gpui::{App, FontWeight, Hsla, Pixels, Rgba, px};
use gpui_component::{Theme, ThemeMode};
use std::sync::LazyLock;

/// Colour from `0xRRGGBB`.
pub fn hex(rgb: u32) -> Hsla {
    hexa(rgb, 1.0)
}

/// Colour from `0xRRGGBB` plus alpha `0..=1`.
pub fn hexa(rgb: u32, alpha: f32) -> Hsla {
    let channel = |shift: u32| ((rgb >> shift) & 0xff) as f32 / 255.0;
    Rgba { r: channel(16), g: channel(8), b: channel(0), a: alpha }.into()
}

/// Neutral grey of brightness `0..=1` (sector-map and timeline ramps).
pub fn grey(level: f32) -> Hsla {
    let v = level.clamp(0.0, 1.0);
    Rgba { r: v, g: v, b: v, a: 1.0 }.into()
}

pub struct Tokens {
    // Surfaces
    pub ground: Hsla,
    pub sidebar: Hsla,
    pub raised: Hsla,
    pub hover: Hsla,
    pub rule: Hsla,
    pub row_rule: Hsla,
    pub selection: Hsla,
    pub ink: Hsla,
    // Text
    pub text: Hsla,
    pub text_secondary: Hsla,
    pub emphasis: Hsla,
    // Data marks (sector map, timeline)
    pub cell_unscanned: Hsla,
    pub cell_scanned: Hsla,
    pub cell_damaged: Hsla,
    // Type
    pub font_ui: &'static str,
    pub font_data: &'static str,
    pub size_small: Pixels,
    pub size_body: Pixels,
    pub size_heading: Pixels,
    pub semibold: FontWeight,
    // Shape and rhythm
    pub radius: Pixels,
    pub command_bar_height: Pixels,
    pub sidebar_width: Pixels,
    pub row_height: Pixels,
    pub gutter: Pixels,
    pub section_gap: Pixels,
    pub block_gap: Pixels,
    pub content_max_width: Pixels,
}

static TOKENS: LazyLock<Tokens> = LazyLock::new(|| Tokens {
    ground: hex(0x232323),
    sidebar: hex(0x1f1f1f),
    raised: hex(0x2b2b2b),
    hover: hex(0x333333),
    rule: hex(0x3a3a3a),
    row_rule: hex(0x333333),
    selection: hexa(0xe6e6e6, 0.14),
    ink: hex(0x1a1a1a),
    text: hex(0xe6e6e6),
    text_secondary: hex(0x8c8c8c),
    emphasis: hex(0xffffff),
    cell_unscanned: hex(0x2f2f2f),
    cell_scanned: hex(0x5a5a5a),
    cell_damaged: hex(0x1a1a1a),
    font_ui: "Bahnschrift",
    font_data: "Cascadia Mono",
    size_small: px(12.),
    size_body: px(13.),
    size_heading: px(15.),
    semibold: FontWeight::SEMIBOLD,
    radius: px(3.),
    command_bar_height: px(44.),
    sidebar_width: px(184.),
    row_height: px(28.),
    gutter: px(32.),
    section_gap: px(32.),
    block_gap: px(24.),
    content_max_width: px(1320.),
});

pub fn tokens() -> &'static Tokens {
    &TOKENS
}

/// Switch gpui-component to dark mode and recolour it with the monochrome palette.
pub fn install(cx: &mut App) {
    Theme::change(ThemeMode::Dark, None, cx);
    let t = tokens();
    Theme::update(cx, |theme| {
        theme.font_family = t.font_ui.into();
        theme.mono_font_family = t.font_data.into();
        theme.font_size = t.size_body;
        theme.mono_font_size = t.size_body;
        theme.radius = t.radius;
        theme.radius_lg = t.radius;
        theme.shadow = false;
        let c = &mut theme.colors;
        c.background = t.ground;
        c.foreground = t.text;
        c.border = t.rule;
        c.input = t.rule;
        c.ring = hexa(0xe6e6e6, 0.5);
        c.caret = t.emphasis;
        c.selection = hexa(0xe6e6e6, 0.28);
        c.muted = t.raised;
        c.muted_foreground = t.text_secondary;
        c.accent = t.hover;
        c.accent_foreground = t.emphasis;
        c.primary = t.text;
        c.primary_hover = t.emphasis;
        c.primary_active = t.emphasis;
        c.primary_foreground = t.ink;
        c.button_primary = t.text;
        c.button_primary_hover = t.emphasis;
        c.button_primary_active = t.emphasis;
        c.button_primary_foreground = t.ink;
        c.button = t.raised;
        c.button_hover = t.hover;
        c.button_active = t.hover;
        c.button_foreground = t.text;
        c.secondary = t.raised;
        c.secondary_hover = t.hover;
        c.secondary_active = t.hover;
        c.secondary_foreground = t.text;
        c.popover = t.raised;
        c.popover_foreground = t.text;
        c.list = t.ground;
        c.list_even = t.ground;
        c.list_head = t.ground;
        c.list_hover = t.hover;
        c.list_active = t.selection;
        c.list_active_border = gpui::transparent_black();
        c.table = t.ground;
        c.table_even = t.ground;
        c.table_head = t.ground;
        c.table_head_foreground = t.text_secondary;
        c.table_hover = t.hover;
        c.table_active = t.selection;
        c.table_active_border = gpui::transparent_black();
        c.table_row_border = t.row_rule;
        c.scrollbar = gpui::transparent_black();
        c.scrollbar_thumb = hexa(0xe6e6e6, 0.18);
        c.scrollbar_thumb_hover = hexa(0xe6e6e6, 0.32);
        c.success = t.text;
        c.warning = t.text;
        c.danger = t.text;
        c.info = t.text;
        c.progress_bar = t.emphasis;
        c.skeleton = t.hover;
        c.link = t.text;
        c.link_hover = t.emphasis;
        c.link_active = t.emphasis;
    });
}
