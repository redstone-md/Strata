//! Design tokens: the single source of colours, radii and spacing for the whole app.
//!
//! Widgets read [`tokens()`]; [`install`] projects the same palette onto gpui-component's
//! global `Theme` so built-in controls (tables, inputs, buttons) blend into the dark glass look.

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

pub struct Tokens {
    // Surfaces
    pub bg_top: Hsla,
    pub bg_bottom: Hsla,
    pub glow_blue: Hsla,
    pub glow_indigo: Hsla,
    pub card: Hsla,
    pub card_border: Hsla,
    pub glass: Hsla,
    pub glass_hover: Hsla,
    pub glass_active: Hsla,
    pub glass_border: Hsla,
    pub glass_border_strong: Hsla,
    pub tile: Hsla,
    pub track: Hsla,
    pub separator: Hsla,
    // Text
    pub text: Hsla,
    pub text_muted: Hsla,
    pub text_dim: Hsla,
    // Accents
    pub blue: Hsla,
    pub indigo: Hsla,
    pub green: Hsla,
    pub yellow: Hsla,
    pub orange: Hsla,
    pub red: Hsla,
    pub rainbow: [Hsla; 4],
    pub scan: [Hsla; 2],
    // Shape
    pub radius_card: Pixels,
    pub radius_control: Pixels,
    pub radius_tile: Pixels,
    pub rail_width: Pixels,
    pub card_padding: Pixels,
    pub gap: Pixels,
    pub gap_lg: Pixels,
    // Type
    pub thin: FontWeight,
    pub light: FontWeight,
    pub size_title: Pixels,
    pub size_hero: Pixels,
    pub size_number: Pixels,
    pub size_card_title: Pixels,
    pub size_caption: Pixels,
}

static TOKENS: LazyLock<Tokens> = LazyLock::new(|| {
    let blue = hex(0x3b82f6);
    let green = hex(0x22c55e);
    let yellow = hex(0xfacc15);
    let orange = hex(0xf97316);
    Tokens {
        bg_top: hex(0x0b1424),
        bg_bottom: hex(0x101d36),
        glow_blue: hexa(0x2563eb, 0.22),
        glow_indigo: hexa(0x6366f1, 0.16),
        card: hexa(0x14203a, 0.75),
        card_border: hexa(0xffffff, 0.10),
        glass: hexa(0xffffff, 0.04),
        glass_hover: hexa(0xffffff, 0.08),
        glass_active: hexa(0xffffff, 0.12),
        glass_border: hexa(0xffffff, 0.12),
        glass_border_strong: hexa(0xffffff, 0.22),
        tile: hexa(0x0a1222, 0.85),
        track: hexa(0xffffff, 0.08),
        separator: hexa(0xffffff, 0.08),
        text: hex(0xe6ecf5),
        text_muted: hex(0x8a97ad),
        text_dim: hex(0x5d6a80),
        blue,
        indigo: hex(0x6366f1),
        green,
        yellow,
        orange,
        red: hex(0xef4444),
        rainbow: [orange, yellow, blue, green],
        scan: [blue, green],
        radius_card: px(16.),
        radius_control: px(12.),
        radius_tile: px(8.),
        rail_width: px(72.),
        card_padding: px(22.),
        gap: px(16.),
        gap_lg: px(24.),
        thin: FontWeight::EXTRA_LIGHT,
        light: FontWeight::LIGHT,
        size_title: px(28.),
        size_hero: px(40.),
        size_number: px(44.),
        size_card_title: px(16.),
        size_caption: px(12.),
    }
});

pub fn tokens() -> &'static Tokens {
    &TOKENS
}

/// Switch gpui-component to dark mode and recolour it with our palette.
pub fn install(cx: &mut App) {
    Theme::change(ThemeMode::Dark, None, cx);
    let t = tokens();
    Theme::update(cx, |theme| {
        theme.radius = t.radius_tile;
        theme.radius_lg = t.radius_control;
        theme.shadow = false;
        theme.font_size = px(14.);
        let c = &mut theme.colors;
        c.background = t.bg_top;
        c.foreground = t.text;
        c.border = t.card_border;
        c.input = t.glass_border;
        c.ring = hexa(0x3b82f6, 0.6);
        c.caret = t.text;
        c.selection = hexa(0x3b82f6, 0.35);
        c.muted = t.glass;
        c.muted_foreground = t.text_muted;
        c.accent = t.glass_hover;
        c.accent_foreground = t.text;
        c.primary = t.blue;
        c.primary_hover = hex(0x2f6fdc);
        c.primary_active = hex(0x2563eb);
        c.primary_foreground = hex(0xffffff);
        c.secondary = t.glass;
        c.secondary_hover = t.glass_hover;
        c.secondary_active = t.glass_active;
        c.secondary_foreground = t.text;
        c.popover = hex(0x111c32);
        c.popover_foreground = t.text;
        c.list = gpui::transparent_black();
        c.list_even = hexa(0xffffff, 0.02);
        c.list_head = gpui::transparent_black();
        c.list_hover = t.glass_hover;
        c.list_active = hexa(0x3b82f6, 0.18);
        c.list_active_border = hexa(0x3b82f6, 0.5);
        c.table = gpui::transparent_black();
        c.table_even = hexa(0xffffff, 0.02);
        c.table_head = hexa(0xffffff, 0.03);
        c.table_head_foreground = t.text_muted;
        c.table_hover = t.glass_hover;
        c.table_active = hexa(0x3b82f6, 0.18);
        c.table_active_border = hexa(0x3b82f6, 0.5);
        c.table_row_border = t.separator;
        c.scrollbar = gpui::transparent_black();
        c.scrollbar_thumb = hexa(0xffffff, 0.15);
        c.scrollbar_thumb_hover = hexa(0xffffff, 0.25);
        c.success = t.green;
        c.warning = t.yellow;
        c.danger = t.red;
        c.info = t.blue;
        c.progress_bar = t.blue;
        c.skeleton = t.glass_hover;
    });
}
