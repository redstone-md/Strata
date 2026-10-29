//! Strata desktop workbench (GPUI).
//!
//! Usage: `strata [CASE_DIR]`. Without an argument the default case
//! `%USERPROFILE%\Documents\Strata\default.strata` is opened (created if missing).

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod assets;
mod categories;
mod format;
mod nav;
mod picker;
mod session;
mod shell;
mod theme;
mod view_state;
mod views;
mod widgets;

use gpui::{
    App, AppContext as _, Bounds, KeyBinding, TitlebarOptions, WindowBounds, WindowOptions, px, size,
};
use std::time::Duration;
use view_state::WindowPlacement;
use gpui_component::Root;
use session::Session;
use shell::{FocusSearch, Shell};
use std::path::PathBuf;

fn case_dir() -> PathBuf {
    if let Some(arg) = std::env::args_os().nth(1) {
        return PathBuf::from(arg);
    }
    let home = std::env::var_os("USERPROFILE").or_else(|| std::env::var_os("HOME")).map(PathBuf::from).unwrap_or_default();
    home.join("Documents").join("Strata").join("default.strata")
}

fn main() {
    let case = case_dir();
    gpui_platform::application().with_assets(assets::StrataAssets).run(move |cx: &mut App| {
        gpui_component::init(cx);
        theme::install(cx);
        cx.bind_keys([KeyBinding::new("alt-f", FocusSearch, None)]);
        cx.on_window_closed(|cx, _| cx.quit()).detach();
        let bounds = WindowPlacement::load()
            .and_then(|p| p.bounds(cx))
            .unwrap_or_else(|| WindowBounds::Windowed(Bounds::centered(None, size(px(1480.), px(940.)), cx)));
        let options = WindowOptions {
            window_bounds: Some(bounds),
            titlebar: Some(TitlebarOptions { title: Some("Strata".into()), appears_transparent: true, ..Default::default() }),
            ..Default::default()
        };
        cx.open_window(options, |window, cx| {
            let session = cx.new(|cx| Session::new(&case, cx));
            let shell = cx.new(|cx| Shell::new(session.clone(), window, cx));
            shell.update(cx, |s, cx| s.restore(window, cx));
            let closing = shell.clone();
            // Closing keeps the work: view state is saved and running jobs stop at a
            // checkpoint, to resume on the next start.
            window.on_window_should_close(cx, move |window, cx| {
                WindowPlacement::of(window).save();
                closing.update(cx, |s, cx| s.save_view_state(cx));
                session.read(cx).workbench().shutdown(Duration::from_secs(5));
                true
            });
            cx.new(|cx| Root::new(shell, window, cx))
        })
        .expect("open main window");
        cx.activate(true);
    });
}
