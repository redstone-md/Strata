//! Native file / folder picker (`App::prompt_for_paths`) with a callback on the UI thread.

use gpui::{App, PathPromptOptions};
use std::path::PathBuf;

pub enum PickKind {
    File,
    Folder,
}

pub fn pick_path(kind: PickKind, cx: &mut App, done: impl FnOnce(PathBuf, &mut App) + 'static) {
    let directories = matches!(kind, PickKind::Folder);
    let rx = cx.prompt_for_paths(PathPromptOptions { files: !directories, directories, multiple: false, prompt: None });
    cx.spawn(async move |cx| {
        if let Ok(Ok(Some(paths))) = rx.await
            && let Some(path) = paths.into_iter().next()
        {
            cx.update(|cx| done(path, cx));
        }
    })
    .detach();
}
