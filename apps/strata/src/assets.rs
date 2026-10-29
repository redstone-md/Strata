//! Embedded SVG icons: the few Lucide line icons the sidebar uses, layered over
//! gpui-component's default set.

use gpui::{AssetSource, Result, SharedString};
use std::borrow::Cow;

gpui_kit_assets::icon_assets!(AppIcons, [LayoutDashboard, HardDrive, KeyRound, Users, GitCompare, Settings]);

pub struct StrataAssets;

impl AssetSource for StrataAssets {
    fn load(&self, path: &str) -> Result<Option<Cow<'static, [u8]>>> {
        match AppIcons.load(path)? {
            Some(bytes) => Ok(Some(bytes)),
            None => gpui_kit_assets::Assets.load(path),
        }
    }

    fn list(&self, path: &str) -> Result<Vec<SharedString>> {
        let mut out = AppIcons.list(path)?;
        out.extend(gpui_kit_assets::Assets.list(path)?);
        Ok(out)
    }
}
