//! Account configuration files: Mozilla `prefs.js` (Thunderbird / Firefox Sync), Windows Live
//! Mail `.oeaccount`, and mining-software configs and launch scripts that name a pool login.
//! None of these carry dates of their own; the extractor dates them by the file's times.

mod miner;
mod mozilla_prefs;
mod oeaccount;

pub(crate) use miner::MinerConfig;
pub(crate) use mozilla_prefs::MozillaPrefs;
pub(crate) use oeaccount::OeAccount;

/// Config text in UTF-16LE (BOM or NUL-interleaved) or UTF-8 / ANSI.
pub(crate) fn config_text(data: &[u8]) -> String {
    let nul_odd = data.iter().skip(1).step_by(2).take(64).filter(|b| **b == 0).count();
    if data.starts_with(&[0xFF, 0xFE]) || (data.len() >= 8 && nul_odd > 24) {
        let body = data.strip_prefix(&[0xFF, 0xFE]).unwrap_or(data);
        let units: Vec<u16> = body.as_chunks::<2>().0.iter().map(|c| u16::from_le_bytes(*c)).collect();
        String::from_utf16_lossy(&units)
    } else {
        String::from_utf8_lossy(data).into_owned()
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn utf16_and_utf8() {
        let wide: Vec<u8> = [0xFF, 0xFE].into_iter().chain("<a>x</a>".bytes().flat_map(|b| [b, 0])).collect();
        assert_eq!(super::config_text(&wide), "<a>x</a>");
        assert_eq!(super::config_text(b"user_pref(\"a\", \"b\");"), "user_pref(\"a\", \"b\");");
    }
}
