//! GNOME/GTK `recently-used.xbel`: `<bookmark href="file:///..." added=".." modified=".."
//! visited="..">` with ISO-8601 UTC times and the applications that opened each file.

use crate::results::Recorder;
use strata_kernel::Timestamp;
use strata_timeline::EventKind;

pub(crate) struct RecentlyUsed;

impl RecentlyUsed {
    pub fn parse(data: &[u8], rec: &mut Recorder) {
        let text = String::from_utf8_lossy(data);
        for chunk in text.split("<bookmark ").skip(1) {
            let tag = chunk.split('>').next().unwrap_or_default();
            let Some(href) = attr(tag, "href") else { continue };
            let target = percent_decode(href.trim_start_matches("file://"));
            let app = chunk.split("<bookmark:application ").nth(1).and_then(|a| attr(a, "name")).unwrap_or_default();
            let detail = if app.is_empty() { "recently used".to_string() } else { format!("opened with {app}") };
            rec.dated(attr(tag, "added").and_then(Timestamp::parse_iso8601), EventKind::FileCreated, target.clone(), "added to recent files");
            rec.emit(attr(tag, "visited").or(attr(tag, "modified")).and_then(Timestamp::parse_iso8601), EventKind::DocumentOpened, target, detail);
        }
    }
}

fn attr<'a>(tag: &'a str, name: &str) -> Option<&'a str> {
    let start = tag.find(&format!("{name}=\""))? + name.len() + 2;
    let len = tag[start..].find('"')?;
    Some(&tag[start..start + len])
}

fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        let hex = |b: u8| (b as char).to_digit(16);
        match (bytes[i], bytes.get(i + 1).copied().and_then(hex), bytes.get(i + 2).copied().and_then(hex)) {
            (b'%', Some(a), Some(b)) => {
                out.push((a * 16 + b) as u8);
                i += 3;
            }
            (b, _, _) => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_bookmarks() {
        let xbel = br#"<xbel><bookmark href="file:///home/u/%D0%BA%D0%BE%D1%88%D0%B5%D0%BB%D0%B5%D0%BA.txt" added="2013-05-01T10:00:00Z" modified="2013-05-01T10:00:00Z" visited="2013-05-02T11:30:15.5Z"><info><metadata><bookmark:applications><bookmark:application name="gedit" exec="gedit %u"/></bookmark:applications></metadata></info></bookmark></xbel>"#;
        let mut rec = Recorder::new("linux.recently_used");
        RecentlyUsed::parse(xbel, &mut rec);
        let out = rec.finish();
        let opened = out.events.iter().find(|e| e.kind() == EventKind::DocumentOpened).unwrap();
        assert_eq!(opened.title(), "/home/u/кошелек.txt");
        assert_eq!(opened.at().to_string(), "2013-05-02 11:30:15");
    }
}
