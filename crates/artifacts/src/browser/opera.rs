//! Opera Presto (≤ 12): `typed_history.xml` and `global_history.dat` / `global.dat`.

use crate::results::Recorder;
use crate::text::{is_url, parse_iso8601};
use strata_kernel::Timestamp;
use strata_timeline::EventKind;

pub(crate) struct OperaTypedHistory;

impl OperaTypedHistory {
    /// `<typed_history_item content="ya.ru" type="text" last_typed="2012-01-31T19:57:06Z"/>`
    pub fn parse(data: &[u8], rec: &mut Recorder) {
        let text = String::from_utf8_lossy(data);
        for item in text.split("<typed_history_item").skip(1) {
            let item = item.split('>').next().unwrap_or("");
            let content = xml_attr(item, "content").unwrap_or_default();
            let kind = match xml_attr(item, "type").as_deref() {
                Some("search") => EventKind::Search,
                _ => EventKind::UrlVisited,
            };
            let at = xml_attr(item, "last_typed").and_then(|t| parse_iso8601(&t));
            rec.emit(at, kind, content, "Opera typed history");
        }
    }
}

fn xml_attr(tag: &str, name: &str) -> Option<String> {
    let pat = format!("{name}=\"");
    let start = tag.find(&pat)? + pat.len();
    let end = tag.get(start..)?.find('"')? + start;
    Some(unescape(tag.get(start..end)?))
}

fn unescape(s: &str) -> String {
    s.replace("&quot;", "\"").replace("&lt;", "<").replace("&gt;", ">").replace("&apos;", "'").replace("&amp;", "&")
}

pub(crate) struct OperaGlobalHistory;

impl OperaGlobalHistory {
    /// Repeating 4-line groups: title, URL, Unix seconds, popularity. Resynchronises on the
    /// next URL line after damage.
    pub fn parse(data: &[u8], rec: &mut Recorder) {
        let text = String::from_utf8_lossy(data);
        let lines: Vec<&str> = text.lines().map(str::trim_end).collect();
        let mut i = 1;
        while i < lines.len() {
            if !is_url(lines[i]) {
                i += 1;
                continue;
            }
            let title = lines[i - 1];
            let at = lines.get(i + 1).and_then(|t| t.trim().parse::<i64>().ok()).and_then(Timestamp::from_unix_secs);
            rec.emit(at, EventKind::UrlVisited, lines[i], title);
            i += if at.is_some() { 4 } else { 1 };
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn typed_and_global() {
        let xml = br#"<?xml version="1.0"?><typed_history>
<typed_history_item content="ya.ru" type="text" last_typed="2012-01-31T19:57:06Z"/>
<typed_history_item content="bitcoin wallet" type="search" last_typed="bad"/>
</typed_history>"#;
        let mut rec = Recorder::new("opera.typed_history");
        OperaTypedHistory::parse(xml, &mut rec);
        let out = rec.finish();
        assert_eq!(out.events.len(), 1);
        assert_eq!(out.events[0].title(), "ya.ru");
        assert_eq!(out.facts.len(), 1);

        let dat = b"Yandex\nhttp://ya.ru/\n1327953426\n-1\nbroken\nhttps://lifehacker.ru/x\n";
        let mut rec = Recorder::new("opera.global_history");
        OperaGlobalHistory::parse(dat, &mut rec);
        let out = rec.finish();
        assert_eq!(out.events.len(), 1);
        assert_eq!(out.events[0].detail(), "Yandex");
        assert_eq!(out.facts.len(), 1);
        OperaGlobalHistory::parse(b"\xff\xfe\n", &mut Recorder::new("t"));
    }
}
