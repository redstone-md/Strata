//! URL pieces every context needs: the host a URL points at and `%xx` decoding. One
//! implementation, shared by the artefact parsers, the case queries and the detectors.

/// Host part of a URL (`https://user@Host:80/x` → `host`), lower case, without a leading dot
/// (cookie hosts are written `.example.com`). Text without `://` is read as `host/path`.
pub fn host_of(url: &str) -> Option<String> {
    let rest = url.split_once("://").map_or(url, |(_, r)| r);
    let authority = rest.split(['/', '?', '#']).next()?;
    let host = authority.rsplit('@').next()?.split(':').next()?.trim_start_matches('.');
    (!host.is_empty()).then(|| host.to_ascii_lowercase())
}

/// `%xx` sequences to bytes, read as UTF-8 (lossy). Broken escapes stay as they are.
pub fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        let hex = |j: usize| bytes.get(j).and_then(|b| (*b as char).to_digit(16));
        match (bytes[i], hex(i + 1), hex(i + 2)) {
            (b'%', Some(h), Some(l)) => {
                out.push((h * 16 + l) as u8);
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
    fn hosts() {
        assert_eq!(host_of("https://u@Shop.Example.com:443/x?y").as_deref(), Some("shop.example.com"));
        assert_eq!(host_of(".example.com").as_deref(), Some("example.com"));
        assert_eq!(host_of("example.org/path").as_deref(), Some("example.org"));
        assert_eq!(host_of("file:///C:/x"), None);
        assert_eq!(host_of(""), None);
    }

    #[test]
    fn decodes() {
        assert_eq!(percent_decode("a%20b%D0%B1%zz%4"), "a bб%zz%4");
    }
}
