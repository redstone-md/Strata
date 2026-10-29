//! Names for members that carry none (the content of a GZIP/BZIP2/XZ stream).

/// `logs.tar.gz` -> `logs.tar`, `x.tgz` -> `x.tar`, `photo.jpg` (a renamed stream) ->
/// `photo.jpg.unpacked`.
pub(super) fn stream_member(container: &str) -> String {
    let last = container.rsplit("!/").next().unwrap_or(container);
    let name = last.rsplit(['/', '\\']).next().unwrap_or(last);
    let lower = name.to_ascii_lowercase();
    for (ext, replacement) in [(".tgz", ".tar"), (".tbz2", ".tar"), (".tbz", ".tar"), (".txz", ".tar"), (".gz", ""), (".bz2", ""), (".xz", "")] {
        if lower.ends_with(ext) && name.len() > ext.len() {
            return format!("{}{replacement}", &name[..name.len() - ext.len()]);
        }
    }
    format!("{name}.unpacked")
}

#[cfg(test)]
mod tests {
    use super::stream_member;

    #[test]
    fn strips_compression_suffix() {
        assert_eq!(stream_member("a/logs.tar.gz"), "logs.tar");
        assert_eq!(stream_member("x.zip!/inner/b.TGZ"), "b.tar");
        assert_eq!(stream_member("photo.jpg"), "photo.jpg.unpacked");
        assert_eq!(stream_member(".gz"), ".gz.unpacked");
    }
}
