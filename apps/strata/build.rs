//! Embeds the app icon and version information into strata.exe (Windows only).

fn main() {
    println!("cargo:rerun-if-changed=strata.rc");
    println!("cargo:rerun-if-changed=../../assets/strata.ico");
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("windows") {
        return;
    }
    let version = env!("CARGO_PKG_VERSION");
    let mut parts: Vec<&str> = version.split(['.', '-']).take(3).collect();
    parts.resize(3, "0");
    let commas = format!("{},0", parts.join(","));
    let quoted = format!("\"{version}\"");
    embed_resource::compile("strata.rc", [format!("STRATA_VERSION={quoted}"), format!("STRATA_VERSION_COMMAS={commas}")])
        .manifest_optional()
        .expect("embed strata.rc");
}
