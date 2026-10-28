# Strata code style (binding for every contributor and agent)

## Architecture
- **Bounded contexts = crates.** `kernel` is the shared kernel (ids, ranges, time, damage, errors).
  Every other crate owns one domain: `source` (evidence bytes), `volume` (partitions), `fs`
  (filesystems), `identify` (what bytes are), `crypto` (keys/wallets), `engine` (scan pipeline),
  `case` (aggregate + persistence + correlation). Apps (`apps/*`) only orchestrate.
- Dependencies point inward: domain crates never depend on UI, CLI or the case database.
- I/O lives at the edges (`source`, `case` storage, `chain` network). Parsers take `&dyn BlockSource`
  or byte slices, never paths.

## OOP
- Struct + `impl` with private fields and validating constructors. Expose behaviour, not fields.
- Swappable adapters behind traits (`BlockSource`, `FileSystem`, `Detector`, `ChainBackend`),
  injected as `Arc<dyn Trait>`.
- Newtypes for ids and offsets (`EvidenceId`, `ByteRange`), enums for states/kinds.

## DRY
- One implementation per concept: Base58Check, WIF, secp256k1 derivation, FILETIME conversion,
  signature tables, regexes. If you need it twice, it moves to the owning crate and is reused.
- Detector tables (magic numbers, markers, context words) are data, defined once.

## Damage tolerance (forensics rule)
- Input bytes are hostile and broken. **Never panic on input.** No `unwrap`/indexing on data from
  evidence; use checked reads (`kernel::bytes::Reader`).
- Parsers return the best partial result plus a list of `Damage`, not `Err`, when anything useful
  was recovered. `Err` is reserved for "nothing usable" and I/O failures.
- Evidence is read-only. Nothing ever opens a source for writing.

## Size and layout
- One responsibility per module; files ≲ 400 lines, split into directory modules beyond that.
- Minimal `pub` surface; re-export the public API from `lib.rs`.
- Tests next to code (`#[cfg(test)]`) with synthetic vectors; no real evidence in the repo.

## Disk budget
- Build output goes to an external target dir (`CARGO_TARGET_DIR` or a git-ignored
  `.cargo/config.toml`). Never commit images, case folders or extracted secrets.
