# R-Studio scan file (`.scn`) — what Strata decodes

Reverse-engineered from scan files written by R-Studio 9 for whole-disk scans. Structure only;
no values from real files appear here. Confidence: **high** = holds for every group of every
file examined, **medium** = consistent but with few samples or an inferred meaning,
**low** = guess, not used for anything that matters.

All integers are little-endian. Four-character tags are stored as little-endian FourCCs, so
they read backwards on disk (`TONI`, `OOGR`, `TRAP` = PART). Below, tags are written as they
appear on disk unless marked "readable".

## Header (high)

| Offset | Size | Meaning |
|-------:|-----:|---------|
| 0x00 | 0x70 | Fixed signature block, identical in every file. Strata does not check it. |
| 0x70 | 4 | Format version (1). |
| 0x74 | 12 | Zero. |

## Groups (high)

From 0x80 to the end of file the file is a sequence of groups:

| Offset | Size | Meaning |
|-------:|-----:|---------|
| 0 | 4 | Group size including this 16-byte header |
| 4 | 4 | Tag |
| 8 | 4 | Sub-tag (zero, or `u16 kind` + 2-char element tag for `HS\0\0` groups) |
| 12 | 4 | CRC-32 (zlib polynomial) of the payload |
| 16 | size − 16 | Payload |

Every group of every examined file passes the CRC and the chain ends exactly at end of file.
The reader skips a group whose CRC fails by searching for the next intact group with a known
tag and reports the skipped span as damage.

Tags seen: `TONI` (object), `ESNI` (the scanned object, appears once), `OOGR` (progress mark),
`HS\0\0` (scan elements). Groups are not compressed.

## Object groups `TONI` / `ESNI` (high for framing, medium for property meanings)

Payload: property records, terminated by a record whose length is `0xFFFFFFFF`:

| Offset | Size | Meaning |
|-------:|-----:|---------|
| 0 | 4 | Object id (same in every record of the group) |
| 4 | 4 | Property id |
| 8 | 4 | Property class (stored backwards: `ESAB` BASE, `TRAP` PART, `EZIS` SIZE, `AVRD` DRVA, `SFCR` RCFS, `SFTN` NTFS, `XTAF` FATX, `TNDI` IDNT, `TSUC` CUST, `PMOC` COMP...) |
| 12 | 4 | Flags |
| 16 | 4 | Value length |
| 20 | len | Value (integers, UTF-16LE strings, raw sector copies) |

The groups form R-Studio's device tree: the computer, every attached disk and its partitions,
not only the scanned device. Properties Strata uses (readable class, property id):

| Property | Meaning | Confidence |
|----------|---------|-----------|
| DRVA 0x02 | Object id | high |
| DRVA 0x10 | Parent object id | high |
| PART 0x02 | Partition start (bytes, relative to the parent) | high for direct children of the disk; nesting is assumed relative |
| PART 0x01 | Partition size (bytes) | high |
| PART 0x201 | MBR partition type byte | medium |
| SIZE 0x01 / SIZE 0x02 | Object size / sector size | high |
| RCFS 0x01 | Filesystem name (`NTFS`, `FAT32`, `Ext4`...) | high |
| BASE 0x20 | Display name | high |

The `ESNI` group is the scanned device. Strata takes as volume candidates the partition
objects that descend from it (by parent id), dropping duplicates and any that run past the
disk end. Other properties (partition-table sector copies, drive identify data, computer
description, custom attributes) are not interpreted.

## Progress marks `OOGR` (high)

Payload 16 bytes: `u64 0 | u64 bytes scanned so far`. Marks are written periodically and
increase; the last one equals the disk size on a finished scan.

## Scan elements `HS\0\0` (framing high)

The sub-tag holds `u16 kind` and a 2-character element tag (readable `TF`, `TN`, `AF`...).
Element groups appear in scan order between progress marks.

### File types `TF`, kind 4 (high)

The payloads of all kind-4 `TF` groups form one byte stream; entries cross group boundaries.
Entry:

| Field | Size | Meaning |
|-------|-----:|---------|
| flags | 1 | `0x60` always set; bits 0–1 sector field width (3, 4, 5, 8 bytes; 5 and 8 assumed, not seen); bits 2–3 size field width (2, 3, 4, 8); `0x80` details follow |
| group | 1 | R-Studio file-type group (0..=15) |
| sector | var | Absolute start sector (sector size of the scanned device) |
| size | var | File size in bytes as estimated by R-Studio |
| tag | 4 | File type, stored backwards (`GPJ\0` = JPG, `ATXT` = TXTA ANSI text, `UTXT` = TXTU Unicode text, `LDEP` = PEDL...) |
| type id | 2 | Internal type number |
| details | var | Only with flag `0x80`: `u8 mask`, then per bit: `0x01` u32 time stamp, `0x02` u16 width + u16 height + u16 depth, `0x04` u16, `0x08` 8 bytes, `0x10` string (`u8 length+1`, `u8 kind`, bytes) |

With this grammar the streams of all three examined files decode with zero undecoded bytes.
A mask with other bits set is not decodable; the reader then skips forward byte by byte to
the next valid entry and reports the number of skipped bytes. Starts are file starts found by
signature, including files inside live files; text types mark runs of text.

Strata maps unambiguous tags to its own types (`crates/index/src/scn/types.rs`) and records
them as R-Studio-sourced signature hits; other tags only flag the block. Text runs seed text
blocks. The meaning of the second byte, the type id and the detail values is not used.

### NTFS boot sector `TN`, kind 3 (high)

48-byte records: `u32 cluster size | u32 MFT record size | u64 $MFT offset | u64 $MFTMirr
offset | u32 index record size | u32 sector size | u64 volume size | u64 absolute offset of
the boot sector`. The record may describe the primary boot sector or the backup in the
volume's last sector; Strata offers both readings (start = offset, start = offset − volume
size) and keeps the one its own boot-sector check accepts.

### FAT boot sector `AF`, kind 3 (medium)

80-byte records. Decoded: `u32 FAT width (12/16/32)` at 0 and `u64 absolute offset of the
boot sector` at 72. The fields between hold layout values (cluster size, FAT and root
directory positions, sector size at 52) whose exact order is not confirmed; the volume length
is taken from our own boot-sector check instead.

### End of scan `TF`, kind 2 (medium)

One group at the very end: `u64 0 | u64 scanned end | u64 0`. Not needed (progress marks
carry the same value).

## Not decoded

Present in the examined files, structure only partly understood, not used:

| Element | Observed shape | Probable meaning (low) |
|---------|----------------|------------------------|
| `TN` 10 | 28-byte records: u64 offset, u64 number, u32 length, u64 | Runs of NTFS MFT records |
| `TN` 11, 12, 13 | Variable | NTFS index / directory structures |
| `AF` 1, 7 | Variable | FAT directory entries / chains |
| `XE` 9, 11 | Variable; kind 11 contains block size and block count | ext2/3/4 superblocks and group descriptors (the location field is not identified, so ext candidates are not imported) |
| `FH` 4, 5; `FU` 5; `FX` 1, 2 | Variable | Other filesystems' metadata (HFS, UFS, XFS by analogy) |
| `PA` 3, 5, 10 | Variable | Partition-table related records |
| `RZ` 1 | Pairs of u64 (offset, length) | Regions; meaning unknown |
| `TF` 5 | 16 bytes | Unknown; also referenced from the scanned object |

The reader lists every element kind it does not interpret in `ScnMetadata::undecoded`, so a
new R-Studio version shows up as such rather than being misread.
