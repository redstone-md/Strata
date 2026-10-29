//! Shell namespace GUIDs (root folder items and known folders) as display names. Data table.

/// (GUID, display name). Upper case, braces included, as `text::guid_at` formats them.
const ROOTS: &[(&str, &str)] = &[
    ("{20D04FE0-3AEA-1069-A2D8-08002B30309D}", "My Computer"),
    ("{450D8FBA-AD25-11D0-98A8-0800361B1103}", "My Documents"),
    ("{208D2C60-3AEA-1069-A2D7-08002B30309D}", "My Network Places"),
    ("{F02C1A0D-BE21-4350-88B0-7367FC96EF3C}", "Network"),
    ("{871C5380-42A0-1069-A2EA-08002B30309D}", "Internet Explorer"),
    ("{645FF040-5081-101B-9F08-00AA002F954E}", "Recycle Bin"),
    ("{21EC2020-3AEA-1069-A2DD-08002B30309D}", "Control Panel"),
    ("{26EE0668-A00A-44D7-9371-BEB064C98683}", "Control Panel"),
    ("{59031A47-3F72-44A7-89C5-5595FE6B30EE}", "User Files"),
    ("{031E4825-7B94-4DC3-B131-E946B44C8DD5}", "Libraries"),
    ("{374DE290-123F-4565-9164-39C4925E467B}", "Downloads"),
    ("{088E3905-0323-4B02-9826-5D99428E115F}", "Downloads"),
    ("{B4BFCC3A-DB2C-424C-B029-7FE99A87C641}", "Desktop"),
    ("{FDD39AD0-238F-46AF-ADB4-6C85480369C7}", "Documents"),
    ("{D3162B92-9365-467A-956B-92703ACA08AF}", "Documents"),
    ("{1CF1260C-4DD0-4EBB-811F-33C572699FDE}", "Music"),
    ("{3ADD1653-EB32-4CB0-BBD7-DFA0ABB5ACCA}", "Pictures"),
    ("{24AD3AD4-A569-4530-98E1-AB02F9417AA8}", "Pictures"),
    ("{A0953C92-50DC-43BF-BE83-3742FED03C9C}", "Videos"),
    ("{018D5C66-4533-4307-9B53-224DE2ED1FE6}", "OneDrive"),
    ("{679F85CB-0220-4080-B29B-5540CC05AAB6}", "Quick Access"),
    ("{35786D3C-B075-49B9-88DD-029876E11C01}", "Portable Devices"),
];

/// Display name of a root folder / known folder GUID; unknown GUIDs are shown as-is.
pub(super) fn root_name(guid: &str) -> String {
    ROOTS.iter().find(|(g, _)| g.eq_ignore_ascii_case(guid)).map_or_else(|| guid.to_string(), |(_, n)| (*n).to_string())
}

/// Roots under which every item is a device rather than a disk folder.
pub(super) fn is_device_root(name: &str) -> bool {
    name == "Portable Devices"
}
