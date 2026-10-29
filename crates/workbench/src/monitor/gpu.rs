//! Strata's own GPU use (the renderer) from the Windows performance counters Task Manager
//! uses: `GPU Engine(pid_N*)\Utilization Percentage` and `GPU Process Memory(pid_N*)\Dedicated
//! Usage`. Anything that fails makes the probe report "not available"; it never errors.

/// One GPU reading of the process.
#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct GpuReading {
    /// Busiest engine type, 0..=100 (how Task Manager reports a process).
    pub utilization: Option<f32>,
    pub dedicated_bytes: Option<u64>,
}

/// Utilization per engine instance → the process figure: per engine type the sum of its
/// engines, then the busiest type.
pub fn busiest_engine<'a>(instances: impl IntoIterator<Item = (&'a str, f64)>) -> Option<f32> {
    let mut by_type: std::collections::HashMap<&str, f64> = std::collections::HashMap::new();
    for (name, value) in instances {
        let ty = name.rsplit_once("engtype_").map_or("", |(_, t)| t);
        *by_type.entry(ty).or_default() += value;
    }
    by_type.values().copied().fold(None, |m: Option<f64>, v| Some(m.map_or(v, |m| m.max(v)))).map(|v| v.clamp(0.0, 100.0) as f32)
}

#[cfg(windows)]
pub use pdh::GpuProbe;

#[cfg(windows)]
mod pdh {
    use super::{GpuReading, busiest_engine};
    use windows_sys::Win32::System::Performance::{
        PDH_FMT, PDH_FMT_COUNTERVALUE_ITEM_W, PDH_FMT_DOUBLE, PDH_FMT_LARGE, PDH_HCOUNTER, PDH_HQUERY, PDH_MORE_DATA,
        PdhAddEnglishCounterW, PdhCloseQuery, PdhCollectQueryData, PdhGetFormattedCounterArrayW, PdhOpenQueryW,
    };

    pub struct GpuProbe {
        query: PDH_HQUERY,
        engines: PDH_HCOUNTER,
        memory: PDH_HCOUNTER,
    }

    // SAFETY: PDH query handles may be used from any thread; the probe is used by one at a time.
    unsafe impl Send for GpuProbe {}

    fn wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(std::iter::once(0)).collect()
    }

    impl GpuProbe {
        /// `None` when the counters do not exist (no WDDM 2 GPU, counters disabled).
        pub fn open(pid: u32) -> Option<Self> {
            let mut query: PDH_HQUERY = std::ptr::null_mut();
            // SAFETY: out-pointer is a live local; a null data source means live data.
            if unsafe { PdhOpenQueryW(std::ptr::null(), 0, &mut query) } != 0 {
                return None;
            }
            let add = |path: String| {
                let mut counter: PDH_HCOUNTER = std::ptr::null_mut();
                let path = wide(&path);
                // SAFETY: valid query, NUL-terminated path, live out-pointer.
                (unsafe { PdhAddEnglishCounterW(query, path.as_ptr(), 0, &mut counter) } == 0).then_some(counter)
            };
            let engines = add(format!(r"\GPU Engine(pid_{pid}_*)\Utilization Percentage"));
            let memory = add(format!(r"\GPU Process Memory(pid_{pid}_*)\Dedicated Usage"));
            match (engines, memory) {
                (Some(engines), Some(memory)) => {
                    let probe = Self { query, engines, memory };
                    // SAFETY: valid query; the first collection primes rate counters.
                    unsafe { PdhCollectQueryData(query) };
                    Some(probe)
                }
                _ => {
                    // SAFETY: closing the query opened above.
                    unsafe { PdhCloseQuery(query) };
                    None
                }
            }
        }

        pub fn sample(&mut self) -> GpuReading {
            // SAFETY: valid query.
            if unsafe { PdhCollectQueryData(self.query) } != 0 {
                return GpuReading::default();
            }
            let engines = values(self.engines, PDH_FMT_DOUBLE);
            let memory = values(self.memory, PDH_FMT_LARGE);
            GpuReading {
                utilization: engines.map(|e| busiest_engine(e.iter().map(|(n, v)| (n.as_str(), *v))).unwrap_or(0.0)),
                dedicated_bytes: memory.map(|m| m.iter().map(|(_, v)| v.max(0.0) as u64).sum()),
            }
        }
    }

    impl Drop for GpuProbe {
        fn drop(&mut self) {
            // SAFETY: the query is closed once; counters close with it.
            unsafe { PdhCloseQuery(self.query) };
        }
    }

    /// Every instance of a wildcard counter as `(instance name, value)`; `None` on failure.
    fn values(counter: PDH_HCOUNTER, format: PDH_FMT) -> Option<Vec<(String, f64)>> {
        let (mut size, mut count) = (0u32, 0u32);
        // SAFETY: sizing call with a null buffer, as documented.
        let status = unsafe { PdhGetFormattedCounterArrayW(counter, format, &mut size, &mut count, std::ptr::null_mut()) };
        if status != PDH_MORE_DATA {
            return (status == 0).then(Vec::new);
        }
        // Items followed by their names; u64 words keep the items aligned.
        let mut buffer = vec![0u64; (size as usize).div_ceil(8) + 1];
        let items = buffer.as_mut_ptr().cast::<PDH_FMT_COUNTERVALUE_ITEM_W>();
        // SAFETY: the buffer holds at least `size` bytes, aligned for the item type.
        if unsafe { PdhGetFormattedCounterArrayW(counter, format, &mut size, &mut count, items) } != 0 {
            return None;
        }
        let mut out = Vec::with_capacity(count as usize);
        for i in 0..count as usize {
            // SAFETY: PDH wrote `count` items into the buffer; names point into the same buffer
            // and are NUL-terminated.
            let (name, value) = unsafe {
                let item = &*items.add(i);
                if item.FmtValue.CStatus != 0 {
                    continue;
                }
                let value = if format == PDH_FMT_LARGE {
                    item.FmtValue.Anonymous.largeValue as f64
                } else {
                    item.FmtValue.Anonymous.doubleValue
                };
                let mut len = 0;
                while !item.szName.is_null() && *item.szName.add(len) != 0 {
                    len += 1;
                }
                let name = if item.szName.is_null() { String::new() } else { String::from_utf16_lossy(std::slice::from_raw_parts(item.szName, len)) };
                (name, value)
            };
            out.push((name, value));
        }
        Some(out)
    }
}

#[cfg(not(windows))]
pub struct GpuProbe;

#[cfg(not(windows))]
impl GpuProbe {
    pub fn open(_pid: u32) -> Option<Self> {
        None
    }

    pub fn sample(&mut self) -> GpuReading {
        GpuReading::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn process_utilization_is_the_busiest_engine_type() {
        let engines = [
            ("pid_1_luid_0x0_0x1_phys_0_eng_0_engtype_3D", 12.0),
            ("pid_1_luid_0x0_0x1_phys_0_eng_1_engtype_3D", 5.0),
            ("pid_1_luid_0x0_0x1_phys_0_eng_4_engtype_Copy", 9.0),
            ("pid_1_luid_0x0_0x1_phys_0_eng_5_engtype_VideoDecode", 0.0),
        ];
        assert_eq!(busiest_engine(engines), Some(17.0));
        assert_eq!(busiest_engine([]), None);
        assert_eq!(busiest_engine([("x_engtype_3D", 250.0)]), Some(100.0));
    }

    #[cfg(windows)]
    #[test]
    fn probe_never_fails() {
        // Counters may be missing on CI machines; opening must still not panic.
        if let Some(mut probe) = GpuProbe::open(std::process::id()) {
            let _ = probe.sample();
        }
    }
}
