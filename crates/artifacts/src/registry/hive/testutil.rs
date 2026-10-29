//! Synthetic hive builder for tests.

/// 2011-05-14 17:36:09 UTC.
pub const DEFAULT_TIME: u64 = 129_498_681_690_000_000;

#[derive(Default)]
struct Node {
    name: String,
    time: u64,
    values: Vec<(String, u32, Vec<u8>)>,
    children: Vec<Node>,
}

impl Node {
    fn child(&mut self, name: &str) -> &mut Node {
        let idx = match self.children.iter().position(|c| c.name.eq_ignore_ascii_case(name)) {
            Some(i) => i,
            None => {
                self.children.push(Node { name: name.to_string(), time: DEFAULT_TIME, ..Default::default() });
                self.children.len() - 1
            }
        };
        &mut self.children[idx]
    }
}

pub struct HiveBuilder {
    root: Node,
    cells: Vec<u8>,
}

/// UTF-16LE with terminator.
pub fn sz(s: &str) -> Vec<u8> {
    s.encode_utf16().chain([0]).flat_map(u16::to_le_bytes).collect()
}

impl Default for HiveBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl HiveBuilder {
    pub fn new() -> Self {
        Self { root: Node { name: "ROOT".into(), time: DEFAULT_TIME, ..Default::default() }, cells: Vec::new() }
    }

    fn node(&mut self, path: &str) -> &mut Node {
        let mut n = &mut self.root;
        for part in path.split('\\').filter(|p| !p.is_empty()) {
            n = n.child(part);
        }
        n
    }

    pub fn key(&mut self, path: &str) -> &mut Self {
        self.node(path);
        self
    }

    pub fn key_time(&mut self, path: &str, filetime: u64) -> &mut Self {
        self.node(path).time = filetime;
        self
    }

    pub fn value(&mut self, path: &str, name: &str, kind: u32, data: &[u8]) -> &mut Self {
        self.node(path).values.push((name.to_string(), kind, data.to_vec()));
        self
    }

    /// Allocate a cell; returns its hive offset (relative to 0x1000).
    fn alloc(&mut self, payload: &[u8]) -> u32 {
        let off = 0x20 + self.cells.len();
        let size = (payload.len() + 4).div_ceil(8) * 8;
        self.cells.extend_from_slice(&(-(size as i32)).to_le_bytes());
        self.cells.extend_from_slice(payload);
        self.cells.resize(off - 0x20 + size, 0);
        off as u32
    }

    fn write_value(&mut self, name: &str, kind: u32, data: &[u8]) -> u32 {
        let (len_field, data_field) = if data.len() <= 4 {
            let mut inline = [0u8; 4];
            inline[..data.len()].copy_from_slice(data);
            (data.len() as u32 | 0x8000_0000, u32::from_le_bytes(inline))
        } else if data.len() > 16_344 {
            let segs: Vec<u32> = data.chunks(16_344).map(|c| self.alloc(c)).collect();
            let list: Vec<u8> = segs.iter().flat_map(|s| s.to_le_bytes()).collect();
            let list_off = self.alloc(&list);
            let mut db = b"db".to_vec();
            db.extend_from_slice(&(segs.len() as u16).to_le_bytes());
            db.extend_from_slice(&list_off.to_le_bytes());
            (data.len() as u32, self.alloc(&db))
        } else {
            (data.len() as u32, self.alloc(data))
        };
        let mut vk = vec![0u8; 0x14];
        vk[..2].copy_from_slice(b"vk");
        vk[2..4].copy_from_slice(&(name.len() as u16).to_le_bytes());
        vk[4..8].copy_from_slice(&len_field.to_le_bytes());
        vk[8..12].copy_from_slice(&data_field.to_le_bytes());
        vk[12..16].copy_from_slice(&kind.to_le_bytes());
        vk[16..18].copy_from_slice(&1u16.to_le_bytes());
        vk.extend_from_slice(name.as_bytes());
        self.alloc(&vk)
    }

    fn write_node(&mut self, node: &Node, root: bool) -> u32 {
        let child_offs: Vec<u32> = node.children.iter().map(|c| self.write_node(c, false)).collect();
        let subkey_list = if child_offs.is_empty() {
            u32::MAX
        } else {
            let mut lf = b"lf".to_vec();
            lf.extend_from_slice(&(child_offs.len() as u16).to_le_bytes());
            for o in &child_offs {
                lf.extend_from_slice(&o.to_le_bytes());
                lf.extend_from_slice(&[0; 4]);
            }
            self.alloc(&lf)
        };
        let value_offs: Vec<u32> = node.values.iter().map(|(n, k, d)| self.write_value(n, *k, d)).collect();
        let value_list = if value_offs.is_empty() {
            u32::MAX
        } else {
            let list: Vec<u8> = value_offs.iter().flat_map(|o| o.to_le_bytes()).collect();
            self.alloc(&list)
        };
        let mut nk = vec![0u8; 0x4C];
        nk[..2].copy_from_slice(b"nk");
        nk[2..4].copy_from_slice(&(if root { 0x2Cu16 } else { 0x20 }).to_le_bytes());
        nk[4..12].copy_from_slice(&node.time.to_le_bytes());
        nk[0x14..0x18].copy_from_slice(&(child_offs.len() as u32).to_le_bytes());
        nk[0x1C..0x20].copy_from_slice(&subkey_list.to_le_bytes());
        nk[0x24..0x28].copy_from_slice(&(value_offs.len() as u32).to_le_bytes());
        nk[0x28..0x2C].copy_from_slice(&value_list.to_le_bytes());
        nk[0x48..0x4A].copy_from_slice(&(node.name.len() as u16).to_le_bytes());
        nk.extend_from_slice(node.name.as_bytes());
        self.alloc(&nk)
    }

    pub fn build(&mut self) -> Vec<u8> {
        self.cells.clear();
        let root = std::mem::take(&mut self.root);
        let root_off = self.write_node(&root, true);
        self.root = root;
        let bin_size = (self.cells.len() + 0x20).div_ceil(0x1000) * 0x1000;
        let mut out = vec![0u8; 0x1000 + bin_size];
        out[..4].copy_from_slice(b"regf");
        out[0x24..0x28].copy_from_slice(&root_off.to_le_bytes());
        out[0x1000..0x1004].copy_from_slice(b"hbin");
        out[0x1008..0x100C].copy_from_slice(&(bin_size as u32).to_le_bytes());
        out[0x1020..0x1020 + self.cells.len()].copy_from_slice(&self.cells);
        // Trailing free cell so the bin is fully covered.
        let tail = 0x1020 + self.cells.len();
        if tail + 8 <= out.len() {
            let free = (out.len() - tail) as i32;
            out[tail..tail + 4].copy_from_slice(&free.to_le_bytes());
        }
        out
    }
}
