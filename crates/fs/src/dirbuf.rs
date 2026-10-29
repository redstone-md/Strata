//! Directory bytes gathered from scattered clusters, remembering where each piece lives.

/// Directory bytes plus where each piece came from on the volume.
#[derive(Default)]
pub(crate) struct DirBuffer {
    bytes: Vec<u8>,
    pieces: Vec<(usize, u64)>,
}

impl DirBuffer {
    pub(crate) fn push(&mut self, volume_offset: u64, data: &[u8]) {
        self.pieces.push((self.bytes.len(), volume_offset));
        self.bytes.extend_from_slice(data);
    }

    pub(crate) fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Volume offset of byte `pos` of the buffer.
    pub(crate) fn volume_offset(&self, pos: usize) -> u64 {
        let i = self.pieces.partition_point(|p| p.0 <= pos).saturating_sub(1);
        self.pieces.get(i).map_or(0, |(start, vol)| vol + (pos - start) as u64)
    }
}
