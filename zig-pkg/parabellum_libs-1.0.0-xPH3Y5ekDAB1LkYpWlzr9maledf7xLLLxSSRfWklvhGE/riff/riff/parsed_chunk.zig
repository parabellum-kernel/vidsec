const ChunkHeader = @import("chunk_header.zig").ChunkHeader;
const ChunkRole = @import("chunk_role.zig").ChunkRole;

/// Measured containment bounds of a RIFF chunk relative to its parent or file.
pub const ContainmentMeasurement = struct {
    available_bytes: u64,
    is_truncated: bool,
    is_overflow: bool,
};

/// An indexed chunk in the dissected RIFF container hierarchy (pure structural facts).
pub const DissectedChunk = struct {
    id: u32,
    parent_id: ?u32,
    depth: u16,
    path: []const u8 = "",
    header: ChunkHeader,
    role: ChunkRole,
    child_count: u32 = 0,
    containment: ContainmentMeasurement,

    pub fn payloadSize(self: DissectedChunk) u64 {
        const hdr_sz: u64 = self.header.headerSize();
        if (self.containment.available_bytes <= hdr_sz) return 0;
        return self.containment.available_bytes - hdr_sz;
    }

    pub fn endOffset(self: DissectedChunk) u64 {
        return self.header.offset +| self.containment.available_bytes;
    }
};

pub const ParsedChunk = DissectedChunk;
