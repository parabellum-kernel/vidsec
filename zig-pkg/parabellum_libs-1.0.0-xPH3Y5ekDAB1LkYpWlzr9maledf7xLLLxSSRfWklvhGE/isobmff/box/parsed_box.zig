const FourCC = @import("fourcc.zig").FourCC;
const BoxRole = @import("box_role.zig").BoxRole;

/// Physical containment measurement of a dissected box against its enclosing parent/EOF.
pub const ContainmentMeasurement = struct {
    claimed_bytes: u64,
    available_bytes: u64,
    is_truncated: bool,
    is_overflow: bool,
};

/// Flattened representation of a dissected ISOBMFF box with hierarchical path and physical bounds.
pub const DissectedBox = struct {
    id: u32,
    parent_id: ?u32,
    depth: u16,
    fourcc: FourCC,
    path: []const u8,
    header_offset: u64,
    payload_offset: u64,
    declared_size: u64,
    header_size: u8,
    is_extended_size: bool = false,
    is_eof_size: bool = false,
    is_full_box: bool = false,
    version: u8 = 0,
    flags: u24 = 0,
    role: BoxRole = .unknown,
    child_count: u32 = 0,
    containment: ContainmentMeasurement,

    pub fn payloadSize(self: DissectedBox) u64 {
        return self.containment.available_bytes -| self.header_size;
    }

    pub fn endOffset(self: DissectedBox) u64 {
        return self.header_offset +| self.declared_size;
    }
};

pub const ParsedBox = DissectedBox;
