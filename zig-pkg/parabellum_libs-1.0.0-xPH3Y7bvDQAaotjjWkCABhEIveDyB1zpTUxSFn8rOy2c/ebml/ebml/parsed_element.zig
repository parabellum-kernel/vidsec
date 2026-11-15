const std = @import("std");
const ElementHeader = @import("element_header.zig").ElementHeader;
const ElementRole = @import("element_role.zig").ElementRole;

/// Measured containment bounds of an EBML element relative to its parent or file.
pub const ContainmentMeasurement = struct {
    available_bytes: u64,
    is_truncated: bool,
    is_overflow: bool,
};

/// A fully indexed EBML element in the dissected container hierarchy (pure structural facts).
pub const DissectedElement = struct {
    region_id: u32,
    id: u32,
    parent_id: ?u32,
    depth: u16,
    path: []const u8 = "",
    header: ElementHeader,
    role: ElementRole,
    child_count: u32 = 0,
    containment: ContainmentMeasurement,

    pub fn payloadSize(self: DissectedElement) u64 {
        const hdr_sz: u64 = self.header.headerSize();
        if (self.containment.available_bytes <= hdr_sz) return 0;
        return self.containment.available_bytes - hdr_sz;
    }

    pub fn endOffset(self: DissectedElement) u64 {
        return self.header.offset +| self.containment.available_bytes;
    }
};

pub const ParsedElement = DissectedElement;
