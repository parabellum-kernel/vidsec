const std = @import("std");
const Allocator = std.mem.Allocator;
const DissectedElement = @import("parsed_element.zig").DissectedElement;

/// Result of dissecting an EBML container stream (pure structural facts, no policy judgments).
pub const EbmlParseResult = struct {
    allocator: Allocator,
    elements: []const DissectedElement,
    doc_type: []const u8,
    doc_type_version: u32,
    has_ebml_header: bool,
    has_segment: bool,
    cluster_count: u32,
    total_cluster_bytes: u64,
    highest_root_end: u64,
    header_truncated_at: ?u64 = null,

    pub fn deinit(self: *EbmlParseResult) void {
        for (self.elements) |e| {
            if (e.path.len > 0) self.allocator.free(e.path);
        }
        self.allocator.free(self.elements);
        if (self.doc_type.len > 0) {
            self.allocator.free(self.doc_type);
        }
    }
};
