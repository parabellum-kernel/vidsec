const std = @import("std");
const DissectedBox = @import("parsed_box.zig").DissectedBox;

/// Pure structural output of `SafeBoxParser.parse`.
pub const ParseResult = struct {
    allocator: std.mem.Allocator,
    boxes: []DissectedBox,
    highest_root_end: u64,
    truncated_tail_offset: ?u64 = null,
    has_ftyp: bool,
    has_moov: bool,
    ftyp_count: u32,
    moov_count: u32,

    pub fn deinit(self: *ParseResult) void {
        for (self.boxes) |b| {
            self.allocator.free(b.path);
        }
        self.allocator.free(self.boxes);
    }
};
