const std = @import("std");
const Allocator = std.mem.Allocator;
const FourCC = @import("fourcc.zig").FourCC;
const DissectedChunk = @import("parsed_chunk.zig").DissectedChunk;

/// Result of dissecting a RIFF container stream (pure structural facts, no policy judgments).
pub const RiffParseResult = struct {
    allocator: Allocator,
    chunks: []const DissectedChunk,
    form_type: FourCC,
    root_size: u32,
    is_valid_root_magic: bool = true,
    movi_bytes: u64,
    junk_bytes: u64,
    highest_root_end: u64,
    header_truncated_at: ?u64 = null,

    pub fn deinit(self: *RiffParseResult) void {
        for (self.chunks) |c| {
            if (c.path.len > 0) self.allocator.free(c.path);
        }
        self.allocator.free(self.chunks);
    }
};
