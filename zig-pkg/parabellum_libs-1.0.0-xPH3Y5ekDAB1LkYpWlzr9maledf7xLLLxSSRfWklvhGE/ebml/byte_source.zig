const std = @import("std");

/// Generic random-access byte stream abstraction (`std`-only, zero external deps).
pub const ByteSource = struct {
    ctx: *const anyopaque,
    read_at_fn: *const fn (ctx: *const anyopaque, buf: []u8, offset: u64) anyerror!usize,
    file_size: u64,

    pub fn readAt(self: ByteSource, buf: []u8, offset: u64) !usize {
        return self.read_at_fn(self.ctx, buf, offset);
    }

    pub fn readExactAt(self: ByteSource, buf: []u8, offset: u64) !void {
        if (offset +| buf.len > self.file_size) return error.UnexpectedEof;
        const n = try self.readAt(buf, offset);
        if (n < buf.len) return error.UnexpectedEof;
    }

    pub fn fromSlicePtr(slice_ptr: *const []const u8) ByteSource {
        const SliceReader = struct {
            fn read(ctx: *const anyopaque, buf: []u8, offset: u64) anyerror!usize {
                const s: *const []const u8 = @ptrCast(@alignCast(ctx));
                if (offset >= s.len) return 0;
                const avail = s.len - @as(usize, @intCast(offset));
                const to_copy = @min(avail, buf.len);
                @memcpy(buf[0..to_copy], s.*[@intCast(offset)..][0..to_copy]);
                return to_copy;
            }
        };
        return .{
            .ctx = @ptrCast(slice_ptr),
            .read_at_fn = SliceReader.read,
            .file_size = slice_ptr.len,
        };
    }
};

