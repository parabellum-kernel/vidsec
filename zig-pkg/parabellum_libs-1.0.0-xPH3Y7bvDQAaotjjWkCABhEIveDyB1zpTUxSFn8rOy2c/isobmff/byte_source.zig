const std = @import("std");

/// Pure, std-only random-access byte source abstraction for streaming container dissection.
pub const ByteSource = struct {
    ctx: *const anyopaque,
    read_at_fn: *const fn (ctx: *const anyopaque, buf: []u8, offset: u64) anyerror!usize,
    file_size: u64,

    pub fn readAt(self: ByteSource, buf: []u8, offset: u64) !usize {
        return self.read_at_fn(self.ctx, buf, offset);
    }

    pub fn readExactAt(self: ByteSource, buf: []u8, offset: u64) !void {
        if (offset + buf.len > self.file_size) return error.EndOfStream;
        const n = try self.readAt(buf, offset);
        if (n < buf.len) return error.EndOfStream;
    }

    pub fn fromSlicePtr(slice_ptr: *const []const u8) ByteSource {
        const Trampoline = struct {
            fn readAt(raw_ctx: *const anyopaque, buf: []u8, offset: u64) anyerror!usize {
                const s: *const []const u8 = @ptrCast(@alignCast(raw_ctx));
                if (offset >= s.len) return 0;
                const start: usize = @intCast(offset);
                const avail = s.len - start;
                const n = @min(buf.len, avail);
                @memcpy(buf[0..n], s.*[start .. start + n]);
                return n;
            }
        };
        return .{
            .ctx = @ptrCast(slice_ptr),
            .read_at_fn = &Trampoline.readAt,
            .file_size = slice_ptr.len,
        };
    }
};
