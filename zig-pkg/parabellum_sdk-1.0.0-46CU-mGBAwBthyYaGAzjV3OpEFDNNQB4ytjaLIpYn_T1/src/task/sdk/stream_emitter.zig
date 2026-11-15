const std = @import("std");
const TaskContext = @import("task_context.zig").TaskContext;
const SdkError = @import("sdk_error.zig").SdkError;
const mapHostError = @import("map_host_error.zig").mapHostError;

/// Marker struct returned by `StreamEmitter.finish()` and recognized by `defineTaskService`
/// inside `Channels(T)` so stream channels are not re-emitted as scalar rows.
pub const StreamOutput = struct {
    pub const is_parabellum_stream_output = true;
    finalized: bool = true,
};

/// Guest SDK handle for emitting streaming byte outputs (literal chunks, zero-copy input splices,
/// and virtual zero padding) across the C-ABI without materializing large buffers in guest memory.
pub const StreamEmitter = struct {
    ctx: TaskContext,
    channel_name: [:0]const u8 = "stream",

    pub fn init(ctx: TaskContext, channel_name: [:0]const u8) StreamEmitter {
        return .{
            .ctx = ctx,
            .channel_name = channel_name,
        };
    }

    pub fn writeChunk(self: StreamEmitter, bytes: []const u8) SdkError!void {
        if (bytes.len == 0) return;
        const f = self.ctx.raw.host.stream_write_chunk orelse return error.InvalidOperation;
        const err = f(self.ctx.raw, self.channel_name.ptr, bytes.ptr, bytes.len);
        if (err != .ok) try mapHostError(err);
    }

    pub fn splice(self: StreamEmitter, offset: u64, length: u64) SdkError!void {
        if (length == 0) return;
        const f = self.ctx.raw.host.stream_splice orelse return error.InvalidOperation;
        const err = f(self.ctx.raw, self.channel_name.ptr, offset, length);
        if (err != .ok) try mapHostError(err);
    }

    pub fn padZeroes(self: StreamEmitter, length: u64) SdkError!void {
        if (length == 0) return;
        const f = self.ctx.raw.host.stream_pad_zeroes orelse return error.InvalidOperation;
        const err = f(self.ctx.raw, self.channel_name.ptr, length);
        if (err != .ok) try mapHostError(err);
    }

    pub fn finish(self: StreamEmitter) SdkError!StreamOutput {
        const f = self.ctx.raw.host.stream_finish orelse return error.InvalidOperation;
        const err = f(self.ctx.raw, self.channel_name.ptr);
        if (err != .ok) try mapHostError(err);
        return .{ .finalized = true };
    }
};
