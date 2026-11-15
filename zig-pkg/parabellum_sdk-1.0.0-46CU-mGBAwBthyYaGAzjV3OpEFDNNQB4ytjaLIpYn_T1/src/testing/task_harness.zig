const std = @import("std");
const Allocator = std.mem.Allocator;

/// Pure-Zig in-memory unit test harness for Parabellum tasks and drivers.
/// Allows testing tasks in isolation with `std.testing.allocator` leak detection
/// and zero external engine binaries.
pub const TaskHarness = struct {
    allocator: Allocator,
    input_stream: []const u8 = &.{},
    params: std.StringHashMapUnmanaged([]const u8) = .{},
    logs: std.ArrayListUnmanaged([]u8) = .empty,

    pub fn init(allocator: Allocator) TaskHarness {
        return .{ .allocator = allocator };
    }

    pub fn deinit(self: *TaskHarness) void {
        var it = self.params.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            self.allocator.free(entry.value_ptr.*);
        }
        self.params.deinit(self.allocator);

        for (self.logs.items) |msg| {
            self.allocator.free(msg);
        }
        self.logs.deinit(self.allocator);
    }

    pub fn setInputStream(self: *TaskHarness, bytes: []const u8) void {
        self.input_stream = bytes;
    }

    pub fn setParam(self: *TaskHarness, key: []const u8, value: []const u8) !void {
        const k = try self.allocator.dupe(u8, key);
        errdefer self.allocator.free(k);
        const v = try self.allocator.dupe(u8, value);
        errdefer self.allocator.free(v);
        try self.params.put(self.allocator, k, v);
    }

    pub fn getParam(self: *const TaskHarness, key: []const u8) ?[]const u8 {
        return self.params.get(key);
    }

    pub fn appendLog(self: *TaskHarness, msg: []const u8) !void {
        const copy = try self.allocator.dupe(u8, msg);
        try self.logs.append(self.allocator, copy);
    }
};

test "TaskHarness in-memory params and logs" {
    var h = TaskHarness.init(std.testing.allocator);
    defer h.deinit();

    h.setInputStream("hello-stream");
    try h.setParam("mode", "fast");
    try h.appendLog("step started");

    try std.testing.expectEqualStrings("hello-stream", h.input_stream);
    try std.testing.expectEqualStrings("fast", h.getParam("mode").?);
    try std.testing.expectEqual(@as(usize, 1), h.logs.items.len);
}
