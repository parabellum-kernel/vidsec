const std = @import("std");

pub const abi = @import("abi/mod.zig");
pub const sdk = @import("sdk/mod.zig");
pub const host = @import("host/mod.zig");
pub const testing = @import("testing/mod.zig");
pub const task = @import("parabellum_abi");

test "parabellum-sdk ABI struct sizes and alignment" {
    try std.testing.expect(@sizeOf(abi.Slice_ABI) > 0);
    try std.testing.expect(@sizeOf(abi.DriverManifest_ABI) > 0);
    try std.testing.expect(@sizeOf(abi.ExtensionManifest_ABI) > 0);

    const s = abi.Slice_ABI.from("hello");
    try std.testing.expectEqualStrings("hello", s.toSlice());
    try std.testing.expectEqualStrings("", abi.Slice_ABI.empty.toSlice());

    const engine_v = abi.SemVer_ABI{ .major = 0, .minor = 2, .patch = 0 };
    try std.testing.expect(engine_v.satisfies(.{ .major = 0, .minor = 1, .patch = 0 }));
    try std.testing.expect(!engine_v.satisfies(.{ .major = 0, .minor = 3, .patch = 0 }));
    try std.testing.expect(!engine_v.satisfies(.{ .major = 1, .minor = 0, .patch = 0 }));
}

test {
    _ = testing.task_harness;
}
