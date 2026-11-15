const std = @import("std");
const sdk = @import("parabellum_sdk");
const catalog = @import("catalog");

test "Tier 2 Host E2E: libparabellum_host initializes and registers analyzer manifest" {
    const ver = sdk.host.c_api.parabellum_host_version();
    try std.testing.expectEqual(@as(u32, 1), ver.major);

    var engine = try sdk.host.TestEngine.init();
    defer engine.deinit();

    try engine.registerStaticModule("analyzer", &catalog.manifest);
    try std.testing.expectEqual(@as(usize, 3), catalog.manifest.requiresSlice().len);
}
