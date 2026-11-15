const std = @import("std");
const abi = @import("../abi/mod.zig");

/// Runs a basic C-ABI conformance suite against any `DriverManifest_ABI`.
pub fn runDriverConformanceSuite(
    manifest: *const abi.DriverManifest_ABI,
    params: []const abi.ConfigParam_ABI,
) !void {
    try std.testing.expectEqual(abi.DRIVER_ABI_VERSION, manifest.abi_version);
    try std.testing.expect(manifest.nameSlice().len > 0);

    var repo: ?*abi.driver.RepoHandle_ABI = null;
    var vtable: ?*const abi.StorageRepositoryVTable_ABI = null;
    const rc = manifest.create_repo(
        if (params.len > 0) params.ptr else null,
        params.len,
        &repo,
        &vtable,
    );
    try std.testing.expectEqual(abi.HostError_ABI.ok, rc);
    try std.testing.expect(repo != null);
    try std.testing.expect(vtable != null);
    defer vtable.?.deinit(repo.?);

    _ = vtable.?.get_capabilities(repo.?);
    _ = vtable.?.record_count(repo.?, abi.Slice_ABI.from("__conformance_test__"));
}
