const std = @import("std");
const abi = @import("../abi/mod.zig");

pub const DriverMeta = struct {
    name: [*:0]const u8,
    version: abi.SemVer_ABI = .{ .major = 0, .minor = 1, .patch = 0 },
    min_engine_version: abi.SemVer_ABI = abi.common.SDK_VERSION,
};

/// Comptime builder that wraps an idiomatic Zig driver type `DriverType` into a
/// C-ABI `DriverManifest_ABI` ready for `@export(..., .{ .name = "parabellum_driver_manifest" })`.
///
/// `DriverType` must implement:
/// - `pub fn create(params: []const abi.ConfigParam_ABI) !*DriverType`
/// - `pub fn deinit(self: *DriverType) void`
/// - `pub fn recordCount(self: *const DriverType, table: []const u8) usize`
/// - `pub fn capabilities(self: *const DriverType) abi.DriverCapabilities_ABI`
pub fn defineDriver(comptime DriverType: type, comptime meta: DriverMeta) abi.DriverManifest_ABI {
    const Trampoline = struct {
        fn getCapabilities(repo: *const abi.driver.RepoHandle_ABI) callconv(.c) abi.DriverCapabilities_ABI {
            const self: *const DriverType = @ptrCast(@alignCast(repo));
            return self.capabilities();
        }

        fn recordCount(repo: *const abi.driver.RepoHandle_ABI, table: abi.Slice_ABI) callconv(.c) usize {
            const self: *const DriverType = @ptrCast(@alignCast(repo));
            return self.recordCount(table.toSlice());
        }

        fn deinitRepo(repo: *abi.driver.RepoHandle_ABI) callconv(.c) void {
            const self: *DriverType = @ptrCast(@alignCast(repo));
            self.deinit();
        }

        const writeRowFn: ?*const fn (repo: *abi.driver.RepoHandle_ABI, spec: *const abi.driver.WriteSpec_ABI) callconv(.c) abi.HostError_ABI = if (@hasDecl(DriverType, "writeRow"))
            struct {
                fn call(repo: *abi.driver.RepoHandle_ABI, spec: *const abi.driver.WriteSpec_ABI) callconv(.c) abi.HostError_ABI {
                    const self: *DriverType = @ptrCast(@alignCast(repo));
                    self.writeRow(spec.*) catch return .internal_error;
                    return .ok;
                }
            }.call
        else
            null;

        const readStreamFn: ?*const fn (
            repo: *abi.driver.RepoHandle_ABI,
            spec: *const abi.driver.ReadSpec_ABI,
            out_iter: *abi.driver.RowIterator_ABI,
        ) callconv(.c) abi.HostError_ABI = if (@hasDecl(DriverType, "readStream"))
            struct {
                fn call(
                    repo: *abi.driver.RepoHandle_ABI,
                    spec: *const abi.driver.ReadSpec_ABI,
                    out_iter: *abi.driver.RowIterator_ABI,
                ) callconv(.c) abi.HostError_ABI {
                    const self: *DriverType = @ptrCast(@alignCast(repo));
                    out_iter.* = self.readStream(spec.*) catch return .internal_error;
                    return .ok;
                }
            }.call
        else
            null;

        const beginTxFn: ?*const fn (repo: *abi.driver.RepoHandle_ABI) callconv(.c) abi.HostError_ABI =
            if (@hasDecl(DriverType, "beginTx"))
                struct {
                    fn call(repo: *abi.driver.RepoHandle_ABI) callconv(.c) abi.HostError_ABI {
                        const self: *DriverType = @ptrCast(@alignCast(repo));
                        self.beginTx() catch return .internal_error;
                        return .ok;
                    }
                }.call
            else
                null;

        const commitFn: ?*const fn (repo: *abi.driver.RepoHandle_ABI) callconv(.c) abi.HostError_ABI =
            if (@hasDecl(DriverType, "commit"))
                struct {
                    fn call(repo: *abi.driver.RepoHandle_ABI) callconv(.c) abi.HostError_ABI {
                        const self: *DriverType = @ptrCast(@alignCast(repo));
                        self.commit() catch return .internal_error;
                        return .ok;
                    }
                }.call
            else
                null;

        const rollbackFn: ?*const fn (repo: *abi.driver.RepoHandle_ABI) callconv(.c) abi.HostError_ABI =
            if (@hasDecl(DriverType, "rollback"))
                struct {
                    fn call(repo: *abi.driver.RepoHandle_ABI) callconv(.c) abi.HostError_ABI {
                        const self: *DriverType = @ptrCast(@alignCast(repo));
                        self.rollback() catch return .internal_error;
                        return .ok;
                    }
                }.call
            else
                null;

        const vtable = abi.StorageRepositoryVTable_ABI{
            .get_capabilities = getCapabilities,
            .record_count = recordCount,
            .deinit = deinitRepo,
            .write_row = writeRowFn,
            .read_stream = readStreamFn,
            .begin_tx = beginTxFn,
            .commit = commitFn,
            .rollback = rollbackFn,
        };

        fn createRepo(
            params_ptr: ?[*]const abi.ConfigParam_ABI,
            params_len: usize,
            out_repo: *?*abi.driver.RepoHandle_ABI,
            out_vt: *?*const abi.StorageRepositoryVTable_ABI,
        ) callconv(.c) abi.HostError_ABI {
            const params: []const abi.ConfigParam_ABI = if (params_len > 0 and params_ptr != null)
                params_ptr.?[0..params_len]
            else
                &.{};

            const instance = DriverType.create(params) catch return .internal_error;
            out_repo.* = @ptrCast(instance);
            out_vt.* = &vtable;
            return .ok;
        }
    };

    return .{
        .abi_version = abi.DRIVER_ABI_VERSION,
        .min_engine_version = meta.min_engine_version,
        .driver_name = meta.name,
        .driver_version = meta.version,
        .create_repo = Trampoline.createRepo,
    };
}
