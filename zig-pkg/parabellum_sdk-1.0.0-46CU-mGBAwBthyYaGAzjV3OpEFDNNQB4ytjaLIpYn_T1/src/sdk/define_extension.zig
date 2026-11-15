const abi = @import("../abi/mod.zig");

pub const ExtensionMeta = struct {
    name: [*:0]const u8,
    version: abi.SemVer_ABI = .{ .major = 0, .minor = 1, .patch = 0 },
    min_engine_version: abi.SemVer_ABI = abi.common.SDK_VERSION,
    register: *const fn (
        kernel: *abi.extension.KernelHandle_ABI,
        api: *const abi.KernelApiVTable_ABI,
    ) anyerror!void,
};

/// Comptime builder that wraps a stateless extension registration function into
/// a C-ABI `ExtensionManifest_ABI` ready for `@export(..., .{ .name = "parabellum_extension_manifest" })`.
pub fn defineExtension(comptime meta: ExtensionMeta) abi.ExtensionManifest_ABI {
    const Trampoline = struct {
        fn register(
            kernel: *abi.extension.KernelHandle_ABI,
            api: *const abi.KernelApiVTable_ABI,
            out_ext_ctx: *?*anyopaque,
        ) callconv(.c) abi.HostError_ABI {
            out_ext_ctx.* = null;
            meta.register(kernel, api) catch return .internal_error;
            return .ok;
        }
    };

    return .{
        .abi_version = abi.EXTENSION_ABI_VERSION,
        .min_engine_version = meta.min_engine_version,
        .extension_name = meta.name,
        .extension_version = meta.version,
        .register = Trampoline.register,
        .deinit = null,
    };
}
