const std = @import("std");
const c_api = @import("engine_c_api.zig");
const common = @import("../abi/common.zig");
const driver_abi = @import("../abi/driver.zig");
const ext_abi = @import("../abi/extension.zig");

pub const RunOptions = struct {
    pipeline_yaml_path: [*:0]const u8,
    dotenv_path: ?[*:0]const u8 = null,
    input_payload: ?[]const u8 = null,
    plugin_search_dir: ?[*:0]const u8 = null,
};

pub const RunSummary = struct {
    engine: *c_api.EngineHandle_ABI,
    raw: c_api.HostRunSummary_ABI,

    pub fn deinit(self: *RunSummary) void {
        c_api.parabellum_host_free_summary(self.engine, &self.raw);
    }

    pub fn outputJson(self: RunSummary) []const u8 {
        if (self.raw.output_json_len == 0 or self.raw.output_json_ptr == null) return &.{};
        return self.raw.output_json_ptr.?[0..self.raw.output_json_len];
    }

    pub fn errorMessage(self: RunSummary) []const u8 {
        if (self.raw.error_msg_len == 0 or self.raw.error_msg_ptr == null) return &.{};
        return self.raw.error_msg_ptr.?[0..self.raw.error_msg_len];
    }
};

/// Idiomatic Zig RAII wrapper around the precompiled `libparabellum_host` C-API.
pub const TestEngine = struct {
    handle: *c_api.EngineHandle_ABI,

    pub fn init() !TestEngine {
        const h = c_api.parabellum_host_create() orelse return error.EngineInitFailed;
        return .{ .handle = h };
    }

    pub fn deinit(self: *TestEngine) void {
        c_api.parabellum_host_destroy(self.handle);
    }

    pub fn registerStaticModule(self: *TestEngine, alias_z: [*:0]const u8, manifest_ptr: *const anyopaque) !void {
        const rc = c_api.parabellum_host_register_static_module(
            self.handle,
            alias_z,
            @ptrCast(manifest_ptr),
        );
        if (rc != .ok) return error.HostError;
    }

    pub fn registerStaticDriver(self: *TestEngine, name_z: [*:0]const u8, manifest: *const driver_abi.DriverManifest_ABI) !void {
        const rc = c_api.parabellum_host_register_static_driver(self.handle, name_z, manifest);
        if (rc != .ok) return error.HostError;
    }

    pub fn registerStaticExtension(self: *TestEngine, name_z: [*:0]const u8, manifest: *const ext_abi.ExtensionManifest_ABI) !void {
        const rc = c_api.parabellum_host_register_static_extension(self.handle, name_z, manifest);
        if (rc != .ok) return error.HostError;
    }

    pub fn loadPluginSo(self: *TestEngine, alias_z: [*:0]const u8, so_path_z: [*:0]const u8) !void {
        const rc = c_api.parabellum_host_load_plugin_so(self.handle, alias_z, so_path_z);
        if (rc != .ok) return error.HostError;
    }

    pub fn runPipeline(self: *TestEngine, opts: RunOptions) !RunSummary {
        var raw = c_api.HostRunSummary_ABI{};
        const c_opts = c_api.HostRunOptions_ABI{
            .pipeline_yaml_path = opts.pipeline_yaml_path,
            .dotenv_path = opts.dotenv_path,
            .input_payload_ptr = if (opts.input_payload) |p| (if (p.len > 0) p.ptr else null) else null,
            .input_payload_len = if (opts.input_payload) |p| p.len else 0,
            .plugin_search_dir = opts.plugin_search_dir,
        };
        const rc = c_api.parabellum_host_run_pipeline(self.handle, &c_opts, &raw);
        if (rc != .ok) return error.PipelineRunFailed;
        return .{
            .engine = self.handle,
            .raw = raw,
        };
    }
};
