const std = @import("std");
const parabellum = @import("parabellum");
const sdk = @import("parabellum_sdk");
const yaml_config = @import("yaml_config");
const abi = sdk.abi;
const tui_app = @import("tui_app.zig");

extern const parabellum_module_vidsec_manifest: parabellum.plugin.ModuleManifest_ABI;
extern const parabellum_driver_memory_manifest: abi.DriverManifest_ABI;
extern const parabellum_driver_file_store_manifest: abi.DriverManifest_ABI;
extern const parabellum_driver_sqlite_manifest: abi.DriverManifest_ABI;
extern const parabellum_extension_opentelemetry_manifest: abi.ExtensionManifest_ABI;
extern const parabellum_extension_trace_jsonl_manifest: abi.ExtensionManifest_ABI;
extern const parabellum_extension_yaml_config_manifest: abi.ExtensionManifest_ABI;
extern const parabellum_extension_tui_inbound_manifest: abi.ExtensionManifest_ABI;

fn registerVidsecDrivers(repos: *parabellum.repository.RepositoryRegistry) anyerror!void {
    try repos.registerAbiDriver("memory", &parabellum_driver_memory_manifest);
    try repos.registerAbiDriver("file_store", &parabellum_driver_file_store_manifest);
    try repos.registerAbiDriver("sqlite", &parabellum_driver_sqlite_manifest);
}

fn writeStdout(msg: []const u8) void {
    _ = std.c.write(std.c.STDOUT_FILENO, msg.ptr, msg.len);
}

fn writeStderr(msg: []const u8) void {
    _ = std.c.write(std.c.STDERR_FILENO, msg.ptr, msg.len);
}

fn abiDispatchTrampoline(
    host_dispatcher: *anyopaque,
    req: *const abi.extension.InboundRequest_ABI,
    out_resp: *abi.extension.InboundResponse_ABI,
) callconv(.c) abi.common.HostError_ABI {
    const d: *parabellum.transport.inbound.InboundDispatcher = @ptrCast(@alignCast(host_dispatcher));
    const route = req.command_or_route.toSlice();
    const payload = req.payload.toSlice();
    const args_json = req.args_json.toSlice();

    var is_custom = false;
    var job_input = false;
    if (args_json.len > 0) {
        is_custom = std.mem.indexOf(u8, args_json, "\"custom\":true") != null;
        job_input = std.mem.indexOf(u8, args_json, "\"input\":\"job_json\"") != null;
    }

    const cmd = if (is_custom)
        parabellum.transport.inbound.contracts.InvocationCommand.custom
    else
        parabellum.transport.inbound.contracts.InvocationCommand.fromString(route) orelse .custom;

    const resp = d.handle(.{
        .command = cmd,
        .custom_command_name = if (cmd == .custom) route else "",
        .options = .{ .load_shared_modules = false },
        .input = if (payload.len == 0)
            .none
        else if (job_input or payload[0] == '{')
            .{ .job_json = payload }
        else
            .{ .file_path = payload },
    }) catch return .internal_error;
    out_resp.* = .{
        .status_code = if (resp.exit_code == 0) 200 else 500,
        .body = abi.Slice_ABI.from(if (resp.output_bytes.len > 0) resp.output_bytes else resp.message),
    };
    return .ok;
}

fn registerTuiTelemetry(k: *abi.extension.KernelHandle_ABI, api: *const abi.KernelApiVTable_ABI) anyerror!void {
    _ = api.subscribe_telemetry(k, @ptrCast(&tui_app.transport_ctx_marker), &tui_app.telemetry_sub_vtable);
}

const tui_telemetry_manifest = sdk.extension.Extension.define(.{
    .name = "vidsec_tui_telemetry",
    .version = .{ .major = 2, .minor = 0, .patch = 2 },
    .register = registerTuiTelemetry,
});

pub fn main(init: std.process.Init) !u8 {
    const allocator = init.gpa;
    const arena = init.arena.allocator();
    const args = try init.minimal.args.toSlice(arena);

    if (args.len >= 2 and (std.mem.eql(u8, args[1], "--version") or std.mem.eql(u8, args[1], "-V"))) {
        writeStdout("vidsec_tui 2.0.2 (tui monolith)\n");
        return 0;
    }

    var kernel = try parabellum.kernel.KernelContext.init(allocator);
    defer kernel.deinit();

    const static_exts = [_]*const abi.ExtensionManifest_ABI{
        &parabellum_extension_opentelemetry_manifest,
        &parabellum_extension_trace_jsonl_manifest,
        &parabellum_extension_yaml_config_manifest,
        &parabellum_extension_tui_inbound_manifest,
        &tui_telemetry_manifest,
    };
    for (static_exts) |ext_m| {
        const ext = try parabellum.kernel.AbiExtensionBridge.initExtension(allocator, ext_m);
        try kernel.use(ext);
    }

    const app_paths = parabellum.platform.app_paths;
    app_paths.exportExeDirEnv(arena);
    const early_env = try app_paths.resolveConfigFile(arena, "VIDSEC", "vidsec", ".env");
    _ = parabellum.yaml.env.loadDotEnvFile(arena, early_env);

    const pipeline_path = if (args.len >= 3 and std.mem.eql(u8, args[1], "--pipeline"))
        args[2]
    else
        try app_paths.resolveConfigFile(arena, "VIDSEC", "vidsec", "pipeline.yaml");

    const caps_path = try app_paths.resolveConfigFile(arena, "VIDSEC", "vidsec", "capabilities.yaml");
    const schema_path = try app_paths.resolveConfigFile(arena, "VIDSEC", "vidsec", "schemas.yaml");
    parabellum.yaml.env.loadDotEnvForPipeline(arena, pipeline_path);
    const data_dir = try app_paths.resolveDataDir(arena, "VIDSEC", "vidsec");
    app_paths.setDefaultEnv(arena, "VIDSEC_SCHEMA_PATH", schema_path);
    app_paths.setDefaultEnv(arena, "VIDSEC_DB_PATH", try std.fs.path.join(arena, &.{ data_dir, "vidsec_state.db" }));
    app_paths.setDefaultEnv(arena, "VIDSEC_ARTIFACTS_DIR", try std.fs.path.join(arena, &.{ data_dir, "artifacts" }));
    app_paths.setDefaultEnv(arena, "VIDSEC_QUARANTINE_DIR", try std.fs.path.join(arena, &.{ data_dir, "quarantine" }));
    var loaded_catalog: ?sdk.capabilities.CapabilityCatalog = yaml_config.loadCapabilityCatalogFile(arena, caps_path) catch null;
    if (loaded_catalog) |cat| {
        if (cat.capabilities.len > 0 or cat.events.len > 0) {
            kernel.commands.setCatalog(cat);
        }
    }

    var dispatcher = parabellum.transport.inbound.InboundDispatcher.init(allocator, .{
        .app_name = "vidsec_tui",
        .description = "VidSec Forensic Media Analysis TUI",
        .version = "2.0.2",
        .kernel = &kernel,
    });
    defer dispatcher.deinit();

    var daemon_opt: ?*parabellum.EngineDaemon = null;
    defer if (daemon_opt) |d| d.deinit();

    var abi_builder = parabellum.config.builder_abi.AbiPipelineBuilder.init(arena);
    if (kernel.loadConfigWithBuilder("yaml", pipeline_path, abi_builder.handle(), &parabellum.config.builder_abi.AbiPipelineBuilder.vtable)) |_| {
        const ast_val = try abi_builder.buildAst();
        const schema_cat = try abi_builder.buildSchemaCatalog();
        if (loaded_catalog == null) {
            if (abi_builder.capability_catalog) |cat| {
                if (cat.capabilities.len > 0 or cat.events.len > 0) {
                    kernel.commands.setCatalog(cat);
                    loaded_catalog = cat;
                }
            }
        }
        var runner = try parabellum.runner.PipelineRunner.init(allocator, ast_val, .{
            .schema_catalog = schema_cat,
            .load_shared_modules = false,
            .driver_initializer = registerVidsecDrivers,
            .kernel = &kernel,
        });
        try runner.registry.registerStaticModule("analyzer", &parabellum_module_vidsec_manifest);
        daemon_opt = try parabellum.EngineDaemon.init(allocator, runner);
        try daemon_opt.?.runBootstrap();
        dispatcher.daemon = daemon_opt.?;
    } else |err| {
        const msg = try std.fmt.allocPrint(arena, "vidsec_tui: failed to load pipeline '{s}': {s}\n", .{ pipeline_path, @errorName(err) });
        _ = std.c.write(std.c.STDERR_FILENO, msg.ptr, msg.len);
        return 1;
    }

    return tui_app.runDirect(allocator, loaded_catalog, &dispatcher, abiDispatchTrampoline, pipeline_path);
}
