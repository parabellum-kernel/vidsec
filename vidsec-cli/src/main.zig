const std = @import("std");
const build_options = @import("build_options");
const parabellum = @import("parabellum");
const sdk = @import("parabellum_sdk");
const abi = sdk.abi;

extern const parabellum_module_vidsec_manifest: parabellum.plugin.ModuleManifest_ABI;
extern const parabellum_driver_memory_manifest: abi.DriverManifest_ABI;
extern const parabellum_driver_file_store_manifest: abi.DriverManifest_ABI;
extern const parabellum_driver_sqlite_manifest: abi.DriverManifest_ABI;
extern const parabellum_extension_opentelemetry_manifest: abi.ExtensionManifest_ABI;
extern const parabellum_extension_trace_jsonl_manifest: abi.ExtensionManifest_ABI;
extern const parabellum_extension_yaml_config_manifest: abi.ExtensionManifest_ABI;
extern const parabellum_extension_inbound_cli_manifest: abi.ExtensionManifest_ABI;

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

fn dispatchTrampoline(ctx: *anyopaque, req: parabellum.transport.inbound.contracts.InvocationRequest) anyerror!parabellum.transport.inbound.contracts.InvocationResponse {
    const d: *parabellum.transport.inbound.InboundDispatcher = @ptrCast(@alignCast(ctx));
    return d.handle(req);
}

pub fn main(init: std.process.Init) !u8 {
    const allocator = init.gpa;
    const arena = init.arena.allocator();
    const args = try init.minimal.args.toSlice(arena);

    if (args.len >= 2 and (std.mem.eql(u8, args[1], "--version") or std.mem.eql(u8, args[1], "-V"))) {
        writeStdout("vidsec " ++ build_options.version ++ " (cli monolith)\n");
        return 0;
    }

    var kernel = try parabellum.kernel.KernelContext.init(allocator);
    defer kernel.deinit();

    const static_exts = [_]*const abi.ExtensionManifest_ABI{
        &parabellum_extension_opentelemetry_manifest,
        &parabellum_extension_trace_jsonl_manifest,
        &parabellum_extension_yaml_config_manifest,
        &parabellum_extension_inbound_cli_manifest,
    };
    for (static_exts) |ext_m| {
        const ext = try parabellum.kernel.AbiExtensionBridge.initExtension(allocator, ext_m);
        try kernel.use(ext);
    }

    if (args.len < 2 or std.mem.eql(u8, args[1], "--help") or std.mem.eql(u8, args[1], "-h")) {
        writeStdout(
            \\vidsec — Forensic Media Triage & Analysis CLI
            \\Usage: vidsec <command> [options]
            \\  --version          Print version
            \\  validate [yaml]    Validate pipeline configuration
            \\  run [yaml]         Execute pipeline
            \\
        );
        return 0;
    }

    var dispatcher = parabellum.transport.inbound.InboundDispatcher.init(allocator, .{
        .app_name = "vidsec",
        .description = "VidSec Forensic Media Analysis CLI",
        .version = build_options.version,
        .kernel = &kernel,
    });
    defer dispatcher.deinit();

    const app_paths = parabellum.platform.app_paths;
    app_paths.exportExeDirEnv(arena);
    const early_env = try app_paths.resolveConfigFile(arena, "VIDSEC", "vidsec", ".env");
    _ = parabellum.yaml.env.loadDotEnvFile(arena, early_env);

    const default_pipeline = try app_paths.resolveConfigFile(arena, "VIDSEC", "vidsec", "pipeline.yaml");
    const pipeline_path = if (args.len >= 3) args[2] else default_pipeline;

    parabellum.yaml.env.loadDotEnvForPipeline(arena, pipeline_path);
    const data_dir = try app_paths.resolveDataDir(arena, "VIDSEC", "vidsec");
    app_paths.setDefaultEnv(arena, "VIDSEC_SCHEMA_PATH", try app_paths.resolveConfigFile(arena, "VIDSEC", "vidsec", "schemas.yaml"));
    app_paths.setDefaultEnv(arena, "VIDSEC_DB_PATH", try std.fs.path.join(arena, &.{ data_dir, "vidsec_state.db" }));
    app_paths.setDefaultEnv(arena, "VIDSEC_ARTIFACTS_DIR", try std.fs.path.join(arena, &.{ data_dir, "artifacts" }));
    app_paths.setDefaultEnv(arena, "VIDSEC_QUARANTINE_DIR", try std.fs.path.join(arena, &.{ data_dir, "quarantine" }));

    if (kernel.inbound.contains("cli")) {
        const cli_transport = try kernel.inbound.create("cli", .{
            .listen_address = "",
            .pipeline_path = "",
        });
        defer cli_transport.deinit(kernel.inbound.allocator);
        return cli_transport.serveArgs(args, &dispatcher, dispatchTrampoline);
    }

    if (std.mem.eql(u8, args[1], "validate")) {
        const resp = try dispatcher.handle(.{ .command = .validate, .options = .{} });
        if (resp.output_bytes.len > 0) writeStdout(resp.output_bytes);
        if (resp.message.len > 0) {
            if (resp.exit_code == 0) writeStdout(resp.message) else writeStderr(resp.message);
        }
        return resp.exit_code;
    }

    if (std.mem.eql(u8, args[1], "run")) {
        var abi_builder = parabellum.config.builder_abi.AbiPipelineBuilder.init(arena);
        if (kernel.loadConfigWithBuilder("yaml", pipeline_path, abi_builder.handle(), &parabellum.config.builder_abi.AbiPipelineBuilder.vtable)) |_| {
            const ast_val = try abi_builder.buildAst();
            const schema_cat = try abi_builder.buildSchemaCatalog();
            if (abi_builder.capability_catalog) |cat| {
                if (cat.capabilities.len > 0 or cat.events.len > 0) {
                    kernel.commands.setCatalog(cat);
                }
            }
            var runner = try parabellum.runner.PipelineRunner.init(allocator, ast_val, .{
                .schema_catalog = schema_cat,
                .load_shared_modules = false,
                .driver_initializer = registerVidsecDrivers,
                .kernel = &kernel,
            });
            try runner.registry.registerStaticModule("analyzer", &parabellum_module_vidsec_manifest);
            dispatcher.cached_runner = runner;
        } else |_| {}
        const resp = try dispatcher.handle(.{ .command = .run, .options = .{} });
        if (resp.output_bytes.len > 0) writeStdout(resp.output_bytes);
        if (resp.message.len > 0) {
            if (resp.exit_code == 0) writeStdout(resp.message) else writeStderr(resp.message);
        }
        return resp.exit_code;
    }

    writeStderr("vidsec: unknown command. Use --help.\n");
    return 1;
}
