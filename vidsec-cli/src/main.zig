const std = @import("std");
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

extern "c" fn setenv(name: [*:0]const u8, value: [*:0]const u8, overwrite: c_int) c_int;

fn getEnv(name: [*:0]const u8) ?[]const u8 {
    if (std.c.getenv(name)) |c_str| {
        const s = std.mem.span(c_str);
        if (s.len > 0) return s;
    }
    return null;
}

fn setDefaultEnv(arena: std.mem.Allocator, name: [*:0]const u8, val: []const u8) void {
    if (getEnv(name) != null) return;
    const z = arena.allocSentinel(u8, val.len, 0) catch return;
    @memcpy(z, val);
    _ = setenv(name, z.ptr, 0);
}

fn resolveDataDir(arena: std.mem.Allocator) ![]const u8 {
    if (getEnv("VIDSEC_DATA_DIR")) |dir| return dir;
    if (getEnv("XDG_DATA_HOME")) |xdg| return try std.fs.path.join(arena, &.{ xdg, "vidsec" });
    if (getEnv("HOME")) |home| return try std.fs.path.join(arena, &.{ home, ".local", "share", "vidsec" });
    return "./data";
}

fn resolveConfigFile(arena: std.mem.Allocator, filename: []const u8) ![]const u8 {
    if (getEnv("VIDSEC_CONFIG_DIR")) |dir| {
        return try std.fs.path.join(arena, &.{ dir, filename });
    }
    if (getEnv("PARABELLUM_CONFIG_DIR")) |pdir| {
        return try std.fs.path.join(arena, &.{ pdir, "vidsec", filename });
    }
    if (getEnv("XDG_CONFIG_HOME")) |xdg| {
        const p_path = try std.fs.path.join(arena, &.{ xdg, "parabellum", "vidsec", filename });
        if (std.Io.Dir.cwd().access(std.Options.debug_io, p_path, .{})) |_| return p_path else |_| {}
        const v_path = try std.fs.path.join(arena, &.{ xdg, "vidsec", filename });
        if (std.Io.Dir.cwd().access(std.Options.debug_io, v_path, .{})) |_| return v_path else |_| {}
    }
    if (getEnv("HOME")) |home| {
        const p_path = try std.fs.path.join(arena, &.{ home, ".config", "parabellum", "vidsec", filename });
        if (std.Io.Dir.cwd().access(std.Options.debug_io, p_path, .{})) |_| return p_path else |_| {}
        const v_path = try std.fs.path.join(arena, &.{ home, ".config", "vidsec", filename });
        if (std.Io.Dir.cwd().access(std.Options.debug_io, v_path, .{})) |_| return v_path else |_| {}
    }
    return try std.fs.path.join(arena, &.{ "configs", filename });
}

fn resolveDefaultPipelinePath(arena: std.mem.Allocator) ![]const u8 {
    if (getEnv("VIDSEC_CONFIG_DIR")) |dir| {
        return try std.fs.path.join(arena, &.{ dir, "pipeline.yaml" });
    }
    if (getEnv("PARABELLUM_CONFIG_DIR")) |pdir| {
        return try std.fs.path.join(arena, &.{ pdir, "vidsec", "pipeline.yaml" });
    }
    if (getEnv("XDG_CONFIG_HOME")) |xdg| {
        return try std.fs.path.join(arena, &.{ xdg, "vidsec", "pipeline.yaml" });
    }
    if (getEnv("HOME")) |home| {
        const xdg_path = try std.fs.path.join(arena, &.{ home, ".config", "vidsec", "pipeline.yaml" });
        if (std.Io.Dir.cwd().access(std.Options.debug_io, xdg_path, .{})) |_| {
            return xdg_path;
        } else |_| {}
    }
    return "configs/pipeline.yaml";
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
        writeStdout("vidsec 2.0.2 (cli monolith)\n");
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
        .version = "2.0.2",
        .kernel = &kernel,
    });
    defer dispatcher.deinit();

    const default_pipeline = try resolveDefaultPipelinePath(arena);
    const pipeline_path = if (args.len >= 3) args[2] else default_pipeline;

    parabellum.yaml.env.loadDotEnvForPipeline(arena, pipeline_path);
    const data_dir = try resolveDataDir(arena);
    setDefaultEnv(arena, "VIDSEC_SCHEMA_PATH", try resolveConfigFile(arena, "schemas.yaml"));
    setDefaultEnv(arena, "VIDSEC_DB_PATH", try std.fs.path.join(arena, &.{ data_dir, "vidsec_state.db" }));
    setDefaultEnv(arena, "VIDSEC_ARTIFACTS_DIR", try std.fs.path.join(arena, &.{ data_dir, "artifacts" }));
    setDefaultEnv(arena, "VIDSEC_QUARANTINE_DIR", try std.fs.path.join(arena, &.{ data_dir, "quarantine" }));

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
