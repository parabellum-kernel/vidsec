const std = @import("std");

pub const PluginOptions = struct {
    name: []const u8,
    root_source_file: std.Build.LazyPath,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
    link_libc: bool = true,
};

/// Helper for building a standalone `.so` Task Catalog plugin (`lib<name>.so`)
/// against `parabellum_sdk`.
pub fn addTaskPlugin(b: *std.Build, sdk_dep: *std.Build.Dependency, opts: PluginOptions) *std.Build.Step.Compile {
    const mod = b.createModule(.{
        .root_source_file = opts.root_source_file,
        .target = opts.target,
        .optimize = opts.optimize,
        .link_libc = opts.link_libc,
    });
    mod.addImport("parabellum_sdk", sdk_dep.module("parabellum_sdk"));
    return b.addLibrary(.{
        .linkage = .dynamic,
        .name = opts.name,
        .root_module = mod,
    });
}

/// Helper for building a standalone `.so` Datasource Driver plugin (`libdriver_<name>.so`)
/// against `parabellum_sdk`.
pub fn addDriverPlugin(b: *std.Build, sdk_dep: *std.Build.Dependency, opts: PluginOptions) *std.Build.Step.Compile {
    const mod = b.createModule(.{
        .root_source_file = opts.root_source_file,
        .target = opts.target,
        .optimize = opts.optimize,
        .link_libc = opts.link_libc,
    });
    mod.addImport("parabellum_sdk", sdk_dep.module("parabellum_sdk"));
    return b.addLibrary(.{
        .linkage = .dynamic,
        .name = b.fmt("driver_{s}", .{opts.name}),
        .root_module = mod,
    });
}

/// Helper for building a standalone `.so` Kernel Extension plugin (`libext_<name>.so`)
/// against `parabellum_sdk`.
pub fn addExtensionPlugin(b: *std.Build, sdk_dep: *std.Build.Dependency, opts: PluginOptions) *std.Build.Step.Compile {
    const mod = b.createModule(.{
        .root_source_file = opts.root_source_file,
        .target = opts.target,
        .optimize = opts.optimize,
        .link_libc = opts.link_libc,
    });
    mod.addImport("parabellum_sdk", sdk_dep.module("parabellum_sdk"));
    return b.addLibrary(.{
        .linkage = .dynamic,
        .name = b.fmt("ext_{s}", .{opts.name}),
        .root_module = mod,
    });
}

pub const LinkHostOptions = struct {
    lib_dir: ?std.Build.LazyPath = null,
    lib_name: []const u8 = "parabellum_host",
};

/// Links a compile step (e.g. an integration test binary using `parabellum_sdk.host.TestEngine`)
/// against a precompiled `libparabellum_host` shared library.
pub fn linkPrecompiledTestEngine(compile: *std.Build.Step.Compile, opts: LinkHostOptions) void {
    compile.root_module.link_libc = true;
    if (opts.lib_dir) |dir| {
        compile.root_module.addLibraryPath(dir);
        compile.root_module.addRPath(dir);
    }
    compile.root_module.linkSystemLibrary(opts.lib_name, .{});
}

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const abi_mod = b.addModule("parabellum_abi", .{
        .root_source_file = b.path("src/task/mod.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    b.modules.put(b.allocator, b.dupe("parabellum_plugin"), abi_mod) catch @panic("OOM");

    const sdk_mod = b.addModule("parabellum_sdk", .{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "parabellum_abi", .module = abi_mod },
        },
    });

    const test_mod = b.createModule(.{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "parabellum_abi", .module = abi_mod },
        },
    });

    const run_tests = b.addRunArtifact(b.addTest(.{ .root_module = test_mod }));
    const run_abi_tests = b.addRunArtifact(b.addTest(.{ .root_module = abi_mod }));
    const test_step = b.step("test", "Run parabellum-sdk unit tests");
    test_step.dependOn(&run_tests.step);
    test_step.dependOn(&run_abi_tests.step);
    _ = sdk_mod;
}
