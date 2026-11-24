const std = @import("std");
const sdk_build = @import("parabellum_sdk");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    const host_lib_dir = b.option([]const u8, "host-lib-dir", "Directory containing precompiled libparabellum_host");

    const vidsec_version = std.SemanticVersion{ .major = 1, .minor = 0, .patch = 0 };

    const sdk_dep = b.dependency("parabellum_sdk", .{
        .target = target,
        .optimize = optimize,
    });
    const libs_dep = b.dependency("parabellum_libs", .{
        .target = target,
        .optimize = optimize,
    });
    const ext_dep = b.dependency("parabellum_extensions", .{
        .target = target,
        .optimize = optimize,
    });
    const media_ir_mod = libs_dep.module("media_ir");
    const isobmff_mod = libs_dep.module("isobmff");
    const ebml_mod = libs_dep.module("ebml");
    const riff_mod = libs_dep.module("riff");
    const tika_mod = libs_dep.module("tika");

    const magic_mod = b.addModule("vidsec_magic", .{
        .root_source_file = b.path("src/magic/mod.zig"),
        .target = target,
        .optimize = optimize,
    });
    magic_mod.addImport("tika", tika_mod);

    const math_mod = b.addModule("vidsec_math", .{
        .root_source_file = b.path("src/math/mod.zig"),
        .target = target,
        .optimize = optimize,
    });

    const analyzer_lib = addPluginSharedLib(
        b,
        target,
        optimize,
        vidsec_version,
        tika_mod,
        magic_mod,
        math_mod,
        media_ir_mod,
        isobmff_mod,
        ebml_mod,
        riff_mod,
        "analyzer",
        "src/catalog.zig",
    );
    analyzer_lib.root_module.addImport("parabellum_sdk", sdk_dep.module("parabellum_sdk"));

    const tui_mod = ext_dep.module("tui_inbound");
    const vidsec_tui_so = sdk_build.addExtensionPlugin(b, sdk_dep, .{
        .name = "vidsec_tui",
        .root_source_file = b.path("src/tui_plugin.zig"),
        .target = target,
        .optimize = optimize,
    });
    vidsec_tui_so.root_module.addImport("tui_inbound", tui_mod);
    b.installArtifact(vidsec_tui_so);

    const vidsec_tui_a = sdk_build.addExtensionPlugin(b, sdk_dep, .{
        .name = "vidsec_tui",
        .root_source_file = b.path("src/tui_plugin.zig"),
        .target = target,
        .optimize = optimize,
        .linkage = .static,
    });
    vidsec_tui_a.root_module.addImport("tui_inbound", tui_mod);
    b.installArtifact(vidsec_tui_a);

    const test_step = b.step("test", "Run Vidsec pure-SDK unit tests");
    test_step.dependOn(&b.addRunArtifact(b.addTest(.{ .root_module = magic_mod })).step);
    test_step.dependOn(&b.addRunArtifact(b.addTest(.{ .root_module = math_mod })).step);

    const e2e_step = b.step("test-e2e", "Run Tier 2 host integration tests against libparabellum_host");
    const e2e_mod = b.createModule(.{
        .root_source_file = b.path("tests/host_e2e_test.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    e2e_mod.addImport("parabellum_sdk", sdk_dep.module("parabellum_sdk"));
    e2e_mod.addImport("catalog", analyzer_lib.root_module);
    const e2e_test = b.addTest(.{ .root_module = e2e_mod });
    sdk_build.linkPrecompiledTestEngine(e2e_test, .{
        .lib_dir = if (host_lib_dir) |d| .{ .cwd_relative = d } else null,
    });
    e2e_step.dependOn(&b.addRunArtifact(e2e_test).step);
}

/// Helper for registering a `.so` plugin shared library in `build.zig`.
pub fn addPluginSharedLib(
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
    version: std.SemanticVersion,
    tika_mod: *std.Build.Module,
    magic_mod: *std.Build.Module,
    math_mod: *std.Build.Module,
    media_ir_mod: *std.Build.Module,
    isobmff_mod: *std.Build.Module,
    ebml_mod: *std.Build.Module,
    riff_mod: *std.Build.Module,
    name: []const u8,
    root_source: []const u8,
) *std.Build.Step.Compile {
    const plugin_mod = b.createModule(.{
        .root_source_file = b.path(root_source),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    plugin_mod.addImport("tika", tika_mod);
    plugin_mod.addImport("vidsec_magic", magic_mod);
    plugin_mod.addImport("vidsec_math", math_mod);
    plugin_mod.addImport("media_ir", media_ir_mod);
    plugin_mod.addImport("isobmff", isobmff_mod);
    plugin_mod.addImport("ebml", ebml_mod);
    plugin_mod.addImport("riff", riff_mod);

    const lib = b.addLibrary(.{
        .linkage = .dynamic,
        .name = name,
        .version = version,
        .root_module = plugin_mod,
    });
    b.installArtifact(lib);

    const static_lib = b.addLibrary(.{
        .linkage = .static,
        .name = name,
        .version = version,
        .root_module = plugin_mod,
    });
    static_lib.bundle_compiler_rt = false;
    b.installArtifact(static_lib);

    return lib;
}
