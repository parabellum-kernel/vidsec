const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const engine_dep = b.dependency("parabellum", .{
        .target = target,
        .optimize = optimize,
    });
    const sdk_dep = b.dependency("parabellum_sdk", .{
        .target = target,
        .optimize = optimize,
    });
    const ext_dep = b.dependency("parabellum_extensions", .{
        .target = target,
        .optimize = optimize,
    });

    const tui_mod = b.createModule(.{
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    tui_mod.addImport("parabellum", engine_dep.module("parabellum"));
    tui_mod.addImport("parabellum_sdk", sdk_dep.module("parabellum_sdk"));
    tui_mod.addImport("tui_inbound", ext_dep.module("tui_inbound"));
    tui_mod.addImport("yaml_config", ext_dep.module("yaml_config"));

    const tui_lib = b.addLibrary(.{
        .linkage = .static,
        .name = "vidsec_tui_app",
        .root_module = tui_mod,
    });
    tui_lib.bundle_compiler_rt = false;
    b.installArtifact(tui_lib);
}
