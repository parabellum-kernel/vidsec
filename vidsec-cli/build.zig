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

    const ver_opts = b.addOptions();
    ver_opts.addOption([]const u8, "version", @import("build.zig.zon").version);

    const cli_mod = b.createModule(.{
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    cli_mod.addImport("parabellum", engine_dep.module("parabellum"));
    cli_mod.addImport("parabellum_sdk", sdk_dep.module("parabellum_sdk"));
    cli_mod.addOptions("build_options", ver_opts);

    const cli_lib = b.addLibrary(.{
        .linkage = .static,
        .name = "vidsec_cli",
        .root_module = cli_mod,
    });
    cli_lib.bundle_compiler_rt = false;
    b.installArtifact(cli_lib);
}
