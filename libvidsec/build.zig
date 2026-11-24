const std = @import("std");
const sdk_build = @import("parabellum_sdk");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    const host_lib_dir = b.option([]const u8, "host-lib-dir", "Directory containing precompiled libparabellum_host");

    const sdk_dep = b.dependency("parabellum_sdk", .{
        .target = target,
        .optimize = optimize,
    });
    const libs_dep = b.dependency("parabellum_libs", .{
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

    const linkages = [_]std.builtin.LinkMode{ .dynamic, .static };
    var dyn_lib: *std.Build.Step.Compile = undefined;
    for (linkages) |lnk| {
        const lib = sdk_build.addTaskPlugin(b, sdk_dep, .{
            .name = "vidsec",
            .root_source_file = b.path("src/catalog.zig"),
            .target = target,
            .optimize = optimize,
            .linkage = lnk,
        });
        lib.root_module.addImport("tika", tika_mod);
        lib.root_module.addImport("vidsec_magic", magic_mod);
        lib.root_module.addImport("vidsec_math", math_mod);
        lib.root_module.addImport("media_ir", media_ir_mod);
        lib.root_module.addImport("isobmff", isobmff_mod);
        lib.root_module.addImport("ebml", ebml_mod);
        lib.root_module.addImport("riff", riff_mod);
        b.installArtifact(lib);
        if (lnk == .dynamic) dyn_lib = lib;
    }

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
    e2e_mod.addImport("catalog", dyn_lib.root_module);
    const e2e_test = b.addTest(.{ .root_module = e2e_mod });
    sdk_build.linkPrecompiledTestEngine(e2e_test, .{
        .lib_dir = if (host_lib_dir) |d| .{ .cwd_relative = d } else null,
    });
    e2e_step.dependOn(&b.addRunArtifact(e2e_test).step);
}
