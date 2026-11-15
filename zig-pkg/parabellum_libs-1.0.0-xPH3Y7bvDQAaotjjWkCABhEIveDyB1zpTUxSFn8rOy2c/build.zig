const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const sql_mod = b.addModule("parabellum_sql", .{
        .root_source_file = b.path("sql/src/root.zig"),
        .target = target,
        .optimize = optimize,
    });

    const sqlite_c = b.addTranslateC(.{
        .root_source_file = b.path("sqlite/c/sqlite3_c.h"),
        .target = target,
        .optimize = optimize,
    });
    sqlite_c.linkSystemLibrary("sqlite3", .{});

    const sqlite_mod = b.addModule("parabellum_sqlite", .{
        .root_source_file = b.path("sqlite/src/root.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    sqlite_mod.addImport("parabellum_sql", sql_mod);
    sqlite_mod.addImport("sqlite_c", sqlite_c.createModule());
    sqlite_mod.linkSystemLibrary("sqlite3", .{});

    const zip_cflags = &.{ "-std=c99", "-O3", "-D_GNU_SOURCE" };
    const miniz_c = b.addTranslateC(.{
        .root_source_file = b.path("zip_archive/c/miniz.h"),
        .target = target,
        .optimize = optimize,
    });

    const zip_mod = b.addModule("parabellum_zip_archive", .{
        .root_source_file = b.path("zip_archive/mod.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    zip_mod.addImport("miniz_c", miniz_c.createModule());
    zip_mod.addIncludePath(b.path("zip_archive/c"));
    zip_mod.addCSourceFile(.{
        .file = b.path("zip_archive/c/miniz.c"),
        .flags = zip_cflags,
    });

    const media_ir_mod = b.addModule("media_ir", .{
        .root_source_file = b.path("media_ir/mod.zig"),
        .target = target,
        .optimize = optimize,
    });
    const isobmff_mod = b.addModule("isobmff", .{
        .root_source_file = b.path("isobmff/mod.zig"),
        .target = target,
        .optimize = optimize,
    });
    const ebml_mod = b.addModule("ebml", .{
        .root_source_file = b.path("ebml/mod.zig"),
        .target = target,
        .optimize = optimize,
    });
    const riff_mod = b.addModule("riff", .{
        .root_source_file = b.path("riff/mod.zig"),
        .target = target,
        .optimize = optimize,
    });
    const tika_mod = b.addModule("tika", .{
        .root_source_file = b.path("tika/mod.zig"),
        .target = target,
        .optimize = optimize,
    });
    const mangadex_sdk_mod = b.addModule("mangadex_sdk", .{
        .root_source_file = b.path("mangadex/mod.zig"),
        .target = target,
        .optimize = optimize,
    });
    const komga_sdk_mod = b.addModule("komga_sdk", .{
        .root_source_file = b.path("komga/mod.zig"),
        .target = target,
        .optimize = optimize,
    });
    const comicinfo_mod = b.addModule("comicinfo", .{
        .root_source_file = b.path("comicinfo/mod.zig"),
        .target = target,
        .optimize = optimize,
    });

    const test_step = b.step("test", "Run all parabellum-libs unit tests");
    const mods = [_]*std.Build.Module{
        sql_mod,
        sqlite_mod,
        zip_mod,
        media_ir_mod,
        isobmff_mod,
        ebml_mod,
        riff_mod,
        tika_mod,
        mangadex_sdk_mod,
        komga_sdk_mod,
        comicinfo_mod,
    };
    for (mods) |m| {
        const t = b.addTest(.{ .root_module = m });
        test_step.dependOn(&b.addRunArtifact(t).step);
    }
}

