const std = @import("std");
const Allocator = std.mem.Allocator;
const abi = @import("parabellum_abi");
const media_ir = @import("media_ir");

pub const Inputs = struct {
    file_size: u64,
    ir_regions: []const media_ir.IrRegionRow,
    ir_codec_configs: []const media_ir.IrCodecConfigRow = &.{},
    ir_sample_runs: []const media_ir.IrSampleRunRow = &.{},
};

pub const OutputsData = struct {
    audit_findings: []const media_ir.AuditFindingRow,
};

pub const Outputs = abi.Channels(OutputsData);

/// Stage 2 format-agnostic inconsistency checker:
/// - `SampleRuns ⊆ media_data` (`sample_outside_media_data`)
/// - `SampleRun.end_offset <= file_size` (`sample_eof_overflow`)
/// - `IrCodecConfigRow` dimension mismatches (`dimension_mismatch`)
pub const Service = struct {
    pub fn execute(_: *const Service, alloc: Allocator, inputs: Inputs) !Outputs {
        const facts = try media_ir.detectInconsistencies(
            alloc,
            inputs.file_size,
            inputs.ir_regions,
            inputs.ir_codec_configs,
            inputs.ir_sample_runs,
        );
        defer alloc.free(facts);

        var findings: std.ArrayList(media_ir.AuditFindingRow) = .empty;
        errdefer findings.deinit(alloc);

        for (facts) |f| {
            switch (f.kind) {
                .dimension_mismatch => {
                    const msg = try std.fmt.allocPrint(
                        alloc,
                        "Track {d} dimension mismatch: container {d}x{d} != bitstream {d}x{d}",
                        .{ f.track_id, f.expected_a, f.expected_b, f.measured_a, f.measured_b },
                    );
                    try findings.append(alloc, .{
                        .rule_id = "dimension_mismatch",
                        .severity = 2,
                        .region_tag = "codec_config",
                        .measured_value = @floatFromInt(f.track_id),
                        .message = msg,
                    });
                },
                .sample_eof_overflow => {
                    const msg = try std.fmt.allocPrint(
                        alloc,
                        "Sample run {d} overflows EOF: end={d} > file_size={d}",
                        .{ f.run_id, f.measured_a, f.expected_a },
                    );
                    try findings.append(alloc, .{
                        .rule_id = "sample_overflow",
                        .severity = 3,
                        .file_offset = @intCast(f.file_offset),
                        .byte_length = @intCast(f.byte_length),
                        .end_offset = @intCast(f.measured_a),
                        .region_tag = "sample_run",
                        .measured_value = @floatFromInt(f.measured_a),
                        .message = msg,
                    });
                },
                .sample_outside_media_data => {
                    const msg = try std.fmt.allocPrint(
                        alloc,
                        "Sample run {d} at offset {d} lies outside any media_data region",
                        .{ f.run_id, f.file_offset },
                    );
                    try findings.append(alloc, .{
                        .rule_id = "sample_outside_media_data",
                        .severity = 4,
                        .file_offset = @intCast(f.file_offset),
                        .byte_length = @intCast(f.byte_length),
                        .end_offset = @intCast(f.file_offset +| f.byte_length),
                        .region_tag = "sample_run",
                        .measured_value = @floatFromInt(f.file_offset),
                        .message = msg,
                    });
                },
                .sample_overlap => {
                    const msg = try std.fmt.allocPrint(
                        alloc,
                        "Sample run {d} overlaps previous run (start={d} < prev_end={d})",
                        .{ f.run_id, f.measured_a, f.expected_a },
                    );
                    try findings.append(alloc, .{
                        .rule_id = "sample_overlap",
                        .severity = 3,
                        .file_offset = @intCast(f.file_offset),
                        .byte_length = @intCast(f.byte_length),
                        .end_offset = @intCast(f.file_offset +| f.byte_length),
                        .region_tag = "sample_run",
                        .message = msg,
                    });
                },
                .decompression_amplification => {
                    const msg = try std.fmt.allocPrint(
                        alloc,
                        "Sample read amplification: logical={d} bytes > media_data={d} bytes",
                        .{ f.measured_a, f.expected_a },
                    );
                    try findings.append(alloc, .{
                        .rule_id = "decompression_amplification",
                        .severity = 3,
                        .region_tag = "sample_run",
                        .measured_value = if (f.expected_a > 0) @as(f64, @floatFromInt(f.measured_a)) / @as(f64, @floatFromInt(f.expected_a)) else 0.0,
                        .message = msg,
                    });
                },
            }
        }

        return .{ .data = .{
            .audit_findings = try findings.toOwnedSlice(alloc),
        } };
    }
};

