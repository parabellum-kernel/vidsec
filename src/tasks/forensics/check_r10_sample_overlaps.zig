const std = @import("std");
const Allocator = std.mem.Allocator;
const abi = @import("parabellum_abi");
const media_ir = @import("media_ir");
const orders = @import("../remediation/orders.zig");

pub const Inputs = struct {
    file_size: u64,
    ir_regions: []const media_ir.IrRegionRow,
    ir_sample_runs: []const media_ir.IrSampleRunRow = &.{},
    max_amplification_ratio: f64 = 1.0,
    quarantine_on_fail: bool = true,
};

pub const OutputsData = struct {
    audit_findings: []const media_ir.AuditFindingRow,
    quarantine_orders: []const orders.QuarantineOrder,
};

pub const Outputs = abi.Channels(OutputsData);

/// Stage 2 R10 validator: detects overlapping sample runs `T_(k) < E_(k-1)`
/// and decompression/read amplification (`R_amp > max_amplification_ratio`).
pub const Service = struct {
    pub fn execute(_: *const Service, alloc: Allocator, inputs: Inputs) !Outputs {
        const facts = try media_ir.detectInconsistencies(
            alloc,
            inputs.file_size,
            inputs.ir_regions,
            &.{},
            inputs.ir_sample_runs,
        );
        defer alloc.free(facts);

        var findings: std.ArrayList(media_ir.AuditFindingRow) = .empty;
        errdefer findings.deinit(alloc);
        var quarantines: std.ArrayList(orders.QuarantineOrder) = .empty;
        errdefer quarantines.deinit(alloc);

        for (facts) |f| {
            switch (f.kind) {
                .sample_overlap => {
                    const msg = try std.fmt.allocPrint(
                        alloc,
                        "Sample run {d} overlaps previous run (start={d} < prev_end={d})",
                        .{ f.run_id, f.measured_a, f.expected_a },
                    );
                    try findings.append(alloc, .{
                        .rule_id = "sample_overlap",
                        .severity = 4,
                        .file_offset = @intCast(f.file_offset),
                        .byte_length = @intCast(f.byte_length),
                        .end_offset = @intCast(f.file_offset +| f.byte_length),
                        .region_tag = "sample_run",
                        .message = msg,
                    });
                    if (inputs.quarantine_on_fail) {
                        try quarantines.append(alloc, .{
                            .rule_id = "sample_overlap",
                            .reason = msg,
                            .severity = 4,
                        });
                    }
                },
                .decompression_amplification => {
                    const ratio: f64 = if (f.expected_a > 0)
                        @as(f64, @floatFromInt(f.measured_a)) / @as(f64, @floatFromInt(f.expected_a))
                    else
                        0.0;
                    if (ratio > inputs.max_amplification_ratio) {
                        const msg = try std.fmt.allocPrint(
                            alloc,
                            "Sample read amplification {d:.2}x (logical={d} > media_data={d})",
                            .{ ratio, f.measured_a, f.expected_a },
                        );
                        try findings.append(alloc, .{
                            .rule_id = "decompression_amplification",
                            .severity = 4,
                            .region_tag = "sample_run",
                            .measured_value = ratio,
                            .message = msg,
                        });
                        if (inputs.quarantine_on_fail) {
                            try quarantines.append(alloc, .{
                                .rule_id = "decompression_amplification",
                                .reason = msg,
                                .severity = 4,
                            });
                        }
                    }
                },
                else => {},
            }
        }

        return .{ .data = .{
            .audit_findings = try findings.toOwnedSlice(alloc),
            .quarantine_orders = try quarantines.toOwnedSlice(alloc),
        } };
    }
};

