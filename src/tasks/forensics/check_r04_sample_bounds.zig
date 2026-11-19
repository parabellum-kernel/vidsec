const std = @import("std");
const Allocator = std.mem.Allocator;
const abi = @import("parabellum_sdk").task;
const media_ir = @import("media_ir");
const orders = @import("../remediation/orders.zig");

pub const Inputs = struct {
    file_size: u64,
    ir_regions: []const media_ir.IrRegionRow,
    ir_sample_runs: []const media_ir.IrSampleRunRow = &.{},
    quarantine_on_fail: bool = true,
};

pub const OutputsData = struct {
    audit_findings: []const media_ir.AuditFindingRow,
    quarantine_orders: []const orders.QuarantineOrder,
};

pub const Outputs = abi.Channels(OutputsData);

/// Stage 2 R04 validator: verifies `SampleRuns ⊆ media_data` and `end_offset <= file_size`.
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
                .sample_eof_overflow => {
                    const msg = try std.fmt.allocPrint(
                        alloc,
                        "Sample run {d} overflows EOF: end={d} > file_size={d}",
                        .{ f.run_id, f.measured_a, f.expected_a },
                    );
                    try findings.append(alloc, .{
                        .rule_id = "sample_overflow",
                        .severity = 4,
                        .file_offset = @intCast(f.file_offset),
                        .byte_length = @intCast(f.byte_length),
                        .end_offset = @intCast(f.measured_a),
                        .region_tag = "sample_run",
                        .measured_value = @floatFromInt(f.measured_a),
                        .message = msg,
                    });
                    if (inputs.quarantine_on_fail) {
                        try quarantines.append(alloc, .{
                            .rule_id = "sample_overflow",
                            .reason = msg,
                            .severity = 4,
                        });
                    }
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
                    if (inputs.quarantine_on_fail) {
                        try quarantines.append(alloc, .{
                            .rule_id = "sample_outside_media_data",
                            .reason = msg,
                            .severity = 4,
                        });
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

