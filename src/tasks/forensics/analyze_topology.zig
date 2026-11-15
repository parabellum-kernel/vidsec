const std = @import("std");
const Allocator = std.mem.Allocator;
const abi = @import("flowdata_abi");
const media_ir = @import("media_ir");

pub const Inputs = struct {
    file_size: u64,
    ir_regions: []const media_ir.IrRegionRow,
    ir_sample_runs: []const media_ir.IrSampleRunRow = &.{},
};

pub const OutputsData = struct {
    ir_unreferenced_slack: []const media_ir.IrUnreferencedSlackRow,
    audit_findings: []const media_ir.AuditFindingRow,
};

pub const Outputs = abi.Channels(OutputsData);

/// Stage 2 pure interval topology analyzer over `ir_regions` + `ir_sample_runs`.
/// Emits `ir_unreferenced_slack` and `region_overlap` findings.
pub const Service = struct {
    pub fn execute(_: *const Service, alloc: Allocator, inputs: Inputs) !Outputs {
        var report = try media_ir.analyzeTopology(alloc, inputs.file_size, inputs.ir_regions, inputs.ir_sample_runs);
        defer report.deinit();

        var slacks: std.ArrayList(media_ir.IrUnreferencedSlackRow) = .empty;
        errdefer slacks.deinit(alloc);
        var findings: std.ArrayList(media_ir.AuditFindingRow) = .empty;
        errdefer findings.deinit(alloc);

        for (report.slacks, 1..) |s, idx| {
            try slacks.append(alloc, .{
                .slack_id = @intCast(idx),
                .region_tag = s.kind.asText(),
                .file_offset = s.file_offset,
                .byte_length = s.byte_length,
            });
        }

        for (report.overlaps) |ov| {
            const msg = try std.fmt.allocPrint(
                alloc,
                "Root regions {d} and {d} overlap by {d} bytes at offset {d}",
                .{ ov.region_a_id, ov.region_b_id, ov.overlap_bytes, ov.overlap_offset },
            );
            try findings.append(alloc, .{
                .rule_id = "region_overlap",
                .severity = 4,
                .file_offset = @intCast(ov.overlap_offset),
                .byte_length = @intCast(ov.overlap_bytes),
                .end_offset = @intCast(ov.overlap_offset +| ov.overlap_bytes),
                .region_tag = "overlap",
                .measured_value = @floatFromInt(ov.overlap_bytes),
                .message = msg,
            });
        }

        return .{ .data = .{
            .ir_unreferenced_slack = try slacks.toOwnedSlice(alloc),
            .audit_findings = try findings.toOwnedSlice(alloc),
        } };
    }
};
