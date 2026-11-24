const std = @import("std");
const Allocator = std.mem.Allocator;
const abi = @import("parabellum_sdk").task;
const media_ir = @import("media_ir");
const dissect_mkv_lacing_anomalies = @import("dissect_mkv_lacing_anomalies.zig");
const common = @import("../common.zig");

pub const Inputs = struct {
    mkv_lacing_anomalies: []const dissect_mkv_lacing_anomalies.MkvLacingAnomalyRow,
};

pub const OutputsData = struct {
    audit_findings: []const media_ir.AuditFindingRow,
};

pub const Outputs = abi.Channels(OutputsData);

/// Stage 1b atomic validator for Matroska block lacing anomalies (`R03`).
pub const Service = struct {
    logger: abi.Logger = .{},

    pub fn execute(self: *const Service, alloc: Allocator, inputs: Inputs) !Outputs {
        var findings: std.ArrayList(media_ir.AuditFindingRow) = .empty;
        errdefer findings.deinit(alloc);

        for (inputs.mkv_lacing_anomalies) |la| {
            try findings.append(alloc, .{
                .rule_id = "mkv_invalid_lacing",
                .severity = 3,
                .file_offset = @intCast(la.offset),
                .byte_length = @intCast(la.payload_size),
                .region_tag = "SimpleBlock",
                .measured_value = @floatFromInt(la.frame_count),
                .message = "Matroska block lacing header exceeds block payload bounds",
            });
        }

        common.logFindings(self.logger, findings.items);
        return .{ .data = .{
            .audit_findings = try findings.toOwnedSlice(alloc),
        } };
    }
};
