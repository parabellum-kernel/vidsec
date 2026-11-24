const std = @import("std");
const Allocator = std.mem.Allocator;
const abi = @import("parabellum_sdk").task;
const media_ir = @import("media_ir");
const dissect_mkv_cues = @import("dissect_mkv_cues.zig");
const common = @import("../common.zig");

pub const Inputs = struct {
    mkv_cues: []const dissect_mkv_cues.MkvCueRow,
};

pub const OutputsData = struct {
    audit_findings: []const media_ir.AuditFindingRow,
};

pub const Outputs = abi.Channels(OutputsData);

/// Stage 1b atomic validator for Matroska Cues Segment bounds (`R04`).
pub const Service = struct {
    logger: abi.Logger = .{},

    pub fn execute(self: *const Service, alloc: Allocator, inputs: Inputs) !Outputs {
        var findings: std.ArrayList(media_ir.AuditFindingRow) = .empty;
        errdefer findings.deinit(alloc);

        for (inputs.mkv_cues) |cue| {
            if (!cue.in_segment_bounds) {
                try findings.append(alloc, .{
                    .rule_id = "mkv_cue_out_of_segment_bounds",
                    .severity = 3,
                    .file_offset = @intCast(cue.cluster_position),
                    .region_tag = "Cues",
                    .measured_value = @floatFromInt(cue.cluster_position),
                    .message = "Matroska CueClusterPosition points outside Segment bounds",
                });
            }
        }

        common.logFindings(self.logger, findings.items);
        return .{ .data = .{
            .audit_findings = try findings.toOwnedSlice(alloc),
        } };
    }
};
