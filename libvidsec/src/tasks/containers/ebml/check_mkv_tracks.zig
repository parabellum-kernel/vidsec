const std = @import("std");
const Allocator = std.mem.Allocator;
const abi = @import("parabellum_sdk").task;
const media_ir = @import("media_ir");
const dissect_mkv_summary = @import("dissect_mkv_summary.zig");
const dissect_mkv_tracks = @import("dissect_mkv_tracks.zig");
const common = @import("../common.zig");

pub const Inputs = struct {
    mkv_structures_summary: dissect_mkv_summary.MkvStructuresSummaryRow,
    mkv_tracks: []const dissect_mkv_tracks.MkvTrackRow,
};

pub const OutputsData = struct {
    audit_findings: []const media_ir.AuditFindingRow,
};

pub const Outputs = abi.Channels(OutputsData);

/// Stage 1b atomic validator for Matroska Tracks and TrackEntry invariants (`R09`).
pub const Service = struct {
    logger: abi.Logger = .{},

    pub fn execute(self: *const Service, alloc: Allocator, inputs: Inputs) !Outputs {
        var findings: std.ArrayList(media_ir.AuditFindingRow) = .empty;
        errdefer findings.deinit(alloc);

        if (!inputs.mkv_structures_summary.has_tracks) {
            try findings.append(alloc, .{
                .rule_id = "segment_missing_tracks",
                .severity = 3,
                .region_tag = "Segment",
                .message = "Segment is missing required Tracks element (0x1654AE6B)",
            });
        }

        var seen = std.AutoHashMap(u64, void).init(alloc);
        defer seen.deinit();

        for (inputs.mkv_tracks) |t| {
            if (t.track_number == 0) {
                try findings.append(alloc, .{
                    .rule_id = "track_number_zero",
                    .severity = 3,
                    .region_tag = "TrackEntry",
                    .message = "TrackEntry specifies illegal TrackNumber = 0",
                });
            } else if (seen.contains(t.track_number)) {
                try findings.append(alloc, .{
                    .rule_id = "track_number_duplicate",
                    .severity = 3,
                    .region_tag = "TrackEntry",
                    .message = "Duplicate TrackNumber encountered in Matroska Tracks",
                });
            } else {
                try seen.put(t.track_number, {});
            }

            if (t.codec_id.len == 0) {
                try findings.append(alloc, .{
                    .rule_id = "track_missing_codec_id",
                    .severity = 3,
                    .region_tag = "TrackEntry",
                    .message = "TrackEntry is missing required CodecID element",
                });
            }
        }

        common.logFindings(self.logger, findings.items);
        return .{ .data = .{
            .audit_findings = try findings.toOwnedSlice(alloc),
        } };
    }
};
