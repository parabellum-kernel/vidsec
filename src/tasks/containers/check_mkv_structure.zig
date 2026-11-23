const std = @import("std");
const Allocator = std.mem.Allocator;
const abi = @import("parabellum_sdk").task;
const media_ir = @import("media_ir");
const dissect_ebml = @import("dissect_ebml.zig");
const dissect_mkv_structures = @import("dissect_mkv_structures.zig");
const common = @import("common.zig");

pub const Inputs = struct {
    ebml_triage: dissect_ebml.EbmlTriageRow,
    ebml_elements: []const dissect_ebml.EbmlElementRow,
    mkv_structures_summary: dissect_mkv_structures.MkvStructuresSummaryRow,
    mkv_tracks: []const dissect_mkv_structures.MkvTrackRow,
    mkv_cues: []const dissect_mkv_structures.MkvCueRow = &.{},
    mkv_lacing_anomalies: []const dissect_mkv_structures.MkvLacingAnomalyRow = &.{},
};

pub const OutputsData = struct {
    mkv_structure_valid: bool,
    audit_findings: []const media_ir.AuditFindingRow,
};

pub const Outputs = abi.Channels(OutputsData);

/// Stage 1b format-specific structural validator for EBML/Matroska (`R03`, `R04`, `R09`).
pub const Service = struct {
    logger: abi.Logger = .{},

    pub fn execute(self: *const Service, alloc: Allocator, inputs: Inputs) !Outputs {
        var findings: std.ArrayList(media_ir.AuditFindingRow) = .empty;
        errdefer findings.deinit(alloc);

        const triage = inputs.ebml_triage;
        // R03: EBML header & Segment presence
        if (triage.header_truncated_at) |trunc_off| {
            try findings.append(alloc, .{
                .rule_id = "ebml_header_truncated",
                .severity = 3,
                .file_offset = @intCast(trunc_off),
                .region_tag = "ebml",
                .message = "Truncated or unparseable EBML element header",
            });
        }
        if (!triage.has_ebml_header) {
            try findings.append(alloc, .{
                .rule_id = "ebml_missing_header",
                .severity = 3,
                .region_tag = "EBML",
                .message = "Stream is missing required EBML Header element",
            });
        }
        if (!triage.has_segment) {
            try findings.append(alloc, .{
                .rule_id = "ebml_missing_segment",
                .severity = 3,
                .region_tag = "Segment",
                .message = "Stream is missing required Matroska Segment element",
            });
        }

        // R03: Element containment, depth, and unknown-size on non-Master elements
        for (inputs.ebml_elements) |e| {
            if (e.is_truncated or e.is_overflow) {
                try findings.append(alloc, .{
                    .rule_id = "ebml_element_containment_overflow",
                    .severity = 3,
                    .file_offset = @intCast(e.header_offset),
                    .byte_length = @intCast(e.available_bytes),
                    .end_offset = @intCast(e.header_offset +| e.available_bytes),
                    .region_tag = try alloc.dupe(u8, e.ebml_id_hex),
                    .message = "EBML element truncated or overflows parent/file boundary",
                });
            }
            if (e.depth > 32) {
                try findings.append(alloc, .{
                    .rule_id = "ebml_recursion_depth_exceeded",
                    .severity = 3,
                    .file_offset = @intCast(e.header_offset),
                    .region_tag = try alloc.dupe(u8, e.ebml_id_hex),
                    .measured_value = @floatFromInt(e.depth),
                    .message = "EBML element nesting depth exceeds 32",
                });
            }
            if (e.is_unknown_size and !std.mem.eql(u8, e.role, "container")) {
                try findings.append(alloc, .{
                    .rule_id = "ebml_unknown_size_non_master",
                    .severity = 3,
                    .file_offset = @intCast(e.header_offset),
                    .region_tag = try alloc.dupe(u8, e.ebml_id_hex),
                    .message = "EBML unknown-size VINT used on non-Master element",
                });
            }
        }

        // R03: Invalid Xiph/EBML/Fixed-size lacing
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

        // R04: CueClusterPosition outside Segment bounds
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

        // R09: Tracks & TrackEntry validation
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
        const findings_slice = try findings.toOwnedSlice(alloc);
        return .{ .data = .{
            .mkv_structure_valid = findings_slice.len == 0,
            .audit_findings = findings_slice,
        } };
    }
};

