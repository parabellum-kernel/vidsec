const std = @import("std");
const Allocator = std.mem.Allocator;
const abi = @import("flowdata_abi");
const media_ir = @import("media_ir");
const dissect_isobmff = @import("dissect_isobmff.zig");
const dissect_mp4_atoms = @import("dissect_mp4_atoms.zig");

pub const Inputs = struct {
    isobmff_triage: dissect_isobmff.IsobmffTriageRow,
    isobmff_boxes: []const dissect_isobmff.IsobmffBoxRow,
    mp4_table_measurements: []const dissect_mp4_atoms.Mp4TableMeasurementRow = &.{},
    mp4_codec_headers: []const dissect_mp4_atoms.Mp4CodecHeaderRow = &.{},
};

pub const OutputsData = struct {
    mp4_structure_valid: bool,
    audit_findings: []const media_ir.AuditFindingRow,
};

pub const Outputs = abi.Channels(OutputsData);

/// Stage 1b format-specific structural validator for ISOBMFF/MP4 (`R03`, `R04a`, `R09a`).
pub const Service = struct {
    pub fn execute(_: *const Service, alloc: Allocator, inputs: Inputs) !Outputs {
        var findings: std.ArrayList(media_ir.AuditFindingRow) = .empty;
        errdefer findings.deinit(alloc);

        const triage = inputs.isobmff_triage;
        // R03: Header truncation & required top-level boxes
        if (triage.truncated_tail_offset) |trunc_off| {
            try findings.append(alloc, .{
                .rule_id = "box_header_truncated",
                .severity = 3,
                .file_offset = @intCast(trunc_off),
                .region_tag = "isobmff",
                .message = "Truncated ISOBMFF box header",
            });
        }
        if (!triage.has_ftyp) {
            try findings.append(alloc, .{
                .rule_id = "mp4_missing_ftyp",
                .severity = 3,
                .region_tag = "ftyp",
                .message = "ISOBMFF/MP4 stream is missing required ftyp box",
            });
        }
        if (!triage.has_moov) {
            try findings.append(alloc, .{
                .rule_id = "mp4_missing_moov",
                .severity = 3,
                .region_tag = "moov",
                .message = "ISOBMFF/MP4 stream is missing required moov box",
            });
        }

        // R03: Box containment & recursion depth
        for (inputs.isobmff_boxes) |b| {
            if (b.is_truncated or b.is_overflow) {
                try findings.append(alloc, .{
                    .rule_id = "box_containment_overflow",
                    .severity = 3,
                    .file_offset = @intCast(b.header_offset),
                    .byte_length = @intCast(b.available_bytes),
                    .end_offset = @intCast(b.header_offset +| b.available_bytes),
                    .region_tag = try alloc.dupe(u8, b.fourcc),
                    .message = "ISOBMFF box truncated or overflows parent/file boundary",
                });
            }
            if (b.depth > 32) {
                try findings.append(alloc, .{
                    .rule_id = "box_recursion_depth_exceeded",
                    .severity = 3,
                    .file_offset = @intCast(b.header_offset),
                    .region_tag = try alloc.dupe(u8, b.fourcc),
                    .measured_value = @floatFromInt(b.depth),
                    .message = "ISOBMFF box nesting depth exceeds 32",
                });
            }
        }

        // R04a: Sample table capacity & arithmetic overflow
        for (inputs.mp4_table_measurements) |tm| {
            if (tm.is_overflow or tm.has_arith_overflow or tm.claimed_bytes > tm.payload_size) {
                try findings.append(alloc, .{
                    .rule_id = "mp4_sample_table_overflow",
                    .severity = 4,
                    .byte_length = @intCast(tm.claimed_bytes),
                    .region_tag = try alloc.dupe(u8, tm.table_fourcc),
                    .measured_value = @floatFromInt(tm.claimed_bytes),
                    .message = "MP4 sample table declared entry count overflows box payload or arithmetic bounds",
                });
            }
        }

        // R09a: Codec configuration headers (avcC, hvcC, esds)
        for (inputs.mp4_codec_headers) |ch| {
            if (ch.is_malformed) {
                const rule_id: []const u8 = if (std.mem.eql(u8, ch.kind, "avcc"))
                    "avcc_malformed_config"
                else if (std.mem.eql(u8, ch.kind, "hvcc"))
                    "hvcc_malformed_config"
                else
                    "esds_malformed_config";

                try findings.append(alloc, .{
                    .rule_id = rule_id,
                    .severity = 4,
                    .byte_length = @intCast(ch.payload_size),
                    .region_tag = try alloc.dupe(u8, ch.codec_tag),
                    .measured_value = @floatFromInt(ch.claimed_bytes),
                    .message = "Malformed MP4 codec configuration record exceeds payload bounds",
                });
            }
            if (std.mem.eql(u8, ch.kind, "avcc") and ch.length_size_minus_one == 2) {
                try findings.append(alloc, .{
                    .rule_id = "avcc_invalid_nalu_length_size",
                    .severity = 3,
                    .region_tag = "avcC",
                    .measured_value = 3.0,
                    .message = "avcC specifies invalid 3-byte NALU lengthSizeMinusOne == 2",
                });
            }
        }

        const findings_slice = try findings.toOwnedSlice(alloc);
        return .{ .data = .{
            .mp4_structure_valid = findings_slice.len == 0,
            .audit_findings = findings_slice,
        } };
    }
};

