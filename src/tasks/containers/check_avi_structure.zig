const std = @import("std");
const Allocator = std.mem.Allocator;
const abi = @import("parabellum_abi");
const media_ir = @import("media_ir");
const dissect_riff = @import("dissect_riff.zig");

pub const Inputs = struct {
    riff_triage: dissect_riff.RiffTriageRow,
    riff_chunks: []const dissect_riff.RiffChunkRow,
    avi_stream_headers: []const dissect_riff.AviStreamHeaderRow = &.{},
};

pub const OutputsData = struct {
    avi_structure_valid: bool,
    audit_findings: []const media_ir.AuditFindingRow,
};

pub const Outputs = abi.Channels(OutputsData);

/// Stage 1b format-specific structural validator for RIFF/AVI (`R01`, `R03`, `R09`).
pub const Service = struct {
    pub fn execute(_: *const Service, alloc: Allocator, inputs: Inputs) !Outputs {
        var findings: std.ArrayList(media_ir.AuditFindingRow) = .empty;
        errdefer findings.deinit(alloc);

        const triage = inputs.riff_triage;
        // R01: Root magic & root_size vs file_size - 8
        if (!triage.is_valid_root_magic) {
            try findings.append(alloc, .{
                .rule_id = "riff_magic_invalid",
                .severity = 4,
                .file_offset = 0,
                .region_tag = "RIFF",
                .message = "Initial 4 bytes do not match RIFF, RIFX, or RF64",
            });
        }
        if (triage.file_size >= 8 and triage.root_size != (triage.file_size - 8)) {
            try findings.append(alloc, .{
                .rule_id = "riff_root_size_mismatch",
                .severity = 3,
                .file_offset = 4,
                .region_tag = "RIFF",
                .measured_value = @floatFromInt(triage.root_size),
                .message = "Declared RIFF root_size does not match file_size - 8",
            });
        }

        // R03: Truncated chunk header, containment overflow, recursion depth
        if (triage.header_truncated_at) |trunc_off| {
            try findings.append(alloc, .{
                .rule_id = "riff_chunk_header_truncated",
                .severity = 3,
                .file_offset = @intCast(trunc_off),
                .region_tag = "RIFF",
                .message = "Truncated RIFF chunk header",
            });
        }
        for (inputs.riff_chunks) |c| {
            if (c.is_truncated or c.is_overflow) {
                try findings.append(alloc, .{
                    .rule_id = "riff_chunk_containment_overflow",
                    .severity = 3,
                    .file_offset = @intCast(c.header_offset),
                    .byte_length = @intCast(c.available_bytes),
                    .end_offset = @intCast(c.header_offset +| c.available_bytes),
                    .region_tag = try alloc.dupe(u8, c.fourcc),
                    .message = "RIFF chunk truncated or overflows parent/file boundary",
                });
            }
            if (c.depth > 32) {
                try findings.append(alloc, .{
                    .rule_id = "riff_recursion_depth_exceeded",
                    .severity = 3,
                    .file_offset = @intCast(c.header_offset),
                    .region_tag = try alloc.dupe(u8, c.fourcc),
                    .measured_value = @floatFromInt(c.depth),
                    .message = "RIFF chunk nesting depth exceeds 32",
                });
            }
        }

        // R09: BITMAPINFOHEADER integer overflow & bounds + idx1 bounds
        for (inputs.avi_stream_headers) |s| {
            if (!s.has_video) continue;
            if (s.dim_mul_overflow) {
                try findings.append(alloc, .{
                    .rule_id = "avi_bitmap_dim_overflow",
                    .severity = 4,
                    .file_offset = @intCast(s.strf_offset),
                    .byte_length = @intCast(s.strf_size),
                    .region_tag = "strf",
                    .message = "AVI BITMAPINFOHEADER biWidth * abs(biHeight) * biBitCount integer overflow",
                });
            }
            if (s.height == std.math.minInt(i32)) {
                try findings.append(alloc, .{
                    .rule_id = "avi_bitmap_height_int32_min",
                    .severity = 4,
                    .file_offset = @intCast(s.strf_offset),
                    .byte_length = @intCast(s.strf_size),
                    .region_tag = "strf",
                    .message = "AVI BITMAPINFOHEADER biHeight equals INT32_MIN",
                });
            }
            if (s.bi_size < 40) {
                try findings.append(alloc, .{
                    .rule_id = "avi_bitmap_header_too_small",
                    .severity = 3,
                    .file_offset = @intCast(s.strf_offset),
                    .byte_length = @intCast(s.strf_size),
                    .region_tag = "strf",
                    .measured_value = @floatFromInt(s.bi_size),
                    .message = "AVI BITMAPINFOHEADER biSize is smaller than 40 bytes",
                });
            }
            if (s.bi_clr_used > 0 and (40 +| (s.bi_clr_used *| 4)) > s.strf_size) {
                try findings.append(alloc, .{
                    .rule_id = "avi_bitmap_clr_used_overflow",
                    .severity = 4,
                    .file_offset = @intCast(s.strf_offset),
                    .byte_length = @intCast(s.strf_size),
                    .region_tag = "strf",
                    .measured_value = @floatFromInt(s.bi_clr_used),
                    .message = "AVI BITMAPINFOHEADER biClrUsed palette exceeds strf chunk size",
                });
            }
        }

        if (triage.idx1_size > 0 and (triage.idx1_entry_count *| 16) > triage.idx1_size) {
            try findings.append(alloc, .{
                .rule_id = "avi_idx1_entry_overflow",
                .severity = 3,
                .byte_length = @intCast(triage.idx1_size),
                .region_tag = "idx1",
                .measured_value = @floatFromInt(triage.idx1_entry_count),
                .message = "AVI idx1 entry count * 16 exceeds idx1 chunk size",
            });
        }

        const findings_slice = try findings.toOwnedSlice(alloc);
        return .{ .data = .{
            .avi_structure_valid = findings_slice.len == 0,
            .audit_findings = findings_slice,
        } };
    }
};

