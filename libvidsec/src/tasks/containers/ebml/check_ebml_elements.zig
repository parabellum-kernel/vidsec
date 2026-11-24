const std = @import("std");
const Allocator = std.mem.Allocator;
const abi = @import("parabellum_sdk").task;
const media_ir = @import("media_ir");
const dissect_ebml = @import("dissect_ebml.zig");
const common = @import("../common.zig");

pub const Inputs = struct {
    ebml_triage: dissect_ebml.EbmlTriageRow,
    ebml_elements: []const dissect_ebml.EbmlElementRow,
};

pub const OutputsData = struct {
    audit_findings: []const media_ir.AuditFindingRow,
};

pub const Outputs = abi.Channels(OutputsData);

/// Stage 1b atomic validator for EBML header, Segment presence, containment, depth, and unknown-size invariants (`R03`).
pub const Service = struct {
    logger: abi.Logger = .{},

    pub fn execute(self: *const Service, alloc: Allocator, inputs: Inputs) !Outputs {
        var findings: std.ArrayList(media_ir.AuditFindingRow) = .empty;
        errdefer findings.deinit(alloc);

        const triage = inputs.ebml_triage;
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

        common.logFindings(self.logger, findings.items);
        return .{ .data = .{
            .audit_findings = try findings.toOwnedSlice(alloc),
        } };
    }
};
