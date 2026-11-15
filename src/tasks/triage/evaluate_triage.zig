const std = @import("std");
const Allocator = std.mem.Allocator;
const abi = @import("parabellum_abi");
const media_ir = @import("media_ir");
const orders = @import("../remediation/orders.zig");

pub const Inputs = struct {
    size_valid: bool = true,
    is_video: bool = false,
    is_hostile: bool = false,
    extension_violation: bool = false,
    has_embedded_executable: bool = false,
    has_suspicious_script: bool = false,
    matched_keyword: []const u8 = "",
    has_tail_polyglot: bool = false,
    low_mid_entropy: bool = false,
};

pub const OutputsData = struct {
    triage_passed: bool,
    audit_findings: []const media_ir.AuditFindingRow,
    quarantine_orders: []const orders.QuarantineOrder,
};

pub const Outputs = abi.Channels(OutputsData);

/// Evaluates Stage 0 gatekeeper flags into explicit `audit_findings` and `QuarantineOrder`s.
pub const Service = struct {
    pub fn execute(_: *const Service, alloc: Allocator, inputs: Inputs) !Outputs {
        var findings: std.ArrayList(media_ir.AuditFindingRow) = .empty;
        errdefer findings.deinit(alloc);
        var q_orders: std.ArrayList(orders.QuarantineOrder) = .empty;
        errdefer q_orders.deinit(alloc);

        if (!inputs.size_valid) {
            try findings.append(alloc, .{
                .rule_id = "stage0_size_violation",
                .severity = 3,
                .region_tag = "file",
                .message = "File failed Stage 0 size bounds check",
            });
        }

        if (inputs.is_hostile or !inputs.is_video) {
            try findings.append(alloc, .{
                .rule_id = "r01_magic_mismatch",
                .severity = 4,
                .region_tag = "header",
                .message = "File magic is hostile or not a recognized media container",
            });
        }

        if (inputs.extension_violation) {
            try findings.append(alloc, .{
                .rule_id = "r01_extension_spoofing",
                .severity = 3,
                .region_tag = "filename",
                .message = "File extension does not match detected magic container family",
            });
        }

        if (inputs.has_embedded_executable) {
            try findings.append(alloc, .{
                .rule_id = "stage0_embedded_executable",
                .severity = 4,
                .region_tag = "header",
                .message = "Embedded executable signature detected in file header",
            });
        }

        if (inputs.has_suspicious_script) {
            const msg = if (inputs.matched_keyword.len > 0)
                try std.fmt.allocPrint(alloc, "Suspicious script/playlist indicator detected in header: {s}", .{inputs.matched_keyword})
            else
                "Suspicious script/playlist indicator detected in header";
            try findings.append(alloc, .{
                .rule_id = "stage0_head_script",
                .severity = 4,
                .region_tag = "header",
                .message = msg,
            });
        }

        if (inputs.has_tail_polyglot) {
            try findings.append(alloc, .{
                .rule_id = "stage0_tail_polyglot",
                .severity = 3,
                .region_tag = "tail",
                .message = "Appended archive polyglot signature detected in file tail",
            });
        }

        if (inputs.low_mid_entropy) {
            try findings.append(alloc, .{
                .rule_id = "stage0_low_mid_entropy",
                .severity = 2,
                .region_tag = "payload",
                .message = "Mid-file entropy is suspiciously low (possible zero-filled or synthetic decoy)",
            });
        }

        const should_quarantine = !inputs.size_valid or
            inputs.is_hostile or
            !inputs.is_video or
            inputs.has_embedded_executable or
            inputs.has_suspicious_script or
            inputs.has_tail_polyglot;

        if (should_quarantine) {
            try q_orders.append(alloc, .{
                .rule_id = if (inputs.has_suspicious_script)
                    "stage0_head_script"
                else if (inputs.has_embedded_executable)
                    "stage0_embedded_executable"
                else if (inputs.has_tail_polyglot)
                    "stage0_tail_polyglot"
                else
                    "stage0_hostile_reject",
                .reason = "File rejected by Stage 0 gatekeeper policy",
                .severity = 4,
            });
        }

        return .{
            .data = .{
                .triage_passed = !should_quarantine and !inputs.extension_violation,
                .audit_findings = try findings.toOwnedSlice(alloc),
                .quarantine_orders = try q_orders.toOwnedSlice(alloc),
            },
        };
    }
};

