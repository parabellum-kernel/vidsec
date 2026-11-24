const std = @import("std");
const Allocator = std.mem.Allocator;
const abi = @import("parabellum_sdk").task;
const media_ir = @import("media_ir");
const orders = @import("../remediation/orders.zig");
const common = @import("../containers/common.zig");

pub const Inputs = struct {
    ir_external_refs: []const media_ir.IrExternalRefRow = &.{},
    quarantine_on_fail: bool = true,
};

pub const OutputsData = struct {
    audit_findings: []const media_ir.AuditFindingRow,
    quarantine_orders: []const orders.QuarantineOrder,
};

pub const Outputs = abi.Channels(OutputsData);

fn startsWithIgnoreCase(haystack: []const u8, prefix: []const u8) bool {
    if (haystack.len < prefix.len) return false;
    return std.ascii.eqlIgnoreCase(haystack[0..prefix.len], prefix);
}

/// Stage 2 R05 validator: classifies external data/URI references (`dref`, `rmra`/`rdrf`, `NextFilename`).
pub const Service = struct {
    logger: abi.Logger = .{},

    pub fn execute(self: *const Service, alloc: Allocator, inputs: Inputs) !Outputs {
        var findings: std.ArrayList(media_ir.AuditFindingRow) = .empty;
        errdefer findings.deinit(alloc);
        var quarantines: std.ArrayList(orders.QuarantineOrder) = .empty;
        errdefer quarantines.deinit(alloc);

        for (inputs.ir_external_refs) |ref| {
            const url = std.mem.trim(u8, ref.target_url, " \t\r\n\x00");
            var rule_id: []const u8 = "r05_external_ref_present";
            var severity: i64 = 3;

            if (startsWithIgnoreCase(url, "http://") or startsWithIgnoreCase(url, "https://")) {
                rule_id = "r05_external_ref_ssrf";
                severity = 4;
            } else if (std.mem.startsWith(u8, url, "\\\\")) {
                rule_id = "r05_external_ref_unc_smb";
                severity = 4;
            } else if (startsWithIgnoreCase(url, "file://")) {
                rule_id = "r05_external_ref_file_uri";
                severity = 4;
            } else if (std.mem.indexOf(u8, url, "../") != null or std.mem.indexOf(u8, url, "..\\") != null) {
                rule_id = "r05_external_ref_path_traversal";
                severity = 4;
            }

            const msg = try std.fmt.allocPrint(
                alloc,
                "External reference in {s} at offset {d}: '{s}'",
                .{ ref.source_tag, ref.file_offset, url },
            );
            try findings.append(alloc, .{
                .rule_id = rule_id,
                .severity = severity,
                .file_offset = @intCast(ref.file_offset),
                .region_tag = try alloc.dupe(u8, ref.source_tag),
                .message = msg,
            });
            if (inputs.quarantine_on_fail) {
                try quarantines.append(alloc, .{
                    .rule_id = rule_id,
                    .reason = msg,
                    .severity = severity,
                });
            }
        }

        common.logFindings(self.logger, findings.items);
        return .{ .data = .{
            .audit_findings = try findings.toOwnedSlice(alloc),
            .quarantine_orders = try quarantines.toOwnedSlice(alloc),
        } };
    }
};

