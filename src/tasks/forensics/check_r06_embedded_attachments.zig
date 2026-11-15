const std = @import("std");
const Allocator = std.mem.Allocator;
const abi = @import("flowdata_abi");
const media_ir = @import("media_ir");
const tika = @import("tika");
const vidsec_magic = @import("vidsec_magic");
const orders = @import("../remediation/orders.zig");

pub const Inputs = struct {
    stream: abi.BoundedStreamReader,
    ir_attachments: []const media_ir.IrAttachmentRow = &.{},
    quarantine_on_fail: bool = true,
};

pub const OutputsData = struct {
    audit_findings: []const media_ir.AuditFindingRow,
    quarantine_orders: []const orders.QuarantineOrder,
};

pub const Outputs = abi.Channels(OutputsData);

fn isFontMagic(head: []const u8) bool {
    if (head.len < 4) return false;
    return std.mem.eql(u8, head[0..4], "\x00\x01\x00\x00") or
        std.mem.eql(u8, head[0..4], "OTTO") or
        std.mem.eql(u8, head[0..4], "ttcf");
}

fn endsWithIgnoreCase(haystack: []const u8, suffix: []const u8) bool {
    if (haystack.len < suffix.len) return false;
    return std.ascii.eqlIgnoreCase(haystack[haystack.len - suffix.len ..], suffix);
}

/// Stage 2 R06 validator: inspects embedded attachments for path traversal,
/// executable/script payloads, risky fonts (.ttf/.otf), and MIME spoofing.
pub const Service = struct {
    pub fn execute(_: *const Service, alloc: Allocator, inputs: Inputs) !Outputs {
        var findings: std.ArrayList(media_ir.AuditFindingRow) = .empty;
        errdefer findings.deinit(alloc);
        var quarantines: std.ArrayList(orders.QuarantineOrder) = .empty;
        errdefer quarantines.deinit(alloc);

        const stream_len = inputs.stream.len();
        var buf: [65536]u8 = undefined;

        for (inputs.ir_attachments) |att| {
            // 1. Path traversal in filename
            if (std.mem.indexOf(u8, att.file_name, "../") != null or
                std.mem.indexOf(u8, att.file_name, "..\\") != null or
                std.mem.startsWith(u8, att.file_name, "/") or
                std.mem.startsWith(u8, att.file_name, "\\"))
            {
                const msg = try std.fmt.allocPrint(alloc, "Attachment filename contains path traversal: '{s}'", .{att.file_name});
                try findings.append(alloc, .{
                    .rule_id = "r06_attachment_path_traversal",
                    .severity = 4,
                    .file_offset = @intCast(att.file_offset),
                    .byte_length = @intCast(att.byte_length),
                    .region_tag = try alloc.dupe(u8, att.file_name),
                    .message = msg,
                });
                if (inputs.quarantine_on_fail) {
                    try quarantines.append(alloc, .{ .rule_id = "r06_attachment_path_traversal", .reason = msg, .severity = 4 });
                }
            }

            if (att.byte_length == 0 or att.file_offset >= stream_len) continue;
            const avail = stream_len - att.file_offset;
            const to_read: usize = @intCast(@min(@min(att.byte_length, avail), buf.len));
            try inputs.stream.readAt(att.file_offset, buf[0..to_read]);
            const slice = buf[0..to_read];

            // 2. Hostile executable/archive/script signature
            if (vidsec_magic.findFirstEmbeddedSignature(slice, 1)) |sig| {
                const msg = try std.fmt.allocPrint(
                    alloc,
                    "Attachment '{s}' contains hostile signature ({s})",
                    .{ att.file_name, sig.info.description },
                );
                try findings.append(alloc, .{
                    .rule_id = "r06_attachment_hostile_payload",
                    .severity = 4,
                    .file_offset = @intCast(att.file_offset),
                    .byte_length = @intCast(att.byte_length),
                    .region_tag = try alloc.dupe(u8, att.file_name),
                    .message = msg,
                });
                if (inputs.quarantine_on_fail) {
                    try quarantines.append(alloc, .{ .rule_id = "r06_attachment_hostile_payload", .reason = msg, .severity = 4 });
                }
                continue;
            }
            if (vidsec_magic.scanHeadScripts(slice)) |kw| {
                const msg = try std.fmt.allocPrint(
                    alloc,
                    "Attachment '{s}' contains suspicious script indicator ({s})",
                    .{ att.file_name, kw },
                );
                try findings.append(alloc, .{
                    .rule_id = "r06_attachment_hostile_payload",
                    .severity = 4,
                    .file_offset = @intCast(att.file_offset),
                    .byte_length = @intCast(att.byte_length),
                    .region_tag = try alloc.dupe(u8, att.file_name),
                    .message = msg,
                });
                if (inputs.quarantine_on_fail) {
                    try quarantines.append(alloc, .{ .rule_id = "r06_attachment_hostile_payload", .reason = msg, .severity = 4 });
                }
                continue;
            }

            // 3. Risky font attachment (.ttf / .otf targeting FreeType/libass)
            if (isFontMagic(slice) or endsWithIgnoreCase(att.file_name, ".ttf") or endsWithIgnoreCase(att.file_name, ".otf")) {
                const msg = try std.fmt.allocPrint(
                    alloc,
                    "Risky font attachment '{s}' (FreeType/libass attack surface)",
                    .{att.file_name},
                );
                try findings.append(alloc, .{
                    .rule_id = "r06_attachment_risky_font",
                    .severity = 3,
                    .file_offset = @intCast(att.file_offset),
                    .byte_length = @intCast(att.byte_length),
                    .region_tag = try alloc.dupe(u8, att.file_name),
                    .message = msg,
                });
                if (inputs.quarantine_on_fail) {
                    try quarantines.append(alloc, .{ .rule_id = "r06_attachment_risky_font", .reason = msg, .severity = 3 });
                }
            }

            // 4. MIME spoofing check via tika
            const det = tika.detect(slice);
            if (det.id != .unknown and att.mime_type.len > 0 and
                !std.mem.eql(u8, att.mime_type, "application/octet-stream") and
                !std.ascii.eqlIgnoreCase(att.mime_type, det.mime_type))
            {
                const msg = try std.fmt.allocPrint(
                    alloc,
                    "Attachment '{s}' MIME mismatch: declared '{s}' vs detected '{s}'",
                    .{ att.file_name, att.mime_type, det.mime_type },
                );
                try findings.append(alloc, .{
                    .rule_id = "r06_attachment_mime_mismatch",
                    .severity = 3,
                    .file_offset = @intCast(att.file_offset),
                    .byte_length = @intCast(att.byte_length),
                    .region_tag = try alloc.dupe(u8, att.file_name),
                    .message = msg,
                });
            }
        }

        return .{ .data = .{
            .audit_findings = try findings.toOwnedSlice(alloc),
            .quarantine_orders = try quarantines.toOwnedSlice(alloc),
        } };
    }
};
