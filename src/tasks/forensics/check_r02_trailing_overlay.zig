const std = @import("std");
const Allocator = std.mem.Allocator;
const abi = @import("flowdata_abi");
const media_ir = @import("media_ir");
const vidsec_magic = @import("vidsec_magic");
const vidsec_math = @import("vidsec_math");
const orders = @import("../remediation/orders.zig");

pub const Inputs = struct {
    stream: abi.BoundedStreamReader,
    ir_unreferenced_slack: []const media_ir.IrUnreferencedSlackRow = &.{},
    entropy_threshold: f64 = 7.2,
    allow_truncate: bool = true,
};

pub const OutputsData = struct {
    audit_findings: []const media_ir.AuditFindingRow,
    truncate_orders: []const orders.TruncateOrder,
    quarantine_orders: []const orders.QuarantineOrder,
};

pub const Outputs = abi.Channels(OutputsData);

/// Stage 2 R02 validator: inspects `trailing_overlay` slack with 16-byte zero tolerance,
/// 64 KB signature scanning, and Shannon entropy measurement.
pub const Service = struct {
    pub fn execute(_: *const Service, alloc: Allocator, inputs: Inputs) !Outputs {
        var findings: std.ArrayList(media_ir.AuditFindingRow) = .empty;
        errdefer findings.deinit(alloc);
        var truncs: std.ArrayList(orders.TruncateOrder) = .empty;
        errdefer truncs.deinit(alloc);
        var quarantines: std.ArrayList(orders.QuarantineOrder) = .empty;
        errdefer quarantines.deinit(alloc);

        const stream_len = inputs.stream.len();
        var window_buf: [65536]u8 = undefined;

        for (inputs.ir_unreferenced_slack) |slack| {
            if (!std.mem.eql(u8, slack.region_tag, "trailing_overlay")) continue;
            if (slack.byte_length == 0 or slack.file_offset >= stream_len) continue;

            const avail = stream_len - slack.file_offset;
            const to_scan: usize = @intCast(@min(@min(slack.byte_length, avail), window_buf.len));
            try inputs.stream.readAt(slack.file_offset, window_buf[0..to_scan]);
            const slice = window_buf[0..to_scan];

            // 16-byte zero tolerance
            if (slack.byte_length <= 16 and std.mem.allEqual(u8, slice, 0)) {
                continue;
            }

            const ent = vidsec_math.shannonEntropy(slice);
            if (vidsec_magic.findFirstEmbeddedSignature(slice, 1)) |sig| {
                const msg = try std.fmt.allocPrint(
                    alloc,
                    "Trailing polyglot signature ({s}) at offset {d} ({d} bytes)",
                    .{ sig.info.description, slack.file_offset +| sig.relative_offset, slack.byte_length },
                );
                try findings.append(alloc, .{
                    .rule_id = "r02_trailing_polyglot_signature",
                    .severity = 4,
                    .file_offset = @intCast(slack.file_offset),
                    .byte_length = @intCast(slack.byte_length),
                    .end_offset = @intCast(slack.file_offset +| slack.byte_length),
                    .region_tag = "trailing_overlay",
                    .measured_value = ent,
                    .message = msg,
                });
                try quarantines.append(alloc, .{
                    .rule_id = "r02_trailing_polyglot_signature",
                    .reason = msg,
                    .severity = 4,
                });
            } else {
                const msg = try std.fmt.allocPrint(
                    alloc,
                    "Trailing unparsed overlay of {d} bytes at offset {d} (entropy={d:.2})",
                    .{ slack.byte_length, slack.file_offset, ent },
                );
                try findings.append(alloc, .{
                    .rule_id = "r02_trailing_overlay",
                    .severity = 3,
                    .file_offset = @intCast(slack.file_offset),
                    .byte_length = @intCast(slack.byte_length),
                    .end_offset = @intCast(slack.file_offset +| slack.byte_length),
                    .region_tag = "trailing_overlay",
                    .measured_value = ent,
                    .message = msg,
                });
                if (inputs.allow_truncate) {
                    try truncs.append(alloc, .{
                        .new_size = slack.file_offset,
                        .rule_id = "r02_trailing_overlay",
                        .reason = "Truncate trailing unreferenced overlay past container end",
                    });
                }
            }
        }

        return .{ .data = .{
            .audit_findings = try findings.toOwnedSlice(alloc),
            .truncate_orders = try truncs.toOwnedSlice(alloc),
            .quarantine_orders = try quarantines.toOwnedSlice(alloc),
        } };
    }
};
