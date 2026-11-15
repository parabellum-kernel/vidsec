const std = @import("std");
const Allocator = std.mem.Allocator;
const abi = @import("flowdata_abi");
const media_ir = @import("media_ir");
const vidsec_magic = @import("vidsec_magic");
const orders = @import("../remediation/orders.zig");
const r07 = @import("check_r07_suspicious_padding.zig");

pub const Inputs = struct {
    stream: abi.BoundedStreamReader,
    ir_unreferenced_slack: []const media_ir.IrUnreferencedSlackRow = &.{},
    entropy_threshold: f64 = 7.2,
    large_slack_bytes: u64 = 4096,
};

pub const OutputsData = struct {
    audit_findings: []const media_ir.AuditFindingRow,
    zero_out_orders: []const orders.ZeroOutOrder,
    quarantine_orders: []const orders.QuarantineOrder,
};

pub const Outputs = abi.Channels(OutputsData);

fn isInteriorOrGapSlack(tag: []const u8) bool {
    return std.mem.eql(u8, tag, "leading_gap") or
        std.mem.eql(u8, tag, "inter_region_gap") or
        std.mem.eql(u8, tag, "interior_media_slack");
}

/// Stage 2 R08 validator: inspects unreferenced gaps & `mdat`/`movi`/`Cluster` interior slack
/// for embedded signatures, high Shannon entropy, or large (>= 4 KB) unreferenced regions.
pub const Service = struct {
    pub fn execute(_: *const Service, alloc: Allocator, inputs: Inputs) !Outputs {
        var findings: std.ArrayList(media_ir.AuditFindingRow) = .empty;
        errdefer findings.deinit(alloc);
        var zero_orders: std.ArrayList(orders.ZeroOutOrder) = .empty;
        errdefer zero_orders.deinit(alloc);
        var quarantines: std.ArrayList(orders.QuarantineOrder) = .empty;
        errdefer quarantines.deinit(alloc);

        const stream_len = inputs.stream.len();

        for (inputs.ir_unreferenced_slack) |slack| {
            if (!isInteriorOrGapSlack(slack.region_tag)) continue;
            if (slack.byte_length < 32 or slack.file_offset >= stream_len) continue;

            if (try vidsec_magic.scanMultiWindowSignatures(&inputs.stream, slack.file_offset, slack.byte_length)) |hit| {
                const msg = try std.fmt.allocPrint(
                    alloc,
                    "Embedded signature ({s}) in {s} at offset {d}",
                    .{ hit.info.description, slack.region_tag, hit.file_offset },
                );
                try findings.append(alloc, .{
                    .rule_id = "r08_slack_embedded_signature",
                    .severity = 4,
                    .file_offset = @intCast(hit.file_offset),
                    .byte_length = @intCast(slack.byte_length),
                    .end_offset = @intCast(slack.file_offset +| slack.byte_length),
                    .region_tag = try alloc.dupe(u8, slack.region_tag),
                    .message = msg,
                });
                try quarantines.append(alloc, .{
                    .rule_id = "r08_slack_embedded_signature",
                    .reason = msg,
                    .severity = 4,
                });
                continue;
            }

            const ent = try r07.maxMultiWindowEntropy(&inputs.stream, slack.file_offset, slack.byte_length);
            if (ent >= inputs.entropy_threshold) {
                const msg = try std.fmt.allocPrint(
                    alloc,
                    "High-entropy ({d:.2} bits/byte) payload in {s} at offset {d}",
                    .{ ent, slack.region_tag, slack.file_offset },
                );
                try findings.append(alloc, .{
                    .rule_id = "high_entropy_slack_payload",
                    .severity = 3,
                    .file_offset = @intCast(slack.file_offset),
                    .byte_length = @intCast(slack.byte_length),
                    .end_offset = @intCast(slack.file_offset +| slack.byte_length),
                    .region_tag = try alloc.dupe(u8, slack.region_tag),
                    .measured_value = ent,
                    .message = msg,
                });
                try zero_orders.append(alloc, .{
                    .offset = slack.file_offset,
                    .length = slack.byte_length,
                    .rule_id = "high_entropy_slack_payload",
                    .reason = "Zero out suspicious high-entropy slack region",
                });
            } else if (slack.byte_length >= inputs.large_slack_bytes) {
                const msg = try std.fmt.allocPrint(
                    alloc,
                    "Large unreferenced {s} ({d} bytes) at offset {d}",
                    .{ slack.region_tag, slack.byte_length, slack.file_offset },
                );
                try findings.append(alloc, .{
                    .rule_id = "r08_large_unreferenced_slack",
                    .severity = 2,
                    .file_offset = @intCast(slack.file_offset),
                    .byte_length = @intCast(slack.byte_length),
                    .end_offset = @intCast(slack.file_offset +| slack.byte_length),
                    .region_tag = try alloc.dupe(u8, slack.region_tag),
                    .measured_value = @floatFromInt(slack.byte_length),
                    .message = msg,
                });
                try zero_orders.append(alloc, .{
                    .offset = slack.file_offset,
                    .length = slack.byte_length,
                    .rule_id = "r08_large_unreferenced_slack",
                    .reason = "Zero out large unreferenced slack region",
                });
            }
        }

        return .{ .data = .{
            .audit_findings = try findings.toOwnedSlice(alloc),
            .zero_out_orders = try zero_orders.toOwnedSlice(alloc),
            .quarantine_orders = try quarantines.toOwnedSlice(alloc),
        } };
    }
};
