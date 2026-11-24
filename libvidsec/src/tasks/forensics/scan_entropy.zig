const std = @import("std");
const Allocator = std.mem.Allocator;
const abi = @import("parabellum_sdk").task;
const media_ir = @import("media_ir");
const vidsec_math = @import("vidsec_math");
const orders = @import("../remediation/orders.zig");

pub const Inputs = struct {
    stream: abi.BoundedStreamReader,
    ir_unreferenced_slack: []const media_ir.IrUnreferencedSlackRow = &.{},
    entropy_threshold: f64 = 7.2,
};

pub const OutputsData = struct {
    audit_findings: []const media_ir.AuditFindingRow,
    zero_out_orders: []const orders.ZeroOutOrder,
};

pub const Outputs = abi.Channels(OutputsData);

/// Stage 2 format-agnostic entropy scanner over `ir_unreferenced_slack`.
/// Emits `AuditFindingRow` + `ZeroOutOrder` when slack entropy exceeds `entropy_threshold`.
pub const Service = struct {
    pub fn execute(_: *const Service, alloc: Allocator, inputs: Inputs) !Outputs {
        var findings: std.ArrayList(media_ir.AuditFindingRow) = .empty;
        errdefer findings.deinit(alloc);
        var zero_orders: std.ArrayList(orders.ZeroOutOrder) = .empty;
        errdefer zero_orders.deinit(alloc);

        const stream_len = inputs.stream.len();
        var window_buf: [65536]u8 = undefined;

        for (inputs.ir_unreferenced_slack) |slack| {
            if (slack.byte_length < 32 or slack.file_offset >= stream_len) continue;
            const avail = stream_len - slack.file_offset;
            const to_scan: usize = @intCast(@min(@min(slack.byte_length, avail), window_buf.len));
            if (to_scan < 32) continue;

            try inputs.stream.readAt(slack.file_offset, window_buf[0..to_scan]);
            const ent = vidsec_math.shannonEntropy(window_buf[0..to_scan]);

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
                    .region_tag = slack.region_tag,
                    .measured_value = ent,
                    .message = msg,
                });
                try zero_orders.append(alloc, .{
                    .offset = slack.file_offset,
                    .length = slack.byte_length,
                    .rule_id = "high_entropy_slack_payload",
                    .reason = "Zero out suspicious high-entropy slack region",
                });
            }
        }

        return .{ .data = .{
            .audit_findings = try findings.toOwnedSlice(alloc),
            .zero_out_orders = try zero_orders.toOwnedSlice(alloc),
        } };
    }
};

