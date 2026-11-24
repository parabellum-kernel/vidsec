const std = @import("std");
const Allocator = std.mem.Allocator;
const abi = @import("parabellum_sdk").task;
const ebml = @import("ebml");
const media_ir = @import("media_ir");
const common = @import("common.zig");
const orders = @import("../remediation/orders.zig");
const dissect_ebml = @import("dissect_ebml.zig");
const remediation_encoder = @import("remediation_encoder.zig");

pub const Inputs = struct {
    stream: abi.BoundedStreamReader,
    ebml_elements: []const dissect_ebml.EbmlElementRow = &.{},
    max_blocks_to_inspect: u64 = 4096,
    rule_id: []const u8 = "cve_ebml_lacing_corruption",
    severity: i64 = 4,
    quarantine_on_fail: bool = true,
    on_fail: []const u8 = "",
};

pub const OutputsData = struct {
    audit_findings: []const media_ir.AuditFindingRow,
    quarantine_orders: []const orders.QuarantineOrder,
    tombstone_orders: []const orders.TombstoneRegionOrder,
};

pub const Outputs = abi.Channels(OutputsData);

fn inspectBlockPayload(
    alloc: Allocator,
    inputs: Inputs,
    source: ebml.ByteSource,
    tag_hex: []const u8,
    header_offset: u64,
    payload_offset: u64,
    available_bytes: u64,
    findings: *std.ArrayList(media_ir.AuditFindingRow),
    q_orders: *std.ArrayList(orders.QuarantineOrder),
    tombstone_orders: *std.ArrayList(orders.TombstoneRegionOrder),
) !void {
    var hdr_buf: [1024]u8 = undefined;
    const stream_avail = source.file_size -| payload_offset;
    const capped_avail = @min(available_bytes, stream_avail);
    const to_read: usize = @intCast(@min(capped_avail, hdr_buf.len));
    if (to_read == 0) return;

    try source.readExactAt(hdr_buf[0..to_read], payload_offset);
    var m = ebml.mkv.lacing.inspectBlockLacing(hdr_buf[0..to_read]);

    if (capped_avail > to_read and !m.is_truncated_or_invalid) {
        const true_remaining = capped_avail -| m.header_bytes;
        switch (m.lacing_kind) {
            .xiph, .ebml => {
                m.has_sum_overflow = m.declared_frames_sum > true_remaining;
            },
            .fixed => {
                m.declared_frames_sum = true_remaining;
                m.has_fixed_remainder = (m.frame_count > 0) and (true_remaining % m.frame_count != 0);
            },
            .none => {},
        }
    }

    const has_violation = m.has_negative_delta or m.has_sum_overflow or m.has_fixed_remainder or m.is_truncated_or_invalid;
    if (has_violation) {
        const reason_kind: []const u8 = if (m.has_negative_delta)
            "negative signed EBML lacing delta underflow"
        else if (m.has_sum_overflow)
            "laced frame sizes exceed block payload"
        else if (m.has_fixed_remainder)
            "fixed lacing payload not divisible by frame count"
        else
            "truncated or malformed block lacing header";

        const msg = try std.fmt.allocPrint(
            alloc,
            "Matroska {s} at offset {d} failed lacing check: {s} (frames={d}, sum={d}, avail={d})",
            .{ tag_hex, payload_offset, reason_kind, m.frame_count, m.declared_frames_sum, capped_avail },
        );
        try findings.append(alloc, .{
            .rule_id = inputs.rule_id,
            .severity = @intCast(inputs.severity),
            .file_offset = @intCast(payload_offset),
            .byte_length = @intCast(@min(m.header_bytes, capped_avail)),
            .end_offset = @intCast(payload_offset +| @min(m.header_bytes, capped_avail)),
            .region_tag = try alloc.dupe(u8, tag_hex),
            .measured_value = @floatFromInt(m.declared_frames_sum),
            .message = msg,
        });
        const policy = try remediation_encoder.resolvePolicy(inputs.on_fail, inputs.quarantine_on_fail);
        switch (policy) {
            .quarantine => {
                try q_orders.append(alloc, .{
                    .rule_id = inputs.rule_id,
                    .reason = msg,
                    .severity = inputs.severity,
                });
            },
            .tombstone => {
                try tombstone_orders.append(alloc, .{
                    .family = .ebml,
                    .region_tag = try alloc.dupe(u8, tag_hex),
                    .header_offset = header_offset,
                    .payload_offset = payload_offset,
                    .available_bytes = available_bytes,
                    .rule_id = inputs.rule_id,
                    .reason = msg,
                    .severity = inputs.severity,
                });
            },
            .log_only => {},
            else => return error.UnsupportedRemediationPolicy,
        }
    }
}

fn walkBlockGroup(
    alloc: Allocator,
    inputs: Inputs,
    source: ebml.ByteSource,
    start_offset: u64,
    end_offset: u64,
    inspected: *u64,
    findings: *std.ArrayList(media_ir.AuditFindingRow),
    q_orders: *std.ArrayList(orders.QuarantineOrder),
    tombstone_orders: *std.ArrayList(orders.TombstoneRegionOrder),
) !void {
    var cursor = start_offset;
    while (cursor < end_offset and inspected.* < inputs.max_blocks_to_inspect) {
        const hdr = (try ebml.ebml.readElementHeader(source, cursor)) orelse break;
        const p_off = hdr.payloadOffset();
        if (p_off <= cursor or p_off > end_offset) break;
        const next_off = @min(end_offset, p_off +| hdr.data_size);
        const avail = next_off -| p_off;

        if (hdr.id == 0xA1) {
            inspected.* += 1;
            try inspectBlockPayload(alloc, inputs, source, "0xa1", cursor, p_off, avail, findings, q_orders, tombstone_orders);
        }
        if (next_off <= cursor) break;
        cursor = next_off;
    }
}

/// Declarative Class IV Matroska Block/SimpleBlock lacing validator (`CVE-2016-1621`).
pub const Service = struct {
    pub fn execute(_: *const Service, alloc: Allocator, inputs: Inputs) !Outputs {
        const source = common.streamToSource(ebml.ByteSource, &inputs.stream);

        var findings: std.ArrayList(media_ir.AuditFindingRow) = .empty;
        errdefer findings.deinit(alloc);
        var q_orders: std.ArrayList(orders.QuarantineOrder) = .empty;
        errdefer q_orders.deinit(alloc);
        var tombstone_orders: std.ArrayList(orders.TombstoneRegionOrder) = .empty;
        errdefer tombstone_orders.deinit(alloc);

        var inspected: u64 = 0;
        for (inputs.ebml_elements) |elem| {
            if (inspected >= inputs.max_blocks_to_inspect) break;

            if (std.ascii.eqlIgnoreCase(elem.ebml_id_hex, "0xa3") or
                std.ascii.eqlIgnoreCase(elem.ebml_id_hex, "0xa1"))
            {
                inspected += 1;
                try inspectBlockPayload(
                    alloc,
                    inputs,
                    source,
                    elem.ebml_id_hex,
                    elem.header_offset,
                    elem.payload_offset,
                    elem.available_bytes,
                    &findings,
                    &q_orders,
                    &tombstone_orders,
                );
            } else if (std.ascii.eqlIgnoreCase(elem.ebml_id_hex, "0x1f43b675")) {
                // Walk Cluster children (SimpleBlock 0xA3, BlockGroup 0xA0 -> Block 0xA1)
                const cluster_end = @min(source.file_size, elem.payload_offset +| elem.available_bytes);
                var cursor = elem.payload_offset;
                while (cursor < cluster_end and inspected < inputs.max_blocks_to_inspect) {
                    const hdr = (try ebml.ebml.readElementHeader(source, cursor)) orelse break;
                    const p_off = hdr.payloadOffset();
                    if (p_off <= cursor or p_off > cluster_end) break;
                    const next_off = @min(cluster_end, p_off +| hdr.data_size);
                    const avail = next_off -| p_off;

                    if (hdr.id == 0xA3) {
                        inspected += 1;
                        try inspectBlockPayload(alloc, inputs, source, "0xa3", cursor, p_off, avail, &findings, &q_orders, &tombstone_orders);
                    } else if (hdr.id == 0xA0) {
                        try walkBlockGroup(alloc, inputs, source, p_off, next_off, &inspected, &findings, &q_orders, &tombstone_orders);
                    }
                    if (next_off <= cursor) break;
                    cursor = next_off;
                }
            }
        }

        return .{ .data = .{
            .audit_findings = try findings.toOwnedSlice(alloc),
            .quarantine_orders = try q_orders.toOwnedSlice(alloc),
            .tombstone_orders = try tombstone_orders.toOwnedSlice(alloc),
        } };
    }
};
