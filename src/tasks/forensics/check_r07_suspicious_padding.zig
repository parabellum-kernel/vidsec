const std = @import("std");
const Allocator = std.mem.Allocator;
const abi = @import("parabellum_sdk").task;
const media_ir = @import("media_ir");
const vidsec_magic = @import("vidsec_magic");
const vidsec_math = @import("vidsec_math");
const orders = @import("../remediation/orders.zig");

pub const Inputs = struct {
    stream: abi.BoundedStreamReader,
    ir_regions: []const media_ir.IrRegionRow = &.{},
    entropy_threshold: f64 = 7.2,
};

pub const OutputsData = struct {
    audit_findings: []const media_ir.AuditFindingRow,
    zero_out_orders: []const orders.ZeroOutOrder,
    quarantine_orders: []const orders.QuarantineOrder,
};

pub const Outputs = abi.Channels(OutputsData);

/// Computes maximum Shannon entropy across up to 3 bounded 64 KB windows (`start`, `mid`, `end`).
pub fn maxMultiWindowEntropy(stream: *const abi.BoundedStreamReader, region_offset: u64, region_len: u64) !f64 {
    const stream_len = stream.len();
    if (region_offset >= stream_len or region_len == 0) return 0.0;
    const bounded_len = @min(region_len, stream_len - region_offset);
    if (bounded_len < 32) return 0.0;

    const win_size: u64 = 65536;
    var buf: [65536]u8 = undefined;
    var max_ent: f64 = 0.0;

    if (bounded_len <= win_size) {
        const n: usize = @intCast(bounded_len);
        try stream.readAt(region_offset, buf[0..n]);
        return vidsec_math.shannonEntropy(buf[0..n]);
    }

    const mid_off = region_offset + (bounded_len - win_size) / 2;
    const end_off = region_offset + (bounded_len - win_size);
    const offsets = [_]u64{ region_offset, mid_off, end_off };
    for (offsets) |off| {
        try stream.readAt(off, &buf);
        const ent = vidsec_math.shannonEntropy(&buf);
        if (ent > max_ent) max_ent = ent;
    }
    return max_ent;
}

/// Stage 2 R07 validator: scans `padding` and `unknown` regions across 3 windows (`start`, `mid`, `end`)
/// for embedded signatures (catching zero-diluted `goloader`) and high Shannon entropy.
pub const Service = struct {
    pub fn execute(_: *const Service, alloc: Allocator, inputs: Inputs) !Outputs {
        var findings: std.ArrayList(media_ir.AuditFindingRow) = .empty;
        errdefer findings.deinit(alloc);
        var zero_orders: std.ArrayList(orders.ZeroOutOrder) = .empty;
        errdefer zero_orders.deinit(alloc);
        var quarantines: std.ArrayList(orders.QuarantineOrder) = .empty;
        errdefer quarantines.deinit(alloc);

        for (inputs.ir_regions) |reg| {
            if (!std.mem.eql(u8, reg.role, "padding") and !std.mem.eql(u8, reg.role, "unknown")) continue;
            const len = reg.effective_end_offset -| reg.payload_offset;
            if (len < 16) continue;

            if (try vidsec_magic.scanMultiWindowSignatures(&inputs.stream, reg.payload_offset, len)) |hit| {
                const msg = try std.fmt.allocPrint(
                    alloc,
                    "Embedded signature ({s}) in {s} region '{s}' at offset {d}",
                    .{ hit.info.description, reg.role, reg.tag_name, hit.file_offset },
                );
                try findings.append(alloc, .{
                    .rule_id = "r07_padding_embedded_signature",
                    .severity = 4,
                    .file_offset = @intCast(hit.file_offset),
                    .byte_length = @intCast(len),
                    .end_offset = @intCast(reg.effective_end_offset),
                    .region_tag = try alloc.dupe(u8, reg.tag_name),
                    .message = msg,
                });
                try quarantines.append(alloc, .{
                    .rule_id = "r07_padding_embedded_signature",
                    .reason = msg,
                    .severity = 4,
                });
                continue;
            }

            const ent = try maxMultiWindowEntropy(&inputs.stream, reg.payload_offset, len);
            if (ent >= inputs.entropy_threshold) {
                const msg = try std.fmt.allocPrint(
                    alloc,
                    "High-entropy ({d:.2} bits/byte) payload in {s} region '{s}' at offset {d}",
                    .{ ent, reg.role, reg.tag_name, reg.payload_offset },
                );
                try findings.append(alloc, .{
                    .rule_id = "r07_padding_high_entropy",
                    .severity = 3,
                    .file_offset = @intCast(reg.payload_offset),
                    .byte_length = @intCast(len),
                    .end_offset = @intCast(reg.effective_end_offset),
                    .region_tag = try alloc.dupe(u8, reg.tag_name),
                    .measured_value = ent,
                    .message = msg,
                });
                try zero_orders.append(alloc, .{
                    .offset = reg.payload_offset,
                    .length = len,
                    .rule_id = "r07_padding_high_entropy",
                    .reason = "Zero out suspicious high-entropy padding/unknown region",
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
