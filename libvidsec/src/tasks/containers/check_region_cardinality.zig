const std = @import("std");
const Allocator = std.mem.Allocator;
const abi = @import("parabellum_sdk").task;
const media_ir = @import("media_ir");
const orders = @import("../remediation/orders.zig");
const dissect_isobmff = @import("isobmff/dissect_isobmff.zig");
const dissect_ebml = @import("ebml/dissect_ebml.zig");
const dissect_riff = @import("riff/dissect_riff.zig");
const remediation_encoder = @import("remediation_encoder.zig");

pub const Inputs = struct {
    isobmff_boxes: []const dissect_isobmff.IsobmffBoxRow = &.{},
    ebml_elements: []const dissect_ebml.EbmlElementRow = &.{},
    riff_chunks: []const dissect_riff.RiffChunkRow = &.{},
    parent_tag: []const u8 = "",
    child_tag: []const u8,
    min_count: u64 = 0,
    max_count: u64 = 1,
    must_precede_tag: []const u8 = "",
    rule_id: []const u8 = "region_cardinality_violation",
    severity: i64 = 3,
    quarantine_on_fail: bool = true,
    on_fail: []const u8 = "",
};

pub const OutputsData = struct {
    audit_findings: []const media_ir.AuditFindingRow,
    quarantine_orders: []const orders.QuarantineOrder,
    tombstone_orders: []const orders.TombstoneRegionOrder,
};

pub const Outputs = abi.Channels(OutputsData);

const RegionNode = struct {
    family: orders.ContainerFamily,
    region_id: i64,
    parent_region_id: ?i64,
    tag: []const u8,
    path: []const u8,
    header_offset: u64,
    payload_offset: u64,
    available_bytes: u64,
};

const ScopeStats = struct {
    tag: []const u8,
    header_offset: u64,
    count: u64 = 0,
    min_child_offset: ?u64 = null,
    min_precede_offset: ?u64 = null,
};

fn pathEndsWithTag(path: []const u8, tag: []const u8) bool {
    if (path.len < tag.len) return false;
    if (path.len == tag.len) return std.ascii.eqlIgnoreCase(path, tag);
    const sep_idx = path.len - tag.len - 1;
    const sep = path[sep_idx];
    return (sep == '/' or sep == ':') and std.ascii.eqlIgnoreCase(path[sep_idx + 1 ..], tag);
}

fn matchesTag(node: RegionNode, tag: []const u8) bool {
    if (std.ascii.eqlIgnoreCase(node.tag, tag)) return true;
    return pathEndsWithTag(node.path, tag);
}

fn updateMinOffset(slot: *?u64, offset: u64) void {
    if (slot.*) |prev| {
        if (offset < prev) slot.* = offset;
    } else {
        slot.* = offset;
    }
}

fn emitViolation(
    alloc: Allocator,
    inputs: Inputs,
    offset: u64,
    region_tag: []const u8,
    measured: f64,
    msg: []const u8,
    findings: *std.ArrayList(media_ir.AuditFindingRow),
    q_orders: *std.ArrayList(orders.QuarantineOrder),
) !void {
    try findings.append(alloc, .{
        .rule_id = inputs.rule_id,
        .severity = @intCast(inputs.severity),
        .file_offset = @intCast(offset),
        .byte_length = 0,
        .end_offset = @intCast(offset),
        .region_tag = try alloc.dupe(u8, region_tag),
        .measured_value = measured,
        .message = msg,
    });
    if (inputs.quarantine_on_fail) {
        try q_orders.append(alloc, .{
            .rule_id = inputs.rule_id,
            .reason = msg,
            .severity = inputs.severity,
        });
    }
}

fn evaluateScope(
    alloc: Allocator,
    inputs: Inputs,
    stats: ScopeStats,
    matching_children: []const RegionNode,
    findings: *std.ArrayList(media_ir.AuditFindingRow),
    q_orders: *std.ArrayList(orders.QuarantineOrder),
    t_orders: *std.ArrayList(orders.TombstoneRegionOrder),
) !void {
    const policy = try remediation_encoder.resolvePolicy(inputs.on_fail, inputs.quarantine_on_fail);
    if (stats.count < inputs.min_count or stats.count > inputs.max_count) {
        const msg = try std.fmt.allocPrint(
            alloc,
            "Cardinality violation in {s}: found {d} '{s}' children (expected [{d}, {d}])",
            .{ stats.tag, stats.count, inputs.child_tag, inputs.min_count, inputs.max_count },
        );
        if (stats.count > inputs.max_count and policy == .tombstone_excess) {
            try findings.append(alloc, .{
                .rule_id = inputs.rule_id,
                .severity = @intCast(inputs.severity),
                .file_offset = @intCast(stats.min_child_offset orelse stats.header_offset),
                .byte_length = 0,
                .end_offset = @intCast(stats.min_child_offset orelse stats.header_offset),
                .region_tag = try alloc.dupe(u8, inputs.child_tag),
                .measured_value = @floatFromInt(stats.count),
                .message = msg,
            });
            const sorted = try alloc.dupe(RegionNode, matching_children);
            defer alloc.free(sorted);
            std.mem.sort(RegionNode, sorted, {}, struct {
                fn lessThan(_: void, a: RegionNode, b: RegionNode) bool {
                    return a.header_offset < b.header_offset;
                }
            }.lessThan);
            const keep: usize = @intCast(@min(inputs.max_count, sorted.len));
            for (sorted[keep..]) |excess| {
                if (excess.header_offset < excess.payload_offset) {
                    try t_orders.append(alloc, .{
                        .family = excess.family,
                        .region_tag = try alloc.dupe(u8, excess.tag),
                        .header_offset = excess.header_offset,
                        .payload_offset = excess.payload_offset,
                        .available_bytes = excess.available_bytes,
                        .rule_id = inputs.rule_id,
                        .reason = msg,
                        .severity = inputs.severity,
                    });
                } else {
                    try q_orders.append(alloc, .{
                        .rule_id = inputs.rule_id,
                        .reason = msg,
                        .severity = inputs.severity,
                    });
                }
            }
        } else {
            try emitViolation(
                alloc,
                inputs,
                stats.min_child_offset orelse stats.header_offset,
                inputs.child_tag,
                @floatFromInt(stats.count),
                msg,
                findings,
                q_orders,
            );
        }
    }

    if (inputs.must_precede_tag.len > 0) {
        if (stats.min_child_offset) |child_off| {
            const order_ok = if (stats.min_precede_offset) |prec_off| prec_off < child_off else false;
            if (!order_ok) {
                const msg = try std.fmt.allocPrint(
                    alloc,
                    "Ordering violation in {s}: '{s}' (offset {d}) appeared before required '{s}'",
                    .{ stats.tag, inputs.child_tag, child_off, inputs.must_precede_tag },
                );
                try emitViolation(
                    alloc,
                    inputs,
                    child_off,
                    inputs.child_tag,
                    @floatFromInt(child_off),
                    msg,
                    findings,
                    q_orders,
                );
            }
        }
    }
}

fn checkTable(
    alloc: Allocator,
    nodes: []const RegionNode,
    inputs: Inputs,
    findings: *std.ArrayList(media_ir.AuditFindingRow),
    q_orders: *std.ArrayList(orders.QuarantineOrder),
    t_orders: *std.ArrayList(orders.TombstoneRegionOrder),
) !void {
    if (nodes.len == 0) return;

    if (inputs.parent_tag.len == 0) {
        var root_stats = ScopeStats{
            .tag = "<root>",
            .header_offset = 0,
        };
        var root_children: std.ArrayList(RegionNode) = .empty;
        defer root_children.deinit(alloc);
        for (nodes) |n| {
            if (n.parent_region_id != null) continue;
            if (matchesTag(n, inputs.child_tag)) {
                root_stats.count += 1;
                updateMinOffset(&root_stats.min_child_offset, n.header_offset);
                try root_children.append(alloc, n);
            }
            if (inputs.must_precede_tag.len > 0 and matchesTag(n, inputs.must_precede_tag)) {
                updateMinOffset(&root_stats.min_precede_offset, n.header_offset);
            }
        }
        try evaluateScope(alloc, inputs, root_stats, root_children.items, findings, q_orders, t_orders);
        return;
    }

    var parent_scopes = std.AutoHashMap(i64, ScopeStats).init(alloc);
    defer parent_scopes.deinit();

    for (nodes) |n| {
        if (matchesTag(n, inputs.parent_tag)) {
            try parent_scopes.put(n.region_id, .{
                .tag = inputs.parent_tag,
                .header_offset = n.header_offset,
            });
        }
    }

    if (parent_scopes.count() == 0) return;

    for (nodes) |n| {
        const pid = n.parent_region_id orelse continue;
        if (parent_scopes.getPtr(pid)) |stats| {
            if (matchesTag(n, inputs.child_tag)) {
                stats.count += 1;
                updateMinOffset(&stats.min_child_offset, n.header_offset);
            }
            if (inputs.must_precede_tag.len > 0 and matchesTag(n, inputs.must_precede_tag)) {
                updateMinOffset(&stats.min_precede_offset, n.header_offset);
            }
        }
    }

    var it = parent_scopes.iterator();
    while (it.next()) |entry| {
        const pid = entry.key_ptr.*;
        var children_in_scope: std.ArrayList(RegionNode) = .empty;
        defer children_in_scope.deinit(alloc);
        for (nodes) |n| {
            if (n.parent_region_id == pid and matchesTag(n, inputs.child_tag)) {
                try children_in_scope.append(alloc, n);
            }
        }
        try evaluateScope(alloc, inputs, entry.value_ptr.*, children_in_scope.items, findings, q_orders, t_orders);
    }
}

/// Pure region-tree cardinality & ordering validator (detects singleton duplication UAF/double-free and out-of-order fragments).
pub const Service = struct {
    pub fn execute(_: *const Service, alloc: Allocator, inputs: Inputs) !Outputs {
        var findings: std.ArrayList(media_ir.AuditFindingRow) = .empty;
        errdefer findings.deinit(alloc);
        var q_orders: std.ArrayList(orders.QuarantineOrder) = .empty;
        errdefer q_orders.deinit(alloc);
        var t_orders: std.ArrayList(orders.TombstoneRegionOrder) = .empty;
        errdefer t_orders.deinit(alloc);

        if (inputs.isobmff_boxes.len > 0) {
            const nodes = try alloc.alloc(RegionNode, inputs.isobmff_boxes.len);
            defer alloc.free(nodes);
            for (inputs.isobmff_boxes, 0..) |b, i| {
                nodes[i] = .{
                    .family = .isobmff,
                    .region_id = b.region_id,
                    .parent_region_id = b.parent_region_id,
                    .tag = b.fourcc,
                    .path = b.path,
                    .header_offset = b.header_offset,
                    .payload_offset = b.payload_offset,
                    .available_bytes = b.available_bytes,
                };
            }
            try checkTable(alloc, nodes, inputs, &findings, &q_orders, &t_orders);
        }

        if (inputs.ebml_elements.len > 0) {
            const nodes = try alloc.alloc(RegionNode, inputs.ebml_elements.len);
            defer alloc.free(nodes);
            for (inputs.ebml_elements, 0..) |e, i| {
                nodes[i] = .{
                    .family = .ebml,
                    .region_id = e.region_id,
                    .parent_region_id = e.parent_region_id,
                    .tag = e.ebml_id_hex,
                    .path = e.path,
                    .header_offset = e.header_offset,
                    .payload_offset = e.payload_offset,
                    .available_bytes = e.available_bytes,
                };
            }
            try checkTable(alloc, nodes, inputs, &findings, &q_orders, &t_orders);
        }

        if (inputs.riff_chunks.len > 0) {
            const nodes = try alloc.alloc(RegionNode, inputs.riff_chunks.len);
            defer alloc.free(nodes);
            for (inputs.riff_chunks, 0..) |c, i| {
                nodes[i] = .{
                    .family = .riff,
                    .region_id = c.region_id,
                    .parent_region_id = c.parent_region_id,
                    .tag = c.fourcc,
                    .path = c.path,
                    .header_offset = c.header_offset,
                    .payload_offset = c.payload_offset,
                    .available_bytes = c.available_bytes,
                };
            }
            try checkTable(alloc, nodes, inputs, &findings, &q_orders, &t_orders);
        }

        return .{ .data = .{
            .audit_findings = try findings.toOwnedSlice(alloc),
            .quarantine_orders = try q_orders.toOwnedSlice(alloc),
            .tombstone_orders = try t_orders.toOwnedSlice(alloc),
        } };
    }
};

test "check_region_cardinality: duplicate CodecPrivate with tombstone_excess targets 2nd occurrence" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    const elems = [_]dissect_ebml.EbmlElementRow{
        .{
            .region_id = 1,
            .parent_region_id = 0,
            .ebml_id_hex = "0xae",
            .path = "/Segment/Tracks/TrackEntry",
            .depth = 3,
            .header_offset = 100,
            .payload_offset = 103,
            .available_bytes = 200,
        },
        .{
            .region_id = 2,
            .parent_region_id = 1,
            .ebml_id_hex = "0x63a2",
            .path = "/Segment/Tracks/TrackEntry/CodecPrivate",
            .depth = 4,
            .header_offset = 120,
            .payload_offset = 123,
            .available_bytes = 20,
        },
        .{
            .region_id = 3,
            .parent_region_id = 1,
            .ebml_id_hex = "0x63a2",
            .path = "/Segment/Tracks/TrackEntry/CodecPrivate",
            .depth = 4,
            .header_offset = 150,
            .payload_offset = 153,
            .available_bytes = 24,
        },
    };

    const svc: Service = .{};
    const out = try svc.execute(alloc, .{
        .ebml_elements = &elems,
        .parent_tag = "0xae",
        .child_tag = "0x63a2",
        .min_count = 0,
        .max_count = 1,
        .on_fail = "tombstone_excess",
    });

    try std.testing.expectEqual(@as(usize, 0), out.data.quarantine_orders.len);
    try std.testing.expectEqual(@as(usize, 1), out.data.tombstone_orders.len);
    try std.testing.expectEqual(orders.ContainerFamily.ebml, out.data.tombstone_orders[0].family);
    try std.testing.expectEqual(@as(u64, 150), out.data.tombstone_orders[0].header_offset);
    try std.testing.expectEqual(@as(u64, 153), out.data.tombstone_orders[0].payload_offset);
    try std.testing.expectEqual(@as(u64, 24), out.data.tombstone_orders[0].available_bytes);
}

test "check_region_cardinality: duplicate stsc with tombstone_excess targets 2nd occurrence" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    const boxes = [_]dissect_isobmff.IsobmffBoxRow{
        .{
            .region_id = 10,
            .parent_region_id = 0,
            .fourcc = "stbl",
            .path = "/moov/trak/mdia/minf/stbl",
            .depth = 5,
            .header_offset = 500,
            .payload_offset = 508,
            .available_bytes = 400,
        },
        .{
            .region_id = 11,
            .parent_region_id = 10,
            .fourcc = "stsc",
            .path = "/moov/trak/mdia/minf/stbl/stsc",
            .depth = 6,
            .header_offset = 520,
            .payload_offset = 528,
            .available_bytes = 28,
        },
        .{
            .region_id = 12,
            .parent_region_id = 10,
            .fourcc = "stsc",
            .path = "/moov/trak/mdia/minf/stbl/stsc",
            .depth = 6,
            .header_offset = 600,
            .payload_offset = 608,
            .available_bytes = 32,
        },
    };

    const svc: Service = .{};
    const out = try svc.execute(alloc, .{
        .isobmff_boxes = &boxes,
        .parent_tag = "stbl",
        .child_tag = "stsc",
        .min_count = 1,
        .max_count = 1,
        .on_fail = "tombstone_excess",
    });

    try std.testing.expectEqual(@as(usize, 0), out.data.quarantine_orders.len);
    try std.testing.expectEqual(@as(usize, 1), out.data.tombstone_orders.len);
    try std.testing.expectEqual(orders.ContainerFamily.isobmff, out.data.tombstone_orders[0].family);
    try std.testing.expectEqual(@as(u64, 600), out.data.tombstone_orders[0].header_offset);
    try std.testing.expectEqual(@as(u64, 608), out.data.tombstone_orders[0].payload_offset);
    try std.testing.expectEqual(@as(u64, 32), out.data.tombstone_orders[0].available_bytes);
}
