const std = @import("std");
const Allocator = std.mem.Allocator;
const abi = @import("parabellum_abi");
const isobmff = @import("isobmff");
const riff = @import("riff");
const media_ir = @import("media_ir");
const common = @import("common.zig");
const orders = @import("../remediation/orders.zig");
const remediation_encoder = @import("remediation_encoder.zig");
const dissect_isobmff = @import("dissect_isobmff.zig");
const dissect_ebml = @import("dissect_ebml.zig");
const dissect_riff = @import("dissect_riff.zig");

pub const Inputs = struct {
    stream: abi.BoundedStreamReader,
    isobmff_boxes: []const dissect_isobmff.IsobmffBoxRow = &.{},
    ebml_elements: []const dissect_ebml.EbmlElementRow = &.{},
    riff_chunks: []const dissect_riff.RiffChunkRow = &.{},
    target_tag: []const u8 = "",
    target_path_contains: []const u8 = "",
    field_offset: u64 = 0,
    from_header: bool = false,
    target_offset: u64 = 0,
    field_kind: []const u8 = "u32be",
    op: []const u8 = "range",
    expected_min: u64 = 0,
    expected_max: u64 = std.math.maxInt(u64),
    stride: u64 = 0,
    header_bytes: u64 = 0,
    version_filter: i64 = -1,
    min_payload_size: u64 = 0,
    rule_id: []const u8 = "field_bounds_violation",
    severity: i64 = 3,
    quarantine_on_fail: bool = false,
    on_fail: []const u8 = "",
    patch_value: ?u64 = null,
    patch_fourcc: []const u8 = "",
};

pub const RegionFieldResultRow = struct {
    tag: []const u8,
    offset: u64,
    field_kind: []const u8,
    u64_value: u64,
    text_value: []const u8,
    in_bounds: bool,
};

pub const OutputsData = struct {
    region_field_results: []const RegionFieldResultRow,
    audit_findings: []const media_ir.AuditFindingRow,
    quarantine_orders: []const orders.QuarantineOrder,
    patch_orders: []const orders.PatchFieldOrder,
    tombstone_orders: []const orders.TombstoneRegionOrder,
    zero_out_orders: []const orders.ZeroOutOrder,
};

pub const Outputs = abi.Channels(OutputsData);

const TargetRegion = struct {
    family: orders.ContainerFamily,
    tag: []const u8,
    path: []const u8,
    header_offset: u64,
    payload_offset: u64,
    available_bytes: u64,
};

fn fieldByteLen(kind: []const u8) !u64 {
    if (std.mem.eql(u8, kind, "u8")) return 1;
    if (std.mem.eql(u8, kind, "u16be") or std.mem.eql(u8, kind, "u16le")) return 2;
    if (std.mem.eql(u8, kind, "u32be") or std.mem.eql(u8, kind, "u32le") or std.mem.eql(u8, kind, "i32le") or std.mem.eql(u8, kind, "fourcc")) return 4;
    if (std.mem.eql(u8, kind, "u64be") or std.mem.eql(u8, kind, "u64le")) return 8;
    if (std.mem.eql(u8, kind, "payload_size")) return 0;
    return error.UnsupportedFieldKind;
}

fn evaluateSignedOp(op: []const u8, val: i64, inputs: Inputs) !bool {
    const min_i64: i64 = @intCast(@min(inputs.expected_min, @as(u64, std.math.maxInt(i64))));
    const max_i64: i64 = @intCast(@min(inputs.expected_max, @as(u64, std.math.maxInt(i64))));
    if (std.mem.eql(u8, op, "eq")) return val == min_i64;
    if (std.mem.eql(u8, op, "ne")) return val != min_i64;
    if (std.mem.eql(u8, op, "gt")) return val > min_i64;
    if (std.mem.eql(u8, op, "ge")) return val >= min_i64;
    if (std.mem.eql(u8, op, "lt")) return val < max_i64;
    if (std.mem.eql(u8, op, "le")) return val <= max_i64;
    if (std.mem.eql(u8, op, "range")) return val >= min_i64 and val <= max_i64;
    if (std.mem.eql(u8, op, "stride_fits")) return false;
    return error.UnsupportedOperator;
}

fn evaluateOp(op: []const u8, val: u64, available_bytes: u64, inputs: Inputs) !bool {
    if (std.mem.eql(u8, op, "eq")) return val == inputs.expected_min;
    if (std.mem.eql(u8, op, "ne")) return val != inputs.expected_min;
    if (std.mem.eql(u8, op, "gt")) return val > inputs.expected_min;
    if (std.mem.eql(u8, op, "ge")) return val >= inputs.expected_min;
    if (std.mem.eql(u8, op, "lt")) return val < inputs.expected_max;
    if (std.mem.eql(u8, op, "le")) return val <= inputs.expected_max;
    if (std.mem.eql(u8, op, "range")) return val >= inputs.expected_min and val <= inputs.expected_max;
    if (std.mem.eql(u8, op, "stride_fits")) {
        const mul = std.math.mul(u64, val, inputs.stride) catch return false;
        const total = std.math.add(u64, inputs.header_bytes, mul) catch return false;
        return total <= available_bytes;
    }
    return error.UnsupportedOperator;
}

fn matchesRegion(tag: []const u8, path: []const u8, inputs: Inputs) bool {
    if (inputs.target_tag.len > 0 and !std.ascii.eqlIgnoreCase(tag, inputs.target_tag)) {
        return false;
    }
    if (inputs.target_path_contains.len > 0 and std.mem.indexOf(u8, path, inputs.target_path_contains) == null) {
        return false;
    }
    return true;
}

/// Data-driven typed field extractor & bounds/stride validator over dissected container regions.
pub const Service = struct {
    pub fn execute(_: *const Service, alloc: Allocator, inputs: Inputs) !Outputs {
        const be_source = common.streamToSource(isobmff.ByteSource, &inputs.stream);
        const le_source = common.streamToSource(riff.ByteSource, &inputs.stream);
        const byte_len = try fieldByteLen(inputs.field_kind);
        const stream_size = be_source.file_size;

        var targets: std.ArrayList(TargetRegion) = .empty;
        defer targets.deinit(alloc);

        for (inputs.isobmff_boxes) |b| {
            if (matchesRegion(b.fourcc, b.path, inputs)) {
                try targets.append(alloc, .{
                    .family = .isobmff,
                    .tag = b.fourcc,
                    .path = b.path,
                    .header_offset = b.header_offset,
                    .payload_offset = b.payload_offset,
                    .available_bytes = b.available_bytes,
                });
            }
        }
        for (inputs.ebml_elements) |e| {
            if (matchesRegion(e.ebml_id_hex, e.path, inputs)) {
                try targets.append(alloc, .{
                    .family = .ebml,
                    .tag = e.ebml_id_hex,
                    .path = e.path,
                    .header_offset = e.header_offset,
                    .payload_offset = e.payload_offset,
                    .available_bytes = e.available_bytes,
                });
            }
        }
        for (inputs.riff_chunks) |c| {
            if (matchesRegion(c.fourcc, c.path, inputs)) {
                try targets.append(alloc, .{
                    .family = .riff,
                    .tag = c.fourcc,
                    .path = c.path,
                    .header_offset = c.header_offset,
                    .payload_offset = c.payload_offset,
                    .available_bytes = c.available_bytes,
                });
            }
        }

        // Direct-offset fallback when no dissected region tables were supplied
        const using_direct_offset = inputs.isobmff_boxes.len == 0 and
            inputs.ebml_elements.len == 0 and
            inputs.riff_chunks.len == 0 and
            inputs.target_tag.len == 0;
        if (using_direct_offset) {
            try targets.append(alloc, .{
                .family = .isobmff,
                .tag = inputs.field_kind,
                .path = "",
                .header_offset = inputs.target_offset,
                .payload_offset = inputs.target_offset,
                .available_bytes = stream_size -| inputs.target_offset,
            });
        }

        var results: std.ArrayList(RegionFieldResultRow) = .empty;
        errdefer results.deinit(alloc);
        var findings: std.ArrayList(media_ir.AuditFindingRow) = .empty;
        errdefer findings.deinit(alloc);
        var q_orders: std.ArrayList(orders.QuarantineOrder) = .empty;
        errdefer q_orders.deinit(alloc);
        var p_orders: std.ArrayList(orders.PatchFieldOrder) = .empty;
        errdefer p_orders.deinit(alloc);
        var t_orders: std.ArrayList(orders.TombstoneRegionOrder) = .empty;
        errdefer t_orders.deinit(alloc);
        var z_orders: std.ArrayList(orders.ZeroOutOrder) = .empty;
        errdefer z_orders.deinit(alloc);
        const policy = try remediation_encoder.resolvePolicy(inputs.on_fail, inputs.quarantine_on_fail);

        for (targets.items) |reg| {
            if (inputs.min_payload_size > 0 and reg.available_bytes < inputs.min_payload_size) {
                const msg = try std.fmt.allocPrint(
                    alloc,
                    "Region {s} payload size {d} is below minimum {d} bytes",
                    .{ reg.tag, reg.available_bytes, inputs.min_payload_size },
                );
                try results.append(alloc, .{
                    .tag = try alloc.dupe(u8, reg.tag),
                    .offset = reg.payload_offset,
                    .field_kind = inputs.field_kind,
                    .u64_value = reg.available_bytes,
                    .text_value = "",
                    .in_bounds = false,
                });
                try findings.append(alloc, .{
                    .rule_id = inputs.rule_id,
                    .severity = @intCast(inputs.severity),
                    .file_offset = @intCast(reg.payload_offset),
                    .byte_length = @intCast(reg.available_bytes),
                    .end_offset = @intCast(reg.payload_offset +| reg.available_bytes),
                    .region_tag = try alloc.dupe(u8, reg.tag),
                    .measured_value = @floatFromInt(reg.available_bytes),
                    .message = msg,
                });
                if (inputs.quarantine_on_fail) {
                    try q_orders.append(alloc, .{
                        .rule_id = inputs.rule_id,
                        .reason = msg,
                        .severity = inputs.severity,
                    });
                }
                continue;
            }

            if (inputs.version_filter >= 0) {
                if (reg.available_bytes < 1 or reg.payload_offset +| 1 > stream_size) {
                    continue;
                }
                const box_ver = try isobmff.field_reader.readU8(be_source, reg.payload_offset);
                if (@as(i64, box_ver) != inputs.version_filter) {
                    continue;
                }
            }

            const is_payload_size = std.mem.eql(u8, inputs.field_kind, "payload_size");
            const rel_off = if (using_direct_offset or is_payload_size) 0 else inputs.field_offset;
            const base = if (inputs.from_header) reg.header_offset else reg.payload_offset;
            const abs_offset = base +| rel_off;

            const region_in_bounds = is_payload_size or
                (!inputs.from_header and (rel_off +| byte_len <= reg.available_bytes)) or
                inputs.from_header;
            const stream_in_bounds = is_payload_size or (abs_offset +| byte_len <= stream_size);

            if (!region_in_bounds or !stream_in_bounds) {
                const msg = try std.fmt.allocPrint(
                    alloc,
                    "Region {s} field {s} at offset {d} exceeds available bounds ({d} bytes)",
                    .{ reg.tag, inputs.field_kind, abs_offset, reg.available_bytes },
                );
                try results.append(alloc, .{
                    .tag = try alloc.dupe(u8, reg.tag),
                    .offset = abs_offset,
                    .field_kind = inputs.field_kind,
                    .u64_value = 0,
                    .text_value = "",
                    .in_bounds = false,
                });
                try findings.append(alloc, .{
                    .rule_id = inputs.rule_id,
                    .severity = @intCast(inputs.severity),
                    .file_offset = @intCast(abs_offset),
                    .byte_length = @intCast(byte_len),
                    .end_offset = @intCast(abs_offset +| byte_len),
                    .region_tag = try alloc.dupe(u8, reg.tag),
                    .message = msg,
                });
                if (inputs.quarantine_on_fail) {
                    try q_orders.append(alloc, .{
                        .rule_id = inputs.rule_id,
                        .reason = msg,
                        .severity = inputs.severity,
                    });
                }
                continue;
            }

            var u64_val: u64 = 0;
            var signed_val: ?i64 = null;
            var text_val: []const u8 = "";

            if (is_payload_size) {
                u64_val = reg.available_bytes;
            } else if (std.mem.eql(u8, inputs.field_kind, "u8")) {
                u64_val = try isobmff.field_reader.readU8(be_source, abs_offset);
            } else if (std.mem.eql(u8, inputs.field_kind, "u16be")) {
                u64_val = try isobmff.field_reader.readU16Be(be_source, abs_offset);
            } else if (std.mem.eql(u8, inputs.field_kind, "u32be")) {
                u64_val = try isobmff.field_reader.readU32Be(be_source, abs_offset);
            } else if (std.mem.eql(u8, inputs.field_kind, "u64be")) {
                u64_val = try isobmff.field_reader.readU64Be(be_source, abs_offset);
            } else if (std.mem.eql(u8, inputs.field_kind, "u16le")) {
                u64_val = try riff.field_reader.readU16Le(le_source, abs_offset);
            } else if (std.mem.eql(u8, inputs.field_kind, "u32le")) {
                u64_val = try riff.field_reader.readU32Le(le_source, abs_offset);
            } else if (std.mem.eql(u8, inputs.field_kind, "i32le")) {
                const v = try riff.field_reader.readI32Le(le_source, abs_offset);
                signed_val = v;
                u64_val = @as(u64, @as(u32, @bitCast(v)));
            } else if (std.mem.eql(u8, inputs.field_kind, "u64le")) {
                u64_val = try riff.field_reader.readU64Le(le_source, abs_offset);
            } else if (std.mem.eql(u8, inputs.field_kind, "fourcc")) {
                const fcc = try isobmff.field_reader.readFourCC(be_source, abs_offset);
                text_val = try alloc.dupe(u8, &fcc.bytes);
            }

            const passed = if (text_val.len > 0) blk: {
                for (text_val) |ch| {
                    if (ch < 0x20 or ch > 0x7E) break :blk false;
                }
                break :blk true;
            } else if (signed_val) |sv|
                try evaluateSignedOp(inputs.op, sv, inputs)
            else
                try evaluateOp(inputs.op, u64_val, reg.available_bytes, inputs);

            try results.append(alloc, .{
                .tag = try alloc.dupe(u8, reg.tag),
                .offset = abs_offset,
                .field_kind = inputs.field_kind,
                .u64_value = u64_val,
                .text_value = text_val,
                .in_bounds = passed,
            });

            if (!passed) {
                const msg = try std.fmt.allocPrint(
                    alloc,
                    "Region {s} field {s} at offset {d} failed {s} check (value={d})",
                    .{ reg.tag, inputs.field_kind, abs_offset, inputs.op, u64_val },
                );
                try findings.append(alloc, .{
                    .rule_id = inputs.rule_id,
                    .severity = @intCast(inputs.severity),
                    .file_offset = @intCast(abs_offset),
                    .byte_length = @intCast(byte_len),
                    .end_offset = @intCast(abs_offset +| byte_len),
                    .region_tag = try alloc.dupe(u8, reg.tag),
                    .measured_value = if (signed_val) |sv| @floatFromInt(sv) else @floatFromInt(u64_val),
                    .message = msg,
                });
                switch (policy) {
                    .log_only => {},
                    .quarantine, .tombstone_excess, .sync_container_dimensions => {
                        try q_orders.append(alloc, .{
                            .rule_id = inputs.rule_id,
                            .reason = msg,
                            .severity = inputs.severity,
                        });
                    },
                    .tombstone => {
                        if (reg.header_offset < reg.payload_offset) {
                            try t_orders.append(alloc, .{
                                .family = reg.family,
                                .region_tag = try alloc.dupe(u8, reg.tag),
                                .header_offset = reg.header_offset,
                                .payload_offset = reg.payload_offset,
                                .available_bytes = reg.available_bytes,
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
                    },
                    .zero_payload => {
                        try z_orders.append(alloc, .{
                            .offset = reg.payload_offset,
                            .length = reg.available_bytes,
                            .rule_id = inputs.rule_id,
                            .reason = msg,
                        });
                    },
                    .clamp, .patch => {
                        const fits = (abs_offset +| byte_len <= stream_size) and
                            (inputs.from_header or (inputs.field_offset +| byte_len <= reg.available_bytes));
                        if (!fits) {
                            try q_orders.append(alloc, .{
                                .rule_id = inputs.rule_id,
                                .reason = msg,
                                .severity = inputs.severity,
                            });
                        } else {
                            const patch_bytes: ?[]const u8 = blk: {
                                if (policy == .patch) {
                                    break :blk remediation_encoder.encodeFieldBytes(
                                        alloc,
                                        inputs.field_kind,
                                        inputs.patch_value orelse 0,
                                        @bitCast(inputs.patch_value orelse 0),
                                        inputs.patch_fourcc,
                                    ) catch null;
                                } else {
                                    if (signed_val) |sv| {
                                        const min_i64: i64 = @bitCast(inputs.expected_min);
                                        const max_i64: i64 = @bitCast(inputs.expected_max);
                                        const clamped_s = remediation_encoder.computeClampedSigned(inputs.op, sv, min_i64, max_i64) orelse break :blk null;
                                        break :blk remediation_encoder.encodeFieldBytes(alloc, inputs.field_kind, 0, clamped_s, "") catch null;
                                    } else {
                                        const clamped_u = remediation_encoder.computeClampedUnsigned(
                                            inputs.op,
                                            u64_val,
                                            inputs.expected_min,
                                            inputs.expected_max,
                                            inputs.stride,
                                            inputs.header_bytes,
                                            reg.available_bytes,
                                        ) orelse break :blk null;
                                        break :blk remediation_encoder.encodeFieldBytes(alloc, inputs.field_kind, clamped_u, 0, "") catch null;
                                    }
                                }
                            };
                            if (patch_bytes) |pb| {
                                try p_orders.append(alloc, .{
                                    .offset = abs_offset,
                                    .new_bytes = pb,
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
                    },
                }
            }
        }

        return .{ .data = .{
            .region_field_results = try results.toOwnedSlice(alloc),
            .audit_findings = try findings.toOwnedSlice(alloc),
            .quarantine_orders = try q_orders.toOwnedSlice(alloc),
            .patch_orders = try p_orders.toOwnedSlice(alloc),
            .tombstone_orders = try t_orders.toOwnedSlice(alloc),
            .zero_out_orders = try z_orders.toOwnedSlice(alloc),
        } };
    }
};

test "TASK-035f.2: inspect_region_field patch and clamp" {
    const alloc = std.testing.allocator;
    // (a) mdhd timescale == 0 -> patch_value: 1000 => [0x00, 0x00, 0x03, 0xE8]
    var buf_a: [24]u8 = @splat(0);
    const stream_a = abi.BoundedStreamReader.fromSlice(&buf_a);
    const boxes_a = [_]dissect_isobmff.IsobmffBoxRow{.{
        .fourcc = "mdhd",
        .path = "moov/trak/mdia/mdhd",
        .header_offset = 0,
        .payload_offset = 8,
        .declared_size = 32,
        .available_bytes = 24,
        .is_container = false,
        .is_truncated = false,
        .is_overflow = false,
    }};
    var arena_a = std.heap.ArenaAllocator.init(alloc);
    defer arena_a.deinit();
    const res_a = try Service.execute(.{
        .stream = stream_a,
        .isobmff_boxes = &boxes_a,
        .target_tag = "mdhd",
        .field_offset = 12,
        .field_kind = "u32be",
        .op = "gt",
        .expected_min = 0,
        .on_fail = "patch",
        .patch_value = 1000,
    }, arena_a.allocator());
    try std.testing.expectEqual(@as(usize, 1), res_a.data.patch_orders.len);
    try std.testing.expectEqual(@as(u64, 20), res_a.data.patch_orders[0].offset);
    try std.testing.expectEqualSlices(u8, &.{ 0x00, 0x00, 0x03, 0xE8 }, res_a.data.patch_orders[0].new_bytes);

    // (b) strf.biClrUsed = 99999 -> clamp expected_max: 256 => u32le(256)
    var buf_b: [40]u8 = @splat(0);
    std.mem.writeInt(u32, buf_b[32..36], 99999, .little);
    const stream_b = abi.BoundedStreamReader.fromSlice(&buf_b);
    const chunks_b = [_]dissect_riff.RiffChunkRow{.{
        .fourcc = "strf",
        .path = "AVI /hdrl/strl/strf",
        .header_offset = 0,
        .payload_offset = 8,
        .declared_size = 40,
        .available_bytes = 40,
        .is_container = false,
        .is_truncated = false,
        .is_overflow = false,
    }};
    var arena_b = std.heap.ArenaAllocator.init(alloc);
    defer arena_b.deinit();
    const res_b = try Service.execute(.{
        .stream = stream_b,
        .riff_chunks = &chunks_b,
        .target_tag = "strf",
        .field_offset = 32,
        .field_kind = "u32le",
        .op = "le",
        .expected_max = 256,
        .on_fail = "clamp",
    }, arena_b.allocator());
    try std.testing.expectEqual(@as(usize, 1), res_b.data.patch_orders.len);
    try std.testing.expectEqual(@as(u32, 256), std.mem.readInt(u32, res_b.data.patch_orders[0].new_bytes[0..4], .little));
}
