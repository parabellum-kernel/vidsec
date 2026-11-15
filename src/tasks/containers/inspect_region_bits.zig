const std = @import("std");
const Allocator = std.mem.Allocator;
const abi = @import("flowdata_abi");
const isobmff = @import("isobmff");
const riff = @import("riff");
const media_ir = @import("media_ir");
const common = @import("common.zig");
const orders = @import("../remediation/orders.zig");
const dissect_isobmff = @import("dissect_isobmff.zig");
const dissect_ebml = @import("dissect_ebml.zig");
const dissect_riff = @import("dissect_riff.zig");
const inspect_region_field = @import("inspect_region_field.zig");
const remediation_encoder = @import("remediation_encoder.zig");

pub const Inputs = struct {
    stream: abi.BoundedStreamReader,
    isobmff_boxes: []const dissect_isobmff.IsobmffBoxRow = &.{},
    ebml_elements: []const dissect_ebml.EbmlElementRow = &.{},
    riff_chunks: []const dissect_riff.RiffChunkRow = &.{},
    target_tag: []const u8 = "",
    target_path_contains: []const u8 = "",
    rule_id: []const u8 = "bitfield_bounds_violation",
    severity: i64 = 3,
    quarantine_on_fail: bool = false,
    byte_offset: u64 = 0,
    byte_width: u8 = 1,
    endian: []const u8 = "big",
    bit_mask: u64 = 0xFF,
    bit_shift: u6 = 0,
    op: []const u8 = "range",
    expected_min: u64 = 0,
    expected_max: u64 = std.math.maxInt(u64),
    forbidden_value: ?u64 = null,
    header_bytes: u64 = 0,
    match_hex_offset: u64 = 0,
    match_hex_prefix: []const u8 = "",
    on_fail: []const u8 = "",
    patch_value: ?u64 = null,
};

pub const OutputsData = struct {
    region_field_results: []const inspect_region_field.RegionFieldResultRow,
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

fn matchesRegion(tag: []const u8, path: []const u8, inputs: Inputs) bool {
    if (inputs.target_tag.len > 0 and !std.ascii.eqlIgnoreCase(tag, inputs.target_tag)) {
        return false;
    }
    if (inputs.target_path_contains.len > 0 and std.mem.indexOf(u8, path, inputs.target_path_contains) == null) {
        return false;
    }
    return true;
}

fn decodeHexPrefix(hex_str: []const u8, out_buf: []u8) !usize {
    var count: usize = 0;
    var high_nibble: ?u8 = null;

    for (hex_str) |ch| {
        if (ch == ' ' or ch == '-' or ch == ':') continue;
        const nibble: u8 = switch (ch) {
            '0'...'9' => ch - '0',
            'a'...'f' => ch - 'a' + 10,
            'A'...'F' => ch - 'A' + 10,
            else => return error.InvalidHexCharacter,
        };
        if (high_nibble) |hi| {
            if (count >= out_buf.len) return error.HexPrefixTooLong;
            out_buf[count] = (hi << 4) | nibble;
            count += 1;
            high_nibble = null;
        } else {
            high_nibble = nibble;
        }
    }
    if (high_nibble != null) return error.OddHexLength;
    return count;
}

fn evaluateBitOp(op: []const u8, val: u64, available_bytes: u64, inputs: Inputs) !bool {
    if (std.mem.eql(u8, op, "eq")) return val == inputs.expected_min;
    if (std.mem.eql(u8, op, "ne")) return val != inputs.expected_min;
    if (std.mem.eql(u8, op, "gt")) return val > inputs.expected_min;
    if (std.mem.eql(u8, op, "ge")) return val >= inputs.expected_min;
    if (std.mem.eql(u8, op, "lt")) return val < inputs.expected_max;
    if (std.mem.eql(u8, op, "le")) return val <= inputs.expected_max;
    if (std.mem.eql(u8, op, "range")) return val >= inputs.expected_min and val <= inputs.expected_max;
    if (std.mem.eql(u8, op, "bit_forbidden")) {
        const forbidden = inputs.forbidden_value orelse inputs.expected_min;
        return val != forbidden;
    }
    if (std.mem.eql(u8, op, "fits_available")) {
        const base_hdr = if (inputs.header_bytes > 0) inputs.header_bytes else (inputs.byte_offset +| inputs.byte_width);
        const total = std.math.add(u64, base_hdr, val) catch return false;
        return total <= available_bytes;
    }
    return error.UnsupportedOperator;
}

/// Data-driven sub-byte bitfield & vendor UUID/GUID prefix validator over dissected container regions.
pub const Service = struct {
    pub fn execute(_: *const Service, alloc: Allocator, inputs: Inputs) !Outputs {
        if (inputs.byte_width != 1 and inputs.byte_width != 2 and inputs.byte_width != 4 and inputs.byte_width != 8) {
            return error.UnsupportedByteWidth;
        }
        const is_little = std.ascii.eqlIgnoreCase(inputs.endian, "little");
        if (!is_little and !std.ascii.eqlIgnoreCase(inputs.endian, "big")) {
            return error.UnsupportedEndianness;
        }

        var prefix_buf: [64]u8 = undefined;
        const prefix_len = if (inputs.match_hex_prefix.len > 0)
            try decodeHexPrefix(inputs.match_hex_prefix, &prefix_buf)
        else
            0;

        const be_source = common.streamToSource(isobmff.ByteSource, &inputs.stream);
        const le_source = common.streamToSource(riff.ByteSource, &inputs.stream);
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

        var results: std.ArrayList(inspect_region_field.RegionFieldResultRow) = .empty;
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
            if (prefix_len > 0) {
                if (inputs.match_hex_offset +| prefix_len > reg.available_bytes) continue;
                const match_abs = reg.payload_offset +| inputs.match_hex_offset;
                if (match_abs +| prefix_len > stream_size) continue;

                var actual_buf: [64]u8 = undefined;
                be_source.readExactAt(actual_buf[0..prefix_len], match_abs) catch continue;
                if (!std.mem.eql(u8, actual_buf[0..prefix_len], prefix_buf[0..prefix_len])) {
                    continue;
                }
            }

            const abs_offset = reg.payload_offset +| inputs.byte_offset;
            const region_in_bounds = (inputs.byte_offset +| inputs.byte_width) <= reg.available_bytes;
            const stream_in_bounds = (abs_offset +| inputs.byte_width) <= stream_size;

            if (!region_in_bounds or !stream_in_bounds) {
                const msg = try std.fmt.allocPrint(
                    alloc,
                    "Region {s} bitfield ({d}B) at offset {d} exceeds available bounds ({d} bytes)",
                    .{ reg.tag, inputs.byte_width, abs_offset, reg.available_bytes },
                );
                try results.append(alloc, .{
                    .tag = try alloc.dupe(u8, reg.tag),
                    .offset = abs_offset,
                    .field_kind = "bitfield",
                    .u64_value = 0,
                    .text_value = "",
                    .in_bounds = false,
                });
                try findings.append(alloc, .{
                    .rule_id = inputs.rule_id,
                    .severity = @intCast(inputs.severity),
                    .file_offset = @intCast(abs_offset),
                    .byte_length = inputs.byte_width,
                    .end_offset = @intCast(abs_offset +| inputs.byte_width),
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

            const raw_val: u64 = switch (inputs.byte_width) {
                1 => try isobmff.field_reader.readU8(be_source, abs_offset),
                2 => if (is_little)
                    try riff.field_reader.readU16Le(le_source, abs_offset)
                else
                    try isobmff.field_reader.readU16Be(be_source, abs_offset),
                4 => if (is_little)
                    try riff.field_reader.readU32Le(le_source, abs_offset)
                else
                    try isobmff.field_reader.readU32Be(be_source, abs_offset),
                8 => if (is_little)
                    try riff.field_reader.readU64Le(le_source, abs_offset)
                else
                    try isobmff.field_reader.readU64Be(be_source, abs_offset),
                else => unreachable,
            };

            const val = (raw_val & inputs.bit_mask) >> inputs.bit_shift;
            const passed = try evaluateBitOp(inputs.op, val, reg.available_bytes, inputs);

            try results.append(alloc, .{
                .tag = try alloc.dupe(u8, reg.tag),
                .offset = abs_offset,
                .field_kind = "bitfield",
                .u64_value = val,
                .text_value = "",
                .in_bounds = passed,
            });

            if (!passed) {
                const msg = try std.fmt.allocPrint(
                    alloc,
                    "Region {s} bitfield at offset {d} (mask=0x{x}, shift={d}) failed {s} check (value={d})",
                    .{ reg.tag, abs_offset, inputs.bit_mask, inputs.bit_shift, inputs.op, val },
                );
                try findings.append(alloc, .{
                    .rule_id = inputs.rule_id,
                    .severity = @intCast(inputs.severity),
                    .file_offset = @intCast(abs_offset),
                    .byte_length = inputs.byte_width,
                    .end_offset = @intCast(abs_offset +| inputs.byte_width),
                    .region_tag = try alloc.dupe(u8, reg.tag),
                    .measured_value = @floatFromInt(val),
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
                        const fits = (abs_offset +| inputs.byte_width <= stream_size) and
                            (inputs.byte_offset +| inputs.byte_width <= reg.available_bytes);
                        if (!fits) {
                            try q_orders.append(alloc, .{
                                .rule_id = inputs.rule_id,
                                .reason = msg,
                                .severity = inputs.severity,
                            });
                        } else {
                            const new_subval: ?u64 = if (policy == .patch)
                                (inputs.patch_value orelse 0)
                            else
                                remediation_encoder.computeClampedUnsigned(
                                    inputs.op,
                                    val,
                                    inputs.expected_min,
                                    inputs.expected_max,
                                    0,
                                    inputs.header_bytes,
                                    reg.available_bytes,
                                );
                            if (new_subval) |sv| {
                                const pb = remediation_encoder.encodeMaskedWord(
                                    alloc,
                                    raw_val,
                                    inputs.byte_width,
                                    is_little,
                                    inputs.bit_mask,
                                    inputs.bit_shift,
                                    sv,
                                ) catch null;
                                if (pb) |bytes| {
                                    try p_orders.append(alloc, .{
                                        .offset = abs_offset,
                                        .new_bytes = bytes,
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

test "TASK-035f.2: inspect_region_bits masked patch and tombstone" {
    const alloc = std.testing.allocator;
    // (c) avcC forbidden bottom 2 bits (0xFC | 0x02 = 0xFE) -> patch_value: 3 => 0xFF
    var buf_c = [_]u8{ 0, 0, 0, 0, 0xFE, 0, 0, 0 };
    const stream_c = abi.BoundedStreamReader.fromSlice(&buf_c);
    const boxes_c = [_]dissect_isobmff.IsobmffBoxRow{.{
        .fourcc = "avcC",
        .path = "moov/trak/mdia/minf/stbl/stsd/avc1/avcC",
        .header_offset = 0,
        .payload_offset = 8,
        .declared_size = 16,
        .available_bytes = 8,
        .is_container = false,
        .is_truncated = false,
        .is_overflow = false,
    }};
    var arena_c = std.heap.ArenaAllocator.init(alloc);
    defer arena_c.deinit();
    const res_c = try Service.execute(.{
        .stream = stream_c,
        .isobmff_boxes = &boxes_c,
        .target_tag = "avcC",
        .byte_offset = 4,
        .byte_width = 1,
        .bit_mask = 0x03,
        .bit_shift = 0,
        .op = "bit_forbidden",
        .forbidden_value = 2,
        .on_fail = "patch",
        .patch_value = 3,
    }, arena_c.allocator());
    try std.testing.expectEqual(@as(usize, 1), res_c.data.patch_orders.len);
    try std.testing.expectEqual(@as(u8, 0xFF), res_c.data.patch_orders[0].new_bytes[0]);

    // (d) malformed uuid with on_fail: "tombstone" -> TombstoneRegionOrder(.isobmff)
    var buf_d: [8]u8 = @splat(0);
    std.mem.writeInt(u32, buf_d[0..4], 999999, .big);
    const stream_d = abi.BoundedStreamReader.fromSlice(&buf_d);
    const boxes_d = [_]dissect_isobmff.IsobmffBoxRow{.{
        .fourcc = "uuid",
        .path = "moov/uuid",
        .header_offset = 0,
        .payload_offset = 8,
        .declared_size = 16,
        .available_bytes = 8,
        .is_container = false,
        .is_truncated = false,
        .is_overflow = false,
    }};
    var arena_d = std.heap.ArenaAllocator.init(alloc);
    defer arena_d.deinit();
    const res_d = try Service.execute(.{
        .stream = stream_d,
        .isobmff_boxes = &boxes_d,
        .target_tag = "uuid",
        .byte_offset = 0,
        .byte_width = 4,
        .endian = "big",
        .bit_mask = 0xFFFFFFFF,
        .bit_shift = 0,
        .op = "fits_available",
        .on_fail = "tombstone",
    }, arena_d.allocator());
    try std.testing.expectEqual(@as(usize, 1), res_d.data.tombstone_orders.len);
    try std.testing.expectEqual(orders.ContainerFamily.isobmff, res_d.data.tombstone_orders[0].family);
}

