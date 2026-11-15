const std = @import("std");
const Allocator = std.mem.Allocator;

pub const OnFailPolicy = enum {
    quarantine,
    clamp,
    patch,
    tombstone,
    tombstone_excess,
    zero_payload,
    sync_container_dimensions,
    log_only,
};

pub fn resolvePolicy(on_fail: []const u8, quarantine_on_fail: bool) !OnFailPolicy {
    if (on_fail.len == 0) {
        return if (quarantine_on_fail) .quarantine else .log_only;
    }
    if (std.mem.eql(u8, on_fail, "quarantine")) return .quarantine;
    if (std.mem.eql(u8, on_fail, "clamp")) return .clamp;
    if (std.mem.eql(u8, on_fail, "patch")) return .patch;
    if (std.mem.eql(u8, on_fail, "tombstone")) return .tombstone;
    if (std.mem.eql(u8, on_fail, "tombstone_excess")) return .tombstone_excess;
    if (std.mem.eql(u8, on_fail, "zero_payload")) return .zero_payload;
    if (std.mem.eql(u8, on_fail, "sync_container_dimensions")) return .sync_container_dimensions;
    if (std.mem.eql(u8, on_fail, "log_only")) return .log_only;
    return error.InvalidOnFailPolicy;
}

pub fn computeClampedUnsigned(
    op: []const u8,
    measured: u64,
    expected_min: u64,
    expected_max: u64,
    stride: u64,
    header_bytes: u64,
    available_bytes: u64,
) ?u64 {
    if (std.mem.eql(u8, op, "stride_fits")) {
        if (stride == 0 or available_bytes < header_bytes) return null;
        return (available_bytes - header_bytes) / stride;
    }
    if (std.mem.eql(u8, op, "ge")) return expected_min;
    if (std.mem.eql(u8, op, "gt")) return expected_min +| 1;
    if (std.mem.eql(u8, op, "le")) return expected_max;
    if (std.mem.eql(u8, op, "lt")) return if (expected_max > 0) expected_max - 1 else 0;
    if (std.mem.eql(u8, op, "range")) {
        if (measured < expected_min) return expected_min;
        if (measured > expected_max) return expected_max;
        return measured;
    }
    if (std.mem.eql(u8, op, "eq")) return expected_min;
    return null;
}

pub fn computeClampedSigned(
    op: []const u8,
    measured: i64,
    expected_min: i64,
    expected_max: i64,
) ?i64 {
    if (std.mem.eql(u8, op, "ge")) return expected_min;
    if (std.mem.eql(u8, op, "gt")) return expected_min +| 1;
    if (std.mem.eql(u8, op, "le")) return expected_max;
    if (std.mem.eql(u8, op, "lt")) return expected_max -| 1;
    if (std.mem.eql(u8, op, "range")) {
        if (measured < expected_min) return expected_min;
        if (measured > expected_max) return expected_max;
        return measured;
    }
    if (std.mem.eql(u8, op, "eq")) return expected_min;
    return null;
}

pub fn encodeFieldBytes(
    alloc: Allocator,
    field_kind: []const u8,
    val: u64,
    signed_val: i64,
    fourcc: []const u8,
) ![]const u8 {
    if (std.mem.eql(u8, field_kind, "u8")) {
        const buf = try alloc.alloc(u8, 1);
        buf[0] = @truncate(val);
        return buf;
    }
    if (std.mem.eql(u8, field_kind, "u16be")) {
        const buf = try alloc.alloc(u8, 2);
        std.mem.writeInt(u16, buf[0..2], @truncate(val), .big);
        return buf;
    }
    if (std.mem.eql(u8, field_kind, "u16le")) {
        const buf = try alloc.alloc(u8, 2);
        std.mem.writeInt(u16, buf[0..2], @truncate(val), .little);
        return buf;
    }
    if (std.mem.eql(u8, field_kind, "u32be")) {
        const buf = try alloc.alloc(u8, 4);
        std.mem.writeInt(u32, buf[0..4], @truncate(val), .big);
        return buf;
    }
    if (std.mem.eql(u8, field_kind, "u32le")) {
        const buf = try alloc.alloc(u8, 4);
        std.mem.writeInt(u32, buf[0..4], @truncate(val), .little);
        return buf;
    }
    if (std.mem.eql(u8, field_kind, "i32le")) {
        const buf = try alloc.alloc(u8, 4);
        const clamped_i32: i32 = @intCast(std.math.clamp(signed_val, std.math.minInt(i32), std.math.maxInt(i32)));
        std.mem.writeInt(i32, buf[0..4], clamped_i32, .little);
        return buf;
    }
    if (std.mem.eql(u8, field_kind, "u64be")) {
        const buf = try alloc.alloc(u8, 8);
        std.mem.writeInt(u64, buf[0..8], val, .big);
        return buf;
    }
    if (std.mem.eql(u8, field_kind, "u64le")) {
        const buf = try alloc.alloc(u8, 8);
        std.mem.writeInt(u64, buf[0..8], val, .little);
        return buf;
    }
    if (std.mem.eql(u8, field_kind, "fourcc")) {
        if (fourcc.len != 4) return error.InvalidFourCC;
        return try alloc.dupe(u8, fourcc);
    }
    return error.UnsupportedFieldKind;
}

pub fn encodeMaskedWord(
    alloc: Allocator,
    raw_word: u64,
    byte_width: u8,
    is_little: bool,
    bit_mask: u64,
    bit_shift: u6,
    new_subval: u64,
) ![]const u8 {
    const shifted = (new_subval << bit_shift) & bit_mask;
    const patched_word = (raw_word & ~bit_mask) | shifted;
    const endian: std.builtin.Endian = if (is_little) .little else .big;

    return switch (byte_width) {
        1 => blk: {
            const buf = try alloc.alloc(u8, 1);
            buf[0] = @truncate(patched_word);
            break :blk buf;
        },
        2 => blk: {
            const buf = try alloc.alloc(u8, 2);
            std.mem.writeInt(u16, buf[0..2], @truncate(patched_word), endian);
            break :blk buf;
        },
        4 => blk: {
            const buf = try alloc.alloc(u8, 4);
            std.mem.writeInt(u32, buf[0..4], @truncate(patched_word), endian);
            break :blk buf;
        },
        8 => blk: {
            const buf = try alloc.alloc(u8, 8);
            std.mem.writeInt(u64, buf[0..8], patched_word, endian);
            break :blk buf;
        },
        else => error.UnsupportedByteWidth,
    };
}

test "remediation_encoder: resolvePolicy defaults and explicit values" {
    try std.testing.expectEqual(OnFailPolicy.quarantine, try resolvePolicy("", true));
    try std.testing.expectEqual(OnFailPolicy.log_only, try resolvePolicy("", false));
    try std.testing.expectEqual(OnFailPolicy.clamp, try resolvePolicy("clamp", true));
    try std.testing.expectEqual(OnFailPolicy.patch, try resolvePolicy("patch", true));
    try std.testing.expectEqual(OnFailPolicy.tombstone, try resolvePolicy("tombstone", true));
    try std.testing.expectEqual(OnFailPolicy.tombstone_excess, try resolvePolicy("tombstone_excess", true));
    try std.testing.expectEqual(OnFailPolicy.zero_payload, try resolvePolicy("zero_payload", true));
    try std.testing.expectEqual(OnFailPolicy.sync_container_dimensions, try resolvePolicy("sync_container_dimensions", true));
    try std.testing.expectError(error.InvalidOnFailPolicy, resolvePolicy("bogus", true));
}

test "remediation_encoder: computeClampedUnsigned all operators" {
    try std.testing.expectEqual(@as(?u64, 5), computeClampedUnsigned("stride_fits", 99, 0, 0, 8, 12, 52));
    try std.testing.expectEqual(@as(?u64, null), computeClampedUnsigned("stride_fits", 99, 0, 0, 0, 12, 52));
    try std.testing.expectEqual(@as(?u64, null), computeClampedUnsigned("stride_fits", 99, 0, 0, 8, 20, 10));
    try std.testing.expectEqual(@as(?u64, 10), computeClampedUnsigned("ge", 2, 10, 0, 0, 0, 0));
    try std.testing.expectEqual(@as(?u64, 1), computeClampedUnsigned("gt", 0, 0, 0, 0, 0, 0));
    try std.testing.expectEqual(@as(?u64, 256), computeClampedUnsigned("le", 999, 0, 256, 0, 0, 0));
    try std.testing.expectEqual(@as(?u64, 255), computeClampedUnsigned("lt", 256, 0, 256, 0, 0, 0));
    try std.testing.expectEqual(@as(?u64, 10), computeClampedUnsigned("range", 5, 10, 20, 0, 0, 0));
    try std.testing.expectEqual(@as(?u64, 20), computeClampedUnsigned("range", 25, 10, 20, 0, 0, 0));
    try std.testing.expectEqual(@as(?u64, 42), computeClampedUnsigned("eq", 0, 42, 0, 0, 0, 0));
}

test "remediation_encoder: encodeFieldBytes and encodeMaskedWord" {
    const alloc = std.testing.allocator;

    const u32be = try encodeFieldBytes(alloc, "u32be", 1000, 0, "");
    defer alloc.free(u32be);
    try std.testing.expectEqualSlices(u8, &.{ 0x00, 0x00, 0x03, 0xE8 }, u32be);

    const i32le = try encodeFieldBytes(alloc, "i32le", 0, -42, "");
    defer alloc.free(i32le);
    try std.testing.expectEqual(@as(i32, -42), std.mem.readInt(i32, i32le[0..4], .little));

    // Preserve upper 6 bits (0b11111100 = 0xFC) while setting bottom 2 bits to 0b11 (3)
    const masked = try encodeMaskedWord(alloc, 0xFC | 0x02, 1, false, 0x03, 0, 3);
    defer alloc.free(masked);
    try std.testing.expectEqual(@as(u8, 0xFF), masked[0]);
}

