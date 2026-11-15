const std = @import("std");
const ByteSource = @import("byte_source.zig").ByteSource;

/// Pure typed scalar & VINT reader over a `ByteSource` for arbitrary EBML/MKV field inspection.
pub fn readU8(source: ByteSource, offset: u64) !u8 {
    var buf: [1]u8 = undefined;
    try source.readExactAt(&buf, offset);
    return buf[0];
}

pub fn readU16Be(source: ByteSource, offset: u64) !u16 {
    var buf: [2]u8 = undefined;
    try source.readExactAt(&buf, offset);
    return std.mem.readInt(u16, &buf, .big);
}

pub fn readU32Be(source: ByteSource, offset: u64) !u32 {
    var buf: [4]u8 = undefined;
    try source.readExactAt(&buf, offset);
    return std.mem.readInt(u32, &buf, .big);
}

pub fn readU64Be(source: ByteSource, offset: u64) !u64 {
    var buf: [8]u8 = undefined;
    try source.readExactAt(&buf, offset);
    return std.mem.readInt(u64, &buf, .big);
}

pub fn readUint(source: ByteSource, offset: u64, size: u64) !u64 {
    if (size == 0 or size > 8) return 0;
    var buf: [8]u8 = @splat(0);
    const sz: usize = @intCast(size);
    try source.readExactAt(buf[8 - sz .. 8], offset);
    return std.mem.readInt(u64, &buf, .big);
}

pub fn readFloat(source: ByteSource, offset: u64, size: u64) !f64 {
    if (size == 4) {
        const bits = try readU32Be(source, offset);
        const f: f32 = @bitCast(bits);
        return @floatCast(f);
    } else if (size == 8) {
        const bits = try readU64Be(source, offset);
        return @bitCast(bits);
    }
    return 0.0;
}

pub fn readString(source: ByteSource, buf: []u8, offset: u64, size: u64) ![]const u8 {
    if (size == 0 or offset >= source.file_size) return "";
    const avail = source.file_size - offset;
    const to_read: usize = @intCast(@min(@min(size, avail), buf.len));
    if (to_read == 0) return "";
    const n = try source.readAt(buf[0..to_read], offset);
    var end = n;
    while (end > 0 and buf[end - 1] == 0) : (end -= 1) {}
    return buf[0..end];
}

