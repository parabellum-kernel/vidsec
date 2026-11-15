const std = @import("std");
const ByteSource = @import("byte_source.zig").ByteSource;
const FourCC = @import("box/fourcc.zig").FourCC;

/// Pure big-endian positional field readers over `ByteSource` for ISOBMFF dissection.
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

pub fn readFourCC(source: ByteSource, offset: u64) !FourCC {
    var buf: [4]u8 = undefined;
    try source.readExactAt(&buf, offset);
    return .{ .bytes = buf };
}

/// Decodes an ISO/IEC 14496-1 expandable size (7-bit continuation TLV length) starting at `offset`.
/// Returns `{ value, bytes_consumed }`.
pub fn readTlvLength(source: ByteSource, offset: u64) !struct { value: u32, bytes_consumed: u8 } {
    var val: u32 = 0;
    var i: u8 = 0;
    while (i < 4) : (i += 1) {
        const b = try readU8(source, offset + i);
        val = (val << 7) | @as(u32, b & 0x7F);
        if ((b & 0x80) == 0) {
            return .{ .value = val, .bytes_consumed = i + 1 };
        }
    }
    return .{ .value = val, .bytes_consumed = 4 };
}

