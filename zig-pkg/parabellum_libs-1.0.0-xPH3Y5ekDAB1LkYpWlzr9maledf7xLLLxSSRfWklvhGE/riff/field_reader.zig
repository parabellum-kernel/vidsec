const std = @import("std");
const ByteSource = @import("byte_source.zig").ByteSource;

/// Pure typed little-endian & FourCC reader over a `ByteSource` for RIFF/AVI field inspection.
pub fn readU8(source: ByteSource, offset: u64) !u8 {
    var buf: [1]u8 = undefined;
    try source.readExactAt(&buf, offset);
    return buf[0];
}

pub fn readU16Le(source: ByteSource, offset: u64) !u16 {
    var buf: [2]u8 = undefined;
    try source.readExactAt(&buf, offset);
    return std.mem.readInt(u16, &buf, .little);
}

pub fn readI16Le(source: ByteSource, offset: u64) !i16 {
    var buf: [2]u8 = undefined;
    try source.readExactAt(&buf, offset);
    return std.mem.readInt(i16, &buf, .little);
}

pub fn readU32Le(source: ByteSource, offset: u64) !u32 {
    var buf: [4]u8 = undefined;
    try source.readExactAt(&buf, offset);
    return std.mem.readInt(u32, &buf, .little);
}

pub fn readI32Le(source: ByteSource, offset: u64) !i32 {
    var buf: [4]u8 = undefined;
    try source.readExactAt(&buf, offset);
    return std.mem.readInt(i32, &buf, .little);
}

pub fn readU64Le(source: ByteSource, offset: u64) !u64 {
    var buf: [8]u8 = undefined;
    try source.readExactAt(&buf, offset);
    return std.mem.readInt(u64, &buf, .little);
}

pub fn readFourCC(source: ByteSource, offset: u64) ![4]u8 {
    var buf: [4]u8 = undefined;
    try source.readExactAt(&buf, offset);
    return buf;
}

