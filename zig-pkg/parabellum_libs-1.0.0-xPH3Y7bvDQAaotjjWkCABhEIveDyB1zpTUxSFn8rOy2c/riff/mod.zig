//! Pure `std`-only RIFF / AVI deep dissector.

const std = @import("std");

pub const byte_source = @import("byte_source.zig");
pub const field_reader = @import("field_reader.zig");
pub const riff = @import("riff/mod.zig");
pub const avi = @import("avi/mod.zig");

pub const ByteSource = byte_source.ByteSource;

test {
    std.testing.refAllDecls(@This());
}

fn appendChunk(list: *std.ArrayList(u8), alloc: std.mem.Allocator, fourcc: *const [4]u8, payload: []const u8) !void {
    try list.appendSlice(alloc, fourcc);
    var sz: [4]u8 = undefined;
    std.mem.writeInt(u32, &sz, @intCast(payload.len), .little);
    try list.appendSlice(alloc, &sz);
    try list.appendSlice(alloc, payload);
    if ((payload.len & 1) != 0) try list.append(alloc, 0);
}

test "riff: detects BITMAPINFOHEADER dimension multiplication overflow" {
    const alloc = std.testing.allocator;

    var strh_pay: [56]u8 = @splat(0);
    @memcpy(strh_pay[0..4], "vids");
    @memcpy(strh_pay[4..8], "H264");
    std.mem.writeInt(u32, strh_pay[20..24], 1, .little);
    std.mem.writeInt(u32, strh_pay[24..28], 30, .little);

    var strf_pay: [40]u8 = @splat(0);
    std.mem.writeInt(u32, strf_pay[0..4], 40, .little); // biSize
    std.mem.writeInt(i32, strf_pay[4..8], 65536, .little); // width
    std.mem.writeInt(i32, strf_pay[8..12], 65536, .little); // height -> 65536 * 65536 overflows u32!
    std.mem.writeInt(u16, strf_pay[12..14], 1, .little); // biPlanes
    std.mem.writeInt(u16, strf_pay[14..16], 24, .little); // biBitCount

    var strl_pay: std.ArrayList(u8) = .empty;
    defer strl_pay.deinit(alloc);
    try strl_pay.appendSlice(alloc, "strl");
    try appendChunk(&strl_pay, alloc, "strh", &strh_pay);
    try appendChunk(&strl_pay, alloc, "strf", &strf_pay);

    var hdrl_pay: std.ArrayList(u8) = .empty;
    defer hdrl_pay.deinit(alloc);
    try hdrl_pay.appendSlice(alloc, "hdrl");
    try appendChunk(&hdrl_pay, alloc, "LIST", strl_pay.items);

    var avi_pay: std.ArrayList(u8) = .empty;
    defer avi_pay.deinit(alloc);
    try avi_pay.appendSlice(alloc, "AVI ");
    try appendChunk(&avi_pay, alloc, "LIST", hdrl_pay.items);

    var buf: std.ArrayList(u8) = .empty;
    defer buf.deinit(alloc);
    try appendChunk(&buf, alloc, "RIFF", avi_pay.items);

    const slice: []const u8 = buf.items;
    const src = ByteSource.fromSlicePtr(&slice);

    var parsed = try riff.SafeRiffParser.init(alloc, .{}).parse(src);
    defer parsed.deinit();

    var dissected = try avi.AviDissector.init(alloc).dissect(src, parsed.chunks);
    defer dissected.deinit();

    try std.testing.expectEqual(@as(usize, 1), dissected.streams.len);
    try std.testing.expect(dissected.streams[0].video != null);
    try std.testing.expect(dissected.streams[0].video.?.dim_mul_overflow);
}
