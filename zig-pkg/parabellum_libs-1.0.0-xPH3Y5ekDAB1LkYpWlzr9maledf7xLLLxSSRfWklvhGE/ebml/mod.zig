//! Pure `std`-only EBML / Matroska (MKV / WebM) deep dissector.

const std = @import("std");

pub const byte_source = @import("byte_source.zig");
pub const field_reader = @import("field_reader.zig");
pub const ebml = @import("ebml/mod.zig");
pub const mkv = @import("mkv/mod.zig");

pub const ByteSource = byte_source.ByteSource;

test {
    std.testing.refAllDecls(@This());
}

fn appendEbmlId(list: *std.ArrayList(u8), alloc: std.mem.Allocator, id: u32) !void {
    if (id <= 0xFF) {
        try list.append(alloc, @truncate(id));
    } else if (id <= 0xFFFF) {
        try list.append(alloc, @truncate(id >> 8));
        try list.append(alloc, @truncate(id));
    } else if (id <= 0xFFFFFF) {
        try list.append(alloc, @truncate(id >> 16));
        try list.append(alloc, @truncate(id >> 8));
        try list.append(alloc, @truncate(id));
    } else {
        try list.append(alloc, @truncate(id >> 24));
        try list.append(alloc, @truncate(id >> 16));
        try list.append(alloc, @truncate(id >> 8));
        try list.append(alloc, @truncate(id));
    }
}

fn appendEbmlElem(list: *std.ArrayList(u8), alloc: std.mem.Allocator, id: u32, payload: []const u8) !void {
    try appendEbmlId(list, alloc, id);
    std.debug.assert(payload.len < 127);
    try list.append(alloc, @as(u8, 0x80) | @as(u8, @truncate(payload.len)));
    try list.appendSlice(alloc, payload);
}

test "ebml: extracts NextFilename external refs, Cues bounds, and EBMLMaxSizeLength" {
    const alloc = std.testing.allocator;
    var buf: std.ArrayList(u8) = .empty;
    defer buf.deinit(alloc);

    // EBML Header with EBMLMaxSizeLength = 12 (0x0c)
    var hdr_pay: std.ArrayList(u8) = .empty;
    defer hdr_pay.deinit(alloc);
    try appendEbmlElem(&hdr_pay, alloc, 0x4282, "matroska");
    try appendEbmlElem(&hdr_pay, alloc, 0x42F3, "\x0c");
    try appendEbmlElem(&buf, alloc, 0x1A45DFA3, hdr_pay.items);

    // Segment -> Info (NextFilename = "../secret.mkv") + Cues (CueClusterPosition = 0xFFFF)
    var info_pay: std.ArrayList(u8) = .empty;
    defer info_pay.deinit(alloc);
    try appendEbmlElem(&info_pay, alloc, 0x3E83BB, "../secret.mkv");

    var tp_pay: std.ArrayList(u8) = .empty;
    defer tp_pay.deinit(alloc);
    try appendEbmlElem(&tp_pay, alloc, 0xF7, "\x01");
    try appendEbmlElem(&tp_pay, alloc, 0xF1, "\xff\xff");

    var cp_pay: std.ArrayList(u8) = .empty;
    defer cp_pay.deinit(alloc);
    try appendEbmlElem(&cp_pay, alloc, 0xB3, "\x00");
    try appendEbmlElem(&cp_pay, alloc, 0xB7, tp_pay.items);

    var cues_pay: std.ArrayList(u8) = .empty;
    defer cues_pay.deinit(alloc);
    try appendEbmlElem(&cues_pay, alloc, 0xBB, cp_pay.items);

    var seg_pay: std.ArrayList(u8) = .empty;
    defer seg_pay.deinit(alloc);
    try appendEbmlElem(&seg_pay, alloc, 0x1549A966, info_pay.items);
    try appendEbmlElem(&seg_pay, alloc, 0x1C53BB6B, cues_pay.items);
    try appendEbmlElem(&buf, alloc, 0x18538067, seg_pay.items);

    var slice: []const u8 = buf.items;
    const src = ByteSource.fromSlicePtr(&slice);

    var parsed = try ebml.SafeEbmlParser.init(alloc, .{}).parse(src);
    defer parsed.deinit();

    var dissected = try mkv.MkvDissector.init(alloc).dissect(src, parsed.elements);
    defer dissected.deinit();

    try std.testing.expectEqual(@as(u64, 12), dissected.header_ebml_max_size_length);
    try std.testing.expectEqual(@as(usize, 1), dissected.external_refs.len);
    try std.testing.expectEqualStrings("../secret.mkv", dissected.external_refs[0].filename);
    try std.testing.expectEqual(@as(usize, 1), dissected.cues.len);
    try std.testing.expect(!dissected.cues[0].in_segment_bounds);
}

test {
    _ = mkv.lacing;
}
