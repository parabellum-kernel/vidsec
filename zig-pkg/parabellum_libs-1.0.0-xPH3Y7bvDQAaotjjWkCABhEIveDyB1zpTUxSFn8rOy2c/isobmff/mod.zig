//! Pure, std-only ISOBMFF / MP4 binary dissector and positional field reader.

const std = @import("std");

pub const byte_source = @import("byte_source.zig");
pub const field_reader = @import("field_reader.zig");
pub const box = @import("box/mod.zig");
pub const mp4 = @import("mp4/mod.zig");

pub const ByteSource = byte_source.ByteSource;

test "isobmff: pure box dissection, hierarchical paths, containment, and coalesced sample runs" {
    const alloc = std.testing.allocator;

    // Build a minimal valid MP4: ftyp (20B) + mdat (16B) + moov/trak(tkhd+mdia(hdlr+minf(stbl(stco+stsz))))
    var buf: [256]u8 = @splat(0);
    var pos: usize = 0;

    // 1. ftyp (20 bytes)
    std.mem.writeInt(u32, buf[pos..][0..4], 20, .big);
    @memcpy(buf[pos + 4 ..][0..4], "ftyp");
    @memcpy(buf[pos + 8 ..][0..4], "isom");
    std.mem.writeInt(u32, buf[pos + 12 ..][0..4], 512, .big);
    @memcpy(buf[pos + 16 ..][0..4], "mp41");
    pos += 20;

    // 2. mdat (24 bytes: 8 hdr + 16 payload at offset 28..44)
    std.mem.writeInt(u32, buf[pos..][0..4], 24, .big);
    @memcpy(buf[pos + 4 ..][0..4], "mdat");
    pos += 24;

    // 3. stco (20 bytes: 8 hdr + 4 vf + 4 count(2) + 8 offsets(28, 36))
    var stbl_children: [64]u8 = @splat(0);
    std.mem.writeInt(u32, stbl_children[0..4], 20, .big);
    @memcpy(stbl_children[4..8], "stco");
    std.mem.writeInt(u32, stbl_children[12..16], 2, .big); // count=2
    std.mem.writeInt(u32, stbl_children[16..20], 28, .big);
    std.mem.writeInt(u32, stbl_children[20..24], 36, .big); // Wait: stco entry 0 at 16..20, entry 1 at 20..24 -> size 24!
    std.mem.writeInt(u32, stbl_children[0..4], 24, .big);

    // stsz (20 bytes: 8 hdr + 4 vf + 4 uniform_size(4) + 4 count(4))
    std.mem.writeInt(u32, stbl_children[24..28], 20, .big);
    @memcpy(stbl_children[28..32], "stsz");
    std.mem.writeInt(u32, stbl_children[36..40], 4, .big); // uniform size = 4
    std.mem.writeInt(u32, stbl_children[40..44], 4, .big); // 4 samples

    // stsc (28 bytes: 8 hdr + 4 vf + 4 count(1) + 12 entry(1, 2, 1))
    var stsc_buf: [28]u8 = @splat(0);
    std.mem.writeInt(u32, stsc_buf[0..4], 28, .big);
    @memcpy(stsc_buf[4..8], "stsc");
    std.mem.writeInt(u32, stsc_buf[12..16], 1, .big);
    std.mem.writeInt(u32, stsc_buf[16..20], 1, .big); // first_chunk = 1
    std.mem.writeInt(u32, stsc_buf[20..24], 2, .big); // 2 samples_per_chunk

    // Wrap stbl (8 + 44 + 28 = 80) -> minf (88) -> mdia (96) -> trak (104) -> moov (112)
    const stbl_len: u32 = 8 + 44 + 28;
    const minf_len: u32 = 8 + stbl_len;
    const mdia_len: u32 = 8 + minf_len;
    const trak_len: u32 = 8 + mdia_len;
    const moov_len: u32 = 8 + trak_len;

    inline for (.{
        .{ "moov", moov_len },
        .{ "trak", trak_len },
        .{ "mdia", mdia_len },
        .{ "minf", minf_len },
        .{ "stbl", stbl_len },
    }) |pair| {
        std.mem.writeInt(u32, buf[pos..][0..4], pair[1], .big);
        @memcpy(buf[pos + 4 ..][0..4], pair[0]);
        pos += 8;
    }
    @memcpy(buf[pos..][0..44], stbl_children[0..44]);
    pos += 44;
    @memcpy(buf[pos..][0..28], &stsc_buf);
    pos += 28;

    const slice: []const u8 = buf[0..pos];
    const src = ByteSource.fromSlicePtr(&slice);

    var parsed = try box.SafeBoxParser.init(alloc).parse(src);
    defer parsed.deinit();

    try std.testing.expect(parsed.has_ftyp);
    try std.testing.expect(parsed.has_moov);
    try std.testing.expectEqualStrings("moov/trak/mdia/minf/stbl/stco", parsed.boxes[7].path);

    var dissected = try mp4.Mp4Dissector.init(alloc).dissect(src, parsed.boxes);
    defer dissected.deinit();

    try std.testing.expectEqual(@as(usize, 1), dissected.tracks.len);
    // Two chunks [28..36) and [36..44) coalesce into a single SampleRun [28..44)!
    try std.testing.expectEqual(@as(usize, 1), dissected.sample_runs.len);
    try std.testing.expectEqual(@as(u64, 28), dissected.sample_runs[0].start_offset);
    try std.testing.expectEqual(@as(u64, 44), dissected.sample_runs[0].end_offset);
    try std.testing.expectEqual(@as(u32, 4), dissected.sample_runs[0].sample_count);
}

fn appendBox(list: *std.ArrayList(u8), alloc: std.mem.Allocator, fourcc: *const [4]u8, payload: []const u8) !void {
    var hdr: [8]u8 = undefined;
    std.mem.writeInt(u32, hdr[0..4], @intCast(8 + payload.len), .big);
    @memcpy(hdr[4..8], fourcc);
    try list.appendSlice(alloc, &hdr);
    try list.appendSlice(alloc, payload);
}

test "isobmff: extracts dref external refs, avcC/hvcC codec measurements, and covr attachments" {
    const alloc = std.testing.allocator;
    var buf: std.ArrayList(u8) = .empty;
    defer buf.deinit(alloc);

    // dref with 1 external url entry ("http://evil.example/x")
    const url_entry = "\x00\x00\x00\x1f" ++ "url " ++ "\x00\x00\x00\x00" ++ "http://evil.example/x\x00";
    //Wait: 8 + 4 + 22 = 34 = 0x22
    const url_box = "\x00\x00\x00\x22" ++ "url " ++ "\x00\x00\x00\x00" ++ "http://evil.example/x\x00";
    _ = url_entry;
    const dref_payload = "\x00\x00\x00\x00" ++ "\x00\x00\x00\x01" ++ url_box;
    var dref_buf: std.ArrayList(u8) = .empty;
    defer dref_buf.deinit(alloc);
    try appendBox(&dref_buf, alloc, "dref", dref_payload);

    // stsd with 1 avc1 entry containing avcC (2 SPS + 1 PPS, lengthSizeMinusOne=2 -> malformed)
    const avcc_payload = "\x01\x64\x00\x1f\xfe" ++ "\xe2" ++ // ver=1, len_m1=2, sps_count=2
        "\x00\x02\x67\x64" ++ "\x00\x02\x67\x42" ++ // 2 SPS
        "\x01" ++ "\x00\x02\x68\xee"; // 1 PPS
    var avcc_box: std.ArrayList(u8) = .empty;
    defer avcc_box.deinit(alloc);
    try appendBox(&avcc_box, alloc, "avcC", avcc_payload);

    // VisualSampleEntry = 78 bytes after 8-byte box header (86 bytes total before children)
    var avc1_payload: std.ArrayList(u8) = .empty;
    defer avc1_payload.deinit(alloc);
    try avc1_payload.appendNTimes(alloc, 0, 78);
    try avc1_payload.appendSlice(alloc, avcc_box.items);

    var avc1_box: std.ArrayList(u8) = .empty;
    defer avc1_box.deinit(alloc);
    try appendBox(&avc1_box, alloc, "avc1", avc1_payload.items);

    var stsd_payload: std.ArrayList(u8) = .empty;
    defer stsd_payload.deinit(alloc);
    try stsd_payload.appendSlice(alloc, "\x00\x00\x00\x00\x00\x00\x00\x01");
    try stsd_payload.appendSlice(alloc, avc1_box.items);

    var stsd_box: std.ArrayList(u8) = .empty;
    defer stsd_box.deinit(alloc);
    try appendBox(&stsd_box, alloc, "stsd", stsd_payload.items);

    var hdlr_payload: [16]u8 = @splat(0);
    @memcpy(hdlr_payload[8..12], "vide");
    var hdlr_box: std.ArrayList(u8) = .empty;
    defer hdlr_box.deinit(alloc);
    try appendBox(&hdlr_box, alloc, "hdlr", &hdlr_payload);

    var trak_payload: std.ArrayList(u8) = .empty;
    defer trak_payload.deinit(alloc);
    try trak_payload.appendSlice(alloc, hdlr_box.items);
    try trak_payload.appendSlice(alloc, dref_buf.items);
    try trak_payload.appendSlice(alloc, stsd_box.items);

    var trak_box: std.ArrayList(u8) = .empty;
    defer trak_box.deinit(alloc);
    try appendBox(&trak_box, alloc, "trak", trak_payload.items);

    // covr attachment inside udta/ilst
    var data_payload: std.ArrayList(u8) = .empty;
    defer data_payload.deinit(alloc);
    try data_payload.appendSlice(alloc, "\x00\x00\x00\x0d\x00\x00\x00\x00" ++ "\xff\xd8\xff\xe0");
    var data_box: std.ArrayList(u8) = .empty;
    defer data_box.deinit(alloc);
    try appendBox(&data_box, alloc, "data", data_payload.items);
    var covr_box: std.ArrayList(u8) = .empty;
    defer covr_box.deinit(alloc);
    try appendBox(&covr_box, alloc, "covr", data_box.items);
    var ilst_box: std.ArrayList(u8) = .empty;
    defer ilst_box.deinit(alloc);
    try appendBox(&ilst_box, alloc, "ilst", covr_box.items);

    var moov_payload: std.ArrayList(u8) = .empty;
    defer moov_payload.deinit(alloc);
    try moov_payload.appendSlice(alloc, trak_box.items);
    try moov_payload.appendSlice(alloc, ilst_box.items);

    try appendBox(&buf, alloc, "moov", moov_payload.items);

    const slice: []const u8 = buf.items;
    const src = ByteSource.fromSlicePtr(&slice);
    var parsed = try box.SafeBoxParser.init(alloc).parse(src);
    defer parsed.deinit();

    var dissected = try mp4.Mp4Dissector.init(alloc).dissect(src, parsed.boxes);
    defer dissected.deinit();

    try std.testing.expectEqual(@as(usize, 1), dissected.external_refs.len);
    try std.testing.expectEqualStrings("http://evil.example/x", dissected.external_refs[0].uri);
    try std.testing.expectEqual(@as(usize, 1), dissected.codec_headers.len);
    try std.testing.expectEqual(@as(u8, 2), dissected.codec_headers[0].sps_count);
    try std.testing.expect(dissected.codec_headers[0].is_malformed);
    try std.testing.expectEqual(@as(usize, 1), dissected.attachments.len);
    try std.testing.expectEqualStrings("image/jpeg", dissected.attachments[0].declared_mime);
}

test {
    _ = mp4.nalu_sps;
}
