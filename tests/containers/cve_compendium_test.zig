const std = @import("std");
const abi = @import("flowdata_abi");
const vidsec = @import("vidsec");

const dissect_isobmff = vidsec.tasks.dissect_isobmff;
const dissect_ebml = vidsec.tasks.dissect_ebml;
const dissect_riff = vidsec.tasks.dissect_riff;
const inspect_region_field = vidsec.tasks.inspect_region_field;
const inspect_region_bits = vidsec.tasks.inspect_region_bits;
const check_region_cardinality = vidsec.tasks.check_region_cardinality;
const inspect_codec_bitstream = vidsec.tasks.inspect_codec_bitstream;
const inspect_ebml_lacing = vidsec.tasks.inspect_ebml_lacing;

const SliceStreamHost = struct {
    data: []const u8,
    ctx_abi: abi.TaskContext_ABI = undefined,
    vtable: abi.HostApiVTable_ABI = undefined,

    fn init(data: []const u8) SliceStreamHost {
        var self = SliceStreamHost{ .data = data };
        self.vtable = std.mem.zeroes(abi.HostApiVTable_ABI);
        self.vtable.stream_size = &streamSize;
        self.vtable.stream_read_at = &streamReadAt;
        self.ctx_abi = .{
            .abi_version = abi.FLOWDATA_ABI_VERSION,
            .host = &self.vtable,
            .opaque_host_state = &self,
        };
        return self;
    }

    fn reader(self: *SliceStreamHost) abi.BoundedStreamReader {
        self.ctx_abi.host = &self.vtable;
        self.ctx_abi.opaque_host_state = self;
        const ctx = abi.TaskContext.init(&self.ctx_abi);
        return ctx.streamReader();
    }

    fn streamSize(raw: *abi.TaskContext_ABI) callconv(.c) u64 {
        const self: *const SliceStreamHost = @ptrCast(@alignCast(raw.opaque_host_state));
        return self.data.len;
    }

    fn streamReadAt(raw: *abi.TaskContext_ABI, offset: u64, dst_ptr: [*]u8, dst_len: usize) callconv(.c) abi.HostError_ABI {
        const self: *const SliceStreamHost = @ptrCast(@alignCast(raw.opaque_host_state));
        if (offset >= self.data.len) return .out_of_bounds;
        const avail = self.data.len - @as(usize, @intCast(offset));
        const n = @min(avail, dst_len);
        @memcpy(dst_ptr[0..n], self.data[@intCast(offset)..][0..n]);
        return .ok;
    }
};

fn buildCleanMp4(alloc: std.mem.Allocator) ![]u8 {
    // ftyp(20) + moov(mvhd + trak(tkhd + mdia(mdhd + minf(stbl(stsd(avc1(avcC)), stsc)))))
    // Keep it clean and valid for all MP4 CVE rules:
    var avcc = [_]u8{
        0x00, 0x00, 0x00, 0x1F, 'a', 'v', 'c', 'C',
        0x01, 0x42, 0xC0, 0x1F, 0xFF, 0xE1,
        0x00, 0x09, 0x67, 0x42, 0xC0, 0x1F, 0xF6, 0x02, 0x80, 0x2D, 0x80,
        0x01, 0x00, 0x03, 0x68, 0xCE, 0x38,
    };

    // mdhd v0 (32 bytes, timescale=1000 @ payload+12)
    var mdhd: [32]u8 = @splat(0);
    std.mem.writeInt(u32, mdhd[0..4], 32, .big);
    @memcpy(mdhd[4..8], "mdhd");
    std.mem.writeInt(u32, mdhd[20..24], 1000, .big);

    // tkhd v0 (92 bytes, width=1280 @ payload+76, height=720 @ payload+80)
    var tkhd: [92]u8 = @splat(0);
    std.mem.writeInt(u32, tkhd[0..4], 92, .big);
    @memcpy(tkhd[4..8], "tkhd");
    std.mem.writeInt(u16, tkhd[84..86], 1280, .big);
    std.mem.writeInt(u16, tkhd[88..90], 720, .big);

    // stsc (28 bytes: 1 entry * 12 + 8 = 20 bytes payload)
    var stsc: [28]u8 = @splat(0);
    std.mem.writeInt(u32, stsc[0..4], 28, .big);
    @memcpy(stsc[4..8], "stsc");
    std.mem.writeInt(u32, stsc[12..16], 1, .big);

    // stbl (8 + avcc.len + stsc.len)
    const stbl_len: u32 = @intCast(8 + avcc.len + stsc.len);
    const trak_len: u32 = @intCast(8 + tkhd.len + mdhd.len + stbl_len);
    const moov_len: u32 = @intCast(8 + trak_len);

    var buf: std.ArrayList(u8) = .empty;
    try buf.appendSlice(alloc, "\x00\x00\x00\x14ftypisom\x00\x00\x02\x00isom");

    var hdr: [8]u8 = undefined;
    std.mem.writeInt(u32, hdr[0..4], moov_len, .big);
    @memcpy(hdr[4..8], "moov");
    try buf.appendSlice(alloc, &hdr);

    std.mem.writeInt(u32, hdr[0..4], trak_len, .big);
    @memcpy(hdr[4..8], "trak");
    try buf.appendSlice(alloc, &hdr);

    try buf.appendSlice(alloc, &tkhd);
    try buf.appendSlice(alloc, &mdhd);

    std.mem.writeInt(u32, hdr[0..4], stbl_len, .big);
    @memcpy(hdr[4..8], "stbl");
    try buf.appendSlice(alloc, &hdr);
    try buf.appendSlice(alloc, &avcc);
    try buf.appendSlice(alloc, &stsc);

    return buf.toOwnedSlice(alloc);
}

test "TASK-035c.5: clean MP4, MKV, and AVI fixtures produce zero CVE findings" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    // 1. Clean MP4
    const clean_mp4 = try buildCleanMp4(alloc);
    var mp4_host = SliceStreamHost.init(clean_mp4);
    const mp4_boxes = (try (dissect_isobmff.Service{}).execute(alloc, .{ .stream = mp4_host.reader() })).data.isobmff_boxes;

    try std.testing.expectEqual(@as(usize, 0), (try (inspect_region_field.Service{}).execute(alloc, .{
        .stream = mp4_host.reader(),
        .isobmff_boxes = mp4_boxes,
        .target_tag = "stsc",
        .field_offset = 4,
        .field_kind = "u32be",
        .op = "stride_fits",
        .stride = 12,
        .header_bytes = 8,
    })).data.audit_findings.len);

    try std.testing.expectEqual(@as(usize, 0), (try (inspect_region_field.Service{}).execute(alloc, .{
        .stream = mp4_host.reader(),
        .isobmff_boxes = mp4_boxes,
        .target_tag = "mdhd",
        .version_filter = 0,
        .field_offset = 12,
        .field_kind = "u32be",
        .op = "gt",
        .expected_min = 0,
    })).data.audit_findings.len);

    try std.testing.expectEqual(@as(usize, 0), (try (inspect_region_field.Service{}).execute(alloc, .{
        .stream = mp4_host.reader(),
        .isobmff_boxes = mp4_boxes,
        .target_tag = "tkhd",
        .version_filter = 0,
        .field_offset = 76,
        .field_kind = "u16be",
        .op = "le",
        .expected_max = 16384,
    })).data.audit_findings.len);

    try std.testing.expectEqual(@as(usize, 0), (try (inspect_region_bits.Service{}).execute(alloc, .{
        .stream = mp4_host.reader(),
        .isobmff_boxes = mp4_boxes,
        .target_tag = "avcC",
        .byte_offset = 4,
        .byte_width = 1,
        .bit_mask = 0x03,
        .op = "bit_forbidden",
        .forbidden_value = 2,
    })).data.audit_findings.len);

    try std.testing.expectEqual(@as(usize, 0), (try (check_region_cardinality.Service{}).execute(alloc, .{
        .isobmff_boxes = mp4_boxes,
        .parent_tag = "stbl",
        .child_tag = "stsc",
        .max_count = 1,
    })).data.audit_findings.len);

    try std.testing.expectEqual(@as(usize, 0), (try (inspect_codec_bitstream.Service{}).execute(alloc, .{
        .stream = mp4_host.reader(),
        .isobmff_boxes = mp4_boxes,
    })).data.audit_findings.len);

    // 2. Clean MKV (EBMLHeader 0x42F3=8 + Segment -> Tracks -> TrackEntry -> CodecPrivate + Cluster -> SimpleBlock)
    const clean_mkv =
        "\x1A\x45\xDF\xA3\x84\x42\xF3\x81\x08" ++
        "\x18\x53\x80\x67\xA2" ++
        "\x16\x54\xAE\x6B\x87\xAE\x85\x63\xA2\x80\x00\x00" ++
        "\x1F\x43\xB6\x75\x95\xA3\x93\x81\x00\x00\x06\x02\x85\xBE" ++ &@as([12]u8, @splat(0xAA));
    var mkv_host = SliceStreamHost.init(clean_mkv);
    const mkv_elems = (try (dissect_ebml.Service{}).execute(alloc, .{ .stream = mkv_host.reader() })).data.ebml_elements;

    try std.testing.expectEqual(@as(usize, 0), (try (inspect_region_field.Service{}).execute(alloc, .{
        .stream = mkv_host.reader(),
        .ebml_elements = mkv_elems,
        .target_tag = "0x42f3",
        .field_offset = 0,
        .field_kind = "u8",
        .op = "le",
        .expected_max = 8,
    })).data.audit_findings.len);

    try std.testing.expectEqual(@as(usize, 0), (try (check_region_cardinality.Service{}).execute(alloc, .{
        .ebml_elements = mkv_elems,
        .parent_tag = "0xae",
        .child_tag = "0x63a2",
        .max_count = 1,
    })).data.audit_findings.len);

    try std.testing.expectEqual(@as(usize, 0), (try (inspect_ebml_lacing.Service{}).execute(alloc, .{
        .stream = mkv_host.reader(),
        .ebml_elements = mkv_elems,
    })).data.audit_findings.len);

    // 3. Clean AVI (strh dwScale=1, strf biClrUsed=0, 1 strf in strl)
    var clean_strh: [56]u8 = @splat(0);
    @memcpy(clean_strh[0..4], "vids");
    std.mem.writeInt(u32, clean_strh[20..24], 1, .little); // dwScale = 1
    var clean_strf: [40]u8 = @splat(0);
    std.mem.writeInt(u32, clean_strf[0..4], 40, .little);
    // LIST hdrl (4 + 8+4+64+48 = 128) -> LIST strl (4 + 64 + 48 = 116)
    const clean_avi =
        "RIFF\x8C\x00\x00\x00AVI " ++
        "LIST\x80\x00\x00\x00hdrl" ++
        "LIST\x74\x00\x00\x00strl" ++
        "strh\x38\x00\x00\x00" ++ clean_strh ++
        "strf\x28\x00\x00\x00" ++ clean_strf;
    var avi_host = SliceStreamHost.init(clean_avi);
    const avi_chunks = (try (dissect_riff.Service{}).execute(alloc, .{ .stream = avi_host.reader() })).data.riff_chunks;

    try std.testing.expectEqual(@as(usize, 0), (try (inspect_region_field.Service{}).execute(alloc, .{
        .stream = avi_host.reader(),
        .riff_chunks = avi_chunks,
        .target_tag = "strh",
        .field_offset = 20,
        .field_kind = "u32le",
        .op = "gt",
        .expected_min = 0,
    })).data.audit_findings.len);

    try std.testing.expectEqual(@as(usize, 0), (try (inspect_region_field.Service{}).execute(alloc, .{
        .stream = avi_host.reader(),
        .riff_chunks = avi_chunks,
        .target_tag = "strf",
        .min_payload_size = 40,
        .field_offset = 32,
        .field_kind = "u32le",
        .op = "le",
        .expected_max = 256,
    })).data.audit_findings.len);

    try std.testing.expectEqual(@as(usize, 0), (try (check_region_cardinality.Service{}).execute(alloc, .{
        .riff_chunks = avi_chunks,
        .parent_tag = "strl",
        .child_tag = "strf",
        .max_count = 1,
    })).data.audit_findings.len);
}

test "TASK-035c.5: synthetic exploit fixtures trigger exact rule_id and QuarantineOrder for all CVE families" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    // CVE-2015-1539: truncated esds (< 12 bytes total box size)
    const esds_exploit = "\x00\x00\x00\x0Aesds\x00\x00";
    var esds_host = SliceStreamHost.init(esds_exploit);
    const esds_boxes = (try (dissect_isobmff.Service{}).execute(alloc, .{ .stream = esds_host.reader() })).data.isobmff_boxes;
    const esds_res = (try (inspect_region_field.Service{}).execute(alloc, .{
        .stream = esds_host.reader(),
        .isobmff_boxes = esds_boxes,
        .target_tag = "esds",
        .field_kind = "payload_size",
        .op = "ge",
        .expected_min = 12,
        .rule_id = "cve_2015_1539_stagefright_esds",
        .quarantine_on_fail = true,
    })).data;
    try std.testing.expectEqual(@as(usize, 1), esds_res.audit_findings.len);
    try std.testing.expectEqualStrings("cve_2015_1539_stagefright_esds", esds_res.audit_findings[0].rule_id);
    try std.testing.expectEqual(@as(usize, 1), esds_res.quarantine_orders.len);

    // CVE-2015-3824: truncated tx3g (< 16 bytes total box size)
    const tx3g_exploit = "\x00\x00\x00\x0Ctx3g\x00\x00\x00\x00";
    var tx3g_host = SliceStreamHost.init(tx3g_exploit);
    const tx3g_boxes = (try (dissect_isobmff.Service{}).execute(alloc, .{ .stream = tx3g_host.reader() })).data.isobmff_boxes;
    const tx3g_res = (try (inspect_region_field.Service{}).execute(alloc, .{
        .stream = tx3g_host.reader(),
        .isobmff_boxes = tx3g_boxes,
        .target_tag = "tx3g",
        .field_kind = "payload_size",
        .op = "ge",
        .expected_min = 16,
        .rule_id = "cve_2015_3824_stagefright_tx3g",
        .quarantine_on_fail = true,
    })).data;
    try std.testing.expectEqual(@as(usize, 1), tx3g_res.audit_findings.len);
    try std.testing.expectEqualStrings("cve_2015_3824_stagefright_tx3g", tx3g_res.audit_findings[0].rule_id);
    try std.testing.expectEqual(@as(usize, 1), tx3g_res.quarantine_orders.len);

    // CVE-2022-3266: tkhd width > 16384
    var tkhd_exploit: [92]u8 = @splat(0);
    std.mem.writeInt(u32, tkhd_exploit[0..4], 92, .big);
    @memcpy(tkhd_exploit[4..8], "tkhd");
    std.mem.writeInt(u16, tkhd_exploit[84..86], 40000, .big); // payload + 76
    var tkhd_host = SliceStreamHost.init(&tkhd_exploit);
    const tkhd_boxes = (try (dissect_isobmff.Service{}).execute(alloc, .{ .stream = tkhd_host.reader() })).data.isobmff_boxes;
    const tkhd_res = (try (inspect_region_field.Service{}).execute(alloc, .{
        .stream = tkhd_host.reader(),
        .isobmff_boxes = tkhd_boxes,
        .target_tag = "tkhd",
        .version_filter = 0,
        .field_offset = 76,
        .field_kind = "u16be",
        .op = "le",
        .expected_max = 16384,
        .rule_id = "cve_2022_3266_tkhd_width",
        .quarantine_on_fail = true,
    })).data;
    try std.testing.expectEqual(@as(usize, 1), tkhd_res.audit_findings.len);
    try std.testing.expectEqualStrings("cve_2022_3266_tkhd_width", tkhd_res.audit_findings[0].rule_id);
    try std.testing.expectEqual(@as(usize, 1), tkhd_res.quarantine_orders.len);

    // CVE-2021-38114: AVI strf biClrUsed > 256
    var strf_exploit: [48]u8 = @splat(0);
    @memcpy(strf_exploit[0..16], "RIFF\x28\x00\x00\x00AVI strf");
    std.mem.writeInt(u32, strf_exploit[16..20], 28, .little); // truncated or full 40B
    // Make it a 40-byte strf payload (RIFF size = 4 + 8 + 40 = 52)
    var strf_full: [60]u8 = @splat(0);
    @memcpy(strf_full[0..16], "RIFF\x34\x00\x00\x00AVI strf");
    std.mem.writeInt(u32, strf_full[16..20], 40, .little);
    std.mem.writeInt(u32, strf_full[52..56], 1024, .little); // biClrUsed @ payload+32 = 20+32 = 52
    var strf_host = SliceStreamHost.init(&strf_full);
    const strf_chunks = (try (dissect_riff.Service{}).execute(alloc, .{ .stream = strf_host.reader() })).data.riff_chunks;
    const strf_res = (try (inspect_region_field.Service{}).execute(alloc, .{
        .stream = strf_host.reader(),
        .riff_chunks = strf_chunks,
        .target_tag = "strf",
        .min_payload_size = 40,
        .field_offset = 32,
        .field_kind = "u32le",
        .op = "le",
        .expected_max = 256,
        .rule_id = "cve_2021_38114_avi_strf_palette",
        .quarantine_on_fail = true,
    })).data;
    try std.testing.expectEqual(@as(usize, 1), strf_res.audit_findings.len);
    try std.testing.expectEqualStrings("cve_2021_38114_avi_strf_palette", strf_res.audit_findings[0].rule_id);
    try std.testing.expectEqual(@as(usize, 1), strf_res.quarantine_orders.len);
}
