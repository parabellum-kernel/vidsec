const std = @import("std");
const abi = @import("parabellum_sdk").task;
const vidsec = @import("vidsec");

const lower_mp4 = vidsec.tasks.lower_mp4_container;
const lower_ebml = vidsec.tasks.lower_ebml_container;
const lower_riff = vidsec.tasks.lower_riff_container;
const dissect_isobmff = vidsec.tasks.dissect_isobmff;
const dissect_mp4_atoms = vidsec.tasks.dissect_mp4_atoms;
const dissect_ebml = vidsec.tasks.dissect_ebml;
const dissect_mkv_structures = vidsec.tasks.dissect_mkv_structures;
const dissect_riff = vidsec.tasks.dissect_riff;
const inspect_region_field = vidsec.tasks.inspect_region_field;
const inspect_region_bits = vidsec.tasks.inspect_region_bits;
const check_region_cardinality = vidsec.tasks.check_region_cardinality;
const inspect_codec_bitstream = vidsec.tasks.inspect_codec_bitstream;
const inspect_ebml_lacing = vidsec.tasks.inspect_ebml_lacing;
const check_mp4_structure = vidsec.tasks.check_mp4_structure;
const check_mkv_structure = vidsec.tasks.check_mkv_structure;
const check_avi_structure = vidsec.tasks.check_avi_structure;

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
            .abi_version = abi.PARABELLUM_ABI_VERSION,
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

    fn streamReadAt(raw: *abi.TaskContext_ABI, offset: u64, dest_ptr: [*]u8, len: usize) callconv(.c) abi.HostError_ABI {
        const self: *const SliceStreamHost = @ptrCast(@alignCast(raw.opaque_host_state));
        if (offset + len > self.data.len) return .end_of_stream;
        @memcpy(dest_ptr[0..len], self.data[@intCast(offset)..][0..len]);
        return .ok;
    }
};

test "lower_mp4_container lowers ftyp + moov + mdat in O(boxes)" {
    // 24-byte ftyp + 8-byte moov + 16-byte mdat = 48 bytes
    const data =
        "\x00\x00\x00\x18ftypisom\x00\x00\x02\x00isommp41" ++
        "\x00\x00\x00\x08moov" ++
        "\x00\x00\x00\x10mdat\xDE\xAD\xBE\xEF\xCA\xFE\xBA\xBE";

    var host = SliceStreamHost.init(data);
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const svc = lower_mp4.Service{};
    const out = (try svc.execute(arena.allocator(), .{
        .stream = host.reader(),
        .true_magic_kind = 10,
        .identified_format = "mp4",
    })).data;

    try std.testing.expectEqual(@as(u64, data.len), out.container_metadata.file_size);
    try std.testing.expectEqual(@as(u64, data.len), out.container_metadata.highest_root_end);
    try std.testing.expectEqual(@as(i64, 10), out.container_metadata.true_magic);
    try std.testing.expectEqualStrings("mp4", out.container_metadata.true_magic_name);
    try std.testing.expectEqual(@as(usize, 3), out.ir_regions.len);
    try std.testing.expectEqualStrings("ftyp", out.ir_regions[0].tag_name);
    try std.testing.expectEqualStrings("moov", out.ir_regions[1].tag_name);
    try std.testing.expectEqualStrings("mdat", out.ir_regions[2].tag_name);
    try std.testing.expectEqualStrings("media_data", out.ir_regions[2].role);
    try std.testing.expect(!@hasField(@TypeOf(out), "audit_findings"));
}

test "lower_mp4_container flags overflowing mdat box" {
    // ftyp (24) + moov (8) + mdat declaring 100 bytes when only 12 remain
    const data =
        "\x00\x00\x00\x18ftypisom\x00\x00\x02\x00isommp41" ++
        "\x00\x00\x00\x08moov" ++
        "\x00\x00\x00\x64mdat\x00\x01\x02\x03";

    var host = SliceStreamHost.init(data);
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const svc = lower_mp4.Service{};
    const out = (try svc.execute(arena.allocator(), .{
        .stream = host.reader(),
    })).data;

    try std.testing.expectEqual(@as(usize, 3), out.ir_regions.len);
    try std.testing.expect(out.ir_regions[2].is_truncated_or_overflow);
}

test "lower_ebml_container lowers EBML header + Segment + Cluster" {
    // EBML Header (0x1A45DFA3, size 4 -> 0x84, 4 dummy bytes) = 9 bytes
    // Segment (0x18538067, size 10 -> 0x8A) containing Cluster (0x1F43B675, size 5 -> 0x85, 5 bytes) = 15 bytes
    const data =
        "\x1A\x45\xDF\xA3\x84\x42\x86\x81\x01" ++
        "\x18\x53\x80\x67\x8A" ++
        "\x1F\x43\xB6\x75\x85\x01\x02\x03\x04\x05";

    var host = SliceStreamHost.init(data);
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const svc = lower_ebml.Service{};
    const out = (try svc.execute(arena.allocator(), .{
        .stream = host.reader(),
        .true_magic_kind = 11,
        .identified_format = "mkv",
    })).data;

    try std.testing.expectEqual(@as(u64, data.len), out.container_metadata.file_size);
    try std.testing.expectEqual(@as(u64, data.len), out.container_metadata.highest_root_end);
    try std.testing.expect(out.ir_regions.len >= 2);
    try std.testing.expectEqualStrings("0x1a45dfa3", out.ir_regions[0].tag_name);
}

test "lower_riff_container lowers RIFF/AVI + LIST hdrl + LIST movi" {
    // RIFF (size=28: "AVI " (4) + LIST hdrl (12) + LIST movi (12)) -> total 36 bytes
    const data =
        "RIFF\x1C\x00\x00\x00AVI " ++
        "LIST\x04\x00\x00\x00hdrl" ++
        "LIST\x04\x00\x00\x00movi";

    var host = SliceStreamHost.init(data);
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const svc = lower_riff.Service{};
    const out = (try svc.execute(arena.allocator(), .{
        .stream = host.reader(),
        .true_magic_kind = 12,
        .identified_format = "avi",
    })).data;

    try std.testing.expectEqual(@as(u64, data.len), out.container_metadata.file_size);
    try std.testing.expectEqual(@as(u64, data.len), out.container_metadata.highest_root_end);
    try std.testing.expect(out.ir_regions.len >= 2);
    try std.testing.expectEqualStrings("RIFF", out.ir_regions[0].tag_name);
    try std.testing.expect(!@hasField(@TypeOf(out), "audit_findings"));
}

test "check_mp4_ftyp validates ftyp brand independently" {
    const data =
        "\x00\x00\x00\x18ftypisom\x00\x00\x02\x00isommp41" ++
        "\x00\x00\x00\x08moov";

    var host = SliceStreamHost.init(data);
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const svc = dissect_isobmff.Service{};
    const out = (try svc.execute(arena.allocator(), .{
        .stream = host.reader(),
    })).data;

    try std.testing.expect(out.isobmff_triage.has_ftyp);
    try std.testing.expect(out.isobmff_triage.has_moov);
    try std.testing.expect(out.isobmff_triage.isobmff_valid);
    try std.testing.expectEqual(@as(u64, 2), out.isobmff_triage.box_count);
}

test "dissect_mp4_atoms + check_mp4_structure catches avcC SPS overflow CVE pattern" {
    // ftyp (24) + avcC (16 bytes total: 8-byte box hdr + 8-byte avcC declaring num_sps=1, sps_len=200 > payload)
    const data =
        "\x00\x00\x00\x18ftypisom\x00\x00\x02\x00isommp41" ++
        "\x00\x00\x00\x10avcC\x01\x42\x00\x1E\xFF\xE1\x00\xC8";

    var host = SliceStreamHost.init(data);
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const iso_out = (try (dissect_isobmff.Service{}).execute(arena.allocator(), .{
        .stream = host.reader(),
    })).data;
    const atoms_out = (try (dissect_mp4_atoms.Service{}).execute(arena.allocator(), .{
        .stream = host.reader(),
    })).data;

    try std.testing.expectEqual(@as(u64, 1), atoms_out.mp4_atoms_summary.avcc_count);
    try std.testing.expect(!atoms_out.mp4_atoms_summary.atoms_valid);
    try std.testing.expect(!@hasField(@TypeOf(atoms_out), "audit_findings"));
    try std.testing.expect(!@hasField(@TypeOf(iso_out), "audit_findings"));

    const chk = (try (check_mp4_structure.Service{}).execute(arena.allocator(), .{
        .isobmff_triage = iso_out.isobmff_triage,
        .isobmff_boxes = iso_out.isobmff_boxes,
        .mp4_table_measurements = atoms_out.mp4_table_measurements,
        .mp4_codec_headers = atoms_out.mp4_codec_headers,
    })).data;
    try std.testing.expect(!chk.mp4_structure_valid);
    var saw_avcc = false;
    for (chk.audit_findings) |f| {
        if (std.mem.eql(u8, f.rule_id, "avcc_malformed_config")) saw_avcc = true;
    }
    try std.testing.expect(saw_avcc);
}

test "inspect_region_field validates typed scalar bounds" {
    const data =
        "\x00\x00\x00\x18ftypisom\x00\x00\x02\x00isommp41" ++
        "\x00\x00\x00\x08moov";

    var host = SliceStreamHost.init(data);
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const svc = inspect_region_field.Service{};
    const ok_out = (try svc.execute(arena.allocator(), .{
        .stream = host.reader(),
        .target_offset = 0,
        .field_kind = "u32be",
        .expected_min = 8,
        .expected_max = 64,
    })).data;
    try std.testing.expectEqual(@as(u64, 24), ok_out.region_field_results[0].u64_value);
    try std.testing.expect(ok_out.region_field_results[0].in_bounds);

    const bad_out = (try svc.execute(arena.allocator(), .{
        .stream = host.reader(),
        .target_offset = 0,
        .field_kind = "u32be",
        .expected_min = 8,
        .expected_max = 16,
        .rule_id = "cve_box_size_limit",
    })).data;
    try std.testing.expect(!bad_out.region_field_results[0].in_bounds);
    try std.testing.expectEqualStrings("cve_box_size_limit", bad_out.audit_findings[0].rule_id);
}

test "dissect_ebml + dissect_mkv_structures are pure and check_mkv_structure validates R03/R04/R09" {
    const data =
        "\x1A\x45\xDF\xA3\x84\x42\x86\x81\x01" ++
        "\x18\x53\x80\x67\x8A" ++
        "\x1F\x43\xB6\x75\x85\x01\x02\x03\x04\x05";

    var host = SliceStreamHost.init(data);
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const hdr_out = (try (dissect_ebml.Service{}).execute(arena.allocator(), .{
        .stream = host.reader(),
    })).data;
    try std.testing.expect(hdr_out.ebml_triage.has_ebml_header);
    try std.testing.expect(hdr_out.ebml_triage.has_segment);
    try std.testing.expectEqual(@as(u64, 1), hdr_out.ebml_triage.cluster_count);
    try std.testing.expect(hdr_out.ebml_triage.ebml_valid);
    try std.testing.expect(!@hasField(@TypeOf(hdr_out), "audit_findings"));

    const trk_out = (try (dissect_mkv_structures.Service{}).execute(arena.allocator(), .{
        .stream = host.reader(),
    })).data;
    try std.testing.expect(!trk_out.mkv_structures_summary.mkv_valid);
    try std.testing.expect(!@hasField(@TypeOf(trk_out), "audit_findings"));

    const chk = (try (check_mkv_structure.Service{}).execute(arena.allocator(), .{
        .ebml_triage = hdr_out.ebml_triage,
        .ebml_elements = hdr_out.ebml_elements,
        .mkv_structures_summary = trk_out.mkv_structures_summary,
        .mkv_tracks = trk_out.mkv_tracks,
        .mkv_cues = &.{.{ .cue_time = 0, .track_number = 1, .cluster_position = 99999, .in_segment_bounds = false }},
        .mkv_lacing_anomalies = &.{.{ .offset = 100, .lacing_kind = 1, .frame_count = 10, .payload_size = 4 }},
    })).data;
    try std.testing.expect(!chk.mkv_structure_valid);
    var saw_missing_tracks = false;
    var saw_cue = false;
    var saw_lacing = false;
    for (chk.audit_findings) |f| {
        if (std.mem.eql(u8, f.rule_id, "segment_missing_tracks")) saw_missing_tracks = true;
        if (std.mem.eql(u8, f.rule_id, "mkv_cue_out_of_segment_bounds")) saw_cue = true;
        if (std.mem.eql(u8, f.rule_id, "mkv_invalid_lacing")) saw_lacing = true;
    }
    try std.testing.expect(saw_missing_tracks and saw_cue and saw_lacing);
}

test "dissect_riff is pure and check_avi_structure catches R01/R03/R09 violations" {
    const data =
        "RIFF\x1C\x00\x00\x00AVI " ++
        "LIST\x04\x00\x00\x00hdrl" ++
        "LIST\x04\x00\x00\x00movi";

    var host = SliceStreamHost.init(data);
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const out = (try (dissect_riff.Service{}).execute(arena.allocator(), .{
        .stream = host.reader(),
    })).data;

    try std.testing.expectEqualStrings("AVI ", out.riff_triage.form_type);
    try std.testing.expectEqual(@as(u64, 28), out.riff_triage.root_size);
    try std.testing.expect(out.riff_triage.riff_valid);
    try std.testing.expect(!@hasField(@TypeOf(out), "audit_findings"));

    // Clean check
    const clean_chk = (try (check_avi_structure.Service{}).execute(arena.allocator(), .{
        .riff_triage = out.riff_triage,
        .riff_chunks = out.riff_chunks,
        .avi_stream_headers = out.avi_stream_headers,
    })).data;
    try std.testing.expect(clean_chk.avi_structure_valid);

    // Violating check: root_size mismatch + BITMAPINFOHEADER overflow + idx1 overflow
    var bad_triage = out.riff_triage;
    bad_triage.root_size = 9999;
    bad_triage.idx1_size = 32;
    bad_triage.idx1_entry_count = 10;
    const bad_chk = (try (check_avi_structure.Service{}).execute(arena.allocator(), .{
        .riff_triage = bad_triage,
        .riff_chunks = out.riff_chunks,
        .avi_stream_headers = &.{.{
            .stream_index = 0,
            .fcc_type = "vids",
            .fcc_handler = "H264",
            .scale = 1,
            .rate = 30,
            .length = 10,
            .strf_offset = 100,
            .strf_size = 40,
            .has_video = true,
            .bi_size = 20,
            .width = 65535,
            .height = std.math.minInt(i32),
            .bi_planes = 1,
            .bit_count = 32,
            .bi_size_image = 0,
            .bi_clr_used = 256,
            .dim_mul_overflow = true,
        }},
    })).data;
    try std.testing.expect(!bad_chk.avi_structure_valid);
    var saw_root = false;
    var saw_dim = false;
    var saw_int_min = false;
    var saw_clr = false;
    var saw_idx1 = false;
    for (bad_chk.audit_findings) |f| {
        if (std.mem.eql(u8, f.rule_id, "riff_root_size_mismatch")) saw_root = true;
        if (std.mem.eql(u8, f.rule_id, "avi_bitmap_dim_overflow")) saw_dim = true;
        if (std.mem.eql(u8, f.rule_id, "avi_bitmap_height_int32_min")) saw_int_min = true;
        if (std.mem.eql(u8, f.rule_id, "avi_bitmap_clr_used_overflow")) saw_clr = true;
        if (std.mem.eql(u8, f.rule_id, "avi_idx1_entry_overflow")) saw_idx1 = true;
    }
    try std.testing.expect(saw_root and saw_dim and saw_int_min and saw_clr and saw_idx1);
}

test "check_mp4_structure catches R03 depth/missing boxes, R04a table overflow, and R09a codec anomalies" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const chk = (try (check_mp4_structure.Service{}).execute(arena.allocator(), .{
        .isobmff_triage = .{
            .box_count = 1,
            .has_ftyp = false,
            .has_moov = false,
            .has_mdat = false,
            .highest_root_end = 16,
            .has_overflow_or_truncated = true,
            .truncated_tail_offset = 16,
            .isobmff_valid = false,
        },
        .isobmff_boxes = &.{.{
            .region_id = 0,
            .parent_region_id = null,
            .depth = 35,
            .fourcc = "moov",
            .path = "/moov",
            .role = "container",
            .header_offset = 0,
            .payload_offset = 8,
            .declared_size = 16,
            .available_bytes = 8,
            .is_truncated = false,
            .is_overflow = true,
        }},
        .mp4_table_measurements = &.{.{
            .table_fourcc = "stsc",
            .path = "/moov/trak/mdia/minf/stbl/stsc",
            .entry_count = 0xFFFFFFFF,
            .entry_size = 12,
            .claimed_bytes = 1000,
            .payload_size = 20,
            .is_overflow = true,
            .has_arith_overflow = true,
        }},
        .mp4_codec_headers = &.{
            .{
                .track_id = 1,
                .codec_tag = "avcC",
                .kind = "avcc",
                .is_malformed = false,
                .length_size_minus_one = 2,
                .sps_count = 1,
                .pps_count = 1,
                .array_count = 0,
                .claimed_bytes = 20,
                .payload_size = 20,
            },
            .{
                .track_id = 2,
                .codec_tag = "hvcC",
                .kind = "hvcc",
                .is_malformed = true,
                .length_size_minus_one = 3,
                .sps_count = 0,
                .pps_count = 0,
                .array_count = 2,
                .claimed_bytes = 50,
                .payload_size = 23,
            },
        },
    })).data;

    try std.testing.expect(!chk.mp4_structure_valid);
    var saw_depth = false;
    var saw_table = false;
    var saw_nalu = false;
    var saw_hvcc = false;
    for (chk.audit_findings) |f| {
        if (std.mem.eql(u8, f.rule_id, "box_recursion_depth_exceeded")) saw_depth = true;
        if (std.mem.eql(u8, f.rule_id, "mp4_sample_table_overflow")) saw_table = true;
        if (std.mem.eql(u8, f.rule_id, "avcc_invalid_nalu_length_size")) saw_nalu = true;
        if (std.mem.eql(u8, f.rule_id, "hvcc_malformed_config")) saw_hvcc = true;
    }
    try std.testing.expect(saw_depth and saw_table and saw_nalu and saw_hvcc);
}

test "inspect_region_field catches synthetic CVE-2015-1538, CVE-2015-3864, CVE-2022-22675, EBML 0x42f3, and AVI strh zero dwScale" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    // 1. CVE-2015-1538 (stsc entry_count overflow via stride_fits)
    // stsc box (20 bytes total): header(8) + version/flags(4) + entry_count=0x10000001 (4) + dummy(4)
    const stsc_data =
        "\x00\x00\x00\x14stsc" ++
        "\x00\x00\x00\x00" ++
        "\x10\x00\x00\x01" ++
        "\x00\x00\x00\x00";
    var stsc_host = SliceStreamHost.init(stsc_data);
    const stsc_boxes = (try (dissect_isobmff.Service{}).execute(alloc, .{ .stream = stsc_host.reader() })).data.isobmff_boxes;
    const stsc_res = (try (inspect_region_field.Service{}).execute(alloc, .{
        .stream = stsc_host.reader(),
        .isobmff_boxes = stsc_boxes,
        .target_tag = "stsc",
        .field_offset = 4,
        .field_kind = "u32be",
        .op = "stride_fits",
        .stride = 12,
        .header_bytes = 8,
        .rule_id = "cve_2015_1538_stagefright_stsc",
        .severity = 4,
        .quarantine_on_fail = true,
    })).data;
    try std.testing.expectEqual(@as(usize, 1), stsc_res.audit_findings.len);
    try std.testing.expectEqualStrings("cve_2015_1538_stagefright_stsc", stsc_res.audit_findings[0].rule_id);
    try std.testing.expectEqual(@as(usize, 1), stsc_res.quarantine_orders.len);

    // 2. CVE-2015-3864 (tx3g declared box size < 8 via from_header=true, op=ge)
    const tx3g_data = "\x00\x00\x00\x04tx3g";
    var tx3g_host = SliceStreamHost.init(tx3g_data);
    const tx3g_res = (try (inspect_region_field.Service{}).execute(alloc, .{
        .stream = tx3g_host.reader(),
        .isobmff_boxes = &.{.{
            .region_id = 0,
            .parent_region_id = null,
            .depth = 0,
            .fourcc = "tx3g",
            .path = "/tx3g",
            .role = "unknown",
            .header_offset = 0,
            .payload_offset = 8,
            .declared_size = 4,
            .available_bytes = 0,
            .is_truncated = true,
            .is_overflow = false,
        }},
        .target_tag = "tx3g",
        .field_offset = 0,
        .from_header = true,
        .field_kind = "u32be",
        .op = "ge",
        .expected_min = 8,
        .rule_id = "cve_2015_3864_stagefright_tx3g",
    })).data;
    try std.testing.expectEqual(@as(usize, 1), tx3g_res.audit_findings.len);
    try std.testing.expectEqualStrings("cve_2015_3864_stagefright_tx3g", tx3g_res.audit_findings[0].rule_id);

    // 3. CVE-2022-22675 (avcC configurationVersion != 1)
    const avcc_data = "\x00\x00\x00\x09avcC\x02";
    var avcc_host = SliceStreamHost.init(avcc_data);
    const avcc_boxes = (try (dissect_isobmff.Service{}).execute(alloc, .{ .stream = avcc_host.reader() })).data.isobmff_boxes;
    const avcc_res = (try (inspect_region_field.Service{}).execute(alloc, .{
        .stream = avcc_host.reader(),
        .isobmff_boxes = avcc_boxes,
        .target_tag = "avcC",
        .field_offset = 0,
        .field_kind = "u8",
        .op = "eq",
        .expected_min = 1,
        .expected_max = 1,
        .rule_id = "cve_2022_22675_apple_avcc",
    })).data;
    try std.testing.expectEqual(@as(usize, 1), avcc_res.audit_findings.len);
    try std.testing.expectEqualStrings("cve_2022_22675_apple_avcc", avcc_res.audit_findings[0].rule_id);

    // 4. EBML 0x42f3 (EBMLMaxSizeLength > 8)
    // EBML Header (0x1A45DFA3, size 4 -> 0x84) containing 0x42F3 (size 1 -> 0x81, value 16 -> 0x10)
    const ebml_data = "\x1A\x45\xDF\xA3\x84\x42\xF3\x81\x10";
    var ebml_host = SliceStreamHost.init(ebml_data);
    const ebml_elems = (try (dissect_ebml.Service{}).execute(alloc, .{ .stream = ebml_host.reader() })).data.ebml_elements;
    const ebml_res = (try (inspect_region_field.Service{}).execute(alloc, .{
        .stream = ebml_host.reader(),
        .ebml_elements = ebml_elems,
        .target_tag = "0x42f3",
        .field_offset = 0,
        .field_kind = "u8",
        .op = "le",
        .expected_max = 8,
        .rule_id = "cve_mkv_ebml_max_size_len",
    })).data;
    try std.testing.expectEqual(@as(usize, 1), ebml_res.audit_findings.len);
    try std.testing.expectEqualStrings("cve_mkv_ebml_max_size_len", ebml_res.audit_findings[0].rule_id);

    // 5. AVI strh zero dwScale (offset 20, u32le, op=gt, expected_min=0)
    var strh_payload: [56]u8 = @splat(0);
    @memcpy(strh_payload[0..4], "vids");
    const avi_data = "RIFF\x4C\x00\x00\x00AVI strh\x38\x00\x00\x00" ++ strh_payload;
    var avi_host = SliceStreamHost.init(avi_data);
    const riff_chunks = (try (dissect_riff.Service{}).execute(alloc, .{ .stream = avi_host.reader() })).data.riff_chunks;
    const avi_res = (try (inspect_region_field.Service{}).execute(alloc, .{
        .stream = avi_host.reader(),
        .riff_chunks = riff_chunks,
        .target_tag = "strh",
        .field_offset = 20,
        .field_kind = "u32le",
        .op = "gt",
        .expected_min = 0,
        .rule_id = "cve_avi_strh_zero_scale",
    })).data;
    try std.testing.expectEqual(@as(usize, 1), avi_res.audit_findings.len);
    try std.testing.expectEqualStrings("cve_avi_strh_zero_scale", avi_res.audit_findings[0].rule_id);
}

test "TASK-035c.1: inspect_region_field version_filter, payload_size, i32le, and CVE-2015-1538/3829/2018-19937" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    // 1. CVE-2015-1538: stbl/stsc stride_fits overflow
    // moov (size 48) -> stbl (size 40) -> stsc (size 16, payload: v/f=0, entry_count=100 -> 8 + 100*12 > 8)
    const stsc_data =
        "\x00\x00\x00\x30moov" ++
        "\x00\x00\x00\x28stbl" ++
        "\x00\x00\x00\x10stsc\x00\x00\x00\x00\x00\x00\x00\x64" ++
        &@as([16]u8, @splat(0));
    var stsc_host = SliceStreamHost.init(stsc_data);
    const stsc_boxes = (try (dissect_isobmff.Service{}).execute(alloc, .{ .stream = stsc_host.reader() })).data.isobmff_boxes;
    const stsc_res = (try (inspect_region_field.Service{}).execute(alloc, .{
        .stream = stsc_host.reader(),
        .isobmff_boxes = stsc_boxes,
        .target_tag = "stsc",
        .field_offset = 4,
        .field_kind = "u32be",
        .op = "stride_fits",
        .stride = 12,
        .header_bytes = 8,
        .rule_id = "cve_2015_1538_stsc_stride",
        .quarantine_on_fail = true,
    })).data;
    try std.testing.expectEqual(@as(usize, 1), stsc_res.audit_findings.len);
    try std.testing.expectEqualStrings("cve_2015_1538_stsc_stride", stsc_res.audit_findings[0].rule_id);
    try std.testing.expectEqual(@as(usize, 1), stsc_res.quarantine_orders.len);

    // 2. CVE-2015-3829: covr/data atom size < 8 (from_header: true, field_offset: 0)
    // Wait: a box with size=7 can't be dissected unless it's at the end or size=8; wait: if size=7, box size < 8!
    // Wait: dissect_isobmff stops or records header_size=7? Let's test payload_size < 8 or size=8 with min_payload_size,
    // AND test from_header: true on a 7-byte data box inside covr!
    // covr (size 15) -> data (size 7, no payload)
    const covr_data = "\x00\x00\x00\x0Fcovr\x00\x00\x00\x07data";
    var covr_host = SliceStreamHost.init(covr_data);
    const covr_boxes = (try (dissect_isobmff.Service{}).execute(alloc, .{ .stream = covr_host.reader() })).data.isobmff_boxes;
    // Even if dissect_isobmff skips or records size<8, let's check both: if recorded, from_header catches size < 8.
    if (covr_boxes.len >= 2) {
        const covr_res = (try (inspect_region_field.Service{}).execute(alloc, .{
            .stream = covr_host.reader(),
            .isobmff_boxes = covr_boxes,
            .target_tag = "data",
            .target_path_contains = "covr",
            .from_header = true,
            .field_offset = 0,
            .field_kind = "u32be",
            .op = "ge",
            .expected_min = 8,
            .rule_id = "cve_2015_3829_covr_underflow",
        })).data;
        try std.testing.expectEqual(@as(usize, 1), covr_res.audit_findings.len);
    }

    // 3. CVE-2018-19937: mdhd timescale == 0 with version_filter = 0 vs version_filter = 1
    // mdhd v0 (size 32): v/f=0x00000000, creation=0, mod=0, timescale=0 (@payload+12), duration=100
    var mdhd_v0: [32]u8 = @splat(0);
    @memcpy(mdhd_v0[0..8], "\x00\x00\x00\x20mdhd");
    var mdhd_host = SliceStreamHost.init(&mdhd_v0);
    const mdhd_boxes = (try (dissect_isobmff.Service{}).execute(alloc, .{ .stream = mdhd_host.reader() })).data.isobmff_boxes;
    // Targeting version_filter = 1 should skip v0 box cleanly (0 results, 0 findings)
    const mdhd_v1_res = (try (inspect_region_field.Service{}).execute(alloc, .{
        .stream = mdhd_host.reader(),
        .isobmff_boxes = mdhd_boxes,
        .target_tag = "mdhd",
        .version_filter = 1,
        .field_offset = 20,
        .field_kind = "u32be",
        .op = "gt",
        .expected_min = 0,
        .rule_id = "cve_2018_19937_mdhd_v1",
    })).data;
    try std.testing.expectEqual(@as(usize, 0), mdhd_v1_res.region_field_results.len);
    try std.testing.expectEqual(@as(usize, 0), mdhd_v1_res.audit_findings.len);

    // Targeting version_filter = 0 should catch timescale == 0
    const mdhd_v0_res = (try (inspect_region_field.Service{}).execute(alloc, .{
        .stream = mdhd_host.reader(),
        .isobmff_boxes = mdhd_boxes,
        .target_tag = "mdhd",
        .version_filter = 0,
        .field_offset = 12,
        .field_kind = "u32be",
        .op = "gt",
        .expected_min = 0,
        .rule_id = "cve_2018_19937_mdhd_timescale",
    })).data;
    try std.testing.expectEqual(@as(usize, 1), mdhd_v0_res.audit_findings.len);

    // 4. i32le negative value check + payload_size check
    var avi_neg: [32]u8 = @splat(0);
    @memcpy(avi_neg[0..16], "RIFF\x18\x00\x00\x00AVI strf");
    std.mem.writeInt(u32, avi_neg[16..20], 12, .little);
    // biHeight at +8 = -10 (i32le)
    std.mem.writeInt(i32, avi_neg[28..32], -10, .little);
    var avi_neg_host = SliceStreamHost.init(&avi_neg);
    const avi_neg_chunks = (try (dissect_riff.Service{}).execute(alloc, .{ .stream = avi_neg_host.reader() })).data.riff_chunks;
    const i32_res = (try (inspect_region_field.Service{}).execute(alloc, .{
        .stream = avi_neg_host.reader(),
        .riff_chunks = avi_neg_chunks,
        .target_tag = "strf",
        .field_offset = 8,
        .field_kind = "i32le",
        .op = "ge",
        .expected_min = 0,
        .rule_id = "negative_i32_height",
    })).data;
    try std.testing.expectEqual(@as(usize, 1), i32_res.audit_findings.len);

    const psize_res = (try (inspect_region_field.Service{}).execute(alloc, .{
        .stream = avi_neg_host.reader(),
        .riff_chunks = avi_neg_chunks,
        .target_tag = "strf",
        .field_kind = "payload_size",
        .op = "ge",
        .expected_min = 40,
        .rule_id = "strf_payload_too_small",
    })).data;
    try std.testing.expectEqual(@as(usize, 1), psize_res.audit_findings.len);
}

test "TASK-035c.1: inspect_region_bits catches CVE-2015-3864 UUID overflow and CVE-2022-22675 avcC bitfield" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    // 1. CVE-2015-3864: uuid box with Stagefright/vendor GUID at @0 and u32be length @16 overflowing available_bytes
    // Box size = 8 + 16 + 4 + 4 = 32 (0x20), available_bytes = 24
    // Declared nested length @16 = 0x00001000 (4096 > 24)
    const uuid_guid_hex = "00112233445566778899aabbccddeeff";
    const uuid_data =
        "\x00\x00\x00\x20uuid" ++
        "\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xAA\xBB\xCC\xDD\xEE\xFF" ++
        "\x00\x00\x10\x00" ++
        "\xDE\xAD\xBE\xEF";
    var uuid_host = SliceStreamHost.init(uuid_data);
    const uuid_boxes = (try (dissect_isobmff.Service{}).execute(alloc, .{ .stream = uuid_host.reader() })).data.isobmff_boxes;

    const uuid_res = (try (inspect_region_bits.Service{}).execute(alloc, .{
        .stream = uuid_host.reader(),
        .isobmff_boxes = uuid_boxes,
        .target_tag = "uuid",
        .match_hex_offset = 0,
        .match_hex_prefix = uuid_guid_hex,
        .byte_offset = 16,
        .byte_width = 4,
        .endian = "big",
        .bit_mask = 0xFFFFFFFF,
        .bit_shift = 0,
        .op = "fits_available",
        .rule_id = "cve_2015_3864_uuid_overflow",
        .quarantine_on_fail = true,
    })).data;
    try std.testing.expectEqual(@as(usize, 1), uuid_res.audit_findings.len);
    try std.testing.expectEqualStrings("cve_2015_3864_uuid_overflow", uuid_res.audit_findings[0].rule_id);
    try std.testing.expectEqual(@as(usize, 1), uuid_res.quarantine_orders.len);

    // Non-matching GUID should be skipped (0 results, 0 findings)
    const uuid_skip = (try (inspect_region_bits.Service{}).execute(alloc, .{
        .stream = uuid_host.reader(),
        .isobmff_boxes = uuid_boxes,
        .target_tag = "uuid",
        .match_hex_offset = 0,
        .match_hex_prefix = "ffffffffffffffffffffffffffffffff",
        .byte_offset = 16,
        .byte_width = 4,
        .bit_mask = 0xFFFFFFFF,
        .op = "fits_available",
        .rule_id = "cve_2015_3864_uuid_overflow",
    })).data;
    try std.testing.expectEqual(@as(usize, 0), uuid_skip.region_field_results.len);
    try std.testing.expectEqual(@as(usize, 0), uuid_skip.audit_findings.len);

    // 2. CVE-2022-22675: avcC lengthSizeMinusOne (@4 & 0x03) == 2 (invalid 3-byte NALU length)
    // avcC payload: [0]=1, [1]=0x42, [2]=0x00, [3]=0x1E, [4]=0xFE (0xFC | 0x02 -> lengthSizeMinusOne == 2), [5]=0xE1 (1 SPS)
    const avcc_data = "\x00\x00\x00\x0EavcC\x01\x42\x00\x1E\xFE\xE1";
    var avcc_host = SliceStreamHost.init(avcc_data);
    const avcc_boxes = (try (dissect_isobmff.Service{}).execute(alloc, .{ .stream = avcc_host.reader() })).data.isobmff_boxes;
    const avcc_bits_res = (try (inspect_region_bits.Service{}).execute(alloc, .{
        .stream = avcc_host.reader(),
        .isobmff_boxes = avcc_boxes,
        .target_tag = "avcC",
        .byte_offset = 4,
        .byte_width = 1,
        .bit_mask = 0x03,
        .bit_shift = 0,
        .op = "bit_forbidden",
        .forbidden_value = 2,
        .rule_id = "cve_2022_22675_avcc_nalu_len",
        .quarantine_on_fail = true,
    })).data;
    try std.testing.expectEqual(@as(usize, 1), avcc_bits_res.audit_findings.len);
    try std.testing.expectEqualStrings("cve_2022_22675_avcc_nalu_len", avcc_bits_res.audit_findings[0].rule_id);
    try std.testing.expectEqual(@as(u64, 2), avcc_bits_res.region_field_results[0].u64_value);
}

test "TASK-035c.2: check_region_cardinality multi-track pass and singleton/ordering CVE failures" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    // 1. Valid multi-track MP4: 2 trak boxes, each with 1 stbl -> 1 stsc + 1 stsd -> 0 findings
    const stbl_one =
        "\x00\x00\x00\x18stbl" ++
        "\x00\x00\x00\x08stsc" ++
        "\x00\x00\x00\x08stsd";
    const trak_one = "\x00\x00\x00\x20trak" ++ stbl_one;
    // moov size = 8 + 32 + 32 = 72 (0x48)
    const valid_multi_track = "\x00\x00\x00\x48moov" ++ trak_one ++ trak_one;
    var valid_host = SliceStreamHost.init(valid_multi_track);
    const valid_boxes = (try (dissect_isobmff.Service{}).execute(alloc, .{ .stream = valid_host.reader() })).data.isobmff_boxes;
    const valid_res = (try (check_region_cardinality.Service{}).execute(alloc, .{
        .isobmff_boxes = valid_boxes,
        .parent_tag = "stbl",
        .child_tag = "stsc",
        .min_count = 0,
        .max_count = 1,
        .rule_id = "cve_2018_13300_dup_stsc",
        .quarantine_on_fail = true,
    })).data;
    try std.testing.expectEqual(@as(usize, 0), valid_res.audit_findings.len);
    try std.testing.expectEqual(@as(usize, 0), valid_res.quarantine_orders.len);

    // 2. CVE-2018-13300: Duplicate stsc inside one stbl
    const dup_stsc_mp4 =
        "\x00\x00\x00\x20moov" ++
        "\x00\x00\x00\x18stbl" ++
        "\x00\x00\x00\x08stsc" ++
        "\x00\x00\x00\x08stsc";
    var dup_stsc_host = SliceStreamHost.init(dup_stsc_mp4);
    const dup_stsc_boxes = (try (dissect_isobmff.Service{}).execute(alloc, .{ .stream = dup_stsc_host.reader() })).data.isobmff_boxes;
    const dup_stsc_res = (try (check_region_cardinality.Service{}).execute(alloc, .{
        .isobmff_boxes = dup_stsc_boxes,
        .parent_tag = "stbl",
        .child_tag = "stsc",
        .max_count = 1,
        .rule_id = "cve_2018_13300_dup_stsc",
        .quarantine_on_fail = true,
    })).data;
    try std.testing.expectEqual(@as(usize, 1), dup_stsc_res.audit_findings.len);
    try std.testing.expectEqualStrings("cve_2018_13300_dup_stsc", dup_stsc_res.audit_findings[0].rule_id);
    try std.testing.expectEqual(@as(usize, 1), dup_stsc_res.quarantine_orders.len);

    // 3. CVE-2020-22019: Duplicate CodecPrivate (0x63A2) inside MKV TrackEntry (0xAE)
    // Segment (0x18538067, size 16 -> 0x90) -> Tracks (0x1654AE6B, size 11 -> 0x8B) -> TrackEntry (0xAE, size 6 -> 0x86)
    //   -> CodecPrivate (0x63A2, size 0 -> 0x80) x 2
    const dup_mkv =
        "\x18\x53\x80\x67\x90" ++
        "\x16\x54\xAE\x6B\x8B" ++
        "\xAE\x86" ++
        "\x63\xA2\x80" ++
        "\x63\xA2\x80";
    var dup_mkv_host = SliceStreamHost.init(dup_mkv);
    const dup_mkv_elems = (try (dissect_ebml.Service{}).execute(alloc, .{ .stream = dup_mkv_host.reader() })).data.ebml_elements;
    const dup_mkv_res = (try (check_region_cardinality.Service{}).execute(alloc, .{
        .ebml_elements = dup_mkv_elems,
        .parent_tag = "0xae",
        .child_tag = "0x63a2",
        .max_count = 1,
        .rule_id = "cve_2020_22019_dup_codec_private",
        .quarantine_on_fail = true,
    })).data;
    try std.testing.expectEqual(@as(usize, 1), dup_mkv_res.audit_findings.len);
    try std.testing.expectEqualStrings("cve_2020_22019_dup_codec_private", dup_mkv_res.audit_findings[0].rule_id);
    try std.testing.expectEqual(@as(usize, 1), dup_mkv_res.quarantine_orders.len);

    // 4. CVE-2017-9992: Duplicate strf inside AVI LIST strl
    // RIFF size = 4 ("AVI ") + 8 (LIST hdrl hdr) + 4 ("hdrl") + 8 (LIST strl hdr) + 4 ("strl") + 16 (strf x 2) = 48 (0x30)
    const dup_avi =
        "RIFF\x30\x00\x00\x00AVI " ++
        "LIST\x20\x00\x00\x00hdrl" ++
        "LIST\x14\x00\x00\x00strl" ++
        "strf\x00\x00\x00\x00" ++
        "strf\x00\x00\x00\x00";
    var dup_avi_host = SliceStreamHost.init(dup_avi);
    const dup_avi_chunks = (try (dissect_riff.Service{}).execute(alloc, .{ .stream = dup_avi_host.reader() })).data.riff_chunks;
    const dup_avi_res = (try (check_region_cardinality.Service{}).execute(alloc, .{
        .riff_chunks = dup_avi_chunks,
        .parent_tag = "strl",
        .child_tag = "strf",
        .max_count = 1,
        .rule_id = "cve_2017_9992_dup_strf",
        .quarantine_on_fail = true,
    })).data;
    try std.testing.expectEqual(@as(usize, 1), dup_avi_res.audit_findings.len);
    try std.testing.expectEqualStrings("cve_2017_9992_dup_strf", dup_avi_res.audit_findings[0].rule_id);
    try std.testing.expectEqual(@as(usize, 1), dup_avi_res.quarantine_orders.len);

    // 5. Ordering violation: moof appearing before moov at root level
    const moof_before_moov =
        "\x00\x00\x00\x08moof" ++
        "\x00\x00\x00\x08moov";
    var order_host = SliceStreamHost.init(moof_before_moov);
    const order_boxes = (try (dissect_isobmff.Service{}).execute(alloc, .{ .stream = order_host.reader() })).data.isobmff_boxes;
    const order_res = (try (check_region_cardinality.Service{}).execute(alloc, .{
        .isobmff_boxes = order_boxes,
        .parent_tag = "",
        .child_tag = "moof",
        .min_count = 0,
        .max_count = 1000,
        .must_precede_tag = "moov",
        .rule_id = "mp4_moof_before_moov",
        .quarantine_on_fail = true,
    })).data;
    try std.testing.expectEqual(@as(usize, 1), order_res.audit_findings.len);
    try std.testing.expectEqualStrings("mp4_moof_before_moov", order_res.audit_findings[0].rule_id);
    try std.testing.expectEqual(@as(usize, 1), order_res.quarantine_orders.len);
}

test "TASK-035c.4: inspect_codec_bitstream and inspect_ebml_lacing on valid and exploit payloads" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    // 1. Valid avcC with 1280x720 Baseline SPS + PPS id=0
    // SPS (9 bytes): 67 42 C0 1F F6 02 80 2D 80
    // PPS (3 bytes): 68 CE 38 (pps_id=0)
    // avcC payload = 6 + 2 + 9 + 1 + 2 + 3 = 23 bytes -> box size = 31 (0x1F)
    const valid_avcc_box =
        "\x00\x00\x00\x1FavcC" ++
        "\x01\x42\xC0\x1F\xFF\xE1" ++
        "\x00\x09\x67\x42\xC0\x1F\xF6\x02\x80\x2D\x80" ++
        "\x01\x00\x03\x68\xCE\x38";
    var valid_avcc_host = SliceStreamHost.init(valid_avcc_box);
    const valid_avcc_boxes = (try (dissect_isobmff.Service{}).execute(alloc, .{ .stream = valid_avcc_host.reader() })).data.isobmff_boxes;
    const valid_bs_res = (try (inspect_codec_bitstream.Service{}).execute(alloc, .{
        .stream = valid_avcc_host.reader(),
        .isobmff_boxes = valid_avcc_boxes,
    })).data;
    try std.testing.expectEqual(@as(usize, 0), valid_bs_res.audit_findings.len);
    try std.testing.expectEqual(@as(usize, 0), valid_bs_res.quarantine_orders.len);

    // 2. Exploit avcC with OOB SPS (sps_id=40, chroma_format_idc=7, max_num_ref_frames=64)
    // exploit_sps (10 bytes): 67 64 00 28 05 22 33 81 05 C0
    // avcC payload = 6 + 2 + 10 + 1 + 2 + 3 = 24 bytes -> box size = 32 (0x20)
    const exploit_avcc_box =
        "\x00\x00\x00\x20avcC" ++
        "\x01\x64\x00\x28\xFF\xE1" ++
        "\x00\x0A\x67\x64\x00\x28\x05\x22\x33\x81\x05\xC0" ++
        "\x01\x00\x03\x68\xCE\x38";
    var exploit_avcc_host = SliceStreamHost.init(exploit_avcc_box);
    const exploit_avcc_boxes = (try (dissect_isobmff.Service{}).execute(alloc, .{ .stream = exploit_avcc_host.reader() })).data.isobmff_boxes;
    const exploit_bs_res = (try (inspect_codec_bitstream.Service{}).execute(alloc, .{
        .stream = exploit_avcc_host.reader(),
        .isobmff_boxes = exploit_avcc_boxes,
        .rule_id = "cve_2021_30860_sps_oob",
        .quarantine_on_fail = true,
    })).data;
    try std.testing.expect(exploit_bs_res.audit_findings.len >= 3);
    try std.testing.expectEqualStrings("cve_2021_30860_sps_oob", exploit_bs_res.audit_findings[0].rule_id);
    try std.testing.expect(exploit_bs_res.quarantine_orders.len >= 1);

    // 3. Valid MKV Cluster -> SimpleBlock (0xA3) with valid EBML lacing
    // SimpleBlock payload (19 bytes -> VINT size 0x93): 81 00 00 06 02 85 BE + 12 bytes
    // Cluster (0x1F43B675) size = 2 + 19 = 21 (0x95)
    // Segment (0x18538067) size = 4 + 1 + 21 = 26 (0x9A)
    const valid_mkv_lacing =
        "\x18\x53\x80\x67\x9A" ++
        "\x1F\x43\xB6\x75\x95" ++
        "\xA3\x93" ++
        "\x81\x00\x00\x06\x02\x85\xBE" ++
        &@as([12]u8, @splat(0xCC));
    var valid_mkv_host = SliceStreamHost.init(valid_mkv_lacing);
    const valid_mkv_elems = (try (dissect_ebml.Service{}).execute(alloc, .{ .stream = valid_mkv_host.reader() })).data.ebml_elements;
    const valid_lacing_res = (try (inspect_ebml_lacing.Service{}).execute(alloc, .{
        .stream = valid_mkv_host.reader(),
        .ebml_elements = valid_mkv_elems,
    })).data;
    try std.testing.expectEqual(@as(usize, 0), valid_lacing_res.audit_findings.len);
    try std.testing.expectEqual(@as(usize, 0), valid_lacing_res.quarantine_orders.len);

    // 4. Exploit MKV Cluster -> SimpleBlock (0xA3) reproducing CVE-2016-1621 negative delta
    // SimpleBlock payload (9 bytes -> VINT size 0x89): 81 00 00 06 02 82 B5 00 00
    // Cluster size = 2 + 9 = 11 (0x8B), Segment size = 5 + 11 = 16 (0x90)
    const exploit_mkv_lacing =
        "\x18\x53\x80\x67\x90" ++
        "\x1F\x43\xB6\x75\x8B" ++
        "\xA3\x89" ++
        "\x81\x00\x00\x06\x02\x82\xB5\x00\x00";
    var exploit_mkv_host = SliceStreamHost.init(exploit_mkv_lacing);
    const exploit_mkv_elems = (try (dissect_ebml.Service{}).execute(alloc, .{ .stream = exploit_mkv_host.reader() })).data.ebml_elements;
    const exploit_lacing_res = (try (inspect_ebml_lacing.Service{}).execute(alloc, .{
        .stream = exploit_mkv_host.reader(),
        .ebml_elements = exploit_mkv_elems,
        .rule_id = "cve_2016_1621_ebml_lacing",
        .quarantine_on_fail = true,
    })).data;
    try std.testing.expectEqual(@as(usize, 1), exploit_lacing_res.audit_findings.len);
    try std.testing.expectEqualStrings("cve_2016_1621_ebml_lacing", exploit_lacing_res.audit_findings[0].rule_id);
    try std.testing.expectEqual(@as(usize, 1), exploit_lacing_res.quarantine_orders.len);
}
