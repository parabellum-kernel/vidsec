const std = @import("std");
const abi = @import("flowdata_abi");
const vidsec = @import("vidsec");
const media_ir = vidsec.media_ir;

const analyze_topology = vidsec.tasks.analyze_topology;
const check_r02_trailing_overlay = vidsec.tasks.check_r02_trailing_overlay;
const check_r04_sample_bounds = vidsec.tasks.check_r04_sample_bounds;
const check_r05_external_refs = vidsec.tasks.check_r05_external_refs;
const check_r06_embedded_attachments = vidsec.tasks.check_r06_embedded_attachments;
const check_r07_suspicious_padding = vidsec.tasks.check_r07_suspicious_padding;
const check_r08_unreferenced_slack = vidsec.tasks.check_r08_unreferenced_slack;
const check_r09_codec_inconsistencies = vidsec.tasks.check_r09_codec_inconsistencies;
const check_r10_sample_overlaps = vidsec.tasks.check_r10_sample_overlaps;
const check_inconsistencies = vidsec.tasks.check_inconsistencies;
const scan_entropy = vidsec.tasks.scan_entropy;

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

test "analyze_topology emits ir_unreferenced_slack cleanly without TruncateOrder" {
    const regions = [_]media_ir.IrRegionRow{
        .{ .region_id = 0, .tag_name = "ftyp", .role = "header", .header_offset = 0, .payload_offset = 8, .effective_end_offset = 24 },
        .{ .region_id = 1, .tag_name = "mdat", .role = "media_data", .header_offset = 24, .payload_offset = 32, .effective_end_offset = 100 },
    };
    const runs = [_]media_ir.IrSampleRunRow{
        .{ .run_id = 1, .track_id = 1, .start_offset = 32, .byte_length = 40, .end_offset = 72 },
    };

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const out = (try (analyze_topology.Service{}).execute(arena.allocator(), .{
        .file_size = 140,
        .ir_regions = &regions,
        .ir_sample_runs = &runs,
    })).data;

    try std.testing.expectEqual(@as(usize, 2), out.ir_unreferenced_slack.len);
    try std.testing.expectEqual(@as(usize, 0), out.audit_findings.len);
    try std.testing.expect(!@hasField(@TypeOf(out), "truncate_orders"));
}

test "check_inconsistencies flags sample outside media_data and dimension mismatch" {
    const regions = [_]media_ir.IrRegionRow{
        .{ .region_id = 0, .tag_name = "moov", .role = "metadata", .header_offset = 0, .payload_offset = 8, .effective_end_offset = 100 },
        .{ .region_id = 1, .tag_name = "mdat", .role = "media_data", .header_offset = 100, .payload_offset = 108, .effective_end_offset = 200 },
    };
    const configs = [_]media_ir.IrCodecConfigRow{
        .{ .config_id = 1, .track_id = 1, .codec_tag = "avc1", .container_width = 1920, .container_height = 1080, .bitstream_width = 640, .bitstream_height = 480, .is_mismatch = true },
    };
    const runs = [_]media_ir.IrSampleRunRow{
        .{ .run_id = 1, .track_id = 1, .start_offset = 20, .byte_length = 20, .end_offset = 40 },
    };

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const out = (try (check_inconsistencies.Service{}).execute(arena.allocator(), .{
        .file_size = 200,
        .ir_regions = &regions,
        .ir_codec_configs = &configs,
        .ir_sample_runs = &runs,
    })).data;

    try std.testing.expectEqual(@as(usize, 2), out.audit_findings.len);
    try std.testing.expectEqualStrings("dimension_mismatch", out.audit_findings[0].rule_id);
    try std.testing.expectEqualStrings("sample_outside_media_data", out.audit_findings[1].rule_id);
}

test "scan_entropy flags high-entropy slack and emits ZeroOutOrder" {
    var buf: [256]u8 = undefined;
    for (&buf, 0..) |*b, i| {
        b.* = @truncate((i * 73 + 19) ^ (i >> 2));
    }
    var host = SliceStreamHost.init(&buf);
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const slacks = [_]media_ir.IrUnreferencedSlackRow{
        .{ .slack_id = 1, .region_tag = "trailing_overlay", .file_offset = 0, .byte_length = 256 },
    };

    const out = (try (scan_entropy.Service{}).execute(arena.allocator(), .{
        .stream = host.reader(),
        .ir_unreferenced_slack = &slacks,
        .entropy_threshold = 7.0,
    })).data;

    try std.testing.expectEqual(@as(usize, 1), out.audit_findings.len);
    try std.testing.expectEqualStrings("high_entropy_slack_payload", out.audit_findings[0].rule_id);
    try std.testing.expectEqual(@as(usize, 1), out.zero_out_orders.len);
    try std.testing.expectEqual(@as(u64, 0), out.zero_out_orders[0].offset);
    try std.testing.expectEqual(@as(u64, 256), out.zero_out_orders[0].length);
}

test "R02 check_r02_trailing_overlay: 16B zero tolerance, TruncateOrder, and QuarantineOrder on polyglot" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    // 16B zero tail -> tolerated
    const zero_tail: [16]u8 = @splat(0);
    var zero_host = SliceStreamHost.init(&zero_tail);
    const z_out = (try (check_r02_trailing_overlay.Service{}).execute(alloc, .{
        .stream = zero_host.reader(),
        .ir_unreferenced_slack = &.{.{ .slack_id = 1, .region_tag = "trailing_overlay", .file_offset = 0, .byte_length = 16 }},
    })).data;
    try std.testing.expectEqual(@as(usize, 0), z_out.audit_findings.len);
    try std.testing.expectEqual(@as(usize, 0), z_out.truncate_orders.len);

    // 32B junk -> TruncateOrder
    const junk_tail = "JUNK" ++ "JUNK" ++ "JUNK" ++ "JUNK" ++ "JUNK" ++ "JUNK" ++ "JUNK" ++ "JUNK";
    var junk_host = SliceStreamHost.init(junk_tail);
    const j_out = (try (check_r02_trailing_overlay.Service{}).execute(alloc, .{
        .stream = junk_host.reader(),
        .ir_unreferenced_slack = &.{.{ .slack_id = 1, .region_tag = "trailing_overlay", .file_offset = 0, .byte_length = 32 }},
    })).data;
    try std.testing.expectEqual(@as(usize, 1), j_out.truncate_orders.len);
    try std.testing.expectEqual(@as(usize, 0), j_out.quarantine_orders.len);

    // ZIP local header tail -> QuarantineOrder
    const zip_tail = "PK\x03\x04\x14\x00\x00\x00\x08\x00" ++ &@as([22]u8, @splat('A'));
    var zip_host = SliceStreamHost.init(zip_tail);
    const p_out = (try (check_r02_trailing_overlay.Service{}).execute(alloc, .{
        .stream = zip_host.reader(),
        .ir_unreferenced_slack = &.{.{ .slack_id = 1, .region_tag = "trailing_overlay", .file_offset = 0, .byte_length = 32 }},
    })).data;
    try std.testing.expectEqual(@as(usize, 1), p_out.quarantine_orders.len);
    try std.testing.expectEqualStrings("r02_trailing_polyglot_signature", p_out.audit_findings[0].rule_id);
}

test "R04 & R10 check_r04_sample_bounds and check_r10_sample_overlaps" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    const regions = [_]media_ir.IrRegionRow{
        .{ .region_id = 0, .tag_name = "moov", .role = "metadata", .header_offset = 0, .payload_offset = 8, .effective_end_offset = 100 },
        .{ .region_id = 1, .tag_name = "mdat", .role = "media_data", .header_offset = 100, .payload_offset = 108, .effective_end_offset = 200 },
    };
    const runs = [_]media_ir.IrSampleRunRow{
        .{ .run_id = 1, .track_id = 1, .start_offset = 20, .byte_length = 20, .end_offset = 40 },
        .{ .run_id = 2, .track_id = 1, .start_offset = 108, .byte_length = 80, .end_offset = 188 },
        .{ .run_id = 3, .track_id = 1, .start_offset = 150, .byte_length = 80, .end_offset = 230 },
    };

    const r04 = (try (check_r04_sample_bounds.Service{}).execute(alloc, .{
        .file_size = 200,
        .ir_regions = &regions,
        .ir_sample_runs = &runs,
    })).data;
    try std.testing.expect(r04.audit_findings.len >= 2);
    try std.testing.expect(r04.quarantine_orders.len >= 2);

    const r10 = (try (check_r10_sample_overlaps.Service{}).execute(alloc, .{
        .file_size = 250,
        .ir_regions = &regions,
        .ir_sample_runs = &runs,
        .max_amplification_ratio = 1.0,
    })).data;
    var saw_overlap = false;
    var saw_amp = false;
    for (r10.audit_findings) |f| {
        if (std.mem.eql(u8, f.rule_id, "sample_overlap")) saw_overlap = true;
        if (std.mem.eql(u8, f.rule_id, "decompression_amplification")) saw_amp = true;
    }
    try std.testing.expect(saw_overlap and saw_amp);
    try std.testing.expect(r10.quarantine_orders.len >= 1);
}

test "R05 & R06 check_r05_external_refs and check_r06_embedded_attachments" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    const r05 = (try (check_r05_external_refs.Service{}).execute(alloc, .{
        .ir_external_refs = &.{
            .{ .ref_id = 1, .track_id = 1, .source_tag = "url ", .file_offset = 40, .target_url = "file:///etc/passwd" },
            .{ .ref_id = 2, .track_id = 1, .source_tag = "0x3e83bb", .file_offset = 80, .target_url = "\\\\evil.local\\share\\x.mkv" },
        },
    })).data;
    try std.testing.expectEqual(@as(usize, 2), r05.audit_findings.len);
    try std.testing.expectEqualStrings("r05_external_ref_file_uri", r05.audit_findings[0].rule_id);
    try std.testing.expectEqualStrings("r05_external_ref_unc_smb", r05.audit_findings[1].rule_id);
    try std.testing.expectEqual(@as(usize, 2), r05.quarantine_orders.len);

    // Attachment with OTTO font magic & path traversal filename
    const font_bytes = "OTTO\x00\x0C\x00\x00" ++ &@as([24]u8, @splat(0));
    var font_host = SliceStreamHost.init(font_bytes);
    const r06 = (try (check_r06_embedded_attachments.Service{}).execute(alloc, .{
        .stream = font_host.reader(),
        .ir_attachments = &.{.{
            .attachment_id = 1,
            .file_offset = 0,
            .byte_length = font_bytes.len,
            .mime_type = "font/otf",
            .file_name = "../../evil.otf",
        }},
    })).data;
    var saw_trav = false;
    var saw_font = false;
    for (r06.audit_findings) |f| {
        if (std.mem.eql(u8, f.rule_id, "r06_attachment_path_traversal")) saw_trav = true;
        if (std.mem.eql(u8, f.rule_id, "r06_attachment_risky_font")) saw_font = true;
    }
    try std.testing.expect(saw_trav and saw_font);
}

test "R07 & R08 catch zero-diluted goloader in 1MB free box and >=4KB slack" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    // 256 KB zero-filled 'free' payload with "\xff Go buildinf:" at the midpoint
    const big = try alloc.alloc(u8, 256 * 1024);
    @memset(big, 0);
    const sig = "\xff Go buildinf:";
    @memcpy(big[128 * 1024 ..][0..sig.len], sig);

    var host = SliceStreamHost.init(big);
    const r07 = (try (check_r07_suspicious_padding.Service{}).execute(alloc, .{
        .stream = host.reader(),
        .ir_regions = &.{.{
            .region_id = 0,
            .tag_name = "free",
            .role = "padding",
            .header_offset = 0,
            .payload_offset = 0,
            .effective_end_offset = big.len,
        }},
    })).data;
    try std.testing.expectEqual(@as(usize, 1), r07.audit_findings.len);
    try std.testing.expectEqualStrings("r07_padding_embedded_signature", r07.audit_findings[0].rule_id);
    try std.testing.expectEqual(@as(usize, 1), r07.quarantine_orders.len);

    // 4096-byte zeroed interior_media_slack -> ZeroOutOrder via R08
    const zeros_4k: [4096]u8 = @splat(0);
    var z_host = SliceStreamHost.init(&zeros_4k);
    const r08 = (try (check_r08_unreferenced_slack.Service{}).execute(alloc, .{
        .stream = z_host.reader(),
        .ir_unreferenced_slack = &.{.{ .slack_id = 1, .region_tag = "interior_media_slack", .file_offset = 0, .byte_length = 4096 }},
    })).data;
    try std.testing.expectEqual(@as(usize, 1), r08.audit_findings.len);
    try std.testing.expectEqualStrings("r08_large_unreferenced_slack", r08.audit_findings[0].rule_id);
    try std.testing.expectEqual(@as(usize, 1), r08.zero_out_orders.len);
}

test "R09 check_r09_codec_inconsistencies flags dimension mismatch and out-of-range dims" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const r09 = (try (check_r09_codec_inconsistencies.Service{}).execute(arena.allocator(), .{
        .ir_codec_configs = &.{.{
            .config_id = 1,
            .track_id = 1,
            .codec_tag = "avc1",
            .container_width = 32768,
            .container_height = 1080,
            .bitstream_width = 1920,
            .bitstream_height = 1080,
            .is_mismatch = true,
        }},
    })).data;
    try std.testing.expectEqual(@as(usize, 2), r09.audit_findings.len);
    try std.testing.expectEqualStrings("dimension_mismatch", r09.audit_findings[0].rule_id);
    try std.testing.expectEqualStrings("r09_codec_dimension_out_of_range", r09.audit_findings[1].rule_id);
}
