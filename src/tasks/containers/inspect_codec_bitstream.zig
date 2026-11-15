const std = @import("std");
const Allocator = std.mem.Allocator;
const abi = @import("parabellum_abi");
const isobmff = @import("isobmff");
const media_ir = @import("media_ir");
const common = @import("common.zig");
const orders = @import("../remediation/orders.zig");
const dissect_isobmff = @import("dissect_isobmff.zig");
const dissect_mp4_atoms = @import("dissect_mp4_atoms.zig");
const dissect_ebml = @import("dissect_ebml.zig");
const dissect_mkv_structures = @import("dissect_mkv_structures.zig");
const remediation_encoder = @import("remediation_encoder.zig");

pub const Inputs = struct {
    stream: abi.BoundedStreamReader,
    isobmff_boxes: []const dissect_isobmff.IsobmffBoxRow = &.{},
    ebml_elements: []const dissect_ebml.EbmlElementRow = &.{},
    mp4_tracks: []const dissect_mp4_atoms.Mp4TrackRow = &.{},
    mkv_tracks: []const dissect_mkv_structures.MkvTrackRow = &.{},
    max_sps_id: u32 = 31,
    max_pps_id: u32 = 255,
    max_ref_frames: u32 = 16,
    max_chroma_format_idc: u32 = 3,
    max_bit_depth_minus8: u32 = 6,
    max_log2_max_frame_num_minus4: u32 = 12,
    max_dimension: u32 = 16384,
    rule_id: []const u8 = "codec_bitstream_parameter_oob",
    severity: i64 = 4,
    quarantine_on_fail: bool = true,
    on_fail: []const u8 = "",
};

pub const OutputsData = struct {
    audit_findings: []const media_ir.AuditFindingRow,
    quarantine_orders: []const orders.QuarantineOrder,
    patch_orders: []const orders.PatchFieldOrder,
};

pub const Outputs = abi.Channels(OutputsData);

fn emitFinding(
    alloc: Allocator,
    inputs: Inputs,
    offset: u64,
    byte_len: u64,
    region_tag: []const u8,
    measured: f64,
    msg: []const u8,
    findings: *std.ArrayList(media_ir.AuditFindingRow),
    q_orders: *std.ArrayList(orders.QuarantineOrder),
) !void {
    try findings.append(alloc, .{
        .rule_id = inputs.rule_id,
        .severity = @intCast(inputs.severity),
        .file_offset = @intCast(offset),
        .byte_length = @intCast(byte_len),
        .end_offset = @intCast(offset +| byte_len),
        .region_tag = try alloc.dupe(u8, region_tag),
        .measured_value = measured,
        .message = msg,
    });
    const policy = try remediation_encoder.resolvePolicy(inputs.on_fail, inputs.quarantine_on_fail);
    if (policy != .log_only) {
        try q_orders.append(alloc, .{
            .rule_id = inputs.rule_id,
            .reason = msg,
            .severity = inputs.severity,
        });
    }
}

fn inspectAvcCPayload(
    alloc: Allocator,
    inputs: Inputs,
    source: isobmff.ByteSource,
    payload_offset: u64,
    available_bytes: u64,
    region_tag: []const u8,
    expected_w: ?u64,
    expected_h: ?u64,
    findings: *std.ArrayList(media_ir.AuditFindingRow),
    q_orders: *std.ArrayList(orders.QuarantineOrder),
) !void {
    var buf: [4096]u8 = undefined;
    const to_read: usize = @intCast(@min(available_bytes, buf.len));
    const stream_avail = source.file_size -| payload_offset;
    const actual_len: usize = @intCast(@min(to_read, stream_avail));
    if (actual_len == 0) return;

    try source.readExactAt(buf[0..actual_len], payload_offset);

    var sps_list: [16]isobmff.mp4.nalu_sps.SpsInfo = undefined;
    var pps_ids: [32]u32 = undefined;
    const summary = isobmff.mp4.nalu_sps.parseAvcC(buf[0..actual_len], &sps_list, &pps_ids);

    if (summary.is_truncated_or_invalid) {
        const msg = try std.fmt.allocPrint(
            alloc,
            "Truncated or malformed avcC codec configuration in {s} at offset {d}",
            .{ region_tag, payload_offset },
        );
        try emitFinding(alloc, inputs, payload_offset, actual_len, region_tag, 0, msg, findings, q_orders);
        return;
    }

    for (sps_list[0..summary.parsed_sps_count]) |sps| {
        if (sps.is_truncated_or_invalid) {
            const msg = try std.fmt.allocPrint(
                alloc,
                "Truncated or invalid H.264 SPS NALU in {s} at offset {d}",
                .{ region_tag, payload_offset },
            );
            try emitFinding(alloc, inputs, payload_offset, actual_len, region_tag, 0, msg, findings, q_orders);
            continue;
        }
        if (sps.seq_parameter_set_id > inputs.max_sps_id) {
            const msg = try std.fmt.allocPrint(
                alloc,
                "H.264 SPS seq_parameter_set_id={d} exceeds max {d} in {s}",
                .{ sps.seq_parameter_set_id, inputs.max_sps_id, region_tag },
            );
            try emitFinding(alloc, inputs, payload_offset, actual_len, region_tag, @floatFromInt(sps.seq_parameter_set_id), msg, findings, q_orders);
        }
        if (sps.chroma_format_idc > inputs.max_chroma_format_idc) {
            const msg = try std.fmt.allocPrint(
                alloc,
                "H.264 SPS chroma_format_idc={d} exceeds max {d} in {s}",
                .{ sps.chroma_format_idc, inputs.max_chroma_format_idc, region_tag },
            );
            try emitFinding(alloc, inputs, payload_offset, actual_len, region_tag, @floatFromInt(sps.chroma_format_idc), msg, findings, q_orders);
        }
        if (sps.bit_depth_luma_minus8 > inputs.max_bit_depth_minus8 or sps.bit_depth_chroma_minus8 > inputs.max_bit_depth_minus8) {
            const max_bd = @max(sps.bit_depth_luma_minus8, sps.bit_depth_chroma_minus8);
            const msg = try std.fmt.allocPrint(
                alloc,
                "H.264 SPS bit_depth_minus8={d} exceeds max {d} in {s}",
                .{ max_bd, inputs.max_bit_depth_minus8, region_tag },
            );
            try emitFinding(alloc, inputs, payload_offset, actual_len, region_tag, @floatFromInt(max_bd), msg, findings, q_orders);
        }
        if (sps.log2_max_frame_num_minus4 > inputs.max_log2_max_frame_num_minus4) {
            const msg = try std.fmt.allocPrint(
                alloc,
                "H.264 SPS log2_max_frame_num_minus4={d} exceeds max {d} in {s}",
                .{ sps.log2_max_frame_num_minus4, inputs.max_log2_max_frame_num_minus4, region_tag },
            );
            try emitFinding(alloc, inputs, payload_offset, actual_len, region_tag, @floatFromInt(sps.log2_max_frame_num_minus4), msg, findings, q_orders);
        }
        if (sps.max_num_ref_frames > inputs.max_ref_frames) {
            const msg = try std.fmt.allocPrint(
                alloc,
                "H.264 SPS max_num_ref_frames={d} exceeds max {d} in {s}",
                .{ sps.max_num_ref_frames, inputs.max_ref_frames, region_tag },
            );
            try emitFinding(alloc, inputs, payload_offset, actual_len, region_tag, @floatFromInt(sps.max_num_ref_frames), msg, findings, q_orders);
        }
        if (sps.computed_width == 0 or sps.computed_height == 0 or sps.computed_width > inputs.max_dimension or sps.computed_height > inputs.max_dimension) {
            const msg = try std.fmt.allocPrint(
                alloc,
                "H.264 SPS decoded dimensions {d}x{d} out of bounds (max {d}) in {s}",
                .{ sps.computed_width, sps.computed_height, inputs.max_dimension, region_tag },
            );
            try emitFinding(alloc, inputs, payload_offset, actual_len, region_tag, @floatFromInt(@max(sps.computed_width, sps.computed_height)), msg, findings, q_orders);
        }
        if (expected_w != null and expected_h != null and expected_w.? > 0 and expected_h.? > 0) {
            if (sps.computed_width != expected_w.? or sps.computed_height != expected_h.?) {
                const msg = try std.fmt.allocPrint(
                    alloc,
                    "H.264 SPS dimensions {d}x{d} mismatch container track metadata {d}x{d} in {s}",
                    .{ sps.computed_width, sps.computed_height, expected_w.?, expected_h.?, region_tag },
                );
                try emitFinding(alloc, inputs, payload_offset, actual_len, region_tag, @floatFromInt(sps.computed_width), msg, findings, q_orders);
            }
        }
    }

    for (pps_ids[0..summary.parsed_pps_count]) |pps_id| {
        if (pps_id > inputs.max_pps_id) {
            const msg = try std.fmt.allocPrint(
                alloc,
                "H.264 PPS pic_parameter_set_id={d} exceeds max {d} in {s}",
                .{ pps_id, inputs.max_pps_id, region_tag },
            );
            try emitFinding(alloc, inputs, payload_offset, actual_len, region_tag, @floatFromInt(pps_id), msg, findings, q_orders);
        }
    }
}

/// Declarative Class IV Exp-Golomb / SPS / PPS bitstream validator over `avcC` (MP4) and `CodecPrivate` (MKV).
pub const Service = struct {
    pub fn execute(_: *const Service, alloc: Allocator, inputs: Inputs) !Outputs {
        const source = common.streamToSource(isobmff.ByteSource, &inputs.stream);

        var findings: std.ArrayList(media_ir.AuditFindingRow) = .empty;
        errdefer findings.deinit(alloc);
        var q_orders: std.ArrayList(orders.QuarantineOrder) = .empty;
        errdefer q_orders.deinit(alloc);
        var patch_orders: std.ArrayList(orders.PatchFieldOrder) = .empty;
        errdefer patch_orders.deinit(alloc);

        // 1. Inspect MP4 avcC boxes
        var avc_mp4_idx: usize = 0;
        for (inputs.isobmff_boxes) |b| {
            if (std.ascii.eqlIgnoreCase(b.fourcc, "avcC")) {
                var exp_w: ?u64 = null;
                var exp_h: ?u64 = null;
                while (avc_mp4_idx < inputs.mp4_tracks.len) : (avc_mp4_idx += 1) {
                    if (inputs.mp4_tracks[avc_mp4_idx].has_avcc) {
                        exp_w = inputs.mp4_tracks[avc_mp4_idx].width;
                        exp_h = inputs.mp4_tracks[avc_mp4_idx].height;
                        avc_mp4_idx += 1;
                        break;
                    }
                }
                try inspectAvcCPayload(
                    alloc,
                    inputs,
                    source,
                    b.payload_offset,
                    b.available_bytes,
                    b.fourcc,
                    exp_w,
                    exp_h,
                    &findings,
                    &q_orders,
                );
            }
        }

        // 2. Inspect MKV CodecPrivate (0x63A2) when AVC or standalone
        var has_avc_mkv_track = inputs.mkv_tracks.len == 0;
        var mkv_w: ?u64 = null;
        var mkv_h: ?u64 = null;
        for (inputs.mkv_tracks) |t| {
            if (std.mem.eql(u8, t.codec_id, "V_MPEG4/ISO/AVC")) {
                has_avc_mkv_track = true;
                mkv_w = t.pixel_width;
                mkv_h = t.pixel_height;
                break;
            }
        }

        if (has_avc_mkv_track) {
            for (inputs.ebml_elements) |e| {
                if (std.ascii.eqlIgnoreCase(e.ebml_id_hex, "0x63a2")) {
                    try inspectAvcCPayload(
                        alloc,
                        inputs,
                        source,
                        e.payload_offset,
                        e.available_bytes,
                        e.ebml_id_hex,
                        mkv_w,
                        mkv_h,
                        &findings,
                        &q_orders,
                    );
                }
            }
        }

        return .{ .data = .{
            .audit_findings = try findings.toOwnedSlice(alloc),
            .quarantine_orders = try q_orders.toOwnedSlice(alloc),
            .patch_orders = try patch_orders.toOwnedSlice(alloc),
        } };
    }
};

