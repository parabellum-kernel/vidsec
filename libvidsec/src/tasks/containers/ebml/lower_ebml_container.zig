const std = @import("std");
const Allocator = std.mem.Allocator;
const ebml = @import("ebml");
const media_ir = @import("media_ir");
const common = @import("../common.zig");

pub const Inputs = common.ContainerInputs;
pub const Outputs = common.ContainerOutputs;

/// Stage 1c Pure Universal IR Lowering for EBML / Matroska (zero policy findings).
pub const Service = struct {
    pub fn execute(_: *const Service, alloc: Allocator, inputs: Inputs) !Outputs {
        const source = common.streamToSource(ebml.ByteSource, &inputs.stream);
        var parsed = try ebml.ebml.SafeEbmlParser.init(alloc, .{}).parse(source);
        defer parsed.deinit();

        var dissected = try ebml.mkv.MkvDissector.init(alloc).dissect(source, parsed.elements);
        defer dissected.deinit();

        var regions: std.ArrayList(media_ir.IrRegionRow) = .empty;
        errdefer regions.deinit(alloc);
        var sample_runs: std.ArrayList(media_ir.IrSampleRunRow) = .empty;
        errdefer sample_runs.deinit(alloc);
        var codec_configs: std.ArrayList(media_ir.IrCodecConfigRow) = .empty;
        errdefer codec_configs.deinit(alloc);
        var attachments: std.ArrayList(media_ir.IrAttachmentRow) = .empty;
        errdefer attachments.deinit(alloc);
        var external_refs: std.ArrayList(media_ir.IrExternalRefRow) = .empty;
        errdefer external_refs.deinit(alloc);

        for (parsed.elements) |e| {
            const role: media_ir.RegionRole = switch (e.role) {
                .header => .header,
                .metadata, .track_info => .metadata,
                .media_data => .media_data,
                .cluster_index => .index,
                .padding => .padding,
                .unknown => .unknown,
            };
            try regions.append(alloc, .{
                .region_id = @intCast(e.region_id),
                .parent_region_id = if (e.parent_id) |pid| @intCast(pid) else null,
                .tag_name = try std.fmt.allocPrint(alloc, "0x{x}", .{e.id}),
                .role = role.asText(),
                .header_offset = e.header.offset,
                .payload_offset = e.header.payloadOffset(),
                .effective_end_offset = e.endOffset(),
                .is_truncated_or_overflow = e.containment.is_truncated or e.containment.is_overflow,
            });
        }

        for (dissected.sample_runs, 1..) |sr, idx| {
            try sample_runs.append(alloc, .{
                .run_id = @intCast(idx),
                .track_id = @intCast(sr.track_number),
                .start_offset = sr.start_offset,
                .byte_length = sr.byte_length,
                .end_offset = sr.start_offset +| sr.byte_length,
                .sample_count = sr.block_count,
            });
        }

        for (dissected.tracks, 1..) |t, idx| {
            const kind: []const u8 = switch (t.track_type) {
                .video => "video",
                .audio => "audio",
                .subtitle => "subtitle",
                .complex => "complex",
                else => "other",
            };
            const w: i64 = if (t.video) |v| v.pixel_width else 0;
            const h: i64 = if (t.video) |v| v.pixel_height else 0;
            try codec_configs.append(alloc, .{
                .config_id = @intCast(idx),
                .track_id = @intCast(t.track_number),
                .track_kind = kind,
                .codec_tag = if (t.codec_id.len > 0) try alloc.dupe(u8, t.codec_id) else "unknown",
                .container_width = w,
                .container_height = h,
                .bitstream_width = w,
                .bitstream_height = h,
                .is_mismatch = false,
            });
        }

        for (dissected.attachments, 1..) |att, idx| {
            try attachments.append(alloc, .{
                .attachment_id = @intCast(idx),
                .file_offset = att.data_offset,
                .byte_length = att.data_size,
                .mime_type = if (att.mime_type.len > 0) try alloc.dupe(u8, att.mime_type) else "application/octet-stream",
                .file_name = if (att.file_name.len > 0) try alloc.dupe(u8, att.file_name) else "unnamed",
            });
        }

        for (dissected.external_refs, 1..) |er, idx| {
            try external_refs.append(alloc, .{
                .ref_id = @intCast(idx),
                .track_id = 0,
                .source_tag = try std.fmt.allocPrint(alloc, "0x{x}", .{er.element_id}),
                .file_offset = er.file_offset,
                .target_url = try alloc.dupe(u8, er.filename),
            });
        }

        return .{ .data = .{
            .container_metadata = .{
                .file_size = inputs.stream.len(),
                .detected_format = 2,
                .true_magic = inputs.true_magic_kind,
                .true_magic_name = inputs.identified_format,
                .highest_root_end = parsed.highest_root_end,
            },
            .ir_regions = try regions.toOwnedSlice(alloc),
            .ir_sample_runs = try sample_runs.toOwnedSlice(alloc),
            .ir_codec_configs = try codec_configs.toOwnedSlice(alloc),
            .ir_attachments = try attachments.toOwnedSlice(alloc),
            .ir_external_refs = try external_refs.toOwnedSlice(alloc),
        } };
    }
};
