const std = @import("std");
const Allocator = std.mem.Allocator;
const isobmff = @import("isobmff");
const media_ir = @import("media_ir");
const common = @import("../common.zig");

pub const Inputs = common.ContainerInputs;
pub const Outputs = common.ContainerOutputs;

/// Stage 1c Pure Universal IR Lowering for ISOBMFF / MP4 (zero policy findings).
pub const Service = struct {
    pub fn execute(_: *const Service, alloc: Allocator, inputs: Inputs) !Outputs {
        const source = common.streamToSource(isobmff.ByteSource, &inputs.stream);
        var parsed = try isobmff.box.SafeBoxParser.init(alloc).parse(source);
        defer parsed.deinit();

        var dissected = try isobmff.mp4.Mp4Dissector.init(alloc).dissect(source, parsed.boxes);
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

        for (parsed.boxes) |b| {
            const role: media_ir.RegionRole = switch (b.role) {
                .header => .header,
                .metadata => .metadata,
                .media_data => .media_data,
                .index => .index,
                .padding => .padding,
                .unknown => .unknown,
            };
            try regions.append(alloc, .{
                .region_id = @intCast(b.id),
                .parent_region_id = if (b.parent_id) |pid| @intCast(pid) else null,
                .tag_name = try alloc.dupe(u8, &b.fourcc.bytes),
                .role = role.asText(),
                .header_offset = b.header_offset,
                .payload_offset = b.payload_offset,
                .effective_end_offset = b.endOffset(),
                .is_truncated_or_overflow = b.containment.is_truncated or b.containment.is_overflow,
            });
        }

        for (dissected.sample_runs, 1..) |sr, idx| {
            try sample_runs.append(alloc, .{
                .run_id = @intCast(idx),
                .track_id = @intCast(sr.track_id),
                .start_offset = sr.start_offset,
                .byte_length = sr.end_offset -| sr.start_offset,
                .end_offset = sr.end_offset,
                .sample_count = sr.sample_count,
            });
        }

        for (dissected.tracks, 1..) |t, idx| {
            const h = &t.handler_type.bytes;
            const kind: []const u8 = if (std.mem.eql(u8, h, "vide"))
                "video"
            else if (std.mem.eql(u8, h, "soun"))
                "audio"
            else if (std.mem.eql(u8, h, "subt") or std.mem.eql(u8, h, "sbtl") or std.mem.eql(u8, h, "text"))
                "subtitle"
            else
                "other";
            try codec_configs.append(alloc, .{
                .config_id = @intCast(idx),
                .track_id = @intCast(t.track_id),
                .track_kind = kind,
                .codec_tag = try alloc.dupe(u8, &t.codec_fourcc.bytes),
                .container_width = t.width,
                .container_height = t.height,
                .bitstream_width = t.width,
                .bitstream_height = t.height,
                .is_mismatch = false,
            });
        }

        for (dissected.attachments, 1..) |att, idx| {
            try attachments.append(alloc, .{
                .attachment_id = @intCast(idx),
                .file_offset = att.file_offset,
                .byte_length = att.payload_size,
                .mime_type = try alloc.dupe(u8, att.declared_mime),
                .file_name = try alloc.dupe(u8, &att.source_fourcc.bytes),
            });
        }

        for (dissected.external_refs, 1..) |er, idx| {
            if (!er.is_self_contained) {
                try external_refs.append(alloc, .{
                    .ref_id = @intCast(idx),
                    .track_id = @intCast(er.track_id),
                    .source_tag = try alloc.dupe(u8, &er.source_fourcc.bytes),
                    .file_offset = er.file_offset,
                    .target_url = try alloc.dupe(u8, er.uri),
                });
            }
        }

        return .{ .data = .{
            .container_metadata = .{
                .file_size = inputs.stream.len(),
                .detected_format = 1,
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
