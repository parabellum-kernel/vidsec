const std = @import("std");
const Allocator = std.mem.Allocator;
const riff = @import("riff");
const media_ir = @import("media_ir");
const common = @import("../common.zig");

pub const Inputs = common.ContainerInputs;
pub const Outputs = common.ContainerOutputs;

/// Stage 1c Pure Universal IR Lowering for RIFF / AVI (zero policy findings).
pub const Service = struct {
    pub fn execute(_: *const Service, alloc: Allocator, inputs: Inputs) !Outputs {
        const source = common.streamToSource(riff.ByteSource, &inputs.stream);
        var parsed = try riff.riff.SafeRiffParser.init(alloc, .{}).parse(source);
        defer parsed.deinit();

        var regions: std.ArrayList(media_ir.IrRegionRow) = .empty;
        errdefer regions.deinit(alloc);
        var sample_runs: std.ArrayList(media_ir.IrSampleRunRow) = .empty;
        errdefer sample_runs.deinit(alloc);
        var codec_configs: std.ArrayList(media_ir.IrCodecConfigRow) = .empty;
        errdefer codec_configs.deinit(alloc);

        for (parsed.chunks) |c| {
            const role: media_ir.RegionRole = switch (c.role) {
                .header => .header,
                .metadata, .stream_header => .metadata,
                .media_data => .media_data,
                .index => .index,
                .padding => .padding,
                .unknown => .unknown,
            };
            try regions.append(alloc, .{
                .region_id = @intCast(c.id),
                .parent_region_id = if (c.parent_id) |pid| @intCast(pid) else null,
                .tag_name = try alloc.dupe(u8, &c.header.fourcc.bytes),
                .role = role.asText(),
                .header_offset = c.header.offset,
                .payload_offset = c.header.payloadOffset(),
                .effective_end_offset = c.endOffset(),
                .is_truncated_or_overflow = c.containment.is_truncated or c.containment.is_overflow,
            });
        }

        if (parsed.form_type.equals(riff.riff.types.FORM_AVI) or parsed.form_type.equals(riff.riff.types.FORM_AVIX)) {
            var avi_res = try riff.avi.AviDissector.init(alloc).dissect(source, parsed.chunks);
            defer avi_res.deinit();

            for (avi_res.sample_runs, 1..) |sr, idx| {
                try sample_runs.append(alloc, .{
                    .run_id = @intCast(idx),
                    .track_id = @intCast(sr.stream_index),
                    .start_offset = sr.start_offset,
                    .byte_length = sr.byte_length,
                    .end_offset = sr.start_offset +| sr.byte_length,
                    .sample_count = sr.chunk_count,
                });
            }

            for (avi_res.streams, 1..) |st, idx| {
                const kind: []const u8 = if (std.mem.eql(u8, &st.fcc_type, "vids"))
                    "video"
                else if (std.mem.eql(u8, &st.fcc_type, "auds"))
                    "audio"
                else if (std.mem.eql(u8, &st.fcc_type, "txts"))
                    "subtitle"
                else
                    "other";
                const w: i64 = if (st.video) |v| @max(0, v.width) else 0;
                const h: i64 = if (st.video) |v| (if (v.height < 0) -@as(i64, v.height) else @as(i64, v.height)) else 0;
                try codec_configs.append(alloc, .{
                    .config_id = @intCast(idx),
                    .track_id = @intCast(st.stream_index),
                    .track_kind = kind,
                    .codec_tag = try alloc.dupe(u8, &st.fcc_handler),
                    .container_width = w,
                    .container_height = h,
                    .bitstream_width = w,
                    .bitstream_height = h,
                    .is_mismatch = false,
                });
            }
        }

        return .{ .data = .{
            .container_metadata = .{
                .file_size = inputs.stream.len(),
                .detected_format = 3,
                .true_magic = inputs.true_magic_kind,
                .true_magic_name = inputs.identified_format,
                .highest_root_end = parsed.highest_root_end,
            },
            .ir_regions = try regions.toOwnedSlice(alloc),
            .ir_sample_runs = try sample_runs.toOwnedSlice(alloc),
            .ir_codec_configs = try codec_configs.toOwnedSlice(alloc),
            .ir_attachments = &.{},
            .ir_external_refs = &.{},
        } };
    }
};
