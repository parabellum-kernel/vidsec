const std = @import("std");
const Allocator = std.mem.Allocator;
const abi = @import("parabellum_sdk").task;
const dissect_ebml = @import("dissect_ebml.zig");
const mkv_common = @import("mkv_common.zig");

pub const Inputs = struct {
    stream: abi.BoundedStreamReader,
    ebml_elements: []const dissect_ebml.EbmlElementRow = &.{},
};

pub const MkvTrackRow = struct {
    track_number: u64,
    track_type: []const u8,
    codec_id: []const u8,
    pixel_width: u64,
    pixel_height: u64,
    codec_private_size: u64,
};

pub const OutputsData = struct {
    mkv_tracks: []const MkvTrackRow,
};

pub const Outputs = abi.Channels(OutputsData);

/// Stage 1a pure atomic dissector for Matroska Tracks (zero policy findings).
pub const Service = struct {
    pub fn execute(_: *const Service, alloc: Allocator, inputs: Inputs) !Outputs {
        var dissected = try mkv_common.dissectMkv(alloc, &inputs.stream, inputs.ebml_elements, .{
            .parse_info = false,
            .parse_tracks = true,
            .parse_attachments = false,
            .parse_cues = false,
            .parse_cluster_blocks = false,
        });
        defer dissected.deinit();

        var tracks: std.ArrayList(MkvTrackRow) = .empty;
        errdefer tracks.deinit(alloc);

        for (dissected.tracks) |t| {
            try tracks.append(alloc, .{
                .track_number = t.track_number,
                .track_type = switch (t.track_type) {
                    .video => "video",
                    .audio => "audio",
                    .complex => "complex",
                    .subtitle => "subtitle",
                    else => "unknown",
                },
                .codec_id = if (t.codec_id.len > 0) try alloc.dupe(u8, t.codec_id) else "",
                .pixel_width = if (t.video) |v| v.pixel_width else 0,
                .pixel_height = if (t.video) |v| v.pixel_height else 0,
                .codec_private_size = t.codec_private_size,
            });
        }

        return .{ .data = .{
            .mkv_tracks = try tracks.toOwnedSlice(alloc),
        } };
    }
};
