const std = @import("std");
const Allocator = std.mem.Allocator;
const abi = @import("flowdata_abi");
const ebml = @import("ebml");
const common = @import("common.zig");

pub const Inputs = struct {
    stream: abi.BoundedStreamReader,
};

pub const MkvStructuresSummaryRow = struct {
    has_tracks: bool,
    track_count: u64,
    attachment_count: u64,
    cluster_count: u64,
    sample_run_count: u64,
    segment_payload_start: u64,
    segment_end: u64,
    header_ebml_max_size_length: u64,
    lacing_anomaly_count: u64,
    mkv_valid: bool,
};

pub const MkvTrackRow = struct {
    track_number: u64,
    track_type: []const u8,
    codec_id: []const u8,
    pixel_width: u64,
    pixel_height: u64,
    codec_private_size: u64,
};

pub const MkvCueRow = struct {
    cue_time: u64,
    track_number: u64,
    cluster_position: u64,
    in_segment_bounds: bool,
};

pub const MkvLacingAnomalyRow = struct {
    offset: u64,
    lacing_kind: u8,
    frame_count: u64,
    payload_size: u64,
};

pub const OutputsData = struct {
    mkv_structures_summary: MkvStructuresSummaryRow,
    mkv_tracks: []const MkvTrackRow,
    mkv_cues: []const MkvCueRow,
    mkv_lacing_anomalies: []const MkvLacingAnomalyRow,
};

pub const Outputs = abi.Channels(OutputsData);

/// Stage 1a pure atomic dissector for Matroska structures (zero policy findings).
pub const Service = struct {
    pub fn execute(_: *const Service, alloc: Allocator, inputs: Inputs) !Outputs {
        const source = common.streamToSource(ebml.ByteSource, &inputs.stream);
        var parsed = try ebml.ebml.SafeEbmlParser.init(alloc, .{}).parse(source);
        defer parsed.deinit();

        var dissected = try ebml.mkv.MkvDissector.init(alloc).dissect(source, parsed.elements);
        defer dissected.deinit();

        var tracks: std.ArrayList(MkvTrackRow) = .empty;
        errdefer tracks.deinit(alloc);
        var cues: std.ArrayList(MkvCueRow) = .empty;
        errdefer cues.deinit(alloc);
        var lacings: std.ArrayList(MkvLacingAnomalyRow) = .empty;
        errdefer lacings.deinit(alloc);

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

        for (dissected.cues) |c| {
            try cues.append(alloc, .{
                .cue_time = c.cue_time,
                .track_number = c.track_number,
                .cluster_position = c.cluster_position,
                .in_segment_bounds = c.in_segment_bounds,
            });
        }

        for (dissected.lacing_anomalies) |la| {
            try lacings.append(alloc, .{
                .offset = la.offset,
                .lacing_kind = la.lacing_kind,
                .frame_count = la.frame_count,
                .payload_size = la.payload_size,
            });
        }

        return .{ .data = .{
            .mkv_structures_summary = .{
                .has_tracks = dissected.has_tracks_element,
                .track_count = dissected.tracks.len,
                .attachment_count = dissected.attachments.len,
                .cluster_count = dissected.cluster_count,
                .sample_run_count = dissected.sample_runs.len,
                .segment_payload_start = dissected.segment_payload_start,
                .segment_end = dissected.segment_end,
                .header_ebml_max_size_length = dissected.header_ebml_max_size_length,
                .lacing_anomaly_count = dissected.lacing_anomalies.len,
                .mkv_valid = dissected.has_tracks_element and dissected.lacing_anomalies.len == 0,
            },
            .mkv_tracks = try tracks.toOwnedSlice(alloc),
            .mkv_cues = try cues.toOwnedSlice(alloc),
            .mkv_lacing_anomalies = try lacings.toOwnedSlice(alloc),
        } };
    }
};
