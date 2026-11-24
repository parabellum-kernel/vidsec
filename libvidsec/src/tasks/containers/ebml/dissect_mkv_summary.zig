const std = @import("std");
const Allocator = std.mem.Allocator;
const abi = @import("parabellum_sdk").task;
const dissect_ebml = @import("dissect_ebml.zig");
const mkv_common = @import("mkv_common.zig");

pub const Inputs = struct {
    stream: abi.BoundedStreamReader,
    ebml_elements: []const dissect_ebml.EbmlElementRow = &.{},
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

pub const OutputsData = struct {
    mkv_structures_summary: MkvStructuresSummaryRow,
};

pub const Outputs = abi.Channels(OutputsData);

/// Stage 1a pure atomic dissector for Matroska structure summary (zero policy findings).
pub const Service = struct {
    pub fn execute(_: *const Service, alloc: Allocator, inputs: Inputs) !Outputs {
        var dissected = try mkv_common.dissectMkv(alloc, &inputs.stream, inputs.ebml_elements, .{
            .parse_info = false,
            .parse_tracks = true,
            .parse_attachments = true,
            .parse_cues = false,
            .parse_cluster_blocks = true,
        });
        defer dissected.deinit();

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
        } };
    }
};
