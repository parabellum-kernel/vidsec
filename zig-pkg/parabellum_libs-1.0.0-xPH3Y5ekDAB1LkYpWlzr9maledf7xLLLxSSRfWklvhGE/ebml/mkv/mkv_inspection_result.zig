const std = @import("std");
const Allocator = std.mem.Allocator;
const MkvInfo = @import("mkv_info.zig").MkvInfo;
const MkvTrackRecord = @import("mkv_track.zig").MkvTrackRecord;

pub const SegmentInfo = MkvInfo;

pub const MkvAttachment = struct {
    file_name: []const u8,
    mime_type: []const u8,
    data_offset: u64,
    data_size: u64,
};

pub const ClusterSpan = struct {
    cluster_index: u32,
    offset: u64,
    size: u64,
    payload_offset: u64,
    payload_size: u64,
};

pub const SampleRun = struct {
    track_number: u32,
    start_offset: u64,
    byte_length: u64,
    block_count: u32,
};

pub const MkvExternalRef = struct {
    element_id: u32,
    file_offset: u64,
    filename: []const u8,
};

pub const CueRecord = struct {
    cue_time: u64 = 0,
    track_number: u64 = 0,
    cluster_position: u64 = 0,
    in_segment_bounds: bool = true,
};

pub const LacingAnomaly = struct {
    offset: u64,
    lacing_kind: u8,
    frame_count: u16,
    payload_size: u64,
};

pub const MkvDissectionResult = struct {
    allocator: Allocator,
    info: SegmentInfo,
    tracks: []const MkvTrackRecord,
    attachments: []const MkvAttachment,
    clusters: []const ClusterSpan,
    sample_runs: []const SampleRun,
    external_refs: []const MkvExternalRef = &.{},
    cues: []const CueRecord = &.{},
    lacing_anomalies: []const LacingAnomaly = &.{},
    segment_payload_start: u64 = 0,
    segment_end: u64 = 0,
    header_ebml_max_size_length: u64 = 8,
    has_tracks_element: bool,
    cluster_count: u32,
    total_cluster_bytes: u64,

    pub fn deinit(self: *MkvDissectionResult) void {
        if (self.info.muxing_app.len > 0) self.allocator.free(self.info.muxing_app);
        if (self.info.writing_app.len > 0) self.allocator.free(self.info.writing_app);
        for (self.tracks) |t| {
            if (t.codec_id.len > 0) self.allocator.free(t.codec_id);
            if (t.codec_name.len > 0) self.allocator.free(t.codec_name);
        }
        self.allocator.free(self.tracks);
        for (self.attachments) |a| {
            if (a.file_name.len > 0) self.allocator.free(a.file_name);
            if (a.mime_type.len > 0) self.allocator.free(a.mime_type);
        }
        self.allocator.free(self.attachments);
        self.allocator.free(self.clusters);
        self.allocator.free(self.sample_runs);
        for (self.external_refs) |r| {
            if (r.filename.len > 0) self.allocator.free(r.filename);
        }
        self.allocator.free(self.external_refs);
        self.allocator.free(self.cues);
        self.allocator.free(self.lacing_anomalies);
    }
};

pub const MkvInspectionResult = MkvDissectionResult;
