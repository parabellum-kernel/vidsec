const std = @import("std");
const types = @import("types.zig");

pub const FtypInfo = types.FtypInfo;
pub const TrackRecord = types.TrackRecord;
pub const SampleRun = types.SampleRun;
pub const TableMeasurement = types.TableMeasurement;
pub const ExternalRefRecord = types.ExternalRefRecord;
pub const AttachmentRecord = types.AttachmentRecord;
pub const CodecHeaderMeasurement = types.CodecHeaderMeasurement;

/// Pure structural output of `Mp4Dissector.dissect`.
pub const Mp4DissectionResult = struct {
    allocator: std.mem.Allocator,
    ftyp: ?FtypInfo = null,
    tracks: []TrackRecord = &.{},
    sample_runs: []SampleRun = &.{},
    table_measurements: []TableMeasurement = &.{},
    external_refs: []ExternalRefRecord = &.{},
    attachments: []AttachmentRecord = &.{},
    codec_headers: []CodecHeaderMeasurement = &.{},
    mdat_total_bytes: u64 = 0,

    pub fn deinit(self: *Mp4DissectionResult) void {
        if (self.ftyp) |f| {
            self.allocator.free(f.compatible_brands);
        }
        self.allocator.free(self.tracks);
        self.allocator.free(self.sample_runs);
        self.allocator.free(self.table_measurements);
        for (self.external_refs) |r| {
            if (r.uri.len > 0) self.allocator.free(r.uri);
        }
        self.allocator.free(self.external_refs);
        self.allocator.free(self.attachments);
        self.allocator.free(self.codec_headers);
    }
};

pub const Mp4InspectionResult = Mp4DissectionResult;
