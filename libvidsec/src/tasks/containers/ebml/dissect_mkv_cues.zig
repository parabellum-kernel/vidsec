const std = @import("std");
const Allocator = std.mem.Allocator;
const abi = @import("parabellum_sdk").task;
const dissect_ebml = @import("dissect_ebml.zig");
const mkv_common = @import("mkv_common.zig");

pub const Inputs = struct {
    stream: abi.BoundedStreamReader,
    ebml_elements: []const dissect_ebml.EbmlElementRow = &.{},
};

pub const MkvCueRow = struct {
    cue_time: u64,
    track_number: u64,
    cluster_position: u64,
    in_segment_bounds: bool,
};

pub const OutputsData = struct {
    mkv_cues: []const MkvCueRow,
};

pub const Outputs = abi.Channels(OutputsData);

/// Stage 1a pure atomic dissector for Matroska Cues (zero policy findings).
pub const Service = struct {
    pub fn execute(_: *const Service, alloc: Allocator, inputs: Inputs) !Outputs {
        var dissected = try mkv_common.dissectMkv(alloc, &inputs.stream, inputs.ebml_elements, .{
            .parse_info = false,
            .parse_tracks = false,
            .parse_attachments = false,
            .parse_cues = true,
            .parse_cluster_blocks = false,
        });
        defer dissected.deinit();

        var cues: std.ArrayList(MkvCueRow) = .empty;
        errdefer cues.deinit(alloc);

        for (dissected.cues) |c| {
            try cues.append(alloc, .{
                .cue_time = c.cue_time,
                .track_number = c.track_number,
                .cluster_position = c.cluster_position,
                .in_segment_bounds = c.in_segment_bounds,
            });
        }

        return .{ .data = .{
            .mkv_cues = try cues.toOwnedSlice(alloc),
        } };
    }
};
