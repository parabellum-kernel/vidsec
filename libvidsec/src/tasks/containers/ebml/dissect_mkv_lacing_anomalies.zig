const std = @import("std");
const Allocator = std.mem.Allocator;
const abi = @import("parabellum_sdk").task;
const dissect_ebml = @import("dissect_ebml.zig");
const mkv_common = @import("mkv_common.zig");

pub const Inputs = struct {
    stream: abi.BoundedStreamReader,
    ebml_elements: []const dissect_ebml.EbmlElementRow = &.{},
};

pub const MkvLacingAnomalyRow = struct {
    offset: u64,
    lacing_kind: u8,
    frame_count: u64,
    payload_size: u64,
};

pub const OutputsData = struct {
    mkv_lacing_anomalies: []const MkvLacingAnomalyRow,
};

pub const Outputs = abi.Channels(OutputsData);

/// Stage 1a pure atomic dissector for Matroska block lacing anomalies (zero policy findings).
pub const Service = struct {
    pub fn execute(_: *const Service, alloc: Allocator, inputs: Inputs) !Outputs {
        var dissected = try mkv_common.dissectMkv(alloc, &inputs.stream, inputs.ebml_elements, .{
            .parse_info = false,
            .parse_tracks = false,
            .parse_attachments = false,
            .parse_cues = false,
            .parse_cluster_blocks = true,
        });
        defer dissected.deinit();

        var lacings: std.ArrayList(MkvLacingAnomalyRow) = .empty;
        errdefer lacings.deinit(alloc);

        for (dissected.lacing_anomalies) |la| {
            try lacings.append(alloc, .{
                .offset = la.offset,
                .lacing_kind = la.lacing_kind,
                .frame_count = la.frame_count,
                .payload_size = la.payload_size,
            });
        }

        return .{ .data = .{
            .mkv_lacing_anomalies = try lacings.toOwnedSlice(alloc),
        } };
    }
};
