const std = @import("std");
const Allocator = std.mem.Allocator;
const abi = @import("parabellum_sdk").task;
const riff = @import("riff");
const common = @import("common.zig");

pub const Inputs = struct {
    stream: abi.BoundedStreamReader,
};

pub const RiffTriageRow = struct {
    form_type: []const u8,
    file_size: u64,
    root_size: u64,
    is_valid_root_magic: bool,
    header_truncated_at: ?u64 = null,
    chunk_count: u64,
    movi_bytes: u64,
    junk_bytes: u64,
    stream_count: u64,
    sample_run_count: u64,
    idx1_size: u64,
    idx1_entry_count: u64,
    highest_root_end: u64,
    riff_valid: bool,
};

pub const RiffChunkRow = struct {
    region_id: i64,
    parent_region_id: ?i64 = null,
    depth: i64,
    fourcc: []const u8,
    path: []const u8,
    role: []const u8,
    header_offset: u64,
    payload_offset: u64,
    available_bytes: u64,
    is_truncated: bool,
    is_overflow: bool,
};

pub const AviStreamHeaderRow = struct {
    stream_index: u64,
    fcc_type: []const u8,
    fcc_handler: []const u8,
    scale: u64,
    rate: u64,
    length: u64,
    strf_offset: u64,
    strf_size: u64,
    has_video: bool,
    bi_size: u64,
    width: i64,
    height: i64,
    bi_planes: u64,
    bit_count: u64,
    bi_size_image: u64,
    bi_clr_used: u64,
    dim_mul_overflow: bool,
};

pub const OutputsData = struct {
    riff_triage: RiffTriageRow,
    riff_chunks: []const RiffChunkRow,
    avi_stream_headers: []const AviStreamHeaderRow,
};

pub const Outputs = abi.Channels(OutputsData);

/// Stage 1a pure atomic dissector for RIFF / AVI chunk hierarchy and stream headers (zero policy findings).
pub const Service = struct {
    pub fn execute(_: *const Service, alloc: Allocator, inputs: Inputs) !Outputs {
        const source = common.streamToSource(riff.ByteSource, &inputs.stream);
        var parsed = try riff.riff.SafeRiffParser.init(alloc, .{}).parse(source);
        defer parsed.deinit();

        var chunks: std.ArrayList(RiffChunkRow) = .empty;
        errdefer chunks.deinit(alloc);
        var stream_headers: std.ArrayList(AviStreamHeaderRow) = .empty;
        errdefer stream_headers.deinit(alloc);

        var has_overflow_or_truncated = parsed.header_truncated_at != null;

        for (parsed.chunks) |c| {
            if (c.containment.is_truncated or c.containment.is_overflow) {
                has_overflow_or_truncated = true;
            }
            try chunks.append(alloc, .{
                .region_id = @intCast(c.id),
                .parent_region_id = if (c.parent_id) |pid| @intCast(pid) else null,
                .depth = @intCast(c.depth),
                .fourcc = try alloc.dupe(u8, &c.header.fourcc.bytes),
                .path = try alloc.dupe(u8, c.path),
                .role = c.role.asText(),
                .header_offset = c.header.offset,
                .payload_offset = c.header.payloadOffset(),
                .available_bytes = c.containment.available_bytes,
                .is_truncated = c.containment.is_truncated,
                .is_overflow = c.containment.is_overflow,
            });
        }

        var stream_count: u64 = 0;
        var sample_run_count: u64 = 0;
        var idx1_size: u64 = 0;
        var idx1_entry_count: u64 = 0;
        if (parsed.form_type.equals(riff.riff.types.FORM_AVI) or parsed.form_type.equals(riff.riff.types.FORM_AVIX)) {
            var avi_res = try riff.avi.AviDissector.init(alloc).dissect(source, parsed.chunks);
            defer avi_res.deinit();
            stream_count = avi_res.streams.len;
            sample_run_count = avi_res.sample_runs.len;
            idx1_size = avi_res.idx1_size;
            idx1_entry_count = avi_res.idx1_entry_count;

            for (avi_res.streams) |s| {
                const v = s.video;
                try stream_headers.append(alloc, .{
                    .stream_index = s.stream_index,
                    .fcc_type = try alloc.dupe(u8, &s.fcc_type),
                    .fcc_handler = try alloc.dupe(u8, &s.fcc_handler),
                    .scale = s.scale,
                    .rate = s.rate,
                    .length = s.length,
                    .strf_offset = s.strf_offset,
                    .strf_size = s.strf_size,
                    .has_video = v != null,
                    .bi_size = if (v) |vv| vv.bi_size else 0,
                    .width = if (v) |vv| vv.width else 0,
                    .height = if (v) |vv| vv.height else 0,
                    .bi_planes = if (v) |vv| vv.bi_planes else 0,
                    .bit_count = if (v) |vv| vv.bit_count else 0,
                    .bi_size_image = if (v) |vv| vv.bi_size_image else 0,
                    .bi_clr_used = if (v) |vv| vv.bi_clr_used else 0,
                    .dim_mul_overflow = if (v) |vv| vv.dim_mul_overflow else false,
                });
            }
        }

        return .{ .data = .{
            .riff_triage = .{
                .form_type = try alloc.dupe(u8, &parsed.form_type.bytes),
                .file_size = source.file_size,
                .root_size = parsed.root_size,
                .is_valid_root_magic = parsed.is_valid_root_magic,
                .header_truncated_at = parsed.header_truncated_at,
                .chunk_count = parsed.chunks.len,
                .movi_bytes = parsed.movi_bytes,
                .junk_bytes = parsed.junk_bytes,
                .stream_count = stream_count,
                .sample_run_count = sample_run_count,
                .idx1_size = idx1_size,
                .idx1_entry_count = idx1_entry_count,
                .highest_root_end = parsed.highest_root_end,
                .riff_valid = parsed.is_valid_root_magic and !has_overflow_or_truncated,
            },
            .riff_chunks = try chunks.toOwnedSlice(alloc),
            .avi_stream_headers = try stream_headers.toOwnedSlice(alloc),
        } };
    }
};
