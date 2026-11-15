const std = @import("std");
const Allocator = std.mem.Allocator;
const abi = @import("parabellum_abi");
const isobmff = @import("isobmff");
const common = @import("common.zig");

pub const Inputs = struct {
    stream: abi.BoundedStreamReader,
};

pub const Mp4AtomsSummaryRow = struct {
    track_count: u64,
    sample_run_count: u64,
    avcc_count: u64,
    hvcc_count: u64,
    esds_count: u64,
    table_overflow_count: u64,
    atoms_valid: bool,
};

pub const Mp4TrackRow = struct {
    track_id: i64,
    handler_type: []const u8,
    codec_fourcc: []const u8,
    width: u64,
    height: u64,
    sample_count: u64,
    has_avcc: bool,
    has_esds: bool,
};

pub const Mp4TableMeasurementRow = struct {
    table_fourcc: []const u8,
    path: []const u8,
    entry_count: u64,
    entry_size: u64,
    claimed_bytes: u64,
    payload_size: u64,
    is_overflow: bool,
    has_arith_overflow: bool,
};

pub const Mp4CodecHeaderRow = struct {
    track_id: u64,
    codec_tag: []const u8,
    kind: []const u8,
    is_malformed: bool,
    length_size_minus_one: u8,
    sps_count: u8,
    pps_count: u8,
    array_count: u8,
    claimed_bytes: u64,
    payload_size: u64,
};

pub const OutputsData = struct {
    mp4_atoms_summary: Mp4AtomsSummaryRow,
    mp4_tracks: []const Mp4TrackRow,
    mp4_table_measurements: []const Mp4TableMeasurementRow,
    mp4_codec_headers: []const Mp4CodecHeaderRow,
};

pub const Outputs = abi.Channels(OutputsData);

/// Stage 1a pure atomic dissector for MP4 track, sample-table, and codec atoms (zero policy findings).
pub const Service = struct {
    pub fn execute(_: *const Service, alloc: Allocator, inputs: Inputs) !Outputs {
        const source = common.streamToSource(isobmff.ByteSource, &inputs.stream);
        var parsed = try isobmff.box.SafeBoxParser.init(alloc).parse(source);
        defer parsed.deinit();

        var dissected = try isobmff.mp4.Mp4Dissector.init(alloc).dissect(source, parsed.boxes);
        defer dissected.deinit();

        var tracks: std.ArrayList(Mp4TrackRow) = .empty;
        errdefer tracks.deinit(alloc);
        var table_rows: std.ArrayList(Mp4TableMeasurementRow) = .empty;
        errdefer table_rows.deinit(alloc);
        var codec_rows: std.ArrayList(Mp4CodecHeaderRow) = .empty;
        errdefer codec_rows.deinit(alloc);

        var avcc_count: u64 = 0;
        var hvcc_count: u64 = 0;
        var esds_count: u64 = 0;

        for (dissected.tracks) |t| {
            if (t.avcc != null) avcc_count += 1;
            if (t.esds != null) esds_count += 1;
            try tracks.append(alloc, .{
                .track_id = @intCast(t.track_id),
                .handler_type = try alloc.dupe(u8, &t.handler_type.bytes),
                .codec_fourcc = try alloc.dupe(u8, &t.codec_fourcc.bytes),
                .width = t.width,
                .height = t.height,
                .sample_count = t.sample_count,
                .has_avcc = t.avcc != null,
                .has_esds = t.esds != null,
            });
        }

        var has_malformed_codec = false;
        for (dissected.codec_headers) |ch| {
            const kind_str = switch (ch.kind) {
                .avcc => blk: {
                    if (avcc_count == 0) avcc_count += 1;
                    break :blk "avcc";
                },
                .hvcc => blk: {
                    hvcc_count += 1;
                    break :blk "hvcc";
                },
                .esds => blk: {
                    if (esds_count == 0) esds_count += 1;
                    break :blk "esds";
                },
            };
            if (ch.is_malformed) has_malformed_codec = true;
            try codec_rows.append(alloc, .{
                .track_id = ch.track_id,
                .codec_tag = try alloc.dupe(u8, &ch.codec_tag.bytes),
                .kind = kind_str,
                .is_malformed = ch.is_malformed,
                .length_size_minus_one = ch.length_size_minus_one,
                .sps_count = ch.sps_count,
                .pps_count = ch.pps_count,
                .array_count = ch.array_count,
                .claimed_bytes = ch.claimed_bytes,
                .payload_size = ch.payload_size,
            });
        }

        // Also measure standalone avcC/esds boxes if none were dissected inside a trak
        if (codec_rows.items.len == 0) {
            for (parsed.boxes) |b| {
                if (std.mem.eql(u8, &b.fourcc.bytes, "avcC")) {
                    avcc_count += 1;
                    var is_malformed = b.payloadSize() < 7;
                    var len_minus_one: u8 = 3;
                    var num_sps: u8 = 0;
                    var claimed: u64 = b.payloadSize();
                    if (b.payloadSize() >= 8) {
                        var buf: [8]u8 = undefined;
                        source.readExactAt(&buf, b.payload_offset) catch {};
                        len_minus_one = buf[4] & 0x03;
                        num_sps = buf[5] & 0x1F;
                        if (num_sps > 0) {
                            const sps_len = std.mem.readInt(u16, buf[6..8], .big);
                            claimed = @as(u64, 8) + sps_len;
                            if (claimed > b.payloadSize()) is_malformed = true;
                        }
                    }
                    if (is_malformed) has_malformed_codec = true;
                    try codec_rows.append(alloc, .{
                        .track_id = 0,
                        .codec_tag = "avcC",
                        .kind = "avcc",
                        .is_malformed = is_malformed,
                        .length_size_minus_one = len_minus_one,
                        .sps_count = num_sps,
                        .pps_count = 0,
                        .array_count = 0,
                        .claimed_bytes = claimed,
                        .payload_size = b.payloadSize(),
                    });
                } else if (std.mem.eql(u8, &b.fourcc.bytes, "esds")) {
                    esds_count += 1;
                }
            }
        }

        var table_overflow_count: u64 = 0;
        for (dissected.table_measurements) |tm| {
            if (tm.is_overflow or tm.has_arith_overflow) table_overflow_count += 1;
            try table_rows.append(alloc, .{
                .table_fourcc = try alloc.dupe(u8, &tm.table_fourcc.bytes),
                .path = try alloc.dupe(u8, tm.path),
                .entry_count = tm.entry_count,
                .entry_size = tm.entry_size,
                .claimed_bytes = tm.claimed_bytes,
                .payload_size = tm.payload_size,
                .is_overflow = tm.is_overflow,
                .has_arith_overflow = tm.has_arith_overflow,
            });
        }

        return .{ .data = .{
            .mp4_atoms_summary = .{
                .track_count = dissected.tracks.len,
                .sample_run_count = dissected.sample_runs.len,
                .avcc_count = avcc_count,
                .hvcc_count = hvcc_count,
                .esds_count = esds_count,
                .table_overflow_count = table_overflow_count,
                .atoms_valid = table_overflow_count == 0 and !has_malformed_codec,
            },
            .mp4_tracks = try tracks.toOwnedSlice(alloc),
            .mp4_table_measurements = try table_rows.toOwnedSlice(alloc),
            .mp4_codec_headers = try codec_rows.toOwnedSlice(alloc),
        } };
    }
};
