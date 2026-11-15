const std = @import("std");
const Allocator = std.mem.Allocator;

pub const AviMainHeader = struct {
    micro_sec_per_frame: u32 = 0,
    max_bytes_per_sec: u32 = 0,
    flags: u32 = 0,
    total_frames: u32 = 0,
    streams: u32 = 0,
    suggested_buffer_size: u32 = 0,
    width: u32 = 0,
    height: u32 = 0,
};

pub const AviVideoFormat = struct {
    bi_size: u32 = 0,
    width: i32 = 0,
    height: i32 = 0,
    bi_planes: u16 = 0,
    bit_count: u16 = 0,
    compression: [4]u8 = .{ 0, 0, 0, 0 },
    bi_size_image: u32 = 0,
    bi_clr_used: u32 = 0,
    strf_size: u64 = 0,
    dim_mul_overflow: bool = false,
};

pub const AviAudioFormat = struct {
    format_tag: u16 = 0,
    channels: u16 = 0,
    samples_per_sec: u32 = 0,
    bits_per_sample: u16 = 0,
};

pub const AviStreamRecord = struct {
    stream_index: u32,
    fcc_type: [4]u8,
    fcc_handler: [4]u8,
    scale: u32 = 0,
    rate: u32 = 0,
    length: u32 = 0,
    suggested_buffer_size: u32 = 0,
    strf_offset: u64 = 0,
    strf_size: u64 = 0,
    video: ?AviVideoFormat = null,
    audio: ?AviAudioFormat = null,
};

pub const AviSampleRun = struct {
    stream_index: u32,
    start_offset: u64,
    byte_length: u64,
    chunk_count: u32,
};

pub const AviDissectionResult = struct {
    allocator: Allocator,
    main_header: ?AviMainHeader = null,
    streams: []const AviStreamRecord,
    sample_runs: []const AviSampleRun,
    movi_payload_offset: u64 = 0,
    movi_payload_size: u64 = 0,
    idx1_offset: u64 = 0,
    idx1_size: u64 = 0,
    idx1_entry_count: u32 = 0,

    pub fn deinit(self: *AviDissectionResult) void {
        self.allocator.free(self.streams);
        self.allocator.free(self.sample_runs);
    }
};

