pub const FourCC = @import("../box/fourcc.zig").FourCC;
pub const FtypInfo = @import("ftyp_info.zig").FtypInfo;
pub const AvcCConfig = @import("avcc_config.zig").AvcCConfig;
pub const EsdsConfig = @import("esds_config.zig").EsdsConfig;

/// Coalesced contiguous byte run of media samples for a track.
pub const SampleRun = struct {
    track_id: u32,
    first_sample: u32,
    sample_count: u32,
    start_offset: u64,
    end_offset: u64,
};

/// Physical containment measurement of an MP4 sample/codec table box.
pub const TableMeasurement = struct {
    table_fourcc: FourCC,
    path: []const u8,
    entry_count: u32,
    entry_size: u32,
    claimed_bytes: u64,
    payload_size: u64,
    is_overflow: bool,
    has_arith_overflow: bool = false,
};

/// External data reference extracted from `dref` (`url `/`urn `) or QuickTime `rmra`/`rdrf`.
pub const ExternalRefRecord = struct {
    track_id: u32 = 0,
    source_fourcc: FourCC,
    file_offset: u64,
    uri: []const u8,
    is_self_contained: bool = false,
};

/// Embedded attachment/cover-art payload extracted from `covr`/`meta`/`iloc`.
pub const AttachmentRecord = struct {
    source_fourcc: FourCC,
    file_offset: u64,
    payload_size: u64,
    declared_mime: []const u8 = "application/octet-stream",
};

pub const CodecHeaderKind = enum {
    avcc,
    hvcc,
    esds,
};

/// Detailed codec configuration header bounds & anomaly measurements (`avcC`, `hvcC`, `esds`).
pub const CodecHeaderMeasurement = struct {
    track_id: u32 = 0,
    codec_tag: FourCC,
    kind: CodecHeaderKind,
    is_malformed: bool = false,
    length_size_minus_one: u2 = 3,
    sps_count: u8 = 0,
    pps_count: u8 = 0,
    array_count: u8 = 0,
    claimed_bytes: u64 = 0,
    payload_size: u64 = 0,
};

/// Dissected MP4 track metadata and codec configuration.
pub const TrackRecord = struct {
    track_id: u32 = 0,
    handler_type: FourCC = FourCC.init("    "),
    width: u32 = 0,
    height: u32 = 0,
    timescale: u32 = 0,
    duration: u64 = 0,
    codec_fourcc: FourCC = FourCC.init("    "),
    avcc: ?AvcCConfig = null,
    esds: ?EsdsConfig = null,
    sample_count: u32 = 0,
    chunk_count: u32 = 0,
};

pub const TrackInfo = TrackRecord;
