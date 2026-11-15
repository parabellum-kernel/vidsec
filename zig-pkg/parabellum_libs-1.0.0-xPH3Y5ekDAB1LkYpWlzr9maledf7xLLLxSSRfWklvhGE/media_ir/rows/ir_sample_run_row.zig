/// Coalesced contiguous sample run in `media_data` (replaces per-sample `IrSampleExtentRow`).
pub const IrSampleRunRow = struct {
    run_id: i64,
    track_id: i64,
    start_offset: u64,
    byte_length: u64,
    end_offset: u64,
    sample_count: u32 = 1,
};

