pub const IrExternalRefRow = struct {
    ref_id: i64,
    track_id: i64 = 0,
    source_tag: []const u8 = "",
    file_offset: u64 = 0,
    target_url: []const u8,
};
