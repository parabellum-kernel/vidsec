/// Order emitted by any analysis task when trailing bytes past `highest_root_end`
/// (e.g., appended ZIP/RAR overlay) can be safely truncated.
pub const TruncateOrder = struct {
    new_size: u64,
    rule_id: []const u8,
    reason: []const u8 = "",
};

/// Order emitted by any analysis task when a bounded region (e.g., `free`/`JUNK` padding
/// or unreferenced slack) contains suspicious payload bytes that can be zero-filled.
pub const ZeroOutOrder = struct {
    offset: u64,
    length: u64,
    rule_id: []const u8,
    reason: []const u8 = "",
};

pub const ContainerFamily = enum {
    isobmff,
    ebml,
    riff,
};

pub const PatchFieldOrder = struct {
    offset: u64,
    new_bytes: []const u8,
    rule_id: []const u8,
    reason: []const u8 = "",
    severity: i64 = 3,
};

pub const TombstoneRegionOrder = struct {
    family: ContainerFamily,
    region_tag: []const u8,
    header_offset: u64,
    payload_offset: u64,
    available_bytes: u64,
    rule_id: []const u8,
    reason: []const u8 = "",
    severity: i64 = 3,
};

pub const QuarantineOrder = struct {
    rule_id: []const u8,
    reason: []const u8 = "",
    severity: i64 = 4,
};

pub const RemediationReport = struct {
    action: []const u8,
    rule_id: []const u8,
    offset: u64,
    length: u64,
    new_size: u64,
    applied: bool,
    requires_reverify: bool,
};

pub const RemediationOutcome = RemediationReport;
