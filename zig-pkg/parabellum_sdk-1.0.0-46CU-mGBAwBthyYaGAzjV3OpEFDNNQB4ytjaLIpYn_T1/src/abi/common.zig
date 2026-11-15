const std = @import("std");

pub const SemVer_ABI = extern struct {
    major: u32,
    minor: u32,
    patch: u32,

    /// Returns true when `self` (the host engine version) satisfies `min_required`
    /// under SemVer major compatibility (`self.major == min_required.major` and `self >= min_required`).
    pub fn satisfies(self: SemVer_ABI, min_required: SemVer_ABI) bool {
        if (self.major != min_required.major) return false;
        if (self.minor != min_required.minor) return self.minor > min_required.minor;
        return self.patch >= min_required.patch;
    }
};

/// Current SDK / Engine compatibility version embedded automatically into manifests.
pub const SDK_VERSION: SemVer_ABI = .{ .major = 1, .minor = 0, .patch = 0 };

pub const Slice_ABI = extern struct {
    ptr: ?[*]const u8,
    len: usize,

    pub const empty: Slice_ABI = .{ .ptr = null, .len = 0 };

    pub fn from(s: []const u8) Slice_ABI {
        return .{
            .ptr = if (s.len > 0) s.ptr else null,
            .len = s.len,
        };
    }

    pub fn toSlice(self: Slice_ABI) []const u8 {
        if (self.len == 0 or self.ptr == null) return &.{};
        return self.ptr.?[0..self.len];
    }
};

pub const HostError_ABI = enum(u32) {
    ok = 0,
    end_of_stream = 1,
    out_of_bounds = 2,
    key_not_found = 3,
    type_mismatch = 4,
    io_error = 5,
    network_denied = 6,
    network_rate_limited = 7,
    invalid_argument = 8,
    out_of_memory = 9,
    not_supported = 10,
    internal_error = 255,
};

pub const LogLevel_ABI = enum(u32) {
    debug = 0,
    info = 1,
    warn = 2,
    err = 3,
};

pub const ValueTag_ABI = enum(u32) {
    null_val = 0,
    bool_val = 1,
    int_val = 2,
    uint_val = 3,
    float_val = 4,
    bytes_val = 5,
};

pub const ValuePayload_ABI = extern union {
    b: bool,
    i: i64,
    u: u64,
    f: f64,
    bytes: Slice_ABI,
};

pub const Value_ABI = extern struct {
    tag: ValueTag_ABI,
    payload: ValuePayload_ABI,

    pub fn fromInt(v: i64) Value_ABI {
        return .{ .tag = .int_val, .payload = .{ .i = v } };
    }

    pub fn fromUint(v: u64) Value_ABI {
        return .{ .tag = .uint_val, .payload = .{ .u = v } };
    }

    pub fn fromBool(v: bool) Value_ABI {
        return .{ .tag = .bool_val, .payload = .{ .b = v } };
    }

    pub fn fromFloat(v: f64) Value_ABI {
        return .{ .tag = .float_val, .payload = .{ .f = v } };
    }

    pub fn fromBytes(s: []const u8) Value_ABI {
        return .{ .tag = .bytes_val, .payload = .{ .bytes = Slice_ABI.from(s) } };
    }
};

pub const NamedField_ABI = extern struct {
    name: [*:0]const u8,
    value: Value_ABI,
};

pub const RowView_ABI = extern struct {
    fields_ptr: ?[*]const NamedField_ABI,
    fields_len: usize,

    pub fn fieldsSlice(self: RowView_ABI) []const NamedField_ABI {
        if (self.fields_len == 0 or self.fields_ptr == null) return &.{};
        return self.fields_ptr.?[0..self.fields_len];
    }
};

