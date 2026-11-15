const std = @import("std");
const ebml = @import("../ebml/mod.zig");

pub const LacingKind = enum {
    none,
    xiph,
    fixed,
    ebml,
};

pub const LacingMeasurement = struct {
    lacing_kind: LacingKind = .none,
    frame_count: u16 = 0,
    header_bytes: u64 = 0,
    declared_frames_sum: u64 = 0,
    block_payload_size: u64 = 0,
    has_negative_delta: bool = false,
    has_sum_overflow: bool = false,
    has_fixed_remainder: bool = false,
    is_truncated_or_invalid: bool = false,
};

/// Inspects a Matroska `Block` or `SimpleBlock` payload slice for lacing header integrity
/// (`CVE-2016-1621` negative signed VINT delta underflow, Xiph/EBML sum overflow, and fixed remainder).
/// Zero heap allocation.
pub fn inspectBlockLacing(block_data: []const u8) LacingMeasurement {
    var m = LacingMeasurement{
        .block_payload_size = block_data.len,
    };

    const track_vint = ebml.vint.readVintSlice(block_data) orelse {
        m.is_truncated_or_invalid = true;
        return m;
    };
    var pos: usize = track_vint.length;
    if (pos + 3 > block_data.len) {
        m.is_truncated_or_invalid = true;
        return m;
    }

    // Skip 2-byte big-endian timecode
    pos += 2;
    const flags = block_data[pos];
    pos += 1;

    const lacing_bits = flags & 0x06;
    if (lacing_bits == 0x00) {
        m.lacing_kind = .none;
        m.frame_count = 1;
        m.header_bytes = pos;
        m.declared_frames_sum = block_data.len - pos;
        return m;
    }

    if (pos >= block_data.len) {
        m.is_truncated_or_invalid = true;
        return m;
    }

    const frame_count: u16 = @as(u16, block_data[pos]) + 1;
    pos += 1;
    m.frame_count = frame_count;

    switch (lacing_bits) {
        0x02 => {
            m.lacing_kind = .xiph;
            var i: u16 = 0;
            while (i + 1 < frame_count) : (i += 1) {
                var frame_size: u64 = 0;
                while (true) {
                    if (pos >= block_data.len) {
                        m.is_truncated_or_invalid = true;
                        m.has_sum_overflow = true;
                        m.header_bytes = pos;
                        return m;
                    }
                    const b = block_data[pos];
                    pos += 1;
                    frame_size = std.math.add(u64, frame_size, b) catch {
                        m.has_sum_overflow = true;
                        m.header_bytes = pos;
                        return m;
                    };
                    if (b != 0xFF) break;
                }
                m.declared_frames_sum = std.math.add(u64, m.declared_frames_sum, frame_size) catch {
                    m.has_sum_overflow = true;
                    m.header_bytes = pos;
                    return m;
                };
            }
            m.header_bytes = pos;
            const remaining = block_data.len - pos;
            if (m.declared_frames_sum > remaining) {
                m.has_sum_overflow = true;
            }
        },
        0x04 => {
            m.lacing_kind = .fixed;
            m.header_bytes = pos;
            const remaining = block_data.len - pos;
            m.declared_frames_sum = remaining;
            if (remaining % frame_count != 0) {
                m.has_fixed_remainder = true;
            }
        },
        0x06 => {
            m.lacing_kind = .ebml;
            if (frame_count == 1) {
                m.header_bytes = pos;
                m.declared_frames_sum = block_data.len - pos;
                return m;
            }

            const first_vint = ebml.vint.readVintSlice(block_data[pos..]) orelse {
                m.is_truncated_or_invalid = true;
                m.header_bytes = pos;
                return m;
            };
            pos += first_vint.length;
            if (first_vint.data_value > std.math.maxInt(i64)) {
                m.has_sum_overflow = true;
                m.header_bytes = pos;
                return m;
            }
            var prev_size: i64 = @intCast(first_vint.data_value);
            m.declared_frames_sum = first_vint.data_value;

            var i: u16 = 1;
            while (i + 1 < frame_count) : (i += 1) {
                const delta_vint = ebml.vint.readVintSlice(block_data[pos..]) orelse {
                    m.is_truncated_or_invalid = true;
                    m.header_bytes = pos;
                    return m;
                };
                pos += delta_vint.length;
                if (delta_vint.data_value > std.math.maxInt(i64)) {
                    m.has_sum_overflow = true;
                    m.header_bytes = pos;
                    return m;
                }
                const bias: i64 = @intCast((@as(u64, 1) << @intCast(7 * delta_vint.length - 1)) - 1);
                const delta: i64 = @as(i64, @intCast(delta_vint.data_value)) - bias;
                const next_size = std.math.add(i64, prev_size, delta) catch {
                    m.has_sum_overflow = true;
                    m.header_bytes = pos;
                    return m;
                };
                if (next_size < 0) {
                    m.has_negative_delta = true;
                } else {
                    m.declared_frames_sum = std.math.add(u64, m.declared_frames_sum, @intCast(next_size)) catch {
                        m.has_sum_overflow = true;
                        m.header_bytes = pos;
                        return m;
                    };
                }
                prev_size = next_size;
            }

            m.header_bytes = pos;
            const remaining = block_data.len - pos;
            if (m.declared_frames_sum > remaining) {
                m.has_sum_overflow = true;
            }
        },
        else => unreachable,
    }

    return m;
}

test "lacing: valid Xiph, Fixed, and EBML laced blocks" {
    // 1. Valid Xiph: track=1 (0x81), tc=0 (00 00), flags=0x02 (Xiph), num_frames-1=1 (2 frames), size1=4, payload=4+4=8 bytes
    const valid_xiph = [_]u8{ 0x81, 0x00, 0x00, 0x02, 0x01, 0x04 } ++ @as([8]u8, @splat(0xAA));
    const rx = inspectBlockLacing(&valid_xiph);
    try std.testing.expectEqual(LacingKind.xiph, rx.lacing_kind);
    try std.testing.expectEqual(@as(u16, 2), rx.frame_count);
    try std.testing.expect(!rx.has_negative_delta);
    try std.testing.expect(!rx.has_sum_overflow);
    try std.testing.expect(!rx.is_truncated_or_invalid);

    // 2. Valid Fixed: 3 frames of 4 bytes each = 12 bytes
    const valid_fixed = [_]u8{ 0x81, 0x00, 0x00, 0x04, 0x02 } ++ @as([12]u8, @splat(0xBB));
    const rf = inspectBlockLacing(&valid_fixed);
    try std.testing.expectEqual(LacingKind.fixed, rf.lacing_kind);
    try std.testing.expectEqual(@as(u16, 3), rf.frame_count);
    try std.testing.expect(!rf.has_fixed_remainder);

    // 3. Valid EBML: 3 frames -> frame1=5 (0x85), delta2=-1 (0x3E + 0x80 = 0xBE -> 62 - 63 = -1 => frame2=4), payload=5+4+3=12 bytes
    const valid_ebml = [_]u8{ 0x81, 0x00, 0x00, 0x06, 0x02, 0x85, 0xBE } ++ @as([12]u8, @splat(0xCC));
    const re = inspectBlockLacing(&valid_ebml);
    try std.testing.expectEqual(LacingKind.ebml, re.lacing_kind);
    try std.testing.expectEqual(@as(u16, 3), re.frame_count);
    try std.testing.expectEqual(@as(u64, 9), re.declared_frames_sum);
    try std.testing.expect(!re.has_negative_delta);
    try std.testing.expect(!re.has_sum_overflow);
}

test "lacing: CVE-2016-1621 negative EBML delta underflow, sum overflow, and fixed remainder" {
    // 1. Negative delta underflow: frame1=2 (0x82), delta2=-10 (bias 63 -> 53 = 0x35 | 0x80 = 0xB5 -> 2 + (-10) = -8 < 0)
    const neg_ebml = [_]u8{ 0x81, 0x00, 0x00, 0x06, 0x02, 0x82, 0xB5, 0x00, 0x00 };
    const rn = inspectBlockLacing(&neg_ebml);
    try std.testing.expect(rn.has_negative_delta);

    // 2. Xiph sum overflow: frame1=50, but only 4 bytes remain
    const ovf_xiph = [_]u8{ 0x81, 0x00, 0x00, 0x02, 0x01, 50, 0x01, 0x02, 0x03, 0x04 };
    const ro = inspectBlockLacing(&ovf_xiph);
    try std.testing.expect(ro.has_sum_overflow);

    // 3. Fixed remainder: 3 frames, 10 bytes remaining (10 % 3 != 0)
    const rem_fixed = [_]u8{ 0x81, 0x00, 0x00, 0x04, 0x02 } ++ @as([10]u8, @splat(0xDD));
    const rr = inspectBlockLacing(&rem_fixed);
    try std.testing.expect(rr.has_fixed_remainder);
}

