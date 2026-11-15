const std = @import("std");

pub const MAX_RBSP_BYTES: usize = 4096;

/// Strips H.264 RBSP emulation-prevention bytes (`0x00 0x00 0x03` -> `0x00 0x00`)
/// into a caller-provided stack buffer without heap allocation.
pub fn rbspFromNal(nalu: []const u8, out_buf: []u8) []const u8 {
    var out_len: usize = 0;
    var zero_count: u8 = 0;

    for (nalu) |b| {
        if (out_len >= out_buf.len) break;
        if (zero_count >= 2 and b == 0x03) {
            zero_count = 0;
            continue;
        }
        out_buf[out_len] = b;
        out_len += 1;
        if (b == 0x00) {
            zero_count = @min(zero_count + 1, 2);
        } else {
            zero_count = 0;
        }
    }
    return out_buf[0..out_len];
}

pub const BitReader = struct {
    data: []const u8,
    byte_pos: usize = 0,
    bit_pos: u3 = 0,

    pub fn init(data: []const u8) BitReader {
        return .{ .data = data };
    }

    pub fn readBit(self: *BitReader) ?u1 {
        if (self.byte_pos >= self.data.len) return null;
        const shift: u3 = @intCast(7 - @as(u4, self.bit_pos));
        const bit: u1 = @truncate((self.data[self.byte_pos] >> shift) & 1);
        if (self.bit_pos == 7) {
            self.bit_pos = 0;
            self.byte_pos += 1;
        } else {
            self.bit_pos += 1;
        }
        return bit;
    }

    pub fn readBits(self: *BitReader, count: u6) ?u32 {
        if (count == 0) return 0;
        if (count > 32) return null;
        var acc: u32 = 0;
        var i: u6 = 0;
        while (i < count) : (i += 1) {
            const bit = self.readBit() orelse return null;
            acc = (acc << 1) | bit;
        }
        return acc;
    }

    /// Reads unsigned Exp-Golomb `ue(v)` with a strict `>= 32` leading-zero guard.
    pub fn readUe(self: *BitReader) ?u32 {
        var leading_zeros: u8 = 0;
        while (true) {
            const bit = self.readBit() orelse return null;
            if (bit == 1) break;
            leading_zeros += 1;
            if (leading_zeros >= 32) return null;
        }
        if (leading_zeros == 0) return 0;
        const suffix = self.readBits(@intCast(leading_zeros)) orelse return null;
        const base: u64 = (@as(u64, 1) << @intCast(leading_zeros)) - 1;
        const val = base + suffix;
        if (val > std.math.maxInt(u32)) return null;
        return @intCast(val);
    }

    /// Reads signed Exp-Golomb `se(v)`.
    pub fn readSe(self: *BitReader) ?i32 {
        const k = self.readUe() orelse return null;
        if (k == 0) return 0;
        const mag = (k + 1) >> 1;
        if (mag > std.math.maxInt(i32)) return null;
        if ((k & 1) == 1) {
            return @intCast(mag);
        } else {
            return -@as(i32, @intCast(mag));
        }
    }
};

pub const SpsInfo = struct {
    nal_unit_type: u8 = 0,
    profile_idc: u8 = 0,
    constraint_set_flags: u8 = 0,
    level_idc: u8 = 0,
    seq_parameter_set_id: u32 = 0,
    chroma_format_idc: u32 = 1,
    bit_depth_luma_minus8: u32 = 0,
    bit_depth_chroma_minus8: u32 = 0,
    log2_max_frame_num_minus4: u32 = 0,
    pic_order_cnt_type: u32 = 0,
    max_num_ref_frames: u32 = 0,
    pic_width_in_mbs_minus1: u32 = 0,
    pic_height_in_map_units_minus1: u32 = 0,
    frame_mbs_only_flag: u1 = 1,
    computed_width: u32 = 0,
    computed_height: u32 = 0,
    is_truncated_or_invalid: bool = false,
};

fn isHighProfile(profile_idc: u8) bool {
    return switch (profile_idc) {
        44, 83, 86, 100, 110, 118, 122, 128, 134, 135, 138, 139, 244 => true,
        else => false,
    };
}

fn skipScalingList(br: *BitReader, size_of_list: usize) bool {
    var last_scale: i64 = 8;
    var next_scale: i64 = 8;
    var j: usize = 0;
    while (j < size_of_list) : (j += 1) {
        if (next_scale != 0) {
            const delta_scale = br.readSe() orelse return false;
            next_scale = @mod(last_scale + @as(i64, delta_scale) + 256, 256);
        }
        last_scale = if (next_scale == 0) last_scale else next_scale;
    }
    return true;
}

/// Decodes an H.264 SPS NALU (with zero heap allocation).
pub fn parseAvcSps(nalu: []const u8) SpsInfo {
    var info = SpsInfo{};
    if (nalu.len < 4) {
        info.is_truncated_or_invalid = true;
        return info;
    }

    var rbsp_buf: [MAX_RBSP_BYTES]u8 = undefined;
    const rbsp = rbspFromNal(nalu, &rbsp_buf);
    if (rbsp.len < 4) {
        info.is_truncated_or_invalid = true;
        return info;
    }

    info.nal_unit_type = rbsp[0] & 0x1F;
    info.profile_idc = rbsp[1];
    info.constraint_set_flags = rbsp[2];
    info.level_idc = rbsp[3];

    var br = BitReader.init(rbsp[4..]);

    info.seq_parameter_set_id = br.readUe() orelse {
        info.is_truncated_or_invalid = true;
        return info;
    };

    if (isHighProfile(info.profile_idc)) {
        info.chroma_format_idc = br.readUe() orelse {
            info.is_truncated_or_invalid = true;
            return info;
        };
        if (info.chroma_format_idc == 3) {
            _ = br.readBit() orelse {
                info.is_truncated_or_invalid = true;
                return info;
            };
        }
        info.bit_depth_luma_minus8 = br.readUe() orelse {
            info.is_truncated_or_invalid = true;
            return info;
        };
        info.bit_depth_chroma_minus8 = br.readUe() orelse {
            info.is_truncated_or_invalid = true;
            return info;
        };
        _ = br.readBit() orelse {
            info.is_truncated_or_invalid = true;
            return info;
        };
        const scaling_matrix_present = br.readBit() orelse {
            info.is_truncated_or_invalid = true;
            return info;
        };
        if (scaling_matrix_present == 1) {
            const list_count: usize = if (info.chroma_format_idc != 3) 8 else 12;
            var i: usize = 0;
            while (i < list_count) : (i += 1) {
                const list_present = br.readBit() orelse {
                    info.is_truncated_or_invalid = true;
                    return info;
                };
                if (list_present == 1) {
                    const list_len: usize = if (i < 6) 16 else 64;
                    if (!skipScalingList(&br, list_len)) {
                        info.is_truncated_or_invalid = true;
                        return info;
                    }
                }
            }
        }
    }

    info.log2_max_frame_num_minus4 = br.readUe() orelse {
        info.is_truncated_or_invalid = true;
        return info;
    };
    info.pic_order_cnt_type = br.readUe() orelse {
        info.is_truncated_or_invalid = true;
        return info;
    };

    if (info.pic_order_cnt_type == 0) {
        _ = br.readUe() orelse {
            info.is_truncated_or_invalid = true;
            return info;
        };
    } else if (info.pic_order_cnt_type == 1) {
        _ = br.readBit() orelse {
            info.is_truncated_or_invalid = true;
            return info;
        };
        _ = br.readSe() orelse {
            info.is_truncated_or_invalid = true;
            return info;
        };
        _ = br.readSe() orelse {
            info.is_truncated_or_invalid = true;
            return info;
        };
        const cycle_len = br.readUe() orelse {
            info.is_truncated_or_invalid = true;
            return info;
        };
        if (cycle_len > 255) {
            info.is_truncated_or_invalid = true;
            return info;
        }
        var j: u32 = 0;
        while (j < cycle_len) : (j += 1) {
            _ = br.readSe() orelse {
                info.is_truncated_or_invalid = true;
                return info;
            };
        }
    }

    info.max_num_ref_frames = br.readUe() orelse {
        info.is_truncated_or_invalid = true;
        return info;
    };
    _ = br.readBit() orelse {
        info.is_truncated_or_invalid = true;
        return info;
    };
    info.pic_width_in_mbs_minus1 = br.readUe() orelse {
        info.is_truncated_or_invalid = true;
        return info;
    };
    info.pic_height_in_map_units_minus1 = br.readUe() orelse {
        info.is_truncated_or_invalid = true;
        return info;
    };
    info.frame_mbs_only_flag = br.readBit() orelse {
        info.is_truncated_or_invalid = true;
        return info;
    };
    if (info.frame_mbs_only_flag == 0) {
        _ = br.readBit() orelse {
            info.is_truncated_or_invalid = true;
            return info;
        };
    }
    _ = br.readBit() orelse {
        info.is_truncated_or_invalid = true;
        return info;
    };

    const frame_cropping_flag = br.readBit() orelse {
        info.is_truncated_or_invalid = true;
        return info;
    };
    var crop_left: u32 = 0;
    var crop_right: u32 = 0;
    var crop_top: u32 = 0;
    var crop_bottom: u32 = 0;
    if (frame_cropping_flag == 1) {
        crop_left = br.readUe() orelse {
            info.is_truncated_or_invalid = true;
            return info;
        };
        crop_right = br.readUe() orelse {
            info.is_truncated_or_invalid = true;
            return info;
        };
        crop_top = br.readUe() orelse {
            info.is_truncated_or_invalid = true;
            return info;
        };
        crop_bottom = br.readUe() orelse {
            info.is_truncated_or_invalid = true;
            return info;
        };
    }

    const raw_w: u64 = (@as(u64, info.pic_width_in_mbs_minus1) + 1) *| 16;
    const mbs_factor: u64 = 2 - @as(u64, info.frame_mbs_only_flag);
    const raw_h: u64 = mbs_factor *| (@as(u64, info.pic_height_in_map_units_minus1) + 1) *| 16;

    const crop_unit_x: u64 = if (info.chroma_format_idc == 0 or info.chroma_format_idc == 3) 1 else 2;
    const crop_unit_y: u64 = (if (info.chroma_format_idc == 0 or info.chroma_format_idc == 3) @as(u64, 1) else @as(u64, 2)) * mbs_factor;

    const crop_w = (@as(u64, crop_left) +| @as(u64, crop_right)) *| crop_unit_x;
    const crop_h = (@as(u64, crop_top) +| @as(u64, crop_bottom)) *| crop_unit_y;

    const final_w = raw_w -| crop_w;
    const final_h = raw_h -| crop_h;

    info.computed_width = @intCast(@min(final_w, std.math.maxInt(u32)));
    info.computed_height = @intCast(@min(final_h, std.math.maxInt(u32)));
    return info;
}

pub const AvcCParseSummary = struct {
    configuration_version: u8 = 0,
    length_size_minus_one: u8 = 0,
    sps_count: u8 = 0,
    pps_count: u8 = 0,
    parsed_sps_count: usize = 0,
    parsed_pps_count: usize = 0,
    is_truncated_or_invalid: bool = false,
};

/// Parses an `avcC` payload (`AVCDecoderConfigurationRecord`) into caller-provided slices
/// with zero heap allocation, decoding SPS parameters and PPS IDs.
pub fn parseAvcC(avcc_payload: []const u8, sps_out: []SpsInfo, pps_ids_out: []u32) AvcCParseSummary {
    var summary = AvcCParseSummary{};
    if (avcc_payload.len < 7) {
        summary.is_truncated_or_invalid = true;
        return summary;
    }

    summary.configuration_version = avcc_payload[0];
    summary.length_size_minus_one = avcc_payload[4] & 0x03;
    summary.sps_count = avcc_payload[5] & 0x1F;

    var pos: usize = 6;
    var i: u8 = 0;
    while (i < summary.sps_count) : (i += 1) {
        if (pos + 2 > avcc_payload.len) {
            summary.is_truncated_or_invalid = true;
            return summary;
        }
        const sps_len: usize = std.mem.readInt(u16, avcc_payload[pos..][0..2], .big);
        pos += 2;
        if (pos + sps_len > avcc_payload.len) {
            summary.is_truncated_or_invalid = true;
            return summary;
        }
        const sps_nalu = avcc_payload[pos .. pos + sps_len];
        pos += sps_len;
        if (summary.parsed_sps_count < sps_out.len) {
            sps_out[summary.parsed_sps_count] = parseAvcSps(sps_nalu);
            summary.parsed_sps_count += 1;
        }
    }

    if (pos >= avcc_payload.len) {
        summary.is_truncated_or_invalid = true;
        return summary;
    }

    summary.pps_count = avcc_payload[pos];
    pos += 1;

    var p: u8 = 0;
    while (p < summary.pps_count) : (p += 1) {
        if (pos + 2 > avcc_payload.len) {
            summary.is_truncated_or_invalid = true;
            return summary;
        }
        const pps_len: usize = std.mem.readInt(u16, avcc_payload[pos..][0..2], .big);
        pos += 2;
        if (pos + pps_len > avcc_payload.len) {
            summary.is_truncated_or_invalid = true;
            return summary;
        }
        const pps_nalu = avcc_payload[pos .. pos + pps_len];
        pos += pps_len;
        if (pps_nalu.len >= 2 and summary.parsed_pps_count < pps_ids_out.len) {
            var rbsp_buf: [256]u8 = undefined;
            const rbsp = rbspFromNal(pps_nalu, &rbsp_buf);
            if (rbsp.len >= 2) {
                var br = BitReader.init(rbsp[1..]);
                if (br.readUe()) |pps_id| {
                    pps_ids_out[summary.parsed_pps_count] = pps_id;
                    summary.parsed_pps_count += 1;
                } else {
                    summary.is_truncated_or_invalid = true;
                }
            }
        }
    }

    return summary;
}

test "nalu_sps: valid Baseline 1280x720 and High 1920x1080 with emulation prevention" {
    // 1. Valid Baseline 1280x720 SPS (no cropping, pic_width_in_mbs_minus1=79, pic_height_in_map_units_minus1=44)
    // Header: 0x67, profile=0x42 (66), constraint=0xC0, level=0x1F
    // Bits after byte 4:
    // sps_id=0 (1)
    // log2_max_frame_num_minus4=0 (1)
    // poc_type=0 (1)
    // log2_max_poc_lsb_minus4=0 (1)
    // max_num_ref_frames=2 (011)
    // gaps=0 (0)
    // width_mbs_minus1=79 -> 79+1=80 -> 000000 1 010000 (13 bits)
    // height_mbs_minus1=44 -> 44+1=45 -> 00000 1 01101 (11 bits)
    // frame_mbs_only=1 (1)
    // direct_8x8=0 (0)
    // frame_cropping=0 (0)
    // vui=0 (0)
    // Bitstream: 1111 0110 | 00000010 10000 000 | 00101101 1000...
    // Bytes: F6, 02, 80, 2D, 80
    const sps_720p = [_]u8{ 0x67, 0x42, 0xC0, 0x1F, 0xF6, 0x02, 0x80, 0x2D, 0x80 };
    const info_720p = parseAvcSps(&sps_720p);
    try std.testing.expect(!info_720p.is_truncated_or_invalid);
    try std.testing.expectEqual(@as(u8, 66), info_720p.profile_idc);
    try std.testing.expectEqual(@as(u32, 0), info_720p.seq_parameter_set_id);
    try std.testing.expectEqual(@as(u32, 2), info_720p.max_num_ref_frames);
    try std.testing.expectEqual(@as(u32, 1280), info_720p.computed_width);
    try std.testing.expectEqual(@as(u32, 720), info_720p.computed_height);

    // 2. Emulation prevention 0x00 0x00 0x03 0x01 -> 0x00 0x00 0x01
    const raw_emul = [_]u8{ 0x67, 0x00, 0x00, 0x03, 0x01, 0xAA };
    var rbsp_out: [32]u8 = undefined;
    const stripped = rbspFromNal(&raw_emul, &rbsp_out);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0x67, 0x00, 0x00, 0x01, 0xAA }, stripped);

    // 3. Valid High profile 1920x1080 SPS (with frame_cropping_flag=1, crop_bottom=4 -> 1088 - 4*2 = 1080)
    // Standard x264 High@L4.0 1920x1080 SPS:
    const sps_1080p = [_]u8{
        0x67, 0x64, 0x00, 0x28, 0xAC, 0xD9, 0x40, 0x78,
        0x02, 0x27, 0xE5, 0xC0, 0x44, 0x00, 0x00, 0x03,
        0x00, 0x04, 0x00, 0x00, 0x03, 0x00, 0xF0, 0x3C,
        0x60, 0xC6, 0x58,
    };
    const info_1080p = parseAvcSps(&sps_1080p);
    try std.testing.expect(!info_1080p.is_truncated_or_invalid);
    try std.testing.expectEqual(@as(u8, 100), info_1080p.profile_idc);
    try std.testing.expectEqual(@as(u32, 1), info_1080p.chroma_format_idc);
    try std.testing.expectEqual(@as(u32, 1920), info_1080p.computed_width);
    try std.testing.expectEqual(@as(u32, 1080), info_1080p.computed_height);
}

test "nalu_sps: crafted exploit SPS (OOB sps_id, chroma_format_idc, max_num_ref_frames, and 0x00000000 DoS)" {
    // 1. Crafted High profile SPS with:
    // sps_id = 40 (ue: 41 = 0b101001 -> 5 zeros + 101001 = 00000101 001)
    // chroma_format_idc = 7 (ue: 8 = 0b1000 -> 3 zeros + 1000 = 0001000)
    // bit_depth_luma_minus8 = 0 (1), bit_depth_chroma_minus8 = 0 (1), qpprime = 0 (0), scaling_matrix = 0 (0)
    // log2_max_frame_num_minus4 = 0 (1), poc_type = 0 (1), log2_max_poc_lsb_minus4 = 0 (1)
    // max_num_ref_frames = 64 (ue: 65 = 0b1000001 -> 6 zeros + 1000001)
    // gaps = 0, width_mbs = 0 (1), height_mbs = 0 (1), frame_mbs_only = 1, direct_8x8 = 0, crop = 0
    // Bits:
    // 00000101 001 | 0001000 | 1100 | 111 | 00000010 00001 | 0 1 1 1 0 0
    // Bytes: 0x05, 0x22, 0x33, 0x82, 0x05, 0xC0
    const exploit_sps = [_]u8{ 0x67, 0x64, 0x00, 0x28, 0x05, 0x22, 0x33, 0x81, 0x05, 0xC0 };
    const info = parseAvcSps(&exploit_sps);
    try std.testing.expect(!info.is_truncated_or_invalid);
    try std.testing.expectEqual(@as(u32, 40), info.seq_parameter_set_id);
    try std.testing.expectEqual(@as(u32, 7), info.chroma_format_idc);
    try std.testing.expectEqual(@as(u32, 64), info.max_num_ref_frames);

    // 2. Leading-zero DoS Exp-Golomb (all zeros -> >= 32 leading zeros -> safely returns truncated_or_invalid)
    const dos_sps = [_]u8{ 0x67, 0x42, 0x00, 0x1E, 0x00, 0x00, 0x00, 0x00, 0x00 };
    const dos_info = parseAvcSps(&dos_sps);
    try std.testing.expect(dos_info.is_truncated_or_invalid);
}
