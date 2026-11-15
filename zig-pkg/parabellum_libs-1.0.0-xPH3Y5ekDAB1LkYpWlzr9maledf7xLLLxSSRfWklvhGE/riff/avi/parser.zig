const std = @import("std");
const Allocator = std.mem.Allocator;
const riff = @import("../riff/mod.zig");
const field_reader = @import("../field_reader.zig");
const types = @import("types.zig");

pub const ByteSource = riff.ByteSource;
pub const DissectedChunk = riff.DissectedChunk;

/// Pure structural dissector for AVI (`avih`, `strh`, `strf`, `LIST movi`, `idx1`).
pub const AviDissector = struct {
    allocator: Allocator,

    pub fn init(allocator: Allocator) AviDissector {
        return .{ .allocator = allocator };
    }

    pub fn dissect(
        self: AviDissector,
        source: ByteSource,
        chunks: []const DissectedChunk,
    ) !types.AviDissectionResult {
        var main_header: ?types.AviMainHeader = null;
        var streams = std.ArrayList(types.AviStreamRecord).empty;
        errdefer streams.deinit(self.allocator);
        var sample_runs = std.ArrayList(types.AviSampleRun).empty;
        errdefer sample_runs.deinit(self.allocator);

        var movi_payload_offset: u64 = 0;
        var movi_payload_size: u64 = 0;
        var idx1_offset: u64 = 0;
        var idx1_size: u64 = 0;
        var idx1_entry_count: u32 = 0;

        for (chunks, 0..) |chunk, idx| {
            if (chunk.header.fourcc.equals(riff.types.CHUNK_AVIH) and chunk.payloadSize() >= 40) {
                const off = chunk.header.payloadOffset();
                main_header = .{
                    .micro_sec_per_frame = try field_reader.readU32Le(source, off + 0),
                    .max_bytes_per_sec = try field_reader.readU32Le(source, off + 4),
                    .flags = try field_reader.readU32Le(source, off + 12),
                    .total_frames = try field_reader.readU32Le(source, off + 16),
                    .streams = try field_reader.readU32Le(source, off + 24),
                    .suggested_buffer_size = try field_reader.readU32Le(source, off + 28),
                    .width = try field_reader.readU32Le(source, off + 32),
                    .height = try field_reader.readU32Le(source, off + 36),
                };
            } else if (chunk.header.fourcc.equals(riff.types.FOURCC_LIST)) {
                if (chunk.header.form_or_list_type) |lt| {
                    if (lt.equals(riff.types.LIST_STRL)) {
                        const stream_idx: u32 = @intCast(streams.items.len);
                        if (try self.parseStreamList(source, chunks, idx, stream_idx)) |rec| {
                            try streams.append(self.allocator, rec);
                        }
                    } else if (lt.equals(riff.types.LIST_MOVI)) {
                        if (movi_payload_offset == 0) {
                            movi_payload_offset = chunk.header.offset + 12;
                            movi_payload_size = if (chunk.containment.available_bytes > 12)
                                chunk.containment.available_bytes - 12
                            else
                                0;
                        }
                    }
                }
            } else if (chunk.header.fourcc.equals(riff.types.CHUNK_IDX1)) {
                idx1_offset = chunk.header.payloadOffset();
                idx1_size = chunk.payloadSize();
            }
        }

        if (idx1_size >= 16) {
            idx1_entry_count = try self.parseIdx1(source, idx1_offset, idx1_size, movi_payload_offset, &sample_runs);
        }

        return .{
            .allocator = self.allocator,
            .main_header = main_header,
            .streams = try streams.toOwnedSlice(self.allocator),
            .sample_runs = try sample_runs.toOwnedSlice(self.allocator),
            .movi_payload_offset = movi_payload_offset,
            .movi_payload_size = movi_payload_size,
            .idx1_offset = idx1_offset,
            .idx1_size = idx1_size,
            .idx1_entry_count = idx1_entry_count,
        };
    }

    fn parseStreamList(
        self: AviDissector,
        source: ByteSource,
        chunks: []const DissectedChunk,
        strl_idx: usize,
        stream_index: u32,
    ) !?types.AviStreamRecord {
        _ = self;
        var has_strh = false;
        var fcc_type: [4]u8 = .{ 0, 0, 0, 0 };
        var fcc_handler: [4]u8 = .{ 0, 0, 0, 0 };
        var scale: u32 = 0;
        var rate: u32 = 0;
        var length: u32 = 0;
        var suggested_buffer_size: u32 = 0;
        var strf_offset: u64 = 0;
        var strf_size: u64 = 0;
        var video: ?types.AviVideoFormat = null;
        var audio: ?types.AviAudioFormat = null;

        for (chunks, 0..) |sub, idx| {
            if (idx <= strl_idx) continue;
            if (sub.parent_id != @as(u32, @intCast(strl_idx))) continue;

            if (sub.header.fourcc.equals(riff.types.CHUNK_STRH) and sub.payloadSize() >= 40) {
                has_strh = true;
                const off = sub.header.payloadOffset();
                fcc_type = try field_reader.readFourCC(source, off + 0);
                fcc_handler = try field_reader.readFourCC(source, off + 4);
                scale = try field_reader.readU32Le(source, off + 20);
                rate = try field_reader.readU32Le(source, off + 24);
                length = try field_reader.readU32Le(source, off + 32);
                suggested_buffer_size = try field_reader.readU32Le(source, off + 36);
            } else if (sub.header.fourcc.equals(riff.types.CHUNK_STRF)) {
                strf_offset = sub.header.payloadOffset();
                strf_size = sub.payloadSize();
            }
        }

        if (!has_strh) return null;

        if (std.mem.eql(u8, &fcc_type, "vids") and strf_size >= 20) {
            const bi_size = try field_reader.readU32Le(source, strf_offset + 0);
            const w = try field_reader.readI32Le(source, strf_offset + 4);
            const h = try field_reader.readI32Le(source, strf_offset + 8);
            const planes = try field_reader.readU16Le(source, strf_offset + 12);
            const bpp = try field_reader.readU16Le(source, strf_offset + 14);
            const comp = try field_reader.readFourCC(source, strf_offset + 16);
            const size_image: u32 = if (strf_size >= 24) try field_reader.readU32Le(source, strf_offset + 20) else 0;
            const clr_used: u32 = if (strf_size >= 36) try field_reader.readU32Le(source, strf_offset + 32) else 0;

            var dim_overflow = (h == std.math.minInt(i32) or w == std.math.minInt(i32));
            if (!dim_overflow) {
                const abs_w: u32 = @intCast(@abs(w));
                const abs_h: u32 = @intCast(@abs(h));
                const eff_bpp: u32 = @max(@as(u32, bpp), 1);
                if (std.math.mul(u32, abs_w, abs_h)) |m1| {
                    if (std.math.mul(u32, m1, eff_bpp)) |_| {} else |_| {
                        dim_overflow = true;
                    }
                } else |_| {
                    dim_overflow = true;
                }
            }

            video = .{
                .bi_size = bi_size,
                .width = w,
                .height = h,
                .bi_planes = planes,
                .bit_count = bpp,
                .compression = comp,
                .bi_size_image = size_image,
                .bi_clr_used = clr_used,
                .strf_size = strf_size,
                .dim_mul_overflow = dim_overflow,
            };
        } else if (std.mem.eql(u8, &fcc_type, "auds") and strf_size >= 16) {
            audio = .{
                .format_tag = try field_reader.readU16Le(source, strf_offset + 0),
                .channels = try field_reader.readU16Le(source, strf_offset + 2),
                .samples_per_sec = try field_reader.readU32Le(source, strf_offset + 4),
                .bits_per_sample = try field_reader.readU16Le(source, strf_offset + 14),
            };
        }

        return .{
            .stream_index = stream_index,
            .fcc_type = fcc_type,
            .fcc_handler = fcc_handler,
            .scale = scale,
            .rate = rate,
            .length = length,
            .suggested_buffer_size = suggested_buffer_size,
            .strf_offset = strf_offset,
            .strf_size = strf_size,
            .video = video,
            .audio = audio,
        };
    }

    fn parseIdx1(
        self: AviDissector,
        source: ByteSource,
        idx1_offset: u64,
        idx1_size: u64,
        movi_payload_offset: u64,
        out_runs: *std.ArrayList(types.AviSampleRun),
    ) !u32 {
        const entry_count: u32 = @intCast(@min(idx1_size / 16, 65536));
        const movi_list_type_base = if (movi_payload_offset >= 4) movi_payload_offset - 4 else 0;

        var i: u32 = 0;
        while (i < entry_count) : (i += 1) {
            const off = idx1_offset + @as(u64, i) * 16;
            var entry_buf: [16]u8 = undefined;
            if ((try source.readAt(&entry_buf, off)) < 16) break;

            const stream_idx = parseStreamIndex(entry_buf[0..2]);
            const rel_offset = std.mem.readInt(u32, entry_buf[8..12], .little);
            const chunk_size = std.mem.readInt(u32, entry_buf[12..16], .little);
            const pad: u64 = if ((chunk_size & 1) == 1) 1 else 0;
            const total_len = 8 + @as(u64, chunk_size) + pad;

            const file_offset: u64 = if (movi_list_type_base > 0)
                movi_list_type_base + @as(u64, rel_offset)
            else
                @as(u64, rel_offset);

            if (out_runs.items.len > 0) {
                const last = &out_runs.items[out_runs.items.len - 1];
                if (last.stream_index == stream_idx and last.start_offset + last.byte_length == file_offset) {
                    last.byte_length += total_len;
                    last.chunk_count += 1;
                    continue;
                }
            }
            try out_runs.append(self.allocator, .{
                .stream_index = stream_idx,
                .start_offset = file_offset,
                .byte_length = total_len,
                .chunk_count = 1,
            });
        }
        return entry_count;
    }

    fn parseStreamIndex(digits: *const [2]u8) u32 {
        if (digits[0] >= '0' and digits[0] <= '9' and digits[1] >= '0' and digits[1] <= '9') {
            return @as(u32, digits[0] - '0') * 10 + @as(u32, digits[1] - '0');
        }
        return 0;
    }
};

