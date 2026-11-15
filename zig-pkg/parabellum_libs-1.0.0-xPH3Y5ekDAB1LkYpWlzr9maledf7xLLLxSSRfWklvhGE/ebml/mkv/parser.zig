const std = @import("std");
const Allocator = std.mem.Allocator;
const ebml = @import("../ebml/mod.zig");
const field_reader = @import("../field_reader.zig");
const types = @import("types.zig");

pub const ByteSource = ebml.ByteSource;
pub const DissectedElement = ebml.DissectedElement;
pub const ElementHeader = ebml.ElementHeader;

pub const MkvTrackRecord = types.MkvTrackRecord;
pub const MkvTrackType = types.MkvTrackType;
pub const MkvVideoConfig = types.MkvVideoConfig;
pub const MkvAudioConfig = types.MkvAudioConfig;
pub const MkvAvcConfig = types.MkvAvcConfig;
pub const SegmentInfo = types.SegmentInfo;
pub const MkvAttachment = types.MkvAttachment;
pub const ClusterSpan = types.ClusterSpan;
pub const SampleRun = types.SampleRun;
pub const MkvExternalRef = types.MkvExternalRef;
pub const CueRecord = types.CueRecord;
pub const LacingAnomaly = types.LacingAnomaly;
pub const MkvDissectionResult = types.MkvDissectionResult;

/// Pure structural dissector for Matroska / WebM (`Segment`, `Info`, `Tracks`, `Attachments`, `Clusters`).
pub const MkvDissector = struct {
    allocator: Allocator,

    pub fn init(allocator: Allocator) MkvDissector {
        return .{ .allocator = allocator };
    }

    pub fn dissect(
        self: MkvDissector,
        source: ByteSource,
        elements: []const DissectedElement,
    ) !MkvDissectionResult {
        var tracks = std.ArrayList(MkvTrackRecord).empty;
        errdefer tracks.deinit(self.allocator);

        var attachments = std.ArrayList(MkvAttachment).empty;
        errdefer attachments.deinit(self.allocator);

        var clusters = std.ArrayList(ClusterSpan).empty;
        errdefer clusters.deinit(self.allocator);

        var sample_runs = std.ArrayList(SampleRun).empty;
        errdefer sample_runs.deinit(self.allocator);

        var external_refs = std.ArrayList(MkvExternalRef).empty;
        errdefer {
            for (external_refs.items) |r| {
                if (r.filename.len > 0) self.allocator.free(r.filename);
            }
            external_refs.deinit(self.allocator);
        }

        var cues = std.ArrayList(CueRecord).empty;
        errdefer cues.deinit(self.allocator);

        var lacing_anomalies = std.ArrayList(LacingAnomaly).empty;
        errdefer lacing_anomalies.deinit(self.allocator);

        var info = SegmentInfo{};
        var has_tracks_element = false;
        var cluster_count: u32 = 0;
        var total_cluster_bytes: u64 = 0;
        var segment_payload_start: u64 = 0;
        var segment_end: u64 = 0;
        var header_ebml_max_size_length: u64 = 8;

        for (elements, 0..) |elem, idx| {
            if (elem.id == ebml.types.ID_SEGMENT) {
                segment_payload_start = elem.header.payloadOffset();
                segment_end = elem.header.offset +| elem.containment.available_bytes;
            } else if (elem.id == ebml.types.ID_EBML_MAX_SIZE_LENGTH) {
                header_ebml_max_size_length = try field_reader.readUint(source, elem.header.payloadOffset(), elem.payloadSize());
            } else if (elem.id == ebml.types.ID_INFO) {
                info = try self.parseInfo(source, elements, idx, &external_refs);
            } else if (elem.id == ebml.types.ID_TRACKS) {
                has_tracks_element = true;
                try self.parseTracks(source, elements, idx, &tracks);
            } else if (elem.id == ebml.types.ID_ATTACHMENTS) {
                try self.parseAttachments(source, elements, idx, &attachments);
            } else if (elem.id == ebml.types.ID_CUES) {
                try self.parseCues(source, elements, idx, segment_payload_start, segment_end, &cues);
            } else if (elem.id == ebml.types.ID_CLUSTER) {
                const span = ClusterSpan{
                    .cluster_index = cluster_count,
                    .offset = elem.header.offset,
                    .size = elem.containment.available_bytes,
                    .payload_offset = elem.header.payloadOffset(),
                    .payload_size = elem.payloadSize(),
                };
                try clusters.append(self.allocator, span);
                cluster_count += 1;
                total_cluster_bytes += elem.containment.available_bytes;
                try self.dissectClusterBlocks(source, span, &sample_runs, &lacing_anomalies);
            }
        }

        return MkvDissectionResult{
            .allocator = self.allocator,
            .info = info,
            .tracks = try tracks.toOwnedSlice(self.allocator),
            .attachments = try attachments.toOwnedSlice(self.allocator),
            .clusters = try clusters.toOwnedSlice(self.allocator),
            .sample_runs = try sample_runs.toOwnedSlice(self.allocator),
            .external_refs = try external_refs.toOwnedSlice(self.allocator),
            .cues = try cues.toOwnedSlice(self.allocator),
            .lacing_anomalies = try lacing_anomalies.toOwnedSlice(self.allocator),
            .segment_payload_start = segment_payload_start,
            .segment_end = segment_end,
            .header_ebml_max_size_length = header_ebml_max_size_length,
            .has_tracks_element = has_tracks_element,
            .cluster_count = cluster_count,
            .total_cluster_bytes = total_cluster_bytes,
        };
    }

    pub const inspect = dissect;

    fn parseInfo(
        self: MkvDissector,
        source: ByteSource,
        elements: []const DissectedElement,
        info_idx: usize,
        out_refs: *std.ArrayList(MkvExternalRef),
    ) !SegmentInfo {
        var info = SegmentInfo{};
        var str_buf: [256]u8 = undefined;

        for (elements, 0..) |elem, idx| {
            if (idx <= info_idx) continue;
            if (elem.parent_id != @as(u32, @intCast(info_idx))) continue;

            if (elem.id == ebml.types.ID_TIMECODE_SCALE) {
                info.timecode_scale = try field_reader.readUint(source, elem.header.payloadOffset(), elem.payloadSize());
            } else if (elem.id == ebml.types.ID_DURATION) {
                info.duration_ticks = try field_reader.readFloat(source, elem.header.payloadOffset(), elem.payloadSize());
            } else if (elem.id == ebml.types.ID_MUXING_APP) {
                const s = try field_reader.readString(source, &str_buf, elem.header.payloadOffset(), elem.payloadSize());
                if (s.len > 0) info.muxing_app = try self.allocator.dupe(u8, s);
            } else if (elem.id == ebml.types.ID_WRITING_APP) {
                const s = try field_reader.readString(source, &str_buf, elem.header.payloadOffset(), elem.payloadSize());
                if (s.len > 0) info.writing_app = try self.allocator.dupe(u8, s);
            } else if (elem.id == ebml.types.ID_NEXT_FILENAME or
                elem.id == ebml.types.ID_PREV_FILENAME or
                elem.id == ebml.types.ID_SEGMENT_FILENAME)
            {
                const s = try field_reader.readString(source, &str_buf, elem.header.payloadOffset(), elem.payloadSize());
                if (s.len > 0) {
                    try out_refs.append(self.allocator, .{
                        .element_id = elem.id,
                        .file_offset = elem.header.offset,
                        .filename = try self.allocator.dupe(u8, s),
                    });
                }
            }
        }

        return info;
    }

    fn parseCues(
        self: MkvDissector,
        source: ByteSource,
        elements: []const DissectedElement,
        cues_idx: usize,
        segment_payload_start: u64,
        segment_end: u64,
        out_cues: *std.ArrayList(CueRecord),
    ) !void {
        for (elements, 0..) |cp_elem, cp_idx| {
            if (cp_idx <= cues_idx) continue;
            if (cp_elem.parent_id != @as(u32, @intCast(cues_idx))) continue;
            if (cp_elem.id != ebml.types.ID_CUE_POINT) continue;

            var cue_time: u64 = 0;
            var track_num: u64 = 0;
            var cluster_pos: u64 = 0;
            var has_pos = false;

            for (elements, 0..) |sub, sub_idx| {
                if (sub_idx <= cp_idx) continue;
                if (sub.parent_id == @as(u32, @intCast(cp_idx))) {
                    if (sub.id == ebml.types.ID_CUE_TIME) {
                        cue_time = try field_reader.readUint(source, sub.header.payloadOffset(), sub.payloadSize());
                    } else if (sub.id == ebml.types.ID_CUE_TRACK_POSITIONS) {
                        for (elements, 0..) |tp, tp_idx| {
                            if (tp_idx <= sub_idx) continue;
                            if (tp.parent_id != @as(u32, @intCast(sub_idx))) continue;
                            if (tp.id == ebml.types.ID_CUE_TRACK) {
                                track_num = try field_reader.readUint(source, tp.header.payloadOffset(), tp.payloadSize());
                            } else if (tp.id == ebml.types.ID_CUE_CLUSTER_POSITION) {
                                cluster_pos = try field_reader.readUint(source, tp.header.payloadOffset(), tp.payloadSize());
                                has_pos = true;
                            }
                        }
                    }
                }
            }

            if (has_pos) {
                const abs_pos = segment_payload_start +| cluster_pos;
                const in_bounds = segment_end == 0 or (abs_pos >= segment_payload_start and abs_pos < segment_end);
                try out_cues.append(self.allocator, .{
                    .cue_time = cue_time,
                    .track_number = track_num,
                    .cluster_position = cluster_pos,
                    .in_segment_bounds = in_bounds,
                });
            }
        }
    }

    fn parseTracks(
        self: MkvDissector,
        source: ByteSource,
        elements: []const DissectedElement,
        tracks_idx: usize,
        out_tracks: *std.ArrayList(MkvTrackRecord),
    ) !void {
        for (elements, 0..) |elem, idx| {
            if (idx <= tracks_idx) continue;
            if (elem.parent_id != @as(u32, @intCast(tracks_idx))) continue;

            if (elem.id == ebml.types.ID_TRACK_ENTRY) {
                const track = try self.parseTrackEntry(source, elements, idx);
                try out_tracks.append(self.allocator, track);
            }
        }
    }

    fn parseTrackEntry(
        self: MkvDissector,
        source: ByteSource,
        elements: []const DissectedElement,
        entry_idx: usize,
    ) !MkvTrackRecord {
        var track_number: u32 = 0;
        var track_uid: u64 = 0;
        var track_type: MkvTrackType = .unknown;
        var codec_id_str: []const u8 = "";
        var codec_name_str: []const u8 = "";
        var default_duration: u64 = 0;
        var codec_private_offset: u64 = 0;
        var codec_private_size: u64 = 0;
        var avcc_config: ?MkvAvcConfig = null;
        var video_cfg: ?MkvVideoConfig = null;
        var audio_cfg: ?MkvAudioConfig = null;
        var str_buf: [128]u8 = undefined;

        for (elements, 0..) |elem, idx| {
            if (idx <= entry_idx) continue;
            if (elem.parent_id != @as(u32, @intCast(entry_idx))) continue;

            if (elem.id == ebml.types.ID_TRACK_NUMBER) {
                track_number = @truncate(try field_reader.readUint(source, elem.header.payloadOffset(), elem.payloadSize()));
            } else if (elem.id == ebml.types.ID_TRACK_UID) {
                track_uid = try field_reader.readUint(source, elem.header.payloadOffset(), elem.payloadSize());
            } else if (elem.id == ebml.types.ID_TRACK_TYPE) {
                const val = try field_reader.readUint(source, elem.header.payloadOffset(), elem.payloadSize());
                track_type = MkvTrackType.fromInt(val);
            } else if (elem.id == ebml.types.ID_CODEC_ID) {
                const s = try field_reader.readString(source, &str_buf, elem.header.payloadOffset(), elem.payloadSize());
                if (s.len > 0) codec_id_str = try self.allocator.dupe(u8, s);
            } else if (elem.id == ebml.types.ID_CODEC_NAME) {
                const s = try field_reader.readString(source, &str_buf, elem.header.payloadOffset(), elem.payloadSize());
                if (s.len > 0) codec_name_str = try self.allocator.dupe(u8, s);
            } else if (elem.id == ebml.types.ID_DEFAULT_DURATION) {
                default_duration = try field_reader.readUint(source, elem.header.payloadOffset(), elem.payloadSize());
            } else if (elem.id == ebml.types.ID_CODEC_PRIVATE) {
                codec_private_offset = elem.header.payloadOffset();
                codec_private_size = elem.payloadSize();
            } else if (elem.id == ebml.types.ID_VIDEO) {
                video_cfg = try self.parseVideoElement(source, elements, idx);
            } else if (elem.id == ebml.types.ID_AUDIO) {
                audio_cfg = try self.parseAudioElement(source, elements, idx);
            }
        }

        if (codec_private_size >= 7 and std.mem.eql(u8, codec_id_str, "V_MPEG4/ISO/AVC")) {
            avcc_config = try self.parseAvcC(source, codec_private_offset, codec_private_size);
        }

        return MkvTrackRecord{
            .track_number = track_number,
            .track_uid = track_uid,
            .track_type = track_type,
            .codec_id = codec_id_str,
            .codec_name = codec_name_str,
            .default_duration_ns = default_duration,
            .video = video_cfg,
            .audio = audio_cfg,
            .codec_private_offset = codec_private_offset,
            .codec_private_size = codec_private_size,
            .avcc = avcc_config,
        };
    }

    fn parseVideoElement(
        self: MkvDissector,
        source: ByteSource,
        elements: []const DissectedElement,
        video_idx: usize,
    ) !MkvVideoConfig {
        _ = self;
        var cfg = MkvVideoConfig{};

        for (elements, 0..) |elem, idx| {
            if (idx <= video_idx) continue;
            if (elem.parent_id != @as(u32, @intCast(video_idx))) continue;

            if (elem.id == ebml.types.ID_PIXEL_WIDTH) {
                cfg.pixel_width = @truncate(try field_reader.readUint(source, elem.header.payloadOffset(), elem.payloadSize()));
            } else if (elem.id == ebml.types.ID_PIXEL_HEIGHT) {
                cfg.pixel_height = @truncate(try field_reader.readUint(source, elem.header.payloadOffset(), elem.payloadSize()));
            } else if (elem.id == ebml.types.ID_DISPLAY_WIDTH) {
                cfg.display_width = @truncate(try field_reader.readUint(source, elem.header.payloadOffset(), elem.payloadSize()));
            } else if (elem.id == ebml.types.ID_DISPLAY_HEIGHT) {
                cfg.display_height = @truncate(try field_reader.readUint(source, elem.header.payloadOffset(), elem.payloadSize()));
            }
        }

        return cfg;
    }

    fn parseAudioElement(
        self: MkvDissector,
        source: ByteSource,
        elements: []const DissectedElement,
        audio_idx: usize,
    ) !MkvAudioConfig {
        _ = self;
        var cfg = MkvAudioConfig{};

        for (elements, 0..) |elem, idx| {
            if (idx <= audio_idx) continue;
            if (elem.parent_id != @as(u32, @intCast(audio_idx))) continue;

            if (elem.id == ebml.types.ID_SAMPLING_FREQUENCY) {
                cfg.sampling_frequency = try field_reader.readFloat(source, elem.header.payloadOffset(), elem.payloadSize());
            } else if (elem.id == ebml.types.ID_CHANNELS) {
                cfg.channels = @truncate(try field_reader.readUint(source, elem.header.payloadOffset(), elem.payloadSize()));
            } else if (elem.id == ebml.types.ID_BIT_DEPTH) {
                cfg.bit_depth = @truncate(try field_reader.readUint(source, elem.header.payloadOffset(), elem.payloadSize()));
            }
        }

        return cfg;
    }

    fn parseAttachments(
        self: MkvDissector,
        source: ByteSource,
        elements: []const DissectedElement,
        att_idx: usize,
        out: *std.ArrayList(MkvAttachment),
    ) !void {
        var str_buf: [256]u8 = undefined;
        for (elements, 0..) |elem, idx| {
            if (idx <= att_idx) continue;
            if (elem.parent_id != @as(u32, @intCast(att_idx))) continue;
            if (elem.id != ebml.types.ID_ATTACHED_FILE) continue;

            var file_name: []const u8 = "";
            var mime_type: []const u8 = "";
            var data_offset: u64 = 0;
            var data_size: u64 = 0;

            for (elements, 0..) |sub, sub_idx| {
                if (sub_idx <= idx) continue;
                if (sub.parent_id != @as(u32, @intCast(idx))) continue;
                if (sub.id == ebml.types.ID_FILE_NAME) {
                    const s = try field_reader.readString(source, &str_buf, sub.header.payloadOffset(), sub.payloadSize());
                    if (s.len > 0) file_name = try self.allocator.dupe(u8, s);
                } else if (sub.id == ebml.types.ID_FILE_MIME_TYPE) {
                    const s = try field_reader.readString(source, &str_buf, sub.header.payloadOffset(), sub.payloadSize());
                    if (s.len > 0) mime_type = try self.allocator.dupe(u8, s);
                } else if (sub.id == ebml.types.ID_FILE_DATA) {
                    data_offset = sub.header.payloadOffset();
                    data_size = sub.payloadSize();
                }
            }
            try out.append(self.allocator, .{
                .file_name = file_name,
                .mime_type = mime_type,
                .data_offset = data_offset,
                .data_size = data_size,
            });
        }
    }

    fn checkBlockLacing(
        self: MkvDissector,
        source: ByteSource,
        block_offset: u64,
        payload_off: u64,
        payload_len: u64,
        trk_len: u64,
        out_anomalies: *std.ArrayList(LacingAnomaly),
    ) !void {
        const hdr_after_trk = trk_len + 3; // 2-byte timecode + 1-byte flags
        if (payload_len < hdr_after_trk) return;
        const flags = try field_reader.readU8(source, payload_off + trk_len + 2);
        const lacing: u8 = (flags >> 1) & 0x03;
        if (lacing == 0) return;

        var pos = hdr_after_trk;
        if (pos >= payload_len) {
            try out_anomalies.append(self.allocator, .{
                .offset = block_offset,
                .lacing_kind = lacing,
                .frame_count = 0,
                .payload_size = payload_len,
            });
            return;
        }
        const frame_count: u16 = @as(u16, try field_reader.readU8(source, payload_off + pos)) + 1;
        pos += 1;

        if (lacing == 1) {
            // Xiph lacing: frame_count - 1 sizes, sum must fit in remaining payload
            var sum: u64 = 0;
            var i: u16 = 0;
            while (i + 1 < frame_count) : (i += 1) {
                var fsize: u64 = 0;
                while (true) {
                    if (pos >= payload_len) {
                        try out_anomalies.append(self.allocator, .{
                            .offset = block_offset,
                            .lacing_kind = lacing,
                            .frame_count = frame_count,
                            .payload_size = payload_len,
                        });
                        return;
                    }
                    const b = try field_reader.readU8(source, payload_off + pos);
                    pos += 1;
                    fsize +|= b;
                    if (b != 255) break;
                }
                sum +|= fsize;
            }
            if (pos +| sum > payload_len) {
                try out_anomalies.append(self.allocator, .{
                    .offset = block_offset,
                    .lacing_kind = lacing,
                    .frame_count = frame_count,
                    .payload_size = payload_len,
                });
            }
        } else if (lacing == 2) {
            // Fixed-size lacing: remaining bytes must be divisible by frame_count
            const rem = payload_len - pos;
            if (rem < frame_count or (rem % frame_count) != 0) {
                try out_anomalies.append(self.allocator, .{
                    .offset = block_offset,
                    .lacing_kind = lacing,
                    .frame_count = frame_count,
                    .payload_size = payload_len,
                });
            }
        } else if (lacing == 3) {
            // EBML lacing: first VINT frame size + signed VINT deltas
            const first = (try ebml.readVint(source, payload_off + pos)) orelse {
                try out_anomalies.append(self.allocator, .{
                    .offset = block_offset,
                    .lacing_kind = lacing,
                    .frame_count = frame_count,
                    .payload_size = payload_len,
                });
                return;
            };
            pos += first.length;
            var sum: u64 = first.data_value;
            var cur_size: i64 = @intCast(@min(first.data_value, std.math.maxInt(i64)));
            var i: u16 = 1;
            while (i + 1 < frame_count) : (i += 1) {
                const dv = (try ebml.readVint(source, payload_off + pos)) orelse {
                    try out_anomalies.append(self.allocator, .{
                        .offset = block_offset,
                        .lacing_kind = lacing,
                        .frame_count = frame_count,
                        .payload_size = payload_len,
                    });
                    return;
                };
                pos += dv.length;
                const bias: i64 = @as(i64, 1) << @intCast(@as(u6, @intCast(dv.length * 7 - 1)));
                const delta: i64 = @as(i64, @intCast(@min(dv.data_value, std.math.maxInt(i64)))) - (bias - 1);
                cur_size +|= delta;
                if (cur_size < 0) {
                    try out_anomalies.append(self.allocator, .{
                        .offset = block_offset,
                        .lacing_kind = lacing,
                        .frame_count = frame_count,
                        .payload_size = payload_len,
                    });
                    return;
                }
                sum +|= @as(u64, @intCast(cur_size));
            }
            if (pos +| sum > payload_len) {
                try out_anomalies.append(self.allocator, .{
                    .offset = block_offset,
                    .lacing_kind = lacing,
                    .frame_count = frame_count,
                    .payload_size = payload_len,
                });
            }
        }
    }

    fn dissectClusterBlocks(
        self: MkvDissector,
        source: ByteSource,
        cluster: ClusterSpan,
        out_runs: *std.ArrayList(SampleRun),
        out_anomalies: *std.ArrayList(LacingAnomaly),
    ) !void {
        var off = cluster.payload_offset;
        const end = cluster.payload_offset +| cluster.payload_size;
        while (off < end) {
            const hdr = (try ebml.readElementHeader(source, off)) orelse break;
            const elem_end = if (hdr.is_unknown_size) end else @min(off +| hdr.totalSize(), end);
            if (elem_end <= off) break;

            if (hdr.id == ebml.types.ID_SIMPLE_BLOCK or hdr.id == ebml.types.ID_BLOCK) {
                const payload_off = hdr.payloadOffset();
                const payload_len = if (elem_end > payload_off) elem_end - payload_off else 0;
                if (payload_len > 0) {
                    if (try ebml.readVint(source, payload_off)) |trk_vint| {
                        try self.checkBlockLacing(source, off, payload_off, payload_len, trk_vint.length, out_anomalies);
                        const track_num: u32 = @truncate(trk_vint.data_value);
                        if (out_runs.items.len > 0) {
                            const last = &out_runs.items[out_runs.items.len - 1];
                            if (last.track_number == track_num and last.start_offset + last.byte_length == off) {
                                last.byte_length += (elem_end - off);
                                last.block_count += 1;
                                off = elem_end;
                                continue;
                            }
                        }
                        try out_runs.append(self.allocator, .{
                            .track_number = track_num,
                            .start_offset = off,
                            .byte_length = elem_end - off,
                            .block_count = 1,
                        });
                    }
                }
            } else if (hdr.id == ebml.types.ID_BLOCK_GROUP) {
                var sub_off = hdr.payloadOffset();
                while (sub_off < elem_end) {
                    const sub_hdr = (try ebml.readElementHeader(source, sub_off)) orelse break;
                    const sub_end = if (sub_hdr.is_unknown_size) elem_end else @min(sub_off +| sub_hdr.totalSize(), elem_end);
                    if (sub_end <= sub_off) break;
                    if (sub_hdr.id == ebml.types.ID_BLOCK) {
                        const p_off = sub_hdr.payloadOffset();
                        if (sub_end > p_off) {
                            if (try ebml.readVint(source, p_off)) |trk_vint| {
                                try self.checkBlockLacing(source, sub_off, p_off, sub_end - p_off, trk_vint.length, out_anomalies);
                                const track_num: u32 = @truncate(trk_vint.data_value);
                                try out_runs.append(self.allocator, .{
                                    .track_number = track_num,
                                    .start_offset = sub_off,
                                    .byte_length = sub_end - sub_off,
                                    .block_count = 1,
                                });
                            }
                        }
                    }
                    sub_off = sub_end;
                }
            }

            off = elem_end;
        }
    }

    fn parseAvcC(
        self: MkvDissector,
        source: ByteSource,
        offset: u64,
        data_size: u64,
    ) !?MkvAvcConfig {
        _ = self;
        if (data_size < 7) return null;

        var buf: [64]u8 = undefined;
        const read_n = try source.readAt(&buf, offset);
        if (read_n < 7) return null;

        const profile = buf[1];
        const level = buf[3];
        const num_sps = buf[5] & 0x1F;

        var cursor: usize = 6;
        var sps_bytes_total: u32 = 0;

        var i: u8 = 0;
        while (i < num_sps and cursor + 2 <= read_n) : (i += 1) {
            const sps_len = std.mem.readInt(u16, buf[cursor..][0..2], .big);
            cursor += 2;
            sps_bytes_total += sps_len;
            if (cursor + sps_len > data_size) break;
            cursor += sps_len;
        }

        var num_pps: u8 = 0;
        var pps_bytes_total: u32 = 0;

        if (cursor < read_n) {
            num_pps = buf[cursor];
            cursor += 1;

            var j: u8 = 0;
            while (j < num_pps and cursor + 2 <= read_n) : (j += 1) {
                const pps_len = std.mem.readInt(u16, buf[cursor..][0..2], .big);
                cursor += 2;
                pps_bytes_total += pps_len;
                if (cursor + pps_len > data_size) break;
                cursor += pps_len;
            }
        }

        return MkvAvcConfig{
            .profile = profile,
            .level = level,
            .sps_count = num_sps,
            .pps_count = num_pps,
            .sps_bytes_total = sps_bytes_total,
            .pps_bytes_total = pps_bytes_total,
        };
    }
};

pub const MkvInspector = MkvDissector;
