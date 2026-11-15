const std = @import("std");
const ByteSource = @import("../byte_source.zig").ByteSource;
const fr = @import("../field_reader.zig");
const box = @import("../box/mod.zig");
const box_constants = @import("../box/box_constants.zig");
const types = @import("types.zig");

pub const FourCC = box.FourCC;
pub const DissectedBox = box.DissectedBox;
pub const FtypInfo = types.FtypInfo;
pub const TrackRecord = types.TrackRecord;
pub const SampleRun = types.SampleRun;
pub const TableMeasurement = types.TableMeasurement;
pub const ExternalRefRecord = types.ExternalRefRecord;
pub const AttachmentRecord = types.AttachmentRecord;
pub const CodecHeaderMeasurement = types.CodecHeaderMeasurement;
pub const AvcCConfig = types.AvcCConfig;
pub const EsdsConfig = types.EsdsConfig;
pub const Mp4DissectionResult = @import("mp4_inspection_result.zig").Mp4DissectionResult;

const BOX_AVCC = FourCC.init("avcC");
const BOX_HVCC = FourCC.init("hvcC");
const BOX_ESDS = FourCC.init("esds");
const BOX_DATA = FourCC.init("data");

const StscEntry = struct {
    first_chunk: u32,
    samples_per_chunk: u32,
};

/// Pure, policy-free MP4 dissector extracting `ftyp`, `TrackRecord`s,
/// `TableMeasurement`s, and coalesced `SampleRun`s.
pub const Mp4Dissector = struct {
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator) Mp4Dissector {
        return .{ .allocator = allocator };
    }

    pub fn dissect(self: Mp4Dissector, source: ByteSource, boxes: []const DissectedBox) !Mp4DissectionResult {
        var ftyp_info: ?FtypInfo = null;
        errdefer if (ftyp_info) |f| self.allocator.free(f.compatible_brands);

        var tracks: std.ArrayList(TrackRecord) = .empty;
        errdefer tracks.deinit(self.allocator);

        var runs: std.ArrayList(SampleRun) = .empty;
        errdefer runs.deinit(self.allocator);

        var tables: std.ArrayList(TableMeasurement) = .empty;
        errdefer tables.deinit(self.allocator);

        var external_refs: std.ArrayList(ExternalRefRecord) = .empty;
        errdefer {
            for (external_refs.items) |r| {
                if (r.uri.len > 0) self.allocator.free(r.uri);
            }
            external_refs.deinit(self.allocator);
        }

        var attachments: std.ArrayList(AttachmentRecord) = .empty;
        errdefer attachments.deinit(self.allocator);

        var codec_headers: std.ArrayList(CodecHeaderMeasurement) = .empty;
        errdefer codec_headers.deinit(self.allocator);

        var mdat_total_bytes: u64 = 0;

        for (boxes) |b| {
            if (b.fourcc.equals(box_constants.BOX_FTYP) and ftyp_info == null) {
                ftyp_info = try self.parseFtyp(source, b);
            } else if (b.fourcc.equals(box_constants.BOX_MDAT)) {
                mdat_total_bytes +|= b.payloadSize();
            } else if (b.fourcc.equals(box_constants.BOX_TRAK)) {
                const tr = try self.parseTrak(source, boxes, b.id, &runs, &tables, &external_refs, &codec_headers);
                try tracks.append(self.allocator, tr);
            } else if (b.fourcc.equals(box_constants.BOX_RDRF)) {
                try self.parseRdrf(source, b, &external_refs);
            } else if (b.fourcc.equals(box_constants.BOX_COVR)) {
                try self.parseCovr(source, b, &attachments);
            }
        }

        return .{
            .allocator = self.allocator,
            .ftyp = ftyp_info,
            .tracks = try tracks.toOwnedSlice(self.allocator),
            .sample_runs = try runs.toOwnedSlice(self.allocator),
            .table_measurements = try tables.toOwnedSlice(self.allocator),
            .external_refs = try external_refs.toOwnedSlice(self.allocator),
            .attachments = try attachments.toOwnedSlice(self.allocator),
            .codec_headers = try codec_headers.toOwnedSlice(self.allocator),
            .mdat_total_bytes = mdat_total_bytes,
        };
    }

    fn parseFtyp(self: Mp4Dissector, source: ByteSource, b: DissectedBox) !?FtypInfo {
        const psize = b.payloadSize();
        if (psize < 8) return null;
        const major = try fr.readFourCC(source, b.payload_offset);
        const minor = try fr.readU32Be(source, b.payload_offset + 4);

        const compat_bytes = psize - 8;
        const brand_count: usize = @intCast(compat_bytes / 4);
        const capped_count = @min(brand_count, 128);
        const brands = try self.allocator.alloc(FourCC, capped_count);
        errdefer self.allocator.free(brands);

        var i: usize = 0;
        while (i < capped_count) : (i += 1) {
            brands[i] = try fr.readFourCC(source, b.payload_offset + 8 + i * 4);
        }

        return FtypInfo{
            .major_brand = major,
            .minor_version = minor,
            .compatible_brands = brands,
        };
    }

    fn isDescendantOf(boxes: []const DissectedBox, box_id: u32, ancestor_id: u32) bool {
        var curr: ?u32 = boxes[box_id].parent_id;
        while (curr) |pid| {
            if (pid == ancestor_id) return true;
            curr = boxes[pid].parent_id;
        }
        return false;
    }

    fn parseTrak(
        self: Mp4Dissector,
        source: ByteSource,
        boxes: []const DissectedBox,
        trak_id: u32,
        runs: *std.ArrayList(SampleRun),
        tables: *std.ArrayList(TableMeasurement),
        external_refs: *std.ArrayList(ExternalRefRecord),
        codec_headers: *std.ArrayList(CodecHeaderMeasurement),
    ) !TrackRecord {
        var tr = TrackRecord{};

        var stsc_box: ?DissectedBox = null;
        var stsz_box: ?DissectedBox = null;
        var stco_box: ?DissectedBox = null;
        var co64_box: ?DissectedBox = null;
        var dref_box: ?DissectedBox = null;

        for (boxes) |b| {
            if (!isDescendantOf(boxes, b.id, trak_id)) continue;
            const psize = b.payloadSize();

            if (b.fourcc.equals(box_constants.BOX_TKHD)) {
                if (b.version == 0 and psize >= 84) {
                    tr.track_id = try fr.readU32Be(source, b.payload_offset + 12);
                    tr.width = (try fr.readU32Be(source, b.payload_offset + 76)) >> 16;
                    tr.height = (try fr.readU32Be(source, b.payload_offset + 80)) >> 16;
                } else if (b.version == 1 and psize >= 96) {
                    tr.track_id = try fr.readU32Be(source, b.payload_offset + 20);
                    tr.width = (try fr.readU32Be(source, b.payload_offset + 88)) >> 16;
                    tr.height = (try fr.readU32Be(source, b.payload_offset + 92)) >> 16;
                }
            } else if (b.fourcc.equals(box_constants.BOX_MDHD)) {
                if (b.version == 0 and psize >= 24) {
                    tr.timescale = try fr.readU32Be(source, b.payload_offset + 12);
                    tr.duration = try fr.readU32Be(source, b.payload_offset + 16);
                } else if (b.version == 1 and psize >= 36) {
                    tr.timescale = try fr.readU32Be(source, b.payload_offset + 20);
                    tr.duration = try fr.readU64Be(source, b.payload_offset + 24);
                }
            } else if (b.fourcc.equals(box_constants.BOX_HDLR) and psize >= 12) {
                tr.handler_type = try fr.readFourCC(source, b.payload_offset + 8);
            } else if (b.fourcc.equals(box_constants.BOX_DREF)) {
                dref_box = b;
            } else if (b.fourcc.equals(box_constants.BOX_STSD)) {
                try self.parseStsd(source, b, &tr, tables, codec_headers);
            } else if (b.fourcc.equals(box_constants.BOX_STTS) or b.fourcc.equals(box_constants.BOX_CTTS)) {
                try self.recordTable(source, b, 8, 8, tables);
            } else if (b.fourcc.equals(box_constants.BOX_STSC)) {
                stsc_box = b;
                try self.recordTable(source, b, 8, 12, tables);
            } else if (b.fourcc.equals(box_constants.BOX_STSZ)) {
                stsz_box = b;
                if (psize >= 12) {
                    const uniform = try fr.readU32Be(source, b.payload_offset + 4);
                    const count = try fr.readU32Be(source, b.payload_offset + 8);
                    tr.sample_count = count;
                    const esize: u32 = if (uniform == 0) 4 else 0;
                    try self.appendTableMeasurement(b, count, esize, 12, tables);
                }
            } else if (b.fourcc.equals(box_constants.BOX_STCO)) {
                stco_box = b;
                if (psize >= 8) {
                    tr.chunk_count = try fr.readU32Be(source, b.payload_offset + 4);
                    try self.appendTableMeasurement(b, tr.chunk_count, 4, 8, tables);
                }
            } else if (b.fourcc.equals(box_constants.BOX_CO64)) {
                co64_box = b;
                if (psize >= 8) {
                    tr.chunk_count = try fr.readU32Be(source, b.payload_offset + 4);
                    try self.appendTableMeasurement(b, tr.chunk_count, 8, 8, tables);
                }
            }
        }

        if (dref_box) |db| {
            try self.parseDref(source, db, tr.track_id, external_refs);
        }

        if (stsz_box != null and (stco_box != null or co64_box != null)) {
            try self.extractSampleRuns(source, tr.track_id, stsc_box, stsz_box.?, stco_box, co64_box, runs);
        }

        return tr;
    }

    fn recordTable(
        self: Mp4Dissector,
        source: ByteSource,
        b: DissectedBox,
        header_bytes: u64,
        entry_size: u32,
        tables: *std.ArrayList(TableMeasurement),
    ) !void {
        if (b.payloadSize() < header_bytes) return;
        const count = try fr.readU32Be(source, b.payload_offset + 4);
        try self.appendTableMeasurement(b, count, entry_size, header_bytes, tables);
    }

    fn appendTableMeasurement(
        self: Mp4Dissector,
        b: DissectedBox,
        count: u32,
        entry_size: u32,
        header_bytes: u64,
        tables: *std.ArrayList(TableMeasurement),
    ) !void {
        const psize = b.payloadSize();
        const mul = @mulWithOverflow(@as(u64, count), @as(u64, entry_size));
        const add = @addWithOverflow(header_bytes, mul[0]);
        const overflow = mul[1] != 0 or add[1] != 0 or add[0] > psize;
        try tables.append(self.allocator, .{
            .table_fourcc = b.fourcc,
            .path = b.path,
            .entry_count = count,
            .entry_size = entry_size,
            .claimed_bytes = if (mul[1] != 0 or add[1] != 0) std.math.maxInt(u64) else add[0],
            .payload_size = psize,
            .is_overflow = overflow,
            .has_arith_overflow = mul[1] != 0 or add[1] != 0,
        });
    }

    fn parseStsd(
        self: Mp4Dissector,
        source: ByteSource,
        stsd_box: DissectedBox,
        tr: *TrackRecord,
        tables: *std.ArrayList(TableMeasurement),
        codec_headers: *std.ArrayList(CodecHeaderMeasurement),
    ) !void {
        const psize = stsd_box.payloadSize();
        if (psize < 16) return;
        const entry_count = try fr.readU32Be(source, stsd_box.payload_offset + 4);
        if (entry_count == 0) return;

        const entry_off = stsd_box.payload_offset + 8;
        const entry_size = try fr.readU32Be(source, entry_off);
        const entry_fourcc = try fr.readFourCC(source, entry_off + 4);
        tr.codec_fourcc = entry_fourcc;

        const stsd_end = stsd_box.payload_offset + psize;
        const entry_end = @min(stsd_end, entry_off +| entry_size);
        if (entry_size < 16) return;

        // VisualSampleEntry has 86-byte header (8 + 78), AudioSampleEntry has 36-byte header (8 + 28)
        const child_start: u64 = if (tr.handler_type.equals(FourCC.init("vide")))
            entry_off + 86
        else if (tr.handler_type.equals(FourCC.init("soun")))
            entry_off + 36
        else
            entry_off + 16;

        var cur = child_start;
        while (cur + 8 <= entry_end) {
            const csize = try fr.readU32Be(source, cur);
            const cfourcc = try fr.readFourCC(source, cur + 4);
            if (csize < 8) break;
            const cend = @min(entry_end, cur + csize);
            const cpay_off = cur + 8;
            const cpay_len = cend - cpay_off;

            if (cfourcc.equals(BOX_AVCC)) {
                tr.avcc = try self.parseAvcC(source, tr.track_id, cpay_off, cpay_len, stsd_box.path, tables, codec_headers);
            } else if (cfourcc.equals(BOX_HVCC)) {
                try self.parseHvcC(source, tr.track_id, cpay_off, cpay_len, stsd_box.path, tables, codec_headers);
            } else if (cfourcc.equals(BOX_ESDS)) {
                tr.esds = try self.parseEsds(source, tr.track_id, cpay_off, cpay_len, stsd_box.path, tables, codec_headers);
            }
            cur = cend;
        }
    }

    fn parseAvcC(
        self: Mp4Dissector,
        source: ByteSource,
        track_id: u32,
        off: u64,
        len: u64,
        parent_path: []const u8,
        tables: *std.ArrayList(TableMeasurement),
        codec_headers: *std.ArrayList(CodecHeaderMeasurement),
    ) !?AvcCConfig {
        if (len < 7) {
            try codec_headers.append(self.allocator, .{
                .track_id = track_id,
                .codec_tag = BOX_AVCC,
                .kind = .avcc,
                .is_malformed = true,
                .claimed_bytes = 7,
                .payload_size = len,
            });
            return null;
        }
        const cfg_ver = try fr.readU8(source, off);
        const prof = try fr.readU8(source, off + 1);
        const compat = try fr.readU8(source, off + 2);
        const level = try fr.readU8(source, off + 3);
        const len_m1: u2 = @truncate((try fr.readU8(source, off + 4)) & 0x03);
        const sps_count: u8 = (try fr.readU8(source, off + 5)) & 0x1F;

        var pos: u64 = 6;
        var sps_bytes: u32 = 0;
        var overflow = false;
        var i: u8 = 0;
        while (i < sps_count) : (i += 1) {
            if (pos + 2 > len) {
                overflow = true;
                break;
            }
            const nlen = try fr.readU16Be(source, off + pos);
            pos += 2;
            if (pos + nlen > len) {
                overflow = true;
                break;
            }
            sps_bytes +|= nlen;
            pos += nlen;
        }

        var pps_count: u8 = 0;
        var pps_bytes: u32 = 0;
        if (!overflow and pos < len) {
            pps_count = try fr.readU8(source, off + pos);
            pos += 1;
            var j: u8 = 0;
            while (j < pps_count) : (j += 1) {
                if (pos + 2 > len) {
                    overflow = true;
                    break;
                }
                const nlen = try fr.readU16Be(source, off + pos);
                pos += 2;
                if (pos + nlen > len) {
                    overflow = true;
                    break;
                }
                pps_bytes +|= nlen;
                pos += nlen;
            }
        }

        try tables.append(self.allocator, .{
            .table_fourcc = BOX_AVCC,
            .path = parent_path,
            .entry_count = @as(u32, sps_count) + @as(u32, pps_count),
            .entry_size = 1,
            .claimed_bytes = pos,
            .payload_size = len,
            .is_overflow = overflow,
        });

        try codec_headers.append(self.allocator, .{
            .track_id = track_id,
            .codec_tag = BOX_AVCC,
            .kind = .avcc,
            .is_malformed = overflow or cfg_ver != 1 or len_m1 == 2,
            .length_size_minus_one = len_m1,
            .sps_count = sps_count,
            .pps_count = pps_count,
            .claimed_bytes = pos,
            .payload_size = len,
        });

        return AvcCConfig{
            .configuration_version = cfg_ver,
            .profile_indication = prof,
            .profile_compatibility = compat,
            .level_indication = level,
            .length_size_minus_one = len_m1,
            .sps_count = sps_count,
            .pps_count = pps_count,
            .sps_bytes_total = sps_bytes,
            .pps_bytes_total = pps_bytes,
        };
    }

    fn parseHvcC(
        self: Mp4Dissector,
        source: ByteSource,
        track_id: u32,
        off: u64,
        len: u64,
        parent_path: []const u8,
        tables: *std.ArrayList(TableMeasurement),
        codec_headers: *std.ArrayList(CodecHeaderMeasurement),
    ) !void {
        if (len < 23) {
            try codec_headers.append(self.allocator, .{
                .track_id = track_id,
                .codec_tag = BOX_HVCC,
                .kind = .hvcc,
                .is_malformed = true,
                .claimed_bytes = 23,
                .payload_size = len,
            });
            return;
        }
        const cfg_ver = try fr.readU8(source, off);
        const len_m1: u2 = @truncate((try fr.readU8(source, off + 21)) & 0x03);
        const num_arrays = try fr.readU8(source, off + 22);
        var pos: u64 = 23;
        var overflow = false;

        var a: u8 = 0;
        while (a < num_arrays) : (a += 1) {
            if (pos + 3 > len) {
                overflow = true;
                break;
            }
            const num_nalus = try fr.readU16Be(source, off + pos + 1);
            pos += 3;
            var n: u16 = 0;
            while (n < num_nalus) : (n += 1) {
                if (pos + 2 > len) {
                    overflow = true;
                    break;
                }
                const nalu_len = try fr.readU16Be(source, off + pos);
                pos += 2;
                if (pos + nalu_len > len) {
                    overflow = true;
                    break;
                }
                pos += nalu_len;
            }
            if (overflow) break;
        }

        try tables.append(self.allocator, .{
            .table_fourcc = BOX_HVCC,
            .path = parent_path,
            .entry_count = num_arrays,
            .entry_size = 3,
            .claimed_bytes = pos,
            .payload_size = len,
            .is_overflow = overflow,
        });

        try codec_headers.append(self.allocator, .{
            .track_id = track_id,
            .codec_tag = BOX_HVCC,
            .kind = .hvcc,
            .is_malformed = overflow or cfg_ver != 1 or len_m1 == 2,
            .length_size_minus_one = len_m1,
            .array_count = num_arrays,
            .claimed_bytes = pos,
            .payload_size = len,
        });
    }

    fn parseEsds(
        self: Mp4Dissector,
        source: ByteSource,
        track_id: u32,
        off: u64,
        len: u64,
        parent_path: []const u8,
        tables: *std.ArrayList(TableMeasurement),
        codec_headers: *std.ArrayList(CodecHeaderMeasurement),
    ) !?EsdsConfig {
        if (len < 4) {
            try codec_headers.append(self.allocator, .{
                .track_id = track_id,
                .codec_tag = BOX_ESDS,
                .kind = .esds,
                .is_malformed = true,
                .claimed_bytes = 4,
                .payload_size = len,
            });
            return null;
        }
        var cfg = EsdsConfig{};
        var pos: u64 = 4; // skip FullBox version + flags
        var overflow = false;

        if (pos + 2 <= len and (try fr.readU8(source, off + pos)) == 0x03) {
            pos += 1;
            const es_tlv = try fr.readTlvLength(source, off + pos);
            pos += es_tlv.bytes_consumed;
            if (pos + es_tlv.value > len) overflow = true;
            if (pos + 3 <= len) {
                cfg.es_id = try fr.readU16Be(source, off + pos);
                const es_flags = try fr.readU8(source, off + pos + 2);
                pos += 3;
                if ((es_flags & 0x80) != 0) pos += 2;
                if ((es_flags & 0x40) != 0 and pos < len) {
                    const url_len = try fr.readU8(source, off + pos);
                    pos += 1 + url_len;
                }
                if ((es_flags & 0x20) != 0) pos += 2;

                if (pos + 2 <= len and (try fr.readU8(source, off + pos)) == 0x04) {
                    pos += 1;
                    const dc_tlv = try fr.readTlvLength(source, off + pos);
                    pos += dc_tlv.bytes_consumed;
                    if (pos + dc_tlv.value > len) overflow = true;
                    if (pos + 13 <= len) {
                        cfg.object_type_indication = try fr.readU8(source, off + pos);
                        cfg.stream_type = (try fr.readU8(source, off + pos + 1)) >> 2;
                        cfg.max_bitrate = try fr.readU32Be(source, off + pos + 5);
                        cfg.avg_bitrate = try fr.readU32Be(source, off + pos + 9);
                    }
                }
            }
        }

        try tables.append(self.allocator, .{
            .table_fourcc = BOX_ESDS,
            .path = parent_path,
            .entry_count = 1,
            .entry_size = @intCast(@min(len, std.math.maxInt(u32))),
            .claimed_bytes = pos,
            .payload_size = len,
            .is_overflow = overflow,
        });

        try codec_headers.append(self.allocator, .{
            .track_id = track_id,
            .codec_tag = BOX_ESDS,
            .kind = .esds,
            .is_malformed = overflow,
            .claimed_bytes = pos,
            .payload_size = len,
        });

        return cfg;
    }

    fn parseDref(
        self: Mp4Dissector,
        source: ByteSource,
        dref_box: DissectedBox,
        track_id: u32,
        external_refs: *std.ArrayList(ExternalRefRecord),
    ) !void {
        const psize = dref_box.payloadSize();
        if (psize < 8) return;
        const entry_count = try fr.readU32Be(source, dref_box.payload_offset + 4);
        const capped = @min(entry_count, 64);
        var cur = dref_box.payload_offset + 8;
        const end = dref_box.payload_offset + psize;

        var i: u32 = 0;
        while (i < capped and cur + 12 <= end) : (i += 1) {
            const esize = try fr.readU32Be(source, cur);
            const efourcc = try fr.readFourCC(source, cur + 4);
            if (esize < 12) break;
            const eend = @min(end, cur + esize);
            const ver_flags = try fr.readU32Be(source, cur + 8);
            const flags = ver_flags & 0x00FF_FFFF;
            const is_self_contained = (flags & 1) != 0;

            if ((efourcc.equals(box_constants.BOX_URL) or efourcc.equals(box_constants.BOX_URN)) and !is_self_contained) {
                const str_off = cur + 12;
                const avail: usize = @intCast(@min(eend - str_off, 1024));
                var uri_slice: []u8 = &.{};
                if (avail > 0) {
                    const tmp = try self.allocator.alloc(u8, avail);
                    defer self.allocator.free(tmp);
                    _ = try source.readAt(tmp, str_off);
                    const nul = std.mem.indexOfScalar(u8, tmp, 0) orelse tmp.len;
                    if (nul > 0) {
                        uri_slice = try self.allocator.dupe(u8, tmp[0..nul]);
                    }
                }
                try external_refs.append(self.allocator, .{
                    .track_id = track_id,
                    .source_fourcc = efourcc,
                    .file_offset = cur,
                    .uri = uri_slice,
                    .is_self_contained = false,
                });
            }
            cur = eend;
        }
    }

    fn parseRdrf(
        self: Mp4Dissector,
        source: ByteSource,
        rdrf_box: DissectedBox,
        external_refs: *std.ArrayList(ExternalRefRecord),
    ) !void {
        const psize = rdrf_box.payloadSize();
        if (psize < 12) return;
        const ref_size = try fr.readU32Be(source, rdrf_box.payload_offset + 8);
        const avail: usize = @intCast(@min(psize - 12, @min(ref_size, 1024)));
        var uri_slice: []u8 = &.{};
        if (avail > 0) {
            const tmp = try self.allocator.alloc(u8, avail);
            defer self.allocator.free(tmp);
            _ = try source.readAt(tmp, rdrf_box.payload_offset + 12);
            const nul = std.mem.indexOfScalar(u8, tmp, 0) orelse tmp.len;
            if (nul > 0) {
                uri_slice = try self.allocator.dupe(u8, tmp[0..nul]);
            }
        }
        try external_refs.append(self.allocator, .{
            .track_id = 0,
            .source_fourcc = box_constants.BOX_RDRF,
            .file_offset = rdrf_box.header_offset,
            .uri = uri_slice,
            .is_self_contained = false,
        });
    }

    fn parseCovr(
        self: Mp4Dissector,
        source: ByteSource,
        covr_box: DissectedBox,
        attachments: *std.ArrayList(AttachmentRecord),
    ) !void {
        const psize = covr_box.payloadSize();
        if (psize < 16) return;
        const dsize = try fr.readU32Be(source, covr_box.payload_offset);
        const dfourcc = try fr.readFourCC(source, covr_box.payload_offset + 4);
        if (!dfourcc.equals(BOX_DATA) or dsize < 16) return;
        const type_ind = try fr.readU32Be(source, covr_box.payload_offset + 8);
        const mime = switch (type_ind) {
            13 => "image/jpeg",
            14 => "image/png",
            else => "application/octet-stream",
        };
        const data_len = @min(psize - 16, dsize - 16);
        try attachments.append(self.allocator, .{
            .source_fourcc = box_constants.BOX_COVR,
            .file_offset = covr_box.payload_offset + 16,
            .payload_size = data_len,
            .declared_mime = mime,
        });
    }

    fn extractSampleRuns(
        self: Mp4Dissector,
        source: ByteSource,
        track_id: u32,
        stsc_opt: ?DissectedBox,
        stsz_box: DissectedBox,
        stco_opt: ?DissectedBox,
        co64_opt: ?DissectedBox,
        runs: *std.ArrayList(SampleRun),
    ) !void {
        if (stsz_box.payloadSize() < 12) return;
        const uniform_size = try fr.readU32Be(source, stsz_box.payload_offset + 4);
        const total_samples = try fr.readU32Be(source, stsz_box.payload_offset + 8);
        if (total_samples == 0) return;

        // Read chunk offsets
        var chunk_offsets: std.ArrayList(u64) = .empty;
        defer chunk_offsets.deinit(self.allocator);

        if (stco_opt) |stco| {
            const psize = stco.payloadSize();
            if (psize >= 8) {
                const count = try fr.readU32Be(source, stco.payload_offset + 4);
                const max_entries: u32 = @intCast(@min(@as(u64, count), (psize - 8) / 4));
                var c: u32 = 0;
                while (c < max_entries) : (c += 1) {
                    try chunk_offsets.append(self.allocator, try fr.readU32Be(source, stco.payload_offset + 8 + @as(u64, c) * 4));
                }
            }
        } else if (co64_opt) |co64| {
            const psize = co64.payloadSize();
            if (psize >= 8) {
                const count = try fr.readU32Be(source, co64.payload_offset + 4);
                const max_entries: u32 = @intCast(@min(@as(u64, count), (psize - 8) / 8));
                var c: u32 = 0;
                while (c < max_entries) : (c += 1) {
                    try chunk_offsets.append(self.allocator, try fr.readU64Be(source, co64.payload_offset + 8 + @as(u64, c) * 8));
                }
            }
        }
        if (chunk_offsets.items.len == 0) return;

        // Read stsc entries
        var stsc_entries: std.ArrayList(StscEntry) = .empty;
        defer stsc_entries.deinit(self.allocator);
        if (stsc_opt) |stsc| {
            const psize = stsc.payloadSize();
            if (psize >= 8) {
                const count = try fr.readU32Be(source, stsc.payload_offset + 4);
                const max_entries: u32 = @intCast(@min(@as(u64, count), (psize - 8) / 12));
                var i: u32 = 0;
                while (i < max_entries) : (i += 1) {
                    const base = stsc.payload_offset + 8 + @as(u64, i) * 12;
                    try stsc_entries.append(self.allocator, .{
                        .first_chunk = try fr.readU32Be(source, base),
                        .samples_per_chunk = try fr.readU32Be(source, base + 4),
                    });
                }
            }
        }

        var stsc_idx: usize = 0;
        var sample_idx: u32 = 0;
        const max_stsz_entries: u32 = if (uniform_size == 0)
            @intCast(@min(@as(u64, total_samples), (stsz_box.payloadSize() - 12) / 4))
        else
            total_samples;

        for (chunk_offsets.items, 0..) |chunk_off, c_idx| {
            if (sample_idx >= max_stsz_entries) break;
            const chunk_num: u32 = @intCast(c_idx + 1);
            while (stsc_idx + 1 < stsc_entries.items.len and chunk_num >= stsc_entries.items[stsc_idx + 1].first_chunk) {
                stsc_idx += 1;
            }
            const spc: u32 = if (stsc_entries.items.len > 0)
                stsc_entries.items[stsc_idx].samples_per_chunk
            else
                total_samples;
            const n_in_chunk = @min(spc, max_stsz_entries - sample_idx);
            if (n_in_chunk == 0) continue;

            var chunk_bytes: u64 = 0;
            if (uniform_size > 0) {
                chunk_bytes = @as(u64, n_in_chunk) * @as(u64, uniform_size);
            } else {
                var s: u32 = 0;
                while (s < n_in_chunk) : (s += 1) {
                    const sz = try fr.readU32Be(source, stsz_box.payload_offset + 12 + @as(u64, sample_idx + s) * 4);
                    chunk_bytes +|= sz;
                }
            }

            if (chunk_bytes > 0) {
                const run_end = chunk_off +| chunk_bytes;
                if (runs.items.len > 0 and runs.items[runs.items.len - 1].track_id == track_id and runs.items[runs.items.len - 1].end_offset == chunk_off) {
                    runs.items[runs.items.len - 1].end_offset = run_end;
                    runs.items[runs.items.len - 1].sample_count +|= n_in_chunk;
                } else {
                    try runs.append(self.allocator, .{
                        .track_id = track_id,
                        .first_sample = sample_idx,
                        .sample_count = n_in_chunk,
                        .start_offset = chunk_off,
                        .end_offset = run_end,
                    });
                }
            }
            sample_idx += n_in_chunk;
        }
    }
};

pub const Mp4Inspector = Mp4Dissector;
