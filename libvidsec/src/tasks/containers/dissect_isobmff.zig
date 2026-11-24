const std = @import("std");
const Allocator = std.mem.Allocator;
const abi = @import("parabellum_sdk").task;
const isobmff = @import("isobmff");
const common = @import("common.zig");

pub const Inputs = struct {
    stream: abi.BoundedStreamReader,
};

pub const IsobmffTriageRow = struct {
    box_count: u64,
    has_ftyp: bool,
    has_moov: bool,
    has_mdat: bool,
    highest_root_end: u64,
    has_overflow_or_truncated: bool,
    truncated_tail_offset: ?u64 = null,
    isobmff_valid: bool,
};

pub const IsobmffBoxRow = struct {
    region_id: i64,
    parent_region_id: ?i64 = null,
    depth: i64,
    fourcc: []const u8,
    path: []const u8,
    role: []const u8,
    header_offset: u64,
    payload_offset: u64,
    declared_size: u64,
    available_bytes: u64,
    is_truncated: bool,
    is_overflow: bool,
};

pub const OutputsData = struct {
    isobmff_triage: IsobmffTriageRow,
    isobmff_boxes: []const IsobmffBoxRow,
};

pub const Outputs = abi.Channels(OutputsData);

/// Stage 1a pure atomic dissector for ISOBMFF/MP4 box hierarchy (zero policy findings).
pub const Service = struct {
    pub fn execute(_: *const Service, alloc: Allocator, inputs: Inputs) !Outputs {
        const source = common.streamToSource(isobmff.ByteSource, &inputs.stream);
        var parsed = try isobmff.box.SafeBoxParser.init(alloc).parse(source);
        defer parsed.deinit();

        var boxes: std.ArrayList(IsobmffBoxRow) = .empty;
        errdefer boxes.deinit(alloc);

        var has_mdat = false;
        var has_overflow_or_truncated = parsed.truncated_tail_offset != null;

        for (parsed.boxes) |b| {
            if (b.role == .media_data) has_mdat = true;
            if (b.containment.is_truncated or b.containment.is_overflow) {
                has_overflow_or_truncated = true;
            }

            try boxes.append(alloc, .{
                .region_id = @intCast(b.id),
                .parent_region_id = if (b.parent_id) |pid| @intCast(pid) else null,
                .depth = @intCast(b.depth),
                .fourcc = try alloc.dupe(u8, &b.fourcc.bytes),
                .path = try alloc.dupe(u8, b.path),
                .role = b.role.asText(),
                .header_offset = b.header_offset,
                .payload_offset = b.payload_offset,
                .declared_size = b.declared_size,
                .available_bytes = b.containment.available_bytes,
                .is_truncated = b.containment.is_truncated,
                .is_overflow = b.containment.is_overflow,
            });
        }

        return .{ .data = .{
            .isobmff_triage = .{
                .box_count = parsed.boxes.len,
                .has_ftyp = parsed.has_ftyp,
                .has_moov = parsed.has_moov,
                .has_mdat = has_mdat,
                .highest_root_end = parsed.highest_root_end,
                .has_overflow_or_truncated = has_overflow_or_truncated,
                .truncated_tail_offset = parsed.truncated_tail_offset,
                .isobmff_valid = parsed.has_ftyp and parsed.has_moov and !has_overflow_or_truncated,
            },
            .isobmff_boxes = try boxes.toOwnedSlice(alloc),
        } };
    }
};
