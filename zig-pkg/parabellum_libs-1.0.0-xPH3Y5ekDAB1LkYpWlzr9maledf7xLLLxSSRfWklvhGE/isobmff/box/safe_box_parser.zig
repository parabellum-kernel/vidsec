const std = @import("std");
const ByteSource = @import("../byte_source.zig").ByteSource;
const FourCC = @import("fourcc.zig").FourCC;
const DissectedBox = @import("parsed_box.zig").DissectedBox;
const ContainmentMeasurement = @import("parsed_box.zig").ContainmentMeasurement;
const BoxRole = @import("box_role.zig").BoxRole;
const ParseResult = @import("parse_result.zig").ParseResult;
const readBoxHeader = @import("read_box_header.zig").readBoxHeader;
const box_constants = @import("box_constants.zig");

pub const MAX_NESTING_DEPTH: usize = 32;

const ContainerFrame = struct {
    box_id: u32,
    end_offset: u64,
    fourcc: FourCC,
    path: []const u8,
};

fn isFullBoxFourCC(fourcc: FourCC) bool {
    const full_boxes = [_]FourCC{
        box_constants.BOX_MVHD, box_constants.BOX_TKHD, box_constants.BOX_MDHD,
        box_constants.BOX_HDLR, box_constants.BOX_VMHD, box_constants.BOX_SMHD,
        box_constants.BOX_HMHD, box_constants.BOX_NMHD, box_constants.BOX_DREF,
        box_constants.BOX_STSD, box_constants.BOX_STTS, box_constants.BOX_CTTS,
        box_constants.BOX_CSLG, box_constants.BOX_STSC, box_constants.BOX_STSZ,
        box_constants.BOX_STZ2, box_constants.BOX_STCO, box_constants.BOX_CO64,
        box_constants.BOX_STSS, box_constants.BOX_STSH, box_constants.BOX_ELST,
        box_constants.BOX_META, box_constants.BOX_ILOC, box_constants.BOX_IPRO,
        box_constants.BOX_IINF, box_constants.BOX_PITM, box_constants.BOX_MFHD,
        box_constants.BOX_TFHD, box_constants.BOX_TRUN, box_constants.BOX_TFRA,
        box_constants.BOX_TREX, box_constants.BOX_MEHD, box_constants.BOX_SIDX,
        box_constants.BOX_SSIX, box_constants.BOX_PRFT, box_constants.BOX_SCHM,
        box_constants.BOX_PDIN,
    };
    for (full_boxes) |fb| {
        if (fourcc.equals(fb)) return true;
    }
    return false;
}

/// Pure, iterative ISOBMFF box tree dissector outputting structural nodes and containment metrics.
pub const SafeBoxParser = struct {
    allocator: std.mem.Allocator,
    max_depth: usize = MAX_NESTING_DEPTH,
    max_boxes: usize = 4096,

    pub fn init(allocator: std.mem.Allocator) SafeBoxParser {
        return .{ .allocator = allocator };
    }

    pub fn parse(self: SafeBoxParser, source: ByteSource) !ParseResult {
        var boxes: std.ArrayList(DissectedBox) = try .initCapacity(self.allocator, 32);
        errdefer {
            for (boxes.items) |b| self.allocator.free(b.path);
            boxes.deinit(self.allocator);
        }

        var frame_stack: [MAX_NESTING_DEPTH]ContainerFrame = undefined;
        var stack_len: usize = 0;

        var curr_offset: u64 = 0;
        var highest_root_end: u64 = 0;
        var truncated_tail_offset: ?u64 = null;
        var has_ftyp: bool = false;
        var has_moov: bool = false;
        var ftyp_count: u32 = 0;
        var moov_count: u32 = 0;

        while (curr_offset < source.file_size and boxes.items.len < self.max_boxes) {
            while (stack_len > 0 and curr_offset >= frame_stack[stack_len - 1].end_offset) {
                stack_len -= 1;
            }

            const enclosing_end: u64 = if (stack_len > 0) frame_stack[stack_len - 1].end_offset else source.file_size;
            if (curr_offset >= enclosing_end) {
                if (stack_len > 0) {
                    stack_len -= 1;
                    continue;
                }
                break;
            }

            if (curr_offset + 8 > enclosing_end) {
                truncated_tail_offset = curr_offset;
                if (stack_len > 0) {
                    curr_offset = enclosing_end;
                    continue;
                }
                break;
            }

            const header_opt = try readBoxHeader(source, curr_offset);
            if (header_opt == null) {
                truncated_tail_offset = curr_offset;
                break;
            }
            const header = header_opt.?;

            const avail_total = enclosing_end - curr_offset;
            const claimed_end_res = @addWithOverflow(curr_offset, header.size);
            const is_overflow = claimed_end_res[1] != 0 or claimed_end_res[0] > enclosing_end or header.size < header.header_size;
            const is_truncated = is_overflow;

            const parent_id: ?u32 = if (stack_len > 0) frame_stack[stack_len - 1].box_id else null;
            const box_id: u32 = @intCast(boxes.items.len);

            const path = if (stack_len > 0)
                try std.fmt.allocPrint(self.allocator, "{s}/{s}", .{ frame_stack[stack_len - 1].path, &header.fourcc.bytes })
            else
                try self.allocator.dupe(u8, &header.fourcc.bytes);
            errdefer self.allocator.free(path);

            if (stack_len == 0) {
                if (header.fourcc.equals(box_constants.BOX_FTYP)) {
                    has_ftyp = true;
                    ftyp_count += 1;
                } else if (header.fourcc.equals(box_constants.BOX_MOOV)) {
                    has_moov = true;
                    moov_count += 1;
                }
                const root_end = @min(source.file_size, curr_offset +| @max(header.size, header.header_size));
                if (root_end > highest_root_end) highest_root_end = root_end;
            } else {
                boxes.items[parent_id.?].child_count += 1;
            }

            var is_full_box = isFullBoxFourCC(header.fourcc);
            var version: u8 = 0;
            var flags: u24 = 0;
            const payload_offset = curr_offset + header.header_size;
            const avail_payload = avail_total -| header.header_size;
            if (is_full_box and avail_payload >= 4) {
                var fb_buf: [4]u8 = undefined;
                if (try source.readAt(&fb_buf, payload_offset) == 4) {
                    version = fb_buf[0];
                    flags = (@as(u24, fb_buf[1]) << 16) | (@as(u24, fb_buf[2]) << 8) | @as(u24, fb_buf[3]);
                }
            } else {
                is_full_box = false;
            }

            try boxes.append(self.allocator, .{
                .id = box_id,
                .parent_id = parent_id,
                .depth = @intCast(stack_len),
                .fourcc = header.fourcc,
                .path = path,
                .header_offset = curr_offset,
                .payload_offset = payload_offset,
                .declared_size = header.size,
                .header_size = header.header_size,
                .is_extended_size = header.is_extended_size,
                .is_eof_size = header.is_eof_size,
                .is_full_box = is_full_box,
                .version = version,
                .flags = flags,
                .role = BoxRole.fromFourCC(header.fourcc),
                .child_count = 0,
                .containment = .{
                    .claimed_bytes = header.size,
                    .available_bytes = @min(header.size, avail_total),
                    .is_truncated = is_truncated,
                    .is_overflow = is_overflow,
                },
            });

            if (box_constants.isContainerBox(header.fourcc) and !is_overflow and stack_len < self.max_depth and stack_len < MAX_NESTING_DEPTH) {
                const child_start = if (header.fourcc.equals(box_constants.BOX_META) and is_full_box)
                    payload_offset + 4
                else
                    payload_offset;
                const box_end = curr_offset + header.size;
                if (child_start < box_end) {
                    frame_stack[stack_len] = .{
                        .box_id = box_id,
                        .end_offset = box_end,
                        .fourcc = header.fourcc,
                        .path = path,
                    };
                    stack_len += 1;
                    curr_offset = child_start;
                    continue;
                }
            }

            if (header.size < header.header_size or is_overflow) {
                curr_offset = enclosing_end;
            } else {
                curr_offset += header.size;
            }
        }

        return ParseResult{
            .allocator = self.allocator,
            .boxes = try boxes.toOwnedSlice(self.allocator),
            .highest_root_end = highest_root_end,
            .truncated_tail_offset = truncated_tail_offset,
            .has_ftyp = has_ftyp,
            .has_moov = has_moov,
            .ftyp_count = ftyp_count,
            .moov_count = moov_count,
        };
    }
};
