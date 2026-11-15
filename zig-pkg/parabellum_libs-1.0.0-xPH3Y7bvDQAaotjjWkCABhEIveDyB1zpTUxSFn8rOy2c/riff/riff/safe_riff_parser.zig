const std = @import("std");
const Allocator = std.mem.Allocator;
const ByteSource = @import("../byte_source.zig").ByteSource;
const FourCC = @import("fourcc.zig").FourCC;
const ChunkHeader = @import("chunk_header.zig").ChunkHeader;
const DissectedChunk = @import("parsed_chunk.zig").DissectedChunk;
const ChunkRole = @import("chunk_role.zig").ChunkRole;
const RiffParserOptions = @import("riff_parser_options.zig").RiffParserOptions;
const RiffParseResult = @import("riff_parse_result.zig").RiffParseResult;
const riff_constants = @import("riff_constants.zig");

pub const MAX_NESTING_DEPTH: usize = 32;

/// Iterative, bounded-depth pure dissector for RIFF containers.
pub const SafeRiffParser = struct {
    allocator: Allocator,
    options: RiffParserOptions,

    pub fn init(allocator: Allocator, options: RiffParserOptions) SafeRiffParser {
        return .{
            .allocator = allocator,
            .options = options,
        };
    }

    pub fn parse(self: SafeRiffParser, source: ByteSource) !RiffParseResult {
        var chunks = std.ArrayList(DissectedChunk).empty;
        errdefer {
            for (chunks.items) |c| {
                if (c.path.len > 0) self.allocator.free(c.path);
            }
            chunks.deinit(self.allocator);
        }

        if (source.file_size < 12) {
            return RiffParseResult{
                .allocator = self.allocator,
                .chunks = try chunks.toOwnedSlice(self.allocator),
                .form_type = FourCC.init("    "),
                .root_size = 0,
                .is_valid_root_magic = false,
                .movi_bytes = 0,
                .junk_bytes = 0,
                .highest_root_end = 0,
                .header_truncated_at = 0,
            };
        }

        var root_hdr_buf: [12]u8 = undefined;
        try source.readExactAt(&root_hdr_buf, 0);

        const root_fourcc = FourCC{ .bytes = root_hdr_buf[0..4].* };
        const is_rifx = root_fourcc.equals(riff_constants.FOURCC_RIFX);
        const endian: std.builtin.Endian = if (is_rifx) .big else .little;

        const is_valid_root = root_fourcc.equals(riff_constants.FOURCC_RIFF) or
            root_fourcc.equals(riff_constants.FOURCC_RIFX) or
            root_fourcc.equals(riff_constants.FOURCC_RF64);

        const root_size_raw = std.mem.readInt(u32, root_hdr_buf[4..8], endian);
        const form_type = FourCC{ .bytes = root_hdr_buf[8..12].* };

        const root_header = ChunkHeader{
            .fourcc = root_fourcc,
            .size = root_size_raw,
            .offset = 0,
            .form_or_list_type = form_type,
            .is_padded = (root_size_raw & 1 == 1),
        };

        const raw_root_end = 8 +| @as(u64, root_size_raw);
        const effective_root_end = @min(raw_root_end, source.file_size);
        const root_path = try std.fmt.allocPrint(self.allocator, "{s}:{s}", .{ &root_fourcc.bytes, &form_type.bytes });

        try chunks.append(self.allocator, .{
            .id = 0,
            .parent_id = null,
            .depth = 0,
            .path = root_path,
            .header = root_header,
            .role = .header,
            .containment = .{
                .available_bytes = effective_root_end,
                .is_truncated = raw_root_end > source.file_size,
                .is_overflow = false,
            },
        });

        const StackFrame = struct {
            parsed_idx: u32,
            end_offset: u64,
            list_type: ?FourCC,
        };

        var frame_stack: [MAX_NESTING_DEPTH]StackFrame = undefined;
        var stack_len: usize = 1;
        frame_stack[0] = .{
            .parsed_idx = 0,
            .end_offset = effective_root_end,
            .list_type = form_type,
        };

        var curr_offset: u64 = 12;
        var movi_bytes: u64 = 0;
        var junk_bytes: u64 = 0;
        var header_truncated_at: ?u64 = null;

        while (curr_offset < source.file_size) {
            while (stack_len > 0 and curr_offset >= frame_stack[stack_len - 1].end_offset) {
                stack_len -= 1;
            }
            if (stack_len == 0 or curr_offset >= source.file_size) break;

            if (curr_offset + 8 > source.file_size) {
                header_truncated_at = curr_offset;
                break;
            }

            var chunk_buf: [8]u8 = undefined;
            if ((try source.readAt(&chunk_buf, curr_offset)) < 8) {
                header_truncated_at = curr_offset;
                break;
            }

            const c_fourcc = FourCC{ .bytes = chunk_buf[0..4].* };
            const c_size = std.mem.readInt(u32, chunk_buf[4..8], endian);
            const is_padded = (c_size & 1 == 1);
            const c_pad_byte: u64 = if (is_padded) 1 else 0;
            const c_total_bytes = 8 + @as(u64, c_size) + c_pad_byte;

            const raw_end = curr_offset +| c_total_bytes;
            const parent_frame = frame_stack[stack_len - 1];
            const effective_end = @min(raw_end, @min(parent_frame.end_offset, source.file_size));
            const available_bytes = if (effective_end > curr_offset) effective_end - curr_offset else 0;
            const is_truncated = raw_end > source.file_size;
            const is_overflow = raw_end > parent_frame.end_offset;

            const is_list = c_fourcc.equals(riff_constants.FOURCC_LIST);
            var list_type: ?FourCC = null;
            if (is_list and available_bytes >= 12) {
                var lt_buf: [4]u8 = undefined;
                if ((try source.readAt(&lt_buf, curr_offset + 8)) == 4) {
                    list_type = FourCC{ .bytes = lt_buf };
                }
            }

            const c_role = ChunkRole.fromFourCC(c_fourcc, list_type);
            if (c_fourcc.equals(riff_constants.CHUNK_JUNK) or c_fourcc.equals(riff_constants.CHUNK_PAD)) {
                junk_bytes += available_bytes;
            } else if (list_type != null and list_type.?.equals(riff_constants.LIST_MOVI)) {
                movi_bytes += available_bytes;
            }

            const parent_idx: u32 = parent_frame.parsed_idx;
            const current_idx: u32 = @intCast(chunks.items.len);
            if (parent_idx < chunks.items.len) {
                chunks.items[parent_idx].child_count += 1;
            }

            const path = if (list_type) |lt|
                try std.fmt.allocPrint(self.allocator, "{s}/{s}:{s}", .{ chunks.items[parent_idx].path, &c_fourcc.bytes, &lt.bytes })
            else
                try std.fmt.allocPrint(self.allocator, "{s}/{s}", .{ chunks.items[parent_idx].path, &c_fourcc.bytes });

            try chunks.append(self.allocator, .{
                .id = current_idx,
                .parent_id = parent_idx,
                .depth = @intCast(stack_len),
                .path = path,
                .header = .{
                    .fourcc = c_fourcc,
                    .size = c_size,
                    .offset = curr_offset,
                    .form_or_list_type = list_type,
                    .is_padded = is_padded,
                },
                .role = c_role,
                .containment = .{
                    .available_bytes = available_bytes,
                    .is_truncated = is_truncated,
                    .is_overflow = is_overflow,
                },
            });

            const is_movi = (list_type != null and list_type.?.equals(riff_constants.LIST_MOVI));
            const should_recurse = is_list and (!is_movi or self.options.recurse_movi);

            if (should_recurse and stack_len < self.options.max_depth) {
                frame_stack[stack_len] = .{
                    .parsed_idx = current_idx,
                    .end_offset = effective_end,
                    .list_type = list_type,
                };
                stack_len += 1;
                curr_offset += 12;
            } else {
                curr_offset = effective_end;
            }
        }

        return RiffParseResult{
            .allocator = self.allocator,
            .chunks = try chunks.toOwnedSlice(self.allocator),
            .form_type = form_type,
            .root_size = root_size_raw,
            .is_valid_root_magic = is_valid_root,
            .movi_bytes = movi_bytes,
            .junk_bytes = junk_bytes,
            .highest_root_end = effective_root_end,
            .header_truncated_at = header_truncated_at,
        };
    }
};
