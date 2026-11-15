const std = @import("std");
const Allocator = std.mem.Allocator;
const ByteSource = @import("../byte_source.zig").ByteSource;
const field_reader = @import("../field_reader.zig");
const ElementHeader = @import("element_header.zig").ElementHeader;
const DissectedElement = @import("parsed_element.zig").DissectedElement;
const ContainmentMeasurement = @import("parsed_element.zig").ContainmentMeasurement;
const ElementRole = @import("element_role.zig").ElementRole;
const EbmlParserOptions = @import("ebml_parser_options.zig").EbmlParserOptions;
const EbmlParseResult = @import("ebml_parse_result.zig").EbmlParseResult;
const readElementHeader = @import("read_element_header.zig").readElementHeader;
const ebml_constants = @import("ebml_constants.zig");

pub const MAX_NESTING_DEPTH: usize = 32;

/// Iterative, bounded-depth pure dissector for EBML streams.
pub const SafeEbmlParser = struct {
    allocator: Allocator,
    options: EbmlParserOptions,

    pub fn init(allocator: Allocator, options: EbmlParserOptions) SafeEbmlParser {
        return .{
            .allocator = allocator,
            .options = options,
        };
    }

    pub fn parse(self: SafeEbmlParser, source: ByteSource) !EbmlParseResult {
        var elements = std.ArrayList(DissectedElement).empty;
        errdefer {
            for (elements.items) |e| {
                if (e.path.len > 0) self.allocator.free(e.path);
            }
            elements.deinit(self.allocator);
        }

        const StackFrame = struct {
            element_id: u32,
            parsed_idx: u32,
            end_offset: u64,
            is_unknown_size: bool,
        };

        var frame_stack: [MAX_NESTING_DEPTH]StackFrame = undefined;
        var stack_len: usize = 0;

        var curr_offset: u64 = 0;
        var is_first_element = true;
        var has_ebml_header = false;
        var has_segment = false;
        var cluster_count: u32 = 0;
        var total_cluster_bytes: u64 = 0;
        var highest_root_end: u64 = 0;
        var header_truncated_at: ?u64 = null;

        var doc_type_buf: [64]u8 = undefined;
        var doc_type_str: []const u8 = "";
        var doc_type_version: u32 = 0;

        while (curr_offset < source.file_size) {
            while (stack_len > 0) {
                const top = &frame_stack[stack_len - 1];
                if (!top.is_unknown_size and curr_offset >= top.end_offset) {
                    stack_len -= 1;
                } else {
                    break;
                }
            }

            if (curr_offset >= source.file_size) break;

            const header_opt = try readElementHeader(source, curr_offset);
            if (header_opt == null) {
                header_truncated_at = curr_offset;
                break;
            }

            const header = header_opt.?;

            const parent_end = if (stack_len > 0 and !frame_stack[stack_len - 1].is_unknown_size)
                frame_stack[stack_len - 1].end_offset
            else
                source.file_size;

            const raw_end = if (header.is_unknown_size)
                parent_end
            else
                curr_offset +| header.totalSize();

            const effective_end = @min(raw_end, @min(parent_end, source.file_size));
            const available_bytes = if (effective_end > curr_offset) effective_end - curr_offset else 0;
            const is_truncated = !header.is_unknown_size and raw_end > source.file_size;
            const is_overflow = !header.is_unknown_size and stack_len > 0 and !frame_stack[stack_len - 1].is_unknown_size and raw_end > frame_stack[stack_len - 1].end_offset;

            if (is_first_element and header.id == ebml_constants.ID_EBML_HEADER) {
                has_ebml_header = true;
            }
            if (header.id == ebml_constants.ID_SEGMENT) {
                has_segment = true;
            } else if (header.id == ebml_constants.ID_CLUSTER) {
                cluster_count += 1;
                total_cluster_bytes += available_bytes;
            }

            if (header.id == ebml_constants.ID_DOC_TYPE and doc_type_str.len == 0) {
                doc_type_str = try field_reader.readString(source, &doc_type_buf, header.payloadOffset(), header.data_size);
            } else if (header.id == ebml_constants.ID_DOC_TYPE_VERSION and doc_type_version == 0) {
                doc_type_version = @truncate(try field_reader.readUint(source, header.payloadOffset(), header.data_size));
            }

            const parent_idx: ?u32 = if (stack_len > 0) frame_stack[stack_len - 1].parsed_idx else null;
            const current_idx: u32 = @intCast(elements.items.len);

            if (parent_idx) |pidx| {
                if (pidx < elements.items.len) {
                    elements.items[pidx].child_count += 1;
                }
            }

            const path = if (parent_idx) |pidx|
                try std.fmt.allocPrint(self.allocator, "{s}/0x{X}", .{ elements.items[pidx].path, header.id })
            else
                try std.fmt.allocPrint(self.allocator, "0x{X}", .{header.id});

            try elements.append(self.allocator, .{
                .region_id = current_idx,
                .id = header.id,
                .parent_id = parent_idx,
                .depth = @intCast(stack_len),
                .path = path,
                .header = header,
                .role = ElementRole.fromId(header.id),
                .containment = .{
                    .available_bytes = available_bytes,
                    .is_truncated = is_truncated,
                    .is_overflow = is_overflow,
                },
            });

            if (stack_len == 0) {
                highest_root_end = @max(highest_root_end, effective_end);
            }

            is_first_element = false;

            const is_master = ebml_constants.isMasterElement(header.id);
            const is_cluster = (header.id == ebml_constants.ID_CLUSTER);
            const should_recurse = is_master and (!is_cluster or self.options.recurse_clusters);

            if (should_recurse and stack_len < self.options.max_depth) {
                frame_stack[stack_len] = .{
                    .element_id = header.id,
                    .parsed_idx = current_idx,
                    .end_offset = effective_end,
                    .is_unknown_size = header.is_unknown_size,
                };
                stack_len += 1;
                curr_offset = header.payloadOffset();
            } else {
                curr_offset = effective_end;
            }
        }

        const owned_doc_type = if (doc_type_str.len > 0)
            try self.allocator.dupe(u8, doc_type_str)
        else
            "";

        return EbmlParseResult{
            .allocator = self.allocator,
            .elements = try elements.toOwnedSlice(self.allocator),
            .doc_type = owned_doc_type,
            .doc_type_version = doc_type_version,
            .has_ebml_header = has_ebml_header,
            .has_segment = has_segment,
            .cluster_count = cluster_count,
            .total_cluster_bytes = total_cluster_bytes,
            .highest_root_end = highest_root_end,
            .header_truncated_at = header_truncated_at,
        };
    }
};
