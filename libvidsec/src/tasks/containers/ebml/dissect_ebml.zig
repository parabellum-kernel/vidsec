const std = @import("std");
const Allocator = std.mem.Allocator;
const abi = @import("parabellum_sdk").task;
const ebml = @import("ebml");
const common = @import("../common.zig");

pub const Inputs = struct {
    stream: abi.BoundedStreamReader,
};

pub const EbmlTriageRow = struct {
    has_ebml_header: bool,
    has_segment: bool,
    doc_type: []const u8,
    doc_type_version: u64,
    element_count: u64,
    cluster_count: u64,
    highest_root_end: u64,
    has_overflow_or_truncated: bool,
    header_truncated_at: ?u64 = null,
    ebml_valid: bool,
};

pub const EbmlElementRow = struct {
    region_id: i64,
    parent_region_id: ?i64 = null,
    depth: i64,
    ebml_id_hex: []const u8,
    path: []const u8,
    role: []const u8,
    header_offset: u64,
    payload_offset: u64,
    available_bytes: u64,
    is_unknown_size: bool,
    is_truncated: bool,
    is_overflow: bool,
};

pub const OutputsData = struct {
    ebml_triage: EbmlTriageRow,
    ebml_elements: []const EbmlElementRow,
};

pub const Outputs = abi.Channels(OutputsData);

/// Stage 1a pure atomic dissector for EBML element hierarchy (zero policy findings).
pub const Service = struct {
    pub fn execute(_: *const Service, alloc: Allocator, inputs: Inputs) !Outputs {
        const source = common.streamToSource(ebml.ByteSource, &inputs.stream);
        var parsed = try ebml.ebml.SafeEbmlParser.init(alloc, .{}).parse(source);
        defer parsed.deinit();

        var elements: std.ArrayList(EbmlElementRow) = .empty;
        errdefer elements.deinit(alloc);

        var has_overflow_or_truncated = parsed.header_truncated_at != null;

        for (parsed.elements) |e| {
            const bad = e.containment.is_truncated or e.containment.is_overflow;
            if (bad) has_overflow_or_truncated = true;
            const id_hex = try std.fmt.allocPrint(alloc, "0x{x}", .{e.id});

            try elements.append(alloc, .{
                .region_id = @intCast(e.region_id),
                .parent_region_id = if (e.parent_id) |pid| @intCast(pid) else null,
                .depth = @intCast(e.depth),
                .ebml_id_hex = id_hex,
                .path = try alloc.dupe(u8, e.path),
                .role = e.role.asText(),
                .header_offset = e.header.offset,
                .payload_offset = e.header.payloadOffset(),
                .available_bytes = e.containment.available_bytes,
                .is_unknown_size = e.header.is_unknown_size,
                .is_truncated = e.containment.is_truncated,
                .is_overflow = e.containment.is_overflow,
            });
        }

        const doc_type = if (parsed.doc_type.len > 0) try alloc.dupe(u8, parsed.doc_type) else "unknown";
        return .{ .data = .{
            .ebml_triage = .{
                .has_ebml_header = parsed.has_ebml_header,
                .has_segment = parsed.has_segment,
                .doc_type = doc_type,
                .doc_type_version = parsed.doc_type_version,
                .element_count = parsed.elements.len,
                .cluster_count = parsed.cluster_count,
                .highest_root_end = parsed.highest_root_end,
                .has_overflow_or_truncated = has_overflow_or_truncated,
                .header_truncated_at = parsed.header_truncated_at,
                .ebml_valid = parsed.has_ebml_header and parsed.has_segment and !has_overflow_or_truncated,
            },
            .ebml_elements = try elements.toOwnedSlice(alloc),
        } };
    }
};
