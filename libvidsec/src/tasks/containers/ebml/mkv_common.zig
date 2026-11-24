const std = @import("std");
const Allocator = std.mem.Allocator;
const abi = @import("parabellum_sdk").task;
const ebml = @import("ebml");
const common = @import("../common.zig");
const dissect_ebml = @import("dissect_ebml.zig");

/// Reuses `ebml_elements` from `dissect_ebml` when available (avoiding redundant EBML parsing)
/// and runs `MkvDissector.dissectWithOptions` with only the sections needed by the caller.
pub fn dissectMkv(
    alloc: Allocator,
    stream: *const abi.BoundedStreamReader,
    ebml_elements: []const dissect_ebml.EbmlElementRow,
    options: ebml.mkv.MkvDissector.DissectOptions,
) !ebml.mkv.MkvDissectionResult {
    const source = common.streamToSource(ebml.ByteSource, stream);
    if (ebml_elements.len > 0) {
        const elems = try alloc.alloc(ebml.ebml.DissectedElement, ebml_elements.len);
        defer alloc.free(elems);

        for (ebml_elements, 0..) |row, i| {
            const hex_slice = if (std.mem.startsWith(u8, row.ebml_id_hex, "0x"))
                row.ebml_id_hex[2..]
            else
                row.ebml_id_hex;
            const elem_id = std.fmt.parseInt(u32, hex_slice, 16) catch 0;
            const hdr_sz = row.payload_offset -| row.header_offset;
            const id_len: u8 = @intCast(@min(hdr_sz, 4));
            const size_len: u8 = @intCast(@min(hdr_sz -| id_len, 8));
            elems[i] = .{
                .region_id = @intCast(row.region_id),
                .id = elem_id,
                .parent_id = if (row.parent_region_id) |pid| @intCast(pid) else null,
                .depth = @intCast(row.depth),
                .path = row.path,
                .header = .{
                    .id = elem_id,
                    .id_len = id_len,
                    .data_size = row.available_bytes -| hdr_sz,
                    .size_len = size_len,
                    .offset = row.header_offset,
                    .is_unknown_size = row.is_unknown_size,
                },
                .role = .unknown,
                .containment = .{
                    .available_bytes = row.available_bytes,
                    .is_truncated = row.is_truncated,
                    .is_overflow = row.is_overflow,
                },
            };
        }

        return try ebml.mkv.MkvDissector.init(alloc).dissectWithOptions(source, elems, options);
    }

    var parsed = try ebml.ebml.SafeEbmlParser.init(alloc, .{}).parse(source);
    defer parsed.deinit();

    return try ebml.mkv.MkvDissector.init(alloc).dissectWithOptions(source, parsed.elements, options);
}
