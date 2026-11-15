const std = @import("std");
const Allocator = std.mem.Allocator;
const ir = @import("../rows/mod.zig");

pub const SlackKind = enum {
    leading_gap,
    inter_region_gap,
    trailing_overlay,
    interior_media_slack,

    pub fn asText(self: SlackKind) []const u8 {
        return switch (self) {
            .leading_gap => "leading_gap",
            .inter_region_gap => "inter_region_gap",
            .trailing_overlay => "trailing_overlay",
            .interior_media_slack => "interior_media_slack",
        };
    }
};

pub const SlackRegion = struct {
    kind: SlackKind,
    file_offset: u64,
    byte_length: u64,
    parent_region_id: ?i64 = null,
};

pub const RegionOverlap = struct {
    region_a_id: i64,
    region_b_id: i64,
    overlap_offset: u64,
    overlap_bytes: u64,
};

pub const TopologyReport = struct {
    allocator: Allocator,
    slacks: []const SlackRegion,
    overlaps: []const RegionOverlap,

    pub fn deinit(self: *TopologyReport) void {
        self.allocator.free(self.slacks);
        self.allocator.free(self.overlaps);
    }
};

const Span = struct {
    region_id: i64,
    start: u64,
    end: u64,

    fn lessThan(_: void, a: Span, b: Span) bool {
        if (a.start != b.start) return a.start < b.start;
        return a.end < b.end;
    }
};

/// 2-level format-agnostic topology analyzer over `ir_regions` + `ir_sample_runs`:
/// - Level 1 (external): leading gaps, inter-region gaps, trailing overlays, and root overlaps.
/// - Level 2 (interior): `media_data \ SampleRuns` unreferenced byte gaps inside `mdat` / `Cluster` / `movi`.
pub fn analyzeTopology(
    allocator: Allocator,
    file_size: u64,
    regions: []const ir.IrRegionRow,
    sample_runs: []const ir.IrSampleRunRow,
) !TopologyReport {
    var slacks: std.ArrayList(SlackRegion) = .empty;
    errdefer slacks.deinit(allocator);

    var overlaps: std.ArrayList(RegionOverlap) = .empty;
    errdefer overlaps.deinit(allocator);

    var roots: std.ArrayList(Span) = .empty;
    defer roots.deinit(allocator);

    for (regions) |reg| {
        if (reg.parent_region_id != null) continue;
        try roots.append(allocator, .{
            .region_id = reg.region_id,
            .start = reg.header_offset,
            .end = reg.effective_end_offset,
        });
    }
    std.mem.sort(Span, roots.items, {}, Span.lessThan);

    // Level 1: External root gaps, trailing overlay, and overlaps
    if (roots.items.len > 0) {
        if (roots.items[0].start > 0) {
            try slacks.append(allocator, .{
                .kind = .leading_gap,
                .file_offset = 0,
                .byte_length = roots.items[0].start,
            });
        }

        var max_end: u64 = roots.items[0].end;
        var prev = roots.items[0];
        for (roots.items[1..]) |cur| {
            if (cur.start < prev.end) {
                const overlap_end = @min(cur.end, prev.end);
                if (overlap_end > cur.start) {
                    try overlaps.append(allocator, .{
                        .region_a_id = prev.region_id,
                        .region_b_id = cur.region_id,
                        .overlap_offset = cur.start,
                        .overlap_bytes = overlap_end - cur.start,
                    });
                }
            } else if (cur.start > max_end) {
                try slacks.append(allocator, .{
                    .kind = .inter_region_gap,
                    .file_offset = max_end,
                    .byte_length = cur.start - max_end,
                });
            }
            if (cur.end > max_end) {
                max_end = cur.end;
                prev = cur;
            }
        }

        if (file_size > max_end) {
            try slacks.append(allocator, .{
                .kind = .trailing_overlay,
                .file_offset = max_end,
                .byte_length = file_size - max_end,
            });
        }
    } else if (file_size > 0) {
        try slacks.append(allocator, .{
            .kind = .trailing_overlay,
            .file_offset = 0,
            .byte_length = file_size,
        });
    }

    // Level 2: Interior `media_data \ SampleRuns` slack
    var run_spans: std.ArrayList(Span) = .empty;
    defer run_spans.deinit(allocator);
    for (sample_runs) |sr| {
        if (sr.end_offset > sr.start_offset) {
            try run_spans.append(allocator, .{
                .region_id = sr.run_id,
                .start = sr.start_offset,
                .end = sr.end_offset,
            });
        }
    }
    std.mem.sort(Span, run_spans.items, {}, Span.lessThan);

    for (regions) |reg| {
        if (!std.mem.eql(u8, reg.role, "media_data")) continue;
        const m_start = reg.payload_offset;
        const m_end = reg.effective_end_offset;
        if (m_end <= m_start) continue;

        var cursor = m_start;
        for (run_spans.items) |rs| {
            if (rs.end <= m_start) continue;
            if (rs.start >= m_end) break;

            const clipped_start = @max(rs.start, m_start);
            const clipped_end = @min(rs.end, m_end);
            if (clipped_start > cursor) {
                try slacks.append(allocator, .{
                    .kind = .interior_media_slack,
                    .file_offset = cursor,
                    .byte_length = clipped_start - cursor,
                    .parent_region_id = reg.region_id,
                });
            }
            if (clipped_end > cursor) {
                cursor = clipped_end;
            }
        }
        if (m_end > cursor and run_spans.items.len > 0) {
            try slacks.append(allocator, .{
                .kind = .interior_media_slack,
                .file_offset = cursor,
                .byte_length = m_end - cursor,
                .parent_region_id = reg.region_id,
            });
        }
    }

    return .{
        .allocator = allocator,
        .slacks = try slacks.toOwnedSlice(allocator),
        .overlaps = try overlaps.toOwnedSlice(allocator),
    };
}

test "analyzeTopology detects external trailing overlay and interior media_data slack" {
    const regions = [_]ir.IrRegionRow{
        .{ .region_id = 0, .tag_name = "ftyp", .role = "header", .header_offset = 0, .payload_offset = 8, .effective_end_offset = 24 },
        .{ .region_id = 1, .tag_name = "mdat", .role = "media_data", .header_offset = 24, .payload_offset = 32, .effective_end_offset = 132 },
    };
    const runs = [_]ir.IrSampleRunRow{
        .{ .run_id = 1, .track_id = 1, .start_offset = 32, .byte_length = 40, .end_offset = 72, .sample_count = 2 },
        .{ .run_id = 2, .track_id = 1, .start_offset = 92, .byte_length = 40, .end_offset = 132, .sample_count = 2 },
    };

    var report = try analyzeTopology(std.testing.allocator, 160, &regions, &runs);
    defer report.deinit();

    try std.testing.expectEqual(@as(usize, 0), report.overlaps.len);
    try std.testing.expectEqual(@as(usize, 2), report.slacks.len);
    try std.testing.expectEqual(SlackKind.trailing_overlay, report.slacks[0].kind);
    try std.testing.expectEqual(@as(u64, 132), report.slacks[0].file_offset);
    try std.testing.expectEqual(@as(u64, 28), report.slacks[0].byte_length);

    try std.testing.expectEqual(SlackKind.interior_media_slack, report.slacks[1].kind);
    try std.testing.expectEqual(@as(u64, 72), report.slacks[1].file_offset);
    try std.testing.expectEqual(@as(u64, 20), report.slacks[1].byte_length);
    try std.testing.expectEqual(@as(?i64, 1), report.slacks[1].parent_region_id);
}
