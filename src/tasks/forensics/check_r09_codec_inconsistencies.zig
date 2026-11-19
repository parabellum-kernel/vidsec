const std = @import("std");
const Allocator = std.mem.Allocator;
const abi = @import("parabellum_sdk").task;
const media_ir = @import("media_ir");

pub const Inputs = struct {
    ir_codec_configs: []const media_ir.IrCodecConfigRow = &.{},
    max_dimension: u64 = 16384,
};

pub const OutputsData = struct {
    audit_findings: []const media_ir.AuditFindingRow,
};

pub const Outputs = abi.Channels(OutputsData);

/// Stage 2 R09 validator: checks container vs bitstream dimension mismatches
/// and out-of-range video dimensions (`0` or `> 16384`).
pub const Service = struct {
    pub fn execute(_: *const Service, alloc: Allocator, inputs: Inputs) !Outputs {
        var findings: std.ArrayList(media_ir.AuditFindingRow) = .empty;
        errdefer findings.deinit(alloc);

        for (inputs.ir_codec_configs) |cfg| {
            const mismatch = cfg.is_mismatch or
                cfg.container_width != cfg.bitstream_width or
                cfg.container_height != cfg.bitstream_height;
            if (mismatch) {
                const msg = try std.fmt.allocPrint(
                    alloc,
                    "Track {d} ({s}) dimension mismatch: container {d}x{d} != bitstream {d}x{d}",
                    .{ cfg.track_id, cfg.codec_tag, cfg.container_width, cfg.container_height, cfg.bitstream_width, cfg.bitstream_height },
                );
                try findings.append(alloc, .{
                    .rule_id = "dimension_mismatch",
                    .severity = 3,
                    .region_tag = try alloc.dupe(u8, cfg.codec_tag),
                    .measured_value = @floatFromInt(cfg.track_id),
                    .message = msg,
                });
            }

            if (cfg.container_width == 0 or cfg.container_height == 0 or
                cfg.container_width > inputs.max_dimension or cfg.container_height > inputs.max_dimension)
            {
                const msg = try std.fmt.allocPrint(
                    alloc,
                    "Track {d} ({s}) out-of-range video dimensions {d}x{d}",
                    .{ cfg.track_id, cfg.codec_tag, cfg.container_width, cfg.container_height },
                );
                try findings.append(alloc, .{
                    .rule_id = "r09_codec_dimension_out_of_range",
                    .severity = 3,
                    .region_tag = try alloc.dupe(u8, cfg.codec_tag),
                    .measured_value = @floatFromInt(@max(cfg.container_width, cfg.container_height)),
                    .message = msg,
                });
            }
        }

        return .{ .data = .{
            .audit_findings = try findings.toOwnedSlice(alloc),
        } };
    }
};

