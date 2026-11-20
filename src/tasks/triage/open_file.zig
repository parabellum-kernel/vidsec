const std = @import("std");
const Allocator = std.mem.Allocator;
const abi = @import("parabellum_sdk").task;

pub const Inputs = struct {
    path: []const u8,
};

pub const ChannelsOut = struct {
    stream: abi.StreamOutput,
};

pub const Outputs = abi.Channels(ChannelsOut);

/// Opens a local media file at `path` and streams its bytes into `stream` via `StreamEmitter`.
pub const Service = struct {
    emitter: abi.StreamEmitter,
    logger: abi.Logger = .{},

    pub fn execute(self: *const Service, alloc: Allocator, inputs: Inputs) !Outputs {
        const path_z = try alloc.dupeSentinel(u8, inputs.path, 0);
        defer alloc.free(path_z);

        const fp = std.c.fopen(path_z.ptr, "rb") orelse {
            self.logger.err("Failed to open input file: {s}", .{inputs.path});
            return error.FileNotFound;
        };
        defer _ = std.c.fclose(fp);

        var buf: [65536]u8 = undefined;
        var total_bytes: u64 = 0;
        while (true) {
            const n = std.c.fread(&buf, 1, buf.len, fp);
            if (n == 0) break;
            try self.emitter.writeChunk(buf[0..n]);
            total_bytes += n;
        }
        const stream_tok = try self.emitter.finish();

        self.logger.info("Loaded input file: path={s} bytes={d}", .{ inputs.path, total_bytes });

        return .{
            .data = .{
                .stream = stream_tok,
            },
        };
    }
};
