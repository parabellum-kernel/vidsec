const std = @import("std");
const Allocator = std.mem.Allocator;
const abi = @import("parabellum_sdk").task;

pub const Inputs = struct {
    path: []const u8,
};

pub const InputFileRow = struct {
    file_id: i64,
    file_path: []const u8,
    file_name: []const u8,
    declared_extension: []const u8,
    file_size: u64,
    analyzed_at_ns: i64,
};

pub const ChannelsOut = struct {
    stream: abi.StreamOutput,
    input_files: InputFileRow,
    file_id: i64,
    declared_extension: []const u8,
};

pub const Outputs = abi.Channels(ChannelsOut);

var last_file_id: std.atomic.Value(i64) = .init(0);

fn nowNs() i64 {
    var ts: std.c.timespec = undefined;
    if (std.c.clock_gettime(.REALTIME, &ts) != 0) return 0;
    return @as(i64, @intCast(ts.sec)) * 1_000_000_000 + @as(i64, @intCast(ts.nsec));
}

fn nextFileId(ts_ns: i64) i64 {
    const base = if (ts_ns > 0) ts_ns else 1;
    while (true) {
        const prev = last_file_id.load(.acquire);
        const next = @max(prev + 1, base);
        if (last_file_id.cmpxchgWeak(prev, next, .acq_rel, .acquire) == null) {
            return next;
        }
    }
}

/// Opens a local media file at `path`, registers an `InputFileRow` with a unique `file_id`,
/// and streams its bytes into `stream` via `StreamEmitter`.
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

        const ts_ns = nowNs();
        const fid = nextFileId(ts_ns);
        const file_path = try alloc.dupe(u8, inputs.path);
        const file_name = try alloc.dupe(u8, std.fs.path.basename(inputs.path));
        const ext_raw = std.fs.path.extension(inputs.path);
        const ext = try alloc.dupe(u8, if (ext_raw.len > 0 and ext_raw[0] == '.') ext_raw[1..] else ext_raw);

        self.logger.info("Loaded input file: file_id={d} path={s} bytes={d}", .{ fid, inputs.path, total_bytes });

        return .{
            .data = .{
                .stream = stream_tok,
                .input_files = .{
                    .file_id = fid,
                    .file_path = file_path,
                    .file_name = file_name,
                    .declared_extension = ext,
                    .file_size = total_bytes,
                    .analyzed_at_ns = ts_ns,
                },
                .file_id = fid,
                .declared_extension = ext,
            },
        };
    }
};
