const abi = @import("parabellum_sdk").task;
const tika = @import("tika");
const magic = @import("vidsec_magic");

pub const Inputs = struct {
    stream: abi.BoundedStreamReader,
    max_scan_bytes: i64 = tika.RECOMMENDED_HEADER_BYTES,
};

pub const Outputs = struct {
    has_suspicious_script: bool,
    matched_keyword: []const u8,
};

/// Stage 0 Check 5: Scans leading 64 KB for suspicious script, shell, or playlist indicators.
pub const Service = struct {
    pub fn execute(_: *const Service, inputs: Inputs) !Outputs {
        const file_size = inputs.stream.len();
        const max_bytes: usize = if (inputs.max_scan_bytes > 0)
            @intCast(@min(@as(u64, @intCast(inputs.max_scan_bytes)), tika.RECOMMENDED_HEADER_BYTES))
        else
            tika.RECOMMENDED_HEADER_BYTES;

        var head_buf: [tika.RECOMMENDED_HEADER_BYTES]u8 = undefined;
        const head_len: usize = @intCast(@min(file_size, max_bytes));
        if (head_len > 0) {
            try inputs.stream.readAt(0, head_buf[0..head_len]);
        }

        if (magic.scanHeadScripts(head_buf[0..head_len])) |kw| {
            return .{
                .has_suspicious_script = true,
                .matched_keyword = kw,
            };
        }

        return .{
            .has_suspicious_script = false,
            .matched_keyword = "",
        };
    }
};

