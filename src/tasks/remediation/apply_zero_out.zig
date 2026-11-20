const abi = @import("parabellum_sdk").task;
const orders = @import("orders.zig");

pub const Inputs = struct {
    stream: abi.BoundedStreamReader,
    offset: u64,
    length: u64,
    rule_id: []const u8,
    reason: []const u8 = "",
};

pub const ChannelsOut = struct {
    stream: abi.StreamOutput,
    remediation_outcomes: orders.RemediationReport,
};

pub const Outputs = abi.Channels(ChannelsOut);

/// Subscribes to `ZeroOutOrder` + stream and emits a zero-copy spliced + zero-padded
/// stream via `abi.StreamEmitter` along with a `RemediationReport`.
pub const Service = struct {
    emitter: abi.StreamEmitter,
    logger: abi.Logger = .{},

    pub fn execute(self: *const Service, inputs: Inputs) !Outputs {
        const current_size = inputs.stream.len();
        const bounded_offset = @min(inputs.offset, current_size);
        const max_len = current_size - bounded_offset;
        const effective_len = @min(inputs.length, max_len);
        const should_apply = effective_len > 0;

        self.logger.warn(
            "Zeroing stream range: rule={s} offset={d} length={d} applied={} reason={s}",
            .{ inputs.rule_id, bounded_offset, effective_len, should_apply, inputs.reason },
        );

        if (bounded_offset > 0) {
            try self.emitter.splice(0, bounded_offset);
        }
        if (effective_len > 0) {
            try self.emitter.padZeroes(effective_len);
        }
        const tail_start = bounded_offset + effective_len;
        if (tail_start < current_size) {
            try self.emitter.splice(tail_start, current_size - tail_start);
        }
        const stream_tok = try self.emitter.finish();

        return .{
            .data = .{
                .stream = stream_tok,
                .remediation_outcomes = .{
                    .action = "zero_out",
                    .rule_id = inputs.rule_id,
                    .offset = bounded_offset,
                    .length = effective_len,
                    .new_size = current_size,
                    .applied = should_apply,
                    .requires_reverify = should_apply,
                },
            },
        };
    }
};
