const abi = @import("flowdata_abi");
const orders = @import("orders.zig");

pub const Inputs = struct {
    stream: abi.BoundedStreamReader,
    new_size: u64,
    rule_id: []const u8,
    reason: []const u8 = "",
};

pub const ChannelsOut = struct {
    stream: abi.StreamOutput,
    remediation_outcomes: orders.RemediationReport,
};

pub const Outputs = abi.Channels(ChannelsOut);

/// Subscribes to `TruncateOrder` + stream and emits a zero-copy spliced stream
/// via `abi.StreamEmitter` along with a `RemediationReport` on `remediation_outcomes`.
pub const Service = struct {
    emitter: abi.StreamEmitter,

    pub fn execute(self: *const Service, inputs: Inputs) !Outputs {
        const current_size = inputs.stream.len();
        const effective_size = @min(inputs.new_size, current_size);
        const should_apply = effective_size < current_size;

        if (effective_size > 0) {
            try self.emitter.splice(0, effective_size);
        }
        const stream_tok = try self.emitter.finish();

        return .{
            .data = .{
                .stream = stream_tok,
                .remediation_outcomes = .{
                    .action = "truncate",
                    .rule_id = inputs.rule_id,
                    .offset = effective_size,
                    .length = if (should_apply) current_size - effective_size else 0,
                    .new_size = effective_size,
                    .applied = should_apply,
                    .requires_reverify = should_apply,
                },
            },
        };
    }
};
