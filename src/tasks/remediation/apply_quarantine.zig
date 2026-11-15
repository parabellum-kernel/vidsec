const abi = @import("parabellum_abi");
const orders = @import("orders.zig");

pub const Inputs = struct {
    stream: abi.BoundedStreamReader,
    rule_id: []const u8,
    reason: []const u8 = "",
    severity: i64 = 4,
};

pub const ChannelsOut = struct {
    stream: abi.StreamOutput,
    remediation_outcomes: orders.RemediationReport,
};

pub const Outputs = abi.Channels(ChannelsOut);

/// Subscribes to `QuarantineOrder` + stream and forwards the unmodified hostile stream
/// to the `quarantine` sink while emitting a `RemediationReport`.
pub const Service = struct {
    emitter: abi.StreamEmitter,

    pub fn execute(self: *const Service, inputs: Inputs) !Outputs {
        const current_size = inputs.stream.len();
        if (current_size > 0) {
            try self.emitter.splice(0, current_size);
        }
        const stream_tok = try self.emitter.finish();

        return .{
            .data = .{
                .stream = stream_tok,
                .remediation_outcomes = .{
                    .action = "quarantine",
                    .rule_id = inputs.rule_id,
                    .offset = 0,
                    .length = current_size,
                    .new_size = current_size,
                    .applied = true,
                    .requires_reverify = false,
                },
            },
        };
    }
};

