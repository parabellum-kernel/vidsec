const std = @import("std");
const abi = @import("flowdata_abi");
const flowdata = @import("flowdata");
const vidsec = @import("vidsec");

const apply_truncate = vidsec.tasks.apply_truncate;
const apply_zero_out = vidsec.tasks.apply_zero_out;
const apply_quarantine = vidsec.tasks.apply_quarantine;
const orders = vidsec.tasks.remediation_orders;

const StreamEmitHost = struct {
    alloc: std.mem.Allocator,
    data: []const u8,
    emitted: std.ArrayListUnmanaged(u8) = .empty,
    finished: bool = false,
    ctx_abi: abi.TaskContext_ABI = undefined,
    vtable: abi.HostApiVTable_ABI = undefined,

    fn init(alloc: std.mem.Allocator, data: []const u8) StreamEmitHost {
        var self = StreamEmitHost{ .alloc = alloc, .data = data };
        self.vtable = std.mem.zeroes(abi.HostApiVTable_ABI);
        self.vtable.stream_size = &streamSize;
        self.vtable.stream_read_at = &streamReadAt;
        self.vtable.stream_write_chunk = &streamWriteChunk;
        self.vtable.stream_splice = &streamSplice;
        self.vtable.stream_pad_zeroes = &streamPadZeroes;
        self.vtable.stream_finish = &streamFinish;
        return self;
    }

    fn deinit(self: *StreamEmitHost) void {
        self.emitted.deinit(self.alloc);
    }

    fn ctx(self: *StreamEmitHost) abi.TaskContext {
        self.ctx_abi = .{
            .abi_version = abi.FLOWDATA_ABI_VERSION,
            .host = &self.vtable,
            .opaque_host_state = self,
        };
        return abi.TaskContext.init(&self.ctx_abi);
    }

    fn streamSize(raw: *abi.TaskContext_ABI) callconv(.c) u64 {
        const self: *const StreamEmitHost = @ptrCast(@alignCast(raw.opaque_host_state));
        return self.data.len;
    }

    fn streamReadAt(raw: *abi.TaskContext_ABI, offset: u64, dest_ptr: [*]u8, len: usize) callconv(.c) abi.HostError_ABI {
        const self: *const StreamEmitHost = @ptrCast(@alignCast(raw.opaque_host_state));
        if (offset + len > self.data.len) return .end_of_stream;
        @memcpy(dest_ptr[0..len], self.data[@intCast(offset)..][0..len]);
        return .ok;
    }

    fn streamWriteChunk(raw: *abi.TaskContext_ABI, _: ?[*:0]const u8, src_ptr: [*]const u8, len: usize) callconv(.c) abi.HostError_ABI {
        const self: *StreamEmitHost = @ptrCast(@alignCast(raw.opaque_host_state));
        self.emitted.appendSlice(self.alloc, src_ptr[0..len]) catch return .out_of_memory;
        return .ok;
    }

    fn streamSplice(raw: *abi.TaskContext_ABI, _: ?[*:0]const u8, offset: u64, length: u64) callconv(.c) abi.HostError_ABI {
        const self: *StreamEmitHost = @ptrCast(@alignCast(raw.opaque_host_state));
        if (offset + length > self.data.len) return .out_of_bounds;
        self.emitted.appendSlice(self.alloc, self.data[@intCast(offset)..][0..@intCast(length)]) catch return .out_of_memory;
        return .ok;
    }

    fn streamPadZeroes(raw: *abi.TaskContext_ABI, _: ?[*:0]const u8, length: u64) callconv(.c) abi.HostError_ABI {
        const self: *StreamEmitHost = @ptrCast(@alignCast(raw.opaque_host_state));
        self.emitted.appendNTimes(self.alloc, 0, @intCast(length)) catch return .out_of_memory;
        return .ok;
    }

    fn streamFinish(raw: *abi.TaskContext_ABI, _: ?[*:0]const u8) callconv(.c) abi.HostError_ABI {
        const self: *StreamEmitHost = @ptrCast(@alignCast(raw.opaque_host_state));
        self.finished = true;
        return .ok;
    }
};

test "apply_truncate splices prefix via StreamEmitter and marks re-verification" {
    const alloc = std.testing.allocator;
    var input: [32]u8 = undefined;
    for (&input, 0..) |*b, i| b.* = @intCast(i);

    var host = StreamEmitHost.init(alloc, &input);
    defer host.deinit();
    const tctx = host.ctx();
    const svc = apply_truncate.Service{ .emitter = abi.StreamEmitter.init(tctx, "stream") };

    const out = try svc.execute(.{
        .stream = tctx.streamReader(),
        .new_size = 20,
        .rule_id = "trailing_overlay",
        .reason = "Appended ZIP overlay",
    });

    const report = out.data.remediation_outcomes;
    try std.testing.expect(host.finished);
    try std.testing.expectEqualStrings("truncate", report.action);
    try std.testing.expect(report.applied);
    try std.testing.expect(report.requires_reverify);
    try std.testing.expectEqual(@as(usize, 20), host.emitted.items.len);
    try std.testing.expectEqualSlices(u8, input[0..20], host.emitted.items);
    try std.testing.expectEqual(@as(u64, 12), report.length);
}

test "apply_zero_out splices and pads zeroes via StreamEmitter" {
    const alloc = std.testing.allocator;
    const input: [32]u8 = @splat(0xAA);

    var host = StreamEmitHost.init(alloc, &input);
    defer host.deinit();
    const tctx = host.ctx();
    const svc = apply_zero_out.Service{ .emitter = abi.StreamEmitter.init(tctx, "stream") };

    const out = try svc.execute(.{
        .stream = tctx.streamReader(),
        .offset = 24,
        .length = 20,
        .rule_id = "hidden_padding_payload",
        .reason = "High-entropy free box",
    });

    const report = out.data.remediation_outcomes;
    try std.testing.expect(host.finished);
    try std.testing.expectEqualStrings("zero_out", report.action);
    try std.testing.expect(report.applied);
    try std.testing.expect(report.requires_reverify);
    try std.testing.expectEqual(@as(u64, 24), report.offset);
    try std.testing.expectEqual(@as(u64, 8), report.length);
    try std.testing.expectEqual(@as(usize, 32), host.emitted.items.len);
    try std.testing.expectEqualSlices(u8, input[0..24], host.emitted.items[0..24]);
    try std.testing.expectEqualSlices(u8, &@as([8]u8, @splat(0)), host.emitted.items[24..32]);
}

test "apply_quarantine forwards stream to quarantine sink without re-verification" {
    const alloc = std.testing.allocator;
    const input = "MZ\x90\x00hostile_payload";

    var host = StreamEmitHost.init(alloc, input);
    defer host.deinit();
    const tctx = host.ctx();
    const svc = apply_quarantine.Service{ .emitter = abi.StreamEmitter.init(tctx, "stream") };

    const out = try svc.execute(.{
        .stream = tctx.streamReader(),
        .rule_id = "stage0_embedded_executable",
        .reason = "Embedded MZ header",
        .severity = 4,
    });

    const report = out.data.remediation_outcomes;
    try std.testing.expect(host.finished);
    try std.testing.expectEqualStrings("quarantine", report.action);
    try std.testing.expect(report.applied);
    try std.testing.expect(!report.requires_reverify);
    try std.testing.expectEqualSlices(u8, input, host.emitted.items);
}

test "ARCH-036 TASK-036.6: End-to-end remediation stream swap, epoch re-verification, and chunked sink" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    const ProbeVerdict = struct { clean: bool };
    const ProbeSvc = struct {
        pub fn execute(_: *@This(), in: struct { stream: abi.BoundedStreamReader }) !abi.Channels(struct {
            verdict: ProbeVerdict,
            truncate_order: ?orders.TruncateOrder = null,
        }) {
            if (in.stream.len() > 12) {
                return .{ .data = .{
                    .verdict = .{ .clean = false },
                    .truncate_order = .{
                        .new_size = 12,
                        .rule_id = "trailing_overlay",
                        .reason = "Trim appended overlay",
                    },
                } };
            }
            return .{ .data = .{
                .verdict = .{ .clean = true },
                .truncate_order = null,
            } };
        }
    };
    _ = ProbeSvc;

    // Simpler probe returning Channels with TruncateOrder when dirty, and CleanVerdict when clean:
    const CleanProbe = struct {
        pub fn execute(_: *@This(), in: struct { stream: abi.BoundedStreamReader }) !abi.TaskStatus_ABI {
            _ = in;
            return .ok;
        }
    };
    _ = CleanProbe;

    // Use two tasks: probe_overlay (emits TruncateOrder if len > 12, else CleanVerdict) + apply_truncate
    const DirtyOut = struct { new_size: u64, rule_id: []const u8, reason: []const u8 };
    const OverlayProbeSvc = struct {
        ctx: abi.TaskContext,
        pub fn execute(self: *@This(), in: struct { stream: abi.BoundedStreamReader }) !abi.TaskStatus_ABI {
            if (in.stream.len() > 12) {
                try self.ctx.emitTypedRow(DirtyOut{
                    .new_size = 12,
                    .rule_id = "trailing_overlay",
                    .reason = "Trimmed",
                });
            } else {
                try self.ctx.emitTypedRow(ProbeVerdict{ .clean = true });
            }
            return .ok;
        }
    };

    var tasks = [_]abi.TaskDescriptor_ABI{
        abi.defineTaskService(OverlayProbeSvc, .{ .name = "probe_overlay" }),
        abi.defineTaskService(apply_truncate.Service, .{ .name = "apply_truncate" }),
    };
    const manifest = abi.ModuleManifest_ABI{
        .module_name = "e2e_reverify",
        .module_version = .{ .major = 1, .minor = 0, .patch = 0 },
        .tasks_ptr = &tasks,
        .tasks_len = tasks.len,
    };

    var mod_reg = flowdata.ModuleRegistry.init(alloc);
    defer mod_reg.deinit();
    try mod_reg.registerStaticModule("e2e_reverify", &manifest);

    const CapturingStreamRepo = struct {
        alloc: std.mem.Allocator,
        captured: std.ArrayListUnmanaged(u8) = .empty,

        fn writePayload(ctx: *anyopaque, channel: []const u8, payload: flowdata.dataflow.PayloadHandle) anyerror!void {
            const self: *@This() = @ptrCast(@alignCast(ctx));
            if (!std.mem.eql(u8, channel, "stream")) return;
            self.captured.clearRetainingCapacity();
            if (payload.stream_backing) |backing| {
                const total = backing.size();
                const buf = try self.alloc.alloc(u8, @intCast(total));
                defer self.alloc.free(buf);
                try backing.readAt(0, buf);
                try self.captured.appendSlice(self.alloc, buf);
            } else if (payload.len > 0 and payload.repr == .bytes) {
                const ptr: [*]const u8 = @ptrCast(payload.ptr);
                try self.captured.appendSlice(self.alloc, ptr[0..payload.len]);
            }
        }
        fn writePayloadWithParams(ctx: *anyopaque, channel: []const u8, payload: flowdata.dataflow.PayloadHandle, _: []const flowdata.repository.ConfigParam) anyerror!void {
            try writePayload(ctx, channel, payload);
        }
        fn readPayload(_: *anyopaque, _: []const u8) ?flowdata.dataflow.PayloadHandle {
            return null;
        }
        fn recordCount(ctx: *anyopaque, _: []const u8) usize {
            const self: *@This() = @ptrCast(@alignCast(ctx));
            return if (self.captured.items.len > 0) 1 else 0;
        }
        fn deinit(_: *anyopaque) void {}
        const vtable = flowdata.repository.StorageRepository.VTable{
            .writePayload = &writePayload,
            .writePayloadWithParams = &writePayloadWithParams,
            .readPayload = &readPayload,
            .recordCount = &recordCount,
            .deinit = &deinit,
        };
    };

    var repo_reg = flowdata.RepositoryRegistry.init(alloc);
    defer repo_reg.deinit();
    var cap_repo = CapturingStreamRepo{ .alloc = alloc };
    try repo_reg.register("artifacts", .{ .ptr = &cap_repo, .vtable = &CapturingStreamRepo.vtable });

    const yaml_text =
        \\version: 2
        \\runtime:
        \\  scheduler: dag
        \\  workers: 1
        \\  routing: type_driven
        \\  max_activations_per_node: 3
        \\pipelines:
        \\  main:
        \\    steps:
        \\      - id: probe
        \\        uses: e2e_reverify/probe_overlay
        \\      - id: sanitize_truncate
        \\        uses: e2e_reverify/apply_truncate
        \\        outputs:
        \\          stream:
        \\            datasource: artifacts
    ;

    const ast = try flowdata.yaml.loadPipelineAstFromYaml(alloc, yaml_text, .{});
    var eng = flowdata.PipelineEngine.init(alloc, ast, &mod_reg, &repo_reg);
    defer eng.deinit();

    const raw_bytes = "CLEAN_HEADEREXTRA_OVERLAY";
    const summary = try eng.run(flowdata.dataflow.PayloadHandle.fromSlice(u8, raw_bytes));
    // Epoch 0: probe (1) -> sanitize_truncate (2); Epoch 1: probe re-runs (3) -> clean!
    try std.testing.expectEqual(@as(usize, 3), summary.steps_executed);

    // Verify artifacts sink received only the 12-byte sanitized header via StreamBacking
    try std.testing.expectEqual(@as(usize, 12), cap_repo.captured.items.len);
    try std.testing.expectEqualSlices(u8, "CLEAN_HEADER", cap_repo.captured.items);
}
