const std = @import("std");
const parabellum = @import("parabellum");
const yaml_config = @import("yaml_config");
const sdk = @import("parabellum_sdk");
const tui = @import("tui_inbound");

const abi = sdk.abi;
const inbound = sdk.transport.inbound;

pub var transport_ctx_marker: u8 = 0;
var global_event_ring = tui.EventRing{};
var global_catalog_parsed: ?std.json.Parsed(sdk.capabilities.CapabilityCatalog) = null;
var global_kernel: ?*abi.extension.KernelHandle_ABI = null;
var global_api: ?*const abi.KernelApiVTable_ABI = null;

// -----------------------------------------------------------------------------
// Live Pipeline & Job Telemetry Monitor
// -----------------------------------------------------------------------------

const StageId = enum(usize) {
    ingest = 0,
    triage = 1,
    dissect = 2,
    checks = 3,
    lower = 4,
    forensics = 5,
    cdr = 6,

    const count = 7;

    fn label(self: StageId) []const u8 {
        return switch (self) {
            .ingest => "Ingest  ",
            .triage => "Stage 0 ",
            .dissect => "Stage 1a",
            .checks => "Stage 1b",
            .lower => "Stage 1c",
            .forensics => "Stage 2 ",
            .cdr => "Stage 3 ",
        };
    }

    fn desc(self: StageId) []const u8 {
        return switch (self) {
            .ingest => "File Open & Stream",
            .triage => "Pre-Triage Gatekeeper",
            .dissect => "Container Dissectors",
            .checks => "Structure & CVE Checks",
            .lower => "Media IR Lowering",
            .forensics => "IR Forensics (R02-R10)",
            .cdr => "Remediation / Quarantine",
        };
    }
};

const StageStats = struct {
    active: u16 = 0,
    ok: u16 = 0,
    err: u16 = 0,
    last_step: [48]u8 = undefined,
    last_step_len: usize = 0,
    total_ns: u64 = 0,

    fn setLastStep(self: *StageStats, name: []const u8) void {
        const n = @min(name.len, self.last_step.len);
        @memcpy(self.last_step[0..n], name[0..n]);
        self.last_step_len = n;
    }
};

const JobStatus = enum {
    idle,
    running,
    completed,
    quarantined,
    failed,
};

const StepStatus = enum {
    running,
    ok,
    err,
};

const StepRecord = struct {
    name: [64]u8 = undefined,
    name_len: usize = 0,
    stage: StageId = .ingest,
    status: StepStatus = .running,
    duration_ns: u64 = 0,
    outputs: u64 = 0,
    msg: [128]u8 = undefined,
    msg_len: usize = 0,

    fn nameSlice(self: *const StepRecord) []const u8 {
        return self.name[0..self.name_len];
    }

    fn msgSlice(self: *const StepRecord) []const u8 {
        return self.msg[0..self.msg_len];
    }

    fn setName(self: *StepRecord, s: []const u8) void {
        const n = @min(s.len, self.name.len);
        @memcpy(self.name[0..n], s[0..n]);
        self.name_len = n;
    }

    fn setMsg(self: *StepRecord, s: []const u8) void {
        const n = @min(s.len, self.msg.len);
        @memcpy(self.msg[0..n], s[0..n]);
        self.msg_len = n;
    }
};

const MAX_STEPS: usize = 128;

const StepStageEntry = struct {
    name: [64]u8 = undefined,
    name_len: usize = 0,
    stage: StageId = .forensics,

    fn nameSlice(self: *const StepStageEntry) []const u8 {
        return self.name[0..self.name_len];
    }
};

const MAX_PIPELINE_ENTRIES: usize = 128;

const PipelineMonitor = struct {
    mutex: std.Io.Mutex = .init,
    status: JobStatus = .idle,
    file_name: [128]u8 = undefined,
    file_name_len: usize = 0,
    pipeline_path: [512]u8 = undefined,
    pipeline_path_len: usize = 0,
    step_map: [MAX_PIPELINE_ENTRIES]StepStageEntry = undefined,
    step_map_count: usize = 0,
    trace_hex: [32]u8 = @splat('0'),
    has_trace: bool = false,
    pipeline_duration_ns: u64 = 0,
    steps_reported: u64 = 0,
    halted: bool = false,
    stages: [StageId.count]StageStats = @splat(.{}),
    steps: [MAX_STEPS]StepRecord = undefined,
    step_count: usize = 0,
    scroll: usize = 0,
    verdict: [128]u8 = undefined,
    verdict_len: usize = 0,
    findings_count: u32 = 0,
    remediated_count: u32 = 0,
    error_step: [64]u8 = undefined,
    error_step_len: usize = 0,
    error_msg: [192]u8 = undefined,
    error_msg_len: usize = 0,

    fn setPipelinePath(self: *PipelineMonitor, path: []const u8) void {
        self.mutex.lockUncancelable(std.Options.debug_io);
        const n = @min(path.len, self.pipeline_path.len);
        @memcpy(self.pipeline_path[0..n], path[0..n]);
        self.pipeline_path_len = n;
        self.mutex.unlock(std.Options.debug_io);
        self.reloadPipelineLayout();
    }

    /// Loads step -> stage mappings dynamically from `pipeline.yaml` and its imports.
    fn reloadPipelineLayout(self: *PipelineMonitor) void {
        var path_buf: [512]u8 = undefined;
        var path_len: usize = 0;
        {
            self.mutex.lockUncancelable(std.Options.debug_io);
            defer self.mutex.unlock(std.Options.debug_io);
            path_len = self.pipeline_path_len;
            @memcpy(path_buf[0..path_len], self.pipeline_path[0..path_len]);
        }
        if (path_len == 0) return;

        var arena = std.heap.ArenaAllocator.init(std.heap.c_allocator);
        defer arena.deinit();
        const alloc = arena.allocator();

        var abi_builder = parabellum.config.builder_abi.AbiPipelineBuilder.init(alloc);
        yaml_config.loadPipelineWithBuilder(
            alloc,
            path_buf[0..path_len],
            abi_builder.handle(),
            &parabellum.config.builder_abi.AbiPipelineBuilder.vtable,
        ) catch return;
        const ast = abi_builder.buildAst() catch return;

        self.mutex.lockUncancelable(std.Options.debug_io);
        defer self.mutex.unlock(std.Options.debug_io);
        self.step_map_count = 0;
        for (ast.pipelines) |p| {
            for (p.steps) |s| {
                if (self.step_map_count >= MAX_PIPELINE_ENTRIES) return;
                const sid = s.id();
                if (sid.len == 0) continue;
                var entry = &self.step_map[self.step_map_count];
                const n = @min(sid.len, entry.name.len);
                @memcpy(entry.name[0..n], sid[0..n]);
                entry.name_len = n;
                entry.stage = classifyStepFromAst(p.name, s);
                self.step_map_count += 1;
            }
        }
    }

    fn classify(self: *const PipelineMonitor, name: []const u8) StageId {
        for (self.step_map[0..self.step_map_count]) |*entry| {
            if (std.mem.eql(u8, entry.nameSlice(), name)) return entry.stage;
        }
        return classifyStepFallback(name);
    }

    fn resetForFile(self: *PipelineMonitor, path: []const u8) void {
        self.reloadPipelineLayout();
        self.mutex.lockUncancelable(std.Options.debug_io);
        defer self.mutex.unlock(std.Options.debug_io);

        self.status = .running;
        const base = std.fs.path.basename(path);
        const n = @min(base.len, self.file_name.len);
        @memcpy(self.file_name[0..n], base[0..n]);
        self.file_name_len = n;
        self.has_trace = false;
        self.pipeline_duration_ns = 0;
        self.steps_reported = 0;
        self.halted = false;
        self.stages = @splat(.{});
        self.step_count = 0;
        self.scroll = 0;
        self.verdict_len = 0;
        self.findings_count = 0;
        self.remediated_count = 0;
        self.error_step_len = 0;
        self.error_msg_len = 0;
    }

    fn findOrAddStep(self: *PipelineMonitor, name: []const u8) ?*StepRecord {
        var i: usize = self.step_count;
        while (i > 0) {
            i -= 1;
            if (std.mem.eql(u8, self.steps[i].nameSlice(), name)) {
                return &self.steps[i];
            }
        }
        if (self.step_count >= MAX_STEPS) return null;
        const rec = &self.steps[self.step_count];
        rec.* = .{};
        rec.setName(name);
        rec.stage = self.classify(name);
        self.step_count += 1;
        return rec;
    }

    fn onEvent(self: *PipelineMonitor, ev: *const abi.TelemetryEvent_ABI) void {
        var emit_verdict_buf: [128]u8 = undefined;
        var emit_verdict_len: usize = 0;
        var emit_verdict_lvl: u32 = 1;

        {
            self.mutex.lockUncancelable(std.Options.debug_io);
            defer self.mutex.unlock(std.Options.debug_io);

            const primary = ev.primary_name.toSlice();
            const secondary = ev.secondary_name.toSlice();
            const payload = ev.payload.toSlice();

            switch (ev.kind) {
                .pipeline_start => {
                    self.status = .running;
                    self.stages = @splat(.{});
                    self.step_count = 0;
                    self.scroll = 0;
                    self.pipeline_duration_ns = 0;
                    self.steps_reported = 0;
                    self.halted = false;
                    self.verdict_len = 0;
                    self.findings_count = 0;
                    self.remediated_count = 0;
                    self.error_step_len = 0;
                    self.error_msg_len = 0;
                    formatTraceHex(&self.trace_hex, ev.trace_id);
                    self.has_trace = true;
                },
                .pipeline_end => {
                    self.pipeline_duration_ns = ev.duration_ns;
                    self.steps_reported = ev.count_a;
                    self.halted = ev.flags != 0;
                    if (self.status == .running) {
                        self.status = if (self.halted or self.error_step_len > 0) .failed else .completed;
                    }
                    const v_text = switch (self.status) {
                        .failed => std.fmt.bufPrint(&self.verdict, "Global verdict: FAILED (steps={d}, findings={d})", .{ self.steps_reported, self.findings_count }) catch "Global verdict: FAILED",
                        .quarantined => std.fmt.bufPrint(&self.verdict, "Global verdict: QUARANTINED (findings={d})", .{self.findings_count}) catch "Global verdict: QUARANTINED",
                        else => if (self.findings_count > 0)
                            std.fmt.bufPrint(&self.verdict, "Global verdict: FLAGGED (findings={d}, remediated={d})", .{ self.findings_count, self.remediated_count }) catch "Global verdict: FLAGGED"
                        else
                            std.fmt.bufPrint(&self.verdict, "Global verdict: PASSED (0 findings, steps={d})", .{self.steps_reported}) catch "Global verdict: PASSED",
                    };
                    self.verdict_len = v_text.len;
                    @memcpy(emit_verdict_buf[0..v_text.len], v_text);
                    emit_verdict_len = v_text.len;
                    emit_verdict_lvl = switch (self.status) {
                        .failed, .quarantined => 3,
                        else => if (self.findings_count > 0) 2 else 1,
                    };
                },
                .step_start => {
                    const st = self.classify(primary);
                    self.stages[@intFromEnum(st)].active +|= 1;
                    self.stages[@intFromEnum(st)].setLastStep(primary);
                    if (self.findOrAddStep(primary)) |rec| {
                        rec.status = .running;
                        rec.duration_ns = 0;
                    }
                },
                .step_end => {
                    const st = self.classify(primary);
                    const s = &self.stages[@intFromEnum(st)];
                    if (s.active > 0) s.active -= 1;
                    s.total_ns +|= ev.duration_ns;
                    const is_ok = std.mem.eql(u8, secondary, "ok");
                    if (is_ok) {
                        s.ok +|= 1;
                    } else {
                        s.err +|= 1;
                        self.status = .failed;
                        const sn = @min(primary.len, self.error_step.len);
                        @memcpy(self.error_step[0..sn], primary[0..sn]);
                        self.error_step_len = sn;
                        if (payload.len > 0 and self.error_msg_len == 0) {
                            const mn = @min(payload.len, self.error_msg.len);
                            @memcpy(self.error_msg[0..mn], payload[0..mn]);
                            self.error_msg_len = mn;
                        }
                    }
                    if (self.findOrAddStep(primary)) |rec| {
                        rec.status = if (is_ok) .ok else .err;
                        rec.duration_ns = ev.duration_ns;
                        rec.outputs = ev.count_a;
                        if (!is_ok and payload.len > 0) rec.setMsg(payload);
                    }
                },
                .task_log => {
                    if (std.mem.indexOf(u8, payload, "Quarantining stream:") != null) {
                        self.status = .quarantined;
                    }
                    if (std.mem.indexOf(u8, payload, "Finding [") != null or
                        std.mem.indexOf(u8, payload, "Stage 0 finding:") != null)
                    {
                        self.findings_count +|= 1;
                    }
                    if (std.mem.indexOf(u8, payload, "Truncating stream:") != null or
                        std.mem.indexOf(u8, payload, "Zeroing stream range:") != null)
                    {
                        self.remediated_count +|= 1;
                    }
                    if (primary.len > 0 and payload.len > 0) {
                        if (self.findOrAddStep(primary)) |rec| {
                            if (rec.msg_len == 0 or ev.count_a >= 2) {
                                rec.setMsg(payload);
                            }
                        }
                    }
                    // Level >= 2 (warn=2, err=3)
                    if (ev.count_a >= 2 and payload.len > 0) {
                        if (self.error_step_len == 0 and primary.len > 0) {
                            const sn = @min(primary.len, self.error_step.len);
                            @memcpy(self.error_step[0..sn], primary[0..sn]);
                            self.error_step_len = sn;
                        }
                        const mn = @min(payload.len, self.error_msg.len);
                        @memcpy(self.error_msg[0..mn], payload[0..mn]);
                        self.error_msg_len = mn;
                    }
                },
                else => {},
            }
        }

        if (emit_verdict_len > 0) {
            if (global_kernel) |k| {
                if (global_api) |api| {
                    _ = api.emit_log(k, emit_verdict_lvl, abi.Slice_ABI.from(emit_verdict_buf[0..emit_verdict_len]));
                }
            }
        }
    }

    fn snapshot(self: *PipelineMonitor) PipelineMonitorSnapshot {
        self.mutex.lockUncancelable(std.Options.debug_io);
        defer self.mutex.unlock(std.Options.debug_io);
        return .{
            .status = self.status,
            .file_name = self.file_name,
            .file_name_len = self.file_name_len,
            .trace_hex = self.trace_hex,
            .has_trace = self.has_trace,
            .pipeline_duration_ns = self.pipeline_duration_ns,
            .steps_reported = self.steps_reported,
            .halted = self.halted,
            .stages = self.stages,
            .steps = self.steps,
            .step_count = self.step_count,
            .scroll = self.scroll,
            .verdict = self.verdict,
            .verdict_len = self.verdict_len,
            .error_step = self.error_step,
            .error_step_len = self.error_step_len,
            .error_msg = self.error_msg,
            .error_msg_len = self.error_msg_len,
        };
    }

    fn handleKey(ctx: ?*anyopaque, key: tui.Key, _: inbound.HostDispatcher) anyerror!bool {
        const self: *PipelineMonitor = @ptrCast(@alignCast(ctx.?));
        self.mutex.lockUncancelable(std.Options.debug_io);
        defer self.mutex.unlock(std.Options.debug_io);
        switch (key) {
            .up => {
                if (self.scroll > 0) self.scroll -= 1;
                return true;
            },
            .down => {
                self.scroll += 1;
                return true;
            },
            .page_up => {
                self.scroll -|= 8;
                return true;
            },
            .page_down => {
                self.scroll += 8;
                return true;
            },
            .home => {
                self.scroll = 0;
                return true;
            },
            .char => |ch| switch (ch) {
                'k' => {
                    if (self.scroll > 0) self.scroll -= 1;
                    return true;
                },
                'j' => {
                    self.scroll += 1;
                    return true;
                },
                else => return false,
            },
            else => return false,
        }
    }

    fn render(ctx: ?*anyopaque, surface: tui.PanelSurface, _: bool) void {
        const self: *PipelineMonitor = @ptrCast(@alignCast(ctx.?));
        const snap = self.snapshot();

        surface.fillRect(0, 0, surface.width, surface.height, ' ', .{});
        if (surface.width < 12 or surface.height < 5) return;

        // Line 0: Job status header
        const badge_style: tui.Style = switch (snap.status) {
            .idle => .{ .fg = .bright_black, .bold = true },
            .running => .{ .fg = .bright_yellow, .bold = true },
            .completed => .{ .fg = .bright_green, .bold = true },
            .quarantined => .{ .fg = .bright_red, .bold = true },
            .failed => .{ .fg = .bright_red, .bold = true },
        };
        const badge_text: []const u8 = switch (snap.status) {
            .idle => "[IDLE]",
            .running => "[RUNNING]",
            .completed => "[PASSED]",
            .quarantined => "[QUARANTINED]",
            .failed => "[FAILED]",
        };
        surface.drawText(1, 0, @intCast(badge_text.len), badge_text, badge_style);

        var hdr_buf: [256]u8 = undefined;
        const fname = if (snap.file_name_len > 0) snap.file_name[0..snap.file_name_len] else "(select a video file on the left and press Enter)";
        const dur_ms: f64 = @as(f64, @floatFromInt(snap.pipeline_duration_ns)) / 1_000_000.0;
        const hdr_str = if (snap.pipeline_duration_ns > 0)
            std.fmt.bufPrint(&hdr_buf, " {s}  |  {d:.1} ms  |  steps={d}", .{ fname, dur_ms, snap.steps_reported }) catch fname
        else if (snap.has_trace)
            std.fmt.bufPrint(&hdr_buf, " {s}  |  trace={s}", .{ fname, snap.trace_hex[0..12] }) catch fname
        else
            std.fmt.bufPrint(&hdr_buf, " {s}", .{fname}) catch fname;

        const start_x: u16 = @intCast(@min(badge_text.len + 1, surface.width));
        surface.drawText(start_x, 0, surface.width -| start_x, hdr_str, .{ .fg = .bright_white, .bold = true });

        // Line 1: separator
        surface.fillRect(0, 1, surface.width, 1, '-', .{ .fg = .bright_black, .dim = true });

        // Footer reserved lines for Verdict / Diagnostics
        var footer_lines: u16 = 0;
        if (snap.verdict_len > 0) footer_lines += 1;
        if (snap.error_step_len > 0 or snap.error_msg_len > 0) footer_lines += 1;
        if (footer_lines > 0) footer_lines += 1; // separator

        const body_top: u16 = 2;
        const body_h: usize = if (surface.height > body_top + footer_lines)
            surface.height - body_top - footer_lines
        else
            0;

        // Build virtual lines for the full stage-grouped task DAG (always show all stages)
        var total_vlines: usize = 0;
        inline for (0..StageId.count) |si| {
            const st_id: StageId = @enumFromInt(si);
            var stage_steps: usize = 0;
            for (snap.steps[0..snap.step_count]) |step| {
                if (step.stage == st_id) stage_steps += 1;
            }
            total_vlines += 1 + stage_steps;
        }

        const max_scroll = if (total_vlines > body_h) total_vlines - body_h else 0;
        const eff_scroll = @min(snap.scroll, max_scroll);

        var vline: usize = 0;
        inline for (0..StageId.count) |si| {
            const st_id: StageId = @enumFromInt(si);
            const st = snap.stages[si];
            var stage_steps: usize = 0;
            for (snap.steps[0..snap.step_count]) |step| {
                if (step.stage == st_id) stage_steps += 1;
            }
            {
                if (vline >= eff_scroll and vline - eff_scroll < body_h) {
                    const ly: u16 = body_top + @as(u16, @intCast(vline - eff_scroll));
                    const st_style: tui.Style = if (st.err > 0)
                        .{ .fg = .bright_red, .bold = true }
                    else if (st.active > 0)
                        .{ .fg = .bright_yellow, .bold = true }
                    else if (st.ok > 0)
                        .{ .fg = .bright_green, .bold = true }
                    else
                        .{ .fg = .bright_black, .dim = true };

                    var sbuf: [160]u8 = undefined;
                    const st_ms: f64 = @as(f64, @floatFromInt(st.total_ns)) / 1_000_000.0;
                    const sline = if (st.active > 0 or st.ok > 0 or st.err > 0)
                        std.fmt.bufPrint(&sbuf, "[{s}] {s}  (ok:{d} act:{d} err:{d} {d:.1}ms)", .{ st_id.label(), st_id.desc(), st.ok, st.active, st.err, st_ms }) catch st_id.desc()
                    else
                        std.fmt.bufPrint(&sbuf, "[{s}] {s}  (idle)", .{ st_id.label(), st_id.desc() }) catch st_id.desc();
                    surface.drawText(1, ly, surface.width -| 2, sline, st_style);
                }
                vline += 1;

                var seen_in_stage: usize = 0;
                for (snap.steps[0..snap.step_count]) |*step| {
                    if (step.stage != st_id) continue;
                    seen_in_stage += 1;
                    if (vline >= eff_scroll and vline - eff_scroll < body_h) {
                        const ly: u16 = body_top + @as(u16, @intCast(vline - eff_scroll));
                        const step_style: tui.Style = switch (step.status) {
                            .running => .{ .fg = .bright_yellow, .bold = true },
                            .ok => .{ .fg = .green },
                            .err => .{ .fg = .bright_red, .bold = true },
                        };
                        const tag: []const u8 = switch (step.status) {
                            .running => "[RUN]",
                            .ok => "[OK ]",
                            .err => "[ERR]",
                        };
                        const branch: []const u8 = if (seen_in_stage == stage_steps) "`-" else "|-";
                        const ms: f64 = @as(f64, @floatFromInt(step.duration_ns)) / 1_000_000.0;

                        var tbuf: [256]u8 = undefined;
                        const msg = step.msgSlice();
                        const tline = if (msg.len > 0)
                            std.fmt.bufPrint(&tbuf, "  {s} {s} {s:<34} {d:6.2}ms  {s}", .{ branch, tag, step.nameSlice(), ms, msg }) catch step.nameSlice()
                        else if (step.status == .running)
                            std.fmt.bufPrint(&tbuf, "  {s} {s} {s}", .{ branch, tag, step.nameSlice() }) catch step.nameSlice()
                        else
                            std.fmt.bufPrint(&tbuf, "  {s} {s} {s:<34} {d:6.2}ms  out={d}", .{ branch, tag, step.nameSlice(), ms, step.outputs }) catch step.nameSlice();

                        surface.drawText(1, ly, surface.width -| 2, tline, step_style);
                    }
                    vline += 1;
                }
            }
        }

        // Render footer diagnostics
        if (footer_lines > 0 and surface.height >= footer_lines) {
            var fy: u16 = surface.height - footer_lines;
            surface.fillRect(0, fy, surface.width, 1, '-', .{ .fg = .bright_black, .dim = true });
            fy += 1;
            if (snap.verdict_len > 0 and fy < surface.height) {
                const vstyle: tui.Style = if (snap.status == .quarantined)
                    .{ .fg = .bright_red, .bold = true }
                else
                    .{ .fg = .bright_green, .bold = true };
                surface.drawText(1, fy, surface.width -| 2, snap.verdict[0..snap.verdict_len], vstyle);
                fy += 1;
            }
            if ((snap.error_step_len > 0 or snap.error_msg_len > 0) and fy < surface.height) {
                var ebuf: [256]u8 = undefined;
                const estep = snap.error_step[0..snap.error_step_len];
                const emsg = snap.error_msg[0..snap.error_msg_len];
                const eline = if (estep.len > 0 and emsg.len > 0)
                    std.fmt.bufPrint(&ebuf, "Diagnostic [{s}]: {s}", .{ estep, emsg }) catch emsg
                else if (emsg.len > 0)
                    std.fmt.bufPrint(&ebuf, "Diagnostic: {s}", .{emsg}) catch emsg
                else
                    std.fmt.bufPrint(&ebuf, "Failed step: {s}", .{estep}) catch estep;
                surface.drawText(1, fy, surface.width -| 2, eline, .{ .fg = .bright_red, .bold = true });
            }
        }
    }
};

const PipelineMonitorSnapshot = struct {
    status: JobStatus,
    file_name: [128]u8,
    file_name_len: usize,
    trace_hex: [32]u8,
    has_trace: bool,
    pipeline_duration_ns: u64,
    steps_reported: u64,
    halted: bool,
    stages: [StageId.count]StageStats,
    steps: [MAX_STEPS]StepRecord,
    step_count: usize,
    scroll: usize,
    verdict: [128]u8,
    verdict_len: usize,
    error_step: [64]u8,
    error_step_len: usize,
    error_msg: [192]u8,
    error_msg_len: usize,
};

var global_monitor = PipelineMonitor{};

fn classifyStepFromAst(pipeline_name: []const u8, step: parabellum.ast.StepNode) StageId {
    if (std.mem.eql(u8, pipeline_name, "ingest")) return .ingest;
    if (std.mem.eql(u8, pipeline_name, "structure_checks") or
        std.mem.startsWith(u8, pipeline_name, "cve_")) return .checks;
    if (std.mem.eql(u8, pipeline_name, "forensics_ir") or
        std.mem.eql(u8, pipeline_name, "attachments")) return .forensics;

    switch (step) {
        .task => |t| {
            if (std.mem.eql(u8, t.module, "fs")) return .ingest;
            if (std.mem.startsWith(u8, t.task, "dissect_")) return .dissect;
            if (std.mem.startsWith(u8, t.task, "lower_")) return .lower;
            if (std.mem.startsWith(u8, t.task, "apply_")) return .cdr;
            if (std.mem.startsWith(u8, t.task, "analyze_")) return .forensics;
            if (std.mem.startsWith(u8, t.task, "inspect_") or
                std.mem.startsWith(u8, t.task, "check_region_")) return .checks;
            if (std.mem.startsWith(u8, t.task, "check_mp4_") or
                std.mem.startsWith(u8, t.task, "check_mkv_") or
                std.mem.startsWith(u8, t.task, "check_avi_")) return .checks;
            if (std.mem.startsWith(u8, t.task, "check_r") or
                std.mem.startsWith(u8, t.task, "check_inconsistencies") or
                std.mem.startsWith(u8, t.task, "scan_entropy")) return .forensics;
            if (std.mem.startsWith(u8, t.task, "check_file_size") or
                std.mem.startsWith(u8, t.task, "detect_magic") or
                std.mem.startsWith(u8, t.task, "check_extension") or
                std.mem.startsWith(u8, t.task, "scan_") or
                std.mem.startsWith(u8, t.task, "measure_") or
                std.mem.startsWith(u8, t.task, "evaluate_triage")) return .triage;
        },
        .router => return .ingest,
    }
    return classifyStepFallback(step.id());
}

fn classifyStepFallback(step_name: []const u8) StageId {
    if (std.mem.eql(u8, step_name, "open_input_file")) return .ingest;
    if (std.mem.startsWith(u8, step_name, "stage0_")) return .triage;
    if (std.mem.startsWith(u8, step_name, "dissect_")) return .dissect;
    if (std.mem.startsWith(u8, step_name, "cve_") or
        std.mem.startsWith(u8, step_name, "check_mp4_") or
        std.mem.startsWith(u8, step_name, "check_mkv_") or
        std.mem.startsWith(u8, step_name, "check_avi_")) return .checks;
    if (std.mem.startsWith(u8, step_name, "lower_")) return .lower;
    if (std.mem.startsWith(u8, step_name, "analyze_topology") or
        std.mem.startsWith(u8, step_name, "check_r")) return .forensics;
    if (std.mem.startsWith(u8, step_name, "sanitize_") or
        std.mem.startsWith(u8, step_name, "execute_quarantine")) return .cdr;
    return .forensics;
}

fn formatTraceHex(out: *[32]u8, bytes: [16]u8) void {
    const hex = "0123456789abcdef";
    for (bytes, 0..) |b, i| {
        out[i * 2] = hex[b >> 4];
        out[i * 2 + 1] = hex[b & 0x0f];
    }
}

fn onTelemetryEvent(_: *abi.extension.SubscriberCtx_ABI, ev: *const abi.TelemetryEvent_ABI) callconv(.c) void {
    global_monitor.onEvent(ev);
    if (ev.kind == .task_log and ev.count_a < 2) {
        const src = ev.primary_name.toSlice();
        if (std.mem.eql(u8, src, "engine") or
            std.mem.eql(u8, src, "module_registry") or
            std.mem.eql(u8, src, "repository_registry"))
        {
            return;
        }
    }
    global_event_ring.pushAbiEvent(ev);
}

pub const telemetry_sub_vtable = abi.TelemetrySubscriberVTable_ABI{
    .on_event = onTelemetryEvent,
};

// -----------------------------------------------------------------------------
// Local Filesystem Explorer (starts in VIDSEC_CALLER_PWD)
// -----------------------------------------------------------------------------

const FsEntry = struct {
    name: []u8,
    is_dir: bool,
    is_video: bool,
    size: u64,

    fn deinit(self: *FsEntry, alloc: std.mem.Allocator) void {
        alloc.free(self.name);
    }
};

const LocalExplorer = struct {
    alloc: std.mem.Allocator,
    app: ?*tui.TuiApp = null,
    cwd: []u8 = &.{},
    entries: std.ArrayList(FsEntry) = .empty,
    selected: usize = 0,
    scroll: usize = 0,
    video_only: bool = false,

    fn init(alloc: std.mem.Allocator) LocalExplorer {
        const start_dir = resolveInitialDir();
        const owned: []u8 = alloc.dupe(u8, start_dir) catch &.{};
        return .{
            .alloc = alloc,
            .cwd = owned,
        };
    }

    fn deinit(self: *LocalExplorer) void {
        self.clearEntries();
        self.entries.deinit(self.alloc);
        if (self.cwd.len > 0) self.alloc.free(self.cwd);
    }

    fn clearEntries(self: *LocalExplorer) void {
        for (self.entries.items) |*e| e.deinit(self.alloc);
        self.entries.clearRetainingCapacity();
        self.selected = 0;
        self.scroll = 0;
    }

    fn resolveInitialDir() []const u8 {
        if (std.c.getenv("VIDSEC_CALLER_PWD")) |p| {
            const s = std.mem.span(p);
            if (s.len > 0) return s;
        }
        if (std.c.getenv("PWD")) |p| {
            const s = std.mem.span(p);
            if (s.len > 0) return s;
        }
        if (std.c.getenv("HOME")) |p| {
            const s = std.mem.span(p);
            if (s.len > 0) return s;
        }
        return ".";
    }

    fn loadDir(self: *LocalExplorer, dir_path: []const u8) void {
        const io = std.Options.debug_io;
        const resolved = std.Io.Dir.cwd().realPathFileAlloc(io, dir_path, self.alloc) catch
            (self.alloc.dupe(u8, dir_path) catch return);

        var dir = std.Io.Dir.openDirAbsolute(io, resolved, .{ .iterate = true }) catch |err| {
            self.alloc.free(resolved);
            if (self.app) |a| a.setStatusFmt("Cannot open dir: {s}", .{@errorName(err)});
            return;
        };
        defer dir.close(io);

        self.clearEntries();
        if (self.cwd.len > 0) self.alloc.free(self.cwd);
        self.cwd = resolved;

        // Parent entry ".." unless at root "/"
        if (!std.mem.eql(u8, self.cwd, "/")) {
            const parent_name = self.alloc.dupe(u8, "..") catch return;
            self.entries.append(self.alloc, .{
                .name = parent_name,
                .is_dir = true,
                .is_video = false,
                .size = 0,
            }) catch self.alloc.free(parent_name);
        }

        var it = dir.iterate();
        while (it.next(io) catch null) |ent| {
            if (ent.name.len > 0 and ent.name[0] == '.') continue;
            const is_dir = (ent.kind == .directory);
            const is_vid = !is_dir and isVideoExt(ent.name);
            if (self.video_only and !is_dir and !is_vid) continue;

            var fsize: u64 = 0;
            if (!is_dir) {
                if (dir.statFile(io, ent.name, .{}) catch null) |st| {
                    fsize = st.size;
                }
            }
            const name_copy = self.alloc.dupe(u8, ent.name) catch continue;
            self.entries.append(self.alloc, .{
                .name = name_copy,
                .is_dir = is_dir,
                .is_video = is_vid,
                .size = fsize,
            }) catch {
                self.alloc.free(name_copy);
                continue;
            };
        }

        // Sort: ".." first, then directories alphabetically, then video/files alphabetically
        std.mem.sort(FsEntry, self.entries.items, {}, struct {
            fn lessThan(_: void, a: FsEntry, b: FsEntry) bool {
                if (std.mem.eql(u8, a.name, "..")) return true;
                if (std.mem.eql(u8, b.name, "..")) return false;
                if (a.is_dir != b.is_dir) return a.is_dir;
                return std.ascii.lessThanIgnoreCase(a.name, b.name);
            }
        }.lessThan);
    }

    fn render(ctx: ?*anyopaque, surface: tui.PanelSurface, focused: bool) void {
        const self: *LocalExplorer = @ptrCast(@alignCast(ctx.?));
        surface.fillRect(0, 0, surface.width, surface.height, ' ', .{});
        if (surface.width < 6 or surface.height < 3) return;

        // Line 0: current directory + filter badge
        var hdr_buf: [256]u8 = undefined;
        const mode_tag = if (self.video_only) "[VID]" else "[ALL]";
        const hdr = std.fmt.bufPrint(&hdr_buf, "{s} {s}", .{ mode_tag, self.cwd }) catch self.cwd;
        surface.drawText(0, 0, surface.width, hdr, .{ .fg = .cyan, .bold = true });

        // Line 1: key hints
        surface.drawText(0, 1, surface.width, "Enter:Open/Run  v:Filter  r:Refresh", .{ .fg = .bright_black, .dim = true });

        const list_top: u16 = 2;
        const list_h: usize = if (surface.height > list_top) surface.height - list_top else 0;
        if (list_h == 0) return;

        if (self.selected < self.scroll) {
            self.scroll = self.selected;
        } else if (self.selected >= self.scroll + list_h) {
            self.scroll = self.selected - list_h + 1;
        }

        var row: usize = 0;
        while (row < list_h) : (row += 1) {
            const idx = self.scroll + row;
            if (idx >= self.entries.items.len) break;
            const ent = self.entries.items[idx];
            const is_sel = (idx == self.selected);
            const ly: u16 = list_top + @as(u16, @intCast(row));

            var line_buf: [256]u8 = undefined;
            const line = if (ent.is_dir)
                std.fmt.bufPrint(&line_buf, " [DIR] {s}", .{ent.name}) catch ent.name
            else blk: {
                var sbuf: [24]u8 = undefined;
                const sz = formatSize(&sbuf, ent.size);
                const tag = if (ent.is_video) "[VID]" else "     ";
                break :blk std.fmt.bufPrint(&line_buf, " {s} {s} ({s})", .{ tag, ent.name, sz }) catch ent.name;
            };

            const style: tui.Style = if (is_sel and focused)
                .{ .fg = .black, .bg = .cyan, .bold = true }
            else if (is_sel)
                .{ .fg = .bright_white, .bg = .bright_black, .bold = true }
            else if (ent.is_dir)
                .{ .fg = .bright_blue, .bold = true }
            else if (ent.is_video)
                .{ .fg = .bright_green }
            else
                .{ .fg = .white };

            if (is_sel) {
                surface.fillRect(0, ly, surface.width, 1, ' ', style);
            }
            surface.drawText(0, ly, surface.width, line, style);
        }
    }

    fn handleKey(ctx: ?*anyopaque, key: tui.Key, dispatcher: inbound.HostDispatcher) anyerror!bool {
        const self: *LocalExplorer = @ptrCast(@alignCast(ctx.?));
        switch (key) {
            .up => {
                if (self.selected > 0) self.selected -= 1;
                return true;
            },
            .down => {
                if (self.selected + 1 < self.entries.items.len) self.selected += 1;
                return true;
            },
            .page_up => {
                self.selected -|= 10;
                return true;
            },
            .page_down => {
                if (self.entries.items.len > 0) {
                    self.selected = @min(self.selected + 10, self.entries.items.len - 1);
                }
                return true;
            },
            .backspace => {
                try self.goParent();
                return true;
            },
            .char => |ch| switch (ch) {
                'k' => {
                    if (self.selected > 0) self.selected -= 1;
                    return true;
                },
                'j' => {
                    if (self.selected + 1 < self.entries.items.len) self.selected += 1;
                    return true;
                },
                'h' => {
                    try self.goParent();
                    return true;
                },
                'v' => {
                    self.video_only = !self.video_only;
                    const cur = try self.alloc.dupe(u8, self.cwd);
                    defer self.alloc.free(cur);
                    self.loadDir(cur);
                    return true;
                },
                'r' => {
                    const cur = try self.alloc.dupe(u8, self.cwd);
                    defer self.alloc.free(cur);
                    self.loadDir(cur);
                    return true;
                },
                else => return false,
            },
            .enter => {
                if (self.selected >= self.entries.items.len) return true;
                const ent = self.entries.items[self.selected];
                if (ent.is_dir) {
                    if (std.mem.eql(u8, ent.name, "..")) {
                        try self.goParent();
                    } else {
                        const next = try std.fs.path.join(self.alloc, &.{ self.cwd, ent.name });
                        defer self.alloc.free(next);
                        self.loadDir(next);
                    }
                    return true;
                }
                const full_path = try std.fs.path.join(self.alloc, &.{ self.cwd, ent.name });
                defer self.alloc.free(full_path);

                var payload_buf: std.ArrayList(u8) = .empty;
                defer payload_buf.deinit(self.alloc);
                try payload_buf.appendSlice(self.alloc, "{\"path\":");
                try appendJsonString(&payload_buf, self.alloc, full_path);
                try payload_buf.append(self.alloc, '}');

                global_monitor.resetForFile(full_path);
                if (self.app) |app| {
                    try app.dispatchCapabilityToOutput("analyze_video", payload_buf.items, dispatcher);
                }
                return true;
            },
            else => return false,
        }
    }

    fn goParent(self: *LocalExplorer) !void {
        if (std.mem.eql(u8, self.cwd, "/")) return;
        const parent = std.fs.path.dirname(self.cwd) orelse "/";
        const owned_parent = try self.alloc.dupe(u8, parent);
        defer self.alloc.free(owned_parent);
        self.loadDir(owned_parent);
    }
};

fn isVideoExt(name: []const u8) bool {
    const ext = std.fs.path.extension(name);
    const video_exts = [_][]const u8{ ".mp4", ".m4v", ".mov", ".mkv", ".webm", ".avi", ".ts", ".flv", ".3gp" };
    for (video_exts) |ve| {
        if (std.ascii.eqlIgnoreCase(ext, ve)) return true;
    }
    return false;
}

fn appendJsonString(out: *std.ArrayList(u8), alloc: std.mem.Allocator, s: []const u8) !void {
    try out.append(alloc, '"');
    for (s) |c| {
        switch (c) {
            '"' => try out.appendSlice(alloc, "\\\""),
            '\\' => try out.appendSlice(alloc, "\\\\"),
            '\n' => try out.appendSlice(alloc, "\\n"),
            '\r' => try out.appendSlice(alloc, "\\r"),
            '\t' => try out.appendSlice(alloc, "\\t"),
            else => try out.append(alloc, c),
        }
    }
    try out.append(alloc, '"');
}

fn formatSize(buf: *[24]u8, bytes: u64) []const u8 {
    if (bytes < 1024) return std.fmt.bufPrint(buf, "{d}B", .{bytes}) catch "?";
    const f: f64 = @floatFromInt(bytes);
    if (bytes < 1024 * 1024) return std.fmt.bufPrint(buf, "{d:.1}K", .{f / 1024.0}) catch "?";
    if (bytes < 1024 * 1024 * 1024) return std.fmt.bufPrint(buf, "{d:.1}M", .{f / (1024.0 * 1024.0)}) catch "?";
    return std.fmt.bufPrint(buf, "{d:.2}G", .{f / (1024.0 * 1024.0 * 1024.0)}) catch "?";
}

// -----------------------------------------------------------------------------
// TUI Lifecycle Hooks & Extension Registration
// -----------------------------------------------------------------------------

const VidsecAppCtx = struct {
    explorer: *LocalExplorer,

    fn onStart(ctx: ?*anyopaque, app: *tui.TuiApp, _: inbound.HostDispatcher) void {
        const self: *VidsecAppCtx = @ptrCast(@alignCast(ctx.?));
        self.explorer.app = app;
        // Keep only: [1] Local Files, [2] Pipeline Task Graph & Diagnostics, [3] Telemetry Logs
        var i: usize = app.panels.items.len;
        while (i > 0) {
            i -= 1;
            const kind = app.panels.items[i].kind;
            if (kind == .form or kind == .output) {
                _ = app.panels.orderedRemove(i);
            }
        }
        if (app.panels.items.len == 3 and app.panels.items[1].kind == .logs and app.panels.items[2].kind == .custom) {
            std.mem.swap(tui.tui_app.PanelEntry, &app.panels.items[1], &app.panels.items[2]);
        }
        const init_dir = self.explorer.alloc.dupe(u8, self.explorer.cwd) catch return;
        defer self.explorer.alloc.free(init_dir);
        self.explorer.loadDir(init_dir);
        app.focusPanelById("files");
    }

    fn onCapabilityComplete(_: ?*anyopaque, app: *tui.TuiApp, cap_id: []const u8, status_code: i32, _: inbound.HostDispatcher) void {
        _ = cap_id;
        _ = status_code;
        app.focusPanelById("files");
    }
};

fn vidsecTuiServe(
    _: *abi.extension.TransportCtx_ABI,
    _: abi.Slice_ABI,
    _: abi.Slice_ABI,
    host_dispatcher: *anyopaque,
    dispatch_fn: abi.extension.HostDispatchFn_ABI,
) callconv(.c) abi.HostError_ABI {
    return vidsecTuiServeWithCatalog(null, host_dispatcher, dispatch_fn);
}

fn vidsecTuiServeWithCatalog(
    catalog_opt: ?sdk.capabilities.CapabilityCatalog,
    host_dispatcher: *anyopaque,
    dispatch_fn: abi.extension.HostDispatchFn_ABI,
) abi.HostError_ABI {
    const alloc = std.heap.c_allocator;
    if (catalog_opt == null) {
        if (global_kernel) |k| {
            if (global_api) |api| {
                if (inbound.fetchCapabilityCatalog(alloc, k, api) catch null) |parsed| {
                    if (global_catalog_parsed) |*old| old.deinit();
                    global_catalog_parsed = parsed;
                }
            }
        }
    }
    const catalog: sdk.capabilities.CapabilityCatalog = catalog_opt orelse if (global_catalog_parsed) |cp|
        cp.value
    else
        .{
            .id = "vidsec",
            .name = "Parabellum VidSec",
            .version = "2.0.5",
        };

    const dispatcher = inbound.HostDispatcher{
        .ptr = host_dispatcher,
        .dispatch_fn = dispatch_fn,
    };

    var explorer = LocalExplorer.init(alloc);
    defer explorer.deinit();
    var app_ctx = VidsecAppCtx{ .explorer = &explorer };

    const panels = [_]tui.CustomPanel{
        .{
            .id = "files",
            .title = "Local Files",
            .dock = .left,
            .visible = true,
            .ctx = &explorer,
            .render = LocalExplorer.render,
            .handle_key = LocalExplorer.handleKey,
        },
        .{
            .id = "pipeline_monitor",
            .title = "Pipeline Task Graph & Diagnostics",
            .dock = .main_bottom,
            .visible = true,
            .ctx = &global_monitor,
            .render = PipelineMonitor.render,
            .handle_key = PipelineMonitor.handleKey,
        },
    };

    var app = tui.TuiApp.init(alloc, catalog, &global_event_ring, .{
        .title = "Parabellum VidSec Forensics Suite",
        .show_sidebar = false,
        .form_on_demand = true,
        .logs_visible = true,
        .extra_panels = &panels,
        .on_start = VidsecAppCtx.onStart,
        .on_start_ctx = &app_ctx,
        .on_capability_complete = VidsecAppCtx.onCapabilityComplete,
        .on_capability_complete_ctx = &app_ctx,
    }) catch return .out_of_memory;
    defer app.deinit();

    app.run(dispatcher) catch |err| switch (err) {
        error.NotATerminal => return .invalid_argument,
        else => return .internal_error,
    };
    return .ok;
}

pub fn runDirect(
    alloc: std.mem.Allocator,
    catalog_opt: ?sdk.capabilities.CapabilityCatalog,
    host_dispatcher: *anyopaque,
    dispatch_fn: abi.extension.HostDispatchFn_ABI,
    pipeline_path: []const u8,
) u8 {
    _ = alloc;
    global_monitor.setPipelinePath(pipeline_path);
    const rc = vidsecTuiServeWithCatalog(catalog_opt, host_dispatcher, dispatch_fn);
    return if (rc == .ok) 0 else 1;
}
