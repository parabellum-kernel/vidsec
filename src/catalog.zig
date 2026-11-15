const abi = @import("flowdata_abi");
const container = @import("container.zig").VidsecPluginContainer;
const tasks_mod = @import("tasks/mod.zig");

const tasks = [_]abi.TaskDescriptor_ABI{
    // Stage 0: Pre-Triage
    container.defineTaskService(tasks_mod.check_file_size.Service, .{
        .name = "check_file_size",
        .description = "Validates stream length against configured minimum and maximum size limits.",
    }),
    container.defineTaskService(tasks_mod.detect_magic.Service, .{
        .name = "detect_magic",
        .description = "Identifies real format, MIME type, and container family from the leading header via tika.",
    }),
    container.defineTaskService(tasks_mod.check_extension.Service, .{
        .name = "check_extension",
        .description = "Validates whether the declared filename or extension matches the detected format.",
    }),
    container.defineTaskService(tasks_mod.scan_head_executables.Service, .{
        .name = "scan_head_executables",
        .description = "Scans the leading header window for primary or embedded MZ/ELF executable signatures.",
    }),
    container.defineTaskService(tasks_mod.scan_head_scripts.Service, .{
        .name = "scan_head_scripts",
        .description = "Scans the leading 64 KB header window for suspicious script, shell, or playlist indicators.",
    }),
    container.defineTaskService(tasks_mod.scan_tail_archives.Service, .{
        .name = "scan_tail_archives",
        .description = "Scans the trailing stream window for appended ZIP EOCD, RAR, or 7z polyglot archives.",
    }),
    container.defineTaskService(tasks_mod.measure_mid_entropy.Service, .{
        .name = "measure_mid_entropy",
        .description = "Measures Shannon entropy over a bounded midpoint window of the stream.",
    }),
    container.defineTaskService(tasks_mod.evaluate_triage.Service, .{
        .name = "evaluate_triage",
        .description = "Evaluates Stage 0 gatekeeper flags into audit findings and QuarantineOrders.",
    }),

    // Remediation Subscribers
    container.defineTaskService(tasks_mod.apply_truncate.Service, .{
        .name = "apply_truncate",
        .description = "Subscribes to TruncateOrder and truncates the managed output artifact to new_size.",
    }),
    container.defineTaskService(tasks_mod.apply_zero_out.Service, .{
        .name = "apply_zero_out",
        .description = "Subscribes to ZeroOutOrder and overwrites the targeted byte range with 0x00.",
    }),
    container.defineTaskService(tasks_mod.apply_quarantine.Service, .{
        .name = "apply_quarantine",
        .description = "Subscribes to QuarantineOrder and forwards the hostile stream to the quarantine sink.",
    }),

    // Stage 1: Format-Specific Container Parsing & Lowering to `media_ir`
    container.defineTaskService(tasks_mod.lower_mp4_container.Service, .{
        .name = "lower_mp4_container",
        .description = "Parses ISOBMFF/MP4 boxes in O(boxes) and lowers structure to media_ir regions and findings",
    }),
    container.defineTaskService(tasks_mod.lower_ebml_container.Service, .{
        .name = "lower_ebml_container",
        .description = "Parses EBML/Matroska elements in O(elements) and lowers structure to media_ir regions and findings",
    }),
    container.defineTaskService(tasks_mod.lower_riff_container.Service, .{
        .name = "lower_riff_container",
        .description = "Parses RIFF/AVI chunks in O(chunks) and lowers structure to media_ir regions and findings",
    }),

    // Stage 1a: Atomic Format-Specific Dissectors & Field Inspector
    container.defineTaskService(tasks_mod.dissect_isobmff.Service, .{
        .name = "dissect_isobmff",
        .description = "Dissects ISOBMFF/MP4 box hierarchy and containment bounds.",
    }),
    container.defineTaskService(tasks_mod.dissect_mp4_atoms.Service, .{
        .name = "dissect_mp4_atoms",
        .description = "Dissects MP4 trak/stbl/avcC/esds atoms into structural records.",
    }),
    container.defineTaskService(tasks_mod.dissect_ebml.Service, .{
        .name = "dissect_ebml",
        .description = "Dissects EBML element hierarchy and containment bounds.",
    }),
    container.defineTaskService(tasks_mod.dissect_mkv_structures.Service, .{
        .name = "dissect_mkv_structures",
        .description = "Dissects Matroska Tracks, Attachments, and Cluster blocks.",
    }),
    container.defineTaskService(tasks_mod.dissect_riff.Service, .{
        .name = "dissect_riff",
        .description = "Dissects RIFF/AVI chunk hierarchy and AVI stream/index metadata.",
    }),
    container.defineTaskService(tasks_mod.inspect_region_field.Service, .{
        .name = "inspect_region_field",
        .description = "Extracts and bounds-checks a typed scalar/FourCC field at a target offset.",
    }),
    container.defineTaskService(tasks_mod.inspect_region_bits.Service, .{
        .name = "inspect_region_bits",
        .description = "Extracts and validates masked/shifted bitfields and optional hex-prefixed vendor payloads.",
    }),
    container.defineTaskService(tasks_mod.check_region_cardinality.Service, .{
        .name = "check_region_cardinality",
        .description = "Validates per-parent child cardinality bounds and structural ordering invariants.",
    }),
    container.defineTaskService(tasks_mod.inspect_codec_bitstream.Service, .{
        .name = "inspect_codec_bitstream",
        .description = "Decodes H.264 SPS/PPS Exp-Golomb syntax elements from avcC/CodecPrivate against declarative bounds.",
    }),
    container.defineTaskService(tasks_mod.inspect_ebml_lacing.Service, .{
        .name = "inspect_ebml_lacing",
        .description = "Validates Matroska Block/SimpleBlock Xiph, Fixed, and EBML lacing deltas and frame sums.",
    }),

    // Stage 1b: Format-Specific Structural Checks
    container.defineTaskService(tasks_mod.check_mp4_structure.Service, .{
        .name = "check_mp4_structure",
        .description = "Validates ISOBMFF/MP4 box containment, recursion depth, sample tables (R04a), and codec headers (R09a).",
    }),
    container.defineTaskService(tasks_mod.check_mkv_structure.Service, .{
        .name = "check_mkv_structure",
        .description = "Validates EBML/Matroska element containment, lacing, Cues bounds (R04), and TrackEntry invariants (R09).",
    }),
    container.defineTaskService(tasks_mod.check_avi_structure.Service, .{
        .name = "check_avi_structure",
        .description = "Validates RIFF/AVI root size (R01), chunk containment (R03), BITMAPINFOHEADER overflow, and idx1 bounds (R09).",
    }),

    // Stage 2: Generalist Format-Agnostic IR Forensics
    container.defineTaskService(tasks_mod.analyze_topology.Service, .{
        .name = "analyze_topology",
        .description = "Analyzes 2-level container topology (external gaps/overlays + interior media_data slack) and root overlaps.",
    }),
    container.defineTaskService(tasks_mod.check_r02_trailing_overlay.Service, .{
        .name = "check_r02_trailing_overlay",
        .description = "R02: Inspects trailing_overlay slack with 16B zero tolerance, 64KB signature scan, and entropy.",
    }),
    container.defineTaskService(tasks_mod.check_r04_sample_bounds.Service, .{
        .name = "check_r04_sample_bounds",
        .description = "R04: Verifies SampleRuns subset media_data and end_offset <= file_size.",
    }),
    container.defineTaskService(tasks_mod.check_r05_external_refs.Service, .{
        .name = "check_r05_external_refs",
        .description = "R05: Classifies external URI/file references (SSRF, UNC SMB, file://, path traversal).",
    }),
    container.defineTaskService(tasks_mod.check_r06_embedded_attachments.Service, .{
        .name = "check_r06_embedded_attachments",
        .description = "R06: Inspects embedded attachments for path traversal, executables, risky fonts, and MIME spoofing.",
    }),
    container.defineTaskService(tasks_mod.check_r07_suspicious_padding.Service, .{
        .name = "check_r07_suspicious_padding",
        .description = "R07: Scans padding/unknown regions across 3 windows for embedded signatures and high entropy.",
    }),
    container.defineTaskService(tasks_mod.check_r08_unreferenced_slack.Service, .{
        .name = "check_r08_unreferenced_slack",
        .description = "R08: Scans unreferenced gaps and interior slack for embedded signatures, high entropy, or >=4KB slack.",
    }),
    container.defineTaskService(tasks_mod.check_r09_codec_inconsistencies.Service, .{
        .name = "check_r09_codec_inconsistencies",
        .description = "R09: Checks container vs bitstream dimension mismatches and out-of-range dimensions.",
    }),
    container.defineTaskService(tasks_mod.check_r10_sample_overlaps.Service, .{
        .name = "check_r10_sample_overlaps",
        .description = "R10: Detects overlapping sample runs and decompression/read amplification bombs.",
    }),
    container.defineTaskService(tasks_mod.check_inconsistencies.Service, .{
        .name = "check_inconsistencies",
        .description = "Verifies SampleRuns subset media_data, EOF bounds, and codec dimension consistency.",
    }),
    container.defineTaskService(tasks_mod.scan_entropy.Service, .{
        .name = "scan_entropy",
        .description = "Scans unreferenced slack regions for high-entropy hidden/encrypted payloads.",
    }),
};

const manifest = abi.ModuleManifest_ABI{
    .abi_version = abi.FLOWDATA_ABI_VERSION,
    .module_name = "analyzer",
    .module_version = .{ .major = 2, .minor = 0, .patch = 0 },
    .tasks_ptr = &tasks,
    .tasks_len = tasks.len,
};

comptime {
    @export(&manifest, .{ .name = "flowdata_module_manifest", .linkage = .strong });
}
