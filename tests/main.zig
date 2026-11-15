const std = @import("std");

test {
    _ = @import("triage/triage_tasks_test.zig");
    _ = @import("remediation/remediation_tasks_test.zig");
    _ = @import("containers/container_tasks_test.zig");
    _ = @import("containers/cve_compendium_test.zig");
    _ = @import("forensics/forensic_tasks_test.zig");
    _ = @import("e2e/pipeline_e2e_test.zig");
}
