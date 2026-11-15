const common = @import("../abi/common.zig");
const driver_abi = @import("../abi/driver.zig");
const ext_abi = @import("../abi/extension.zig");

pub const EngineHandle_ABI = opaque {};
pub const ModuleManifestHandle_ABI = opaque {};

pub const HostRunOptions_ABI = extern struct {
    pipeline_yaml_path: [*:0]const u8,
    dotenv_path: ?[*:0]const u8 = null,
    input_payload_ptr: ?[*]const u8 = null,
    input_payload_len: usize = 0,
    plugin_search_dir: ?[*:0]const u8 = null,
};

pub const HostRunSummary_ABI = extern struct {
    status_code: c_int = 0,
    steps_executed: u32 = 0,
    items_emitted: u64 = 0,
    output_json_ptr: ?[*]const u8 = null,
    output_json_len: usize = 0,
    error_msg_ptr: ?[*]const u8 = null,
    error_msg_len: usize = 0,
};

pub extern "c" fn parabellum_host_version() common.SemVer_ABI;
pub extern "c" fn parabellum_host_create() ?*EngineHandle_ABI;
pub extern "c" fn parabellum_host_destroy(handle: *EngineHandle_ABI) void;

pub extern "c" fn parabellum_host_register_static_module(
    handle: *EngineHandle_ABI,
    alias_z: [*:0]const u8,
    manifest: *const ModuleManifestHandle_ABI,
) common.HostError_ABI;

pub extern "c" fn parabellum_host_register_static_driver(
    handle: *EngineHandle_ABI,
    driver_name_z: [*:0]const u8,
    manifest: *const driver_abi.DriverManifest_ABI,
) common.HostError_ABI;

pub extern "c" fn parabellum_host_register_static_extension(
    handle: *EngineHandle_ABI,
    ext_name_z: [*:0]const u8,
    manifest: *const ext_abi.ExtensionManifest_ABI,
) common.HostError_ABI;

pub extern "c" fn parabellum_host_load_plugin_so(
    handle: *EngineHandle_ABI,
    alias_z: [*:0]const u8,
    so_path_z: [*:0]const u8,
) common.HostError_ABI;

pub extern "c" fn parabellum_host_run_pipeline(
    handle: *EngineHandle_ABI,
    opts: *const HostRunOptions_ABI,
    out_summary: *HostRunSummary_ABI,
) common.HostError_ABI;

pub extern "c" fn parabellum_host_free_summary(
    handle: *EngineHandle_ABI,
    summary: *HostRunSummary_ABI,
) void;
