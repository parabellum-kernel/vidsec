const std = @import("std");
const common = @import("common.zig");

pub const Slice_ABI = common.Slice_ABI;
pub const HostError_ABI = common.HostError_ABI;
pub const RowView_ABI = common.RowView_ABI;
pub const NamedField_ABI = common.NamedField_ABI;
pub const SemVer_ABI = common.SemVer_ABI;

pub const DRIVER_MANIFEST_SYMBOL_NAME = "parabellum_driver_manifest";
pub const DRIVER_ABI_VERSION: u32 = 1;

pub const DriverContext_ABI = opaque {};
pub const RowIteratorHandle_ABI = opaque {};
pub const RepoHandle_ABI = opaque {};

pub const ConfigParam_ABI = extern struct {
    key: Slice_ABI,
    value: Slice_ABI,
};

pub const DriverCapabilities_ABI = extern struct {
    read: bool = false,
    write: bool = false,
    streaming_read: bool = false,
    streaming_write: bool = false,
    schema_ddl: bool = false,
    transactions: bool = false,
    savepoints: bool = false,
    partial_update: bool = false,
    filter_pushdown: bool = false,
    order_pushdown: bool = false,
    relational_constraints: bool = false,
    batch_emitter: bool = false,
};

pub const WriteMode_ABI = enum(u8) {
    insert = 0,
    upsert = 1,
    append = 2,
    replace = 3,
};

pub const WriteSpec_ABI = extern struct {
    table: Slice_ABI,
    mode: WriteMode_ABI = .insert,
    fields_ptr: ?[*]const NamedField_ABI = null,
    fields_len: usize = 0,
    raw_bytes: Slice_ABI = Slice_ABI.empty,

    pub fn fieldsSlice(self: WriteSpec_ABI) []const NamedField_ABI {
        if (self.fields_len == 0 or self.fields_ptr == null) return &.{};
        return self.fields_ptr.?[0..self.fields_len];
    }
};

pub const ReadSpec_ABI = extern struct {
    table: Slice_ABI,
    limit: u64 = 0,
    offset: u64 = 0,
    filter_sql_or_expr: Slice_ABI = Slice_ABI.empty,
};

pub const RowIteratorVTable_ABI = extern struct {
    next: *const fn (iter: *RowIteratorHandle_ABI, out_row: *RowView_ABI) callconv(.c) HostError_ABI,
    deinit: *const fn (iter: *RowIteratorHandle_ABI) callconv(.c) void,
};

pub const RowIterator_ABI = extern struct {
    handle: *RowIteratorHandle_ABI,
    vtable: *const RowIteratorVTable_ABI,
};

pub const StorageRepositoryVTable_ABI = extern struct {
    get_capabilities: *const fn (repo: *const RepoHandle_ABI) callconv(.c) DriverCapabilities_ABI,
    record_count: *const fn (repo: *const RepoHandle_ABI, table: Slice_ABI) callconv(.c) usize,
    deinit: *const fn (repo: *RepoHandle_ABI) callconv(.c) void,

    write_row: ?*const fn (repo: *RepoHandle_ABI, spec: *const WriteSpec_ABI) callconv(.c) HostError_ABI = null,
    read_stream: ?*const fn (
        repo: *RepoHandle_ABI,
        spec: *const ReadSpec_ABI,
        out_iter: *RowIterator_ABI,
    ) callconv(.c) HostError_ABI = null,
    ensure_schema_json: ?*const fn (repo: *RepoHandle_ABI, schema_json: Slice_ABI) callconv(.c) HostError_ABI = null,

    begin_tx: ?*const fn (repo: *RepoHandle_ABI) callconv(.c) HostError_ABI = null,
    commit: ?*const fn (repo: *RepoHandle_ABI) callconv(.c) HostError_ABI = null,
    rollback: ?*const fn (repo: *RepoHandle_ABI) callconv(.c) HostError_ABI = null,
    begin_savepoint: ?*const fn (repo: *RepoHandle_ABI, name: Slice_ABI) callconv(.c) HostError_ABI = null,
    rollback_savepoint: ?*const fn (repo: *RepoHandle_ABI, name: Slice_ABI) callconv(.c) HostError_ABI = null,
    release_savepoint: ?*const fn (repo: *RepoHandle_ABI, name: Slice_ABI) callconv(.c) HostError_ABI = null,
};

pub const DriverManifest_ABI = extern struct {
    abi_version: u32 = DRIVER_ABI_VERSION,
    min_engine_version: SemVer_ABI = common.SDK_VERSION,
    driver_name: [*:0]const u8,
    driver_version: SemVer_ABI,
    create_repo: *const fn (
        params_ptr: ?[*]const ConfigParam_ABI,
        params_len: usize,
        out_repo: *?*RepoHandle_ABI,
        out_vtable: *?*const StorageRepositoryVTable_ABI,
    ) callconv(.c) HostError_ABI,

    pub fn nameSlice(self: DriverManifest_ABI) []const u8 {
        return std.mem.span(self.driver_name);
    }
};

