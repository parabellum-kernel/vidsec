const std = @import("std");
const Allocator = std.mem.Allocator;
const TaskContext = @import("task_context.zig").TaskContext;
const Logger = @import("logger.zig").Logger;
const StreamEmitter = @import("stream_emitter.zig").StreamEmitter;

/// Validates at compile time that `ContextImpl` fulfills the DI Context contract.
pub fn assertValidContext(comptime ContextImpl: type) void {
    comptime {
        const info = @typeInfo(ContextImpl);
        if (info != .@"struct") {
            @compileError("[Parabellum DI] ContextImpl '" ++ @typeName(ContextImpl) ++ "' must be a struct");
        }

        var requires_init = false;
        for (info.@"struct".field_attrs) |fa| {
            if (fa.default_value_ptr == null) {
                requires_init = true;
                break;
            }
        }

        if (requires_init and !@hasDecl(ContextImpl, "init")) {
            @compileError("[Parabellum DI] Context '" ++ @typeName(ContextImpl) ++
                "' has uninitialized fields and must declare 'pub fn init(self: *" ++
                @typeName(ContextImpl) ++ ", alloc: Allocator, ctx: TaskContext) !void'");
        }

        if (@hasDecl(ContextImpl, "init")) {
            const InitFn = @TypeOf(ContextImpl.init);
            const fn_info = @typeInfo(InitFn).@"fn";
            if (fn_info.param_types.len != 3 or fn_info.param_types[0].? != *ContextImpl) {
                @compileError("[Parabellum DI] '" ++ @typeName(ContextImpl) ++
                    ".init' must have signature 'fn (self: *" ++ @typeName(ContextImpl) ++
                    ", alloc: Allocator, ctx: TaskContext) !void'");
            }
        }
    }
}

/// Inspects whether `DeclType` is a function returning `TargetType` or `ErrorSet!TargetType`
/// whose first parameter is `ContextImpl` / `*ContextImpl` / `*const ContextImpl`.
fn isFactoryFor(comptime ContextImpl: type, comptime DeclType: type, comptime TargetType: type) bool {
    const info = @typeInfo(DeclType);
    if (info != .@"fn") return false;
    const fn_info = info.@"fn";
    if (fn_info.param_types.len == 0 or fn_info.param_types.len > 2) return false;

    const P0 = fn_info.param_types[0] orelse return false;
    if (P0 != ContextImpl and P0 != *ContextImpl and P0 != *const ContextImpl) return false;

    const Ret = fn_info.return_type orelse return false;
    if (Ret == TargetType) return true;
    if (@typeInfo(Ret) == .error_union and @typeInfo(Ret).error_union.payload == TargetType) {
        return true;
    }
    return false;
}

fn typeBaseName(comptime T: type) []const u8 {
    const full = @typeName(T);
    var last_dot: usize = 0;
    for (full, 0..) |c, i| {
        if (c == '.') last_dot = i + 1;
    }
    return full[last_dot..];
}

fn asciiEqlIgnoreCase(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;
    for (a, 0..) |c, i| {
        if (std.ascii.toLower(c) != std.ascii.toLower(b[i])) return false;
    }
    return true;
}

fn matchesMethodName(comptime method_name: []const u8, comptime field_name: []const u8, comptime TargetType: type) bool {
    if (asciiEqlIgnoreCase(method_name, field_name)) return true;

    if (std.mem.startsWith(u8, method_name, "provide")) {
        var rest = method_name["provide".len..];
        if (std.mem.startsWith(u8, rest, "_")) rest = rest[1..];
        if (asciiEqlIgnoreCase(rest, field_name)) return true;
    }

    const type_name = typeBaseName(TargetType);
    if (asciiEqlIgnoreCase(method_name, type_name)) return true;
    if (std.mem.startsWith(u8, method_name, "provide")) {
        var rest = method_name["provide".len..];
        if (std.mem.startsWith(u8, rest, "_")) rest = rest[1..];
        if (asciiEqlIgnoreCase(rest, type_name)) return true;
    }

    return false;
}

/// Finds the name of a factory method on `ContextImpl` returning `TargetType` or `!TargetType`.
pub fn findFactoryMethod(
    comptime ContextImpl: type,
    comptime field_name: []const u8,
    comptime TargetType: type,
    comptime has_default: bool,
) ?[]const u8 {
    inline for (@typeInfo(ContextImpl).@"struct".decl_names) |decl_name| {
        if (@hasDecl(ContextImpl, decl_name)) {
            const DeclType = @TypeOf(@field(ContextImpl, decl_name));
            if (isFactoryFor(ContextImpl, DeclType, TargetType)) {
                if (matchesMethodName(decl_name, field_name, TargetType)) {
                    return decl_name;
                }
            }
        }
    }

    if (!has_default) {
        inline for (@typeInfo(ContextImpl).@"struct".decl_names) |decl_name| {
            if (@hasDecl(ContextImpl, decl_name)) {
                const DeclType = @TypeOf(@field(ContextImpl, decl_name));
                if (isFactoryFor(ContextImpl, DeclType, TargetType)) {
                    return decl_name;
                }
            }
        }
    }

    return null;
}

/// Validates at compile time that `Service` fulfills the Task Service contract and that every
/// declared field can be resolved from `ContextImpl`, SDK built-ins, or default values.
pub fn assertValidService(comptime ContextImpl: type, comptime Service: type) void {
    comptime {
        assertValidContext(ContextImpl);
        const s_info = @typeInfo(Service);
        if (s_info != .@"struct") {
            @compileError("[Parabellum DI] Service '" ++ @typeName(Service) ++ "' must be a struct");
        }
        if (!@hasDecl(Service, "execute")) {
            @compileError("[Parabellum DI] Service '" ++ @typeName(Service) ++ "' must declare 'pub fn execute(...)'");
        }

        const s_st = s_info.@"struct";
        const ctx_st = @typeInfo(ContextImpl).@"struct";
        for (s_st.field_names, s_st.field_types, s_st.field_attrs) |f_name, f_type, f_attr| {
            const has_default = (f_attr.default_value_ptr != null);
            var resolved = false;

            for (ctx_st.field_names, ctx_st.field_types) |cf_name, cf_type| {
                const matches_name = std.mem.eql(u8, cf_name, f_name);
                const matches_type = (cf_type == f_type or *const cf_type == f_type or *cf_type == f_type);
                if (matches_name and matches_type) {
                    resolved = true;
                    break;
                }
            }

            if (!resolved and !has_default) {
                for (ctx_st.field_types) |cf_type| {
                    if (cf_type == f_type or *const cf_type == f_type or *cf_type == f_type) {
                        resolved = true;
                        break;
                    }
                }
            }

            if (!resolved and findFactoryMethod(ContextImpl, f_name, f_type, has_default) != null) resolved = true;
            if (!resolved and (f_type == Logger or f_type == Allocator or f_type == TaskContext or f_type == StreamEmitter)) resolved = true;
            if (!resolved and has_default) resolved = true;

            if (!resolved) {
                @compileError("[Parabellum DI] Unsatisfied dependency '" ++ f_name ++ ": " ++
                    @typeName(f_type) ++ "' in service '" ++ @typeName(Service) ++
                    "' (not provided by '" ++ @typeName(ContextImpl) ++ "' or SDK built-ins)");
            }
        }
    }
}

/// Resolves a single dependency of type `FieldType` prioritizing `ContextImpl` overrides
/// before falling back to SDK built-in primitives.
pub fn resolveDependency(
    comptime field_name: []const u8,
    comptime FieldType: type,
    comptime has_default: bool,
    comptime ContextImpl: type,
    ctx_impl: *ContextImpl,
    alloc: Allocator,
    ctx: ?TaskContext,
    input: anytype,
) !FieldType {
    // Rule 1: Direct field match on ContextImpl (by value, *const T, or *T)
    const ctx_st = @typeInfo(ContextImpl).@"struct";
    inline for (ctx_st.field_names, ctx_st.field_types) |cf_name, cf_type| {
        const matches_name = std.mem.eql(u8, cf_name, field_name);
        const matches_type = (cf_type == FieldType or *const cf_type == FieldType or *cf_type == FieldType);
        if (matches_name and matches_type) {
            if (cf_type == FieldType) return @field(ctx_impl, cf_name);
            return &@field(ctx_impl, cf_name);
        }
    }

    if (!has_default) {
        inline for (ctx_st.field_names, ctx_st.field_types) |cf_name, cf_type| {
            if (cf_type == FieldType) {
                return @field(ctx_impl, cf_name);
            }
            if (*const cf_type == FieldType or *cf_type == FieldType) {
                return &@field(ctx_impl, cf_name);
            }
        }
    }

    // Rule 2: @Bean Factory method on ContextImpl returning FieldType or !FieldType
    if (comptime findFactoryMethod(ContextImpl, field_name, FieldType, has_default)) |method_name| {
        const method = @field(ContextImpl, method_name);
        const fn_info = @typeInfo(@TypeOf(method)).@"fn";
        const Ret = fn_info.return_type.?;
        const is_err_union = (@typeInfo(Ret) == .error_union);

        if (fn_info.param_types.len == 2) {
            return if (is_err_union) try method(ctx_impl, input) else method(ctx_impl, input);
        } else {
            return if (is_err_union) try method(ctx_impl) else method(ctx_impl);
        }
    }

    // Rule 3: Built-in SDK fallback primitives
    if (FieldType == Logger) {
        return if (ctx) |c| Logger.init(c.raw) else Logger.noop();
    }
    if (FieldType == Allocator) return alloc;
    if (FieldType == TaskContext) {
        return ctx orelse @panic("TaskContext requested in container without active host context");
    }
    if (FieldType == StreamEmitter) {
        const c = ctx orelse @panic("StreamEmitter requested in container without active host context");
        return StreamEmitter.init(c, "stream");
    }

    unreachable; // Already verified at comptime by assertValidService
}

/// Instantiates `Service` by automatically injecting all declared struct fields.
pub fn injectService(
    comptime Service: type,
    comptime ContextImpl: type,
    ctx_impl: *ContextImpl,
    alloc: Allocator,
    ctx: ?TaskContext,
    input: anytype,
) !Service {
    comptime assertValidService(ContextImpl, Service);
    var instance: Service = undefined;
    const s_st = @typeInfo(Service).@"struct";
    const ctx_st = @typeInfo(ContextImpl).@"struct";
    inline for (s_st.field_names, s_st.field_types, s_st.field_attrs) |f_name, f_type, f_attr| {
        const has_default = (f_attr.default_value_ptr != null);
        const has_provider = comptime blk: {
            for (ctx_st.field_names, ctx_st.field_types) |cf_name, cf_type| {
                const matches_name = std.mem.eql(u8, cf_name, f_name);
                const matches_type = (cf_type == f_type or *const cf_type == f_type or *cf_type == f_type);
                if (matches_name and matches_type) break :blk true;
            }
            if (!has_default) {
                for (ctx_st.field_types) |cf_type| {
                    if (cf_type == f_type or *const cf_type == f_type or *cf_type == f_type) break :blk true;
                }
            }
            if (findFactoryMethod(ContextImpl, f_name, f_type, has_default) != null) break :blk true;
            if (f_type == Logger or f_type == Allocator or f_type == TaskContext or f_type == StreamEmitter) break :blk true;
            break :blk false;
        };

        if (has_provider) {
            @field(instance, f_name) = try resolveDependency(f_name, f_type, has_default, ContextImpl, ctx_impl, alloc, ctx, input);
        } else if (f_attr.default_value_ptr) |def_ptr| {
            // Rule 4: Field has a default value and is not provided by ContextImpl
            const typed_def: *const f_type = @ptrCast(@alignCast(def_ptr));
            @field(instance, f_name) = typed_def.*;
        }
    }
    return instance;
}

test "Parabellum DI: field injection, factory method injection, and SDK overrides" {
    const testing = std.testing;

    const DummyService = struct {
        greeting: []const u8 = "hello",
        number: i32,
        computed: []const u8,
        logger: Logger,

        pub fn execute(self: *@This(), in_val: i32) !i32 {
            _ = self;
            return in_val * 2;
        }
    };

    const DummyContext = struct {
        number: i32 = 42,
        logger: Logger = Logger.noop(),

        pub fn provideComputed(self: *@This(), input: anytype) ![]const u8 {
            _ = self;
            _ = input;
            return "computed_value";
        }
    };

    var ctx_inst = DummyContext{};
    var svc = try injectService(DummyService, DummyContext, &ctx_inst, testing.allocator, null, @as(i32, 10));

    try testing.expectEqualStrings("hello", svc.greeting);
    try testing.expectEqual(@as(i32, 42), svc.number);
    try testing.expectEqualStrings("computed_value", svc.computed);
    try testing.expectEqual(@as(i32, 20), try svc.execute(10));
}
