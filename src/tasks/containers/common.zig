const std = @import("std");
const abi = @import("parabellum_abi");
const media_ir = @import("media_ir");

/// Common inputs for Stage 1c pure IR lowering tasks.
pub const ContainerInputs = struct {
    stream: abi.BoundedStreamReader,
    true_magic_kind: i64 = 0,
    identified_format: []const u8 = "unknown",
};

/// Common outputs emitted by Stage 1c pure IR lowering tasks (zero policy findings).
pub const ContainerOutputsData = struct {
    container_metadata: media_ir.ContainerMetadataRow,
    ir_regions: []const media_ir.IrRegionRow,
    ir_sample_runs: []const media_ir.IrSampleRunRow,
    ir_codec_configs: []const media_ir.IrCodecConfigRow,
    ir_attachments: []const media_ir.IrAttachmentRow,
    ir_external_refs: []const media_ir.IrExternalRefRow,
};

pub const ContainerOutputs = abi.Channels(ContainerOutputsData);

/// Adapts a `BoundedStreamReader` into any structural `ByteSource` (`ctx`, `read_at_fn`, `file_size`).
pub fn streamToSource(comptime SourceT: type, reader: *const abi.BoundedStreamReader) SourceT {
    const Wrapper = struct {
        fn readAt(ctx_ptr: *const anyopaque, buf: []u8, offset: u64) anyerror!usize {
            const stream_ptr: *const abi.BoundedStreamReader = @ptrCast(@alignCast(ctx_ptr));
            try stream_ptr.readAt(offset, buf);
            return buf.len;
        }
    };
    return .{
        .ctx = reader,
        .read_at_fn = Wrapper.readAt,
        .file_size = reader.len(),
    };
}
