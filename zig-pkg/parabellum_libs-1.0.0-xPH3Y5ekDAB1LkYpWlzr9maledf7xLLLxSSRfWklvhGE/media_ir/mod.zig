//! Pure, zero-dependency Universal Container Intermediate Representation (IR)
//! and format-agnostic forensic analysis primitives (`topology`, `inconsistencies`, `intervals`).

const std = @import("std");

// Domain entities
pub const container_format = @import("entities/container_format.zig");
pub const region_role = @import("entities/region_role.zig");
pub const track_type = @import("entities/track_type.zig");
pub const byte_stream = @import("entities/byte_stream.zig");
pub const slice_stream = @import("entities/slice_stream.zig");
pub const region = @import("entities/region.zig");
pub const track = @import("entities/track.zig");
pub const sample_extent = @import("entities/sample_extent.zig");
pub const container_ir = @import("entities/container_ir.zig");

// Pipeline relational rows
pub const rows = @import("rows/mod.zig");
pub const audit_finding_row = @import("findings/audit_finding_row.zig");

// Format-agnostic analysis & lowering helpers
pub const intervals = @import("analysis/intervals.zig");
pub const lowering_types = @import("analysis/lowering_types.zig");
pub const lowering_common = @import("analysis/lowering_common.zig");
pub const topology = @import("analysis/topology.zig");
pub const inconsistencies = @import("analysis/inconsistencies.zig");

// Canonical re-exports: Entities
pub const ContainerFormat = container_format.ContainerFormat;
pub const RegionRole = region_role.RegionRole;
pub const TrackType = track_type.TrackType;
pub const ByteStream = byte_stream.ByteStream;
pub const SliceStream = slice_stream.SliceStream;
pub const Region = region.Region;
pub const Track = track.Track;
pub const SampleExtent = sample_extent.SampleExtent;
pub const ContainerIR = container_ir.ContainerIR;

// Canonical re-exports: Rows
pub const ContainerMetadataRow = rows.ContainerMetadataRow;
pub const IrRegionRow = rows.IrRegionRow;
pub const IrSampleRunRow = rows.IrSampleRunRow;
pub const IrUnreferencedSlackRow = rows.IrUnreferencedSlackRow;
pub const IrCodecConfigRow = rows.IrCodecConfigRow;
pub const IrAttachmentRow = rows.IrAttachmentRow;
pub const IrExternalRefRow = rows.IrExternalRefRow;
pub const ByteInterval = rows.ByteInterval;
pub const AuditFindingRow = audit_finding_row.AuditFindingRow;
pub const AuditFinding = AuditFindingRow;

// Canonical re-exports: Analysis
pub const Interval = intervals.Interval;
pub const RegionInput = lowering_types.RegionInput;
pub const LowerContainerOutput = lowering_types.LowerContainerOutput;
pub const lowerRegions = lowering_common.lowerRegions;

pub const SlackKind = topology.SlackKind;
pub const SlackRegion = topology.SlackRegion;
pub const RegionOverlap = topology.RegionOverlap;
pub const TopologyReport = topology.TopologyReport;
pub const analyzeTopology = topology.analyzeTopology;

pub const InconsistencyKind = inconsistencies.InconsistencyKind;
pub const InconsistencyFact = inconsistencies.InconsistencyFact;
pub const detectInconsistencies = inconsistencies.detectInconsistencies;

test {
    std.testing.refAllDecls(@This());
}
