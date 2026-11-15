pub const types = @import("types.zig");
pub const parser = @import("parser.zig");

pub const AviMainHeader = types.AviMainHeader;
pub const AviVideoFormat = types.AviVideoFormat;
pub const AviAudioFormat = types.AviAudioFormat;
pub const AviStreamRecord = types.AviStreamRecord;
pub const AviSampleRun = types.AviSampleRun;
pub const AviDissectionResult = types.AviDissectionResult;
pub const AviDissector = parser.AviDissector;

