pub const define_driver = @import("define_driver.zig");
pub const define_extension = @import("define_extension.zig");

pub const DriverMeta = define_driver.DriverMeta;
pub const defineDriver = define_driver.defineDriver;

pub const ExtensionMeta = define_extension.ExtensionMeta;
pub const defineExtension = define_extension.defineExtension;
