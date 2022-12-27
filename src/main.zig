const std = @import("std");

pub const handshake = @import("handshake.zig");
pub const stream = @import("stream.zig");

pub fn client(
    allocator: std.mem.Allocator,
    inner_reader: anytype,
    inner_writer: anytype,
    host: []const u8,
    path: []const u8,
) !stream.Stream(@TypeOf(inner_reader), @TypeOf(inner_writer)) {
    try handshake.client(allocator, inner_reader, inner_writer, host, path);
    return try stream.client(allocator, inner_reader, inner_writer);
}

test {
    // Run tests in imported files in `zig build test`
    _ = @import("handshake.zig");
    _ = @import("stream.zig");
    _ = @import("frame.zig");
}
