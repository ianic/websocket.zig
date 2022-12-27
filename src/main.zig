const std = @import("std");

pub const Frame = @import("frame.zig").Frame;
pub const Client = @import("client.zig").TcpClient;

pub const clientHandshake = @import("handshake_stream.zig").clientHandshake;
pub const stream = @import("stream.zig");

pub fn clientStream(
    allocator: std.mem.Allocator,
    inner_reader: anytype,
    inner_writer: anytype,
    host: []const u8,
    path: []const u8,
) !stream.Stream(@TypeOf(inner_reader), @TypeOf(inner_writer)) {
    try clientHandshake(allocator, inner_reader, inner_writer, host, path);
    return try stream.stream(allocator, inner_reader, inner_writer);
}

test {
    // Run tests in imported files in `zig build test`
    _ = @import("handshake.zig");
    _ = @import("client.zig");
    _ = @import("frame.zig");
}
