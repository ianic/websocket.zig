const std = @import("std");
const mem = std.mem;
const assert = std.debug.assert;

pub const handshake = @import("handshake.zig");
pub const stream = @import("stream.zig");
pub const Message = stream.Message;

pub fn client(
    allocator: std.mem.Allocator,
    inner_reader: anytype,
    inner_writer: anytype,
    uri: []const u8,
) !stream.Stream(@TypeOf(inner_reader), @TypeOf(inner_writer)) {
    const options = try handshake.client(allocator, inner_reader, inner_writer, uri);
    return try stream.client(allocator, inner_reader, inner_writer, options);
}

test {
    // Run tests in imported files in `zig build test`
    _ = @import("handshake.zig");
    _ = @import("stream.zig");
    _ = @import("frame.zig");
    _ = @import("async.zig");
}

const asyn_ = @import("async.zig");

pub const asyn = struct {
    pub const Server = asyn_.Server;
    pub const Client = asyn_.Client;
    pub const Conn = asyn_.Conn;
};

pub const Msg = asyn_.Msg;
