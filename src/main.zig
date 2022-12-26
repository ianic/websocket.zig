pub const Frame = @import("frame.zig").Frame;
pub const Client = @import("client.zig").TcpClient;

pub const clientHandshake = @import("handshake_stream.zig").clientHandshake;
pub const stream = @import("stream.zig").stream;

test {
    // Run tests in imported files in `zig build test`
    _ = @import("handshake.zig");
    _ = @import("client.zig");
    _ = @import("frame.zig");
}
