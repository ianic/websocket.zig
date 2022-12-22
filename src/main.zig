pub const Frame = @import("frame.zig").Frame;
pub const Client = @import("client.zig").TcpClient;

test {
    // Run tests in imported files in `zig build test`
    _ = @import("handshake.zig");
    _ = @import("client.zig");
    _ = @import("frame.zig");
}
