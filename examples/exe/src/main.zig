const std = @import("std");
const ws = @import("ws");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const hostname = "ws.vi-server.org";
    const uri = "ws://ws.vi-server.org/mirror/";
    const port = 80;

    var tcp = try std.net.tcpConnectToHost(allocator, hostname, port);
    defer tcp.close();
    var cli = try ws.client(allocator, tcp.reader(), tcp.writer(), uri);
    defer cli.deinit();

    try cli.send(.text, "hello world", true);
    if (cli.nextMessage()) |msg| {
        defer msg.deinit();
        std.debug.print("{s}", .{msg.payload});
    }
    if (cli.err) |err| return err;
}
