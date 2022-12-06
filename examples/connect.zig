const std = @import("std");
const net = std.x.net;
const tcp = net.tcp;

pub fn main() !void {
    const client = try tcpConnect();

    var scratch_buf: [1024]u8 = undefined;
    _ = try client.write(upgrade_request, 0);

    while (true) {
        const offset = try client.read(&scratch_buf, 0);
        std.debug.print("got {d} bytes:\n", .{offset});
        std.debug.print("{s}\n", .{scratch_buf[0..offset]});
        if (offset == 0) {
            break;
        }
    }
}

fn tcpConnect() !tcp.Client {
    const addr = net.ip.Address.initIPv4(try std.x.os.IPv4.parse("127.0.0.1"), 9001);
    const client = try tcp.Client.init(.ip, .{ .close_on_exec = true });
    try client.connect(addr);
    errdefer client.deinit();
    return client;
}

const upgrade_request = "GET ws://127.0.0.1:9001/runCase?case=3&agent=Chrome/105.0.0.0 HTTP/1.1\r\nHost: 127.0.0.1:9001\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nOrigin: http://example.com\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Protocol: chat, superchat\r\nSec-WebSocket-Version: 13\r\n\r\n";
