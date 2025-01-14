const std = @import("std");
const tls = @import("tls");
const ws = @import("ws");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    const allocator = gpa.allocator();

    const url = "wss://www.supersport.hr/api/sbk";
    const uri = try std.Uri.parse(url);
    const host = uri.host.?.percent_encoded;
    const port = 443;

    // Load system root certificates
    var root_ca = try tls.config.CertBundle.fromSystem(allocator);
    defer root_ca.deinit(allocator);

    // Establish tcp connection
    var tcp = try std.net.tcpConnectToHost(allocator, host, port);
    defer tcp.close();

    // Upgrade tcp connection to tls
    var conn = try tls.client(tcp, .{
        .host = host,
        .root_ca = root_ca,
    });

    // Websocket client
    var cli = try ws.client(allocator, conn.reader(), conn.writer(), url);
    defer cli.deinit();

    // Subscription
    const payload =
        \\{"t":1,"u":[{"s":"i_hr"},{"s":"bb","n":0}]}
    ;
    try cli.send(.text, payload, true);

    // Show incoming messages
    var i: usize = 0;
    while (cli.nextMessage()) |msg| : (i += 1) {
        defer msg.deinit();
        //std.debug.print("{s}\n", .{msg.payload});
        std.debug.print("{} {}\n", .{ i, msg.payload.len });
    }
    if (cli.err) |err| return err;
}
