const std = @import("std");
const net = std.x.net;
const tcp = net.tcp;
const ws = @import("websocket");

const http_request_separator = "\r\n\r\n";

pub fn main() !void {
    const tests = [_]u8{
        // 1, 2, 3, 4, 5, 6, 7, 8, // 1.1 text messages
        // 9, 10, 11, 12, 13, 14, 15, 16, // 1.2 binary messages
        // 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, // ping pongs
        //28, 29, 30, 31, 32, 33, 34, // reserved bits
        35, 36, 37, 38, 39, // non cotrol opcodes
        40, 41, 42, 43, 44, // control opcodes
        //45, // fragmentation -- FAILING
        65, 66, 67, // utf-8
        68, 69, 70, 71, // utf-8
        72, 73, // invalid utf-8 FAILING
        74, 75, 76, 77, //
        78, 79, 80, 81, 82, //
    };

    var buf: [128]u8 = undefined;
    for (tests) |t| {
        const path = try std.fmt.bufPrint(&buf, "/runCase?case={d}&agent=websocket.zig", .{t});
        try runCase(path);
    }
}

fn runCase(path: []const u8) !void {
    const client = try tcpConnect();

    var write_buf: [17 * 4096]u8 = undefined;
    var read_buf: [17 * 4096]u8 = undefined;
    var hs = ws.Handshake.init("127.0.0.1:9001");

    _ = try client.write(try hs.request(&write_buf, path), 0);
    var hwm: usize = 0;
    var eob: usize = 0;

    // handshake
    while (true) {
        const br = try client.read(read_buf[eob..], 0);
        if (br == 0) {
            return;
        }
        eob += br;
        const buf = read_buf[0..eob];
        var eor = std.mem.indexOf(u8, buf, http_request_separator) orelse 0;
        if (eor == 0) {
            continue;
        }
        eor += http_request_separator.len;
        const rsp_buf = read_buf[0..eor];
        if (!hs.isValidResponse(rsp_buf)) {
            try client.shutdown(.both);
            return;
        }
        hwm = eor;
        break;
    }

    // reading messages
    while (true) {
        const buf = read_buf[hwm..eob];
        if (buf.len > 0) {
            // decode frame
            var rsp = ws.Frame.decode(buf) catch {
                try client.shutdown(.both);
                return;
            };
            if (rsp.required_bytes == 0) {
                var frame = rsp.frame.?;
                var echo_frame = frame.echo();
                //std.debug.print("{}\n", .{frame});
                if (frame.opcode != .pong) {
                    // send echo frame
                    const encode_rsp = echo_frame.encode(&write_buf);
                    switch (encode_rsp) {
                        .required_bytes => |rb| {
                            std.log.err("write buf len: {d}, required: {d}", .{ write_buf.len, rb });
                            unreachable;
                        },
                        .bytes => |rb| {
                            _ = try client.write(write_buf[0..rb], 0);
                        },
                    }
                }
                // close if recived close frame
                if (frame.opcode == .close) {
                    try client.shutdown(.both);
                    return;
                }
                hwm += rsp.bytes;
                if (hwm < eob) { // there is something more in buf
                    std.log.debug("{s} continue hwm: {d}, eob: {d}, bytes: {d}", .{ path, hwm, eob, rsp.bytes });
                    continue;
                }
                hwm = 0;
                eob = 0;
            } else {
                if (rsp.required_bytes > read_buf.len) {
                    // TODO extend read_buffer
                    unreachable;
                }
                //std.log.debug("{s} get more read buf len: {d}, required: {d}", .{ path, buf.len, rsp.required_bytes });
                if (hwm > 0) { // rewind existing to the read_buffer start
                    std.log.debug("{s} rewind read_buf to start hwm: {d}, eob: {d}", .{ path, hwm, eob });
                    std.mem.copy(u8, read_buf[0..], read_buf[hwm..eob]);
                    eob -= hwm;
                    hwm = 0;
                }
            }
        } else {
            hwm = 0;
            eob = 0;
        }
        const br = try client.read(read_buf[eob..], 0);
        if (br == 0) {
            return;
        }
        eob += br;
    }
}

fn showBuf(buf: []const u8) void {
    std.debug.print("\n", .{});
    for (buf) |b|
        std.debug.print("{x:0>2} ", .{b});
}

fn tcpConnect() !tcp.Client {
    const addr = net.ip.Address.initIPv4(try std.x.os.IPv4.parse("127.0.0.1"), 9001);
    const client = try tcp.Client.init(.ip, .{ .close_on_exec = true });
    try client.connect(addr);
    errdefer client.deinit();
    return client;
}

const upgrade_request = "GET ws://127.0.0.1:9001/runCase?case=3&agent=Chrome/105.0.0.0 HTTP/1.1\r\nHost: 127.0.0.1:9001\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nOrigin: http://example.com\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Protocol: chat, superchat\r\nSec-WebSocket-Version: 13\r\n\r\n";
