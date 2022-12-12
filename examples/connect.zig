const std = @import("std");
const net = std.x.net;
const tcp = net.tcp;
const ws = @import("websocket");

const http_request_separator = "\r\n\r\n";

const Group = struct {
    cases: u8,
    desc: []const u8,

    pub fn descStartsWith(self: Group, needle: []const u8) bool {
        return std.ascii.startsWithIgnoreCase(self.desc, needle);
    }
};

pub fn main() !void {
    const tests_groups = [_]Group{
        // 1 Framing
        .{ .cases = 8, .desc = "1.1 Text Messages" },
        .{ .cases = 8, .desc = "1.2 Binary Messages" },

        .{ .cases = 11, .desc = "2 Pings/Pongs" },
        .{ .cases = 7, .desc = "3 Reserved Bits" },
        // 4 Opcodes
        .{ .cases = 5, .desc = "4.1 Non-control Opcodes" },
        .{ .cases = 5, .desc = "4.2 Control Opcodes" },

        .{ .cases = 20, .desc = "5 Fragmentation" },
        // 6 UTF-8 Handling
        .{ .cases = 3, .desc = "6.1 Valid UTF-8 with zero payload fragments" },
        .{ .cases = 4, .desc = "6.2 Valid UTF-8 unfragmented, fragmented on code-points and within code-points" },
        .{ .cases = 2, .desc = "6.3 Invalid UTF-8 differently fragmented" },
        .{ .cases = 4, .desc = "6.4 Fail-fast on invalid UTF-8" },
        .{ .cases = 5, .desc = "6.5 Some valid UTF-8 sequences" },
        .{ .cases = 11, .desc = "6.6 All prefixes of a valid UTF-8 string that contains multi-byte code points" },
        .{ .cases = 4, .desc = "6.7 First possible sequence of a certain length" },
        .{ .cases = 2, .desc = "6.8 First possible sequence length 5/6 (invalid codepoints)" },
        .{ .cases = 4, .desc = "6.9 Last possible sequence of a certain length" },
        .{ .cases = 3, .desc = "6.10 Last possible sequence length 4/5/6 (invalid codepoints)" },
        .{ .cases = 5, .desc = "6.11 Other boundary conditions" },
        .{ .cases = 8, .desc = "6.12 Unexpected continuation bytes" },
        .{ .cases = 5, .desc = "6.13 Lonely start characters" },
        .{ .cases = 10, .desc = "6.14 Sequences with last continuation byte missing" },
        .{ .cases = 1, .desc = "6.15 Concatenation of incomplete sequences" },
        .{ .cases = 3, .desc = "6.16 Impossible bytes" },
        .{ .cases = 5, .desc = "6.17 Examples of an overlong ASCII characte" },
        .{ .cases = 5, .desc = "6.18 Maximum overlong sequences" },
        .{ .cases = 5, .desc = "6.19 Overlong representation of the NUL character" },
        .{ .cases = 7, .desc = "6.20 Single UTF-16 surrogates" },
        .{ .cases = 8, .desc = "6.21 Paired UTF-16 surrogates" },
        .{ .cases = 34, .desc = "6.22 Non-character code points (valid UTF-8)" },
        .{ .cases = 7, .desc = "6.23 Unicode specials (i.e. replacement char)" },
        // 7 Close Handling
        .{ .cases = 6, .desc = "7.1 Basic close behavior (fuzzer initiated)" },
        .{ .cases = 6, .desc = "7.3 Close frame structure: payload length (fuzzer initiated)" },
        .{ .cases = 1, .desc = "7.5 Close frame structure: payload value (fuzzer initiated)" },
        .{ .cases = 13, .desc = "7.7 Close frame structure: valid close codes (fuzzer initiated)" },
        .{ .cases = 9, .desc = "7.9 Close frame structure: invalid close codes (fuzzer initiated)" },
        .{ .cases = 2, .desc = "7.13 Informational close information (fuzzer initiated)" },
        // 9 Limits/Performance
        // 10 Misc
        // 12 WebSocket Compression (different payloads)
        // 13 WebSocket Compression (different parameters)
    };

    var case_no: usize = 0;
    for (tests_groups) |group| {
        var group_case: usize = 0;
        while (group_case < group.cases) : (group_case += 1) {
            case_no += 1;
            // if (group.descStartsWith("6.") or
            //     group.descStartsWith("7.") or
            //     group.descStartsWith("5"))
            //     continue;
            if (!group.descStartsWith("6")) {
                continue;
            }
            // if (case_no != 210) {
            //     continue;
            // }
            std.log.debug("running case no: {d} {s} {d} ", .{ case_no, group.desc, group_case + 1 });
            try runCase(case_no);
        }
    }
}

fn runCase(case_no: usize) !void {
    var path_buf: [128]u8 = undefined;
    const path = try std.fmt.bufPrint(&path_buf, "/runCase?case={d}&agent=websocket.zig", .{case_no});

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

    var last_frame_fragmentation: ws.Frame.Fragment = .unfragmented;

    // reading messages
    while (true) {
        const buf = read_buf[hwm..eob];
        if (buf.len > 0) {
            // decode frame
            var rsp = ws.Frame.decode(buf) catch {
                try client.shutdown(.both);
                return;
            };
            //showBuf(buf);

            if (rsp.required_bytes == 0) {
                var frame = rsp.frame.?;
                //std.debug.print("frame fragmentation: {}\n", .{frame.fragmentation()});
                if (!frame.isValidContinuation(last_frame_fragmentation)) {
                    // close connection
                    client.shutdown(.both) catch {};
                    return;
                }

                if (!frame.isControl()) {
                    last_frame_fragmentation = frame.fragmentation();
                }
                // create and write echo frame
                var echo_frame = frame.echo();
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
                    client.shutdown(.both) catch {};
                    return;
                }
                hwm += rsp.bytes;
                if (hwm < eob) { // there is something more in buf
                    //std.log.debug("{d} continue hwm: {d}, eob: {d}, bytes: {d}", .{ case_no, hwm, eob, rsp.bytes });
                    continue;
                }
                hwm = 0;
                eob = 0;
            } else {
                if (rsp.required_bytes > read_buf.len) {
                    std.log.err("{d} read buffer overflow required: {d}, current: {d}", .{ case_no, rsp.required_bytes, read_buf.len });
                    // TODO extend read_buffer
                    client.shutdown(.both) catch {};
                    return;
                    //unreachable;
                }
                //std.log.debug("{s} get more read buf len: {d}, required: {d}", .{ path, buf.len, rsp.required_bytes });
                if (hwm > 0) { // rewind existing to the read_buffer start
                    //std.log.debug("{d} rewind read_buf to start hwm: {d}, eob: {d}", .{ case_no, hwm, eob });
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
        std.debug.print("0x{x:0>2}, ", .{b});
}

fn tcpConnect() !tcp.Client {
    const addr = net.ip.Address.initIPv4(try std.x.os.IPv4.parse("127.0.0.1"), 9001);
    const client = try tcp.Client.init(.ip, .{ .close_on_exec = true });
    try client.connect(addr);
    errdefer client.deinit();
    return client;
}

const upgrade_request = "GET ws://127.0.0.1:9001/runCase?case=3&agent=Chrome/105.0.0.0 HTTP/1.1\r\nHost: 127.0.0.1:9001\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nOrigin: http://example.com\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Protocol: chat, superchat\r\nSec-WebSocket-Version: 13\r\n\r\n";
