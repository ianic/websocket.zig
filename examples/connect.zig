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
        // 2 Pings/Pongs
        .{ .cases = 11, .desc = "2 Pings/Pongs" },
        // 3 Reserved Bits
        .{ .cases = 7, .desc = "3 Reserved Bits" },
        // 4 Opcodes
        .{ .cases = 5, .desc = "4.1 Non-control Opcodes" },
        .{ .cases = 5, .desc = "4.2 Control Opcodes" },
        // 5 Fragmentation
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
    var path_buf: [128]u8 = undefined;
    for (tests_groups) |group| {
        var group_case: usize = 0;
        while (group_case < group.cases) : (group_case += 1) {
            case_no += 1;
            // if (group.descStartsWith("6.") or
            //     group.descStartsWith("7.") or
            //     group.descStartsWith("5"))
            //     continue;
            // if (!group.descStartsWith("1")) {
            //     continue;
            // }
            // if (case_no != 1) {
            //     continue;
            // }
            std.log.debug("running case no: {d} {s} {d} ", .{ case_no, group.desc, group_case + 1 });

            const path = try std.fmt.bufPrint(&path_buf, "/runCase?case={d}&agent=1.zig", .{case_no});
            var runner = try Runner.init("127.0.0.1", 9001, path);
            while (runner.readFrame()) |frame| {
                try runner.sendEcho(frame);
            }
            if (runner.err) |err| {
                std.log.err("{}", .{err});
            }
        }
    }
}

const Runner = struct {
    tcp: tcp.Client,

    write_buf: [17 * 4096]u8 = undefined, // TODO buf size, this is because there are tests with 16 * 4096 payload size
    read_buf: [17 * 4096]u8 = undefined,
    lwm: usize = 0,
    consumed: usize = 0,
    hwm: usize = 0,

    last_frame_fragmentation: ws.Frame.Fragment = .unfragmented,
    err: ?anyerror = null,

    const Self = @This();
    pub fn init(host: []const u8, port: u16, path: []const u8) !Self {
        var r = Self{
            .tcp = try Runner.tcpConnect(host, port),
        };
        try r.wsHandshake(host, port, path);
        return r;
    }

    fn wsHandshake(self: *Self, addr: []const u8, port: u16, path: []const u8) !void {
        const host = try std.fmt.bufPrint(self.write_buf[0..], "{s}:{d}", .{ addr, port });
        var offset: usize = host.len;
        var hs = ws.Handshake.init(host);
        try self.write(try hs.request(self.write_buf[offset..], path));

        // handshake
        while (true) {
            try self.read();
            const buf = self.unconsumedReadBuf();
            var eor = std.mem.indexOf(u8, buf, http_request_separator) orelse 0; // eor = end of request
            if (eor == 0) continue; // read more

            eor += http_request_separator.len;
            const rsp_buf = buf[0..eor];
            if (!hs.isValidResponse(rsp_buf)) {
                self.tcpShutdown();
                return error.IvalidHandshakeResponse;
            }
            self.lwm = eor;
            self.consumed = eor;
            break; // fine
        }
    }

    fn decodeFrame(self: *Self) !ws.Frame {
        while (true) {
            if (self.consumed < self.hwm) { // there is something unconsumed
                var rsp = try ws.Frame.decode(self.unconsumedReadBuf());
                if (rsp.isValid()) {
                    var frame = rsp.frame.?;
                    try self.assertValidContinutation(&frame);
                    self.consumed += rsp.bytes;
                    return frame;
                } else { // not enough bytes in read_buf to decode frame
                    if (rsp.required_bytes > self.read_buf.len) {
                        // TODO extend read_buffer
                        // TODO send close with too big message close status code
                        return error.ReadBufferOverflow;
                    }
                    self.shrinkReadBuf();
                }
            }
            try self.read();
        }
    }

    fn tryReadFrame(self: *Self) !?ws.Frame {
        while (true) {
            var frame = try self.decodeFrame();
            if (frame.isControl()) {
                // TODO: send pong on ping, close on close, ignore pong
                try self.sendEcho(frame);
                if (frame.opcode == .close) return null;
                continue;
            }
            if (frame.fin == 1) self.lwm += self.consumed;
            return frame;
        }
    }

    pub fn readFrame(self: *Self) ?ws.Frame {
        const frame = self.tryReadFrame() catch |err| {
            self.err = err;
            self.tcpShutdown();
            return null;
        };
        if (frame == null) self.tcpShutdown();
        return frame;
    }

    fn unconsumedReadBuf(self: *Self) []u8 {
        return self.read_buf[self.consumed..self.hwm];
    }

    fn readBufConsumed(self: *Self) bool {
        return self.lwm == self.hwm and self.consumed == self.lwm;
    }

    fn read(self: *Self) !void {
        if (self.readBufConsumed()) {
            // move to the start of read buf
            self.lwm = 0;
            self.hwm = 0;
            self.consumed = 0;
        }
        const bytes_read = try self.tcp.read(self.read_buf[self.hwm..], 0);
        if (bytes_read == 0) return error.ConnectionClosed;
        self.hwm += bytes_read;
    }

    fn shrinkReadBuf(self: *Self) void {
        if (self.lwm == 0) return;
        std.mem.copy(u8, self.read_buf[0..], self.read_buf[self.lwm..self.hwm]);
        self.hwm -= self.lwm;
        if (self.consumed >= self.lwm) self.consumed -= self.lwm;
        self.lwm = 0;
    }

    fn assertValidContinutation(self: *Self, frame: *ws.Frame) !void {
        if (!frame.isValidContinuation(self.last_frame_fragmentation)) return error.InvalidFragmentation;
        if (!frame.isControl()) self.last_frame_fragmentation = frame.fragmentation();
    }

    pub fn sendEcho(self: *Self, frame: ws.Frame) !void {
        if (frame.opcode == .pong) return;

        // send echo frame
        var echo_frame = frame.echo();
        const encode_rsp = echo_frame.encode(&self.write_buf);
        switch (encode_rsp) {
            .required_bytes => |_| {
                // std.log.err("write buf len: {d}, required: {d}", .{ self.write_buf.len, rb });
                return error.WriteBufferOverflow;
            },
            .bytes => |rb| {
                try self.write(self.write_buf[0..rb]);
            },
        }
    }

    fn write(self: *Self, buf: []const u8) !void {
        var bytes_written: usize = 0;
        while (bytes_written < buf.len)
            bytes_written += try self.tcp.write(buf, 0);
    }

    fn tcpShutdown(self: *Self) void {
        self.tcp.shutdown(.both) catch {};
    }

    fn tcpConnect(host: []const u8, port: u16) !tcp.Client {
        const addr = net.ip.Address.initIPv4(try std.x.os.IPv4.parse(host), port);
        const client = try tcp.Client.init(.ip, .{ .close_on_exec = true });
        try client.connect(addr);
        errdefer client.deinit();
        return client;
    }
};

fn showBuf(buf: []const u8) void {
    std.debug.print("\n", .{});
    for (buf) |b|
        std.debug.print("0x{x:0>2}, ", .{b});
}
