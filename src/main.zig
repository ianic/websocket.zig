const std = @import("std");
const testing = std.testing;
const assert = std.debug.assert;
const ascii = std.ascii;
const mem = std.mem;
const fmt = std.fmt;

const WS_MAGIC_KEY = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
var base64Encoder = std.base64.standard.Encoder;
var rnd = std.rand.DefaultPrng.init(0);

pub const Frame = @import("frame.zig").Frame;

fn secKey() [24]u8 {
    var buf: [16]u8 = undefined;
    var ret: [24]u8 = undefined;
    rnd.random().bytes(&buf);
    var encoded = base64Encoder.encode(&ret, &buf);
    assert(encoded.len == ret.len);
    return ret;
}

test "random secKey" {
    try testing.expectEqualStrings("3yMLSWFdF1MH1YDDPW/aYQ==", &secKey());
    try testing.expectEqualStrings("/Hua7JHfD1waXr47jL/uAg==", &secKey());
}

fn secAccept(key: []const u8) [28]u8 {
    var h = std.crypto.hash.Sha1.init(.{});
    var buf: [20]u8 = undefined;

    h.update(key);
    h.update(WS_MAGIC_KEY);
    h.final(&buf);

    var ret: [28]u8 = undefined;
    const encoded = std.base64.standard.Encoder.encode(&ret, &buf);
    assert(encoded.len == ret.len);
    return ret;
}

fn isValidSecAccept(key: []const u8, accept: []const u8) bool {
    return mem.eql(u8, accept, &secAccept(key));
}

test "secAccept" {
    try testing.expectEqualStrings(&secAccept("dGhlIHNhbXBsZSBub25jZQ=="), "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=");
    try testing.expectEqualStrings(&secAccept("3yMLSWFdF1MH1YDDPW/aYQ=="), "9bQuZIN64KrRsqgxuR1CxYN94zQ=");
    try testing.expectEqualStrings(&secAccept("/Hua7JHfD1waXr47jL/uAg=="), "ELgfPf42E81xadzWVke1JyXNmqU=");
}

test "isValidSecAccept" {
    try testing.expect(isValidSecAccept("dGhlIHNhbXBsZSBub25jZQ==", "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="));
    try testing.expect(isValidSecAccept("3yMLSWFdF1MH1YDDPW/aYQ==", "9bQuZIN64KrRsqgxuR1CxYN94zQ="));
    try testing.expect(!isValidSecAccept("3yMLSWFdF1MH1YDDPW/aYQ==", "9bQuZIN64KrRsqgxuR1CxYN94zQ"));
}

pub fn isWebSocketUpgrade(rsp: *HttpResponse, sec_key: []const u8) bool {
    if (!mem.eql(u8, rsp.status, "101")) return false;

    var iter = rsp.headerIter();
    var upgrade_headers: usize = 0;
    var sec_accept_valid = false;

    while (iter.next()) |h| {
        if (h.match("upgrade", "websocket")) upgrade_headers += 1;
        if (h.match("connection", "upgrade")) upgrade_headers += 1;
        if (h.keyMatch("sec-websocket-accept")) {
            sec_accept_valid = isValidSecAccept(sec_key, h.value);
        }
    }

    return upgrade_headers == 2 and sec_accept_valid;
}

const HttpResponse = struct {
    buffer: []const u8,
    headers: []const u8,

    protocol: []const u8,
    status: []const u8,
    status_description: []const u8,

    const Self = @This();

    pub fn parse(buffer: []const u8) !Self {
        var start_index: usize = 0;
        const status_line = try readLine(buffer, &start_index);
        const sp1 = mem.indexOfScalar(u8, status_line, ' ') orelse return error.InvalidHttpResponse;
        const sp2 = mem.indexOfScalarPos(u8, status_line, sp1 + 1, ' ') orelse return error.InvalidHttpResponse;
        return .{
            .protocol = status_line[0..sp1],
            .status = status_line[sp1 + 1 .. sp2],
            .status_description = status_line[sp2 + 1 ..],
            .buffer = buffer,
            .headers = buffer[start_index..],
        };
    }

    pub fn headerIter(self: *Self) HeaderIterator {
        return HeaderIterator{ .buffer = self.headers };
    }

    pub fn hasHeader(self: *Self, key: []const u8, value: []const u8) bool {
        var iter = self.headerIter();
        while (iter.next()) |h|
            if (h.match(key, value)) return true;
        return false;
    }

    pub fn getHeader(self: *Self, key: []const u8) ?[]const u8 {
        var iter = self.headerIter();
        while (iter.next()) |h|
            if (h.keyMatch(key)) return h.value;
        return null;
    }
};

fn readLine(buffer: []const u8, start_index: *usize) ![]const u8 {
    const si = start_index.*;
    const eol = mem.indexOfScalarPos(u8, buffer, si, '\n') orelse return error.InvalidHttpResponse;
    var line = buffer[si..eol];
    start_index.* += line.len + 1;
    if (mem.endsWith(u8, line, "\r")) {
        line = line[0 .. line.len - 1];
    }
    return line;
}

const HeaderIterator = struct {
    buffer: []const u8,
    index: usize = 0,

    const Header = struct {
        key: []const u8,
        value: []const u8,

        pub fn keyMatch(h: Header, key: []const u8) bool {
            return ascii.eqlIgnoreCase(h.key, key);
        }

        pub fn match(h: Header, key: []const u8, value: []const u8) bool {
            return (ascii.eqlIgnoreCase(h.key, key) and
                ascii.eqlIgnoreCase(h.value, value));
        }
    };

    const Self = @This();

    pub fn next(self: *Self) ?Header {
        const header_line = readLine(self.buffer, &self.index) catch return null;
        if (header_line.len == 0)
            return null;
        const sep = mem.indexOfScalar(u8, header_line, ':') orelse return null;
        const whitespace = " \t";
        const key = mem.trim(u8, header_line[0..sep], whitespace);
        const value = mem.trim(u8, header_line[sep + 1 ..], whitespace);

        return Header{ .key = key, .value = value };
    }
};

test "parse response" {
    const rsp =
        \\HTTP/1.1 101 Switching Protocols
        \\Upgrade: websocket
        \\Connection: Upgrade
        \\Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=
        \\
    ;
    try assertHttpResponse(rsp);

    const rspWithCR = "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n";
    try assertHttpResponse(rspWithCR);
}

fn assertHttpResponse(rsp: []const u8) !void {
    const sec_key = "dGhlIHNhbXBsZSBub25jZQ==";
    const sec_accept = "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=";

    var p = try HttpResponse.parse(rsp);
    try testing.expectEqualStrings("HTTP/1.1", p.protocol);
    try testing.expectEqualStrings("101", p.status);
    try testing.expectEqualStrings("Switching Protocols", p.status_description);

    try testing.expectEqualStrings(p.getHeader("Sec-WebSocket-Accept").?, sec_accept);
    try testing.expectEqualStrings(p.getHeader("upgrade").?, "websocket");
    try testing.expect(p.hasHeader("upgrade", "websocket"));
    try testing.expectEqualStrings(p.getHeader("connection").?, "Upgrade");
    try testing.expect(p.hasHeader("connection", "UPGRADE")); // case insensitive match

    try testing.expect(isWebSocketUpgrade(&p, sec_key));
}

test "request" {
    var buf: [4096]u8 = undefined;
    var hs = Handshake.init("127.0.0.1:9001");
    const request = try hs.request(&buf, "/pero");

    const expected = "GET ws://127.0.0.1:9001/pero HTTP/1.1\r\nHost: 127.0.0.1:9001\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: 6l5Kr+sEyn6ajfBXd8NDBQ==\r\nSec-WebSocket-Version: 13\r\n\r\n";
    try testing.expectEqualStrings(request, expected);
}

pub const Handshake = struct {
    sec_key: [24]u8,
    host: []const u8,

    const Self = @This();
    pub fn init(host: []const u8) Self {
        return .{
            .sec_key = secKey(),
            .host = host,
        };
    }

    pub fn request(self: *Self, buf: []u8, path: []const u8) ![]u8 {
        const format = "GET ws://{s}{s} HTTP/1.1\r\nHost: {s}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: {s}\r\nSec-WebSocket-Version: 13\r\n\r\n";
        return try fmt.bufPrint(buf, format, .{ self.host, path, self.host, self.sec_key });
    }

    pub fn isValidResponse(self: *Self, buf: []const u8) bool {
        var rsp = HttpResponse.parse(buf) catch return false;
        return isWebSocketUpgrade(&rsp, &self.sec_key);
    }
};

const net = std.x.net;
const tcp = net.tcp;

pub fn Client(comptime buffers_size: usize) type {
    return struct {
        tcp: tcp.Client,

        write_buf: [buffers_size]u8 = undefined,
        read_buf: [buffers_size]u8 = undefined,
        lwm: usize = 0,
        consumed: usize = 0,
        hwm: usize = 0,

        last_frame_fragmentation: Frame.Fragment = .unfragmented,
        err: ?anyerror = null,

        const http_request_separator = "\r\n\r\n";
        const Self = @This();
        pub fn init(host: []const u8, port: u16, path: []const u8) !Self {
            var r = Self{
                .tcp = try Self.tcpConnect(host, port),
            };
            try r.wsHandshake(host, port, path);
            return r;
        }

        fn wsHandshake(self: *Self, addr: []const u8, port: u16, path: []const u8) !void {
            const host = try std.fmt.bufPrint(self.write_buf[0..], "{s}:{d}", .{ addr, port });
            var offset: usize = host.len;
            var hs = Handshake.init(host);
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

        fn decodeFrame(self: *Self) !Frame {
            while (true) {
                if (self.consumed < self.hwm) { // there is something unconsumed
                    var rsp = try Frame.decode(self.unconsumedReadBuf());
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

        fn tryReadFrame(self: *Self) !?Frame {
            while (true) {
                var frame = try self.decodeFrame();
                if (frame.isControl()) {
                    // TODO: send pong on ping, close on close, ignore pong
                    try self.echoFrame(frame);
                    if (frame.opcode == .close) return null;
                    continue;
                }
                if (frame.fin == 1) self.lwm += self.consumed;
                return frame;
            }
        }

        pub fn readFrame(self: *Self) ?Frame {
            const frame = self.tryReadFrame() catch |err| {
                self.err = err;
                self.tcpShutdown();
                return null;
            };
            if (frame == null) self.tcpShutdown();
            return frame;
        }

        pub fn readMsg(self: *Self, allocator: std.mem.Allocator) ?Msg {
            var frames = std.ArrayList(Frame).init(allocator);
            defer frames.deinit();

            while (self.readFrame()) |next| {
                frames.append(next) catch |err| {
                    self.err = err;
                    self.tcpShutdown();
                    return null;
                };
                if (next.isFin()) {
                    const msg_frames = frames.toOwnedSlice();
                    var m = Msg{
                        .encoding = if (msg_frames[0].opcode == .binary) .binary else .text,
                        .frames = msg_frames,
                    };
                    if (m.frames.len > 1 and m.encoding == .text) {
                        m.assertValidUtf8Payload() catch |err| {
                            m.deinit(allocator);
                            self.err = err;
                            self.tcpShutdown();
                            return null;
                        };
                    }
                    return m;
                }
            }
            return null;
        }

        pub fn echoMsg(self: *Self, msg: Msg) !void {
            for (msg.frames) |frame| {
                try self.echoFrame(frame);
            }
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

        fn assertValidContinutation(self: *Self, frame: *Frame) !void {
            if (!frame.isValidContinuation(self.last_frame_fragmentation)) return error.InvalidFragmentation;
            if (!frame.isControl()) self.last_frame_fragmentation = frame.fragmentation();
        }

        pub fn echoFrame(self: *Self, frame: Frame) !void {
            if (frame.opcode == .pong) return;

            var echo_frame = frame.echo();
            const encode_rsp = echo_frame.encode(&self.write_buf);
            switch (encode_rsp) {
                .required_bytes => |_| {
                    // std.log.err("write buf len: {d}, required: {d}", .{ self.write_buf.len, rb });
                    return error.WriteBufferOverflow;
                },
                .bytes => |b| {
                    try self.write(self.write_buf[0..b]);
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
}

// debug helper
fn showBuf(buf: []const u8) void {
    std.debug.print("\n", .{});
    for (buf) |b|
        std.debug.print("0x{x:0>2}, ", .{b});
}

pub const MsgEncoding = enum {
    text,
    binary,
};

pub const Msg = struct {
    frames: []Frame,
    encoding: MsgEncoding = .text,

    const Self = @This();

    pub fn assertValidUtf8Payload(self: Self) !void {
        var cp: [4]u8 = undefined;
        var cp_len: usize = 0;
        var cp_pos: usize = 0;

        var frame_no: usize = 0;
        while (frame_no < self.frames.len) {
            var s = self.frames[frame_no].payload;
            var i: usize = 0;

            while (i < s.len) : (i += 1) {
                if (cp_len == 0) {
                    cp_len = std.unicode.utf8ByteSequenceLength(s[i]) catch return error.InvalidUtf8Payload;
                }
                cp[cp_pos] = s[i];
                cp_pos += 1;
                if (cp_pos == cp_len) {
                    _ = std.unicode.utf8Decode(cp[0..cp_len]) catch return error.InvalidUtf8Payload;
                    cp_len = 0;
                    cp_pos = 0;
                }
            }
            frame_no += 1;
        }
        if (cp_len != 0) return error.InvalidUtf8Payload;
    }

    pub fn deinit(self: Self, allocator: std.mem.Allocator) void {
        allocator.free(self.frames);
    }
};

test "valid utf8 message" {
    // Hello-µ@ßöäüàá-UTF-8!!
    var data1 = [_]u8{ 0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x2d, 0xc2, 0xb5, 0x40, 0xc3, 0x9f, 0xc3, 0xb6, 0xc3, 0xa4, 0xc3, 0xbc, 0xc3, 0xa0, 0xc3, 0xa1, 0x2d, 0x55, 0x54, 0x46, 0x2d, 0x38, 0x21, 0x21 };
    try testWithFragmentation(&data1);
    // κόσμε
    var data2 = [_]u8{ 0xce, 0xba, 0xe1, 0xbd, 0xb9, 0xcf, 0x83, 0xce, 0xbc, 0xce, 0xb5 };
    try testWithFragmentation(&data2);
}

fn testWithFragmentation(data: []u8) !void {
    var fragment_len: usize = 1;
    while (fragment_len <= data.len) : (fragment_len += 1) {
        var m = try testMsgWithFragments(data, fragment_len);
        try m.assertValidUtf8Payload();
        m.deinit(testing.allocator);
    }
}

fn testMsgWithFragments(data: []u8, fragment_len: usize) !Msg {
    var frames = std.ArrayList(Frame).init(testing.allocator);
    var i: usize = 0;
    while (i < data.len) : (i += fragment_len) {
        var j = i + fragment_len;
        if (j > data.len) j = data.len;
        try frames.append(Frame{ .fin = 1, .opcode = .text, .payload = data[i..j] });
    }
    return Msg{
        .frames = frames.toOwnedSlice(),
    };
}

test "invalid utf8 message" {
    var data = [_]u8{ 0xce, 0xba, 0xe1, 0xbd, 0xb9, 0xcf, 0x83, 0xce, 0xbc, 0xce, 0xb5, 0xed, 0xa0, 0x80, 0x65, 0x64, 0x69, 0x74, 0x65, 0x64 };
    var m = try testMsgWithFragments(&data, 1);
    try testing.expectError(error.InvalidUtf8Payload, m.assertValidUtf8Payload());
    m.deinit(testing.allocator);
}
