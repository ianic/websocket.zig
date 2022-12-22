const std = @import("std");
const testing = std.testing;
const net = std.x.net;
const tcp = net.tcp;

const Frame = @import("frame.zig").Frame;
const Handshake = @import("handshake.zig").Handshake;

pub const TcpClient = Client(TcpStream);

pub const TcpStream = struct {
    client: tcp.Client,

    const Self = @This();

    pub fn init(host: []const u8, port: u16) !Self {
        const addr = net.ip.Address.initIPv4(try std.x.os.IPv4.parse(host), port);
        const client = try tcp.Client.init(.ip, .{ .close_on_exec = true });
        try client.connect(addr);
        errdefer client.deinit();
        return .{ .client = client };
    }

    pub fn read(self: *Self, buf: []u8) !usize {
        return self.client.read(buf, 0);
    }

    pub fn write(self: *Self, buf: []const u8) !usize {
        return self.client.write(buf, 0);
    }

    pub fn close(self: *Self) void {
        self.client.shutdown(.both) catch {};
        self.client.deinit();
    }
};

pub fn Client(comptime StreamType: type) type {
    return struct {
        stream: StreamType,

        write_buf: []u8,
        read_buf: []u8,
        lwm: usize = 0,
        consumed: usize = 0,
        hwm: usize = 0,

        last_frame_fragmentation: Frame.Fragment = .unfragmented,
        err: ?anyerror = null,

        const http_request_separator = "\r\n\r\n";
        const Self = @This();

        pub fn init(read_buf: []u8, write_buf: []u8, host: []const u8, port: u16, path: []const u8) !Self {
            var self = Self{
                .read_buf = read_buf,
                .write_buf = write_buf,
                .stream = try StreamType.init(host, port),
            };
            try self.wsHandshake(host, port, path);
            return self;
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
                    self.stream.close();
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
                    switch (frame.opcode) {
                        .ping => {
                            const bytes = Frame.encodePong(self.write_buf, frame.payload);
                            try self.write(self.write_buf[0..bytes]);
                        },
                        .close => {
                            const bytes = Frame.encodeClose(self.write_buf, frame.closeCode(), frame.closePayload());
                            try self.write(self.write_buf[0..bytes]);
                            return null;
                        },
                        .pong => {},
                        else => unreachable,
                    }
                    continue;
                }
                if (frame.fin == 1) self.lwm += self.consumed;
                return frame;
            }
        }

        pub fn readFrame(self: *Self) ?Frame {
            const frame = self.tryReadFrame() catch |err| {
                self.err = err;
                self.stream.close();
                return null;
            };
            if (frame == null) self.stream.close();
            return frame;
        }

        pub fn readMsg(self: *Self, allocator: std.mem.Allocator) ?Msg {
            var frames = std.ArrayList(Frame).init(allocator);
            defer frames.deinit();

            while (self.readFrame()) |next| {
                frames.append(next) catch |err| {
                    self.err = err;
                    self.stream.close();
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
                            self.stream.close();
                            return null;
                        };
                    }
                    return m;
                }
            }
            return null;
        }

        pub fn readMessage(self: *Self) ?Message {
            if (self.framesToMessage()) |msg| {
                if (msg.encoding == .text) {
                    // validate text payload as valid utf8
                    if (!std.unicode.utf8ValidateSlice(msg.payload)) {
                        self.err = error.InvalidUtf8Payload;
                        self.stream.close();
                        return null;
                    }
                }
                return msg;
            }
            return null;
        }

        fn framesToMessage(self: *Self) ?Message {
            var buf: []u8 = undefined;
            var len: usize = 0;
            var encoding: MsgEncoding = .text;

            if (self.readFrame()) |frame| {
                encoding = if (frame.opcode == .binary) .binary else .text;
                if (frame.isFin()) {
                    // if single frame return frame payload
                    return Message{
                        .encoding = encoding,
                        .payload = frame.payload,
                    };
                }
                // remember position of the frame payload in read_buf
                len = frame.payload.len;
                buf = self.read_buf[self.consumed - len ..];
            } else {
                return null;
            }

            while (self.readFrame()) |frame| {
                // append frame payload to the end of last frame payload
                std.mem.copy(u8, buf[len..], frame.payload);
                len += frame.payload.len;
                if (frame.isFin()) {
                    return Message{
                        .encoding = encoding,
                        .payload = buf[0..len],
                    };
                }
            }
            return null;
        }

        pub fn sendMessage(self: *Self, msg: Message) !void {
            var sent_payload: usize = 0;
            // send multiple frames if needed
            while (true) {
                var fin: u1 = 1;
                // use frame payload that fits into write_buf
                var frame_payload = msg.payload[sent_payload..];
                if (frame_payload.len + Frame.max_header > self.write_buf.len) {
                    frame_payload = frame_payload[0 .. self.write_buf.len - Frame.max_header];
                    fin = 0;
                }
                // set opcode for the first frame
                const opcode = if (sent_payload == 0)
                    if (msg.encoding == .text) Frame.Opcode.text else Frame.Opcode.binary
                else
                    Frame.Opcode.continuation;
                // create frame
                const frame = Frame.msg(fin, opcode, frame_payload);
                // encode frame into write_buf and send it to stream
                const bytes = frame.encode(self.write_buf);
                try self.write(self.write_buf[0..bytes]);
                // loop if something is left
                sent_payload += frame_payload.len;
                if (sent_payload >= msg.payload.len) {
                    break;
                }
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
            const bytes_read = try self.stream.read(self.read_buf[self.hwm..]);
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

        fn write(self: *Self, buf: []const u8) !void {
            var bytes_written: usize = 0;
            while (bytes_written < buf.len)
                bytes_written += try self.stream.write(buf);
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

pub const Message = struct {
    encoding: MsgEncoding = .text,
    payload: []const u8,
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

pub const TestStream = struct {
    read_buf: []const u8,
    write_buf: []u8,

    read_pos: usize = 0,
    write_pos: usize = 0,
    chunk: usize = 128,

    const Self = @This();
    var input_buf: []const u8 = undefined;

    pub fn init(host: []const u8, port: u16) !Self {
        _ = port;
        _ = host;

        const allocator = std.testing.allocator;
        return Self{ // text frame, fin, payload 1 byte
            .read_buf = input_buf,
            .write_buf = try allocator.alloc(u8, 1024),
        };
    }

    pub fn read(self: *Self, buf: []u8) !usize {
        var chunk = self.chunk;
        if (buf.len < chunk) chunk = buf.len;
        if (self.read_pos + chunk > self.read_buf.len) chunk = self.read_buf.len - self.read_pos;
        std.mem.copy(u8, buf, self.read_buf[self.read_pos .. self.read_pos + chunk]);
        self.read_pos += chunk;
        return chunk;
    }

    pub fn write(self: *Self, buf: []const u8) !usize {
        std.mem.copy(u8, self.write_buf[self.write_pos..], buf);
        self.write_pos += buf.len;
        return buf.len;
    }

    pub fn close(self: *Self) void {
        const allocator = std.testing.allocator;
        allocator.free(self.write_buf);
    }
};

const testHandshakeResponse = "HTTP/1.1 101 Switching Protocols\r\nUpgrade: WebSocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: 9bQuZIN64KrRsqgxuR1CxYN94zQ=\r\n\r\n";

const TestClient = Client(TestStream);

fn testClientInit() !TestClient {
    const allocator = std.testing.allocator;
    const buf_size = 1024;
    var read_buf = try allocator.alloc(u8, buf_size);
    var write_buf = try allocator.alloc(u8, buf_size);
    return try TestClient.init(read_buf, write_buf, "127.0.0.1", 80, "path");
}

fn testClientDeinit(client: *TestClient) void {
    const allocator = std.testing.allocator;
    client.stream.close();
    allocator.free(client.read_buf);
    allocator.free(client.write_buf);
}

test "client handshake" {
    TestStream.input_buf = testHandshakeResponse;
    var client = try testClientInit();
    testClientDeinit(&client);
}

test "client readFrame" {
    TestStream.input_buf = testHandshakeResponse[0..] ++ [_]u8{ 0x81, 0x1, 0xa };
    var client = try testClientInit();
    defer testClientDeinit(&client);

    var frame = client.readFrame().?;
    try testing.expectEqual(frame.fin, 1);
    try testing.expectEqual(frame.opcode, .text);
    try testing.expectEqual(frame.payload.len, 1);
    try testing.expectEqual(frame.payload[0], 0xa);
}

test "client readMessage" {
    TestStream.input_buf = testHandshakeResponse[0..] ++ [_]u8{ 0x81, 0x1, 0xa };
    var client = try testClientInit();
    defer testClientDeinit(&client);

    var msg = client.readMessage().?;
    try testing.expectEqual(msg.encoding, .text);
    try testing.expectEqual(msg.payload.len, 1);
    try testing.expectEqual(msg.payload[0], 0xa);
}

test "client readMessage fragmented" {
    TestStream.input_buf = testHandshakeResponse[0..] ++
        [_]u8{ 0x01, 0x1, 0xa } ++ // first text frame
        [_]u8{ 0x89, 0x00 } ++ // ping in between
        [_]u8{ 0x80, 0x1, 0xb }; // last frame

    var client = try testClientInit();
    defer testClientDeinit(&client);

    var msg = client.readMessage().?;
    try testing.expectEqual(msg.encoding, .text);
    try testing.expectEqual(msg.payload.len, 2);
    try testing.expectEqualSlices(u8, msg.payload, &[_]u8{ 0xa, 0xb });
    // expect pong message in the write buffer
    try testing.expectEqualSlices(u8, client.write_buf[0..2], &[_]u8{ 0x8a, 0x80 });

    // output buffer contains handsake and pong
    // pong is 2 bytes + 4 bytes mask
    const cs = client.stream;
    try testing.expectEqual(cs.write_pos, 177);
    try testing.expectEqualSlices(u8, cs.write_buf[cs.write_pos - 6 .. cs.write_pos - 4], &[_]u8{ 0x8a, 0x80 });
}

test "client readMessage fragmented in 3 frames" {
    TestStream.input_buf = testHandshakeResponse[0..] ++
        [_]u8{ 0x01, 0x1, 0xa } ++ // first text frame
        [_]u8{ 0x89, 0x00 } ++ // ping in between
        [_]u8{ 0x00, 0x3, 0xb, 0xc, 0xd } ++ // continuation frame
        [_]u8{ 0x8a, 0x00 } ++ // pong
        [_]u8{ 0x80, 0x2, 0xe, 0xf }; // last frame

    var client = try testClientInit();
    defer testClientDeinit(&client);

    var msg = client.readMessage().?;
    try testing.expectEqual(msg.encoding, .text);
    try testing.expectEqual(msg.payload.len, 6);
    try testing.expectEqualSlices(u8, msg.payload, &[_]u8{ 0xa, 0xb, 0xc, 0xd, 0xe, 0xf });
}
