const std = @import("std");
const io = std.io;
const mem = std.mem;

const assert = std.debug.assert;
const Allocator = mem.Allocator;
const utf8ValidateSlice = std.unicode.utf8ValidateSlice;

var rnd = std.rand.DefaultPrng.init(0);

pub const Message = struct {
    pub const Encoding = enum {
        text,
        binary,
    };

    encoding: Encoding = .text,
    payload: []const u8,
    allocator: ?Allocator = null,

    const Self = @This();

    pub fn deinit(self: *Self) void {
        if (self.allocator) |a| a.free(self.payload);
    }
};

pub const Frame = struct {
    pub const Opcode = enum(u4) {
        continuation = 0,
        text = 1,
        binary = 2,
        close = 8,
        ping = 9,
        pong = 0xa,

        pub fn isControl(self: Opcode) bool {
            return self == .close or self == .ping or self == .pong;
        }

        pub fn decode(val: u4) !Opcode {
            return switch (val) {
                0 => .continuation,
                1 => .text,
                2 => .binary,
                8 => .close,
                9 => .ping,
                0xa => .pong,
                else => return error.ReservedOpcode,
            };
        }
    };

    pub const max_header = 14; // 1 + 9 + 4 (flags|opcode + mask|payload_len + masking_key)
    const empty_payload = &[_]u8{};

    fin: u1,
    mask: u1,
    opcode: Opcode,
    payload: []const u8,
    allocator: ?Allocator = null,

    const Self = @This();

    const default_close_code = 1000;

    pub fn closeCode(self: *Self) u16 {
        if (self.opcode != .close) return 0;
        if (self.payload.len == 1) return 0; //invalid
        if (self.payload.len == 0) return default_close_code;
        return mem.readIntBig(u16, self.payload[0..2]);
    }

    pub fn closePayload(self: *Self) []const u8 {
        if (self.payload.len > 2) return self.payload[2..];
        return self.payload[0..0];
    }

    fn assertValidCloseCode(self: *Self) !void {
        return switch (self.closeCode()) {
            1000...1003 => {},
            1007...1011 => {},
            3000...3999 => {},
            4000...4999 => {},
            else => return error.InvalidCloseCode,
        };
    }

    pub fn assertValid(self: *Self) !void {
        if (self.isControl()) try self.assertValidControl();
        if (self.opcode == .close) try self.assertValidClose();
    }

    fn assertValidClose(self: *Self) !void {
        if (!utf8ValidateSlice(self.closePayload())) return error.InvalidUtf8Payload;
        try self.assertValidCloseCode();
    }

    fn assertValidControl(self: *Self) !void {
        if (self.payload.len > 125) return error.TooBigPayloadForControlFrame;
        if (self.fin == 0) return error.FragmentedControlFrame;
    }

    pub fn isFin(self: *Self) bool {
        return self.fin == 1;
    }

    pub fn isControl(self: *Self) bool {
        return self.opcode.isControl();
    }

    pub fn deinit(self: *Self) void {
        if (self.allocator) |a| a.free(self.payload);
    }

    pub const Fragment = enum {
        unfragmented,
        start,
        fragment,
        end,
    };

    pub fn fragment(self: *Self) Fragment {
        if (self.fin == 1) {
            if (self.opcode == .continuation) return .end else return .unfragmented;
        } else {
            if (self.opcode == .continuation) return .fragment else return .start;
        }
    }

    fn isValidContinuation(self: *Self, prev: Fragment) bool {
        if (self.isControl()) return true;
        const curr = self.fragment();
        return switch (prev) {
            .unfragmented, .end => curr == .unfragmented or curr == .start,
            .start, .fragment => curr == .fragment or curr == .end,
        };
    }

    fn assertValidContinuation(self: *Self, prev: Fragment) !void {
        if (!self.isValidContinuation(prev)) return error.InvalidFragmentation;
    }

    pub fn encode(self: Self, buf: []u8, close_code: u16) usize {
        const payload_len: u64 = if (self.opcode == .close) self.payload.len + 2 else self.payload.len;
        const payload_bytes = payloadBytes(payload_len);
        const masked = self.mask == 1;
        const is_close = self.opcode == .close;

        const required_buf_len: usize = 1 + payload_bytes +
            if (masked) 4 else 0 +
            if (is_close) 2 else 0 +
            payload_len;
        assert(buf.len >= required_buf_len);

        buf[0] = (@intCast(u8, self.fin) << 7) +
            //(@intCast(u8, self.rsv1) << 6) +
            //(@intCast(u8, self.rsv2) << 5) +
            //(@intCast(u8, self.rsv3) << 4) +
            @enumToInt(self.opcode);

        var offset: usize = 1;

        buf[1] = if (masked) 0x80 else 0;
        if (payload_bytes == 1) {
            buf[1] += @intCast(u8, payload_len);
            offset = 2;
        } else if (payload_bytes == 3) {
            buf[1] += 126;
            std.mem.writeInt(u16, buf[2..4], @intCast(u16, payload_len), .Big);
            offset = 4;
        } else {
            buf[1] += 127;
            std.mem.writeInt(u64, buf[2..10], payload_len, .Big);
            offset = 10;
        }

        var masking_key = [_]u8{0} ** 4;
        if (masked) {
            masking_key = maskingKey();
            std.mem.copy(u8, buf[offset .. offset + 4], &masking_key);
            offset += 4;
        }
        const payload_start = offset;
        var payload_end = payload_start + self.payload.len;
        if (is_close) {
            const cc = if (close_code == 0) default_close_code else close_code;
            std.mem.writeIntSliceBig(u16, buf[offset .. offset + 2], cc);
            offset += 2;
            payload_end += 2;
        }
        std.mem.copy(u8, buf[offset..], self.payload);
        if (masked)
            maskUnmask(&masking_key, buf[payload_start..payload_end]);

        return payload_end;
    }

    fn maskingKey() [4]u8 {
        var masking_key: [4]u8 = undefined;
        rnd.random().bytes(&masking_key);
        return masking_key;
    }

    fn payloadBytes(len: u64) u8 {
        if (len < 126) return 1;
        if (len < 65536) return 3;
        return 9;
    }

    fn maskUnmask(mask: []const u8, buf: []u8) void {
        for (buf) |c, i|
            buf[i] = c ^ mask[i % 4];
    }
};

pub fn Stream(comptime ReaderType: type, comptime WriterType: type) type {
    return struct {
        reader: Reader(ReaderType),
        writer: Writer(WriterType),

        allocator: Allocator,
        err: ?anyerror = null,

        last_frame_fragment: Frame.Fragment = .unfragmented,

        const Self = @This();

        fn readDataFrame(self: *Self) !Frame {
            while (true) {
                var frame = try self.reader.frame();
                if (frame.isControl()) {
                    defer frame.deinit();
                    try self.handleControlFrame(&frame);
                } else {
                    try frame.assertValidContinuation(self.last_frame_fragment);
                    self.last_frame_fragment = frame.fragment();
                    return frame;
                }
            }
        }

        fn handleControlFrame(self: *Self, frame: *Frame) !void {
            switch (frame.opcode) {
                .ping => try self.writer.pong(frame.payload),
                .close => {
                    try self.writer.close(frame.closeCode(), frame.closePayload());
                    return error.EndOfStream;
                },
                .pong => {},
                else => unreachable,
            }
        }

        fn setErr(self: *Self, err: anyerror) void {
            if (err != error.EndOfStream) self.err = err;
        }

        pub fn nextMessage(self: *Self) ?Message {
            return self.readMessage() catch |err| {
                self.setErr(err);
                return null;
            };
        }

        fn readMessage(self: *Self) !Message {
            var frame = try self.readDataFrame();
            const encoding: Message.Encoding = if (frame.opcode == .binary) .binary else .text;
            if (frame.isFin()) return self.initMessage(encoding, frame.payload); // if single frame return frame payload as message payload

            // collect frames payloads
            var payload = try std.ArrayList(u8).initCapacity(self.allocator, frame.payload.len);
            try payload.appendSlice(frame.payload);
            frame.deinit();
            defer payload.deinit();

            while (true) {
                var next = try self.readDataFrame();
                defer next.deinit();
                try payload.appendSlice(next.payload);
                if (next.isFin()) return self.initMessage(encoding, try payload.toOwnedSlice());
            }
        }

        pub fn sendMessage(self: *Self, msg: Message) !void {
            try self.writer.message(msg);
        }

        fn initMessage(self: *Self, encoding: Message.Encoding, payload: []const u8) !Message {
            if (encoding == .text)
                if (!utf8ValidateSlice(payload)) return error.InvalidUtf8Payload;

            return Message{ .encoding = encoding, .payload = payload, .allocator = self.allocator };
        }

        pub fn deinit(self: *Self) void {
            self.writer.deinit();
        }
    };
}

pub fn Reader(comptime ReaderType: type) type {
    const BitReader = io.BitReader(.Big, ReaderType);
    return struct {
        bit_reader: BitReader,
        allocator: Allocator,

        const Self = @This();

        pub fn init(inner_reader: ReaderType, allocator: Allocator) Self {
            return .{
                .bit_reader = io.bitReader(.Big, inner_reader),
                .allocator = allocator,
            };
        }

        // TODO does all this inlines make sense
        inline fn readBit(self: *Self) !u1 {
            return try self.bit_reader.readBitsNoEof(u1, 1);
        }
        inline fn readOpcode(self: *Self) !Frame.Opcode {
            return try Frame.Opcode.decode(try self.bit_reader.readBitsNoEof(u4, 4));
        }
        inline fn readPayloadLen(self: *Self) !u64 {
            var payload_len = try self.bit_reader.readBitsNoEof(u64, 7);
            return switch (payload_len) {
                126 => try self.bit_reader.readBitsNoEof(u64, 8 * 2),
                127 => try self.bit_reader.readBitsNoEof(u64, 8 * 8),
                else => payload_len,
            };
        }
        inline fn readAll(self: *Self, buffer: []u8) !void {
            var index: usize = 0;
            while (index != buffer.len) {
                const amt = try self.bit_reader.read(buffer[index..]);
                if (amt == 0) return error.EndOfStream;
                index += amt;
            }
        }
        inline fn readPayload(self: *Self, payload_len: u64, masked: bool) ![]u8 {
            if (payload_len == 0) return Frame.empty_payload;
            var masking_key = [_]u8{0} ** 4;
            if (masked) try self.readAll(&masking_key);
            var payload = try self.allocator.alloc(u8, payload_len);
            try self.readAll(payload);
            if (masked) Frame.maskUnmask(&masking_key, payload);
            return payload;
        }

        pub fn frame(self: *Self) !Frame {
            const fin = try self.readBit();
            const rsv1 = try self.readBit();
            const rsv2 = try self.readBit();
            const rsv3 = try self.readBit();
            // TODO rsv1 can be set is compression is supported
            if (rsv1 != 0 or rsv2 != 0 or rsv3 != 0) return error.WrongRsv;

            const opcode = try self.readOpcode();
            const mask = try self.readBit();
            const payload_len = try self.readPayloadLen();
            var payload = try self.readPayload(payload_len, mask == 1);

            var frm = Frame{
                .fin = fin,
                .mask = mask,
                .opcode = opcode,
                .payload = payload,
                .allocator = if (payload.len > 0) self.allocator else null,
            };
            try frm.assertValid();
            return frm;
        }
    };
}

pub fn Writer(comptime WriterType: type) type {
    return struct {
        writer: WriterType,
        buf: []u8,
        allocator: Allocator,

        const Self = @This();

        const writer_buffer_len = 4096;

        pub fn init(inner_writer: WriterType, allocator: Allocator) !Self {
            return .{
                .writer = inner_writer,
                .allocator = allocator,
                .buf = try allocator.alloc(u8, writer_buffer_len),
            };
        }

        pub fn pong(self: *Self, payload: []const u8) !void {
            assert(payload.len < 126);
            const frame = Frame{ .fin = 1, .opcode = .pong, .payload = payload, .mask = 1 };
            const bytes = frame.encode(self.buf, 0);
            try self.writer.writeAll(self.buf[0..bytes]);
        }

        pub fn close(self: *Self, code: u16, payload: []const u8) !void {
            assert(payload.len < 124);
            const frame = Frame{ .fin = 1, .opcode = .close, .payload = payload, .mask = 1 };
            const bytes = frame.encode(self.buf, code);
            try self.writer.writeAll(self.buf[0..bytes]);
        }

        pub fn message(self: *Self, msg: Message) !void {
            var sent_payload: usize = 0;
            // send multiple frames if needed
            while (true) {
                var fin: u1 = 1;
                // use frame payload that fits into write_buf
                var frame_payload = msg.payload[sent_payload..];
                if (frame_payload.len + Frame.max_header > self.buf.len) {
                    frame_payload = frame_payload[0 .. self.buf.len - Frame.max_header];
                    fin = 0;
                }
                const opcode = if (sent_payload == 0) // set opcode for the first frame
                    if (msg.encoding == .text) Frame.Opcode.text else Frame.Opcode.binary
                else
                    Frame.Opcode.continuation; // for all other frames

                // create frame
                const frame = Frame{ .fin = fin, .opcode = opcode, .payload = frame_payload, .mask = 1 };
                // encode frame into write_buf and send it to stream
                const bytes = frame.encode(self.buf, 0);
                try self.writer.writeAll(self.buf[0..bytes]);
                // loop if something is left
                sent_payload += frame_payload.len;
                if (sent_payload >= msg.payload.len) {
                    break;
                }
            }
        }

        pub fn text(self: *Self, payload: []const u8) !void {
            try self.message(Message{ .encoding = .text, .payload = payload });
        }

        pub fn binary(self: *Self, payload: []const u8) !void {
            try self.message(Message{ .encoding = .binary, .payload = payload });
        }

        pub fn deinit(self: *Self) void {
            self.allocator.free(self.buf);
        }
    };
}

fn reader(inner_reader: anytype, allocator: Allocator) Reader(@TypeOf(inner_reader)) {
    return Reader(@TypeOf(inner_reader)).init(inner_reader, allocator);
}

fn writer(inner_writer: anytype, allocator: Allocator) !Writer(@TypeOf(inner_writer)) {
    return try Writer(@TypeOf(inner_writer)).init(inner_writer, allocator);
}

pub fn stream(inner_reader: anytype, inner_writer: anytype, allocator: Allocator) !Stream(@TypeOf(inner_reader), @TypeOf(inner_writer)) {
    return .{
        .allocator = allocator,
        .reader = reader(inner_reader, allocator),
        .writer = try writer(inner_writer, allocator),
    };
}

const testing = std.testing;
const expectEqual = testing.expectEqual;
const expectEqualSlices = testing.expectEqualSlices;
const expectError = testing.expectError;

test "reader read close frame" {
    var input = [_]u8{ 0x88, 0x02, 0x03, 0xe8 };
    var inner_stm = io.fixedBufferStream(&input);
    var rdr = reader(inner_stm.reader(), testing.allocator);
    var frame = try rdr.frame();
    defer frame.deinit();

    try expectEqual(frame.opcode, .close);
    try expectEqual(frame.fin, 1);
    try expectEqual(frame.payload.len, 2);
    try expectEqualSlices(u8, frame.payload, input[2..4]);
    try expectEqual(frame.closeCode(), 1000);
    try expectError(error.EndOfStream, rdr.frame());
}

test "reader read masked close frame with payload" {
    var input = [_]u8{ 0x88, 0x87, 0xa, 0xb, 0xc, 0xd, 0x09, 0xe2, 0x0d, 0x0f, 0x09, 0x0f, 0x09 };
    var inner_stm = io.fixedBufferStream(&input);
    var rdr = reader(inner_stm.reader(), testing.allocator);
    var frame = try rdr.frame();
    defer frame.deinit();

    const expected_payload = [_]u8{ 0x3, 0xe9, 0x1, 0x2, 0x3, 0x4, 0x5 };

    try expectEqual(frame.opcode, .close);
    try expectEqual(frame.fin, 1);
    try expectEqual(frame.payload.len, 7);
    try expectEqualSlices(u8, frame.payload, &expected_payload);
    try expectEqual(frame.closeCode(), 1001);
    try expectError(error.EndOfStream, rdr.frame());
}

test "read fragmented message" {
    var output: [128]u8 = undefined;
    var reader_stm = io.fixedBufferStream(&fixture_fragmented_message);
    var writer_stm = io.fixedBufferStream(&output);
    var stm = try stream(reader_stm.reader(), writer_stm.writer(), testing.allocator);
    defer stm.deinit();

    var msg = try stm.readMessage();
    defer msg.deinit();

    try testing.expectEqual(msg.encoding, .text);
    try testing.expectEqual(msg.payload.len, 6);
    try testing.expectEqualSlices(u8, msg.payload, &[_]u8{ 0xa, 0xb, 0xc, 0xd, 0xe, 0xf });

    // expect pong in the output
    try expectEqual(writer_stm.pos, 6); // pong header (2 bytes) + mask (4 bytes)
    try testing.expectEqualSlices(u8, output[0..2], &[_]u8{ 0x8a, 0x80 });
}

const fixture_fragmented_message =
    [_]u8{ 0x01, 0x1, 0xa } ++ // first text frame
    [_]u8{ 0x89, 0x00 } ++ // ping in between
    [_]u8{ 0x00, 0x3, 0xb, 0xc, 0xd } ++ // continuation frame
    [_]u8{ 0x8a, 0x00 } ++ // pong
    [_]u8{ 0x80, 0x2, 0xe, 0xf };

test "reader read frames" {
    var fbs = io.fixedBufferStream(&fixture_fragmented_message);
    var rdr = reader(fbs.reader(), testing.allocator);

    const frames = [_]struct { Frame.Opcode, u1, usize }{
        // opcode, fin, payload_len
        .{ .text, 0, 1 },
        .{ .ping, 1, 0 },
        .{ .continuation, 0, 3 },
        .{ .pong, 1, 0 },
        .{ .continuation, 1, 2 },
    };

    for (frames) |expected| {
        var actual = try rdr.frame();
        defer actual.deinit();
        try testing.expectEqual(actual.opcode, expected[0]);
        try testing.expectEqual(actual.fin, expected[1]);
        try testing.expectEqual(actual.payload.len, expected[2]);
    }
    try expectError(error.EndOfStream, rdr.frame());
}

test "stream read frames" {
    var output: [128]u8 = undefined;
    var reader_stm = io.fixedBufferStream(&fixture_fragmented_message);
    var writer_stm = io.fixedBufferStream(&output);
    var stm = try stream(reader_stm.reader(), writer_stm.writer(), testing.allocator);
    defer stm.deinit();

    const frames = [_]struct { Frame.Opcode, u1, usize }{
        // opcode, fin, payload_len
        .{ .text, 0, 1 },
        .{ .ping, 1, 0 },
        .{ .continuation, 0, 3 },
        .{ .pong, 1, 0 },
        .{ .continuation, 1, 2 },
    };

    var rdr = stm.reader;
    for (frames) |expected| {
        var actual = try rdr.frame();
        defer actual.deinit();
        try testing.expectEqual(actual.opcode, expected[0]);
        try testing.expectEqual(actual.fin, expected[1]);
        try testing.expectEqual(actual.payload.len, expected[2]);
    }
    try expectError(error.EndOfStream, rdr.frame());
}

test "writer pong with payload" {
    var output: [128]u8 = undefined;
    var writer_stm = io.fixedBufferStream(&output);
    var w = try writer(writer_stm.writer(), testing.allocator);
    defer w.deinit();
    const payload = "hello";
    try w.pong(payload);

    try expectEqual(writer_stm.pos, 11); // pong header (2 bytes) + mask (4 bytes) + payload (5 bytes)
    try testing.expectEqualSlices(u8, output[0..2], &[_]u8{ 0x8a, 0x85 });
    Frame.maskUnmask(output[2..6], output[6 .. 6 + payload.len]);
    try testing.expectEqualSlices(u8, output[6 .. 6 + payload.len], payload);
}

test "writer close with payload" {
    var output: [128]u8 = undefined;
    var writer_stm = io.fixedBufferStream(&output);
    var w = try writer(writer_stm.writer(), testing.allocator);
    defer w.deinit();
    const payload = "hello";
    try w.close(1002, payload);

    try expectEqual(writer_stm.pos, 13); // pong header (2 bytes) + mask (4 bytes) + code (2 bytes) + payload (5 bytes)
    try testing.expectEqualSlices(u8, output[0..2], &[_]u8{ 0x88, 0x87 });
    Frame.maskUnmask(output[2..6], output[6 .. 8 + payload.len]);
    try testing.expectEqualSlices(u8, output[8 .. 8 + payload.len], payload);
}

test "writer message" {
    var output: [128]u8 = undefined;
    var writer_stm = io.fixedBufferStream(&output);
    var w = try writer(writer_stm.writer(), testing.allocator);
    defer w.deinit();
    const payload = "hello world";
    try w.text(payload);

    try expectEqual(writer_stm.pos, 17); // pong header (2 bytes) + mask (4 bytes) +  payload (11 bytes)
    try testing.expectEqualSlices(u8, output[0..2], &[_]u8{ 0x81, 0x8B });
    Frame.maskUnmask(output[2..6], output[6 .. 6 + payload.len]);
    try testing.expectEqualSlices(u8, output[6 .. 6 + payload.len], payload);
}

// debug helper
fn showBuf(buf: []const u8) void {
    std.debug.print("\n", .{});
    for (buf) |b|
        std.debug.print("0x{x:0>2}, ", .{b});
    std.debug.print("\n", .{});
}
