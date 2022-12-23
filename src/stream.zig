const std = @import("std");
const testing = std.testing;
const assert = std.debug.assert;
const io = std.io;
const Allocator = std.mem.Allocator;

pub const Frame = struct {
    pub const Opcode = enum(u4) {
        continuation = 0,
        text = 1,
        binary = 2,
        close = 8,
        ping = 9,
        pong = 0xa,

        pub fn isControl(o: Opcode) bool {
            return o == .close or o == .ping or o == .pong;
        }

        pub fn decode(first_byte: u8) !Opcode {
            const val = @intCast(u4, first_byte & 0x0f);
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

    fin: u1,
    opcode: Opcode,
    payload: []const u8,
    allocator: Allocator,

    const Self = @This();

    pub fn closeCode(self: Self) u16 {
        if (self.opcode != .close) return 0;
        if (self.payload.len == 1) return 0; //invalid
        if (self.payload.len == 0) return 1000;
        return std.mem.readIntBig(u16, self.payload[0..2]);
    }

    pub fn closePayload(self: Self) []const u8 {
        if (self.payload.len > 2) return self.payload[2..];
        return self.payload[0..0];
    }

    fn assertValidCloseCode(self: Self) !void {
        return switch (self.closeCode()) {
            1000...1003 => {},
            1007...1011 => {},
            3000...3999 => {},
            4000...4999 => {},
            else => return error.InvalidCloseCode,
        };
    }

    fn assertValid(self: Self) !void {
        if (self.opcode == .close) {
            if (!std.unicode.utf8ValidateSlice(self.closePayload())) return error.InvalidUtf8Payload;
            try self.assertValidCloseCode();
        }
    }

    pub fn isFin(self: Self) bool {
        return self.fin == 1;
    }

    pub fn deinit(self: Self) void {
        self.allocator.free(self.payload);
    }
};

pub fn Client(comptime StreamType: type) type {
    return struct {
        stream: StreamType,
        allocator: Allocator,

        const Self = @This();

        pub fn readFrame(self: *Self) !Frame {
            var reader = self.stream.reader();
            var bit_reader = io.bitReader(.Big, reader);

            const fin = try bit_reader.readBitsNoEof(u1, 1);
            const rsv1 = try bit_reader.readBitsNoEof(u1, 1);
            const rsv2 = try bit_reader.readBitsNoEof(u1, 1);
            const rsv3 = try bit_reader.readBitsNoEof(u1, 1);
            // TODO rsv1 can be set is compression is supported
            if (rsv1 != 0 or rsv2 != 0 or rsv3 != 0) return error.WrongRsv;

            const opcode = try Frame.Opcode.decode(try bit_reader.readBitsNoEof(u4, 4));

            const masked = (try bit_reader.readBitsNoEof(u1, 1) == 1);
            var payload_len = try bit_reader.readBitsNoEof(u64, 7);
            payload_len = switch (payload_len) {
                126 => try bit_reader.readBitsNoEof(u64, 8 * 2),
                127 => try bit_reader.readBitsNoEof(u64, 8 * 4),
                else => payload_len,
            };
            if (opcode.isControl()) try assertValidControlFrame(payload_len, fin);

            var mask = [_]u8{0} ** 4;
            if (masked) try reader.readNoEof(&mask);
            var payload = try self.allocator.alloc(u8, payload_len);
            try reader.readNoEof(payload);
            if (masked) maskUnmask(&mask, payload);

            const frame = Frame{
                .fin = fin,
                .opcode = opcode,
                .payload = payload,
                .allocator = self.allocator,
            };
            try frame.assertValid();
            return frame;
        }

        fn assertValidControlFrame(payload_len: u64, fin: u1) !void {
            if (payload_len > 125) return error.TooBigPayloadForControlFrame;
            if (fin == 0) return error.FragmentedControlFrame;
        }
    };
}

fn maskUnmask(mask: []const u8, buf: []u8) void {
    for (buf) |c, i|
        buf[i] = c ^ mask[i % 4];
}

pub fn client(underlying_stream: anytype, allocator: Allocator) Client(@TypeOf(underlying_stream)) {
    return .{
        .stream = underlying_stream,
        .allocator = allocator,
    };
}

test "close frame" {
    var input = [_]u8{ 0x88, 0x02, 0x03, 0xe8 };
    var cli = client(io.fixedBufferStream(&input), testing.allocator);
    const frame = try cli.readFrame();
    defer frame.deinit();

    try testing.expectEqual(frame.opcode, .close);
    try testing.expectEqual(frame.fin, 1);
    try testing.expectEqual(frame.payload.len, 2);
    try testing.expectEqualSlices(u8, frame.payload, input[2..4]);
    try testing.expectEqual(frame.closeCode(), 1000);
    try testing.expectError(error.EndOfStream, cli.readFrame());
}

test "masked close frame with payload" {
    var input = [_]u8{ 0x88, 0x87, 0xa, 0xb, 0xc, 0xd, 0x09, 0xe2, 0x0d, 0x0f, 0x09, 0x0f, 0x09 };
    var cli = client(io.fixedBufferStream(&input), testing.allocator);
    const frame = try cli.readFrame();
    defer frame.deinit();

    const expected_payload = [_]u8{ 0x3, 0xe9, 0x1, 0x2, 0x3, 0x4, 0x5 };

    try testing.expectEqual(frame.opcode, .close);
    try testing.expectEqual(frame.fin, 1);
    try testing.expectEqual(frame.payload.len, 7);
    try testing.expectEqualSlices(u8, frame.payload, &expected_payload);
    try testing.expectEqual(frame.closeCode(), 1001);
    try testing.expectError(error.EndOfStream, cli.readFrame());
}

test "bit stratch" {
    var buf = [_]u8{ 0x3, 0xe9, 0x1, 0x2, 0x3, 0x4, 0x5 };
    maskUnmask(&[_]u8{ 0xa, 0xb, 0xc, 0xd }, &buf);
    showBuf(&buf);
}

// debug helper
fn showBuf(buf: []const u8) void {
    std.debug.print("\n", .{});
    for (buf) |b|
        std.debug.print("0x{x:0>2}, ", .{b});
}
