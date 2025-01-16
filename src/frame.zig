const std = @import("std");
const mem = std.mem;
const testing = std.testing;

const assert = std.debug.assert;
const Allocator = mem.Allocator;
const utf8ValidateSlice = std.unicode.utf8ValidateSlice;

var rnd = std.Random.DefaultPrng.init(0);

pub const Error = error{
    ReservedOpcode,
    InvalidCloseCode,
    InvalidUtf8Payload,
    TooBigPayloadForControlFrame,
    FragmentedControlFrame,
    InvalidFragmentation,
    DeflateNotSupported,
    ReservedRsv,
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
                else => return Error.ReservedOpcode,
            };
        }
    };

    pub const max_header = 14; // 1 + 9 + 4 (flags|opcode + mask|payload_len + masking_key)

    fin: u1,
    rsv1: u1 = 0,
    mask: u1,
    opcode: Opcode,
    payload: []const u8,
    allocator: ?Allocator = null,

    const Self = @This();

    const default_close_code = 1000;

    pub fn closeCode(self: Self) u16 {
        if (self.opcode != .close) return 0;
        if (self.payload.len == 1) return 0; //invalid
        if (self.payload.len == 0) return default_close_code;
        return mem.readInt(u16, self.payload[0..2], .big);
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
            else => return Error.InvalidCloseCode,
        };
    }

    pub fn assertValid(self: Self, deflate_supported: bool) !void {
        if (self.isControl()) try self.assertValidControl();
        if (self.opcode == .close) try self.assertValidClose();
        if (self.rsv1 == 1 and !deflate_supported) return Error.DeflateNotSupported;
    }

    fn assertValidClose(self: Self) !void {
        try assertValidUtf8(self.closePayload());
        try self.assertValidCloseCode();
    }

    fn assertValidControl(self: Self) !void {
        if (self.payload.len > 125) return Error.TooBigPayloadForControlFrame;
        if (self.fin == 0) return Error.FragmentedControlFrame;
    }

    pub fn isFin(self: Self) bool {
        return self.fin == 1;
    }

    pub fn isCompressed(self: Self) bool {
        return self.rsv1 == 1;
    }

    pub fn isControl(self: Self) bool {
        return self.opcode.isControl();
    }

    pub fn deinit(self: Self) void {
        if (self.allocator) |a| a.free(self.payload);
    }

    pub const Fragment = enum {
        unfragmented,
        start,
        fragment,
        end,
    };

    pub fn fragment(self: Self) Fragment {
        if (self.fin == 1) {
            if (self.opcode == .continuation) return .end else return .unfragmented;
        } else {
            if (self.opcode == .continuation) return .fragment else return .start;
        }
    }

    fn isValidContinuation(self: Self, prev: Fragment) bool {
        if (self.isControl()) return true;
        const curr = self.fragment();
        return switch (prev) {
            .unfragmented, .end => curr == .unfragmented or curr == .start,
            .start, .fragment => curr == .fragment or curr == .end,
        };
    }

    pub fn assertValidContinuation(self: Self, prev: Fragment) !void {
        if (!self.isValidContinuation(prev)) return Error.InvalidFragmentation;
    }

    pub fn encode(self: Self, buf: []u8, close_code: u16) usize {
        const payload_len: u64 = if (self.opcode == .close) self.payload.len + 2 else self.payload.len;
        const payload_bytes = payloadBytes(payload_len);
        const masked = self.mask == 1;
        const is_close = self.opcode == .close;

        const encoded_len = 1 + payload_bytes +
            @as(usize, (if (self.mask == 1) 4 else 0)) +
            @as(usize, (if (self.opcode == .close) 2 else 0)) +
            payload_len;
        assert(buf.len >= encoded_len);

        buf[0] = (@as(u8, @intCast(self.fin)) << 7) +
            (@as(u8, @intCast(self.rsv1)) << 6) +
            @intFromEnum(self.opcode);

        var offset: usize = 1;

        buf[1] = if (masked) 0x80 else 0;
        if (payload_bytes == 1) {
            buf[1] += @as(u8, @intCast(payload_len));
            offset = 2;
        } else if (payload_bytes == 3) {
            buf[1] += 126;
            std.mem.writeInt(u16, buf[2..4], @as(u16, @intCast(payload_len)), .big);
            offset = 4;
        } else {
            buf[1] += 127;
            std.mem.writeInt(u64, buf[2..10], payload_len, .big);
            offset = 10;
        }

        var masking_key = [_]u8{0} ** 4;
        if (masked) {
            masking_key = maskingKey();
            @memcpy(buf[offset .. offset + 4], &masking_key);
            offset += 4;
        }
        const payload_start = offset;
        var payload_end = payload_start + self.payload.len;
        if (is_close) {
            const cc = if (close_code == 0) default_close_code else close_code;
            std.mem.writeInt(u16, buf[offset .. offset + 2][0..2], cc, .big);
            offset += 2;
            payload_end += 2;
        }
        @memcpy(buf[offset .. offset + self.payload.len], self.payload);
        if (masked)
            maskUnmask(&masking_key, buf[payload_start..payload_end]);

        return payload_end;
    }

    pub fn encodedLen(self: Self) usize {
        const payload_len: u64 = if (self.opcode == .close) self.payload.len + 2 else self.payload.len;
        const payload_bytes = payloadBytes(payload_len);
        return 1 + payload_bytes +
            @as(usize, (if (self.mask == 1) 4 else 0)) +
            @as(usize, (if (self.opcode == .close) 2 else 0)) +
            payload_len;
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

    pub fn maskUnmask(mask: []const u8, buf: []u8) void {
        for (buf, 0..) |c, i|
            buf[i] = c ^ mask[i % 4];
    }

    pub fn assertRsvBits(rsv2: u1, rsv3: u1) !void {
        if (rsv2 == 1 or rsv3 == 1) return Error.ReservedRsv;
    }

    pub fn assertValidUtf8(data: []const u8) !void {
        if (!utf8ValidateSlice(data)) return Error.InvalidUtf8Payload;
    }

    pub fn parse(data: []u8) !struct { Frame, usize } {
        if (data.len < 2) return error.SplitBuffer;

        const fin: u1 = readBit(data[0], 0b1000_0000);
        const rsv1: u1 = readBit(data[0], 0b0100_0000);
        const rsv2: u1 = readBit(data[0], 0b0010_0000);
        const rsv3: u1 = readBit(data[0], 0b0001_0000);
        if (rsv2 == 1 or rsv3 == 1) return Error.ReservedRsv;

        const opcode = try Frame.Opcode.decode(@intCast(data[0] & 0b0000_1111));
        const mask: u1 = readBit(data[1], 0b1000_0000);

        const payload_len, const payload_len_bytes = try readPayloadLen(data[1..]);

        if (opcode.isControl()) {
            if (payload_len > 125) return Error.TooBigPayloadForControlFrame;
            if (fin == 0) return Error.FragmentedControlFrame;
        }

        const mask_start = payload_len_bytes + 1;
        const mask_end: usize = mask_start + @as(usize, if (mask == 1) 4 else 0);
        const payload_start = mask_end;
        const payload_end = payload_start + payload_len;

        if (data.len < payload_end) return error.SplitBuffer;

        const masking_key = data[mask_start..mask_end];
        const payload = data[payload_start..payload_end];
        if (mask == 1) {
            Frame.maskUnmask(masking_key, payload);
        }

        return .{
            .{ .fin = fin, .rsv1 = rsv1, .mask = mask, .opcode = opcode, .payload = payload },
            payload_end,
        };
    }

    fn readPayloadLen(data: []const u8) !struct { u64, usize } {
        if (data.len < 1) return error.SplitBuffer;
        const payload_len: u64 = @intCast(data[0] & 0b0111_1111);
        switch (payload_len) {
            126 => {
                if (data.len < 3) return error.SplitBuffer;
                return .{ @intCast(std.mem.readInt(u16, data[1..3], .big)), 3 };
            },
            127 => {
                if (data.len < 9) return error.SplitBuffer;
                return .{ @intCast(std.mem.readInt(u64, data[1..9], .big)), 9 };
            },
            else => return .{ payload_len, 1 },
        }
    }

    fn readBit(byte: u8, comptime mask: u8) u1 {
        return if (byte & mask == 0) 0 else 1;
    }

    test readBit {
        try testing.expectEqual(0, readBit(0, 0));
        try testing.expectEqual(1, readBit(255, 1));
        try testing.expectEqual(1, readBit(0b1000_0000, 0b1000_0000));
        try testing.expectEqual(0, readBit(0b1000_0000, 0b0100_0000));
    }

    test readPayloadLen {
        {
            const len, const n = try readPayloadLen(&.{125});
            try testing.expectEqual(125, len);
            try testing.expectEqual(1, n);
        }
        {
            const len, const n = try readPayloadLen(&.{ 126, 0xaa, 0xbb });
            try testing.expectEqual(0xaabb, len);
            try testing.expectEqual(3, n);
        }
        {
            const len, const n = try readPayloadLen(&.{ 127, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11 });
            try testing.expectEqual(0xaabbccddeeff0011, len);
            try testing.expectEqual(9, n);
        }
    }
};

test "parse close frame" {
    const frame_data = [_]u8{ 0x88, 0x87, 0xa, 0xb, 0xc, 0xd, 0x09, 0xe2, 0x0d, 0x0f, 0x09, 0x0f, 0x09 };
    var data = frame_data ++ [_]u8{ 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff }; // suffix which is not parsed

    // Parsing partial frame returns SplitBuffer error
    for (0..frame_data.len) |i| {
        try testing.expectError(error.SplitBuffer, Frame.parse(data[0..i]));
    }
    const expected_payload = [_]u8{ 0x3, 0xe9, 0x1, 0x2, 0x3, 0x4, 0x5 };

    const frm, const n = try Frame.parse(&data);
    try testing.expectEqual(frame_data.len, n);
    try testing.expectEqual(frm.opcode, .close);
    try testing.expectEqual(frm.fin, 1);
    try testing.expectEqual(frm.payload.len, 7);
    try testing.expectEqualSlices(u8, &expected_payload, frm.payload);
    try testing.expectEqualSlices(u8, frm.payload, data[6..][0..7]);
}

test {
    _ = Frame;
}
