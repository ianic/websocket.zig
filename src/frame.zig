const std = @import("std");
const testing = std.testing;

var rnd = std.rand.DefaultPrng.init(0);

const U1_1: u1 = 1;
const U1_0: u1 = 0;

pub const Frame = struct {
    fin: u1,
    rsv1: u1,
    rsv2: u1,
    rsv3: u1,
    opcode: Opcode,
    mask: u1 = 0,
    masking_key: [4]u8 = [_]u8{ 0, 0, 0, 0 },
    payload: []u8,
    frame_len: u64,

    const Opcode = enum(u4) {
        continuation = 0,
        text = 1,
        binary = 2,
        close = 8,
        ping = 9,
        pong = 0xa,

        pub fn isControl(o: Opcode) bool {
            return o == .close or o == .ping or o == .pong;
        }
    };

    const Self = @This();
    const invalidFrame = Self{ .fin = 0, .rsv1 = 0, .rsv2 = 0, .rsv3 = 0, .opcode = .close, .mask = 0, .payload = &[0]u8{}, .frame_len = 0 };

    const DecodeResult = struct {
        required_bytes: usize = 0,
        bytes: usize = 0,
        frame: ?Frame = null,

        pub fn isValid(self: DecodeResult) bool {
            return self.required_bytes == 0;
        }
    };

    pub fn decode(buf: []u8) !DecodeResult {
        if (buf.len < 2) {
            return .{ .required_bytes = 2 };
        }
        const pl_rsp = try decodePayloadLen(buf[1..]);
        if (pl_rsp.required_bytes > 0) {
            return .{ .required_bytes = pl_rsp.required_bytes };
        }

        const payload_bytes = pl_rsp.bytes;
        const payload_len = pl_rsp.value;
        const masked = buf[1] & 0x80 == 0x80;

        const mask_start: usize = 1 + payload_bytes;
        const payload_start: usize = mask_start + if (masked) @intCast(usize, 4) else @intCast(usize, 0);
        const frame_len: usize = payload_start + payload_len;
        if (buf.len < frame_len) {
            return .{ .required_bytes = frame_len };
        }

        const fin = if (buf[0] & 0x80 == 0x80) U1_1 else U1_0;
        const rsv1 = if (buf[0] & 0x40 == 0x40) U1_1 else U1_0;
        const rsv2 = if (buf[0] & 0x20 == 0x20) U1_1 else U1_0;
        const rsv3 = if (buf[0] & 0x10 == 0x10) U1_1 else U1_0;
        if (rsv1 != 0 or rsv2 != 0 or rsv3 != 0)
            return error.WrongRsv;

        const opcode = try getOpcode(@intCast(u4, buf[0] & 0x0f));
        if (opcode.isControl()) {
            if (payload_bytes != 1)
                return error.WrongPayloadForControlOpcode;
            if (fin == 0)
                return error.FragmentedControlFrame;
        }
        const payload = buf[payload_start..frame_len];

        var f = Frame{
            // TODO
            .fin = fin,
            .rsv1 = rsv1,
            .rsv2 = rsv2,
            .rsv3 = rsv3,
            .opcode = opcode,
            .mask = if (masked) U1_1 else U1_0,
            .payload = payload,
            .frame_len = frame_len,
        };
        if (masked) {
            f.masking_key[0] = buf[mask_start];
            f.masking_key[1] = buf[mask_start + 1];
            f.masking_key[2] = buf[mask_start + 2];
            f.masking_key[3] = buf[mask_start + 3];
            f.unmaskPayload();
        }
        if (opcode == .text)
            try f.assertValidUtf8Payload();

        return .{ .bytes = frame_len, .frame = f };
    }

    fn getOpcode(opcode: u4) !Opcode {
        return switch (opcode) {
            0 => .continuation,
            1 => .text,
            2 => .binary,
            8 => .close,
            9 => .ping,
            0xa => .pong,
            else => return error.WrongOpcode,
        };
    }

    fn maskPayload(self: *Self) void {
        maskUnmask(&self.masking_key, self.payload);
    }
    fn unmaskPayload(self: *Self) void {
        maskUnmask(&self.masking_key, self.payload);
    }

    pub fn echo(self: Self) Frame {
        var f = Frame{
            .fin = self.fin,
            .rsv1 = self.rsv1,
            .rsv2 = self.rsv2,
            .rsv3 = self.rsv3,
            .opcode = self.opcode,
            .payload = self.payload,
            .frame_len = self.frame_len,
        };
        if (f.opcode == .ping) {
            f.opcode = .pong;
        }
        if (f.opcode == .close and !self.isValidCloseCode() and self.payload.len >= 2) {
            // set close code to 1002 (protocol error) when received invalid close code
            f.payload[0] = 0x3;
            f.payload[1] = 0xea;
        }
        //if (f.opcode != .ping and f.opcode != .pong)
        f.setMaskingKey();
        return f;
    }

    const EncodeResult = union(enum) {
        required_bytes: usize,
        bytes: usize,
    };

    pub fn encode(self: *Self, buf: []u8) EncodeResult {
        const payload_len: u64 = self.payload.len;
        const payload_bytes = payloadBytes(payload_len);

        const buf_len: usize = 1 + payload_bytes + payload_len;
        if (buf.len < buf_len) {
            return .{ .required_bytes = buf_len };
        }

        buf[0] = (@intCast(u8, self.fin) << 7) +
            (@intCast(u8, self.rsv1) << 6) +
            (@intCast(u8, self.rsv2) << 5) +
            (@intCast(u8, self.rsv1) << 4) +
            @enumToInt(self.opcode);

        var offset: usize = 1;

        buf[1] = (@intCast(u8, self.mask) << 7);
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

        if (self.mask == 1) {
            std.mem.copy(u8, buf[offset .. offset + 4], &self.masking_key);
            offset += 4;
        }

        std.mem.copy(u8, buf[offset..], self.payload);
        maskUnmask(&self.masking_key, buf[offset .. offset + self.payload.len]);

        return .{ .bytes = self.payload.len + offset };
    }

    fn setMaskingKey(self: *Self) void {
        self.mask = 1;
        rnd.random().bytes(&self.masking_key);
    }

    pub fn fragmentation(self: Self) Fragment {
        if (self.fin == 1) {
            if (self.opcode == .continuation) return .end else return .unfragmented;
        } else {
            if (self.opcode == .continuation) return .fragment else return .start;
        }
    }

    pub const Fragment = enum {
        unfragmented,
        start,
        fragment,
        end,
    };

    pub fn isControl(self: Self) bool {
        return self.opcode.isControl();
    }

    pub fn isData(self: Self) bool {
        return !self.isControl();
    }

    pub fn isValidContinuation(self: Self, prev: Fragment) bool {
        if (self.isControl()) return true;
        const curr = self.fragmentation();
        return switch (prev) {
            .unfragmented, .end => curr == .unfragmented or curr == .start,
            .start, .fragment => curr == .fragment or curr == .end,
        };
    }

    pub fn closeCode(self: Self) u16 {
        if (self.opcode != .close) return 0;
        if (self.payload.len < 2) return 1000;
        return std.mem.readIntBig(u16, self.payload[0..2]);
    }

    pub fn isValidCloseCode(self: Self) bool {
        return switch (self.closeCode()) {
            1000...1003 => true,
            1007...1011 => true,
            3000...3999 => true,
            4000...4999 => true,
            else => false,
        };
    }

    fn assertValidUtf8Payload(self: Self) !void {
        if (self.payload.len == 0) return;
        var utf8Payload = self.payload;
        if (self.opcode == .close) {
            if (self.payload.len <= 2) return;
            utf8Payload = self.payload[2..];
        }
        if (!std.unicode.utf8ValidateSlice(utf8Payload)) return error.InvalidUtf8Payload;
    }
};

fn payloadBytes(len: u64) u8 {
    if (len < 126) {
        return 1;
    }
    if (len < 65536) {
        return 3;
    }
    return 9;
}

const DecodePayloadLenResult = struct {
    required_bytes: u8 = 0,
    bytes: u8 = 0,
    value: u64 = 0,
};

fn decodePayloadLen(buf: []const u8) !DecodePayloadLenResult {
    if (buf.len < 1) return .{ .required_bytes = 1 };

    var pl: u64 = buf[0] & 0x7f;
    if (pl <= 125) {
        return .{ .bytes = 1, .value = pl };
    }
    if (pl == 126) {
        if (buf.len < 3) return .{ .required_bytes = 3 };
        pl = (@intCast(u64, buf[1]) << 8) + buf[2];
        return .{ .bytes = 3, .value = pl };
    }
    if (buf.len < 9) return .{ .required_bytes = 9 };
    if (buf[1] & 0x80 == 0x80) {
        return error.WrongPayloadLen;
    }
    // TODO: there must be std fn for this
    pl = (@intCast(u64, buf[1]) << 56) +
        (@intCast(u64, buf[2]) << 48) +
        (@intCast(u64, buf[3]) << 40) +
        (@intCast(u64, buf[4]) << 32) +
        (@intCast(u64, buf[5]) << 24) +
        (@intCast(u64, buf[6]) << 16) +
        (@intCast(u64, buf[7]) << 8) +
        buf[8];
    return .{ .bytes = 9, .value = pl };
}

test "decodePayloadLen" {
    // 1 byte
    try testing.expectEqual(try decodePayloadLen(&[_]u8{0x00}), .{ .bytes = 1, .value = 0 });
    try testing.expectEqual(try decodePayloadLen(&[_]u8{0x0a}), .{ .bytes = 1, .value = 0xa });
    try testing.expectEqual(try decodePayloadLen(&[_]u8{0x7d}), .{ .bytes = 1, .value = 0x7d });
    // 2 bytes
    try testing.expectEqual(try decodePayloadLen(&[_]u8{ 0x7e, 0x00, 0x01 }), .{ .bytes = 3, .value = 0x01 });
    try testing.expectEqual(try decodePayloadLen(&[_]u8{ 0x7e, 0x00, 0xaa }), .{ .bytes = 3, .value = 0xaa });
    try testing.expectEqual(try decodePayloadLen(&[_]u8{ 0x7e, 0x00, 0xff }), .{ .bytes = 3, .value = 0xff });
    try testing.expectEqual(try decodePayloadLen(&[_]u8{ 0x7e, 0x01, 0xff }), .{ .bytes = 3, .value = 0x01ff });
    try testing.expectEqual(try decodePayloadLen(&[_]u8{ 0x7e, 0x12, 0x34 }), .{ .bytes = 3, .value = 0x1234 });
    // 8 bytes
    try testing.expectEqual(try decodePayloadLen(&[_]u8{ 0x7f, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1 }), .{ .bytes = 9, .value = 0x1 });
    try testing.expectEqual(try decodePayloadLen(&[_]u8{ 0x7f, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8 }), .{ .bytes = 9, .value = 0x0102030405060708 });

    // insufficent buffer
    try testing.expectEqual(try decodePayloadLen(&[_]u8{}), .{ .required_bytes = 1 });
    try testing.expectEqual(try decodePayloadLen(&[_]u8{0x7e}), .{ .required_bytes = 3 });
    try testing.expectEqual(try decodePayloadLen(&[_]u8{0x7f}), .{ .required_bytes = 9 });

    // error
    try testing.expectError(error.WrongPayloadLen, decodePayloadLen(&[_]u8{ 0x7f, 0x80, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8 }));
}

test "decode" {
    var hello = [_]u8{ 0x81, 0x05, 0x48, 0x65, 0x6c, 0x6c, 0x6f };
    var rsp = try Frame.decode(&hello);
    try testing.expectEqual(rsp.bytes, 7);
    const f = rsp.frame.?;
    try testing.expectEqual(f.frame_len, 7);
    try testing.expectEqual(f.fin, 1);
    try testing.expectEqual(f.rsv1, 0);
    try testing.expectEqual(f.rsv2, 0);
    try testing.expectEqual(f.rsv3, 0);
    try testing.expectEqual(f.opcode, .text);
    try testing.expectEqual(f.mask, 0);
    try testing.expectEqual(f.payload.len, 5);
    try testing.expectEqualStrings(f.payload, "Hello");
}

test "decode masked" {
    var hello = [_]u8{ 0x81, 0x85, 0x37, 0xfa, 0x21, 0x3d, 0x7f, 0x9f, 0x4d, 0x51, 0x58 };
    var rsp = try Frame.decode(&hello);
    try testing.expectEqual(rsp.bytes, 11);
    var f = rsp.frame.?;
    try testing.expectEqual(f.frame_len, 11);
    try testing.expectEqual(f.fin, 1);
    try testing.expectEqual(f.rsv1, 0);
    try testing.expectEqual(f.rsv2, 0);
    try testing.expectEqual(f.rsv3, 0);
    try testing.expectEqual(f.opcode, .text);
    try testing.expectEqual(f.mask, 1);
    try testing.expectEqual(f.masking_key.len, 4);
    try testing.expectEqual(f.payload.len, 5);
    //f.unmaskPayload();
    try testing.expectEqualStrings(f.payload, "Hello");
}

fn maskUnmask(mask: []const u8, buf: []u8) void {
    for (buf) |c, i|
        buf[i] = c ^ mask[i % 4];
}

test "maskUnmask" {
    const masking_key = [_]u8{ 0xa, 0xb, 0xc, 0xd };
    var payload = [_]u8{ 'H', 'e', 'l', 'l', 'o' };
    maskUnmask(&masking_key, &payload);
    try testing.expectEqualSlices(u8, &payload, &[_]u8{ 0x42, 0x6e, 0x60, 0x61, 0x65 });
    maskUnmask(&masking_key, &payload);
    try testing.expectEqualSlices(u8, &payload, &[_]u8{ 0x48, 0x65, 0x6c, 0x6c, 0x6f });
    try testing.expectEqualStrings(&payload, "Hello");
}

test "encode" {
    var hello = [_]u8{ 0x81, 0x05, 0x48, 0x65, 0x6c, 0x6c, 0x6f };
    var rsp = try Frame.decode(&hello);
    try testing.expectEqual(rsp.bytes, 7);
    var f = rsp.frame.?;
    var ef = f.echo();

    var buf: [16]u8 = undefined;
    var offset = ef.encode(&buf).bytes;

    var payload = buf[offset - 5 .. offset];
    maskUnmask(&ef.masking_key, payload);
    try testing.expectEqualStrings(payload, "Hello");

    // for (buf[0..@intCast(usize, offset)]) |b|
    //     std.debug.print("{x:0>2} ", .{b});
    // var close = [_]u8{ 0x88, 0x02, 0x03, 0xe8 };
    // fr = try Frame.decode(&close);
    // f = fr[1];
    // try testing.expectEqual(f.opcode, .close);
    // ef = f.echo();
    // offset = @intCast(usize, ef.encode(&buf));
    // try testing.expectEqualSlices(u8, buf[0..offset], &close);
}

test "close status codes" {
    var buf = [_]u8{ 0x88, 0x02, 0x03, 0xe8 };
    var rsp = try Frame.decode(&buf);
    var f = rsp.frame.?;
    try testing.expectEqual(f.opcode, .close);
    try testing.expectEqual(f.closeCode(), 1000);
    try testing.expectEqual(f.closeCode(), 0x03e8);

    buf = [_]u8{ 0x88, 0x02, 0x03, 0xe9 };
    rsp = try Frame.decode(&buf);
    f = rsp.frame.?;
    try testing.expectEqual(f.opcode, .close);
    try testing.expectEqual(f.closeCode(), 1001);
    try testing.expectEqual(f.closeCode(), 0x03e9);

    var close_without_status_code = [_]u8{ 0x88, 0x00 };
    rsp = try Frame.decode(&close_without_status_code);
    f = rsp.frame.?;
    try testing.expectEqual(f.opcode, .close);
    try testing.expectEqual(f.closeCode(), 1000);
}
