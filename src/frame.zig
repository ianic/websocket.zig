const std = @import("std");
const testing = std.testing;

pub const Frame = struct {
    fin: u1,
    rsv1: u1,
    rsv2: u1,
    rsv3: u1,
    opcode: Opcode,
    mask: u1 = U1_0,
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
    };

    const Self = @This();
    const invalidFrame = Self{ .fin = 0, .rsv1 = 0, .rsv2 = 0, .rsv3 = 0, .opcode = .close, .mask = 0, .payload = &[0]u8{}, .frame_len = 0 };

    // first attribute:
    //   - if positive => number of bytes consumed from buf
    //   - if negative => number of bytes missing in buf
    pub fn decode(buf: []u8) !struct { isize, Frame } {
        if (buf.len < 2) {
            return .{ -2, invalidFrame };
        }
        const pl_rsp = try decodePayloadLen(buf[1..]);
        const pl_bytes = pl_rsp[0];
        if (pl_bytes < 0) {
            return .{ pl_bytes - 1, invalidFrame };
        }

        const payload_bytes = @intCast(usize, pl_bytes);
        const payload_len = pl_rsp[1];
        const masked = buf[1] & 0x80 == 0x80;

        const mask_start: usize = 1 + payload_bytes;
        const payload_start: usize = mask_start + if (masked) @intCast(usize, 4) else @intCast(usize, 0);
        const frame_len: usize = payload_start + payload_len;
        if (buf.len > frame_len) {
            return .{ -@intCast(isize, frame_len), invalidFrame };
        }

        var f = Frame{
            .fin = if (buf[0] & 0x80 == 0x80) U1_1 else U1_0,
            .rsv1 = if (buf[0] & 0x40 == 0x40) U1_1 else U1_0,
            .rsv2 = if (buf[0] & 0x20 == 0x20) U1_1 else U1_0,
            .rsv3 = if (buf[0] & 0x10 == 0x10) U1_1 else U1_0,
            .opcode = try getOpcode(@intCast(u4, buf[0] & 0x0f)),
            .mask = if (masked) U1_1 else U1_0,
            .payload = buf[payload_start..frame_len],
            .frame_len = frame_len,
        };
        if (masked) {
            f.masking_key[0] = buf[mask_start];
            f.masking_key[1] = buf[mask_start + 1];
            f.masking_key[2] = buf[mask_start + 2];
            f.masking_key[3] = buf[mask_start + 3];
        }
        return .{ @intCast(isize, frame_len), f };
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

    pub fn echo(self: *Self) Frame {
        var f = Frame{
            .fin = self.fin,
            .rsv1 = self.rsv1,
            .rsv2 = self.rsv2,
            .rsv3 = self.rsv3,
            .opcode = self.opcode,
            .payload = self.payload,
            .frame_len = self.frame_len,
        };
        //if (f.opcode == .text or f.opcode == .binary)
        f.setMaskingKey();
        return f;
    }

    pub fn encode(self: *Self, buf: []u8) isize {
        const payload_len: u64 = self.payload.len;
        const buf_len: usize = 1 + if (payload_len < 126) 1 else if (payload_len < 65536) 3 else 9 +
            if (self.mask == 1) 4 else 0 + payload_len;
        if (buf.len < buf_len) {
            return -@intCast(isize, buf_len);
        }

        buf[0] = (@intCast(u8, self.fin) << 7) +
            (@intCast(u8, self.rsv1) << 6) +
            (@intCast(u8, self.rsv2) << 5) +
            (@intCast(u8, self.rsv1) << 4) +
            @enumToInt(self.opcode);

        var offset: usize = 1;

        buf[1] = (@intCast(u8, self.mask) << 7);
        if (payload_len < 126) {
            buf[1] += @intCast(u8, payload_len);
            offset = 2;
        } else if (payload_len <= 65536) {
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

        return @intCast(isize, self.payload.len + offset);
    }

    fn setMaskingKey(self: *Self) void {
        self.mask = 1;
        rnd.random().bytes(&self.masking_key);
    }
};
var rnd = std.rand.DefaultPrng.init(0);

const U1_1: u1 = 1;
const U1_0: u1 = 0;

fn decodePayloadLen(buf: []const u8) !struct { isize, u64 } {
    if (buf.len < 1) return .{ -1, 0 };

    var pl: u64 = buf[0] & 0x7f;
    if (pl <= 125) {
        return .{ 1, pl };
    }
    if (pl == 126) {
        if (buf.len < 3) return .{ -3, 0 };
        pl = (@intCast(u64, buf[1]) << 8) + buf[2];
        return .{ 3, pl };
    }
    if (buf.len < 9) return .{ -9, 0 };
    if (buf[1] & 0x80 == 0x80) {
        return error.WrongPayloadLen;
    }
    pl = (@intCast(u64, buf[1]) << 56) +
        (@intCast(u64, buf[2]) << 48) +
        (@intCast(u64, buf[3]) << 40) +
        (@intCast(u64, buf[4]) << 32) +
        (@intCast(u64, buf[5]) << 24) +
        (@intCast(u64, buf[6]) << 16) +
        (@intCast(u64, buf[7]) << 8) +
        buf[8];
    return .{ 9, pl };
}

test "decodePayloadLen" {
    // 1 byte
    try testing.expectEqual(try decodePayloadLen(&[_]u8{0x00}), .{ 1, 0 });
    try testing.expectEqual(try decodePayloadLen(&[_]u8{0x0a}), .{ 1, 0xa });
    try testing.expectEqual(try decodePayloadLen(&[_]u8{0x7d}), .{ 1, 0x7d });
    // 2 bytes
    try testing.expectEqual(try decodePayloadLen(&[_]u8{ 0x7e, 0x00, 0x01 }), .{ 3, 0x01 });
    try testing.expectEqual(try decodePayloadLen(&[_]u8{ 0x7e, 0x00, 0xaa }), .{ 3, 0xaa });
    try testing.expectEqual(try decodePayloadLen(&[_]u8{ 0x7e, 0x00, 0xff }), .{ 3, 0xff });
    try testing.expectEqual(try decodePayloadLen(&[_]u8{ 0x7e, 0x01, 0xff }), .{ 3, 0x01ff });
    try testing.expectEqual(try decodePayloadLen(&[_]u8{ 0x7e, 0x12, 0x34 }), .{ 3, 0x1234 });
    // 8 bytes
    try testing.expectEqual(try decodePayloadLen(&[_]u8{ 0x7f, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1 }), .{ 9, 0x1 });
    try testing.expectEqual(try decodePayloadLen(&[_]u8{ 0x7f, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8 }), .{ 9, 0x0102030405060708 });

    // insufficent buffer
    try testing.expectEqual(try decodePayloadLen(&[_]u8{}), .{ -1, 0 });
    try testing.expectEqual(try decodePayloadLen(&[_]u8{0x7e}), .{ -3, 0 });
    try testing.expectEqual(try decodePayloadLen(&[_]u8{0x7f}), .{ -9, 0 });

    // error
    try testing.expectError(error.WrongPayloadLen, decodePayloadLen(&[_]u8{ 0x7f, 0x80, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8 }));
}

test "decode" {
    var hello = [_]u8{ 0x81, 0x05, 0x48, 0x65, 0x6c, 0x6c, 0x6f };
    var fr = try Frame.decode(&hello);
    try testing.expectEqual(fr[0], 7);
    const f = fr[1];
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
    var fr = try Frame.decode(&hello);
    try testing.expectEqual(fr[0], 11);
    var f = fr[1];
    try testing.expectEqual(f.frame_len, 11);
    try testing.expectEqual(f.fin, 1);
    try testing.expectEqual(f.rsv1, 0);
    try testing.expectEqual(f.rsv2, 0);
    try testing.expectEqual(f.rsv3, 0);
    try testing.expectEqual(f.opcode, .text);
    try testing.expectEqual(f.mask, 1);
    try testing.expectEqual(f.masking_key.len, 4);
    try testing.expectEqual(f.payload.len, 5);
    f.unmaskPayload();
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
    var fr = try Frame.decode(&hello);
    try testing.expectEqual(fr[0], 7);
    var f = fr[1];
    var ef = f.echo();

    var buf: [16]u8 = undefined;
    var offset = @intCast(usize, ef.encode(&buf));

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

test {
    const x: u32 = 0xabcd;
    //const buf = std.mem.toBytes(x);
    var buf: [8]u8 = undefined;
    std.mem.writeInt(u64, &buf, x, .Big);

    for (&buf) |b|
        std.debug.print("{x:0>2} ", .{b});
}
