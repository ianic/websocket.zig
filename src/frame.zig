const std = @import("std");
const testing = std.testing;

const Frame = struct {
    fin: u1,
    rsv1: u1,
    rsv2: u1,
    rsv3: u1,
    opcode: Opcode,
    mask: u1,
    masking_key: []const u8,
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
    const invalidFrame = Self{ .fin = 0, .rsv1 = 0, .rsv2 = 0, .rsv3 = 0, .opcode = .close, .mask = 0, .masking_key = &[0]u8{}, .payload = &[0]u8{}, .frame_len = 0 };

    // first attribute:
    //   - if positive => number of bytes consumed from buf
    //   - if negative => number of bytes missing in buf
    pub fn parse(buf: []u8) !struct { isize, Frame } {
        if (buf.len < 2) {
            return .{ -2, invalidFrame };
        }
        const pl_rsp = try parsePayloadLen(buf[1..]);
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

        const f = Frame{
            .fin = if (buf[0] & 0x80 == 0x80) U1_1 else U1_0,
            .rsv1 = if (buf[0] & 0x40 == 0x40) U1_1 else U1_0,
            .rsv2 = if (buf[0] & 0x20 == 0x20) U1_1 else U1_0,
            .rsv3 = if (buf[0] & 0x10 == 0x10) U1_1 else U1_0,
            .opcode = try getOpcode(@intCast(u4, buf[0] & 0x0f)),
            .mask = if (masked) U1_1 else U1_0,
            .masking_key = if (masked) buf[mask_start .. mask_start + 4] else buf[0..0],
            .payload = buf[payload_start..frame_len],
            .frame_len = frame_len,
        };
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
        maskUnmask(self.masking_key, self.payload);
    }
    fn unmaskPayload(self: *Self) void {
        maskUnmask(self.masking_key, self.payload);
    }
};

const U1_1: u1 = 1;
const U1_0: u1 = 0;

fn parsePayloadLen(buf: []const u8) !struct { isize, u64 } {
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

test "parsePayloadLen" {
    // 1 byte
    try testing.expectEqual(try parsePayloadLen(&[_]u8{0x00}), .{ 1, 0 });
    try testing.expectEqual(try parsePayloadLen(&[_]u8{0x0a}), .{ 1, 0xa });
    try testing.expectEqual(try parsePayloadLen(&[_]u8{0x7d}), .{ 1, 0x7d });
    // 2 bytes
    try testing.expectEqual(try parsePayloadLen(&[_]u8{ 0x7e, 0x00, 0x01 }), .{ 3, 0x01 });
    try testing.expectEqual(try parsePayloadLen(&[_]u8{ 0x7e, 0x00, 0xaa }), .{ 3, 0xaa });
    try testing.expectEqual(try parsePayloadLen(&[_]u8{ 0x7e, 0x00, 0xff }), .{ 3, 0xff });
    try testing.expectEqual(try parsePayloadLen(&[_]u8{ 0x7e, 0x01, 0xff }), .{ 3, 0x01ff });
    try testing.expectEqual(try parsePayloadLen(&[_]u8{ 0x7e, 0x12, 0x34 }), .{ 3, 0x1234 });
    // 8 bytes
    try testing.expectEqual(try parsePayloadLen(&[_]u8{ 0x7f, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1 }), .{ 9, 0x1 });
    try testing.expectEqual(try parsePayloadLen(&[_]u8{ 0x7f, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8 }), .{ 9, 0x0102030405060708 });

    // insufficent buffer
    try testing.expectEqual(try parsePayloadLen(&[_]u8{}), .{ -1, 0 });
    try testing.expectEqual(try parsePayloadLen(&[_]u8{0x7e}), .{ -3, 0 });
    try testing.expectEqual(try parsePayloadLen(&[_]u8{0x7f}), .{ -9, 0 });

    // error
    try testing.expectError(error.WrongPayloadLen, parsePayloadLen(&[_]u8{ 0x7f, 0x80, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8 }));
}

test "parse" {
    var hello = [_]u8{ 0x81, 0x05, 0x48, 0x65, 0x6c, 0x6c, 0x6f };
    var fr = try Frame.parse(&hello);
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

test "parse masked" {
    var hello = [_]u8{ 0x81, 0x85, 0x37, 0xfa, 0x21, 0x3d, 0x7f, 0x9f, 0x4d, 0x51, 0x58 };
    var fr = try Frame.parse(&hello);
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
