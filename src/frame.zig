const std = @import("std");
const mem = std.mem;

const assert = std.debug.assert;
const Allocator = mem.Allocator;
const utf8ValidateSlice = std.unicode.utf8ValidateSlice;

var rnd = std.rand.DefaultPrng.init(0);

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
    pub const empty_payload = &[_]u8{};

    fin: u1,
    rsv1: u1 = 0,
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
        return mem.readInt(u16, self.payload[0..2], .big);
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
            else => return Error.InvalidCloseCode,
        };
    }

    pub fn assertValid(self: *Self) !void {
        if (self.isControl()) try self.assertValidControl();
        if (self.opcode == .close) try self.assertValidClose();
    }

    fn assertValidClose(self: *Self) !void {
        try assertValidUtf8(self.closePayload());
        try self.assertValidCloseCode();
    }

    fn assertValidControl(self: *Self) !void {
        if (self.payload.len > 125) return Error.TooBigPayloadForControlFrame;
        if (self.fin == 0) return Error.FragmentedControlFrame;
    }

    pub fn isFin(self: *Self) bool {
        return self.fin == 1;
    }

    pub fn isCompressed(self: *Self) bool {
        return self.rsv1 == 1;
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

    pub fn assertValidContinuation(self: *Self, prev: Fragment) !void {
        if (!self.isValidContinuation(prev)) return Error.InvalidFragmentation;
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

        buf[0] = (@as(u8, @intCast(self.fin)) << 7) +
            (@as(u8, @intCast(self.rsv1)) << 6) +
            //(@intCast(u8, self.rsv2) << 5) +
            //(@intCast(u8, self.rsv3) << 4) +
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
        @memcpy(buf[offset..], self.payload);
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

    pub fn maskUnmask(mask: []const u8, buf: []u8) void {
        for (buf, 0..) |c, i|
            buf[i] = c ^ mask[i % 4];
    }

    pub fn assertRsvBits(rsv1: u1, rsv2: u1, rsv3: u1, deflate_supported: bool) !void {
        if (rsv1 == 1 and !deflate_supported) return Error.DeflateNotSupported;
        if (rsv2 == 1 or rsv3 == 1) return Error.ReservedRsv;
    }

    pub fn assertValidUtf8(data: []const u8) !void {
        if (!utf8ValidateSlice(data)) return Error.InvalidUtf8Payload;
    }
};
