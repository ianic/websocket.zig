const std = @import("std");
const mem = std.mem;
const assert = std.debug.assert;
const testing = std.testing;

const handshake = @import("handshake.zig");
const Options = @import("stream.zig").Options;
const Frame = @import("frame.zig").Frame;
const Message = @import("stream.zig").Message;

pub const Msg = struct {
    encoding: Message.Encoding = .text,
    data: []const u8,
};

pub fn Server(comptime Handler: type) type {
    return struct {
        const Self = @This();
        const State = enum {
            handshake,
            open,
        };

        allocator: std.mem.Allocator,
        handler: *Handler,
        host: []const u8,
        conn: Conn(Handler),
        state: State,

        pub fn init(
            allocator: std.mem.Allocator,
            handler: *Handler,
            host: []const u8,
        ) Self {
            return .{
                .allocator = allocator,
                .handler = handler,
                .host = host,
                .conn = .{ .allocator = allocator, .handler = handler, .mask = 0 },
                .state = .handshake,
            };
        }

        pub fn connect(_: *Self) !void {}

        pub fn deinit(self: *Self) void {
            self.conn.deinit();
        }

        pub fn onSend(self: *Self, buf: []const u8) void {
            self.allocator.free(buf);
        }

        pub fn recv(self: *Self, bytes: []u8) !usize {
            switch (self.state) {
                .handshake => {
                    const req, const n = handshake.Req.parse(bytes) catch |err| switch (err) {
                        error.SplitBuffer => return 0,
                        else => return err,
                    };
                    const accept = handshake.secAccept(req.key);
                    const buf = try handshake.responseAllocPrint(self.allocator, &accept, req.options);
                    try self.handler.sendZc(buf);
                    self.state = .open;
                    return n;
                },
                .open => {
                    return try self.conn.recv(bytes);
                },
            }
        }

        pub fn send(self: *Self, msg: Msg) !void {
            try self.conn.send(msg);
        }
    };
}

pub fn Client(comptime Handler: type) type {
    return struct {
        const Self = @This();
        const State = enum {
            init,
            handshake,
            open,
        };

        allocator: std.mem.Allocator,
        handler: *Handler,
        uri: []const u8,
        conn: Conn(Handler),
        sec_key: [24]u8,
        state: State,

        pub fn init(
            allocator: std.mem.Allocator,
            handler: *Handler,
            uri: []const u8,
        ) Self {
            return .{
                .allocator = allocator,
                .handler = handler,
                .uri = uri,
                .sec_key = handshake.secKey(),
                .conn = .{ .allocator = allocator, .handler = handler, .mask = 1 },
                .state = .init,
            };
        }

        pub fn deinit(self: *Self) void {
            self.conn.deinit();
        }

        pub fn connect(self: *Self) !void {
            const buf = try handshake.requestAllocPrint(self.allocator, self.uri, &self.sec_key);
            errdefer self.allocator.free(buf);
            try self.handler.sendZc(buf);
            self.state = .handshake;
        }

        pub fn onSend(self: *Self, buf: []const u8) void {
            self.allocator.free(buf);
        }

        pub fn recv(self: *Self, bytes: []u8) !usize {
            switch (self.state) {
                .handshake => {
                    const rsp, const n = handshake.Rsp.parse(bytes) catch |err| switch (err) {
                        error.SplitBuffer => return 0,
                        else => return err,
                    };
                    try rsp.validate(&self.sec_key);
                    const options = rsp.options;
                    if (options.per_message_deflate) {
                        const decompressor = try self.allocator.create(DecompressorType);
                        decompressor.* = .{};
                        self.conn.decompressor = decompressor;
                        self.conn.reset_decompressor = options.server_no_context_takeover;
                    }
                    self.state = .open;
                    self.handler.onConnect();
                    return n + try self.conn.recv(bytes[n..]);
                },
                .open => {
                    return try self.conn.recv(bytes);
                },
                else => unreachable,
            }
        }

        pub fn send(self: *Self, msg: Msg) !void {
            try self.conn.send(msg);
        }
    };
}

const DecompressorType = std.compress.flate.Decompressor(std.io.FixedBufferStream([]const u8).Reader);

pub fn Conn(comptime Handler: type) type {
    return struct {
        const Self = @This();

        allocator: mem.Allocator,
        handler: *Handler,

        decompressor: ?*DecompressorType = null, // not null if per_message_deflate is negotiated
        reset_decompressor: bool = false, //        true if sliding window is not negotiated

        last_frame_fragment: Frame.Fragment = .unfragmented,
        message: ?Message = null,
        mask: u1,

        pub fn deinit(self: *Self) void {
            if (self.message) |*msg|
                msg.deinit();
            if (self.decompressor) |decompressor|
                self.allocator.destroy(decompressor);
        }

        pub fn recv(self: *Self, bytes: []u8) !usize {
            var n: usize = 0;
            while (n < bytes.len) {
                const frm, const frm_len = Frame.parse(bytes[n..]) catch |err| switch (err) {
                    error.SplitBuffer => return n,
                    else => return err,
                };
                try frm.assertValid(self.decompressor != null);
                if (frm.opcode.isControl()) {
                    try self.recvControlFrame(frm);
                } else {
                    try self.recvFrame(frm);
                }
                n += frm_len;
            }
            return n;
        }

        pub fn send(self: *Self, msg: Msg) !void {
            try self.sendFrame(.{
                .fin = 1,
                .opcode = msg.encoding.opcode(),
                .payload = msg.data,
                .mask = self.mask,
            }, 0);
        }

        fn sendFrame(self: *Self, frame: Frame, close_code: u16) !void {
            const buf = try self.allocator.alloc(u8, frame.encodedLen());
            errdefer self.allocator.free(buf);
            _ = frame.encode(buf, close_code);
            try self.handler.sendZc(buf);
        }

        pub fn onSend(self: *Self, buf: []const u8) void {
            self.allocator.free(buf);
        }

        fn recvFrame(self: *Self, frm: Frame) !void {
            try frm.assertValidContinuation(self.last_frame_fragment);
            self.last_frame_fragment = frm.fragment();
            switch (frm.fragment()) {
                .unfragmented => {
                    assert(self.message == null);
                    var msg = Message{
                        .encoding = Message.Encoding.from(frm.opcode),
                        .compressed = frm.isCompressed(),
                        .payload = frm.payload,
                    };
                    defer msg.deinit();
                    try self.recvMessage(&msg);
                },
                .start => {
                    assert(self.message == null);
                    self.message = Message{
                        .encoding = Message.Encoding.from(frm.opcode),
                        .compressed = frm.isCompressed(),
                        .allocator = self.allocator,
                        .payload = try self.allocator.dupe(u8, frm.payload),
                    };
                },
                .fragment => {
                    const msg = &self.message.?;
                    try msg.append(frm.payload);
                },
                .end => {
                    var msg = &self.message.?;
                    try msg.append(frm.payload);
                    defer {
                        msg.deinit();
                        self.message = null;
                    }
                    try self.recvMessage(msg);
                },
            }
        }

        fn recvMessage(self: *Self, msg: *Message) !void {
            if (msg.compressed) {
                const decompressor = self.decompressor orelse return error.DeflateNotSupported;
                try msg.decompress(self.allocator, decompressor);
                if (self.reset_decompressor) decompressor.* = .{};
            }
            try msg.validate();
            self.handler.onRecv(Msg{ .encoding = msg.encoding, .data = msg.payload });
        }

        fn recvControlFrame(self: *Self, frm: Frame) !void {
            switch (frm.opcode) {
                .ping => try self.pong(frm.payload),
                .close => {
                    try self.close(frm.closeCode(), frm.closePayload());
                    return error.EndOfStream;
                },
                .pong => {},
                else => unreachable,
            }
        }

        fn pong(self: *Self, payload: []const u8) !void {
            assert(payload.len < 126);
            try self.sendFrame(.{ .fin = 1, .opcode = .pong, .payload = payload, .mask = self.mask }, 0);
        }

        fn close(self: *Self, close_code: u16, payload: []const u8) !void {
            assert(payload.len < 124);
            try self.sendFrame(.{ .fin = 1, .opcode = .close, .payload = payload, .mask = self.mask }, close_code);
        }
    };
}

test "async" {
    const Handler = struct {
        const Self = @This();
        control_frames: usize = 0,
        messages: usize = 0,
        pub fn onControlFrame(self: *Self, frm: Frame) !void {
            _ = frm;
            self.control_frames += 1;
        }
        pub fn onRecv(self: *Self, msg: Msg) void {
            testing.expectEqual(msg.encoding, .text) catch unreachable;
            testing.expectEqualSlices(u8, &[_]u8{ 10, 11, 12, 13, 14, 15 }, msg.data) catch unreachable;
            self.messages += 1;
        }
        pub fn sendZc(_: *Self, _: []const u8) !void {}
    };
    var handler: Handler = .{};

    var conn = Conn(Handler).init(testing.allocator, &handler);
    defer conn.deinit();
    const n = try conn.recv(@constCast(&fixture_fragmented_message));
    try testing.expectEqual(16, n);
    try testing.expectEqual(2, handler.control_frames);
    try testing.expectEqual(1, handler.messages);
}

const fixture_fragmented_message =
    [_]u8{ 0x01, 0x1, 0xa } ++ // first text frame
    [_]u8{ 0x89, 0x00 } ++ // ping in between
    [_]u8{ 0x00, 0x3, 0xb, 0xc, 0xd } ++ // continuation frame
    [_]u8{ 0x8a, 0x00 } ++ // pong
    [_]u8{ 0x80, 0x2, 0xe, 0xf };
