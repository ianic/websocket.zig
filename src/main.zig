const std = @import("std");
const mem = std.mem;
const assert = std.debug.assert;
const testing = std.testing;

pub const handshake = @import("handshake.zig");
pub const stream = @import("stream.zig");
pub const Message = stream.Message;

pub const Msg = struct {
    encoding: Message.Encoding = .text,
    data: []const u8,
};

pub fn client(
    allocator: std.mem.Allocator,
    inner_reader: anytype,
    inner_writer: anytype,
    uri: []const u8,
) !stream.Stream(@TypeOf(inner_reader), @TypeOf(inner_writer)) {
    const options = try handshake.client(allocator, inner_reader, inner_writer, uri);
    return try stream.client(allocator, inner_reader, inner_writer, options);
}

test {
    // Run tests in imported files in `zig build test`
    _ = @import("handshake.zig");
    _ = @import("stream.zig");
    _ = @import("frame.zig");
}

const Options = @import("stream.zig").Options;
const Frame = @import("frame.zig").Frame;

pub const asyn = struct {
    // Handler: upstream application handler
    // Transport: downstream transport protocol
    pub fn Client(comptime Handler: type, comptime Transport: type) type {
        const HandshakeType = handshake.Client(
            std.io.FixedBufferStream([]u8).Reader,
            std.ArrayList(u8).Writer,
        );

        return struct {
            const Self = @This();

            allocator: std.mem.Allocator,
            handler: *Handler,
            transport: *Transport,
            uri: []const u8,
            opt: Options = .{},
            handshake: ?*HandshakeType = null,
            conn: Conn(Handler, Transport),

            pub fn init(
                allocator: std.mem.Allocator,
                handler: *Handler,
                transport: *Transport,
                uri: []const u8,
            ) Self {
                return .{
                    .allocator = allocator,
                    .handler = handler,
                    .transport = transport,
                    .uri = uri,
                    .conn = Conn(Handler, Transport).init(allocator, handler, transport),
                };
            }

            pub fn deinit(self: *Self) void {
                if (self.handshake) |hs| {
                    hs.deinit();
                    self.allocator.destroy(hs);
                    self.handshake = null;
                }
                self.conn.deinit();
            }

            pub fn connect(self: *Self) !void {
                var list = std.ArrayList(u8).init(self.allocator);
                defer list.deinit();

                const hs = try self.allocator.create(HandshakeType);
                errdefer {
                    self.allocator.destroy(hs);
                    self.handshake = null;
                }
                hs.* = HandshakeType.init(self.allocator, undefined, list.writer());
                self.handshake = hs;

                try hs.writeRequest(self.uri);
                const buf = try list.toOwnedSlice();
                errdefer self.allocator.free(buf);
                try self.transport.sendZc(buf);
            }

            pub fn onSend(self: *Self, buf: []const u8) void {
                self.allocator.free(buf);
            }

            pub fn recv(self: *Self, bytes: []u8) !usize {
                if (self.handshake) |hs| {
                    var fbs = std.io.fixedBufferStream(bytes);
                    hs.reader = fbs.reader();
                    hs.assertValidResponse() catch |err| switch (err) {
                        error.EndOfStream => return 0,
                        else => return err,
                    };
                    self.opt = hs.options;
                    const n = fbs.pos;
                    hs.deinit();
                    self.allocator.destroy(hs);
                    self.handshake = null;

                    self.handler.onConnect();
                    return n + try self.conn.recv(bytes[n..]);
                }
                return try self.conn.recv(bytes);
            }

            pub fn send(self: *Self, msg: Msg) !void {
                try self.conn.send(msg);
            }
        };
    }

    pub fn Conn(comptime Handler: type, comptime Transport: type) type {
        return struct {
            const Self = @This();

            allocator: mem.Allocator,
            handler: *Handler,
            transport: *Transport,

            last_frame_fragment: Frame.Fragment = .unfragmented,
            message: ?Message = null,

            pub fn init(
                allocator: mem.Allocator,
                handler: *Handler,
                transport: *Transport,
            ) Self {
                return .{
                    .allocator = allocator,
                    .handler = handler,
                    .transport = transport,
                };
            }

            pub fn deinit(self: *Self) void {
                if (self.message) |msg| msg.deinit();
            }

            pub fn recv(self: *Self, bytes: []u8) !usize {
                var n: usize = 0;
                while (n < bytes.len) {
                    const frm, const frm_len = Frame.parse(bytes[n..]) catch |err| switch (err) {
                        error.SplitBuffer => return n,
                        else => return err,
                    };
                    try frm.assertValid(false); // TODO deflate
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
                    .mask = 1,
                }, 0);
            }

            fn sendFrame(self: *Self, frame: Frame, close_code: u16) !void {
                const buf = try self.allocator.alloc(u8, frame.encodedLen());
                errdefer self.allocator.free(buf);
                _ = frame.encode(buf, close_code);
                try self.transport.sendZc(buf);
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
                        const msg = Message{
                            .encoding = Message.Encoding.from(frm.opcode),
                            .compressed = frm.isCompressed(),
                            .payload = frm.payload,
                        };
                        try msg.validate();
                        self.handler.onRecv(Msg{ .encoding = msg.encoding, .data = msg.payload });
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
                        const msg = &self.message.?;
                        try msg.append(frm.payload);
                        try msg.validate();
                        defer {
                            msg.deinit();
                            self.message = null;
                        }
                        self.handler.onRecv(Msg{ .encoding = msg.encoding, .data = msg.payload });
                    },
                }
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
                try self.sendFrame(.{ .fin = 1, .opcode = .pong, .payload = payload, .mask = 1 }, 0);
            }

            pub fn close(self: *Self, close_code: u16, payload: []const u8) !void {
                assert(payload.len < 124);
                try self.sendFrame(.{ .fin = 1, .opcode = .close, .payload = payload, .mask = 1 }, close_code);
            }
        };
    }

    test "async" {
        const Child = struct {
            const Self = @This();
            control_frames: usize = 0,
            messages: usize = 0,
            pub fn onControlFrame(self: *Self, frm: Frame) !void {
                _ = frm;
                self.control_frames += 1;
            }
            pub fn onMessage(self: *Self, msg: Message) !void {
                try testing.expectEqual(msg.encoding, .text);
                try testing.expectEqualSlices(u8, &[_]u8{ 10, 11, 12, 13, 14, 15 }, msg.payload);
                self.messages += 1;
            }
        };
        var child: Child = .{};

        var conn = Conn(*Child).init(testing.allocator, &child);
        defer conn.deinit();
        const n = try conn.onRecv(@constCast(&fixture_fragmented_message));
        try testing.expectEqual(16, n);
        try testing.expectEqual(2, child.control_frames);
        try testing.expectEqual(1, child.messages);
    }
};

const fixture_fragmented_message =
    [_]u8{ 0x01, 0x1, 0xa } ++ // first text frame
    [_]u8{ 0x89, 0x00 } ++ // ping in between
    [_]u8{ 0x00, 0x3, 0xb, 0xc, 0xd } ++ // continuation frame
    [_]u8{ 0x8a, 0x00 } ++ // pong
    [_]u8{ 0x80, 0x2, 0xe, 0xf };
