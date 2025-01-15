const std = @import("std");

pub const handshake = @import("handshake.zig");
pub const stream = @import("stream.zig");
pub const Message = stream.Message;

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

pub const asyn = struct {
    pub fn Client(comptime Upstream: type, comptime Downstream: type) type {
        const HandshakeType = handshake.Client(
            std.io.FixedBufferStream([]u8).Reader,
            std.ArrayList(u8).Writer,
        );

        return struct {
            const Self = @This();

            allocator: std.mem.Allocator,
            upstream: Upstream,
            downstream: Downstream,
            uri: []const u8,
            opt: Options = .{},
            handshake: ?*HandshakeType = null,
            conn: Conn(Upstream, Downstream),

            pub fn init(
                allocator: std.mem.Allocator,
                upstream: Upstream,
                downstream: Downstream,
                uri: []const u8,
            ) Self {
                return .{
                    .allocator = allocator,
                    .upstream = upstream,
                    .downstream = downstream,
                    .uri = uri,
                    .conn = Conn(Upstream, Downstream).init(allocator, upstream, downstream),
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
                try self.downstream.sendZc(try list.toOwnedSlice());
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

                    self.upstream.onConnect();
                    return n + try self.conn.recv(bytes[n..]);
                }
                return try self.conn.recv(bytes);
            }

            pub fn send(self: *Self, bytes: []const u8) !void {
                try self.conn.send(bytes);
            }
        };
    }

    const Frame = @import("frame.zig").Frame;
    const mem = std.mem;
    const assert = std.debug.assert;

    pub fn Conn(comptime Upstream: type, comptime Downstream: type) type {
        return struct {
            const Self = @This();

            allocator: mem.Allocator,
            upstream: Upstream,
            downstream: Downstream,

            last_frame_fragment: Frame.Fragment = .unfragmented,
            message: ?Message = null,

            pub fn init(
                allocator: mem.Allocator,
                upstream: Upstream,
                downstream: Downstream,
            ) Self {
                return .{
                    .allocator = allocator,
                    .upstream = upstream,
                    .downstream = downstream,
                };
            }

            pub fn deinit(self: *Self) void {
                if (self.message) |msg| msg.deinit();
            }

            pub fn recv(self: *Self, bytes: []u8) !usize {
                var n: usize = 0;
                while (n < bytes.len) {
                    const frm, const frm_len = Frame.parse(bytes[n..]) catch |err| switch (err) {
                        error.SplitBuffer => return 0,
                        else => return err,
                    };
                    try frm.assertValid();
                    if (frm.opcode.isControl()) {
                        // TODO
                        // try self.child.onControlFrame(frm);
                    } else {
                        try self.recvFrame(frm);
                    }
                    n += frm_len;
                }
                return n;
            }

            pub fn send(self: *Self, bytes: []const u8) !void {
                const frame = Frame{ .fin = 1, .rsv1 = 0, .opcode = .text, .payload = bytes, .mask = 1 };
                const buf = try self.allocator.alloc(u8, frame.encodedLen());
                _ = frame.encode(buf, 0);
                try self.downstream.sendZc(buf);
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
                        self.upstream.onMessage(msg);
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
                        self.upstream.onMessage(msg.*);
                    },
                }
            }
        };
    }

    const testing = std.testing;

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
