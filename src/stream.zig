const std = @import("std");
const io = std.io;
const mem = std.mem;
const zlib = @import("zlib");

const assert = std.debug.assert;
const Allocator = mem.Allocator;
const utf8ValidateSlice = std.unicode.utf8ValidateSlice;

const Frame = @import("frame.zig").Frame;

pub const Message = struct {
    pub const Encoding = enum {
        text,
        binary,

        pub fn opcode(self: Encoding) Frame.Opcode {
            return if (self == .text) Frame.Opcode.text else Frame.Opcode.binary;
        }
    };

    encoding: Encoding = .text,
    payload: []const u8,
    allocator: ?Allocator = null,

    const Self = @This();

    pub fn init(allocator: Allocator, encoding: Encoding, payload: []const u8) !Self {
        var self = Self{
            .allocator = allocator,
            .encoding = encoding,
            .payload = payload,
        };
        try self.validate();
        return self;
    }

    pub fn deinit(self: Self) void {
        if (self.allocator) |a| a.free(self.payload);
    }

    fn validate(self: Self) !void {
        if (self.encoding == .text)
            try Frame.assertValidUtf8(self.payload);
    }
};

pub const Options = struct {
    // is compression supported
    per_message_deflate: bool = false,

    // false indicates that the client can decompress a message that the server built using context takeover
    server_no_context_takeover: bool = false,

    // false indicates that the server can decompress messages built by the client using context takeover
    client_no_context_takeover: bool = false,

    // by including this extension parameter in an extension negotiation response, a server
    // limits the LZ77 sliding window size that the client uses to compress messages
    client_max_window_bits: u4 = 15,

    // limits the LZ77 sliding window size that the server will use to compress messages
    server_max_window_bits: u4 = 15,

    // don't compress payload smaller than threshold
    compress_threshold: usize = 126,
};

pub fn Stream(comptime ReaderType: type, comptime WriterType: type) type {
    return struct {
        reader: Reader(ReaderType),
        writer: Writer(WriterType),

        allocator: Allocator,
        err: ?anyerror = null,

        // used in validation
        last_frame_fragment: Frame.Fragment = .unfragmented,

        // message compression
        decompressor: ?zlib.Decompressor = null, // not null if per_message_deflate is negotiated
        compressor: ?zlib.Compressor = null, // not null if per_message_deflate is negotiated
        reset_compressor: bool = false, // true if sliding window is not negotiated
        reset_decompressor: bool = false, // true if sliding window is not negotiated
        compress_threshold: usize = 126, // don't compress tiny payload

        const Self = @This();

        fn readDataFrame(self: *Self) !Frame {
            while (true) {
                var frame = try self.reader.frame();
                if (frame.isControl()) {
                    defer frame.deinit();
                    try self.handleControlFrame(&frame);
                } else {
                    errdefer frame.deinit();
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
            // read first frame
            var frame = try self.readDataFrame();

            // get encoding and compressed from first frame
            const encoding: Message.Encoding = if (frame.opcode == .binary) .binary else .text;
            const compressed = frame.isCompressed();

            if (frame.isFin()) {
                // if single frame return frame payload as message payload
                // message takes ownership of the allocated payload
                errdefer frame.deinit();
                return self.initMessage(encoding, frame.payload, compressed);
            }

            // other frames payload will be collected into payload
            var payload = blk: {
                errdefer frame.deinit();
                const payload = try self.allocator.alloc(u8, frame.payload.len);
                @memcpy(payload, frame.payload);
                break :blk payload;
            };
            frame.deinit();

            while (true) {
                errdefer self.allocator.free(payload);
                frame = try self.readDataFrame();
                defer frame.deinit();

                // append frame.payload  to payload
                const start = payload.len;
                payload = try self.allocator.realloc(payload, start + frame.payload.len);
                @memcpy(payload[start..], frame.payload);

                if (frame.isFin())
                    return self.initMessage(encoding, payload, compressed);
            }
        }

        pub fn sendMessage(self: *Self, msg: Message) !void {
            try self.send(msg.encoding, msg.payload, false);
        }

        pub fn send(
            self: *Self,
            encoding: Message.Encoding,
            payload: []const u8,
            // prevent payload compression
            // usefull if payload is of already compressed type, for example jpg
            no_compress: bool,
        ) !void {
            if (!no_compress and payload.len >= self.compress_threshold) {
                if (self.compressor) |*cmp| {
                    // send compressed
                    const compressed = try cmp.compressAllAlloc(payload);
                    defer self.allocator.free(compressed);
                    if (self.reset_compressor) try cmp.reset();
                    try self.writer.message(encoding, compressed, true);
                    return;
                }
            }
            try self.writer.message(encoding, payload, false);
            return;
        }

        fn initMessage(
            self: *Self,
            encoding: Message.Encoding,
            payload: []const u8,
            payload_compressed: bool,
        ) !Message {
            if (payload_compressed) {
                if (self.decompressor) |*dcp| {
                    defer self.allocator.free(payload);
                    const decompressed = try dcp.decompressAllAlloc(payload);
                    errdefer self.allocator.free(decompressed);
                    if (self.reset_decompressor) try dcp.reset();
                    return Message.init(self.allocator, encoding, decompressed);
                }
                return error.DeflateNotSupported;
            }
            return Message.init(self.allocator, encoding, payload);
        }

        pub fn deinit(self: *Self) void {
            if (self.compressor) |*cmp| cmp.deinit();
            if (self.decompressor) |*dcmp| dcmp.deinit();
            self.writer.deinit();
        }
    };
}

pub fn Reader(comptime ReaderType: type) type {
    const BitReader = io.BitReader(.big, ReaderType);
    return struct {
        bit_reader: BitReader,
        allocator: Allocator,
        deflate_supported: bool,

        const Self = @This();

        pub fn init(allocator: Allocator, inner_reader: ReaderType, deflate_supported: bool) Self {
            return .{
                .allocator = allocator,
                .bit_reader = io.bitReader(.big, inner_reader),
                .deflate_supported = deflate_supported,
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
            const payload_len = try self.bit_reader.readBitsNoEof(u64, 7);
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
            const payload = try self.allocator.alloc(u8, payload_len);
            try self.readAll(payload);
            if (masked) Frame.maskUnmask(&masking_key, payload);
            return payload;
        }

        pub fn frame(self: *Self) !Frame {
            const fin = try self.readBit();
            const rsv1 = try self.readBit();
            const rsv2 = try self.readBit();
            const rsv3 = try self.readBit();
            try Frame.assertRsvBits(rsv1, rsv2, rsv3, self.deflate_supported);

            const opcode = try self.readOpcode();
            const mask = try self.readBit();
            const payload_len = try self.readPayloadLen();
            const payload = try self.readPayload(payload_len, mask == 1);

            var frm = Frame{
                .fin = fin,
                .rsv1 = rsv1,
                .mask = mask,
                .opcode = opcode,
                .payload = payload,
                .allocator = if (payload.len > 0) self.allocator else null,
            };
            errdefer frm.deinit();
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

        pub fn init(allocator: Allocator, inner_writer: WriterType) !Self {
            return .{
                .allocator = allocator,
                .buf = try allocator.alloc(u8, writer_buffer_len),
                .writer = inner_writer,
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

        pub fn message(self: *Self, encoding: Message.Encoding, payload: []const u8, compressed: bool) !void {
            var sent_payload: usize = 0;
            // send multiple frames if needed
            while (true) {
                const first_frame = sent_payload == 0;

                var fin: u1 = 1;
                const rsv1: u1 = if (compressed and first_frame) 1 else 0;

                // use frame payload that fits into write_buf
                var frame_payload = payload[sent_payload..];
                if (frame_payload.len + Frame.max_header > self.buf.len) {
                    frame_payload = frame_payload[0 .. self.buf.len - Frame.max_header];
                    fin = 0;
                }
                const opcode = if (first_frame) encoding.opcode() else Frame.Opcode.continuation;

                // create frame
                const frame = Frame{ .fin = fin, .rsv1 = rsv1, .opcode = opcode, .payload = frame_payload, .mask = 1 };
                // encode frame into write_buf and send it to stream
                const bytes = frame.encode(self.buf, 0);
                try self.writer.writeAll(self.buf[0..bytes]);
                // loop if something is left
                sent_payload += frame_payload.len;
                if (sent_payload >= payload.len) {
                    break;
                }
            }
        }

        pub fn deinit(self: *Self) void {
            self.allocator.free(self.buf);
        }
    };
}

fn reader(allocator: Allocator, inner_reader: anytype, deflate_supported: bool) Reader(@TypeOf(inner_reader)) {
    return Reader(@TypeOf(inner_reader)).init(allocator, inner_reader, deflate_supported);
}

fn writer(allocator: Allocator, inner_writer: anytype) !Writer(@TypeOf(inner_writer)) {
    return try Writer(@TypeOf(inner_writer)).init(allocator, inner_writer);
}

// create websocket client stream
pub fn client(
    allocator: Allocator,
    inner_reader: anytype,
    inner_writer: anytype,
    options: Options,
) !Stream(@TypeOf(inner_reader), @TypeOf(inner_writer)) {
    return .{
        .allocator = allocator,
        .reader = reader(allocator, inner_reader, options.per_message_deflate),
        .writer = try writer(allocator, inner_writer),

        .decompressor = if (options.per_message_deflate)
            try zlib.Decompressor.init(allocator, .{ .header = .ws, .window_size = options.server_max_window_bits })
        else
            null,
        .compressor = if (options.per_message_deflate)
            try zlib.Compressor.init(allocator, .{ .header = .ws, .window_size = options.client_max_window_bits })
        else
            null,
        .reset_compressor = options.client_no_context_takeover,
        .reset_decompressor = options.server_no_context_takeover,
        .compress_threshold = options.compress_threshold,
    };
}

const testing = std.testing;
const expectEqual = testing.expectEqual;
const expectEqualSlices = testing.expectEqualSlices;
const expectError = testing.expectError;
const testing_stream = @import("testing_stream.zig");

test "reader read close frame" {
    var input = [_]u8{ 0x88, 0x02, 0x03, 0xe8 };
    var inner_stm = io.fixedBufferStream(&input);
    var rdr = reader(testing.allocator, inner_stm.reader(), false);
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
    var rdr = reader(testing.allocator, inner_stm.reader(), false);
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

const fixture_fragmented_message =
    [_]u8{ 0x01, 0x1, 0xa } ++ // first text frame
    [_]u8{ 0x89, 0x00 } ++ // ping in between
    [_]u8{ 0x00, 0x3, 0xb, 0xc, 0xd } ++ // continuation frame
    [_]u8{ 0x8a, 0x00 } ++ // pong
    [_]u8{ 0x80, 0x2, 0xe, 0xf };

test "read fragmented message" {
    var inner_stm = testing_stream.init(&fixture_fragmented_message);
    var stm = try client(testing.allocator, inner_stm.reader(), inner_stm.writer(), .{});
    defer stm.deinit();

    var msg = try stm.readMessage();
    defer msg.deinit();

    try testing.expectEqual(msg.encoding, .text);
    try testing.expectEqual(msg.payload.len, 6);
    try testing.expectEqualSlices(u8, msg.payload, &[_]u8{ 0xa, 0xb, 0xc, 0xd, 0xe, 0xf });

    // expect pong in the output
    try expectEqual(inner_stm.write_pos, 6); // pong header (2 bytes) + mask (4 bytes)
    try testing.expectEqualSlices(u8, inner_stm.written()[0..2], &[_]u8{ 0x8a, 0x80 });
}

test "reader read frames" {
    var fbs = io.fixedBufferStream(&fixture_fragmented_message);
    var rdr = reader(testing.allocator, fbs.reader(), false);

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
    var inner_stm = testing_stream.init(&fixture_fragmented_message);
    var stm = try client(testing.allocator, inner_stm.reader(), inner_stm.writer(), .{});
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
    var w = try writer(testing.allocator, writer_stm.writer());
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
    var w = try writer(testing.allocator, writer_stm.writer());
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
    var w = try writer(testing.allocator, writer_stm.writer());
    defer w.deinit();
    const payload = "hello world";
    try w.message(.text, payload, false);

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

test "deflate compress/decompress" {
    const allocator = testing.allocator;
    const input = "Hello";

    var compressor_stm = std.ArrayList(u8).init(allocator);
    defer compressor_stm.deinit();

    var comp = try std.compress.flate.compressor(compressor_stm.writer(), .{});
    _ = try comp.write(input);
    try comp.finish();
    const compressed = compressor_stm.items;
    var temp = io.fixedBufferStream(compressed);
    //showBuf(compressed);

    try testing.expectEqualSlices(u8, compressed, &[_]u8{ 0xf2, 0x48, 0xcd, 0xc9, 0xc9, 0x07, 0x04, 0x00, 0x00, 0xff, 0xff });

    var decompressor_stm = io.fixedBufferStream(compressed);
    try std.compress.flate.decompress(temp.reader(), decompressor_stm.writer());
    try testing.expectEqualSlices(u8, input, decompressor_stm.getWritten());
}

test "zlib compress/decompress" {
    const allocator = testing.allocator;
    const input = "Hello";

    var cmp = try zlib.Compressor.init(allocator, .{ .header = .none });
    defer cmp.deinit();

    const compressed = try cmp.compressAllAlloc(input);
    defer allocator.free(compressed);
    //showBuf(compressed);

    var dcmp = try zlib.Decompressor.init(allocator, .{ .header = .none });
    defer dcmp.deinit();

    const decompressed = try dcmp.decompressAllAlloc(compressed);
    defer allocator.free(decompressed);
    try testing.expectEqualSlices(u8, input, decompressed);
}
