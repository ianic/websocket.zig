const std = @import("std");
const testing = std.testing;
const assert = std.debug.assert;
const ascii = std.ascii;
const mem = std.mem;
const io = std.io;
const fmt = std.fmt;
const builtin = @import("builtin");
const Allocator = std.mem.Allocator;

const WS_MAGIC_KEY = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
var base64Encoder = std.base64.standard.Encoder;
var rnd = std.rand.DefaultPrng.init(0);

fn secKey() [24]u8 {
    if (builtin.is_test) {
        return "3yMLSWFdF1MH1YDDPW/aYQ==".*;
    }

    var buf: [16]u8 = undefined;
    var ret: [24]u8 = undefined;
    rnd.random().bytes(&buf);
    var encoded = base64Encoder.encode(&ret, &buf);
    assert(encoded.len == ret.len);
    return ret;
}

test "random secKey" {
    try testing.expectEqualStrings("3yMLSWFdF1MH1YDDPW/aYQ==", &secKey());
    //try testing.expectEqualStrings("/Hua7JHfD1waXr47jL/uAg==", &secKey());
}

fn secAccept(key: []const u8) [28]u8 {
    var h = std.crypto.hash.Sha1.init(.{});
    var buf: [20]u8 = undefined;

    h.update(key);
    h.update(WS_MAGIC_KEY);
    h.final(&buf);

    var ret: [28]u8 = undefined;
    const encoded = std.base64.standard.Encoder.encode(&ret, &buf);
    assert(encoded.len == ret.len);
    return ret;
}

fn isValidSecAccept(key: []const u8, accept: []const u8) bool {
    return mem.eql(u8, accept, &secAccept(key));
}

test "secAccept" {
    try testing.expectEqualStrings(&secAccept("dGhlIHNhbXBsZSBub25jZQ=="), "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=");
    try testing.expectEqualStrings(&secAccept("3yMLSWFdF1MH1YDDPW/aYQ=="), "9bQuZIN64KrRsqgxuR1CxYN94zQ=");
    try testing.expectEqualStrings(&secAccept("/Hua7JHfD1waXr47jL/uAg=="), "ELgfPf42E81xadzWVke1JyXNmqU=");
}

test "isValidSecAccept" {
    try testing.expect(isValidSecAccept("dGhlIHNhbXBsZSBub25jZQ==", "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="));
    try testing.expect(isValidSecAccept("3yMLSWFdF1MH1YDDPW/aYQ==", "9bQuZIN64KrRsqgxuR1CxYN94zQ="));
    try testing.expect(!isValidSecAccept("3yMLSWFdF1MH1YDDPW/aYQ==", "9bQuZIN64KrRsqgxuR1CxYN94zQ"));
}

pub fn Client(comptime ReaderType: type, comptime WriterType: type) type {
    return struct {
        reader: ReaderType,
        writer: WriterType,
        arena: std.heap.ArenaAllocator,
        sec_key: [24]u8,

        const Self = @This();

        pub fn init(allocator: Allocator, reader: ReaderType, writer: WriterType) Self {
            return .{
                .reader = reader,
                .writer = writer,
                .sec_key = secKey(),
                .arena = std.heap.ArenaAllocator.init(allocator),
            };
        }

        pub fn deinit(self: *Self) void {
            self.arena.deinit();
        }

        pub fn writeRequest(self: *Self, host: []const u8, path: []const u8) !void {
            var buf: [1024]u8 = undefined;
            const format = "GET ws://{s}{s} HTTP/1.1\r\nHost: {s}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: {s}\r\nSec-WebSocket-Version: 13\r\n\r\n";
            try self.writer.writeAll(try fmt.bufPrint(&buf, format, .{ host, path, host, self.sec_key }));
        }

        pub fn assertValidResponse(self: *Self) !void {
            var rsp = try self.parseResponse();
            try rsp.assertWebSocketUpgrade(&self.sec_key);
        }

        const max_response_line_len = 1024;

        const Header = struct {
            key: []const u8,
            value: []const u8,

            pub fn keyMatch(h: Header, key: []const u8) bool {
                return ascii.eqlIgnoreCase(h.key, key);
            }

            pub fn match(h: Header, key: []const u8, value: []const u8) bool {
                return (ascii.eqlIgnoreCase(h.key, key) and
                    ascii.eqlIgnoreCase(h.value, value));
            }
        };

        const Response = struct {
            protocol: []const u8,
            status: []const u8,
            status_description: []const u8,
            headers: []Header,

            pub fn assertWebSocketUpgrade(rsp: *Response, sec_key: []const u8) !void {
                if (!rsp.isWebSocketUpgrade(sec_key)) return error.NotWebsocketUpgradeResponse;
            }

            pub fn isWebSocketUpgrade(rsp: *Response, sec_key: []const u8) bool {
                if (!mem.eql(u8, rsp.status, "101")) return false;

                var upgrade_headers: usize = 0;
                var sec_accept_valid = false;

                for (rsp.headers) |h| {
                    if (h.match("upgrade", "websocket")) upgrade_headers += 1;
                    if (h.match("connection", "upgrade")) upgrade_headers += 1;
                    if (h.keyMatch("sec-websocket-accept")) {
                        sec_accept_valid = isValidSecAccept(sec_key, h.value);
                    }
                }

                return upgrade_headers == 2 and sec_accept_valid;
            }
        };

        pub fn parseResponse(self: *Self) !Response {
            // parse status line
            var status_line = try self.reader.readUntilDelimiterAlloc(self.arena.allocator(), '\n', max_response_line_len);
            if (std.mem.endsWith(u8, status_line, "\r")) {
                status_line = status_line[0 .. status_line.len - 1];
            }
            const sp1 = mem.indexOfScalar(u8, status_line, ' ') orelse return error.InvalidHttpResponse;
            const sp2 = mem.indexOfScalarPos(u8, status_line, sp1 + 1, ' ') orelse return error.InvalidHttpResponse;
            const protocol = status_line[0..sp1];
            const status = status_line[sp1 + 1 .. sp2];
            const status_description = status_line[sp2 + 1 ..];

            // parse headers
            var headers = std.ArrayList(Header).init(self.arena.allocator());
            defer headers.deinit();
            while (true) {
                var header_line = try self.reader.readUntilDelimiterAlloc(self.arena.allocator(), '\n', max_response_line_len);
                if (std.mem.endsWith(u8, header_line, "\r")) {
                    header_line = header_line[0 .. header_line.len - 1];
                }
                if (header_line.len == 0)
                    break;

                const index = std.mem.indexOfScalar(u8, header_line, ':') orelse return error.InvalidHeader;

                const whitespace = " \t";
                const key = std.mem.trim(u8, header_line[0..index], whitespace);
                const value = std.mem.trim(u8, header_line[index + 1 ..], whitespace);

                try headers.append(Header{ .key = key, .value = value });
            }

            return Response{
                .protocol = protocol,
                .status = status,
                .status_description = status_description,
                .headers = try headers.toOwnedSlice(),
            };
        }
    };
}

fn clientInit(allocator: Allocator, reader: anytype, writer: anytype) Client(@TypeOf(reader), @TypeOf(writer)) {
    return Client(@TypeOf(reader), @TypeOf(writer)).init(allocator, reader, writer);
}

// do client handshake using stream
// error on unsuccessful handshake
pub fn client(allocator: Allocator, reader: anytype, writer: anytype, host: []const u8, path: []const u8) !void {
    var cs = clientInit(allocator, reader, writer);
    defer cs.deinit();
    try cs.writeRequest(host, path);
    try cs.assertValidResponse();
}

const testing_stream = @import("testing_stream.zig");

test "parse response" {
    const http_server_response =
        \\HTTP/1.1 101 Switching Protocols
        \\Upgrade: websocket
        \\Connection: Upgrade
        \\Sec-WebSocket-Accept: 9bQuZIN64KrRsqgxuR1CxYN94zQ=
        \\
        \\
    ;
    var stm = testing_stream.init(http_server_response);
    var cs = clientInit(testing.allocator, stm.reader(), stm.writer());
    defer cs.deinit();
    var rsp = try cs.parseResponse();
    const sec_key = "3yMLSWFdF1MH1YDDPW/aYQ==";
    try testing.expect(rsp.isWebSocketUpgrade(sec_key));
    try rsp.assertWebSocketUpgrade(sec_key);
    try rsp.assertWebSocketUpgrade(&cs.sec_key);
}

test "valid ws handshake" {
    const input =
        "HTTP/1.1 101 Switching Protocols\r\n" ++
        "Upgrade: websocket\r\n" ++
        "Connection: Upgrade\r\n" ++
        "Sec-WebSocket-Accept: 9bQuZIN64KrRsqgxuR1CxYN94zQ=\r\n\r\n";
    const expected_output =
        "GET ws://ws.example.com/ws HTTP/1.1\r\n" ++
        "Host: ws.example.com\r\n" ++
        "Upgrade: websocket\r\n" ++
        "Connection: Upgrade\r\n" ++
        "Sec-WebSocket-Key: 3yMLSWFdF1MH1YDDPW/aYQ==\r\n" ++
        "Sec-WebSocket-Version: 13\r\n\r\n";

    var stm = testing_stream.init(input);
    try client(testing.allocator, stm.reader(), stm.writer(), "ws.example.com", "/ws");
    try testing.expectEqualSlices(u8, stm.written(), &expected_output.*);
}

// debug helper
fn showBuf(buf: []const u8) void {
    std.debug.print("\n", .{});
    for (buf) |b|
        std.debug.print("0x{x:0>2}, ", .{b});
    std.debug.print("\n", .{});
}
