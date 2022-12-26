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

pub fn isWebSocketUpgrade(rsp: *HttpResponse, sec_key: []const u8) bool {
    if (!mem.eql(u8, rsp.status, "101")) return false;

    var iter = rsp.headerIter();
    var upgrade_headers: usize = 0;
    var sec_accept_valid = false;

    while (iter.next()) |h| {
        if (h.match("upgrade", "websocket")) upgrade_headers += 1;
        if (h.match("connection", "upgrade")) upgrade_headers += 1;
        if (h.keyMatch("sec-websocket-accept")) {
            sec_accept_valid = isValidSecAccept(sec_key, h.value);
        }
    }

    return upgrade_headers == 2 and sec_accept_valid;
}

const HttpResponse = struct {
    buffer: []const u8,
    headers: []const u8,

    protocol: []const u8,
    status: []const u8,
    status_description: []const u8,

    const Self = @This();

    pub fn parse(buffer: []const u8) !Self {
        var start_index: usize = 0;
        const status_line = try readLine(buffer, &start_index);
        const sp1 = mem.indexOfScalar(u8, status_line, ' ') orelse return error.InvalidHttpResponse;
        const sp2 = mem.indexOfScalarPos(u8, status_line, sp1 + 1, ' ') orelse return error.InvalidHttpResponse;
        return .{
            .protocol = status_line[0..sp1],
            .status = status_line[sp1 + 1 .. sp2],
            .status_description = status_line[sp2 + 1 ..],
            .buffer = buffer,
            .headers = buffer[start_index..],
        };
    }

    pub fn headerIter(self: *Self) HeaderIterator {
        return HeaderIterator{ .buffer = self.headers };
    }

    pub fn hasHeader(self: *Self, key: []const u8, value: []const u8) bool {
        var iter = self.headerIter();
        while (iter.next()) |h|
            if (h.match(key, value)) return true;
        return false;
    }

    pub fn getHeader(self: *Self, key: []const u8) ?[]const u8 {
        var iter = self.headerIter();
        while (iter.next()) |h|
            if (h.keyMatch(key)) return h.value;
        return null;
    }
};

fn readLine(buffer: []const u8, start_index: *usize) ![]const u8 {
    const si = start_index.*;
    const eol = mem.indexOfScalarPos(u8, buffer, si, '\n') orelse return error.InvalidHttpResponse;
    var line = buffer[si..eol];
    start_index.* += line.len + 1;
    if (mem.endsWith(u8, line, "\r")) {
        line = line[0 .. line.len - 1];
    }
    return line;
}

const HeaderIterator = struct {
    buffer: []const u8,
    index: usize = 0,

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

    const Self = @This();

    pub fn next(self: *Self) ?Header {
        const header_line = readLine(self.buffer, &self.index) catch return null;
        if (header_line.len == 0)
            return null;
        const sep = mem.indexOfScalar(u8, header_line, ':') orelse return null;
        const whitespace = " \t";
        const key = mem.trim(u8, header_line[0..sep], whitespace);
        const value = mem.trim(u8, header_line[sep + 1 ..], whitespace);

        return Header{ .key = key, .value = value };
    }
};

test "parse response" {
    const rsp =
        \\HTTP/1.1 101 Switching Protocols
        \\Upgrade: websocket
        \\Connection: Upgrade
        \\Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=
        \\
    ;
    try assertHttpResponse(rsp);

    const rspWithCR = "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n";
    try assertHttpResponse(rspWithCR);
}

fn assertHttpResponse(rsp: []const u8) !void {
    const sec_key = "dGhlIHNhbXBsZSBub25jZQ==";
    const sec_accept = "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=";

    var p = try HttpResponse.parse(rsp);
    try testing.expectEqualStrings("HTTP/1.1", p.protocol);
    try testing.expectEqualStrings("101", p.status);
    try testing.expectEqualStrings("Switching Protocols", p.status_description);

    try testing.expectEqualStrings(p.getHeader("Sec-WebSocket-Accept").?, sec_accept);
    try testing.expectEqualStrings(p.getHeader("upgrade").?, "websocket");
    try testing.expect(p.hasHeader("upgrade", "websocket"));
    try testing.expectEqualStrings(p.getHeader("connection").?, "Upgrade");
    try testing.expect(p.hasHeader("connection", "UPGRADE")); // case insensitive match

    try testing.expect(isWebSocketUpgrade(&p, sec_key));
}

pub fn ClientHandshake(comptime ReaderType: type, comptime WriterType: type) type {
    return struct {
        reader: ReaderType,
        writer: WriterType,
        arena: std.heap.ArenaAllocator,
        sec_key: [24]u8,

        const Self = @This();

        pub fn init(reader: ReaderType, writer: WriterType, allocator: Allocator) Self {
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

fn initClientHandshake(reader: anytype, writer: anytype, allocator: Allocator) ClientHandshake(@TypeOf(reader), @TypeOf(writer)) {
    return ClientHandshake(@TypeOf(reader), @TypeOf(writer)).init(reader, writer, allocator);
}

pub fn clientHandshake(allocator: Allocator, reader: anytype, writer: anytype, host: []const u8, path: []const u8) !void {
    var cs = initClientHandshake(reader, writer, allocator);
    defer cs.deinit();
    try cs.writeRequest(host, path);
    try cs.assertValidResponse();
}

const testingStream = @import("fixed_buffers_stream.zig").testingStream;

test "parse response" {
    const http_server_response =
        \\HTTP/1.1 101 Switching Protocols
        \\Upgrade: websocket
        \\Connection: Upgrade
        \\Sec-WebSocket-Accept: 9bQuZIN64KrRsqgxuR1CxYN94zQ=
        \\
        \\
    ;
    var stm = testingStream(http_server_response, 1024).init();
    var cs = initClientHandshake(stm.reader(), stm.writer(), testing.allocator);
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

    var stm = testingStream(input, 1024).init();
    try clientHandshake(testing.allocator, stm.reader(), stm.writer(), "ws.example.com", "/ws");
    try testing.expectEqualSlices(u8, stm.written(), &expected_output.*);
}

// debug helper
fn showBuf(buf: []const u8) void {
    std.debug.print("\n", .{});
    for (buf) |b|
        std.debug.print("0x{x:0>2}, ", .{b});
    std.debug.print("\n", .{});
}
