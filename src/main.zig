const std = @import("std");
const testing = std.testing;
const assert = std.debug.assert;

const WS_MAGIC_KEY = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
var base64Encoder = std.base64.standard.Encoder;
var rnd = std.rand.DefaultPrng.init(0);

fn secKey() [24]u8 {
    var buf: [16]u8 = undefined;
    var ret: [24]u8 = undefined;
    rnd.random().bytes(&buf);
    var encoded = base64Encoder.encode(&ret, &buf);
    assert(encoded.len == ret.len);
    return ret;
}

test "random secKey" {
    try testing.expectEqualStrings("3yMLSWFdF1MH1YDDPW/aYQ==", &secKey());
    try testing.expectEqualStrings("/Hua7JHfD1waXr47jL/uAg==", &secKey());
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
    return std.mem.eql(u8, accept, &secAccept(key));
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

test "header parser" {
    var upgrade_request = "GET ws://127.0.0.1:9001/runCase?case=3&agent=Chrome/105.0.0.0 HTTP/1.1\r\nHost: 127.0.0.1:9001\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nOrigin: http://example.com\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Protocol: chat, superchat\r\nSec-WebSocket-Version: 13\r\n\r\n".*;
    var fbs = std.io.fixedBufferStream(&upgrade_request);
    var buf: [1024]u8 = undefined;
    var reader = fbs.reader();

    var request_line = try reader.readUntilDelimiter(&buf, '\n');
    if (std.mem.endsWith(u8, request_line, "\r")) {
        request_line = request_line[0 .. request_line.len - 1];
    }

    var tokens = std.mem.tokenize(u8, request_line, " \t");
    while (tokens.next()) |token| {
        std.debug.print("request line token: {s}\n", .{token});
    }

    //std.debug.print("\nstart line: {s}\n", .{start_line});

    //ref: https://github.com/MasterQ32/zig-serve/blob/2e11e5671d52c256c66bd4d60b1e5975fb9f27f8/src/http.zig#L253
    while (true) {
        var header_line = try reader.readUntilDelimiter(&buf, '\n');
        if (std.mem.endsWith(u8, header_line, "\r")) {
            header_line = header_line[0 .. header_line.len - 1];
        }
        if (header_line.len == 0)
            break;
        const sep = std.mem.indexOfScalar(u8, header_line, ':') orelse return error.InvalidHeader;

        const whitespace = " \t";
        const key = std.mem.trim(u8, header_line[0..sep], whitespace);
        const value = std.mem.trim(u8, header_line[sep + 1 ..], whitespace);
        std.debug.print("header line: {s} '{s}' '{s}'\n", .{ header_line, key, value });
    }
}

fn HeaderParser(comptime ReaderType: type) type {
    return struct {
        reader: ReaderType,
        buf: [1024]u8 = undefined,

        const Self = @This();
        const Header = struct {
            key: []const u8,
            value: []const u8,
        };

        pub fn init(reader: ReaderType) Self {
            return .{
                .reader = reader,
            };
        }

        pub fn requestLine(self: *Self) ![]const u8 {
            var request_line = try self.reader.readUntilDelimiter(&self.buf, '\n');
            if (std.mem.endsWith(u8, request_line, "\r")) {
                request_line = request_line[0 .. request_line.len - 1];
            }
            return request_line;
        }

        pub fn header(self: *Self) !?Header {
            var header_line = try self.reader.readUntilDelimiter(&self.buf, '\n');
            if (std.mem.endsWith(u8, header_line, "\r")) {
                header_line = header_line[0 .. header_line.len - 1];
            }
            if (header_line.len == 0)
                return null;
            const sep = std.mem.indexOfScalar(u8, header_line, ':') orelse return error.InvalidHeader;

            const whitespace = " \t";
            const key = std.mem.trim(u8, header_line[0..sep], whitespace);
            const value = std.mem.trim(u8, header_line[sep + 1 ..], whitespace);
            return Header{
                .key = key,
                .value = value,
            };
        }
    };
}

fn headerParser(underlying_stream: anytype) HeaderParser(@TypeOf(underlying_stream)) {
    return HeaderParser(@TypeOf(underlying_stream)).init(underlying_stream);
}

test "header parser" {
    var upgrade_request = "GET ws://127.0.0.1:9001/runCase?case=3&agent=Chrome/105.0.0.0 HTTP/1.1\r\nHost: 127.0.0.1:9001\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nOrigin: http://example.com\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Protocol: chat, superchat\r\nSec-WebSocket-Version: 13\r\n\r\n".*;
    var fbs = std.io.fixedBufferStream(&upgrade_request);
    var reader = fbs.reader();

    var parser = headerParser(reader);
    while (try parser.header()) |h| {
        std.debug.print("{s} => {s}\n", .{ h.key, h.value });
    }
}

const HeaderParser2 = struct {
    buf: []const u8,
    index: usize = 0,

    const Token = union(TokenTag) {
        status: Status,
        header: Header,
    };
    const TokenTag = enum {
        status,
        header,
    };
    const Header = struct {
        key: []const u8,
        value: []const u8,
    };
    const Status = struct {
        line: []const u8,
        pub fn tokens(self: Status) std.mem.TokenIterator(u8) {
            return std.mem.tokenize(u8, self.line, " \t");
        }
    };

    const Self = @This();

    pub fn init(buf: []const u8) Self {
        return .{ .buf = buf };
    }

    pub fn requestLine(self: *Self) ![]const u8 {
        const i = std.mem.indexOfScalar(u8, self.buf, '\n') orelse return error.InvalidHeader;
        var request_line = self.buf[0..i];
        if (std.mem.endsWith(u8, request_line, "\r")) {
            request_line = request_line[0 .. request_line.len - 1];
        }
    }

    pub fn next(self: *Self) ?Token {
        if (self.index == 0) {
            const i = std.mem.indexOfScalar(u8, self.buf, '\n') orelse return null;
            var request_line = self.buf[0..i];
            if (std.mem.endsWith(u8, request_line, "\r")) {
                request_line = request_line[0 .. request_line.len - 1];
            }
            self.index = i + 1;
            return Token{ .status = Status{ .line = request_line } };
        }
        const i = std.mem.indexOfScalar(u8, self.buf[self.index..], '\n') orelse return null;
        var header_line = self.buf[self.index .. self.index + i];
        if (std.mem.endsWith(u8, header_line, "\r")) {
            header_line = header_line[0 .. header_line.len - 1];
        }
        if (header_line.len == 0)
            return null;
        const sep = std.mem.indexOfScalar(u8, header_line, ':') orelse return null;

        const whitespace = " \t";
        const key = std.mem.trim(u8, header_line[0..sep], whitespace);
        const value = std.mem.trim(u8, header_line[sep + 1 ..], whitespace);
        self.index += i + 1;
        return Token{ .header = Header{ .key = key, .value = value } };
    }
};

test "headerParser2" {
    //var upgrade_request = "GET ws://127.0.0.1:9001/runCase?case=3&agent=Chrome/105.0.0.0 HTTP/1.1\r\nHost: 127.0.0.1:9001\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nOrigin: http://example.com\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Protocol: chat, superchat\r\nSec-WebSocket-Version: 13\r\n\r\n".*;
    var upgrade_request =
        \\HTTP/1.1 101 Switching Protocols
        \\Server: AutobahnTestSuite/0.8.2-0.10.9
        \\X-Powered-By: AutobahnPython/0.10.9
        \\Upgrade: WebSocket
        \\Connection: Upgrade
        \\Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=
        \\
    ;

    var p = HeaderParser2.init(&upgrade_request.*);
    const status = p.next().?.status;
    var tokens = status.tokens();
    try testing.expectEqualStrings("HTTP/1.1", tokens.next().?);
    try testing.expectEqualStrings("101", tokens.next().?);
    try testing.expectEqualStrings("Switching", tokens.next().?);
    try testing.expectEqualStrings("Protocols", tokens.next().?);
    try testing.expect(tokens.next() == null);

    var header = p.next().?.header;
    try testing.expectEqualStrings("Server", header.key);
    try testing.expectEqualStrings("AutobahnTestSuite/0.8.2-0.10.9", header.value);

    header = p.next().?.header;
    try testing.expectEqualStrings("X-Powered-By", header.key);
    try testing.expectEqualStrings("AutobahnPython/0.10.9", header.value);

    header = p.next().?.header;
    try testing.expectEqualStrings("Upgrade", header.key);
    try testing.expectEqualStrings("WebSocket", header.value);

    header = p.next().?.header;
    try testing.expectEqualStrings("Connection", header.key);
    try testing.expectEqualStrings("Upgrade", header.value);

    header = p.next().?.header;
    try testing.expectEqualStrings("Sec-WebSocket-Accept", header.key);
    try testing.expectEqualStrings("s3pPLMBiTxaQ9kYGzzhZRbK+xOo=", header.value);

    try testing.expect(p.next() == null);
}
