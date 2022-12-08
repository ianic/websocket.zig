const std = @import("std");
const testing = std.testing;
const assert = std.debug.assert;
const ascii = std.ascii;

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

    try testing.expect(p.isValidWSResponse(sec_key));

    // // print headers
    // var iter = p.headerIter();
    // std.debug.print("\n", .{});
    // while (iter.next()) |h| {
    //     std.debug.print("header: {s} {s}\n", .{ h.key, h.value });
    // }
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
        const sp1 = std.mem.indexOfScalar(u8, status_line, ' ') orelse return error.InvalidHttpResponse;
        const sp2 = std.mem.indexOfScalarPos(u8, status_line, sp1 + 1, ' ') orelse return error.InvalidHttpResponse;
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

    pub fn isValidWSResponse(self: *Self, sec_key: []const u8) bool {
        if (!std.mem.eql(u8, self.status, "101")) return false;

        var iter = self.headerIter();
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
    const eol = std.mem.indexOfScalarPos(u8, buffer, si, '\n') orelse return error.InvalidHttpResponse;
    var line = buffer[si..eol];
    start_index.* += line.len + 1;
    if (std.mem.endsWith(u8, line, "\r")) {
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
        const sep = std.mem.indexOfScalar(u8, header_line, ':') orelse return null;
        //std.debug.print("header_line: {s} {d}\n", .{ header_line, self.index });

        const whitespace = " \t";
        const key = std.mem.trim(u8, header_line[0..sep], whitespace);
        const value = std.mem.trim(u8, header_line[sep + 1 ..], whitespace);

        return Header{ .key = key, .value = value };
    }
};
