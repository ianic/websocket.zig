const std = @import("std");
const ws = @import("ws");
const mem = std.mem;
const net = std.net;
const crypto = std.crypto;
const tls = crypto.tls;

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const url = "wss://ws.vi-server.org/mirror/";

    var conn = try Connection.init(allocator, url);
    defer conn.deinit();

    var cli = try ws.client(allocator, conn.reader(), conn.writer(), url);
    defer cli.deinit();

    try cli.send(.text, "hello world", true);
    if (cli.nextMessage()) |msg| {
        defer msg.deinit();
        std.debug.print("{s}", .{msg.payload});
    }
    if (cli.err) |err| return err;
}

// Makes common reader/writer interface for tcp or tls connection.
const Connection = struct {
    tls_client: ?*tls.Client,
    tcp_stream: net.Stream,
    allocator: ?mem.Allocator,

    pub fn init(allocator: mem.Allocator, url: []const u8) !Connection {
        const uri = try std.Uri.parse(url);
        const hostname = uri.host.?;
        const is_wss = mem.eql(u8, uri.scheme, "wss");
        const port: u16 = uri.port orelse if (is_wss) 443 else 80;

        const tcp_stream = try net.tcpConnectToHost(allocator, hostname, port);

        var self = Connection{
            .tcp_stream = tcp_stream,
            .tls_client = null,
            .allocator = null,
        };

        if (is_wss) {
            var ca_bundle: crypto.Certificate.Bundle = .{};
            try ca_bundle.rescan(allocator);
            defer ca_bundle.deinit(allocator);

            var tls_client = try allocator.create(tls.Client);
            tls_client.* = try tls.Client.init(tcp_stream, ca_bundle, hostname);
            tls_client.allow_truncation_attacks = true;

            self.tls_client = tls_client;
            self.allocator = allocator;
        }
        return self;
    }

    pub fn deinit(self: Connection) void {
        self.tcp_stream.close();
        if (self.tls_client) |tc| {
            self.allocator.?.destroy(tc);
        }
    }

    pub const ReadError = error{
        AccessDenied,
        Unexpected,
        SystemResources,
        IsDir,
        WouldBlock,
        InputOutput,
        OperationAborted,
        BrokenPipe,
        ConnectionResetByPeer,
        ConnectionTimedOut,
        NotOpenForReading,
        NetNameDeleted,
        Overflow,
        TlsConnectionTruncated,
        TlsRecordOverflow,
        TlsDecodeError,
        TlsAlertUnexpectedMessage,
        TlsAlertBadRecordMac,
        TlsAlertRecordOverflow,
        TlsAlertHandshakeFailure,
        TlsAlertBadCertificate,
        TlsAlertUnsupportedCertificate,
        TlsAlertCertificateRevoked,
        TlsAlertCertificateExpired,
        TlsAlertCertificateUnknown,
        TlsAlertIllegalParameter,
        TlsAlertUnknownCa,
        TlsAlertAccessDenied,
        TlsAlertDecodeError,
        TlsAlertDecryptError,
        TlsAlertProtocolVersion,
        TlsAlertInsufficientSecurity,
        TlsAlertInternalError,
        TlsAlertInappropriateFallback,
        TlsAlertMissingExtension,
        TlsAlertUnsupportedExtension,
        TlsAlertUnrecognizedName,
        TlsAlertBadCertificateStatusResponse,
        TlsAlertUnknownPskIdentity,
        TlsAlertCertificateRequired,
        TlsAlertNoApplicationProtocol,
        TlsAlertUnknown,
        TlsUnexpectedMessage,
        TlsBadRecordMac,
        TlsBadLength,
        TlsIllegalParameter,
    };

    pub const Reader = std.io.Reader(*Connection, (ReadError || error{SocketNotConnected}), read);

    pub fn reader(req: *Connection) Reader {
        return .{ .context = req };
    }

    pub fn read(w: *Connection, buffer: []u8) !usize {
        if (w.tls_client) |tc| {
            return tc.read(w.tcp_stream, buffer);
        }
        return w.tcp_stream.read(buffer);
    }

    pub const WriteError = error{
        AccessDenied,
        Unexpected,
        SystemResources,
        FileTooBig,
        NoSpaceLeft,
        DeviceBusy,
        WouldBlock,
        InputOutput,
        OperationAborted,
        BrokenPipe,
        ConnectionResetByPeer,
        DiskQuota,
        InvalidArgument,
        NotOpenForWriting,
        LockViolation,
    };
    pub const Writer = std.io.Writer(*Connection, WriteError, write);

    pub fn writer(req: *Connection) Writer {
        return .{ .context = req };
    }

    pub fn write(w: *Connection, bytes: []const u8) !usize {
        if (w.tls_client) |tc| {
            return tc.write(w.tcp_stream, bytes);
        }
        return w.tcp_stream.write(bytes);
    }
};
