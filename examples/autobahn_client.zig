const std = @import("std");
const ws = @import("websocket");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;

pub fn main() !void {
    assert(std.os.argv.len > 1);

    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    const cases_count = try std.fmt.parseUnsigned(usize, args[1], 10);
    std.log.debug("number of test cases: {d}", .{cases_count});

    var case_no: usize = 1;
    while (case_no <= cases_count) : (case_no += 1) {
        //std.debug.print("running case no: {d}\n", .{case_no});
        try runTestCase(allocator, case_no);
    }
    std.debug.print("\n", .{});
}

fn runTestCase(allocator: Allocator, no: usize) !void {
    var path_buf: [128]u8 = undefined;
    const path = try std.fmt.bufPrint(&path_buf, "/runCase?case={d}&agent=websocket.zig", .{no});

    var tcp_client = try TcpClient.init("127.0.0.1", 9001);
    var stm = try ws.client(
        allocator,
        tcp_client.client.reader(0),
        tcp_client.client.writer(0),
        "127.0.0.1:9001",
        path,
    );
    defer stm.deinit();
    defer tcp_client.close();

    // echo loop read and send message
    while (stm.nextMessage()) |msg| {
        try stm.sendMessage(msg);
    }
    if (stm.err) |_| {
        std.debug.print("e", .{});
        //std.log.err("case: {d} {}", .{ no, err });
    } else {
        std.debug.print(".", .{});
    }
}

const tcp = net.tcp;
const net = std.x.net;

pub const TcpClient = struct {
    client: tcp.Client,

    const Self = @This();

    pub fn init(host: []const u8, port: u16) !Self {
        const addr = net.ip.Address.initIPv4(try std.x.os.IPv4.parse(host), port);
        const client = try tcp.Client.init(.ip, .{ .close_on_exec = true });
        try client.connect(addr);
        errdefer client.deinit();
        return .{ .client = client };
    }

    pub fn reader(self: *Self) tcp.Client.Reader {
        return self.client.reader(0);
    }

    pub fn writer(self: *Self) tcp.Client.Writer {
        return self.client.writer(0);
    }

    pub fn close(self: *Self) void {
        self.client.shutdown(.both) catch {};
        self.client.deinit();
    }
};
