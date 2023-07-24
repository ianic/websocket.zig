const std = @import("std");
const ws = @import("ws");
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
        const start = std.time.milliTimestamp();

        try runTestCase(allocator, case_no);
        const durationMs = std.time.milliTimestamp() - start;
        if (durationMs > 100) {
            std.debug.print("{d}/{d} {d}ms\n", .{ case_no, cases_count, durationMs });
        }
    }
    std.debug.print("\n", .{});
}

fn runTestCase(allocator: Allocator, no: usize) !void {
    var uri_buf: [128]u8 = undefined;
    const hostname = "localhost";
    const port = 9001;
    const uri = try std.fmt.bufPrint(&uri_buf, "ws://{s}:{d}/runCase?case={d}&agent=websocket_test.zig", .{ hostname, port, no });

    var tcp = try std.net.tcpConnectToHost(allocator, hostname, port);
    defer tcp.close();
    var cli = try ws.client(allocator, tcp.reader(), tcp.writer(), uri);
    defer cli.deinit();

    // echo loop read and send message
    while (cli.nextMessage()) |msg| {
        defer msg.deinit();
        try cli.sendMessage(msg);
    }
    if (cli.err) |_| {
        std.debug.print("e", .{});
        //std.log.err("case: {d} {}", .{ no, err });
    } else {
        std.debug.print(".", .{});
    }
}
