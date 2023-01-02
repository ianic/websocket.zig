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
    const path = try std.fmt.bufPrint(&path_buf, "/runCase?case={d}&agent=websocket_test.zig", .{no});

    var tcp_stm = try std.net.tcpConnectToHost(allocator, "127.0.0.1", 9001);
    var stm = try ws.client(
        allocator,
        tcp_stm.reader(),
        tcp_stm.writer(),
        "127.0.0.1:9001",
        path,
    );
    defer stm.deinit();
    defer tcp_stm.close();

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
