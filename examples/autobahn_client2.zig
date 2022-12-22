const std = @import("std");
const ws = @import("websocket");
const assert = std.debug.assert;

pub fn main() !void {
    assert(std.os.argv.len > 1);

    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    const cases_count = try std.fmt.parseUnsigned(usize, args[1], 10);
    std.log.debug("number of test cases: {d}", .{cases_count});

    const buf_size = 16 * 1024 * 1024 + 1024;
    var read_buf = try allocator.alloc(u8, buf_size);
    var write_buf = try allocator.alloc(u8, buf_size);
    defer allocator.free(read_buf);
    defer allocator.free(write_buf);

    var case_no: usize = 1;
    while (case_no <= cases_count) : (case_no += 1) {
        //std.log.debug("running case no: {d}", .{case_no});
        try runTestCase(read_buf, write_buf, case_no);
    }
    std.debug.print("\n", .{});
}

fn runTestCase(read_buf: []u8, write_buf: []u8, no: usize) !void {
    var path_buf: [128]u8 = undefined;
    const path = try std.fmt.bufPrint(&path_buf, "/runCase?case={d}&agent=websocket.zig", .{no});

    var client = try ws.Client.init(read_buf, write_buf, "127.0.0.1", 9001, path);

    // echo loop read and send message
    while (client.readMessage()) |msg| {
        try client.sendMessage(msg);
    }
    if (client.err) |_| {
        std.debug.print("e", .{});
        //std.log.err("case: {d} {}", .{ no, err });
    } else {
        std.debug.print(".", .{});
    }
}
