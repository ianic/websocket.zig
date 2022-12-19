const std = @import("std");
const ws = @import("websocket");

const Group = struct {
    cases: u8,
    desc: []const u8,

    pub fn descStartsWith(self: Group, needle: []const u8) bool {
        return std.ascii.startsWithIgnoreCase(self.desc, needle);
    }
};

const tests_groups = [_]Group{
    // 1 Framing
    .{ .cases = 8, .desc = "1.1 Text Messages" },
    .{ .cases = 8, .desc = "1.2 Binary Messages" },
    // 2 Pings/Pongs
    .{ .cases = 11, .desc = "2 Pings/Pongs" },
    // 3 Reserved Bits
    .{ .cases = 7, .desc = "3 Reserved Bits" },
    // 4 Opcodes
    .{ .cases = 5, .desc = "4.1 Non-control Opcodes" },
    .{ .cases = 5, .desc = "4.2 Control Opcodes" },
    // 5 Fragmentation
    .{ .cases = 20, .desc = "5 Fragmentation" },
    // 6 UTF-8 Handling
    .{ .cases = 3, .desc = "6.1 Valid UTF-8 with zero payload fragments" },
    .{ .cases = 4, .desc = "6.2 Valid UTF-8 unfragmented, fragmented on code-points and within code-points" },
    .{ .cases = 2, .desc = "6.3 Invalid UTF-8 differently fragmented" },
    .{ .cases = 4, .desc = "6.4 Fail-fast on invalid UTF-8" },
    .{ .cases = 5, .desc = "6.5 Some valid UTF-8 sequences" },
    .{ .cases = 11, .desc = "6.6 All prefixes of a valid UTF-8 string that contains multi-byte code points" },
    .{ .cases = 4, .desc = "6.7 First possible sequence of a certain length" },
    .{ .cases = 2, .desc = "6.8 First possible sequence length 5/6 (invalid codepoints)" },
    .{ .cases = 4, .desc = "6.9 Last possible sequence of a certain length" },
    .{ .cases = 3, .desc = "6.10 Last possible sequence length 4/5/6 (invalid codepoints)" },
    .{ .cases = 5, .desc = "6.11 Other boundary conditions" },
    .{ .cases = 8, .desc = "6.12 Unexpected continuation bytes" },
    .{ .cases = 5, .desc = "6.13 Lonely start characters" },
    .{ .cases = 10, .desc = "6.14 Sequences with last continuation byte missing" },
    .{ .cases = 1, .desc = "6.15 Concatenation of incomplete sequences" },
    .{ .cases = 3, .desc = "6.16 Impossible bytes" },
    .{ .cases = 5, .desc = "6.17 Examples of an overlong ASCII characte" },
    .{ .cases = 5, .desc = "6.18 Maximum overlong sequences" },
    .{ .cases = 5, .desc = "6.19 Overlong representation of the NUL character" },
    .{ .cases = 7, .desc = "6.20 Single UTF-16 surrogates" },
    .{ .cases = 8, .desc = "6.21 Paired UTF-16 surrogates" },
    .{ .cases = 34, .desc = "6.22 Non-character code points (valid UTF-8)" },
    .{ .cases = 7, .desc = "6.23 Unicode specials (i.e. replacement char)" },
    // 7 Close Handling
    .{ .cases = 6, .desc = "7.1 Basic close behavior (fuzzer initiated)" },
    .{ .cases = 6, .desc = "7.3 Close frame structure: payload length (fuzzer initiated)" },
    .{ .cases = 1, .desc = "7.5 Close frame structure: payload value (fuzzer initiated)" },
    .{ .cases = 13, .desc = "7.7 Close frame structure: valid close codes (fuzzer initiated)" },
    .{ .cases = 9, .desc = "7.9 Close frame structure: invalid close codes (fuzzer initiated)" },
    .{ .cases = 2, .desc = "7.13 Informational close information (fuzzer initiated)" },
    // 9 Limits/Performance
    // 10 Misc
    // 12 WebSocket Compression (different payloads)
    // 13 WebSocket Compression (different parameters)
};

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var case_no: usize = 0;
    for (tests_groups) |group| {
        var group_case: usize = 0;
        while (group_case < group.cases) : (group_case += 1) {
            case_no += 1;
            // if (group.descStartsWith("6.") or
            //     group.descStartsWith("7.") or
            //     group.descStartsWith("5"))
            //     continue;
            // if (!group.descStartsWith("4")) {
            //     continue;
            // }
            // if (case_no != 73) {
            //     continue;
            // }
            std.log.debug("running case no: {d} {s} {d} ", .{ case_no, group.desc, group_case + 1 });
            try runTestCase(case_no, allocator);
        }
    }
}

const Client = ws.Client(17 * 4096); // buf size, this is because there are tests with 16 * 4096 payload size)

fn runTestCase(no: usize, allocator: std.mem.Allocator) !void {
    var path_buf: [128]u8 = undefined;
    const path = try std.fmt.bufPrint(&path_buf, "/runCase?case={d}&agent=2.zig", .{no});

    var client = try Client.init("127.0.0.1", 9001, path);
    // while (client.readFrame()) |frame| {
    //     try client.echoFrame(frame);
    // }
    while (client.readMsg(allocator)) |msg| {
        defer msg.deinit(allocator);
        //defer allocator.free(msg.frames);
        try client.echoMsg(msg);
    }
    if (client.err) |err| {
        std.log.err("case: {d} {}", .{ no, err });
    }
}
