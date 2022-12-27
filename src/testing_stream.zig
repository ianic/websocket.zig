const std = @import("std");
const io = std.io;
const mem = std.mem;

pub fn TestingStream(comptime output_len: usize) type {
    return struct {
        read_pos: usize = 0,
        write_pos: usize = 0,
        output: [output_len]u8 = undefined,
        input: []const u8,

        pub const ReadError = error{};
        pub const WriteError = error{NoSpaceLeft};

        pub const Reader = io.Reader(*Self, ReadError, read);
        pub const Writer = io.Writer(*Self, WriteError, write);

        const Self = @This();

        pub fn init(input_buf: []const u8) Self {
            return .{ .input = input_buf };
        }

        pub fn reader(self: *Self) Reader {
            return .{ .context = self };
        }

        pub fn writer(self: *Self) Writer {
            return .{ .context = self };
        }

        pub fn read(self: *Self, dest: []u8) ReadError!usize {
            //        std.debug.print("read input.len: {d}, read_pos: {d}\n", .{ self.input.len, self.read_pos });
            const size = std.math.min(dest.len, self.input.len - self.read_pos);
            const end = self.read_pos + size;

            mem.copy(u8, dest[0..size], self.input[self.read_pos..end]);
            self.read_pos = end;

            return size;
        }

        pub fn write(self: *Self, bytes: []const u8) WriteError!usize {
            if (bytes.len == 0) return 0;
            if (self.write_pos >= self.output.len) return error.NoSpaceLeft;

            const n = if (self.write_pos + bytes.len <= self.output.len)
                bytes.len
            else
                self.output.len - self.write_pos;

            mem.copy(u8, self.output[self.write_pos .. self.write_pos + n], bytes[0..n]);
            self.write_pos += n;

            if (n == 0) return error.NoSpaceLeft;

            return n;
        }

        pub fn written(self: *Self) []const u8 {
            return self.output[0..self.write_pos];
        }
    };
}

const default_output_len = 4096;

pub fn init(input: []const u8) TestingStream(default_output_len) {
    return TestingStream(default_output_len).init(input);
}
