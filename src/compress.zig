const std = @import("std");
const io = std.io;
const mem = std.mem;
const deflate = std.compress.deflate;

const assert = std.debug.assert;
const testing = std.testing;

const deflate_tail = [_]u8{ 0x0, 0x0, 0xff, 0xff };

const Compressor = struct {
    const Writer = std.io.Writer(*Compressor, error{OutOfMemory}, write);

    inner: ?deflate.Compressor(Writer) = null,
    buf: ?[]u8 = null,
    alloc: mem.Allocator,

    pub fn init(alloc: mem.Allocator) Compressor {
        return .{
            .alloc = alloc,
        };
    }

    fn writer(self: *Compressor) Writer {
        return .{ .context = self };
    }

    fn write(self: *Compressor, m: []const u8) mem.Allocator.Error!usize {
        if (self.buf) |b| {
            var buf = try self.alloc.realloc(b, b.len + m.len);
            @memcpy(buf[b.len..], m);
            self.buf = buf;
            return m.len;
        }
        var buf = try self.alloc.alloc(u8, m.len);
        @memcpy(buf, m);
        self.buf = buf;
        return m.len;
    }

    pub fn compress(self: *Compressor, data: []const u8) ![]u8 {
        if (self.inner == null)
            self.inner = try deflate.compressor(self.alloc, self.writer(), .{});

        try self.inner.?.writer().writeAll(data);
        try self.inner.?.close();
        var buf = self.buf.?;
        self.buf = null;
        errdefer self.alloc.free(buf);
        return try self.alloc.realloc(buf, buf.len - deflate_tail.len);
    }

    pub fn deinit(self: *Compressor) void {
        if (self.inner) |*i| i.deinit();
        if (self.buf) |b|
            self.alloc.free(b);
    }
};

const Decompressor = struct {
    const Reader = std.io.Reader(*Decompressor, mem.Allocator.Error, read);
    const ReadError = error{};

    alloc: mem.Allocator,
    inner: ?deflate.Decompressor(Reader) = null,
    buf: ?[]const u8 = null,
    pos: usize = 0,

    pub fn init(alloc: mem.Allocator) Decompressor {
        return .{ .alloc = alloc };
    }

    pub fn reader(self: *Decompressor) Reader {
        return .{ .context = self };
    }

    pub fn read(self: *Decompressor, dest: []u8) ReadError!usize {
        if (self.buf) |buf| {
            if (self.pos == buf.len + deflate_tail.len) {
                // done buf and tail
                return 0;
            }
            if (self.pos > buf.len) {
                // buf done, copy tail
                const tail_pos = self.pos - buf.len;
                const size = @min(dest.len, deflate_tail.len - tail_pos);
                @memcpy(dest[0..size], deflate_tail[tail_pos .. tail_pos + size]);
                self.pos += size;
                return size;
            }
            // copy buf
            var size = @min(dest.len, buf.len - self.pos);
            const end = self.pos + size;
            @memcpy(dest[0..size], buf[self.pos..end]);
            self.pos = end;

            if (self.pos == buf.len and dest.len > size) {
                // buf done there is space for tail (or part of the tail)
                const tail_size = @min(dest.len - size, deflate_tail.len);
                @memcpy(dest[size .. size + tail_size], deflate_tail[0..tail_size]);
                size += tail_size;
                self.pos += tail_size;
            }

            return size;
        }
        return 0;
    }

    pub fn decompress(self: *Decompressor, data: []const u8) ![]u8 {
        if (self.inner == null)
            self.inner = try deflate.decompressor(self.alloc, self.reader(), null);

        self.buf = data;
        self.pos = 0;
        var out = try self.inner.?.reader().readAllAlloc(self.alloc, std.math.maxInt(usize));
        self.buf = null;
        self.pos = 0;
        return out;
    }

    pub fn deinit(self: *Decompressor) void {
        if (self.inner) |*i| i.deinit();
    }
};

test "Compressor/Decompressor" {
    const alloc = testing.allocator;
    const input = "Hello";

    var cmp = Compressor.init(alloc);
    defer cmp.deinit();
    var compressed = try cmp.compress(input);
    defer alloc.free(compressed);
    try testing.expectEqualSlices(u8, compressed, &[_]u8{ 0xf2, 0x48, 0xcd, 0xc9, 0xc9, 0x07, 0x04 });

    var dcp = Decompressor.init(alloc);
    defer dcp.deinit();
    var decompressed = try dcp.decompress(compressed);
    defer alloc.free(decompressed);
    try testing.expectEqualSlices(u8, decompressed, input);
}

test "deflate compress/decompress" {
    const allocator = testing.allocator;
    const input = "Hello";

    var compressor_stm = std.ArrayList(u8).init(allocator);
    defer compressor_stm.deinit();
    var comp = try deflate.compressor(allocator, compressor_stm.writer(), .{});
    defer comp.deinit();
    _ = try comp.write(input);
    try comp.close();
    var compressed = compressor_stm.items;
    //showBuf(compressed);
    try testing.expectEqualSlices(u8, compressed, &[_]u8{ 0xf2, 0x48, 0xcd, 0xc9, 0xc9, 0x07, 0x04, 0x00, 0x00, 0xff, 0xff });

    var decompressor_stm = io.fixedBufferStream(compressed);
    var decomp = try deflate.decompressor(allocator, decompressor_stm.reader(), null);
    defer decomp.deinit();

    var decompressed = try decomp.reader().readAllAlloc(allocator, std.math.maxInt(usize));
    defer allocator.free(decompressed);
    try testing.expectEqual(input.len, decompressed.len);
    try testing.expectEqualSlices(u8, input, decompressed);
}
