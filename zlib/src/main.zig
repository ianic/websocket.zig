// reference: https://zlib.net/manual.html#Advanced

const std = @import("std");
const builtin = @import("builtin");
const c = @cImport({
    @cInclude("zlib.h");
    @cInclude("stddef.h");
});

const alignment = @alignOf(c.max_align_t);
const Allocator = std.mem.Allocator;

pub const Error = error{
    StreamEnd,
    NeedDict,
    Errno,
    StreamError,
    DataError,
    MemError,
    BufError,
    VersionError,
    OutOfMemory,
    Unknown,
};

pub fn errorFromInt(val: c_int) Error {
    return switch (val) {
        c.Z_STREAM_END => error.StreamEnd,
        c.Z_NEED_DICT => error.NeedDict,
        c.Z_ERRNO => error.Errno,
        c.Z_STREAM_ERROR => error.StreamError,
        c.Z_DATA_ERROR => error.DataError,
        c.Z_MEM_ERROR => error.MemError,
        c.Z_BUF_ERROR => error.BufError,
        c.Z_VERSION_ERROR => error.VersionError,
        else => error.Unknown,
    };
}

pub fn checkRC(val: c_int) Error!void {
    if (val == c.Z_OK) return;
    return errorFromInt(val);
}

// method is copied from pfg's https://gist.github.com/pfgithub/65c13d7dc889a4b2ba25131994be0d20
// we have a header for each allocation that records the length, which we need
// for the allocator. Assuming that there aren't many small allocations this is
// acceptable overhead.
const magic_value = 0x1234;
const ZallocHeader = struct {
    magic: usize,
    size: usize,

    const size_of_aligned = (std.math.divCeil(usize, @sizeOf(ZallocHeader), alignment) catch unreachable) * alignment;
};

comptime {
    if (@alignOf(ZallocHeader) > alignment) {
        @compileError("header has incorrect alignment");
    }
}

fn zalloc(private: ?*anyopaque, items: c_uint, size: c_uint) callconv(.C) ?*anyopaque {
    if (private == null)
        return null;

    const allocator: *Allocator = @ptrCast(@alignCast(private.?));
    var buf = allocator.allocWithOptions(u8, ZallocHeader.size_of_aligned + (items * size), @alignOf(*ZallocHeader), null) catch return null;
    const header: *ZallocHeader = @ptrCast(@alignCast(buf.ptr));
    header.* = .{
        .magic = magic_value,
        .size = items * size,
    };

    return buf[ZallocHeader.size_of_aligned..].ptr;
}

fn zfree(private: ?*anyopaque, addr: ?*anyopaque) callconv(.C) void {
    if (private == null)
        return;

    const allocator: *Allocator = @ptrCast(@alignCast(private.?));
    const header = @as(*ZallocHeader, @ptrFromInt(@intFromPtr(addr.?) - ZallocHeader.size_of_aligned));

    if (builtin.mode != .ReleaseFast) {
        if (header.magic != magic_value)
            @panic("magic value is incorrect");
    }

    var buf: []align(alignment) u8 = undefined;
    buf.ptr = @as([*]align(alignment) u8, @ptrCast(header));
    buf.len = ZallocHeader.size_of_aligned + header.size;
    allocator.free(buf);
}

pub fn compressorWriter(allocator: Allocator, writer: anytype, options: CompressorOptions) Error!CompressorWriter(@TypeOf(writer)) {
    return CompressorWriter(@TypeOf(writer)).init(allocator, writer, options);
}

pub fn decompressorReader(allocator: Allocator, writer: anytype, options: DecompressorOptions) Error!DecompressorReader(@TypeOf(writer)) {
    return DecompressorReader(@TypeOf(writer)).init(allocator, writer, options);
}

fn zStreamInit(allocator: Allocator) !*c.z_stream {
    var stream: *c.z_stream = try allocator.create(c.z_stream);
    errdefer allocator.destroy(stream);

    // if the user provides an allocator zlib uses an opaque pointer for
    // custom malloc an free callbacks, this requires pinning, so we use
    // the allocator to allocate the Allocator struct on the heap
    const pinned = try allocator.create(Allocator);
    errdefer allocator.destroy(pinned);

    pinned.* = allocator;
    stream.@"opaque" = pinned;
    stream.zalloc = zalloc;
    stream.zfree = zfree;
    return stream;
}

fn zStreamDeinit(allocator: Allocator, stream: *c.z_stream) void {
    const pinned: *Allocator = @ptrCast(@alignCast(stream.@"opaque".?));
    allocator.destroy(pinned);
    allocator.destroy(stream);
}

pub const CompressorOptions = struct {
    const HeaderOptions = enum {
        none, // raw deflate data with no zlib header or trailer
        zlib,
        gzip, // to write a simple gzip header and trailer around the compressed data instead of a zlib wrapper
    };
    compression_level: c_int = c.Z_DEFAULT_COMPRESSION,

    // memLevel=1 uses minimum memory but is slow and reduces compression ratio; memLevel=9 uses maximum memory for optimal speed. The default value is 8.
    memory_level: c_int = 8,

    strategy: c_int = c.Z_DEFAULT_STRATEGY,

    header: HeaderOptions = .zlib,
    window_size: u4 = 15, // in the range 9..15, base two logarithm of the maximum window size (the size of the history buffer).

    const Self = @This();

    pub fn windowSize(self: Self) i6 {
        var ws = @as(i6, if (self.window_size < 9) 9 else self.window_size);
        return switch (self.header) {
            .zlib => ws,
            .none => -@as(i6, ws),
            .gzip => ws + 16,
        };
    }
};

pub fn CompressorWriter(comptime WriterType: type) type {
    return struct {
        allocator: Allocator,
        stream: *c.z_stream,
        inner: WriterType,

        const Self = @This();
        const WriterError = Error || WriterType.Error;
        const Writer = std.io.Writer(*Self, WriterError, write);

        pub fn init(allocator: Allocator, inner_writer: WriterType, opt: CompressorOptions) !Self {
            var stream = try zStreamInit(allocator);
            errdefer zStreamDeinit(allocator, stream);

            try checkRC(c.deflateInit2(
                stream,
                opt.compression_level,
                c.Z_DEFLATED, // only option
                opt.windowSize(),
                opt.memory_level,
                opt.strategy,
            ));

            return .{ .allocator = allocator, .stream = stream, .inner = inner_writer };
        }

        pub fn deinit(self: *Self) void {
            _ = c.deflateEnd(self.stream);
            zStreamDeinit(self.allocator, self.stream);
        }

        pub fn flush(self: *Self) !void {
            var tmp: [4096]u8 = undefined;
            while (true) {
                self.stream.next_out = &tmp;
                self.stream.avail_out = tmp.len;
                var rc = c.deflate(self.stream, c.Z_FINISH);
                if (rc != c.Z_STREAM_END)
                    return errorFromInt(rc);

                if (self.stream.avail_out != 0) {
                    const n = tmp.len - self.stream.avail_out;
                    try self.inner.writeAll(tmp[0..n]);
                    break;
                } else try self.inner.writeAll(&tmp);
            }
        }

        pub fn write(self: *Self, buf: []const u8) WriterError!usize {
            var tmp: [4096]u8 = undefined;

            // uncompressed
            self.stream.next_in = @as([*]u8, @ptrFromInt(@intFromPtr(buf.ptr)));
            self.stream.avail_in = @as(c_uint, @intCast(buf.len));

            while (true) {
                // compressed
                self.stream.next_out = &tmp;
                self.stream.avail_out = tmp.len;
                var rc = c.deflate(self.stream, c.Z_PARTIAL_FLUSH);
                if (rc != c.Z_OK)
                    return errorFromInt(rc);

                if (self.stream.avail_out != 0) {
                    const n = tmp.len - self.stream.avail_out;
                    try self.inner.writeAll(tmp[0..n]);
                    break;
                } else try self.inner.writeAll(&tmp);
            }

            return buf.len - self.stream.avail_in;
        }

        pub fn writer(self: *Self) Writer {
            return .{ .context = self };
        }
    };
}

pub const DecompressorOptions = struct {
    const HeaderOptions = enum {
        none, // raw deflate data with no zlib header or trailer,
        zlib_or_gzip,
    };

    header: HeaderOptions = .zlib_or_gzip,
    window_size: u4 = 15, // in the range 8..15, base two logarithm of the maximum window size (the size of the history buffer).

    const Self = @This();

    pub fn windowSize(self: Self) i5 {
        var ws = if (self.window_size < 8) 15 else self.window_size;
        return if (self.header == .none) -@as(i5, ws) else ws;
    }
};

pub fn DecompressorReader(comptime ReaderType: type) type {
    return struct {
        allocator: Allocator,
        stream: *c.z_stream,
        inner: ReaderType,
        tmp: [4096]u8 = undefined,
        pos: usize = 0,

        const Self = @This();
        const ReaderError = Error || ReaderType.Error;
        const Reader = std.io.Reader(*Self, ReaderError, read);

        pub fn init(allocator: Allocator, inner_reader: ReaderType, options: DecompressorOptions) !Self {
            var stream = try zStreamInit(allocator);
            errdefer zStreamDeinit(allocator, stream);

            const rc = c.inflateInit2(stream, options.windowSize());
            if (rc != c.Z_OK) return errorFromInt(rc);

            return .{
                .allocator = allocator,
                .stream = stream,
                .inner = inner_reader,
            };
        }

        pub fn deinit(self: *Self) void {
            _ = c.inflateEnd(self.stream);
            zStreamDeinit(self.allocator, self.stream);
        }

        pub fn reset(self: *Self) void {
            const rc = c.inflateReset(self.stream);
            if (rc != c.Z_OK) return errorFromInt(rc);
        }

        pub fn read(self: *Self, buf: []u8) ReaderError!usize {
            //std.debug.print("pos: {d} buf.len {d}\n", .{ self.pos, buf.len });
            self.pos += try self.inner.readAll(self.tmp[self.pos..]);

            self.stream.next_in = &self.tmp;
            self.stream.avail_in = @as(c_uint, @intCast(self.pos));

            self.stream.next_out = @as([*]u8, @ptrFromInt(@intFromPtr(buf.ptr)));
            self.stream.avail_out = @as(c_uint, @intCast(buf.len));

            var rc = c.inflate(self.stream, c.Z_SYNC_FLUSH);
            if (rc != c.Z_OK and rc != c.Z_STREAM_END)
                return errorFromInt(rc);

            if (self.stream.avail_in != 0) {
                const done_pos = self.pos - self.stream.avail_in;
                std.mem.copy(u8, self.tmp[0..], self.tmp[done_pos..]);
                self.pos = self.tmp[done_pos..].len;
            }

            return buf.len - self.stream.avail_out;
        }

        pub fn reader(self: *Self) Reader {
            return .{ .context = self };
        }
    };
}

pub const Compressor = struct {
    allocator: Allocator,
    stream: *c.z_stream,

    const Self = @This();

    pub fn init(allocator: Allocator, opt: CompressorOptions) !Self {
        var stream = try zStreamInit(allocator);
        errdefer zStreamDeinit(allocator, stream);
        try checkRC(c.deflateInit2(
            stream,
            opt.compression_level,
            c.Z_DEFLATED, // only option
            opt.windowSize(),
            opt.memory_level,
            opt.strategy,
        ));
        return .{ .allocator = allocator, .stream = stream };
    }

    pub fn deinit(self: *Self) void {
        _ = c.deflateEnd(self.stream);
        zStreamDeinit(self.allocator, self.stream);
    }

    pub fn reset(self: *Self) !void {
        try checkRC(c.deflateReset(self.stream));
    }

    // Compresses to new allocated buffer.
    // Caller owns returned memory.
    pub fn compressAllAlloc(self: *Self, uncompressed: []const u8) ![]u8 {
        self.stream.next_in = @as([*]u8, @ptrFromInt(@intFromPtr(uncompressed.ptr)));
        self.stream.avail_in = @as(c_uint, @intCast(uncompressed.len));

        var tmp = try self.allocator.alloc(u8, chunk_size);
        var len: usize = 0; // used part of the tmp buffer

        var flag = c.Z_PARTIAL_FLUSH;
        while (true) {
            var out = tmp[len..];
            self.stream.next_out = @as([*]u8, @ptrFromInt(@intFromPtr(out.ptr)));
            self.stream.avail_out = @as(c_uint, @intCast(out.len));

            var rc = c.deflate(self.stream, flag);
            if (rc != c.Z_OK and rc != c.Z_STREAM_END)
                return errorFromInt(rc);

            len += out.len - self.stream.avail_out;
            if (self.stream.avail_out == 0) { // out is full
                tmp = try self.allocator.realloc(tmp, tmp.len * 2);
                continue;
            }

            if (flag == c.Z_SYNC_FLUSH) break;
            flag = c.Z_SYNC_FLUSH;
        }
        return try self.allocator.realloc(tmp, len);
    }
};

const chunk_size = 4096;

pub const Decompressor = struct {
    allocator: Allocator,
    stream: *c.z_stream,

    const Self = @This();

    pub fn init(allocator: Allocator, options: DecompressorOptions) !Self {
        var stream = try zStreamInit(allocator);
        errdefer zStreamDeinit(allocator, stream);
        try checkRC(c.inflateInit2(stream, options.windowSize()));
        return .{ .allocator = allocator, .stream = stream };
    }

    pub fn deinit(self: *Self) void {
        _ = c.inflateEnd(self.stream);
        zStreamDeinit(self.allocator, self.stream);
    }

    pub fn reset(self: *Self) !void {
        try checkRC(c.inflateReset(self.stream));
    }

    // Decompresses to new allocated buffer.
    // Caller owns returned memory.
    pub fn decompressAllAlloc(self: *Self, compressed: []const u8) ![]u8 {
        self.stream.next_in = @as([*]u8, @ptrFromInt(@intFromPtr(compressed.ptr)));
        self.stream.avail_in = @as(c_uint, @intCast(compressed.len));

        var tmp = try self.allocator.alloc(u8, chunk_size);
        var len: usize = 0; // inflated part of the tmp buffer
        while (true) {
            var out = tmp[len..];
            self.stream.next_out = @as([*]u8, @ptrFromInt(@intFromPtr(out.ptr)));
            self.stream.avail_out = @as(c_uint, @intCast(out.len));

            var rc = c.inflate(self.stream, c.Z_SYNC_FLUSH);
            if (rc != c.Z_OK and rc != c.Z_STREAM_END) {
                return errorFromInt(rc);
            }
            len += out.len - self.stream.avail_out;
            if (self.stream.avail_in != 0 and self.stream.avail_out == 0) { // in not empty, out full
                tmp = try self.allocator.realloc(tmp, tmp.len * 2); // make more space
                continue;
            }
            break;
        }
        return try self.allocator.realloc(tmp, len);
    }
};

test "compress gzip with zig interface" {
    const allocator = std.testing.allocator;
    var fifo = std.fifo.LinearFifo(u8, .Dynamic).init(allocator);
    defer fifo.deinit();

    // compress with zlib
    const input = @embedFile("rfc1951.txt");
    var cmp = try compressorWriter(allocator, fifo.writer(), .{ .header = .gzip });
    defer cmp.deinit();
    const writer = cmp.writer();
    try writer.writeAll(input);
    try cmp.flush();

    // decompress with zig std lib gzip
    var dcmp = try std.compress.gzip.decompress(allocator, fifo.reader());
    defer dcmp.deinit();
    const actual = try dcmp.reader().readAllAlloc(allocator, std.math.maxInt(usize));
    defer allocator.free(actual);

    try std.testing.expectEqualStrings(input, actual);
}

test "compress/decompress" {
    const allocator = std.testing.allocator;
    var fifo = std.fifo.LinearFifo(u8, .Dynamic).init(allocator);
    defer fifo.deinit();

    // compress
    const input = @embedFile("rfc1951.txt");
    var cmp = try compressorWriter(allocator, fifo.writer(), .{});
    defer cmp.deinit();
    const writer = cmp.writer();
    try writer.writeAll(input);
    try cmp.flush();

    // decompress
    var dcmp = try decompressorReader(allocator, fifo.reader(), .{});
    defer dcmp.deinit();
    const actual = try dcmp.reader().readAllAlloc(allocator, std.math.maxInt(usize));
    defer allocator.free(actual);

    try std.testing.expectEqualStrings(input, actual);
}

test "buffer compress/decompress" {
    const allocator = std.testing.allocator;

    const input = @embedFile("rfc1951.txt");
    var cmp = try Compressor.init(allocator, .{ .header = .none });
    defer cmp.deinit();
    const compressed = try cmp.compressAllAlloc(input);
    defer allocator.free(compressed);

    var dcmp = try Decompressor.init(allocator, .{ .header = .none });
    defer dcmp.deinit();
    const decompressed = try dcmp.decompressAllAlloc(compressed);
    defer allocator.free(decompressed);

    try std.testing.expectEqualSlices(u8, input, decompressed);
}

test "compress gzip with C interface" {
    var input = [_]u8{ 'b', 'l', 'a', 'r', 'g' };
    var output_buf: [4096]u8 = undefined;

    var zs: c.z_stream = undefined;
    zs.zalloc = null;
    zs.zfree = null;
    zs.@"opaque" = null;
    zs.avail_in = input.len;
    zs.next_in = &input;
    zs.avail_out = output_buf.len;
    zs.next_out = &output_buf;

    _ = c.deflateInit2(&zs, c.Z_DEFAULT_COMPRESSION, c.Z_DEFLATED, 15 | 16, 8, c.Z_DEFAULT_STRATEGY);
    _ = c.deflate(&zs, c.Z_FINISH);
    _ = c.deflateEnd(&zs);
}

// debug helper
fn showBuf(buf: []const u8) void {
    std.debug.print("\n", .{});
    for (buf) |b|
        std.debug.print("0x{x:0>2}, ", .{b});
    std.debug.print("\n", .{});
}

test "Hello" {
    const allocator = std.testing.allocator;
    const input = "Hello";

    var cmp = try Compressor.init(allocator, .{ .header = .none });
    defer cmp.deinit();
    const compressed = try cmp.compressAllAlloc(input);
    defer allocator.free(compressed);
    //try std.testing.expectEqualSlices(u8, &[_]u8{ 0xf2, 0x48, 0xcd, 0xc9, 0xc9, 0x07, 0x04, 0x00, 0x00, 0xff, 0xff }, compressed);

    var dcp = try Decompressor.init(allocator, .{ .header = .none });
    defer dcp.deinit();
    const decompressed = try dcp.decompressAllAlloc(compressed);
    defer allocator.free(decompressed);

    try std.testing.expectEqualSlices(u8, input, decompressed);
}
