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

    const allocator = @ptrCast(*Allocator, @alignCast(@alignOf(*Allocator), private.?));
    var buf = allocator.alloc(u8, ZallocHeader.size_of_aligned + (items * size)) catch return null;
    const header = @ptrCast(*ZallocHeader, @alignCast(@alignOf(*ZallocHeader), buf.ptr));
    header.* = .{
        .magic = magic_value,
        .size = items * size,
    };

    return buf[ZallocHeader.size_of_aligned..].ptr;
}

fn zfree(private: ?*anyopaque, addr: ?*anyopaque) callconv(.C) void {
    if (private == null)
        return;

    const allocator = @ptrCast(*Allocator, @alignCast(@alignOf(*Allocator), private.?));
    const header = @intToPtr(*ZallocHeader, @ptrToInt(addr.?) - ZallocHeader.size_of_aligned);
    if (builtin.mode != .ReleaseFast) {
        if (header.magic != magic_value)
            @panic("magic value is incorrect");
    }

    var buf: []align(alignment) u8 = undefined;
    buf.ptr = @ptrCast([*]align(alignment) u8, @alignCast(alignment, header));
    buf.len = ZallocHeader.size_of_aligned + header.size;
    allocator.free(buf);
}

pub fn compressor(allocator: Allocator, writer: anytype, options: CompressorOptions) Error!Compressor(@TypeOf(writer)) {
    return Compressor(@TypeOf(writer)).init(allocator, writer, options);
}

pub fn decompressor(allocator: Allocator, writer: anytype, options: DecompressorOptions) Error!Decompressor(@TypeOf(writer)) {
    return Decompressor(@TypeOf(writer)).init(allocator, writer, options);
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
    const pinned = @ptrCast(*Allocator, @alignCast(@alignOf(*Allocator), stream.@"opaque".?));
    allocator.destroy(pinned);
    allocator.destroy(stream);
}

pub const CompressorOptions = struct {
    const HeaderOptions = enum {
        none, // raw deflate data with no zlib header or trailer,
        zlib,
        gzip, // to write a simple gzip header and trailer around the compressed data instead of a zlib wrapper.
    };
    // TODO add compression into options

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

pub fn Compressor(comptime WriterType: type) type {
    return struct {
        allocator: Allocator,
        stream: *c.z_stream,
        inner: WriterType,

        const Self = @This();
        const WriterError = Error || WriterType.Error;
        const Writer = std.io.Writer(*Self, WriterError, write);

        pub fn init(allocator: Allocator, inner_writer: WriterType, options: CompressorOptions) !Self {
            var stream = try zStreamInit(allocator);
            errdefer zStreamDeinit(allocator, stream);

            const rc = c.deflateInit2(
                stream,
                c.Z_DEFAULT_COMPRESSION,
                c.Z_DEFLATED, // only option
                options.windowSize(),
                8, // memLevel
                c.Z_DEFAULT_STRATEGY,
            );
            if (rc != c.Z_OK) return errorFromInt(rc);

            return .{
                .allocator = allocator,
                .stream = stream,
                .inner = inner_writer,
            };
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
            self.stream.next_in = @intToPtr([*]u8, @ptrToInt(buf.ptr));
            self.stream.avail_in = @intCast(c_uint, buf.len);

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
        var ws = if (self.window_size < 8) 8 else self.window_size;
        return if (self.header == .none) -@as(i5, ws) else ws;
    }
};

pub fn Decompressor(comptime ReaderType: type) type {
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

        pub fn read(self: *Self, buf: []u8) ReaderError!usize {
            std.debug.print("pos: {d} buf.len {d}\n", .{ self.pos, buf.len });
            self.pos += try self.inner.readAll(self.tmp[self.pos..]);

            self.stream.next_in = &self.tmp;
            self.stream.avail_in = @intCast(c_uint, self.pos);

            self.stream.next_out = @intToPtr([*]u8, @ptrToInt(buf.ptr));
            self.stream.avail_out = @intCast(c_uint, buf.len);

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

pub const BufferCompressor = struct {
    allocator: Allocator,
    stream: *c.z_stream,

    const Self = @This();

    pub fn init(allocator: Allocator, options: CompressorOptions) !Self {
        var stream = try zStreamInit(allocator);
        errdefer zStreamDeinit(allocator, stream);

        const rc = c.deflateInit2(
            stream,
            c.Z_DEFAULT_COMPRESSION,
            c.Z_DEFLATED, // only option
            options.windowSize(),
            8, // memLevel
            c.Z_DEFAULT_STRATEGY,
        );
        if (rc != c.Z_OK) return errorFromInt(rc);
        return .{ .allocator = allocator, .stream = stream };
    }

    pub fn deinit(self: *Self) void {
        _ = c.deflateEnd(self.stream);
        zStreamDeinit(self.allocator, self.stream);
    }

    pub fn compressAllAlloc(self: *Self, uncompressed: []const u8) ![]u8 {
        self.stream.next_in = @intToPtr([*]u8, @ptrToInt(uncompressed.ptr));
        self.stream.avail_in = @intCast(c_uint, uncompressed.len);

        var compressed_list = std.ArrayList(u8).init(self.allocator);
        while (true) {
            const unused = @max(compressed_list.capacity, uncompressed.len / expected_ratio);
            try compressed_list.ensureUnusedCapacity(unused);
            var tmp = compressed_list.unusedCapacitySlice();
            self.stream.next_out = @intToPtr([*]u8, @ptrToInt(tmp.ptr));
            self.stream.avail_out = @intCast(c_uint, tmp.len);

            var rc = c.deflate(self.stream, c.Z_SYNC_FLUSH);
            if (rc != c.Z_OK and rc != c.Z_STREAM_END)
                return errorFromInt(rc);

            if (self.stream.avail_out == 0) {
                compressed_list.items.len += tmp.len;
                continue;
            }
            const n = tmp.len - self.stream.avail_out;
            compressed_list.items.len += n;
            return try compressed_list.toOwnedSlice();
        }
    }
};

pub const BufferDecompressor = struct {
    allocator: Allocator,
    stream: *c.z_stream,

    const Self = @This();

    pub fn init(allocator: Allocator, options: DecompressorOptions) !Self {
        var stream = try zStreamInit(allocator);
        errdefer zStreamDeinit(allocator, stream);

        const rc = c.inflateInit2(stream, options.windowSize());
        if (rc != c.Z_OK) return errorFromInt(rc);

        return .{ .allocator = allocator, .stream = stream };
    }

    pub fn deinit(self: *Self) void {
        _ = c.inflateEnd(self.stream);
        zStreamDeinit(self.allocator, self.stream);
    }

    pub fn decompressAllAlloc(self: *Self, compressed: []const u8) ![]u8 {
        self.stream.next_in = @intToPtr([*]u8, @ptrToInt(compressed.ptr));
        self.stream.avail_in = @intCast(c_uint, compressed.len);

        var decompressed_list = std.ArrayList(u8).init(self.allocator);
        defer decompressed_list.deinit();
        while (true) {
            const unused = @max(decompressed_list.capacity, compressed.len * 4);
            try decompressed_list.ensureUnusedCapacity(unused);
            var tmp = decompressed_list.unusedCapacitySlice();
            self.stream.next_out = @intToPtr([*]u8, @ptrToInt(tmp.ptr));
            self.stream.avail_out = @intCast(c_uint, tmp.len);

            var rc = c.inflate(self.stream, c.Z_SYNC_FLUSH);
            if (rc != c.Z_OK and rc != c.Z_STREAM_END)
                return errorFromInt(rc);

            if (self.stream.avail_out == 0) {
                decompressed_list.items.len += tmp.len;
                continue;
            }
            const n = tmp.len - self.stream.avail_out;
            decompressed_list.items.len += n;
            return try decompressed_list.toOwnedSlice();
        }
    }
};

// for extending allocated buffers
// assumed ratio between uncompressed and compressed buffers
const expected_ratio = 4;

test "compress gzip with zig interface" {
    const allocator = std.testing.allocator;
    var fifo = std.fifo.LinearFifo(u8, .Dynamic).init(allocator);
    defer fifo.deinit();

    // compress with zlib
    const input = @embedFile("rfc1951.txt");
    var cmp = try compressor(allocator, fifo.writer(), .{ .header = .gzip });
    defer cmp.deinit();
    const writer = cmp.writer();
    try writer.writeAll(input);
    try cmp.flush();

    // decompress with zig std lib gzip
    var dcmp = try std.compress.gzip.gzipStream(allocator, fifo.reader());
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
    var cmp = try compressor(allocator, fifo.writer(), .{});
    defer cmp.deinit();
    const writer = cmp.writer();
    try writer.writeAll(input);
    try cmp.flush();

    // decompress
    var dcmp = try decompressor(allocator, fifo.reader(), .{});
    defer dcmp.deinit();
    const actual = try dcmp.reader().readAllAlloc(allocator, std.math.maxInt(usize));
    defer allocator.free(actual);

    try std.testing.expectEqualStrings(input, actual);
}

test "buffer compress/decompress" {
    const allocator = std.testing.allocator;

    const input = @embedFile("rfc1951.txt");
    var cmp = try BufferCompressor.init(allocator, .{ .header = .none });
    defer cmp.deinit();
    const compressed = try cmp.compressAllAlloc(input);
    defer allocator.free(compressed);

    var dcmp = try BufferDecompressor.init(allocator, .{ .header = .none });
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
