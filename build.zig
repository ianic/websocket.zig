const std = @import("std");
const zlib_build = @import("zlib/zlib.zig");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const zlib = zlib_build.create(b, target, optimize);
    //b.installArtifact(zlib.step);

    const zlib_module = b.addModule("zlib", .{
        .source_file = .{ .path = "zlib/src/main.zig" },
    });
    const ws_module = b.addModule("ws", .{
        .source_file = .{ .path = "src/main.zig" },
        .dependencies = &[_]std.Build.ModuleDependency{.{ .name = "zlib", .module = zlib_module }},
    });

    const ws_lib = b.addStaticLibrary(.{
        .name = "ws",
        .root_source_file = .{ .path = "src/main.zig" },
        .target = target,
        .optimize = optimize,
    });
    zlib.link(ws_lib, .{ .import_name = "zlib" });
    b.installArtifact(ws_lib);

    // zig build test
    const test_compile = b.addTest(.{
        .root_source_file = .{ .path = "src/main.zig" },
        .target = target,
        .optimize = optimize,
    });
    zlib.link(test_compile, .{ .import_name = "zlib" });

    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&test_compile.step);

    // build examples
    const bin = b.addExecutable(.{
        .name = "autobahn_client",
        .root_source_file = .{ .path = "examples/autobahn_client.zig" },
        .target = target,
        .optimize = optimize,
    });
    bin.linkLibrary(ws_lib);
    bin.addModule("ws", ws_module);
    b.installArtifact(bin);
}

// to test single file
// $ zig test src/main.zig --deps zlib=zlib --mod zlib::zlib/src/main.zig -l z
