const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // Define dependencies.
    const zlib = b.dependency("zlib", .{});

    // Define module
    const ws_module = b.addModule("ws", .{
        .source_file = .{ .path = "src/main.zig" },
        .dependencies = &[_]std.Build.ModuleDependency{.{ .name = "zlib", .module = zlib.module("zlib") }},
    });

    // Build library.
    const ws_lib = b.addStaticLibrary(.{
        .name = "ws",
        .root_source_file = .{ .path = "src/main.zig" },
        .target = target,
        .optimize = optimize,
    });
    // Link z library and zlib module.
    ws_lib.linkLibrary(b.dependency("zlib", .{
        .target = target,
        .optimize = optimize,
    }).artifact("z"));
    ws_lib.addModule("zlib", zlib.module("zlib"));
    b.installArtifact(ws_lib);

    // Build test.
    const test_compile = b.addTest(.{
        .root_source_file = .{ .path = "src/main.zig" },
        .target = target,
        .optimize = optimize,
    });
    test_compile.linkLibrary(b.dependency("zlib", .{
        .target = target,
        .optimize = optimize,
    }).artifact("z"));
    test_compile.addModule("zlib", zlib.module("zlib"));
    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&test_compile.step);

    // Build examples.
    var bin = b.addExecutable(.{
        .name = "autobahn_client",
        .root_source_file = .{ .path = "examples/autobahn_client.zig" },
        .target = target,
        .optimize = optimize,
    });
    bin.linkLibrary(ws_lib);
    bin.addModule("ws", ws_module);
    b.installArtifact(bin);

    bin = b.addExecutable(.{
        .name = "wss",
        .root_source_file = .{ .path = "examples/wss.zig" },
        .target = target,
        .optimize = optimize,
    });
    bin.linkLibrary(ws_lib);
    bin.addModule("ws", ws_module);
    b.installArtifact(bin);
}

// to test single file
// $ zig test src/main.zig --deps zlib=zlib --mod zlib::zlib/src/main.zig -l z
