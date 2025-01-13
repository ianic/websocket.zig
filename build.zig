const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const ws_module = b.addModule("ws", .{
        .root_source_file = b.path("src/main.zig"),
    });

    // Build library
    const ws_lib = b.addStaticLibrary(.{
        .name = "ws",
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
    });

    // Build test
    const test_compile = b.addTest(.{
        //.root_module = ws_module,
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
    });
    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&test_compile.step);

    // Build autobahn_client
    var bin = b.addExecutable(.{
        .name = "autobahn_client",
        .root_source_file = b.path("examples/autobahn_client.zig"),
        .target = target,
        .optimize = optimize,
    });
    bin.linkLibrary(ws_lib);
    bin.root_module.addImport("ws", ws_module);
    b.installArtifact(bin);
}
