const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // Define dependencies.
    //const zlib = b.dependency("zlib", .{});

    // // Define module
    // const ws_module = b.addModule("ws", .{
    //     .root_source_file = b.path("src/main.zig"),
    //     // .dependencies = &[_]std.Build.ModuleDependency{.{ .name = "zlib", .module = zlib.module("zlib") }},
    // });

    const ws_module = b.createModule(.{
        // `root_source_file` is the Zig "entry point" of the module. If a module
        // only contains e.g. external object files, you can make this `null`.
        // In this case the main source file is merely a path, however, in more
        // complicated build scripts, this could be a generated file.
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
    });

    // Build library.
    const ws_lib = b.addStaticLibrary(.{
        .name = "ws",
        .root_module = ws_module,
        //.root_source_file = .{ .path = "src/main.zig" },
        //.target = target,
        //.optimize = optimize,
    });
    // // Link z library and zlib module.
    // ws_lib.linkLibrary(b.dependency("zlib", .{
    //     .target = target,
    //     .optimize = optimize,
    // }).artifact("z"));
    // ws_lib.addModule("zlib", zlib.module("zlib"));
    // b.installArtifact(ws_lib);

    // Build test.
    const test_compile = b.addTest(.{
        .root_module = ws_module,
        // .root_source_file = .{ .path = "src/main.zig" },
        //.target = target,
        //.optimize = optimize,
    });
    // test_compile.linkLibrary(b.dependency("zlib", .{
    //     .target = target,
    //     .optimize = optimize,
    // }).artifact("z"));
    // test_compile.addModule("zlib", zlib.module("zlib"));
    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&test_compile.step);

    // Build examples.
    var bin = b.addExecutable(.{
        .name = "autobahn_client",
        .root_source_file = b.path("examples/autobahn_client.zig"),
        .target = target,
        .optimize = optimize,
    });
    bin.linkLibrary(ws_lib);
    bin.root_module.addImport("ws", ws_module);
    b.installArtifact(bin);

    // bin = b.addExecutable(.{
    //     .name = "wss",
    //     .root_source_file = b.path("examples/wss.zig"),
    //     .target = target,
    //     .optimize = optimize,
    // });
    // bin.linkLibrary(ws_lib);
    // bin.root_module.addImport("ws", ws_module);
    // b.installArtifact(bin);
}

// to test single file
// $ zig test src/main.zig --deps zlib=zlib --mod zlib::zlib/src/main.zig -l z
