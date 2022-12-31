const std = @import("std");
const zlib = @import("zlib/zlib.zig");
const Pkg = std.build.Pkg;

pub const pkgs = struct {
    pub const zlib = Pkg{
        .name = "zlib",
        .source = std.build.FileSource.relative("zlib/src/main.zig"),
    };

    pub const websocket = Pkg{
        .name = "websocket",
        .source = .{ .path = "src/main.zig" },
        .dependencies = &[_]Pkg{
            pkgs.zlib,
        },
    };
};

pub fn build(b: *std.build.Builder) void {
    // Standard release options allow the person running `zig build` to select
    // between Debug, ReleaseSafe, ReleaseFast, and ReleaseSmall.
    const mode = b.standardReleaseOptions();
    const target = b.standardTargetOptions(.{});

    const zlib_lib = zlib.create(b, target, mode);

    const lib = b.addStaticLibrary("websocket", "src/main.zig");
    lib.setBuildMode(mode);
    b.installArtifact(lib);

    const main_tests = b.addTest("src/main.zig");
    zlib_lib.link(main_tests, .{ .import_name = "zlib" });
    main_tests.setBuildMode(mode);

    const test_step = b.step("test", "Run library tests");
    test_step.dependOn(&main_tests.step);

    const example_step = b.step("examples", "Build examples");
    inline for (.{
        "autobahn_client",
    }) |example_name| {
        const example = b.addExecutable(example_name, "examples/" ++ example_name ++ ".zig");

        zlib_lib.link(example, .{ .import_name = "zlib" });
        example.addPackage(pkgs.websocket);

        example.setBuildMode(mode);
        example.setTarget(target);
        example.install();
        example_step.dependOn(&example.step);
    }
}
