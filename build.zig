const std = @import("std");
const ws = @import("websocket.zig");

pub fn build(b: *std.build.Builder) void {
    // Standard release options allow the person running `zig build` to select
    // between Debug, ReleaseSafe, ReleaseFast, and ReleaseSmall.
    const mode = b.standardReleaseOptions();
    const target = b.standardTargetOptions(.{});

    const lib = ws.create(b, target, mode);
    lib.step.install();

    const main_tests = b.addTest("src/main.zig");
    lib.link(main_tests);
    main_tests.setBuildMode(mode);

    const test_step = b.step("test", "Run library tests");
    test_step.dependOn(&main_tests.step);

    const example_step = b.step("examples", "Build examples");
    inline for (.{
        "autobahn_client",
    }) |example_name| {
        const exe = b.addExecutable(example_name, "examples/" ++ example_name ++ ".zig");
        lib.link(exe);
        exe.setBuildMode(mode);
        exe.setTarget(target);
        exe.install();
        example_step.dependOn(&exe.step);
    }
}
