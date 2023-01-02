const std = @import("std");
const zlib = @import("zlib/zlib.zig");
const Pkg = std.build.Pkg;

fn root() []const u8 {
    return std.fs.path.dirname(@src().file) orelse ".";
}

const root_path = root() ++ "/";
const package_path = root_path ++ "src/main.zig";

pub const Library = struct {
    step: *std.build.LibExeObjStep,
    zlib: zlib.Library,

    pub fn link(self: Library, other: *std.build.LibExeObjStep) void {
        other.linkLibrary(self.step);
        self.zlib.link(other, .{ .import_name = "zlib" });
        other.addPackage(Pkg{
            .name = "websocket",
            .source = .{ .path = root_path ++ "src/main.zig" },
            .dependencies = &[_]Pkg{
                Pkg{
                    .name = "zlib",
                    .source = .{ .path = root_path ++ "zlib/src/main.zig" },
                },
            },
        });
    }
};

pub fn create(b: *std.build.Builder, target: std.zig.CrossTarget, mode: std.builtin.Mode) Library {
    var ret = b.addStaticLibrary("websocket", package_path);
    ret.setTarget(target);
    ret.setBuildMode(mode);
    const zl = zlib.create(b, target, mode);
    zl.link(ret, .{ .import_name = "zlib" });
    return Library{ .step = ret, .zlib = zl };
}
