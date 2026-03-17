const std = @import("std");
const builtin = @import("builtin");

pub fn build(b: *std.Build) !void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    const test_filters = b.option([]const []const u8, "test-filter", "Skip tests that do not match any filter") orelse &[0][]const u8{};

    // main
    {
        const exe = b.addExecutable(.{
            .name = "xit",
            .root_module = b.createModule(.{
                .root_source_file = b.path("src/main.zig"),
                .target = target,
                .optimize = optimize,
            }),
        });
        exe.root_module.addImport("xitdb", b.dependency("xitdb", .{}).module("xitdb"));
        exe.root_module.addImport("xitui", b.dependency("xitui", .{}).module("xitui"));
        if (.windows == builtin.os.tag) {
            exe.root_module.link_libc = true;
        }
        exe.use_llvm = true;
        b.installArtifact(exe);

        const run_cmd = b.addRunArtifact(exe);
        run_cmd.step.dependOn(b.getInstallStep());
        if (b.args) |args| {
            run_cmd.addArgs(args);
        }

        const run_step = b.step("run", "Run the app");
        run_step.dependOn(&run_cmd.step);
    }

    // module for using xit as a library
    // (the commands below consume xit this way)
    const xit = b.addModule("xit", .{
        .root_source_file = b.path("src/lib.zig"),
    });
    xit.addImport("xitdb", b.dependency("xitdb", .{}).module("xitdb"));
    xit.addImport("xitui", b.dependency("xitui", .{}).module("xitui"));

    // try
    {
        const exe = b.addExecutable(.{
            .name = "try",
            .root_module = b.createModule(.{
                .root_source_file = b.path("src/try.zig"),
                .target = target,
                .optimize = optimize,
            }),
        });
        exe.root_module.addImport("xit", xit);
        if (.windows == builtin.os.tag) {
            exe.root_module.link_libc = true;
        }
        exe.use_llvm = true;
        b.installArtifact(exe);

        const run_cmd = b.addRunArtifact(exe);
        run_cmd.step.dependOn(b.getInstallStep());
        if (b.args) |args| {
            run_cmd.addArgs(args);
        }

        const run_step = b.step("try", "Try the app");
        run_step.dependOn(&run_cmd.step);
    }

    // test
    {
        const zlib = @import("deps/test/zlib.zig");
        const mbedtls = @import("deps/test/mbedtls.zig");
        const libgit2 = @import("deps/test/libgit2.zig");

        const z = zlib.create(b, target, optimize);
        const tls = mbedtls.create(b, target, optimize);

        const git2 = try libgit2.create(b, target, optimize);
        tls.link(git2.step);
        z.link(git2.step);

        const unit_tests = b.addTest(.{
            .root_module = b.createModule(.{
                .root_source_file = b.path("src/test.zig"),
                .target = target,
                .optimize = optimize,
            }),
            .filters = test_filters,
        });
        unit_tests.root_module.addImport("xit", xit);
        unit_tests.root_module.link_libc = true;
        unit_tests.root_module.addIncludePath(b.path("deps/test/libgit2/include"));
        unit_tests.root_module.linkLibrary(git2.step);

        const run_unit_tests = b.addRunArtifact(unit_tests);
        run_unit_tests.has_side_effects = true;
        const test_step = b.step("test", "Run unit tests");
        test_step.dependOn(&run_unit_tests.step);
    }

    // testnet
    {
        const unit_tests = b.addTest(.{
            .root_module = b.createModule(.{
                .root_source_file = b.path("src/testnet.zig"),
                .target = target,
                .optimize = optimize,
            }),
            .filters = test_filters,
        });
        unit_tests.root_module.addImport("xit", xit);
        if (.windows == builtin.os.tag) {
            unit_tests.root_module.link_libc = true;
        }

        const run_unit_tests = b.addRunArtifact(unit_tests);
        run_unit_tests.has_side_effects = true;
        const test_step = b.step("testnet", "Run network unit tests");
        test_step.dependOn(&run_unit_tests.step);
    }
}
