//! tests that create repos via the Repo struct.
//! runs with both git and xit modes.

const std = @import("std");
const hash = @import("../hash.zig");
const rp = @import("../repo.zig");
const rf = @import("../ref.zig");
const obj = @import("../object.zig");
const mrg = @import("../merge.zig");
const ui = @import("../ui.zig");
const patch = @import("../patch.zig");
const df = @import("../diff.zig");

fn addFile(
    comptime repo_kind: rp.RepoKind,
    comptime repo_opts: rp.RepoOpts(repo_kind),
    repo: *rp.Repo(repo_kind, repo_opts),
    io: std.Io,
    allocator: std.mem.Allocator,
    path: []const u8,
    content: []const u8,
) !void {
    if (std.fs.path.dirname(path)) |parent_path| {
        try repo.core.work_dir.createDirPath(io, parent_path);
    }
    const file = try repo.core.work_dir.createFile(io, path, .{ .truncate = true });
    defer file.close(io);
    try file.writeStreamingAll(io, content);
    try repo.add(io, allocator, &.{path});
}

test "simple" {
    try testSimple(.git, .{ .is_test = true });
    try testSimple(.xit, .{ .is_test = true });
}

fn testSimple(comptime repo_kind: rp.RepoKind, comptime repo_opts: rp.RepoOpts(repo_kind)) !void {
    const io = std.testing.io;
    const allocator = std.testing.allocator;
    const temp_dir_name = "temp-test-repo-simple";

    // create the temp dir
    const cwd = std.Io.Dir.cwd();
    var temp_dir_or_err = cwd.openDir(io, temp_dir_name, .{});
    if (temp_dir_or_err) |*temp_dir| {
        temp_dir.close(io);
        try cwd.deleteTree(io, temp_dir_name);
    } else |_| {}
    var temp_dir = try cwd.createDirPathOpen(io, temp_dir_name, .{});
    defer cwd.deleteTree(io, temp_dir_name) catch {};
    defer temp_dir.close(io);

    const cwd_path = try std.process.currentPathAlloc(io, allocator);
    defer allocator.free(cwd_path);

    const work_path = try std.fs.path.join(allocator, &.{ cwd_path, temp_dir_name, "repo" });
    defer allocator.free(work_path);

    {
        var repo = try rp.Repo(repo_kind, repo_opts).init(io, allocator, .{ .path = work_path });
        defer repo.deinit(io, allocator);
    }

    var repo = try rp.Repo(repo_kind, repo_opts).open(io, allocator, .{ .path = work_path });
    defer repo.deinit(io, allocator);

    try addFile(repo_kind, repo_opts, &repo, io, allocator, "README.md", "Hello, world!");
    const commit_a = try repo.commit(io, allocator, .{ .message = "a" });
    try addFile(repo_kind, repo_opts, &repo, io, allocator, "README.md", "Goodbye, world!");
    const commit_b = try repo.commit(io, allocator, .{ .message = "b" });
    try repo.remove(io, allocator, &.{"README.md"}, .{});
    const commit_c = try repo.commit(io, allocator, .{ .message = "c" });

    if (repo_kind == .xit) {
        try std.testing.expectEqual(1, try repo.commitCount(io, allocator, .{ .oid = &commit_a }));
        try std.testing.expectEqual(2, try repo.commitCount(io, allocator, .{ .oid = &commit_b }));
        try std.testing.expectEqual(3, try repo.commitCount(io, allocator, .{ .oid = &commit_c }));
        try std.testing.expectEqual(3, try repo.commitCount(io, allocator, .{ .ref = .{ .kind = .head, .name = "master" } }));
        try std.testing.expectError(error.RefNotFound, repo.commitCount(io, allocator, .{ .ref = .{ .kind = .head, .name = "missing" } }));
        try std.testing.expectError(error.UnsupportedRefKind, repo.commitCount(io, allocator, .{ .ref = .{ .kind = .none, .name = "HEAD" } }));
    }

    inline for (.{ false, true }) |bare| {
        try repo.addConfig(io, allocator, .{ .name = "core.bare", .value = if (bare) "true" else "false" });
        var root = try ui.rootWidget(repo_kind, repo_opts, &repo, io, allocator, .log);
        defer root.deinit(allocator);

        const tabs = &root.ui_root.box.children.values()[0].widget.ui_root_tabs;
        try std.testing.expectEqual(!bare, tabs.getChildFocusId(.status) != null);
        try std.testing.expectEqual(if (repo_kind == .xit) @as(usize, 4) else 3, tabs.box.children.count() + @intFromBool(bare));

        var config_root = try ui.rootWidget(repo_kind, repo_opts, &repo, io, allocator, .config);
        defer config_root.deinit(allocator);
        try std.testing.expect(config_root.ui_root.box.children.values()[1].widget.stack.getSelected().?.* == .ui_config_list);

        const grid = try root.getGrid().?.toString(allocator);
        defer allocator.free(grid);

        var grid_without_tabs = grid;
        for (0..3) |_| {
            grid_without_tabs = grid_without_tabs[std.mem.indexOfScalar(u8, grid_without_tabs, '\n').? + 1 ..];
        }

        try std.testing.expectEqualStrings(
            \\┌─┐                                     ┌──────────────────────────────────────────────────────────┐
            \\│c│                                     │                                                          │
            \\└─┘                                     │ diff --git a/README.md b/README.md                       │
            \\                                        │ deleted file mode 100644                                 │
            \\ b                                      │ index 6b49ab7..0000000                                   │
            \\                                        │ --- a/README.md                                          │
            \\                                        │ +++ /dev/null                                            │
            \\ a                                      │                                                          │
            \\                                        │                                                          │
            \\                                        │                                                          │
            \\                                        │ @@ -0,1 +0,0 @@                                          │
            \\                                        │ - Goodbye, world!                                        │
            \\                                        │                                                          │
            \\                                        │                                                          │
            \\                                        └──────────────────────────────────────────────────────────┘
        , grid_without_tabs);
    }
    try repo.addConfig(io, allocator, .{ .name = "core.bare", .value = "false" });

    // can't add path that is outside repo
    try std.testing.expectError(error.PathIsOutsideRepo, repo.add(io, allocator, &.{"../README.md"}));

    // commits that haven't changed content are an error
    try std.testing.expectError(error.EmptyCommit, repo.commit(io, allocator, .{ .message = "d" }));

    // put oids in a set
    var oid_set: std.StringArrayHashMapUnmanaged(void) = .empty;
    defer oid_set.deinit(allocator);
    try oid_set.put(allocator, &commit_a, {});
    try oid_set.put(allocator, &commit_b, {});
    try oid_set.put(allocator, &commit_c, {});

    // assert that all commits have been found in the log
    {
        var commit_iter = try repo.log(io, allocator, .{});
        defer commit_iter.deinit();
        while (try commit_iter.next(allocator)) |commit_object| {
            defer commit_object.deinit();
            _ = oid_set.swapRemove(&commit_object.oid);
        }
        try std.testing.expectEqual(0, oid_set.count());
    }

    {
        var result = try repo.resetDir(io, allocator, .{ .target = .{ .oid = &commit_b } });
        defer result.deinit();
    }
    if (repo_kind == .xit) {
        try std.testing.expectEqual(2, try repo.commitCount(io, allocator, .{ .ref = .{ .kind = .head, .name = "master" } }));
    }

    {
        const readme_md_content = try repo.core.work_dir.readFileAlloc(io, "README.md", allocator, .limited(1024));
        defer allocator.free(readme_md_content);
        try std.testing.expectEqualStrings("Goodbye, world!", readme_md_content);
    }

    {
        var result = try repo.resetDir(io, allocator, .{ .target = .{ .oid = &commit_a } });
        defer result.deinit();
    }

    {
        const readme_md_content = try repo.core.work_dir.readFileAlloc(io, "README.md", allocator, .limited(1024));
        defer allocator.free(readme_md_content);
        try std.testing.expectEqualStrings("Hello, world!", readme_md_content);
    }

    {
        var result = try repo.resetDir(io, allocator, .{ .target = .{ .oid = &commit_c } });
        defer result.deinit();
    }

    if (repo.core.work_dir.openFile(io, "README.md", .{ .mode = .read_only })) |readme_md| {
        readme_md.close(io);
        return error.FileNotExpected;
    } else |err| switch (err) {
        error.FileNotFound => {},
        else => |e| return e,
    }

    const tag_oid = try repo.addTag(io, allocator, .{ .name = "1.0.0", .message = "hi" });
    if (repo_kind == .xit) {
        try std.testing.expectEqual(3, try repo.commitCount(io, allocator, .{ .ref = .{ .kind = .tag, .name = "1.0.0" } }));
        try std.testing.expectEqual(3, try repo.commitCount(io, allocator, .{ .oid = &tag_oid }));
    }

    // we can enable patches after adding a tag
    if (repo_kind == .xit) {
        try repo.patchAll(io, allocator, null);
    }

    {
        // we can set the tag to HEAD
        var result = try repo.resetDir(io, allocator, .{ .target = .{ .ref = .{ .kind = .tag, .name = "1.0.0" } } });
        defer result.deinit();

        // status works when HEAD points to a tag
        var status = try repo.status(io, allocator);
        defer status.deinit(allocator);
    }
}

test "empty branch" {
    try testEmptyBranch(.git, .{ .is_test = true });
    try testEmptyBranch(.xit, .{ .is_test = true });
}

test "commit count missing legacy index" {
    const io = std.testing.io;
    const allocator = std.testing.allocator;
    const temp_dir_name = "temp-test-repo-commit-count-legacy";
    const repo_opts = rp.RepoOpts(.xit){ .is_test = true };
    const DB = rp.Repo(.xit, repo_opts).DB;

    const cwd = std.Io.Dir.cwd();
    var temp_dir_or_err = cwd.openDir(io, temp_dir_name, .{});
    if (temp_dir_or_err) |*temp_dir| {
        temp_dir.close(io);
        try cwd.deleteTree(io, temp_dir_name);
    } else |_| {}
    var temp_dir = try cwd.createDirPathOpen(io, temp_dir_name, .{});
    defer cwd.deleteTree(io, temp_dir_name) catch {};
    defer temp_dir.close(io);

    const cwd_path = try std.process.currentPathAlloc(io, allocator);
    defer allocator.free(cwd_path);
    const work_path = try std.fs.path.join(allocator, &.{ cwd_path, temp_dir_name, "repo" });
    defer allocator.free(work_path);

    var repo = try rp.Repo(.xit, repo_opts).init(io, allocator, .{ .path = work_path });
    defer repo.deinit(io, allocator);

    try addFile(.xit, repo_opts, &repo, io, allocator, "file", "a");
    _ = try repo.commit(io, allocator, .{ .message = "a" });
    try addFile(.xit, repo_opts, &repo, io, allocator, "file", "b");
    const commit_b = try repo.commit(io, allocator, .{ .message = "b" });

    // simulate a repository created before the depth index existed.
    const Ctx = struct {
        pub fn run(_: @This(), cursor: *DB.Cursor(.read_write)) !void {
            var moment = try DB.HashMap(.read_write).init(cursor.*);
            if (!try moment.remove(hash.hashInt(repo_opts.hash, obj.COMMIT_ID_TO_FIRST_PARENT_DEPTH_KEY))) {
                return error.CommitDepthNotFound;
            }
        }
    };
    {
        try repo.core.db_file.lock(io, .exclusive);
        defer repo.core.db_file.unlock(io);
        const history = try DB.ArrayList(.read_write).init(repo.core.db.rootCursor());
        try history.appendContext(.{ .slot = try history.getSlot(-1) }, Ctx{});
    }

    try std.testing.expectError(error.CommitDepthNotFound, repo.commitCount(io, allocator, .{ .oid = &commit_b }));

    // a later write fills the missing chain before indexing the new commit.
    try addFile(.xit, repo_opts, &repo, io, allocator, "file", "c");
    const commit_c = try repo.commit(io, allocator, .{ .message = "c" });
    try std.testing.expectEqual(2, try repo.commitCount(io, allocator, .{ .oid = &commit_b }));
    try std.testing.expectEqual(3, try repo.commitCount(io, allocator, .{ .oid = &commit_c }));
}

fn testEmptyBranch(comptime repo_kind: rp.RepoKind, comptime repo_opts: rp.RepoOpts(repo_kind)) !void {
    const io = std.testing.io;
    const allocator = std.testing.allocator;
    const temp_dir_name = "temp-test-repo-branch";

    // create the temp dir
    const cwd = std.Io.Dir.cwd();
    var temp_dir_or_err = cwd.openDir(io, temp_dir_name, .{});
    if (temp_dir_or_err) |*temp_dir| {
        temp_dir.close(io);
        try cwd.deleteTree(io, temp_dir_name);
    } else |_| {}
    var temp_dir = try cwd.createDirPathOpen(io, temp_dir_name, .{});
    defer cwd.deleteTree(io, temp_dir_name) catch {};
    defer temp_dir.close(io);

    const cwd_path = try std.process.currentPathAlloc(io, allocator);
    defer allocator.free(cwd_path);

    const work_path = try std.fs.path.join(allocator, &.{ cwd_path, temp_dir_name, "repo" });
    defer allocator.free(work_path);

    {
        var repo = try rp.Repo(repo_kind, repo_opts).init(io, allocator, .{ .path = work_path });
        defer repo.deinit(io, allocator);
    }

    var repo = try rp.Repo(repo_kind, repo_opts).open(io, allocator, .{ .path = work_path });
    defer repo.deinit(io, allocator);

    try addFile(repo_kind, repo_opts, &repo, io, allocator, "README.md", "Hello, world!");
    _ = try repo.commit(io, allocator, .{ .message = "a" });
    try addFile(repo_kind, repo_opts, &repo, io, allocator, "README.md", "Goodbye, world!");
    const commit_b = try repo.commit(io, allocator, .{ .message = "b" });

    // create empty branch with no target, so it doesn't point to anything
    try repo.addBranch(io, .{ .name = "foo", .target = .none });
    if (repo_kind == .xit) {
        try std.testing.expectEqual(0, try repo.commitCount(io, allocator, .{ .ref = .{ .kind = .head, .name = "foo" } }));
    }

    // make an empty commit at foo without checking it out
    const commit_c = try repo.commitAtRef(io, allocator, .{ .message = "c" }, null, .{ .kind = .head, .name = "foo" });

    // foo points to c
    {
        const oid_foo = try repo.readRef(io, .{ .kind = .head, .name = "foo" }) orelse return error.RefNotFound;
        try std.testing.expectEqualStrings(&commit_c, &oid_foo);
    }

    // master points to b
    const oid_master = try repo.readRef(io, .{ .kind = .head, .name = "master" }) orelse return error.RefNotFound;
    try std.testing.expectEqualStrings(&commit_b, &oid_master);

    // c has no parents
    {
        var obj_iter = try repo.log(io, allocator, .{ .start_oids = &.{commit_c} });
        defer obj_iter.deinit();
        var count: usize = 0;
        while (try obj_iter.next(allocator)) |commit| {
            defer commit.deinit();
            count += 1;
        }
        try std.testing.expectEqual(1, count);
    }

    // make another empty commit at foo without checking it out
    const commit_d = try repo.commitAtRef(io, allocator, .{ .message = "d" }, null, .{ .kind = .head, .name = "foo" });
    if (repo_kind == .xit) {
        try std.testing.expectEqual(1, try repo.commitCount(io, allocator, .{ .oid = &commit_c }));
        try std.testing.expectEqual(2, try repo.commitCount(io, allocator, .{ .oid = &commit_d }));
    }

    // foo points to d
    {
        const oid_foo = try repo.readRef(io, .{ .kind = .head, .name = "foo" }) orelse return error.RefNotFound;
        try std.testing.expectEqualStrings(&commit_d, &oid_foo);
    }
}

test "merge" {
    try testMerge(.git, .{ .is_test = true });
    try testMerge(.xit, .{ .is_test = true });
}

test "merge patch application" {
    try testMergePatchApplication(.patch, .multiple);
    try testMergePatchApplication(.diff3, .multiple);
    try testMergePatchApplication(.patch, .dependent);
    try testMergePatchApplication(.patch, .first_parents);
    try testMergePatchApplication(.patch, .second_parent);
}

fn testMergePatchApplication(algo: mrg.MergeAlgorithm, case: enum { multiple, dependent, first_parents, second_parent }) !void {
    const io = std.testing.io;
    const allocator = std.testing.allocator;
    const opts: rp.RepoOpts(.xit) = .{ .is_test = true };
    errdefer std.debug.print("patch application: {s}, {s}\n", .{ @tagName(case), @tagName(algo) });
    const temp_dir_name = "temp-test-repo-merge-patch-application";

    // create the temp dir
    const cwd = std.Io.Dir.cwd();
    var temp_dir_or_err = cwd.openDir(io, temp_dir_name, .{});
    if (temp_dir_or_err) |*temp_dir| {
        temp_dir.close(io);
        try cwd.deleteTree(io, temp_dir_name);
    } else |_| {}
    var temp_dir = try cwd.createDirPathOpen(io, temp_dir_name, .{});
    defer cwd.deleteTree(io, temp_dir_name) catch {};
    defer temp_dir.close(io);

    const cwd_path = try std.process.currentPathAlloc(io, allocator);
    defer allocator.free(cwd_path);
    const work_path = try std.fs.path.join(allocator, &.{ cwd_path, temp_dir_name, "repo" });
    defer allocator.free(work_path);
    var repo = try rp.Repo(.xit, opts).init(io, allocator, .{ .path = work_path });
    defer repo.deinit(io, allocator);

    const initial = "a\nb\nc\nd\ne\nf\ng";
    try addFile(.xit, opts, &repo, io, allocator, "f.txt", initial);
    const root_oid = try repo.commit(io, allocator, .{ .message = "root", .timestamp = 1 });
    const base_oid = if (case == .second_parent) blk: {
        try addFile(.xit, opts, &repo, io, allocator, "f.txt", "a\nb\nc\nd\ne\nf\nbase");
        break :blk try repo.commit(io, allocator, .{ .message = "base", .timestamp = 2 });
    } else root_oid;
    try addFile(.xit, opts, &repo, io, allocator, "f.txt", if (case == .second_parent) "A\nb\nc\nd\ne\nf\nbase" else "A\nb\nc\nd\ne\nf\ng");
    _ = try repo.commit(io, allocator, .{ .message = "target", .timestamp = 3 });
    try repo.addBranch(io, .{ .name = "target" });

    const expected = switch (case) {
        .multiple, .dependent => blk: {
            // unrelated commits inherit the previous patch id, including the base's
            try addFile(.xit, opts, &repo, io, allocator, "f.txt", initial);
            try addFile(.xit, opts, &repo, io, allocator, "other.txt", "before");
            _ = try repo.commit(io, allocator, .{ .message = "unrelated before", .parent_oids = &.{root_oid}, .timestamp = 4 });
            const sources: []const []const u8 = if (case == .multiple) &.{
                "a\nb\nC\nd\ne\nf\ng",
                "a\nb\nC\nd\ne\nf\nG",
            } else &.{
                "a\nb\nnew\nc\nd\ne\nf\ng",
                "a\nb\nnew\nmore\nc\nd\ne\nf\ng",
            };
            for (sources, 0..) |source, i| {
                try addFile(.xit, opts, &repo, io, allocator, "f.txt", source);
                _ = try repo.commit(io, allocator, .{ .message = "source", .timestamp = 5 + i * 2 });
                try addFile(.xit, opts, &repo, io, allocator, "other.txt", source);
                _ = try repo.commit(io, allocator, .{ .message = "unrelated after", .timestamp = 6 + i * 2 });
            }
            break :blk if (case == .multiple) "A\nb\nC\nd\ne\nf\nG" else "A\nb\nnew\nmore\nc\nd\ne\nf\ng";
        },
        .first_parents => blk: {
            try addFile(.xit, opts, &repo, io, allocator, "f.txt", "a\nb\nside\nd\ne\nf\ng");
            _ = try repo.commit(io, allocator, .{ .message = "side", .parent_oids = &.{root_oid}, .timestamp = 4 });
            try addFile(.xit, opts, &repo, io, allocator, "f.txt", "a\nb\nside\nmore\nd\ne\nf\ng");
            const side_oid = try repo.commit(io, allocator, .{ .message = "side follow-up", .timestamp = 5 });
            try addFile(.xit, opts, &repo, io, allocator, "f.txt", "a\nb\nc\nd\nE\nf\ng");
            var source_oid = try repo.commit(io, allocator, .{ .message = "source", .parent_oids = &.{root_oid}, .timestamp = 6 });
            // make the first-parent chain longer than the side chain.
            // reversing a breadth-first walk would put some children before their parents.
            for (0..3) |i| {
                source_oid = try repo.commit(io, allocator, .{ .message = "empty", .allow_empty = true, .timestamp = 7 + i });
            }
            // create a merge commit with a manual resolution.
            // we shouldn't apply the side branch's patches separately.
            try addFile(.xit, opts, &repo, io, allocator, "f.txt", "a\nb\nresolved\nd\nE\nf\ng");
            _ = try repo.commit(io, allocator, .{ .message = "resolved merge", .parent_oids = &.{ source_oid, side_oid }, .timestamp = 10 });
            try addFile(.xit, opts, &repo, io, allocator, "f.txt", "a\nb\nresolved\nfollow-up\nd\nE\nf\ng");
            _ = try repo.commit(io, allocator, .{ .message = "merge follow-up", .timestamp = 11 });
            break :blk "A\nb\nresolved\nfollow-up\nd\nE\nf\ng";
        },
        .second_parent => blk: {
            // root --- base --- target
            //    \       \
            //     source--merge---follow-up
            // the merge's first parent is source; base is its second parent
            try addFile(.xit, opts, &repo, io, allocator, "f.txt", "a\nb\nc\nd\nE\nf\ng");
            const source_oid = try repo.commit(io, allocator, .{ .message = "source", .parent_oids = &.{root_oid}, .timestamp = 4 });
            try addFile(.xit, opts, &repo, io, allocator, "f.txt", "a\nb\nc\nd\nE\nf\nbase");
            _ = try repo.commit(io, allocator, .{ .message = "merge", .parent_oids = &.{ source_oid, base_oid }, .timestamp = 5 });
            try addFile(.xit, opts, &repo, io, allocator, "f.txt", "a\nb\nC\nd\nE\nf\nbase");
            _ = try repo.commit(io, allocator, .{ .message = "follow-up", .timestamp = 6 });
            break :blk "A\nb\nC\nd\nE\nf\nbase";
        },
    };
    {
        var result = try repo.switchDir(io, allocator, .{ .target = .{ .ref = .{ .kind = .head, .name = "target" } } });
        defer result.deinit();
    }
    var merge = try repo.merge(io, allocator, .{ .kind = .full, .action = .{ .new = .{
        .algo = algo,
        .source = &.{.{ .ref = .{ .kind = .head, .name = "master" } }},
    } } }, null);
    defer merge.deinit();
    try std.testing.expectEqualStrings(&base_oid, &merge.base_oid);
    try std.testing.expect(merge.result == .success);
    const actual = try repo.core.work_dir.readFileAlloc(io, "f.txt", allocator, .limited(4096));
    defer allocator.free(actual);
    try std.testing.expectEqualStrings(expected, actual);
}

test "applied patches" {
    try testAppliedPatches(.repeat);
    try testAppliedPatches(.later_edit);
    try testAppliedPatches(.conflict);
    try testAppliedPatches(.rollback);
    try testAppliedPatches(.merge);
}

fn testAppliedPatches(case: enum { repeat, later_edit, conflict, rollback, merge }) !void {
    const io = std.testing.io;
    const allocator = std.testing.allocator;
    const opts: rp.RepoOpts(.xit) = .{ .is_test = true };
    const DB = rp.Repo(.xit, opts).DB;
    errdefer std.debug.print("applied patches: {s}\n", .{@tagName(case)});
    const temp_dir_name = "temp-test-repo-applied-patches";

    // create the temp dir
    const cwd = std.Io.Dir.cwd();
    var temp_dir_or_err = cwd.openDir(io, temp_dir_name, .{});
    if (temp_dir_or_err) |*temp_dir| {
        temp_dir.close(io);
        try cwd.deleteTree(io, temp_dir_name);
    } else |_| {}
    var temp_dir = try cwd.createDirPathOpen(io, temp_dir_name, .{});
    defer cwd.deleteTree(io, temp_dir_name) catch {};
    defer temp_dir.close(io);

    const cwd_path = try std.process.currentPathAlloc(io, allocator);
    defer allocator.free(cwd_path);
    const work_path = try std.fs.path.join(allocator, &.{ cwd_path, temp_dir_name, "repo" });
    defer allocator.free(work_path);
    var repo = try rp.Repo(.xit, opts).init(io, allocator, .{ .path = work_path });
    defer repo.deinit(io, allocator);

    // both files should share patch ids, but track their application separately
    const paths = [_][]const u8{ "a.txt", "b.txt" };
    for (paths) |path| try addFile(.xit, opts, &repo, io, allocator, path, "a\nb\nc\nd\ne");
    const root_oid = try repo.commit(io, allocator, .{ .message = "root", .timestamp = 1 });
    for (paths) |path| try addFile(.xit, opts, &repo, io, allocator, path, "a\nB\nc\nd\ne");
    const target_oid = try repo.commit(io, allocator, .{ .message = "target", .timestamp = 2 });
    try repo.addBranch(io, .{ .name = "target" });
    const source_content = switch (case) {
        .later_edit => "a\nBB\nc\nd\ne",
        .conflict => "a\nother\nc\nd\ne",
        else => "a\nb\nc\nd\nE",
    };
    for (paths) |path| try addFile(.xit, opts, &repo, io, allocator, path, source_content);
    const source_oid = try repo.commit(io, allocator, .{
        .message = "source",
        .parent_oids = &.{if (case == .later_edit) target_oid else root_oid},
        .timestamp = 3,
    });
    try repo.patchAll(io, allocator, null);

    if (case == .merge) {
        var result = try repo.switchDir(io, allocator, .{ .target = .{ .ref = .{ .kind = .head, .name = "target" } } });
        defer result.deinit();
        var merge = try repo.merge(io, allocator, .{ .kind = .full, .action = .{ .new = .{ .algo = .patch, .source = &.{.{ .oid = &source_oid }} } } }, null);
        defer merge.deinit();
        try std.testing.expect(merge.result == .success);
        for (paths) |path| {
            const content = try repo.core.work_dir.readFileAlloc(io, path, allocator, .limited(4096));
            defer allocator.free(content);
            try std.testing.expectEqualStrings("a\nB\nc\nd\nE", content);
        }
        return;
    }

    const Ctx = struct {
        case: @TypeOf(case),
        snapshot_oid: [hash.hexLen(opts.hash)]u8,
        patch_oid: [hash.hexLen(opts.hash)]u8,

        pub fn run(ctx: @This(), cursor: *DB.Cursor(.read_write)) !void {
            var moment = try DB.HashMap(.read_write).init(cursor.*);
            const snapshots = try DB.HashMap(.read_only).init((try moment.getCursor(hash.hashInt(opts.hash, "commit-id->snapshot"))).?);
            const original = (try snapshots.getCursor(try hash.hexToInt(opts.hash, &ctx.snapshot_oid))).?;
            var snapshot_cursor = try moment.putCursor(hash.hashInt(opts.hash, "test-patch-snapshot"));
            try snapshot_cursor.write(.{ .slot = original.slot() });
            const snapshot = try DB.HashMap(.read_write).init(snapshot_cursor);
            const patch_snapshot = (try snapshots.getCursor(try hash.hexToInt(opts.hash, &ctx.patch_oid))).?;
            var patch_ids: [2][hash.byteLen(opts.hash)]u8 = undefined;
            for (paths, &patch_ids) |path, *patch_id| {
                const patch_cursor = (try patch_snapshot.readPath(void, &.{
                    .{ .hash_map_get = .{ .value = hash.hashInt(opts.hash, "path->patch-id") } },
                    .{ .hash_map_get = .{ .value = hash.hashInt(opts.hash, path) } },
                })).?;
                _ = try patch_cursor.readBytes(patch_id);
            }
            try std.testing.expectEqualSlices(u8, &patch_ids[0], &patch_ids[1]);
            const patch_id = hash.bytesToInt(opts.hash, &patch_ids[0]);
            const path_hash = hash.hashInt(opts.hash, paths[0]);

            if (ctx.case == .rollback) {
                // fail after the patch's graph changes, not before application starts
                const changes = try DB.HashMap(.read_write).init(try moment.putCursor(hash.hashInt(opts.hash, "patch-id->change-list")));
                const bytes = try (try changes.getCursor(patch_id)).?.readBytesAlloc(allocator, opts.max_read_size);
                defer allocator.free(bytes);
                const invalid = try std.mem.concat(allocator, u8, &.{ bytes, "\xff" });
                defer allocator.free(invalid);
                try changes.put(patch_id, .{ .bytes = invalid });
            }
            var read_moment = moment.readOnly();
            if (ctx.case != .later_edit) {
                try patch.applyPatch(opts, &read_moment, &snapshot, allocator, path_hash, patch_id);
            }
            const membership = try snapshot.cursor.readPath(void, &.{
                .{ .hash_map_get = .{ .value = hash.hashInt(opts.hash, "path->patch-id-set") } },
                .{ .hash_map_get = .{ .value = path_hash } },
                .{ .hash_map_get = .{ .key = patch_id } },
            });
            try std.testing.expect(membership != null);
            const line_list = try snapshot.cursor.readPath(void, &.{
                .{ .hash_map_get = .{ .value = hash.hashInt(opts.hash, "path->line-id-list") } },
                .{ .hash_map_get = .{ .value = path_hash } },
            });
            try std.testing.expectEqual(ctx.case != .conflict, line_list != null);

            // freezing forces any writes to copy existing data.
            // applying the patch again should make no changes at all.
            try cursor.db.freeze();
            const size_before = try cursor.db.core.length();
            try patch.applyPatch(opts, &read_moment, &snapshot, allocator, path_hash, patch_id);
            try std.testing.expectEqual(size_before, try cursor.db.core.length());
        }
    };
    const ctx = Ctx{
        .case = case,
        .snapshot_oid = if (case == .later_edit) source_oid else target_oid,
        .patch_oid = if (case == .later_edit) target_oid else source_oid,
    };
    const before = try repo.core.latestMoment();
    try repo.core.db_file.lock(io, .exclusive);
    defer repo.core.db_file.unlock(io);
    const history = try DB.ArrayList(.read_write).init(repo.core.db.rootCursor());
    if (case == .rollback) {
        try std.testing.expectError(error.InvalidEnumTag, history.appendContext(.{ .slot = try history.getSlot(-1) }, ctx));
        const after = try repo.core.latestMoment();
        try std.testing.expectEqualDeep(before.cursor.slot(), after.cursor.slot());
    } else {
        try history.appendContext(.{ .slot = try history.getSlot(-1) }, ctx);
    }
}

test "merge at ref" {
    try testMergeAtRef(.git, .{ .is_test = true }, false);
    try testMergeAtRef(.xit, .{ .is_test = true }, false);
    try testMergeAtRef(.git, .{ .is_test = true }, true);
    try testMergeAtRef(.xit, .{ .is_test = true }, true);
}

fn testMergeAtRef(comptime repo_kind: rp.RepoKind, comptime repo_opts: rp.RepoOpts(repo_kind), bare: bool) !void {
    const io = std.testing.io;
    const allocator = std.testing.allocator;
    const temp_dir_name = "temp-test-repo-merge-at-ref";

    const cwd = std.Io.Dir.cwd();
    var temp_dir_or_err = cwd.openDir(io, temp_dir_name, .{});
    if (temp_dir_or_err) |*temp_dir| {
        temp_dir.close(io);
        try cwd.deleteTree(io, temp_dir_name);
    } else |_| {}
    var temp_dir = try cwd.createDirPathOpen(io, temp_dir_name, .{});
    defer cwd.deleteTree(io, temp_dir_name) catch {};
    defer temp_dir.close(io);

    const cwd_path = try std.process.currentPathAlloc(io, allocator);
    defer allocator.free(cwd_path);
    const work_path = try std.fs.path.join(allocator, &.{ cwd_path, temp_dir_name, "repo" });
    defer allocator.free(work_path);

    var repo = try rp.Repo(repo_kind, repo_opts).init(io, allocator, .{ .path = work_path });
    defer repo.deinit(io, allocator);

    try addFile(repo_kind, repo_opts, &repo, io, allocator, "base.txt", "base");
    const base_oid = try repo.commit(io, allocator, .{ .message = "base" });
    try repo.addBranch(io, .{ .name = "target" });
    try repo.addBranch(io, .{ .name = "source" });

    {
        var switch_result = try repo.switchDir(io, allocator, .{ .target = .{ .ref = .{ .kind = .head, .name = "target" } } });
        defer switch_result.deinit();
    }
    try addFile(repo_kind, repo_opts, &repo, io, allocator, "target.txt", "target");
    _ = try repo.commit(io, allocator, .{ .message = "target" });

    {
        var switch_result = try repo.switchDir(io, allocator, .{ .target = .{ .ref = .{ .kind = .head, .name = "source" } } });
        defer switch_result.deinit();
    }
    try addFile(repo_kind, repo_opts, &repo, io, allocator, "source.txt", "source");
    _ = try repo.commit(io, allocator, .{ .message = "source" });

    {
        var switch_result = try repo.switchDir(io, allocator, .{ .target = .{ .ref = .{ .kind = .head, .name = "master" } } });
        defer switch_result.deinit();
    }
    try addFile(repo_kind, repo_opts, &repo, io, allocator, "current.txt", "current");

    if (bare) try repo.addConfig(io, allocator, .{ .name = "core.bare", .value = "true" });

    {
        var merge = try repo.mergeAtRef(io, allocator, .{
            .kind = .full,
            .action = .{ .new = .{
                .source = &.{.{ .ref = .{ .kind = .head, .name = "source" } }},
                .algo = .diff3,
            } },
        }, .{ .kind = .head, .name = "target" }, null);
        defer merge.deinit();
        try std.testing.expect(.success == merge.result);
    }

    const head_oid = try repo.readRef(io, .{ .kind = .none, .name = "HEAD" }) orelse return error.RefNotFound;
    try std.testing.expectEqualStrings(&base_oid, &head_oid);
    const current_content = try repo.core.work_dir.readFileAlloc(io, "current.txt", allocator, .limited(1024));
    defer allocator.free(current_content);
    try std.testing.expectEqualStrings("current", current_content);
    try std.testing.expectError(error.FileNotFound, repo.core.work_dir.openFile(io, "target.txt", .{ .mode = .read_only }));
    try std.testing.expectError(error.FileNotFound, repo.core.work_dir.openFile(io, "source.txt", .{ .mode = .read_only }));

    if (bare) try repo.addConfig(io, allocator, .{ .name = "core.bare", .value = "false" });
    _ = try repo.commit(io, allocator, .{ .message = "current" });

    {
        var switch_result = try repo.switchDir(io, allocator, .{ .target = .{ .ref = .{ .kind = .head, .name = "target" } } });
        defer switch_result.deinit();
    }
    for ([_]struct { path: []const u8, content: []const u8 }{
        .{ .path = "base.txt", .content = "base" },
        .{ .path = "target.txt", .content = "target" },
        .{ .path = "source.txt", .content = "source" },
    }) |expected| {
        const content = try repo.core.work_dir.readFileAlloc(io, expected.path, allocator, .limited(1024));
        defer allocator.free(content);
        try std.testing.expectEqualStrings(expected.content, content);
    }
    try std.testing.expectError(error.FileNotFound, repo.core.work_dir.openFile(io, "current.txt", .{ .mode = .read_only }));

    {
        var switch_result = try repo.switchDir(io, allocator, .{ .target = .{ .ref = .{ .kind = .head, .name = "master" } } });
        defer switch_result.deinit();
    }
    try std.testing.expectError(error.FileNotFound, repo.core.work_dir.openFile(io, "target.txt", .{ .mode = .read_only }));
    try std.testing.expectError(error.FileNotFound, repo.core.work_dir.openFile(io, "source.txt", .{ .mode = .read_only }));
    const restored_current_content = try repo.core.work_dir.readFileAlloc(io, "current.txt", allocator, .limited(1024));
    defer allocator.free(restored_current_content);
    try std.testing.expectEqualStrings("current", restored_current_content);
}

fn testMerge(comptime repo_kind: rp.RepoKind, comptime repo_opts: rp.RepoOpts(repo_kind)) !void {
    const io = std.testing.io;
    const allocator = std.testing.allocator;
    const temp_dir_name = "temp-test-repo-merge";

    // create the temp dir
    const cwd = std.Io.Dir.cwd();
    var temp_dir_or_err = cwd.openDir(io, temp_dir_name, .{});
    if (temp_dir_or_err) |*temp_dir| {
        temp_dir.close(io);
        try cwd.deleteTree(io, temp_dir_name);
    } else |_| {}
    var temp_dir = try cwd.createDirPathOpen(io, temp_dir_name, .{});
    defer cwd.deleteTree(io, temp_dir_name) catch {};
    defer temp_dir.close(io);

    const cwd_path = try std.process.currentPathAlloc(io, allocator);
    defer allocator.free(cwd_path);

    const work_path = try std.fs.path.join(allocator, &.{ cwd_path, temp_dir_name, "repo" });
    defer allocator.free(work_path);

    {
        var repo = try rp.Repo(repo_kind, repo_opts).init(io, allocator, .{ .path = work_path });
        defer repo.deinit(io, allocator);
    }

    var repo = try rp.Repo(repo_kind, repo_opts).open(io, allocator, .{ .path = work_path });
    defer repo.deinit(io, allocator);

    // A --- B --- C --------- J --- K [master]
    //        \               /
    //         \             /
    //          D --- E --- F [foo]
    //           \
    //            \
    //             G --- H [bar]

    try addFile(repo_kind, repo_opts, &repo, io, allocator, "master.md", "a");
    const commit_a = try repo.commit(io, allocator, .{ .message = "a" });
    try addFile(repo_kind, repo_opts, &repo, io, allocator, "master.md", "b");
    const commit_b = try repo.commit(io, allocator, .{ .message = "b" });
    try repo.addBranch(io, .{ .name = "foo" });
    {
        var result = try repo.switchDir(io, allocator, .{ .target = .{ .ref = .{ .kind = .head, .name = "foo" } } });
        defer result.deinit();
    }
    try addFile(repo_kind, repo_opts, &repo, io, allocator, "foo.md", "d");
    const commit_d = try repo.commit(io, allocator, .{ .message = "d" });
    try repo.addBranch(io, .{ .name = "bar" });
    {
        var result = try repo.switchDir(io, allocator, .{ .target = .{ .ref = .{ .kind = .head, .name = "bar" } } });
        defer result.deinit();
    }
    try addFile(repo_kind, repo_opts, &repo, io, allocator, "bar.md", "g");
    _ = try repo.commit(io, allocator, .{ .message = "g" });
    try addFile(repo_kind, repo_opts, &repo, io, allocator, "bar.md", "h");
    const commit_h = try repo.commit(io, allocator, .{ .message = "h" });
    {
        var result = try repo.switchDir(io, allocator, .{ .target = .{ .ref = .{ .kind = .head, .name = "master" } } });
        defer result.deinit();
    }
    try addFile(repo_kind, repo_opts, &repo, io, allocator, "master.md", "c");
    const commit_c = try repo.commit(io, allocator, .{ .message = "c" });
    {
        var result = try repo.switchDir(io, allocator, .{ .target = .{ .ref = .{ .kind = .head, .name = "foo" } } });
        defer result.deinit();
    }
    try addFile(repo_kind, repo_opts, &repo, io, allocator, "foo.md", "e");
    _ = try repo.commit(io, allocator, .{ .message = "e" });
    try addFile(repo_kind, repo_opts, &repo, io, allocator, "foo.md", "f");
    _ = try repo.commit(io, allocator, .{ .message = "f" });
    {
        var result = try repo.switchDir(io, allocator, .{ .target = .{ .ref = .{ .kind = .head, .name = "master" } } });
        defer result.deinit();
    }
    const commit_j = blk: {
        var merge = try repo.merge(io, allocator, .{ .kind = .full, .action = .{ .new = .{ .source = &.{.{ .ref = .{ .kind = .head, .name = "foo" } }} } } }, null);
        defer merge.deinit();
        try std.testing.expect(.success == merge.result);
        break :blk merge.result.success.oid;
    };
    try addFile(repo_kind, repo_opts, &repo, io, allocator, "master.md", "k");
    const commit_k = try repo.commit(io, allocator, .{ .message = "k" });

    if (repo_kind == .xit) {
        try std.testing.expectEqual(4, try repo.commitCount(io, allocator, .{ .oid = &commit_j }));
        try std.testing.expectEqual(5, try repo.commitCount(io, allocator, .{ .oid = &commit_k }));
    }

    // first-parent logs skip the merged branch.
    {
        const expected_oids = [_][hash.hexLen(repo_opts.hash)]u8{ commit_k, commit_j, commit_c, commit_b, commit_a };
        var commit_iter = try repo.log(io, allocator, .{ .start_oids = &.{commit_k}, .first_parent = true });
        defer commit_iter.deinit();
        for (expected_oids) |expected_oid| {
            const commit_object = (try commit_iter.next(allocator)) orelse return error.ExpectedObject;
            defer commit_object.deinit();
            try std.testing.expectEqual(expected_oid, commit_object.oid);
        }
        try std.testing.expectEqual(null, try commit_iter.next(allocator));
    }

    var moment = try repo.core.latestMoment();
    const state = rp.Repo(repo_kind, repo_opts).State(.read_only){ .core = &repo.core, .extra = .{ .moment = &moment } };

    // there are multiple common ancestors, b and d,
    // but d is the best one because it is a descendent of b
    const ancestor_k_h = try mrg.commonAncestor(repo_kind, repo_opts, state, io, allocator, &commit_k, &commit_h);
    try std.testing.expectEqualStrings(&commit_d, &ancestor_k_h);

    // if one commit is an ancestor of the other, it is the best common ancestor
    const ancestor_k_j = try mrg.commonAncestor(repo_kind, repo_opts, state, io, allocator, &commit_k, &commit_j);
    try std.testing.expectEqualStrings(&commit_j, &ancestor_k_j);

    // if we try merging foo again, it does nothing
    {
        var merge = try repo.merge(io, allocator, .{ .kind = .full, .action = .{ .new = .{ .source = &.{.{ .ref = .{ .kind = .head, .name = "foo" } }} } } }, null);
        defer merge.deinit();
        try std.testing.expect(.nothing == merge.result);
    }

    // if we try merging master into foo, it fast forwards
    {
        var switch_result = try repo.switchDir(io, allocator, .{ .target = .{ .ref = .{ .kind = .head, .name = "foo" } } });
        defer switch_result.deinit();
        var merge = try repo.merge(io, allocator, .{ .kind = .full, .action = .{ .new = .{ .source = &.{.{ .ref = .{ .kind = .head, .name = "master" } }} } } }, null);
        defer merge.deinit();
        try std.testing.expect(.fast_forward == merge.result);

        const head_oid = try rf.readHeadRecur(repo_kind, repo_opts, state, io);
        try std.testing.expectEqual(commit_k, head_oid);

        // make sure file from commit k exists
        const master_md_content = try repo.core.work_dir.readFileAlloc(io, "master.md", allocator, .limited(1024));
        defer allocator.free(master_md_content);
        try std.testing.expectEqualStrings("k", master_md_content);
    }

    // copy all objects to a new repo.
    // this will fail if we are not correctly resetting tx_start
    // in `writeAndApplyPatches`, because we'll end up mutating
    // the snapshot of the base commit due to the fact that it has
    // more than one child commits. if that explanation doesn't
    // make sense to you, you're not alone...my future self won't
    // know what it means either probably.
    {
        var obj_iter = try obj.ObjectIterator(repo_kind, repo_opts).init(state, io, allocator, .{ .kind = .all });
        defer obj_iter.deinit();
        try obj_iter.include(&commit_k);

        const dest_work_path = try std.fs.path.join(allocator, &.{ cwd_path, temp_dir_name, "dest_repo" });
        defer allocator.free(dest_work_path);

        var dest_repo = try rp.Repo(repo_kind, repo_opts).init(io, allocator, .{ .path = dest_work_path });
        defer dest_repo.deinit(io, allocator);
        try dest_repo.copyObjects(repo_kind, repo_opts, &obj_iter, io, null);

        var dest_obj_iter = try dest_repo.log(io, allocator, .{ .start_oids = &.{commit_k} });
        defer dest_obj_iter.deinit();
        const dest_commit_k = (try dest_obj_iter.next(allocator)) orelse return error.ExpectedObject;
        defer dest_commit_k.deinit();

        if (repo_kind == .xit) {
            try std.testing.expectEqual(5, try dest_repo.commitCount(io, allocator, .{ .oid = &commit_k }));
        }
    }
}

test "merge side branch" {
    try testMergeSideBranch(.git, .{ .is_test = true });
    try testMergeSideBranch(.xit, .{ .is_test = true });
}

fn testMergeSideBranch(comptime repo_kind: rp.RepoKind, comptime repo_opts: rp.RepoOpts(repo_kind)) !void {
    const io = std.testing.io;
    const allocator = std.testing.allocator;
    const temp_dir_name = "temp-test-repo-merge-side-branch";

    // create the temp dir
    const cwd = std.Io.Dir.cwd();
    var temp_dir_or_err = cwd.openDir(io, temp_dir_name, .{});
    if (temp_dir_or_err) |*temp_dir| {
        temp_dir.close(io);
        try cwd.deleteTree(io, temp_dir_name);
    } else |_| {}
    var temp_dir = try cwd.createDirPathOpen(io, temp_dir_name, .{});
    defer cwd.deleteTree(io, temp_dir_name) catch {};
    defer temp_dir.close(io);

    const cwd_path = try std.process.currentPathAlloc(io, allocator);
    defer allocator.free(cwd_path);

    const work_path = try std.fs.path.join(allocator, &.{ cwd_path, temp_dir_name, "repo" });
    defer allocator.free(work_path);

    {
        var repo = try rp.Repo(repo_kind, repo_opts).init(io, allocator, .{ .path = work_path });
        defer repo.deinit(io, allocator);
    }

    var repo = try rp.Repo(repo_kind, repo_opts).open(io, allocator, .{ .path = work_path });
    defer repo.deinit(io, allocator);

    //           C <------ D [side]
    //          /           \
    //         /             \
    // A <--- B <---- E <---- F <---- G [master]
    //                 \
    //                  \
    //                   \
    //                    H <---- I <---- J [topic]

    try addFile(repo_kind, repo_opts, &repo, io, allocator, "master.md", "a");
    _ = try repo.commit(io, allocator, .{ .message = "a" });

    try addFile(repo_kind, repo_opts, &repo, io, allocator, "master.md", "b");
    _ = try repo.commit(io, allocator, .{ .message = "b" });

    try repo.addBranch(io, .{ .name = "side" });

    {
        var result = try repo.switchDir(io, allocator, .{ .target = .{ .ref = .{ .kind = .head, .name = "side" } } });
        defer result.deinit();
    }

    try addFile(repo_kind, repo_opts, &repo, io, allocator, "side.md", "c");
    _ = try repo.commit(io, allocator, .{ .message = "c" });

    try addFile(repo_kind, repo_opts, &repo, io, allocator, "side.md", "d");
    _ = try repo.commit(io, allocator, .{ .message = "d" });

    {
        var result = try repo.switchDir(io, allocator, .{ .target = .{ .ref = .{ .kind = .head, .name = "master" } } });
        defer result.deinit();
    }

    try addFile(repo_kind, repo_opts, &repo, io, allocator, "master.md", "e");
    const commit_e = try repo.commit(io, allocator, .{ .message = "e" });

    try repo.addBranch(io, .{ .name = "topic" });

    // commit f
    _ = blk: {
        var merge = try repo.merge(io, allocator, .{ .kind = .full, .action = .{ .new = .{ .source = &.{.{ .ref = .{ .kind = .head, .name = "side" } }} } } }, null);
        defer merge.deinit();
        try std.testing.expect(.success == merge.result);
        break :blk merge.result.success.oid;
    };

    try addFile(repo_kind, repo_opts, &repo, io, allocator, "master.md", "g");
    const commit_g = try repo.commit(io, allocator, .{ .message = "g" });

    {
        var result = try repo.switchDir(io, allocator, .{ .target = .{ .ref = .{ .kind = .head, .name = "topic" } } });
        defer result.deinit();
    }

    try addFile(repo_kind, repo_opts, &repo, io, allocator, "topic.md", "h");
    _ = try repo.commit(io, allocator, .{ .message = "h" });

    try addFile(repo_kind, repo_opts, &repo, io, allocator, "topic.md", "i");
    _ = try repo.commit(io, allocator, .{ .message = "i" });

    try addFile(repo_kind, repo_opts, &repo, io, allocator, "topic.md", "j");
    const commit_j = try repo.commit(io, allocator, .{ .message = "j" });

    var moment = try repo.core.latestMoment();
    const state = rp.Repo(repo_kind, repo_opts).State(.read_only){ .core = &repo.core, .extra = .{ .moment = &moment } };

    const ancestor_g_j = try mrg.commonAncestor(repo_kind, repo_opts, state, io, allocator, &commit_g, &commit_j);
    try std.testing.expectEqualStrings(&commit_e, &ancestor_g_j);
}

test "merge conflict" {
    // read and write objects in small increments to help uncover bugs

    // same file conflict
    try testMergeConflictSameFile(.git, .{ .read_size = 1, .is_test = true });
    try testMergeConflictSameFile(.xit, .{ .read_size = 1, .is_test = true, .extra = .{
        .chunk_opts = .{ .min_size = 1, .avg_size = 2, .max_size = 4, .normalization = .level1 },
    } });

    // same file conflict with an empty base
    try testMergeConflictSameFileEmptyBase(.git, .{ .read_size = 1, .is_test = true });
    try testMergeConflictSameFileEmptyBase(.xit, .{ .read_size = 1, .is_test = true, .extra = .{
        .chunk_opts = .{ .min_size = 1, .avg_size = 2, .max_size = 4, .normalization = .level1 },
    } });

    // same file conflict that is autoresolved
    try testMergeConflictSameFileAutoresolved(.git, .{ .read_size = 1, .is_test = true });
    try testMergeConflictSameFileAutoresolved(.xit, .{ .read_size = 1, .is_test = true, .extra = .{
        .chunk_opts = .{ .min_size = 1, .avg_size = 2, .max_size = 4, .normalization = .level1 },
    } });

    // same file conflict on neighboring lines that is autoresolved only with patch-based merging
    try testMergeConflictSameFileAutoresolvedNeighboringLines(.git, .{ .read_size = 1, .is_test = true });
    try testMergeConflictSameFileAutoresolvedNeighboringLines(.xit, .{ .read_size = 1, .is_test = true, .extra = .{
        .chunk_opts = .{ .min_size = 1, .avg_size = 2, .max_size = 4, .normalization = .level1 },
    } });

    // delete/modify conflict (target deletes, source modifies)
    try testMergeConflictModifyDelete(.git, .{ .read_size = 1, .is_test = true });
    try testMergeConflictModifyDelete(.xit, .{ .read_size = 1, .is_test = true, .extra = .{
        .chunk_opts = .{ .min_size = 1, .avg_size = 2, .max_size = 4, .normalization = .level1 },
    } });

    // delete/modify conflict (target deletes, source modifies)
    try testMergeConflictDeleteModify(.git, .{ .read_size = 1, .is_test = true });
    try testMergeConflictDeleteModify(.xit, .{ .read_size = 1, .is_test = true, .extra = .{
        .chunk_opts = .{ .min_size = 1, .avg_size = 2, .max_size = 4, .normalization = .level1 },
    } });

    // file/dir conflict (target has file, source has dir)
    try testMergeConflictFileDir(.git, .{ .read_size = 1, .is_test = true });
    try testMergeConflictFileDir(.xit, .{ .read_size = 1, .is_test = true, .extra = .{
        .chunk_opts = .{ .min_size = 1, .avg_size = 2, .max_size = 4, .normalization = .level1 },
    } });

    // dir/file conflict (target has dir, source has file)
    try testMergeConflictDirFile(.git, .{ .read_size = 1, .is_test = true });
    try testMergeConflictDirFile(.xit, .{ .read_size = 1, .is_test = true, .extra = .{
        .chunk_opts = .{ .min_size = 1, .avg_size = 2, .max_size = 4, .normalization = .level1 },
    } });
}

fn testMergeConflictSameFile(comptime repo_kind: rp.RepoKind, comptime repo_opts: rp.RepoOpts(repo_kind)) !void {
    const io = std.testing.io;
    const allocator = std.testing.allocator;
    const temp_dir_name = "temp-test-repo-merge-conflict-same-file";

    // create the temp dir
    const cwd = std.Io.Dir.cwd();
    var temp_dir_or_err = cwd.openDir(io, temp_dir_name, .{});
    if (temp_dir_or_err) |*temp_dir| {
        temp_dir.close(io);
        try cwd.deleteTree(io, temp_dir_name);
    } else |_| {}
    var temp_dir = try cwd.createDirPathOpen(io, temp_dir_name, .{});
    defer cwd.deleteTree(io, temp_dir_name) catch {};
    defer temp_dir.close(io);

    const cwd_path = try std.process.currentPathAlloc(io, allocator);
    defer allocator.free(cwd_path);

    const work_path = try std.fs.path.join(allocator, &.{ cwd_path, temp_dir_name, "repo" });
    defer allocator.free(work_path);

    {
        var repo = try rp.Repo(repo_kind, repo_opts).init(io, allocator, .{ .path = work_path });
        defer repo.deinit(io, allocator);
    }

    var repo = try rp.Repo(repo_kind, repo_opts).open(io, allocator, .{ .path = work_path });
    defer repo.deinit(io, allocator);

    // A --- B --- D [master]
    //  \         /
    //   \       /
    //    `---- C [foo]

    try addFile(repo_kind, repo_opts, &repo, io, allocator, "f.txt",
        \\a
        \\b
        \\c
    );
    _ = try repo.commit(io, allocator, .{ .message = "a" });
    try repo.addBranch(io, .{ .name = "foo" });
    try addFile(repo_kind, repo_opts, &repo, io, allocator, "f.txt",
        \\a
        \\x
        \\c
    );
    _ = try repo.commit(io, allocator, .{ .message = "b" });
    {
        var result = try repo.switchDir(io, allocator, .{ .target = .{ .ref = .{ .kind = .head, .name = "foo" } } });
        defer result.deinit();
    }
    try addFile(repo_kind, repo_opts, &repo, io, allocator, "f.txt",
        \\a
        \\y
        \\c
    );
    _ = try repo.commit(io, allocator, .{ .message = "c" });
    {
        var result = try repo.switchDir(io, allocator, .{ .target = .{ .ref = .{ .kind = .head, .name = "master" } } });
        defer result.deinit();
    }
    {
        var merge = try repo.merge(io, allocator, .{ .kind = .full, .action = .{ .new = .{ .source = &.{.{ .ref = .{ .kind = .head, .name = "foo" } }} } } }, null);
        defer merge.deinit();
        try std.testing.expect(.conflict == merge.result);

        // verify f.txt has conflict markers
        const f_txt_content = try repo.core.work_dir.readFileAlloc(io, "f.txt", allocator, .limited(1024));
        defer allocator.free(f_txt_content);
        const expected_f_txt_content = try std.fmt.allocPrint(allocator,
            \\a
            \\<<<<<<< target (master)
            \\x
            \\||||||| base ({s})
            \\b
            \\=======
            \\y
            \\>>>>>>> source (foo)
            \\c
        , .{merge.base_oid});
        defer allocator.free(expected_f_txt_content);
        try std.testing.expectEqualStrings(expected_f_txt_content, f_txt_content);
    }

    {
        var root = try ui.rootWidget(repo_kind, repo_opts, &repo, io, allocator, .status);
        defer root.deinit(allocator);

        const grid = try root.getGrid().?.toString(allocator);
        defer allocator.free(grid);

        var grid_without_tabs = grid;
        for (0..3) |_| {
            grid_without_tabs = grid_without_tabs[std.mem.indexOfScalar(u8, grid_without_tabs, '\n').? + 1 ..];
        }

        try std.testing.expectEqualStrings(
            \\           ┌─────────────┐                                                       
            \\ added (0) │not added (1)│ not tracked (0)                                       
            \\           └─────────────┘                                                       
            \\   ┌─────┐          ┌───────────────────────────────────────────────────────────┐
            \\ ≠ │f.txt│          │                                                           │
            \\   └─────┘          │ diff --git a/f.txt b/f.txt                                │
            \\                    │ index 98d5083..c3736c3 100644                             │
            \\                    │ --- a/f.txt                                               │
            \\                    │ +++ b/f.txt                                               │
            \\                    │                                                           │
            \\                    │                                                           │
            \\                    │                                                           │
            \\                    │ @@ -1,3 +1,9 @@                                           │
            \\                    │   a                                                       │
            \\                    │ + <<<<<<< target (master)                                 │
            \\                    │   x                                                       │
            \\                    │ + ||||||| base (31791fdb2aea4e32bde323475a03cfec7ad51bf4) │
            \\                    │ + b                                                       │
            \\                    │ + =======                                                 │
            \\                    │ + y                                                       │
            \\                    │ + >>>>>>> source (foo)                                    │
            \\                    │   c                                                       │
            \\                    │                                                           │
            \\                    │                                                           │
            \\                    └───────────────────────────────────────────────────────────┘
        , grid_without_tabs);
    }

    // generate diff
    var status = try repo.status(io, allocator);
    defer status.deinit(allocator);
    var file_iter = try repo.filePairs(io, allocator, .{
        .work_dir = .{
            .conflict_diff_kind = .target,
            .status = &status,
        },
    });
    if (try file_iter.next()) |*line_iter_pair_ptr| {
        var line_iter_pair = line_iter_pair_ptr.*;
        defer line_iter_pair.deinit();
    } else {
        return error.DiffResultExpected;
    }

    // ensure merge cannot be run again while there are unresolved conflicts
    {
        // can't merge again with an unresolved merge
        {
            var result_or_err = repo.merge(io, allocator, .{ .kind = .full, .action = .{ .new = .{ .source = &.{.{ .ref = .{ .kind = .head, .name = "foo" } }} } } }, null);
            if (result_or_err) |*result| {
                defer result.deinit();
                return error.ExpectedMergeToNotFinish;
            } else |err| switch (err) {
                error.UnfinishedMergeInProgress => {},
                else => |e| return e,
            }
        }

        // can't continue merge with unresolved conflicts
        {
            var result_or_err = repo.merge(io, allocator, .{ .kind = .full, .action = .cont }, null);
            if (result_or_err) |*result| {
                defer result.deinit();
                return error.ExpectedMergeToNotFinish;
            } else |err| switch (err) {
                error.CannotContinueMergeWithUnresolvedConflicts => {},
                else => |e| return e,
            }
        }
    }

    // resolve conflict with changes from source branch
    try addFile(repo_kind, repo_opts, &repo, io, allocator, "f.txt",
        \\a
        \\y
        \\c
    );

    {
        var root = try ui.rootWidget(repo_kind, repo_opts, &repo, io, allocator, .status);
        defer root.deinit(allocator);

        const grid = try root.getGrid().?.toString(allocator);
        defer allocator.free(grid);

        var grid_without_tabs = grid;
        for (0..3) |_| {
            grid_without_tabs = grid_without_tabs[std.mem.indexOfScalar(u8, grid_without_tabs, '\n').? + 1 ..];
        }

        try std.testing.expectEqualStrings(
            \\┌─────────┐                                                                     
            \\│added (1)│ not added (0)  not tracked (0)                                      
            \\└─────────┘                                                                     
            \\   ┌─────┐          ┌──────────────────────────────────────────────────────────┐
            \\ ± │f.txt│          │                                                          │
            \\   └─────┘          │ diff --git a/f.txt b/f.txt                               │
            \\                    │ index 98d5083..ae42890 100644                            │
            \\                    │ --- a/f.txt                                              │
            \\                    │ +++ b/f.txt                                              │
            \\                    │                                                          │
            \\                    │                                                          │
            \\                    │                                                          │
            \\                    │ @@ -1,3 +1,3 @@                                          │
            \\                    │   a                                                      │
            \\                    │ - x                                                      │
            \\                    │ + y                                                      │
            \\                    │   c                                                      │
            \\                    │                                                          │
            \\                    │                                                          │
            \\                    └──────────────────────────────────────────────────────────┘
        , grid_without_tabs);
    }

    // resolve conflict with changes from target branch
    try addFile(repo_kind, repo_opts, &repo, io, allocator, "f.txt",
        \\a
        \\x
        \\c
    );

    {
        var root = try ui.rootWidget(repo_kind, repo_opts, &repo, io, allocator, .status);
        defer root.deinit(allocator);

        const grid = try root.getGrid().?.toString(allocator);
        defer allocator.free(grid);

        var grid_without_tabs = grid;
        for (0..3) |_| {
            grid_without_tabs = grid_without_tabs[std.mem.indexOfScalar(u8, grid_without_tabs, '\n').? + 1 ..];
        }

        try std.testing.expectEqualStrings(
            \\┌─────────┐                                                                     
            \\│added (1)│ not added (0)  not tracked (0)                                      
            \\└─────────┘                                                                     
            \\   ┌─────┐          ┌──────────────────────────────────────────────────────────┐
            \\ ≠ │f.txt│          │                                                          │
            \\   └─────┘          │ diff --git a/f.txt b/f.txt                               │
            \\                    │ index ae42890..98d5083 100644                            │
            \\                    │ --- a/f.txt                                              │
            \\                    │ +++ b/f.txt                                              │
            \\                    │                                                          │
            \\                    │                                                          │
            \\                    │                                                          │
            \\                    │ @@ -1,3 +1,3 @@                                          │
            \\                    │   a                                                      │
            \\                    │ - y                                                      │
            \\                    │ + x                                                      │
            \\                    │   c                                                      │
            \\                    │                                                          │
            \\                    │                                                          │
            \\                    └──────────────────────────────────────────────────────────┘
        , grid_without_tabs);
    }

    {
        var merge = try repo.merge(io, allocator, .{ .kind = .full, .action = .cont }, null);
        defer merge.deinit();
        try std.testing.expect(.success == merge.result);
    }

    // if we try merging foo again, it does nothing
    {
        var merge = try repo.merge(io, allocator, .{ .kind = .full, .action = .{ .new = .{ .source = &.{.{ .ref = .{ .kind = .head, .name = "foo" } }} } } }, null);
        defer merge.deinit();
        try std.testing.expect(.nothing == merge.result);
    }
}

fn testMergeConflictSameFileEmptyBase(comptime repo_kind: rp.RepoKind, comptime repo_opts: rp.RepoOpts(repo_kind)) !void {
    const io = std.testing.io;
    const allocator = std.testing.allocator;
    const temp_dir_name = "temp-test-repo-merge-conflict-same-file-empty-base";

    // create the temp dir
    const cwd = std.Io.Dir.cwd();
    var temp_dir_or_err = cwd.openDir(io, temp_dir_name, .{});
    if (temp_dir_or_err) |*temp_dir| {
        temp_dir.close(io);
        try cwd.deleteTree(io, temp_dir_name);
    } else |_| {}
    var temp_dir = try cwd.createDirPathOpen(io, temp_dir_name, .{});
    defer cwd.deleteTree(io, temp_dir_name) catch {};
    defer temp_dir.close(io);

    const cwd_path = try std.process.currentPathAlloc(io, allocator);
    defer allocator.free(cwd_path);

    const work_path = try std.fs.path.join(allocator, &.{ cwd_path, temp_dir_name, "repo" });
    defer allocator.free(work_path);

    {
        var repo = try rp.Repo(repo_kind, repo_opts).init(io, allocator, .{ .path = work_path });
        defer repo.deinit(io, allocator);
    }

    var repo = try rp.Repo(repo_kind, repo_opts).open(io, allocator, .{ .path = work_path });
    defer repo.deinit(io, allocator);

    // A --- B --- D [master]
    //  \         /
    //   \       /
    //    `---- C [foo]

    // commit A (base commit) is empty
    _ = try repo.commit(io, allocator, .{ .message = "a", .allow_empty = true });

    // newlines are intentionally added to the end of the files this time,
    // to test that the merge code behaves correctly with end lines of zero length

    try repo.addBranch(io, .{ .name = "foo" });
    try addFile(repo_kind, repo_opts, &repo, io, allocator, "f.txt",
        \\a
        \\x
        \\c
        \\
    );
    _ = try repo.commit(io, allocator, .{ .message = "b" });
    {
        var result = try repo.switchDir(io, allocator, .{ .target = .{ .ref = .{ .kind = .head, .name = "foo" } } });
        defer result.deinit();
    }
    try addFile(repo_kind, repo_opts, &repo, io, allocator, "f.txt",
        \\a
        \\y
        \\c
        \\
    );
    _ = try repo.commit(io, allocator, .{ .message = "c" });
    {
        var result = try repo.switchDir(io, allocator, .{ .target = .{ .ref = .{ .kind = .head, .name = "master" } } });
        defer result.deinit();
    }
    {
        var merge = try repo.merge(io, allocator, .{ .kind = .full, .action = .{ .new = .{ .source = &.{.{ .ref = .{ .kind = .head, .name = "foo" } }} } } }, null);
        defer merge.deinit();
        try std.testing.expect(.conflict == merge.result);

        // verify f.txt has conflict markers
        const f_txt_content = try repo.core.work_dir.readFileAlloc(io, "f.txt", allocator, .limited(1024));
        defer allocator.free(f_txt_content);
        const expected_f_txt_content = try std.fmt.allocPrint(allocator,
            \\<<<<<<< target (master)
            \\a
            \\x
            \\c
            \\
            \\||||||| base ({s})
            \\=======
            \\a
            \\y
            \\c
            \\
            \\>>>>>>> source (foo)
        , .{merge.base_oid});
        defer allocator.free(expected_f_txt_content);
        try std.testing.expectEqualStrings(expected_f_txt_content, f_txt_content);
    }

    {
        var root = try ui.rootWidget(repo_kind, repo_opts, &repo, io, allocator, .status);
        defer root.deinit(allocator);

        const grid = try root.getGrid().?.toString(allocator);
        defer allocator.free(grid);

        var grid_without_tabs = grid;
        for (0..3) |_| {
            grid_without_tabs = grid_without_tabs[std.mem.indexOfScalar(u8, grid_without_tabs, '\n').? + 1 ..];
        }

        try std.testing.expectEqualStrings(
            \\           ┌─────────────┐                                                       
            \\ added (0) │not added (1)│ not tracked (0)                                       
            \\           └─────────────┘                                                       
            \\   ┌─────┐          ┌───────────────────────────────────────────────────────────┐
            \\ ≠ │f.txt│          │                                                           │
            \\   └─────┘          │ diff --git a/f.txt b/f.txt                                │
            \\                    │ index f5aa8c1..c4f76dc 100644                             │
            \\                    │ --- a/f.txt                                               │
            \\                    │ +++ b/f.txt                                               │
            \\                    │                                                           │
            \\                    │                                                           │
            \\                    │                                                           │
            \\                    │ @@ -1,4 +1,12 @@                                          │
            \\                    │ + <<<<<<< target (master)                                 │
            \\                    │   a                                                       │
            \\                    │   x                                                       │
            \\                    │ + c                                                       │
            \\                    │ +                                                         │
            \\                    │ + ||||||| base (7b0a80ff255e0024621edbbb4d75b2859e8601e9) │
            \\                    │ + =======                                                 │
            \\                    │ + a                                                       │
            \\                    │ + y                                                       │
            \\                    │   c                                                       │
            \\                    │                                                           │
            \\                    │ + >>>>>>> source (foo)                                    │
            \\                    │                                                           │
            \\                    │                                                           │
            \\                    └───────────────────────────────────────────────────────────┘
        , grid_without_tabs);
    }

    // generate diff
    var status = try repo.status(io, allocator);
    defer status.deinit(allocator);
    var file_iter = try repo.filePairs(io, allocator, .{
        .work_dir = .{
            .conflict_diff_kind = .target,
            .status = &status,
        },
    });
    if (try file_iter.next()) |*line_iter_pair_ptr| {
        var line_iter_pair = line_iter_pair_ptr.*;
        defer line_iter_pair.deinit();
    } else {
        return error.DiffResultExpected;
    }

    // ensure merge cannot be run again while there are unresolved conflicts
    {
        // can't merge again with an unresolved merge
        {
            var result_or_err = repo.merge(io, allocator, .{ .kind = .full, .action = .{ .new = .{ .source = &.{.{ .ref = .{ .kind = .head, .name = "foo" } }} } } }, null);
            if (result_or_err) |*result| {
                defer result.deinit();
                return error.ExpectedMergeToNotFinish;
            } else |err| switch (err) {
                error.UnfinishedMergeInProgress => {},
                else => |e| return e,
            }
        }

        // can't continue merge with unresolved conflicts
        {
            var result_or_err = repo.merge(io, allocator, .{ .kind = .full, .action = .cont }, null);
            if (result_or_err) |*result| {
                defer result.deinit();
                return error.ExpectedMergeToNotFinish;
            } else |err| switch (err) {
                error.CannotContinueMergeWithUnresolvedConflicts => {},
                else => |e| return e,
            }
        }
    }

    // resolve conflict with changes from source branch
    try addFile(repo_kind, repo_opts, &repo, io, allocator, "f.txt",
        \\a
        \\y
        \\c
        \\
    );

    {
        var root = try ui.rootWidget(repo_kind, repo_opts, &repo, io, allocator, .status);
        defer root.deinit(allocator);

        const grid = try root.getGrid().?.toString(allocator);
        defer allocator.free(grid);

        var grid_without_tabs = grid;
        for (0..3) |_| {
            grid_without_tabs = grid_without_tabs[std.mem.indexOfScalar(u8, grid_without_tabs, '\n').? + 1 ..];
        }

        try std.testing.expectEqualStrings(
            \\┌─────────┐                                                                     
            \\│added (1)│ not added (0)  not tracked (0)                                      
            \\└─────────┘                                                                     
            \\   ┌─────┐          ┌──────────────────────────────────────────────────────────┐
            \\ ± │f.txt│          │                                                          │
            \\   └─────┘          │ diff --git a/f.txt b/f.txt                               │
            \\                    │ index f5aa8c1..475bb7f 100644                            │
            \\                    │ --- a/f.txt                                              │
            \\                    │ +++ b/f.txt                                              │
            \\                    │                                                          │
            \\                    │                                                          │
            \\                    │                                                          │
            \\                    │ @@ -1,4 +1,4 @@                                          │
            \\                    │   a                                                      │
            \\                    │ - x                                                      │
            \\                    │ + y                                                      │
            \\                    │   c                                                      │
            \\                    │                                                          │
            \\                    │                                                          │
            \\                    │                                                          │
            \\                    └──────────────────────────────────────────────────────────┘
        , grid_without_tabs);
    }

    // resolve conflict with changes from target branch
    try addFile(repo_kind, repo_opts, &repo, io, allocator, "f.txt",
        \\a
        \\x
        \\c
        \\
    );

    {
        var root = try ui.rootWidget(repo_kind, repo_opts, &repo, io, allocator, .status);
        defer root.deinit(allocator);

        const grid = try root.getGrid().?.toString(allocator);
        defer allocator.free(grid);

        var grid_without_tabs = grid;
        for (0..3) |_| {
            grid_without_tabs = grid_without_tabs[std.mem.indexOfScalar(u8, grid_without_tabs, '\n').? + 1 ..];
        }

        try std.testing.expectEqualStrings(
            \\┌─────────┐                                                                     
            \\│added (1)│ not added (0)  not tracked (0)                                      
            \\└─────────┘                                                                     
            \\   ┌─────┐          ┌──────────────────────────────────────────────────────────┐
            \\ ≠ │f.txt│          │                                                          │
            \\   └─────┘          │ diff --git a/f.txt b/f.txt                               │
            \\                    │ index 475bb7f..f5aa8c1 100644                            │
            \\                    │ --- a/f.txt                                              │
            \\                    │ +++ b/f.txt                                              │
            \\                    │                                                          │
            \\                    │                                                          │
            \\                    │                                                          │
            \\                    │ @@ -1,4 +1,4 @@                                          │
            \\                    │   a                                                      │
            \\                    │ - y                                                      │
            \\                    │ + x                                                      │
            \\                    │   c                                                      │
            \\                    │                                                          │
            \\                    │                                                          │
            \\                    │                                                          │
            \\                    └──────────────────────────────────────────────────────────┘
        , grid_without_tabs);
    }

    {
        var merge = try repo.merge(io, allocator, .{ .kind = .full, .action = .cont }, null);
        defer merge.deinit();
        try std.testing.expect(.success == merge.result);
    }

    // if we try merging foo again, it does nothing
    {
        var merge = try repo.merge(io, allocator, .{ .kind = .full, .action = .{ .new = .{ .source = &.{.{ .ref = .{ .kind = .head, .name = "foo" } }} } } }, null);
        defer merge.deinit();
        try std.testing.expect(.nothing == merge.result);
    }
}

fn testMergeConflictSameFileAutoresolved(comptime repo_kind: rp.RepoKind, comptime repo_opts: rp.RepoOpts(repo_kind)) !void {
    const io = std.testing.io;
    const allocator = std.testing.allocator;
    const temp_dir_name = "temp-test-repo-merge-conflict-same-file-autoresolved";

    // create the temp dir
    const cwd = std.Io.Dir.cwd();
    var temp_dir_or_err = cwd.openDir(io, temp_dir_name, .{});
    if (temp_dir_or_err) |*temp_dir| {
        temp_dir.close(io);
        try cwd.deleteTree(io, temp_dir_name);
    } else |_| {}
    var temp_dir = try cwd.createDirPathOpen(io, temp_dir_name, .{});
    defer cwd.deleteTree(io, temp_dir_name) catch {};
    defer temp_dir.close(io);

    const cwd_path = try std.process.currentPathAlloc(io, allocator);
    defer allocator.free(cwd_path);

    const work_path = try std.fs.path.join(allocator, &.{ cwd_path, temp_dir_name, "repo" });
    defer allocator.free(work_path);

    {
        var repo = try rp.Repo(repo_kind, repo_opts).init(io, allocator, .{ .path = work_path });
        defer repo.deinit(io, allocator);
    }

    var repo = try rp.Repo(repo_kind, repo_opts).open(io, allocator, .{ .path = work_path });
    defer repo.deinit(io, allocator);

    // A --- B --- D [master]
    //  \         /
    //   \       /
    //    `---- C [foo]

    try addFile(repo_kind, repo_opts, &repo, io, allocator, "f.txt",
        \\a
        \\b
        \\c
    );
    _ = try repo.commit(io, allocator, .{ .message = "a" });
    try repo.addBranch(io, .{ .name = "foo" });
    try addFile(repo_kind, repo_opts, &repo, io, allocator, "f.txt",
        \\x
        \\b
        \\c
    );
    _ = try repo.commit(io, allocator, .{ .message = "b" });
    {
        var result = try repo.switchDir(io, allocator, .{ .target = .{ .ref = .{ .kind = .head, .name = "foo" } } });
        defer result.deinit();
    }
    try addFile(repo_kind, repo_opts, &repo, io, allocator, "f.txt",
        \\a
        \\b
        \\y
    );
    _ = try repo.commit(io, allocator, .{ .message = "c" });
    {
        var result = try repo.switchDir(io, allocator, .{ .target = .{ .ref = .{ .kind = .head, .name = "master" } } });
        defer result.deinit();
    }
    {
        var merge = try repo.merge(io, allocator, .{ .kind = .full, .action = .{ .new = .{ .source = &.{.{ .ref = .{ .kind = .head, .name = "foo" } }} } } }, null);
        defer merge.deinit();
        try std.testing.expect(.success == merge.result);

        // verify f.txt has been autoresolved
        const f_txt_content = try repo.core.work_dir.readFileAlloc(io, "f.txt", allocator, .limited(1024));
        defer allocator.free(f_txt_content);
        try std.testing.expectEqualStrings(
            \\x
            \\b
            \\y
        ,
            f_txt_content,
        );
    }

    // generate diff
    var status = try repo.status(io, allocator);
    defer status.deinit(allocator);
    var file_iter = try repo.filePairs(io, allocator, .{
        .work_dir = .{
            .conflict_diff_kind = .target,
            .status = &status,
        },
    });
    if (try file_iter.next()) |*line_iter_pair_ptr| {
        var line_iter_pair = line_iter_pair_ptr.*;
        defer line_iter_pair.deinit();
        return error.DiffResultNotExpected;
    }

    // if we try merging foo again, it does nothing
    {
        var merge = try repo.merge(io, allocator, .{ .kind = .full, .action = .{ .new = .{ .source = &.{.{ .ref = .{ .kind = .head, .name = "foo" } }} } } }, null);
        defer merge.deinit();
        try std.testing.expect(.nothing == merge.result);
    }
}

fn testMergeConflictSameFileAutoresolvedNeighboringLines(comptime repo_kind: rp.RepoKind, comptime repo_opts: rp.RepoOpts(repo_kind)) !void {
    const io = std.testing.io;
    const allocator = std.testing.allocator;
    const temp_dir_name = "temp-test-repo-merge-conflict-same-file-autoresolved-neighboring-lines";

    // create the temp dir
    const cwd = std.Io.Dir.cwd();
    var temp_dir_or_err = cwd.openDir(io, temp_dir_name, .{});
    if (temp_dir_or_err) |*temp_dir| {
        temp_dir.close(io);
        try cwd.deleteTree(io, temp_dir_name);
    } else |_| {}
    var temp_dir = try cwd.createDirPathOpen(io, temp_dir_name, .{});
    defer cwd.deleteTree(io, temp_dir_name) catch {};
    defer temp_dir.close(io);

    const cwd_path = try std.process.currentPathAlloc(io, allocator);
    defer allocator.free(cwd_path);

    const work_path = try std.fs.path.join(allocator, &.{ cwd_path, temp_dir_name, "repo" });
    defer allocator.free(work_path);

    {
        var repo = try rp.Repo(repo_kind, repo_opts).init(io, allocator, .{ .path = work_path });
        defer repo.deinit(io, allocator);
    }

    var repo = try rp.Repo(repo_kind, repo_opts).open(io, allocator, .{ .path = work_path });
    defer repo.deinit(io, allocator);

    // A --- B --- D [master]
    //  \         /
    //   \       /
    //    `---- C [foo]

    try addFile(repo_kind, repo_opts, &repo, io, allocator, "f.txt",
        \\a
        \\b
        \\c
        \\d
    );
    _ = try repo.commit(io, allocator, .{ .message = "a" });
    try repo.addBranch(io, .{ .name = "foo" });
    try addFile(repo_kind, repo_opts, &repo, io, allocator, "f.txt",
        \\a
        \\b
        \\e
        \\d
    );
    const commit_b = try repo.commit(io, allocator, .{ .message = "b" });
    {
        var result = try repo.switchDir(io, allocator, .{ .target = .{ .ref = .{ .kind = .head, .name = "foo" } } });
        defer result.deinit();
    }
    try addFile(repo_kind, repo_opts, &repo, io, allocator, "f.txt",
        \\a
        \\f
        \\c
        \\d
    );
    _ = try repo.commit(io, allocator, .{ .message = "c" });
    {
        var result = try repo.switchDir(io, allocator, .{ .target = .{ .ref = .{ .kind = .head, .name = "master" } } });
        defer result.deinit();
    }

    {
        var merge = try repo.merge(io, allocator, .{ .kind = .full, .action = .{ .new = .{ .source = &.{.{ .ref = .{ .kind = .head, .name = "foo" } }} } } }, null);
        defer merge.deinit();

        // the conflict is only autoresolved when patch-based merging is enabled
        switch (repo_kind) {
            .xit => {
                try std.testing.expect(.success == merge.result);

                // verify f.txt has been autoresolved
                const f_txt_content = try repo.core.work_dir.readFileAlloc(io, "f.txt", allocator, .limited(1024));
                defer allocator.free(f_txt_content);
                try std.testing.expectEqualStrings(
                    \\a
                    \\f
                    \\e
                    \\d
                ,
                    f_txt_content,
                );

                // generate diff
                var status = try repo.status(io, allocator);
                defer status.deinit(allocator);
                var file_iter = try repo.filePairs(io, allocator, .{
                    .work_dir = .{
                        .conflict_diff_kind = .target,
                        .status = &status,
                    },
                });
                if (try file_iter.next()) |*line_iter_pair_ptr| {
                    var line_iter_pair = line_iter_pair_ptr.*;
                    defer line_iter_pair.deinit();
                    return error.DiffResultNotExpected;
                }

                // if we try merging foo again, it does nothing
                {
                    var merge_again = try repo.merge(io, allocator, .{ .kind = .full, .action = .{ .new = .{ .source = &.{.{ .ref = .{ .kind = .head, .name = "foo" } }} } } }, null);
                    defer merge_again.deinit();
                    try std.testing.expect(.nothing == merge_again.result);
                }

                // undo merge
                var result = try repo.resetDir(io, allocator, .{ .target = .{ .oid = &commit_b }, .force = true });
                defer result.deinit();
            },
            .git => {
                try std.testing.expect(.conflict == merge.result);

                // abort merge
                var result = try repo.resetDir(io, allocator, .{ .target = null, .force = true });
                defer result.deinit();
            },
        }
    }

    // now try merging from the other direction

    {
        var result = try repo.switchDir(io, allocator, .{ .target = .{ .ref = .{ .kind = .head, .name = "foo" } } });
        defer result.deinit();
    }

    {
        var merge = try repo.merge(io, allocator, .{ .kind = .full, .action = .{ .new = .{ .source = &.{.{ .ref = .{ .kind = .head, .name = "master" } }} } } }, null);
        defer merge.deinit();

        // the conflict is only autoresolved when patch-based merging is enabled
        switch (repo_kind) {
            .xit => {
                try std.testing.expect(.success == merge.result);

                // verify f.txt has been autoresolved
                const f_txt_content = try repo.core.work_dir.readFileAlloc(io, "f.txt", allocator, .limited(1024));
                defer allocator.free(f_txt_content);
                try std.testing.expectEqualStrings(
                    \\a
                    \\f
                    \\e
                    \\d
                ,
                    f_txt_content,
                );

                // generate diff
                var status = try repo.status(io, allocator);
                defer status.deinit(allocator);
                var file_iter = try repo.filePairs(io, allocator, .{
                    .work_dir = .{
                        .conflict_diff_kind = .target,
                        .status = &status,
                    },
                });
                if (try file_iter.next()) |*line_iter_pair_ptr| {
                    var line_iter_pair = line_iter_pair_ptr.*;
                    defer line_iter_pair.deinit();
                    return error.DiffResultNotExpected;
                }

                // if we try merging foo again, it does nothing
                {
                    var merge_again = try repo.merge(io, allocator, .{ .kind = .full, .action = .{ .new = .{ .source = &.{.{ .ref = .{ .kind = .head, .name = "master" } }} } } }, null);
                    defer merge_again.deinit();
                    try std.testing.expect(.nothing == merge_again.result);
                }
            },
            .git => try std.testing.expect(.conflict == merge.result),
        }
    }
}

fn testMergeConflictModifyDelete(comptime repo_kind: rp.RepoKind, comptime repo_opts: rp.RepoOpts(repo_kind)) !void {
    const io = std.testing.io;
    const allocator = std.testing.allocator;
    const temp_dir_name = "temp-test-repo-merge-conflict-modify-delete";

    // create the temp dir
    const cwd = std.Io.Dir.cwd();
    var temp_dir_or_err = cwd.openDir(io, temp_dir_name, .{});
    if (temp_dir_or_err) |*temp_dir| {
        temp_dir.close(io);
        try cwd.deleteTree(io, temp_dir_name);
    } else |_| {}
    var temp_dir = try cwd.createDirPathOpen(io, temp_dir_name, .{});
    defer cwd.deleteTree(io, temp_dir_name) catch {};
    defer temp_dir.close(io);

    const cwd_path = try std.process.currentPathAlloc(io, allocator);
    defer allocator.free(cwd_path);

    const work_path = try std.fs.path.join(allocator, &.{ cwd_path, temp_dir_name, "repo" });
    defer allocator.free(work_path);

    {
        var repo = try rp.Repo(repo_kind, repo_opts).init(io, allocator, .{ .path = work_path });
        defer repo.deinit(io, allocator);
    }

    var repo = try rp.Repo(repo_kind, repo_opts).open(io, allocator, .{ .path = work_path });
    defer repo.deinit(io, allocator);

    // A --- B --- D [master]
    //  \         /
    //   \       /
    //    `---- C [foo]

    try addFile(repo_kind, repo_opts, &repo, io, allocator, "f.txt", "1");
    _ = try repo.commit(io, allocator, .{ .message = "a" });
    try repo.addBranch(io, .{ .name = "foo" });
    try addFile(repo_kind, repo_opts, &repo, io, allocator, "f.txt", "2");
    _ = try repo.commit(io, allocator, .{ .message = "b" });
    {
        var result = try repo.switchDir(io, allocator, .{ .target = .{ .ref = .{ .kind = .head, .name = "foo" } } });
        defer result.deinit();
    }
    try repo.remove(io, allocator, &.{"f.txt"}, .{});
    _ = try repo.commit(io, allocator, .{ .message = "c" });
    {
        var result = try repo.switchDir(io, allocator, .{ .target = .{ .ref = .{ .kind = .head, .name = "master" } } });
        defer result.deinit();
    }
    {
        var merge = try repo.merge(io, allocator, .{ .kind = .full, .action = .{ .new = .{ .source = &.{.{ .ref = .{ .kind = .head, .name = "foo" } }} } } }, null);
        defer merge.deinit();
        try std.testing.expect(.conflict == merge.result);
    }

    {
        var root = try ui.rootWidget(repo_kind, repo_opts, &repo, io, allocator, .status);
        defer root.deinit(allocator);

        const grid = try root.getGrid().?.toString(allocator);
        defer allocator.free(grid);

        var grid_without_tabs = grid;
        for (0..3) |_| {
            grid_without_tabs = grid_without_tabs[std.mem.indexOfScalar(u8, grid_without_tabs, '\n').? + 1 ..];
        }

        try std.testing.expectEqualStrings(
            \\           ┌─────────────┐                                                      
            \\ added (0) │not added (1)│ not tracked (0)                                      
            \\           └─────────────┘                                                      
            \\   ┌─────┐          ┌──────────────────────────────────────────────────────────┐
            \\ ≠ │f.txt│          │                                                          │
            \\   └─────┘          │ diff --git a/f.txt b/f.txt                               │
            \\                    │                                                          │
            \\                    │                                                          │
            \\                    └──────────────────────────────────────────────────────────┘
        , grid_without_tabs);
    }

    // generate diff
    var status = try repo.status(io, allocator);
    defer status.deinit(allocator);
    var file_iter = try repo.filePairs(io, allocator, .{
        .work_dir = .{
            .conflict_diff_kind = .target,
            .status = &status,
        },
    });
    if (try file_iter.next()) |*line_iter_pair_ptr| {
        var line_iter_pair = line_iter_pair_ptr.*;
        defer line_iter_pair.deinit();
        try std.testing.expectEqualStrings("f.txt", line_iter_pair.path);
    } else {
        return error.DiffResultExpected;
    }

    // ensure merge cannot be run again while there are unresolved conflicts
    {
        // can't merge again with an unresolved merge
        {
            var result_or_err = repo.merge(io, allocator, .{ .kind = .full, .action = .{ .new = .{ .source = &.{.{ .ref = .{ .kind = .head, .name = "foo" } }} } } }, null);
            if (result_or_err) |*result| {
                defer result.deinit();
                return error.ExpectedMergeToNotFinish;
            } else |err| switch (err) {
                error.UnfinishedMergeInProgress => {},
                else => |e| return e,
            }
        }

        // can't continue merge with unresolved conflicts
        {
            var result_or_err = repo.merge(io, allocator, .{ .kind = .full, .action = .cont }, null);
            if (result_or_err) |*result| {
                defer result.deinit();
                return error.ExpectedMergeToNotFinish;
            } else |err| switch (err) {
                error.CannotContinueMergeWithUnresolvedConflicts => {},
                else => |e| return e,
            }
        }
    }

    // resolve conflict
    try repo.add(io, allocator, &.{"f.txt"});
    {
        var merge = try repo.merge(io, allocator, .{ .kind = .full, .action = .cont }, null);
        defer merge.deinit();
        try std.testing.expect(.success == merge.result);
    }

    // if we try merging foo again, it does nothing
    {
        var merge = try repo.merge(io, allocator, .{ .kind = .full, .action = .{ .new = .{ .source = &.{.{ .ref = .{ .kind = .head, .name = "foo" } }} } } }, null);
        defer merge.deinit();
        try std.testing.expect(.nothing == merge.result);
    }
}

fn testMergeConflictDeleteModify(comptime repo_kind: rp.RepoKind, comptime repo_opts: rp.RepoOpts(repo_kind)) !void {
    const io = std.testing.io;
    const allocator = std.testing.allocator;
    const temp_dir_name = "temp-test-repo-merge-conflict-delete-modify";

    // create the temp dir
    const cwd = std.Io.Dir.cwd();
    var temp_dir_or_err = cwd.openDir(io, temp_dir_name, .{});
    if (temp_dir_or_err) |*temp_dir| {
        temp_dir.close(io);
        try cwd.deleteTree(io, temp_dir_name);
    } else |_| {}
    var temp_dir = try cwd.createDirPathOpen(io, temp_dir_name, .{});
    defer cwd.deleteTree(io, temp_dir_name) catch {};
    defer temp_dir.close(io);

    const cwd_path = try std.process.currentPathAlloc(io, allocator);
    defer allocator.free(cwd_path);

    const work_path = try std.fs.path.join(allocator, &.{ cwd_path, temp_dir_name, "repo" });
    defer allocator.free(work_path);

    {
        var repo = try rp.Repo(repo_kind, repo_opts).init(io, allocator, .{ .path = work_path });
        defer repo.deinit(io, allocator);
    }

    var repo = try rp.Repo(repo_kind, repo_opts).open(io, allocator, .{ .path = work_path });
    defer repo.deinit(io, allocator);

    // A --- B --- D [master]
    //  \         /
    //   \       /
    //    `---- C [foo]

    try addFile(repo_kind, repo_opts, &repo, io, allocator, "f.txt", "1");
    _ = try repo.commit(io, allocator, .{ .message = "a" });
    try repo.addBranch(io, .{ .name = "foo" });
    try repo.remove(io, allocator, &.{"f.txt"}, .{});
    _ = try repo.commit(io, allocator, .{ .message = "b" });
    {
        var result = try repo.switchDir(io, allocator, .{ .target = .{ .ref = .{ .kind = .head, .name = "foo" } } });
        defer result.deinit();
    }
    try addFile(repo_kind, repo_opts, &repo, io, allocator, "f.txt", "2");
    _ = try repo.commit(io, allocator, .{ .message = "c" });
    {
        var result = try repo.switchDir(io, allocator, .{ .target = .{ .ref = .{ .kind = .head, .name = "master" } } });
        defer result.deinit();
    }
    {
        var merge = try repo.merge(io, allocator, .{ .kind = .full, .action = .{ .new = .{ .source = &.{.{ .ref = .{ .kind = .head, .name = "foo" } }} } } }, null);
        defer merge.deinit();
        try std.testing.expect(.conflict == merge.result);
    }

    {
        var root = try ui.rootWidget(repo_kind, repo_opts, &repo, io, allocator, .status);
        defer root.deinit(allocator);

        const grid = try root.getGrid().?.toString(allocator);
        defer allocator.free(grid);

        var grid_without_tabs = grid;
        for (0..3) |_| {
            grid_without_tabs = grid_without_tabs[std.mem.indexOfScalar(u8, grid_without_tabs, '\n').? + 1 ..];
        }

        try std.testing.expectEqualStrings(
            \\           ┌─────────────┐                                                      
            \\ added (0) │not added (1)│ not tracked (0)                                      
            \\           └─────────────┘                                                      
            \\   ┌─────┐          ┌──────────────────────────────────────────────────────────┐
            \\ ≠ │f.txt│          │                                                          │
            \\   └─────┘          │ diff --git a/f.txt b/f.txt                               │
            \\                    │                                                          │
            \\                    │                                                          │
            \\                    └──────────────────────────────────────────────────────────┘
        , grid_without_tabs);
    }

    // generate diff
    var status = try repo.status(io, allocator);
    defer status.deinit(allocator);
    var file_iter = try repo.filePairs(io, allocator, .{
        .work_dir = .{
            .conflict_diff_kind = .target,
            .status = &status,
        },
    });
    if (try file_iter.next()) |*line_iter_pair_ptr| {
        var line_iter_pair = line_iter_pair_ptr.*;
        defer line_iter_pair.deinit();
        return error.DiffResultNotExpected;
    }

    // ensure merge cannot be run again while there are unresolved conflicts
    {
        // can't merge again with an unresolved merge
        {
            var result_or_err = repo.merge(io, allocator, .{ .kind = .full, .action = .{ .new = .{ .source = &.{.{ .ref = .{ .kind = .head, .name = "foo" } }} } } }, null);
            if (result_or_err) |*result| {
                defer result.deinit();
                return error.ExpectedMergeToNotFinish;
            } else |err| switch (err) {
                error.UnfinishedMergeInProgress => {},
                else => |e| return e,
            }
        }

        // can't continue merge with unresolved conflicts
        {
            var result_or_err = repo.merge(io, allocator, .{ .kind = .full, .action = .cont }, null);
            if (result_or_err) |*result| {
                defer result.deinit();
                return error.ExpectedMergeToNotFinish;
            } else |err| switch (err) {
                error.CannotContinueMergeWithUnresolvedConflicts => {},
                else => |e| return e,
            }
        }
    }

    // resolve conflict
    try repo.add(io, allocator, &.{"f.txt"});
    {
        var merge = try repo.merge(io, allocator, .{ .kind = .full, .action = .cont }, null);
        defer merge.deinit();
        try std.testing.expect(.success == merge.result);
    }

    // if we try merging foo again, it does nothing
    {
        var merge = try repo.merge(io, allocator, .{ .kind = .full, .action = .{ .new = .{ .source = &.{.{ .ref = .{ .kind = .head, .name = "foo" } }} } } }, null);
        defer merge.deinit();
        try std.testing.expect(.nothing == merge.result);
    }
}

fn testMergeConflictFileDir(comptime repo_kind: rp.RepoKind, comptime repo_opts: rp.RepoOpts(repo_kind)) !void {
    const io = std.testing.io;
    const allocator = std.testing.allocator;
    const temp_dir_name = "temp-test-repo-merge-conflict-file-dir";

    // create the temp dir
    const cwd = std.Io.Dir.cwd();
    var temp_dir_or_err = cwd.openDir(io, temp_dir_name, .{});
    if (temp_dir_or_err) |*temp_dir| {
        temp_dir.close(io);
        try cwd.deleteTree(io, temp_dir_name);
    } else |_| {}
    var temp_dir = try cwd.createDirPathOpen(io, temp_dir_name, .{});
    defer cwd.deleteTree(io, temp_dir_name) catch {};
    defer temp_dir.close(io);

    const cwd_path = try std.process.currentPathAlloc(io, allocator);
    defer allocator.free(cwd_path);

    const work_path = try std.fs.path.join(allocator, &.{ cwd_path, temp_dir_name, "repo" });
    defer allocator.free(work_path);

    {
        var repo = try rp.Repo(repo_kind, repo_opts).init(io, allocator, .{ .path = work_path });
        defer repo.deinit(io, allocator);
    }

    var repo = try rp.Repo(repo_kind, repo_opts).open(io, allocator, .{ .path = work_path });
    defer repo.deinit(io, allocator);

    // A --- B --- D [master]
    //  \         /
    //   \       /
    //    `---- C [foo]

    try addFile(repo_kind, repo_opts, &repo, io, allocator, "hi.txt", "hi");
    _ = try repo.commit(io, allocator, .{ .message = "a" });
    try repo.addBranch(io, .{ .name = "foo" });
    try addFile(repo_kind, repo_opts, &repo, io, allocator, "f.txt", "hi");
    _ = try repo.commit(io, allocator, .{ .message = "b" });
    {
        var result = try repo.switchDir(io, allocator, .{ .target = .{ .ref = .{ .kind = .head, .name = "foo" } } });
        defer result.deinit();
    }
    try addFile(repo_kind, repo_opts, &repo, io, allocator, "f.txt/g.txt", "hi");
    _ = try repo.commit(io, allocator, .{ .message = "c" });
    {
        var result = try repo.switchDir(io, allocator, .{ .target = .{ .ref = .{ .kind = .head, .name = "master" } } });
        defer result.deinit();
    }
    {
        var merge = try repo.merge(io, allocator, .{ .kind = .full, .action = .{ .new = .{ .source = &.{.{ .ref = .{ .kind = .head, .name = "foo" } }} } } }, null);
        defer merge.deinit();
        try std.testing.expect(.conflict == merge.result);
    }

    // make sure renamed file exists
    var renamed_file = try repo.core.work_dir.openFile(io, "f.txt~master", .{});
    defer renamed_file.close(io);

    {
        var root = try ui.rootWidget(repo_kind, repo_opts, &repo, io, allocator, .status);
        defer root.deinit(allocator);

        {
            const grid = try root.getGrid().?.toString(allocator);
            defer allocator.free(grid);

            var grid_without_tabs = grid;
            for (0..3) |_| {
                grid_without_tabs = grid_without_tabs[std.mem.indexOfScalar(u8, grid_without_tabs, '\n').? + 1 ..];
            }

            try std.testing.expectEqualStrings(
                \\┌─────────┐                                                                     
                \\│added (1)│ not added (1)  not tracked (1)                                      
                \\└─────────┘                                                                     
                \\   ┌───────────┐    ┌──────────────────────────────────────────────────────────┐
                \\ + │f.txt/g.txt│    │                                                          │
                \\   └───────────┘    │ diff --git a/f.txt/g.txt b/f.txt/g.txt                   │
                \\                    │ new file mode 100644                                     │
                \\                    │ index 0000000..32f95c0                                   │
                \\                    │ --- a/f.txt/g.txt                                        │
                \\                    │ +++ b/f.txt/g.txt                                        │
                \\                    │                                                          │
                \\                    │                                                          │
                \\                    │                                                          │
                \\                    │ @@ -0,0 +0,1 @@                                          │
                \\                    │ + hi                                                     │
                \\                    │                                                          │
                \\                    │                                                          │
                \\                    └──────────────────────────────────────────────────────────┘
            , grid_without_tabs);
        }

        try ui.input(repo_kind, repo_opts, &root, allocator, .arrow_down);
        try ui.input(repo_kind, repo_opts, &root, allocator, .arrow_right);

        {
            const grid = try root.getGrid().?.toString(allocator);
            defer allocator.free(grid);

            var grid_without_tabs = grid;
            for (0..3) |_| {
                grid_without_tabs = grid_without_tabs[std.mem.indexOfScalar(u8, grid_without_tabs, '\n').? + 1 ..];
            }

            try std.testing.expectEqualStrings(
                \\           ╔═════════════╗                                                      
                \\ added (1) ║not added (1)║ not tracked (1)                                      
                \\           ╚═════════════╝                                                      
                \\   ┌─────┐          ┌──────────────────────────────────────────────────────────┐
                \\ ≠ │f.txt│          │                                                          │
                \\   └─────┘          └──────────────────────────────────────────────────────────┘
            , grid_without_tabs);
        }

        try ui.input(repo_kind, repo_opts, &root, allocator, .arrow_right);

        {
            const grid = try root.getGrid().?.toString(allocator);
            defer allocator.free(grid);

            var grid_without_tabs = grid;
            for (0..3) |_| {
                grid_without_tabs = grid_without_tabs[std.mem.indexOfScalar(u8, grid_without_tabs, '\n').? + 1 ..];
            }

            try std.testing.expectEqualStrings(
                \\                          ╔═══════════════╗                                     
                \\ added (1)  not added (1) ║not tracked (1)║                                     
                \\                          ╚═══════════════╝                                     
                \\   ┌────────────┐   ┌──────────────────────────────────────────────────────────┐
                \\ ? │f.txt~master│   │                                                          │
                \\   └────────────┘   │ diff --git a/f.txt~master b/f.txt~master                 │
                \\                    │ new file mode 100644                                     │
                \\                    │ index 0000000..32f95c0                                   │
                \\                    │ --- a/f.txt~master                                       │
                \\                    │ +++ b/f.txt~master                                       │
                \\                    │                                                          │
                \\                    │                                                          │
                \\                    │                                                          │
                \\                    │ @@ -0,0 +0,1 @@                                          │
                \\                    │ + hi                                                     │
                \\                    │                                                          │
                \\                    │                                                          │
                \\                    └──────────────────────────────────────────────────────────┘
            , grid_without_tabs);
        }
    }

    // generate diff
    var status = try repo.status(io, allocator);
    defer status.deinit(allocator);
    var file_iter = try repo.filePairs(io, allocator, .{
        .work_dir = .{
            .conflict_diff_kind = .target,
            .status = &status,
        },
    });
    if (try file_iter.next()) |*line_iter_pair_ptr| {
        var line_iter_pair = line_iter_pair_ptr.*;
        defer line_iter_pair.deinit();
        try std.testing.expectEqualStrings("f.txt", line_iter_pair.path);
    } else {
        return error.DiffResultExpected;
    }

    // ensure merge cannot be run again while there are unresolved conflicts
    {
        // can't merge again with an unresolved merge
        {
            var result_or_err = repo.merge(io, allocator, .{ .kind = .full, .action = .{ .new = .{ .source = &.{.{ .ref = .{ .kind = .head, .name = "foo" } }} } } }, null);
            if (result_or_err) |*result| {
                defer result.deinit();
                return error.ExpectedMergeToNotFinish;
            } else |err| switch (err) {
                error.UnfinishedMergeInProgress => {},
                else => |e| return e,
            }
        }

        // can't continue merge with unresolved conflicts
        {
            var result_or_err = repo.merge(io, allocator, .{ .kind = .full, .action = .cont }, null);
            if (result_or_err) |*result| {
                defer result.deinit();
                return error.ExpectedMergeToNotFinish;
            } else |err| switch (err) {
                error.CannotContinueMergeWithUnresolvedConflicts => {},
                else => |e| return e,
            }
        }
    }

    // resolve conflict
    try repo.add(io, allocator, &.{"f.txt"});
    {
        var merge = try repo.merge(io, allocator, .{ .kind = .full, .action = .cont }, null);
        defer merge.deinit();
        try std.testing.expect(.success == merge.result);
    }

    // if we try merging foo again, it does nothing
    {
        var merge = try repo.merge(io, allocator, .{ .kind = .full, .action = .{ .new = .{ .source = &.{.{ .ref = .{ .kind = .head, .name = "foo" } }} } } }, null);
        defer merge.deinit();
        try std.testing.expect(.nothing == merge.result);
    }
}

fn testMergeConflictDirFile(comptime repo_kind: rp.RepoKind, comptime repo_opts: rp.RepoOpts(repo_kind)) !void {
    const io = std.testing.io;
    const allocator = std.testing.allocator;
    const temp_dir_name = "temp-test-repo-merge-conflict-dir-file";

    // create the temp dir
    const cwd = std.Io.Dir.cwd();
    var temp_dir_or_err = cwd.openDir(io, temp_dir_name, .{});
    if (temp_dir_or_err) |*temp_dir| {
        temp_dir.close(io);
        try cwd.deleteTree(io, temp_dir_name);
    } else |_| {}
    var temp_dir = try cwd.createDirPathOpen(io, temp_dir_name, .{});
    defer cwd.deleteTree(io, temp_dir_name) catch {};
    defer temp_dir.close(io);

    const cwd_path = try std.process.currentPathAlloc(io, allocator);
    defer allocator.free(cwd_path);

    const work_path = try std.fs.path.join(allocator, &.{ cwd_path, temp_dir_name, "repo" });
    defer allocator.free(work_path);

    {
        var repo = try rp.Repo(repo_kind, repo_opts).init(io, allocator, .{ .path = work_path });
        defer repo.deinit(io, allocator);
    }

    var repo = try rp.Repo(repo_kind, repo_opts).open(io, allocator, .{ .path = work_path });
    defer repo.deinit(io, allocator);

    // A --- B --- D [master]
    //  \         /
    //   \       /
    //    `---- C [foo]

    try addFile(repo_kind, repo_opts, &repo, io, allocator, "hi.txt", "hi");
    _ = try repo.commit(io, allocator, .{ .message = "a" });
    try repo.addBranch(io, .{ .name = "foo" });
    try addFile(repo_kind, repo_opts, &repo, io, allocator, "f.txt/g.txt", "hi");
    _ = try repo.commit(io, allocator, .{ .message = "b" });
    {
        var result = try repo.switchDir(io, allocator, .{ .target = .{ .ref = .{ .kind = .head, .name = "foo" } } });
        defer result.deinit();
    }
    try addFile(repo_kind, repo_opts, &repo, io, allocator, "f.txt", "hi");
    _ = try repo.commit(io, allocator, .{ .message = "c" });
    {
        var result = try repo.switchDir(io, allocator, .{ .target = .{ .ref = .{ .kind = .head, .name = "master" } } });
        defer result.deinit();
    }
    {
        var merge = try repo.merge(io, allocator, .{ .kind = .full, .action = .{ .new = .{ .source = &.{.{ .ref = .{ .kind = .head, .name = "foo" } }} } } }, null);
        defer merge.deinit();
        try std.testing.expect(.conflict == merge.result);
    }

    // make sure renamed file exists
    var renamed_file = try repo.core.work_dir.openFile(io, "f.txt~foo", .{});
    defer renamed_file.close(io);

    {
        var root = try ui.rootWidget(repo_kind, repo_opts, &repo, io, allocator, .status);
        defer root.deinit(allocator);

        {
            const grid = try root.getGrid().?.toString(allocator);
            defer allocator.free(grid);

            var grid_without_tabs = grid;
            for (0..3) |_| {
                grid_without_tabs = grid_without_tabs[std.mem.indexOfScalar(u8, grid_without_tabs, '\n').? + 1 ..];
            }

            try std.testing.expectEqualStrings(
                \\           ┌─────────────┐                                                      
                \\ added (0) │not added (1)│ not tracked (1)                                      
                \\           └─────────────┘                                                      
                \\   ┌─────┐          ┌──────────────────────────────────────────────────────────┐
                \\ ≠ │f.txt│          │                                                          │
                \\   └─────┘          └──────────────────────────────────────────────────────────┘
            , grid_without_tabs);
        }

        try ui.input(repo_kind, repo_opts, &root, allocator, .arrow_down);
        try ui.input(repo_kind, repo_opts, &root, allocator, .arrow_right);

        {
            const grid = try root.getGrid().?.toString(allocator);
            defer allocator.free(grid);

            var grid_without_tabs = grid;
            for (0..3) |_| {
                grid_without_tabs = grid_without_tabs[std.mem.indexOfScalar(u8, grid_without_tabs, '\n').? + 1 ..];
            }

            try std.testing.expectEqualStrings(
                \\                          ╔═══════════════╗                                     
                \\ added (0)  not added (1) ║not tracked (1)║                                     
                \\                          ╚═══════════════╝                                     
                \\   ┌─────────┐      ┌──────────────────────────────────────────────────────────┐
                \\ ? │f.txt~foo│      │                                                          │
                \\   └─────────┘      │ diff --git a/f.txt~foo b/f.txt~foo                       │
                \\                    │ new file mode 100644                                     │
                \\                    │ index 0000000..32f95c0                                   │
                \\                    │ --- a/f.txt~foo                                          │
                \\                    │ +++ b/f.txt~foo                                          │
                \\                    │                                                          │
                \\                    │                                                          │
                \\                    │                                                          │
                \\                    │ @@ -0,0 +0,1 @@                                          │
                \\                    │ + hi                                                     │
                \\                    │                                                          │
                \\                    │                                                          │
                \\                    └──────────────────────────────────────────────────────────┘
            , grid_without_tabs);
        }
    }

    // generate diff
    var status = try repo.status(io, allocator);
    defer status.deinit(allocator);
    var file_iter = try repo.filePairs(io, allocator, .{
        .work_dir = .{
            .conflict_diff_kind = .target,
            .status = &status,
        },
    });
    if (try file_iter.next()) |*line_iter_pair_ptr| {
        var line_iter_pair = line_iter_pair_ptr.*;
        defer line_iter_pair.deinit();
        return error.DiffResultNotExpected;
    }

    // ensure merge cannot be run again while there are unresolved conflicts
    {
        // can't merge again with an unresolved merge
        {
            var result_or_err = repo.merge(io, allocator, .{ .kind = .full, .action = .{ .new = .{ .source = &.{.{ .ref = .{ .kind = .head, .name = "foo" } }} } } }, null);
            if (result_or_err) |*result| {
                defer result.deinit();
                return error.ExpectedMergeToNotFinish;
            } else |err| switch (err) {
                error.UnfinishedMergeInProgress => {},
                else => |e| return e,
            }
        }

        // can't continue merge with unresolved conflicts
        {
            var result_or_err = repo.merge(io, allocator, .{ .kind = .full, .action = .cont }, null);
            if (result_or_err) |*result| {
                defer result.deinit();
                return error.ExpectedMergeToNotFinish;
            } else |err| switch (err) {
                error.CannotContinueMergeWithUnresolvedConflicts => {},
                else => |e| return e,
            }
        }
    }

    // resolve conflict
    try repo.add(io, allocator, &.{"f.txt"});
    {
        var merge = try repo.merge(io, allocator, .{ .kind = .full, .action = .cont }, null);
        defer merge.deinit();
        try std.testing.expect(.success == merge.result);
    }

    // if we try merging foo again, it does nothing
    {
        var merge = try repo.merge(io, allocator, .{ .kind = .full, .action = .{ .new = .{ .source = &.{.{ .ref = .{ .kind = .head, .name = "foo" } }} } } }, null);
        defer merge.deinit();
        try std.testing.expect(.nothing == merge.result);
    }
}

test "merge conflict binary" {
    try testMergeConflictBinary(.git, .{ .is_test = true }, .diff3, .binary);
    try testMergeConflictBinary(.xit, .{ .is_test = true }, .patch, .binary);
    try testMergeConflictBinary(.xit, .{ .is_test = true }, .patch, .base);
    try testMergeConflictBinary(.xit, .{ .is_test = true }, .patch, .target);
    try testMergeConflictBinary(.xit, .{ .is_test = true }, .patch, .source);
    try testMergeConflictBinary(.xit, .{ .is_test = true }, .patch, .target_text);
    try testMergeConflictBinary(.xit, .{ .is_test = true }, .patch, .source_text);
    try testMergeConflictBinary(.xit, .{ .is_test = true }, .diff3, .source_text);
    try testMergeConflictBinary(.xit, .{ .is_test = true }, .patch, .target_neighbors);
    try testMergeConflictBinary(.xit, .{ .is_test = true }, .patch, .source_neighbors);
    try testMergeConflictBinary(.xit, .{ .is_test = true }, .patch, .shared_text);
    try testMergeConflictBinary(.xit, .{ .is_test = true }, .diff3, .shared_text);
    try testMergeConflictBinary(.xit, .{ .is_test = true }, .patch, .empty_text);
    try testMergeConflictBinary(.xit, .{ .is_test = true }, .patch, .initial_binary);
    try testMergeConflictBinary(.xit, .{ .is_test = true }, .patch, .deleted_text);
    try testMergeConflictBinary(.xit, .{ .is_test = true }, .patch, .text_conflict);
    try testMergeConflictBinary(.xit, .{ .is_test = true }, .diff3, .source_neighbors);
    try testMergeConflictBinary(.xit, .{ .is_test = true }, .patch, .first_parent);
}

/// tests binary conflicts and transitions between binary and text
fn testMergeConflictBinary(
    comptime repo_kind: rp.RepoKind,
    comptime repo_opts: rp.RepoOpts(repo_kind),
    algo: mrg.MergeAlgorithm,
    case: enum { binary, base, target, source, target_text, source_text, target_neighbors, source_neighbors, shared_text, empty_text, initial_binary, deleted_text, text_conflict, first_parent },
) !void {
    const io = std.testing.io;
    const allocator = std.testing.allocator;
    errdefer std.debug.print("binary merge: {s}, {s}, {s}\n", .{ @tagName(repo_kind), @tagName(algo), @tagName(case) });
    const temp_dir_name = "temp-test-repo-merge-conflict-binary";

    // create the temp dir
    const cwd = std.Io.Dir.cwd();
    var temp_dir_or_err = cwd.openDir(io, temp_dir_name, .{});
    if (temp_dir_or_err) |*temp_dir| {
        temp_dir.close(io);
        try cwd.deleteTree(io, temp_dir_name);
    } else |_| {}
    var temp_dir = try cwd.createDirPathOpen(io, temp_dir_name, .{});
    defer cwd.deleteTree(io, temp_dir_name) catch {};
    defer temp_dir.close(io);

    const cwd_path = try std.process.currentPathAlloc(io, allocator);
    defer allocator.free(cwd_path);

    const work_path = try std.fs.path.join(allocator, &.{ cwd_path, temp_dir_name, "repo" });
    defer allocator.free(work_path);

    {
        var repo = try rp.Repo(repo_kind, repo_opts).init(io, allocator, .{ .path = work_path });
        defer repo.deinit(io, allocator);
    }

    var repo = try rp.Repo(repo_kind, repo_opts).open(io, allocator, .{ .path = work_path });
    defer repo.deinit(io, allocator);

    if (case != .binary) {
        const initial = "a\nb\nc\nd\ne";
        const binary = "\xffbinary";
        const target = "a\nB\nc\nd\ne";
        const neighboring = case == .shared_text or case == .target_neighbors or case == .source_neighbors;
        const source = if (case == .text_conflict) "a\nother\nc\nd\ne" else if (neighboring) "a\nb\nC\nd\ne" else "a\nb\nc\nd\nE";
        const histories = [_][]const ?[]const u8{
            switch (case) {
                .base => &.{ initial, binary },
                .initial_binary => &.{ binary, null, "\xfebinary", "", initial },
                .deleted_text => &.{ "older text", null, binary, initial },
                .shared_text, .first_parent => &.{ initial, binary, initial },
                .empty_text => &.{ initial, binary, initial, binary, "", initial },
                else => &.{initial},
            },
            switch (case) {
                .target => &.{ target, binary },
                .target_text, .target_neighbors => &.{ binary, initial, target },
                else => &.{target},
            },
            switch (case) {
                .source => &.{ source, binary },
                .source_text => &.{ binary, "\xfebinary", "a\nb\nc\nd\nchanged", source },
                .source_neighbors, .text_conflict => &.{ binary, source },
                else => &.{source},
            },
        };
        var oids: [3][hash.hexLen(repo_opts.hash)]u8 = undefined;
        var root_oid: [hash.hexLen(repo_opts.hash)]u8 = undefined;
        for (histories, 0..) |history, side| {
            var parent_oid_maybe: ?[hash.hexLen(repo_opts.hash)]u8 = if (side == 0) null else if (side == 2 and case == .first_parent) root_oid else oids[0];
            for (history, 0..) |content_maybe, i| {
                if (content_maybe) |content| {
                    try addFile(repo_kind, repo_opts, &repo, io, allocator, "bin", content);
                } else {
                    try repo.remove(io, allocator, &.{"bin"}, .{});
                }
                const oid = try repo.commit(io, allocator, .{
                    .message = "edit",
                    .parent_oids = if (parent_oid_maybe) |parent_oid| &.{parent_oid} else null,
                    .timestamp = 1 + side * 10 + i,
                });
                if (side == 0 and i == 0) root_oid = oid;
                oids[side] = oid;
                var iter = try df.LineIterator(repo_kind, repo_opts).initFromTestBuffer(io, allocator, content_maybe orelse "");
                defer iter.deinit();
                const is_binary = !std.unicode.utf8ValidateSlice(content_maybe orelse "");
                try std.testing.expectEqual(is_binary, iter.source == .binary);

                if (repo_kind == .xit) {
                    try repo.patchAll(io, allocator, null);
                    const moment = try repo.core.latestMoment();
                    const snapshot = (try moment.cursor.readPath(void, &.{
                        .{ .hash_map_get = .{ .value = hash.hashInt(repo_opts.hash, "commit-id->snapshot") } },
                        .{ .hash_map_get = .{ .value = try hash.hexToInt(repo_opts.hash, &oid) } },
                    })).?;
                    const parent_snapshot_maybe = if (is_binary and parent_oid_maybe != null)
                        (try moment.cursor.readPath(void, &.{
                            .{ .hash_map_get = .{ .value = hash.hashInt(repo_opts.hash, "commit-id->snapshot") } },
                            .{ .hash_map_get = .{ .value = try hash.hexToInt(repo_opts.hash, &parent_oid_maybe.?) } },
                        })).?
                    else
                        null;
                    for ([_][]const u8{ "path->patch-id", "path->patch-id-set", "path->live-parent->children", "path->child->parent", "path->line-id-list" }) |name| {
                        const entry = try snapshot.readPath(void, &.{
                            .{ .hash_map_get = .{ .value = hash.hashInt(repo_opts.hash, name) } },
                            .{ .hash_map_get = .{ .value = hash.hashInt(repo_opts.hash, "bin") } },
                        });
                        try std.testing.expectEqual(!(case == .initial_binary and side == 0 and i == 0), entry != null);
                        if (parent_snapshot_maybe) |parent_snapshot| {
                            const parent_entry = try parent_snapshot.readPath(void, &.{
                                .{ .hash_map_get = .{ .value = hash.hashInt(repo_opts.hash, name) } },
                                .{ .hash_map_get = .{ .value = hash.hashInt(repo_opts.hash, "bin") } },
                            });
                            try std.testing.expectEqualDeep(parent_entry.?.slot(), entry.?.slot());
                        }
                    }
                }
                parent_oid_maybe = oid;
            }
            if (side == 1) try repo.addBranch(io, .{ .name = "target" });
        }
        if (case == .first_parent) {
            // the merge base is the second parent, so patch selection reaches
            // back past its binary transition to the original text commit
            oids[2] = try repo.commit(io, allocator, .{ .message = "merge", .parent_oids = &.{ oids[2], oids[0] }, .allow_empty = true, .timestamp = 30 });
        }
        {
            var result = try repo.switchDir(io, allocator, .{ .target = .{ .ref = .{ .kind = .head, .name = "target" } } });
            defer result.deinit();
        }
        var merge = try repo.merge(io, allocator, .{ .kind = .full, .action = .{ .new = .{ .algo = algo, .source = &.{.{ .oid = &oids[2] }} } } }, null);
        defer merge.deinit();
        try std.testing.expectEqualStrings(&oids[0], &merge.base_oid);
        const binary_conflict = case == .base or case == .target or case == .source;
        const text_conflict = case == .text_conflict or (neighboring and algo == .diff3);
        try std.testing.expectEqual(binary_conflict or text_conflict, merge.result == .conflict);
        const content = try repo.core.work_dir.readFileAlloc(io, "bin", allocator, .limited(4096));
        defer allocator.free(content);
        if (binary_conflict) {
            try std.testing.expectEqualStrings(if (case == .source) binary else source, content);
        } else if (text_conflict) {
            try std.testing.expect(std.mem.indexOf(u8, content, "<<<<<<<") != null);
            try std.testing.expect(std.mem.indexOf(u8, content, "B") != null);
            try std.testing.expect(std.mem.indexOf(u8, content, if (case == .text_conflict) "other" else "C") != null);
        } else {
            try std.testing.expect(merge.result == .success);
            try std.testing.expectEqualStrings(if (neighboring) "a\nB\nC\nd\ne" else "a\nB\nc\nd\nE", content);
        }
        return;
    }

    // A --- B --------- D [master]
    //  \               /
    //   \             /
    //    C ---------- [foo]

    var bin = [_]u8{0} ** 256;
    for (&bin, 0..) |*byte, i| {
        if (i % 2 == 1) {
            byte.* = '\n';
        } else {
            byte.* = @intCast(i % 255);
        }
    }

    try addFile(repo_kind, repo_opts, &repo, io, allocator, "bin", &bin);
    _ = try repo.commit(io, allocator, .{ .message = "a" });

    try repo.addBranch(io, .{ .name = "foo" });

    {
        var result = try repo.switchDir(io, allocator, .{ .target = .{ .ref = .{ .kind = .head, .name = "foo" } } });
        defer result.deinit();
    }

    bin[0] = 1;

    try addFile(repo_kind, repo_opts, &repo, io, allocator, "bin", &bin);
    _ = try repo.commit(io, allocator, .{ .message = "c" });

    {
        var result = try repo.switchDir(io, allocator, .{ .target = .{ .ref = .{ .kind = .head, .name = "master" } } });
        defer result.deinit();
    }

    bin[0] = 2;

    try addFile(repo_kind, repo_opts, &repo, io, allocator, "bin", &bin);
    _ = try repo.commit(io, allocator, .{ .message = "b" });

    {
        var merge = try repo.merge(io, allocator, .{ .kind = .full, .action = .{ .new = .{ .algo = algo, .source = &.{.{ .ref = .{ .kind = .head, .name = "foo" } }} } } }, null);
        defer merge.deinit();
        try std.testing.expect(.conflict == merge.result);
    }

    {
        var root = try ui.rootWidget(repo_kind, repo_opts, &repo, io, allocator, .status);
        defer root.deinit(allocator);

        const grid = try root.getGrid().?.toString(allocator);
        defer allocator.free(grid);

        var grid_without_tabs = grid;
        for (0..3) |_| {
            grid_without_tabs = grid_without_tabs[std.mem.indexOfScalar(u8, grid_without_tabs, '\n').? + 1 ..];
        }

        try std.testing.expectEqualStrings(
            \\           ┌─────────────┐                                                      
            \\ added (0) │not added (1)│ not tracked (0)                                      
            \\           └─────────────┘                                                      
            \\   ┌───┐            ┌──────────────────────────────────────────────────────────┐
            \\ ≠ │bin│            │                                                          │
            \\   └───┘            │ diff --git a/bin b/bin                                   │
            \\                    │ index 6071ef1..47e3b37 100644                            │
            \\                    │ --- a/bin                                                │
            \\                    │ +++ b/bin                                                │
            \\                    │                                                          │
            \\                    │                                                          │
            \\                    └──────────────────────────────────────────────────────────┘
        , grid_without_tabs);
    }

    // verify no lines are longer than one byte
    // so we know that conflict markers haven't been added
    {
        const bin_file_content = try repo.core.work_dir.readFileAlloc(io, "bin", allocator, .limited(1024));
        defer allocator.free(bin_file_content);
        var iter = std.mem.splitScalar(u8, bin_file_content, '\n');
        while (iter.next()) |line| {
            try std.testing.expect(line.len <= 1);
        }
    }

    // resolve conflict
    try repo.add(io, allocator, &.{"bin"});
    {
        var merge = try repo.merge(io, allocator, .{ .kind = .full, .action = .cont }, null);
        defer merge.deinit();
        try std.testing.expect(.success == merge.result);
    }

    // if we try merging foo again, it does nothing
    {
        var merge = try repo.merge(io, allocator, .{ .kind = .full, .action = .{ .new = .{ .source = &.{.{ .ref = .{ .kind = .head, .name = "foo" } }} } } }, null);
        defer merge.deinit();
        try std.testing.expect(.nothing == merge.result);
    }

    // replace bin with a text file containing a single line that
    // is too long, and assert that it is considered a binary file
    {
        const file = try repo.core.work_dir.createFile(io, "bin", .{ .truncate = true, .read = true });
        defer file.close(io);
        while (try file.length(io) < repo_opts.max_line_size) {
            try file.writeStreamingAll(io, &[_]u8{' '} ** 256);
        }

        var status = try repo.status(io, allocator);
        defer status.deinit(allocator);
        var file_iter = try repo.filePairs(io, allocator, .{
            .work_dir = .{
                .conflict_diff_kind = .target,
                .status = &status,
            },
        });
        if (try file_iter.next()) |*line_iter_pair_ptr| {
            var line_iter_pair = line_iter_pair_ptr.*;
            defer line_iter_pair.deinit();
            try std.testing.expect(.binary == line_iter_pair.b.source);
        } else {
            return error.DiffResultExpected;
        }
    }
}

test "merge conflict shuffle" {
    try testMergeConflictShuffle(.git, .{ .is_test = true });
    try testMergeConflictShuffle(.xit, .{ .is_test = true });
}

/// demonstrates an example of git shuffling lines unexpectedly
/// when auto-resolving a merge conflict
fn testMergeConflictShuffle(comptime repo_kind: rp.RepoKind, comptime repo_opts: rp.RepoOpts(repo_kind)) !void {
    const io = std.testing.io;
    const allocator = std.testing.allocator;
    const temp_dir_name = "temp-test-repo-merge-conflict-shuffle";

    // create the temp dir
    const cwd = std.Io.Dir.cwd();
    var temp_dir_or_err = cwd.openDir(io, temp_dir_name, .{});
    if (temp_dir_or_err) |*temp_dir| {
        temp_dir.close(io);
        try cwd.deleteTree(io, temp_dir_name);
    } else |_| {}
    var temp_dir = try cwd.createDirPathOpen(io, temp_dir_name, .{});
    defer cwd.deleteTree(io, temp_dir_name) catch {};
    defer temp_dir.close(io);

    const cwd_path = try std.process.currentPathAlloc(io, allocator);
    defer allocator.free(cwd_path);

    // from https://pijul.org/manual/why_pijul.html
    {
        const work_path = try std.fs.path.join(allocator, &.{ cwd_path, temp_dir_name, "simple" });
        defer allocator.free(work_path);

        {
            var repo = try rp.Repo(repo_kind, repo_opts).init(io, allocator, .{ .path = work_path });
            defer repo.deinit(io, allocator);
        }

        var repo = try rp.Repo(repo_kind, repo_opts).open(io, allocator, .{ .path = work_path });
        defer repo.deinit(io, allocator);

        // A --- B --- C --- E [master]
        //  \               /
        //   \             /
        //    `---------- D [foo]

        try addFile(repo_kind, repo_opts, &repo, io, allocator, "f.txt",
            \\a
            \\b
        );
        _ = try repo.commit(io, allocator, .{ .message = "a" });
        try repo.addBranch(io, .{ .name = "foo" });
        try addFile(repo_kind, repo_opts, &repo, io, allocator, "f.txt",
            \\g
            \\a
            \\b
        );
        _ = try repo.commit(io, allocator, .{ .message = "b" });
        try addFile(repo_kind, repo_opts, &repo, io, allocator, "f.txt",
            \\a
            \\b
            \\g
            \\a
            \\b
        );
        _ = try repo.commit(io, allocator, .{ .message = "c" });
        {
            var result = try repo.switchDir(io, allocator, .{ .target = .{ .ref = .{ .kind = .head, .name = "foo" } } });
            defer result.deinit();
        }
        try addFile(repo_kind, repo_opts, &repo, io, allocator, "f.txt",
            \\a
            \\x
            \\b
        );
        _ = try repo.commit(io, allocator, .{ .message = "d" });
        {
            var result = try repo.switchDir(io, allocator, .{ .target = .{ .ref = .{ .kind = .head, .name = "master" } } });
            defer result.deinit();
        }
        {
            var merge = try repo.merge(io, allocator, .{ .kind = .full, .action = .{ .new = .{ .source = &.{.{ .ref = .{ .kind = .head, .name = "foo" } }} } } }, null);
            defer merge.deinit();
            try std.testing.expect(.success == merge.result);

            // verify f.txt has been autoresolved
            const f_txt_content = try repo.core.work_dir.readFileAlloc(io, "f.txt", allocator, .limited(1024));
            defer allocator.free(f_txt_content);
            switch (repo_kind) {
                // git shuffles lines
                .git => try std.testing.expectEqualStrings(
                    \\a
                    \\x
                    \\b
                    \\g
                    \\a
                    \\b
                ,
                    f_txt_content,
                ),
                // xit does not!
                .xit => try std.testing.expectEqualStrings(
                    \\a
                    \\b
                    \\g
                    \\a
                    \\x
                    \\b
                ,
                    f_txt_content,
                ),
            }
        }

        // generate diff
        var status = try repo.status(io, allocator);
        defer status.deinit(allocator);
        var file_iter = try repo.filePairs(io, allocator, .{
            .work_dir = .{
                .conflict_diff_kind = .target,
                .status = &status,
            },
        });
        if (try file_iter.next()) |*line_iter_pair_ptr| {
            var line_iter_pair = line_iter_pair_ptr.*;
            defer line_iter_pair.deinit();
            return error.DiffResultNotExpected;
        }

        // if we try merging foo again, it does nothing
        {
            var merge = try repo.merge(io, allocator, .{ .kind = .full, .action = .{ .new = .{ .source = &.{.{ .ref = .{ .kind = .head, .name = "foo" } }} } } }, null);
            defer merge.deinit();
            try std.testing.expect(.nothing == merge.result);
        }
    }

    // from https://tahoe-lafs.org/~zooko/badmerge/concrete-good-semantics.html
    {
        const work_path = try std.fs.path.join(allocator, &.{ cwd_path, temp_dir_name, "concrete" });
        defer allocator.free(work_path);

        {
            var repo = try rp.Repo(repo_kind, repo_opts).init(io, allocator, .{ .path = work_path });
            defer repo.deinit(io, allocator);
        }

        var repo = try rp.Repo(repo_kind, repo_opts).open(io, allocator, .{ .path = work_path });
        defer repo.deinit(io, allocator);

        // A --- B --- C --- E [master]
        //  \               /
        //   \             /
        //    `---------- D [foo]

        try addFile(repo_kind, repo_opts, &repo, io, allocator, "f.txt",
            \\int square(int x) {
            \\  int y = x;
            \\  /* Update y to equal the result. */
            \\  /* Question: what is the order of magnitude of this algorithm with respect to x? */
            \\  for (int i = 0; i < x; i++) y += x;
            \\  return y;
            \\}
        );
        _ = try repo.commit(io, allocator, .{ .message = "a" });
        try repo.addBranch(io, .{ .name = "foo" });
        try addFile(repo_kind, repo_opts, &repo, io, allocator, "f.txt",
            \\int very_slow_square(int x) {
            \\  int y = 0;
            \\  /* Update y to equal the result. */
            \\  /* Question: what is the order of magnitude of this algorithm with respect to x? */
            \\  for (int i = 0; i < x; i++)
            \\    for (int j = 0; j < x; j++)
            \\      y += 1;
            \\  return y;
            \\}
            \\
            \\int square(int x) {
            \\  int y = x;
            \\  /* Update y to equal the result. */
            \\  /* Question: what is the order of magnitude of this algorithm with respect to x? */
            \\  for (int i = 0; i < x; i++) y += x;
            \\  return y;
            \\}
        );
        _ = try repo.commit(io, allocator, .{ .message = "b" });
        try addFile(repo_kind, repo_opts, &repo, io, allocator, "f.txt",
            \\int square(int x) {
            \\  int y = x;
            \\  /* Update y to equal the result. */
            \\  /* Question: what is the order of magnitude of this algorithm with respect to x? */
            \\  return y * x;
            \\}
            \\
            \\int very_slow_square(int x) {
            \\  int y = 0;
            \\  /* Update y to equal the result. */
            \\  /* Question: what is the order of magnitude of this algorithm with respect to x? */
            \\  for (int i = 0; i < x; i++)
            \\    for (int j = 0; j < x; j++)
            \\      y += 1;
            \\  return y;
            \\}
            \\
            \\int slow_square(int x) {
            \\  int y = x;
            \\  /* Update y to equal the result. */
            \\  /* Question: what is the order of magnitude of this algorithm with respect to x? */
            \\  for (int i = 0; i < x; i++) y += x;
            \\  return y;
            \\}
        );
        _ = try repo.commit(io, allocator, .{ .message = "c" });
        {
            var result = try repo.switchDir(io, allocator, .{ .target = .{ .ref = .{ .kind = .head, .name = "foo" } } });
            defer result.deinit();
        }
        try addFile(repo_kind, repo_opts, &repo, io, allocator, "f.txt",
            \\int square(int x) {
            \\  int y = 0;
            \\  /* Update y to equal the result. */
            \\  /* Question: what is the order of magnitude of this algorithm with respect to x? */
            \\  for (int i = 0; i < x; i++) y += x;
            \\  return y;
            \\}
        );
        _ = try repo.commit(io, allocator, .{ .message = "d" });
        {
            var result = try repo.switchDir(io, allocator, .{ .target = .{ .ref = .{ .kind = .head, .name = "master" } } });
            defer result.deinit();
        }
        {
            var merge = try repo.merge(io, allocator, .{ .kind = .full, .action = .{ .new = .{ .source = &.{.{ .ref = .{ .kind = .head, .name = "foo" } }} } } }, null);
            defer merge.deinit();

            const f_txt_content = try repo.core.work_dir.readFileAlloc(io, "f.txt", allocator, .limited(1024));
            defer allocator.free(f_txt_content);
            switch (repo_kind) {
                .git => {
                    try std.testing.expectEqualStrings(
                        \\int square(int x) {
                        \\  int y = 0;
                        \\  /* Update y to equal the result. */
                        \\  /* Question: what is the order of magnitude of this algorithm with respect to x? */
                        \\  return y * x;
                        \\}
                        \\
                        \\int very_slow_square(int x) {
                        \\  int y = 0;
                        \\  /* Update y to equal the result. */
                        \\  /* Question: what is the order of magnitude of this algorithm with respect to x? */
                        \\  for (int i = 0; i < x; i++)
                        \\    for (int j = 0; j < x; j++)
                        \\      y += 1;
                        \\  return y;
                        \\}
                        \\
                        \\int slow_square(int x) {
                        \\  int y = x;
                        \\  /* Update y to equal the result. */
                        \\  /* Question: what is the order of magnitude of this algorithm with respect to x? */
                        \\  for (int i = 0; i < x; i++) y += x;
                        \\  return y;
                        \\}
                    , f_txt_content);
                },
                .xit => {
                    try std.testing.expect(.success == merge.result);
                    try std.testing.expectEqualStrings(
                        \\int square(int x) {
                        \\  int y = x;
                        \\  /* Update y to equal the result. */
                        \\  /* Question: what is the order of magnitude of this algorithm with respect to x? */
                        \\  return y * x;
                        \\}
                        \\
                        \\int very_slow_square(int x) {
                        \\  int y = 0;
                        \\  /* Update y to equal the result. */
                        \\  /* Question: what is the order of magnitude of this algorithm with respect to x? */
                        \\  for (int i = 0; i < x; i++)
                        \\    for (int j = 0; j < x; j++)
                        \\      y += 1;
                        \\  return y;
                        \\}
                        \\
                        \\int slow_square(int x) {
                        \\  int y = 0;
                        \\  /* Update y to equal the result. */
                        \\  /* Question: what is the order of magnitude of this algorithm with respect to x? */
                        \\  for (int i = 0; i < x; i++) y += x;
                        \\  return y;
                        \\}
                    , f_txt_content);
                },
            }
        }
    }
}

test "cherry-pick" {
    try testCherryPick(.git, .{ .is_test = true });
    try testCherryPick(.xit, .{ .is_test = true });
}

fn testCherryPick(comptime repo_kind: rp.RepoKind, comptime repo_opts: rp.RepoOpts(repo_kind)) !void {
    const io = std.testing.io;
    const allocator = std.testing.allocator;
    const temp_dir_name = "temp-test-repo-cherry-pick";

    // create the temp dir
    const cwd = std.Io.Dir.cwd();
    var temp_dir_or_err = cwd.openDir(io, temp_dir_name, .{});
    if (temp_dir_or_err) |*temp_dir| {
        temp_dir.close(io);
        try cwd.deleteTree(io, temp_dir_name);
    } else |_| {}
    var temp_dir = try cwd.createDirPathOpen(io, temp_dir_name, .{});
    defer cwd.deleteTree(io, temp_dir_name) catch {};
    defer temp_dir.close(io);

    const cwd_path = try std.process.currentPathAlloc(io, allocator);
    defer allocator.free(cwd_path);

    const work_path = try std.fs.path.join(allocator, &.{ cwd_path, temp_dir_name, "repo" });
    defer allocator.free(work_path);

    {
        var repo = try rp.Repo(repo_kind, repo_opts).init(io, allocator, .{ .path = work_path });
        defer repo.deinit(io, allocator);
    }

    var repo = try rp.Repo(repo_kind, repo_opts).open(io, allocator, .{ .path = work_path });
    defer repo.deinit(io, allocator);

    // A --- B ------------ D' [master]
    //        \
    //         \
    //          C --- D --- E [foo]

    try addFile(repo_kind, repo_opts, &repo, io, allocator, "readme.md", "a");
    _ = try repo.commit(io, allocator, .{ .message = "a" });
    try addFile(repo_kind, repo_opts, &repo, io, allocator, "readme.md", "b");
    _ = try repo.commit(io, allocator, .{ .message = "b" });
    try repo.addBranch(io, .{ .name = "foo" });
    {
        var result = try repo.switchDir(io, allocator, .{ .target = .{ .ref = .{ .kind = .head, .name = "foo" } } });
        defer result.deinit();
    }
    // commit c will be the parent of the cherry-picked commit,
    // and it is modifying a different file, so it shouldn't
    // cause a conflict.
    try addFile(repo_kind, repo_opts, &repo, io, allocator, "stuff.md", "c");
    _ = try repo.commit(io, allocator, .{ .message = "c" });
    try addFile(repo_kind, repo_opts, &repo, io, allocator, "readme.md", "d");
    const commit_d = try repo.commit(io, allocator, .{ .message = "d" });
    try addFile(repo_kind, repo_opts, &repo, io, allocator, "readme.md", "e");
    _ = try repo.commit(io, allocator, .{ .message = "e" });
    {
        var result = try repo.switchDir(io, allocator, .{ .target = .{ .ref = .{ .kind = .head, .name = "master" } } });
        defer result.deinit();
    }

    {
        var merge = try repo.merge(io, allocator, .{ .kind = .pick, .action = .{ .new = .{ .source = &.{.{ .oid = &commit_d }} } } }, null);
        defer merge.deinit();
        try std.testing.expect(.success == merge.result);
    }

    // make sure stuff.md does not exist
    if (repo.core.work_dir.openFile(io, "stuff.md", .{})) |*file| {
        file.close(io);
        return error.UnexpectedFile;
    } else |_| {}

    // if we try cherry-picking the same commit again, it succeeds again
    {
        var merge = try repo.merge(io, allocator, .{
            .kind = .pick,
            .action = .{ .new = .{ .source = &.{.{ .oid = &commit_d }} } },
            .commit_metadata = .{ .allow_empty = true },
        }, null);
        defer merge.deinit();
        try std.testing.expect(.success == merge.result);
    }
}

test "cherry-pick conflict" {
    try testCherryPickConflict(.git, .{ .is_test = true });
    try testCherryPickConflict(.xit, .{ .is_test = true });
}

fn testCherryPickConflict(comptime repo_kind: rp.RepoKind, comptime repo_opts: rp.RepoOpts(repo_kind)) !void {
    const io = std.testing.io;
    const allocator = std.testing.allocator;
    const temp_dir_name = "temp-test-repo-cherry-pick-conflict";

    // create the temp dir
    const cwd = std.Io.Dir.cwd();
    var temp_dir_or_err = cwd.openDir(io, temp_dir_name, .{});
    if (temp_dir_or_err) |*temp_dir| {
        temp_dir.close(io);
        try cwd.deleteTree(io, temp_dir_name);
    } else |_| {}
    var temp_dir = try cwd.createDirPathOpen(io, temp_dir_name, .{});
    defer cwd.deleteTree(io, temp_dir_name) catch {};
    defer temp_dir.close(io);

    const cwd_path = try std.process.currentPathAlloc(io, allocator);
    defer allocator.free(cwd_path);

    const work_path = try std.fs.path.join(allocator, &.{ cwd_path, temp_dir_name, "repo" });
    defer allocator.free(work_path);

    {
        var repo = try rp.Repo(repo_kind, repo_opts).init(io, allocator, .{ .path = work_path });
        defer repo.deinit(io, allocator);
    }

    var repo = try rp.Repo(repo_kind, repo_opts).open(io, allocator, .{ .path = work_path });
    defer repo.deinit(io, allocator);

    // A --- B ------------ D' [master]
    //        \
    //         \
    //          D --------- E [foo]

    try addFile(repo_kind, repo_opts, &repo, io, allocator, "readme.md", "a");
    _ = try repo.commit(io, allocator, .{ .message = "a" });
    try addFile(repo_kind, repo_opts, &repo, io, allocator, "readme.md", "b");
    _ = try repo.commit(io, allocator, .{ .message = "b" });
    try repo.addBranch(io, .{ .name = "foo" });
    {
        var result = try repo.switchDir(io, allocator, .{ .target = .{ .ref = .{ .kind = .head, .name = "foo" } } });
        defer result.deinit();
    }
    try addFile(repo_kind, repo_opts, &repo, io, allocator, "readme.md", "c");
    _ = try repo.commit(io, allocator, .{ .message = "c" });
    try addFile(repo_kind, repo_opts, &repo, io, allocator, "readme.md", "d");
    const commit_d = try repo.commit(io, allocator, .{ .message = "d" });
    try addFile(repo_kind, repo_opts, &repo, io, allocator, "readme.md", "e");
    _ = try repo.commit(io, allocator, .{ .message = "e" });
    {
        var result = try repo.switchDir(io, allocator, .{ .target = .{ .ref = .{ .kind = .head, .name = "master" } } });
        defer result.deinit();
    }
    {
        var merge = try repo.merge(io, allocator, .{ .kind = .pick, .action = .{ .new = .{ .source = &.{.{ .oid = &commit_d }} } } }, null);
        defer merge.deinit();
        try std.testing.expect(.conflict == merge.result);

        // verify readme.md has conflict markers
        const readme_md_content = try repo.core.work_dir.readFileAlloc(io, "readme.md", allocator, .limited(1024));
        defer allocator.free(readme_md_content);
        const expected_readme_md_content = try std.fmt.allocPrint(allocator,
            \\<<<<<<< target (master)
            \\b
            \\||||||| base ({s})
            \\c
            \\=======
            \\d
            \\>>>>>>> source ({s})
        , .{ merge.base_oid, commit_d });
        defer allocator.free(expected_readme_md_content);
        try std.testing.expectEqualStrings(expected_readme_md_content, readme_md_content);
    }

    // generate diff
    var status = try repo.status(io, allocator);
    defer status.deinit(allocator);
    var file_iter = try repo.filePairs(io, allocator, .{
        .work_dir = .{
            .conflict_diff_kind = .target,
            .status = &status,
        },
    });
    if (try file_iter.next()) |*line_iter_pair_ptr| {
        var line_iter_pair = line_iter_pair_ptr.*;
        defer line_iter_pair.deinit();
    } else {
        return error.DiffResultExpected;
    }

    // ensure cherry-pick cannot be run again while there are unresolved conflicts
    {
        // can't cherry-pick again with an unresolved cherry-pick
        {
            var result_or_err = repo.merge(io, allocator, .{ .kind = .pick, .action = .{ .new = .{ .source = &.{.{ .oid = &([_]u8{0} ** hash.hexLen(repo_opts.hash)) }} } } }, null);
            if (result_or_err) |*result| {
                defer result.deinit();
                return error.ExpectedMergeToNotFinish;
            } else |err| switch (err) {
                error.UnfinishedMergeInProgress => {},
                else => |e| return e,
            }
        }

        // can't continue cherry-pick with unresolved conflicts
        {
            var result_or_err = repo.merge(io, allocator, .{ .kind = .pick, .action = .cont }, null);
            if (result_or_err) |*result| {
                defer result.deinit();
                return error.ExpectedMergeToNotFinish;
            } else |err| switch (err) {
                error.CannotContinueMergeWithUnresolvedConflicts => {},
                else => |e| return e,
            }
        }
    }

    // resolve conflict
    try addFile(repo_kind, repo_opts, &repo, io, allocator, "readme.md",
        \\e
    );

    // can't continue with .kind = merge
    {
        var result_or_err = repo.merge(io, allocator, .{ .kind = .full, .action = .cont }, null);
        if (result_or_err) |*result| {
            defer result.deinit();
            return error.ExpectedMergeToNotFinish;
        } else |err| switch (err) {
            error.OtherMergeInProgress => {},
            else => |e| return e,
        }
    }

    // continue cherry-pick
    {
        var merge = try repo.merge(io, allocator, .{ .kind = .pick, .action = .cont }, null);
        defer merge.deinit();
        try std.testing.expect(.success == merge.result);
    }
}

test "log" {
    try testLog(.git, .{ .is_test = true });
    try testLog(.xit, .{ .is_test = true });
}

fn testLog(comptime repo_kind: rp.RepoKind, comptime repo_opts: rp.RepoOpts(repo_kind)) !void {
    const io = std.testing.io;
    const allocator = std.testing.allocator;
    const temp_dir_name = "temp-test-repo-log";

    // create the temp dir
    const cwd = std.Io.Dir.cwd();
    var temp_dir_or_err = cwd.openDir(io, temp_dir_name, .{});
    if (temp_dir_or_err) |*temp_dir| {
        temp_dir.close(io);
        try cwd.deleteTree(io, temp_dir_name);
    } else |_| {}
    var temp_dir = try cwd.createDirPathOpen(io, temp_dir_name, .{});
    defer cwd.deleteTree(io, temp_dir_name) catch {};
    defer temp_dir.close(io);

    const cwd_path = try std.process.currentPathAlloc(io, allocator);
    defer allocator.free(cwd_path);

    const work_path = try std.fs.path.join(allocator, &.{ cwd_path, temp_dir_name, "repo" });
    defer allocator.free(work_path);

    {
        var repo = try rp.Repo(repo_kind, repo_opts).init(io, allocator, .{ .path = work_path });
        defer repo.deinit(io, allocator);
    }

    var repo = try rp.Repo(repo_kind, repo_opts).open(io, allocator, .{ .path = work_path });
    defer repo.deinit(io, allocator);

    // A --- B --- C --------- G --- H [master]
    //        \               /
    //         \             /
    //          D --- E --- F [foo]

    try addFile(repo_kind, repo_opts, &repo, io, allocator, "master.md", "a");
    const commit_a = try repo.commit(io, allocator, .{ .message = "a" });
    try addFile(repo_kind, repo_opts, &repo, io, allocator, "master.md", "b");
    const commit_b = try repo.commit(io, allocator, .{ .message = "b" });
    try repo.addBranch(io, .{ .name = "foo" });
    {
        var result = try repo.switchDir(io, allocator, .{ .target = .{ .ref = .{ .kind = .head, .name = "foo" } } });
        defer result.deinit();
    }
    try addFile(repo_kind, repo_opts, &repo, io, allocator, "foo.md", "d");
    const commit_d = try repo.commit(io, allocator, .{ .message = "d" });
    {
        var result = try repo.switchDir(io, allocator, .{ .target = .{ .ref = .{ .kind = .head, .name = "master" } } });
        defer result.deinit();
    }
    try addFile(repo_kind, repo_opts, &repo, io, allocator, "master.md", "c");
    const commit_c = try repo.commit(io, allocator, .{ .message = "c" });
    {
        var result = try repo.switchDir(io, allocator, .{ .target = .{ .ref = .{ .kind = .head, .name = "foo" } } });
        defer result.deinit();
    }
    try addFile(repo_kind, repo_opts, &repo, io, allocator, "foo.md", "e");
    const commit_e = try repo.commit(io, allocator, .{ .message = "e" });
    try addFile(repo_kind, repo_opts, &repo, io, allocator, "foo.md", "f");
    const commit_f = try repo.commit(io, allocator, .{ .message = "f" });
    {
        var result = try repo.switchDir(io, allocator, .{ .target = .{ .ref = .{ .kind = .head, .name = "master" } } });
        defer result.deinit();
    }
    const commit_g = blk: {
        var merge = try repo.merge(io, allocator, .{ .kind = .full, .action = .{ .new = .{ .source = &.{.{ .ref = .{ .kind = .head, .name = "foo" } }} } } }, null);
        defer merge.deinit();
        try std.testing.expect(.success == merge.result);
        break :blk merge.result.success.oid;
    };
    try addFile(repo_kind, repo_opts, &repo, io, allocator, "master.md", "h");
    const commit_h = try repo.commit(io, allocator, .{ .message = "h" });

    // put oids in a set
    var oid_set: std.StringArrayHashMapUnmanaged(void) = .empty;
    defer oid_set.deinit(allocator);
    try oid_set.put(allocator, &commit_a, {});
    try oid_set.put(allocator, &commit_b, {});
    try oid_set.put(allocator, &commit_c, {});
    try oid_set.put(allocator, &commit_d, {});
    try oid_set.put(allocator, &commit_e, {});
    try oid_set.put(allocator, &commit_f, {});
    try oid_set.put(allocator, &commit_g, {});
    try oid_set.put(allocator, &commit_h, {});

    // assert that all commits have been found in the log
    // and they aren't repeated
    {
        var commit_iter = try repo.log(io, allocator, .{});
        defer commit_iter.deinit();
        while (try commit_iter.next(allocator)) |commit_object| {
            defer commit_object.deinit();
            try std.testing.expect(oid_set.contains(&commit_object.oid));
            _ = oid_set.swapRemove(&commit_object.oid);
        }
        try std.testing.expectEqual(0, oid_set.count());
    }

    try oid_set.put(allocator, &commit_c, {});
    try oid_set.put(allocator, &commit_d, {});
    try oid_set.put(allocator, &commit_e, {});
    try oid_set.put(allocator, &commit_f, {});
    try oid_set.put(allocator, &commit_g, {});

    // assert that only some commits have been found in the log
    // and they aren't repeated
    {
        var commit_iter = try repo.log(io, allocator, .{ .start_oids = &.{commit_g} });
        defer commit_iter.deinit();
        try commit_iter.exclude(&commit_b);
        while (try commit_iter.next(allocator)) |commit_object| {
            defer commit_object.deinit();
            try std.testing.expect(oid_set.contains(&commit_object.oid));
            _ = oid_set.swapRemove(&commit_object.oid);
        }
        try std.testing.expectEqual(0, oid_set.count());
    }

    // iterate over all objects
    {
        var count: usize = 0;
        var moment = try repo.core.latestMoment();
        const state = rp.Repo(repo_kind, repo_opts).State(.read_only){ .core = &repo.core, .extra = .{ .moment = &moment } };
        var obj_iter = try obj.ObjectIterator(repo_kind, repo_opts).init(state, io, allocator, .{ .kind = .all });
        defer obj_iter.deinit();
        try obj_iter.include(&commit_g);
        while (try obj_iter.next(allocator)) |object| {
            defer object.deinit();
            count += 1;
        }
        try std.testing.expectEqual(20, count);
    }
}

test "chunks are stored and deduplicated in the repo db" {
    const io = std.testing.io;
    const allocator = std.testing.allocator;
    const temp_dir_name = "temp-test-repo-unified-db";
    const repo_opts = rp.RepoOpts(.xit){ .is_test = true };

    // create the temp dir
    const cwd = std.Io.Dir.cwd();
    var temp_dir_or_err = cwd.openDir(io, temp_dir_name, .{});
    if (temp_dir_or_err) |*temp_dir| {
        temp_dir.close(io);
        try cwd.deleteTree(io, temp_dir_name);
    } else |_| {}
    var temp_dir = try cwd.createDirPathOpen(io, temp_dir_name, .{});
    defer cwd.deleteTree(io, temp_dir_name) catch {};
    defer temp_dir.close(io);

    const cwd_path = try std.process.currentPathAlloc(io, allocator);
    defer allocator.free(cwd_path);

    const work_path = try std.fs.path.join(allocator, &.{ cwd_path, temp_dir_name, "repo" });
    defer allocator.free(work_path);

    var repo = try rp.Repo(.xit, repo_opts).init(io, allocator, .{ .path = work_path });
    defer repo.deinit(io, allocator);

    // A unified repo has no separate chunks entry.
    {
        var xit_dir = try temp_dir.openDir(io, "repo/.xit", .{});
        defer xit_dir.close(io);
        try std.testing.expectError(error.FileNotFound, xit_dir.access(io, "chunks", .{}));
    }

    // Random content cannot be compressed and makes file growth reflect
    // whether the second object reused the first object's chunks.
    const content = try allocator.alloc(u8, 200_000);
    defer allocator.free(content);
    var prng = std.Random.DefaultPrng.init(42);
    prng.random().bytes(content);

    try addFile(.xit, repo_opts, &repo, io, allocator, "data.bin", content);
    _ = try repo.commit(io, allocator, .{ .message = "a" });
    const size_before = try repo.core.db_file.length(io);

    try addFile(.xit, repo_opts, &repo, io, allocator, "same.bin", content);
    _ = try repo.commit(io, allocator, .{ .message = "b" });
    const size_after = try repo.core.db_file.length(io);

    try std.testing.expect(size_after - size_before < content.len / 10);

    try repo.core.work_dir.deleteFile(io, "same.bin");
    try repo.restore(io, allocator, "same.bin");
    const actual = try repo.core.work_dir.readFileAlloc(io, "same.bin", allocator, .limited(content.len * 2));
    defer allocator.free(actual);
    try std.testing.expectEqualSlices(u8, content, actual);
}
