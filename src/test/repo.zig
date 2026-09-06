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

    // create the temp dir
    var temp = std.testing.tmpDir(.{});
    defer temp.cleanup();
    const temp_path = try temp.dir.realPathFileAlloc(io, ".", allocator);
    defer allocator.free(temp_path);

    const work_path = try std.fs.path.join(allocator, &.{ temp_path, "repo" });
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
    const repo_opts = rp.RepoOpts(.xit){ .is_test = true };
    const DB = rp.Repo(.xit, repo_opts).DB;

    var temp = std.testing.tmpDir(.{});
    defer temp.cleanup();
    const temp_path = try temp.dir.realPathFileAlloc(io, ".", allocator);
    defer allocator.free(temp_path);

    const work_path = try std.fs.path.join(allocator, &.{ temp_path, "repo" });
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

    // create the temp dir
    var temp = std.testing.tmpDir(.{});
    defer temp.cleanup();
    const temp_path = try temp.dir.realPathFileAlloc(io, ".", allocator);
    defer allocator.free(temp_path);

    const work_path = try std.fs.path.join(allocator, &.{ temp_path, "repo" });
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

test "merge ancestry" {
    try testMergeAncestry(.git, .{ .is_test = true }, .basic);
    try testMergeAncestry(.git, .{ .is_test = true }, .equal_timestamps);
    try testMergeAncestry(.git, .{ .is_test = true }, .clock_skew);
    try testMergeAncestry(.git, .{ .is_test = true }, .criss_cross);
    try testMergeAncestry(.git, .{ .is_test = true }, .diamonds);
    try testMergeAncestry(.git, .{ .is_test = true }, .tags);

    try testMergeAncestry(.xit, .{ .is_test = true }, .basic);
    try testMergeAncestry(.xit, .{ .is_test = true }, .equal_timestamps);
    try testMergeAncestry(.xit, .{ .is_test = true }, .clock_skew);
    try testMergeAncestry(.xit, .{ .is_test = true }, .criss_cross);
    try testMergeAncestry(.xit, .{ .is_test = true }, .diamonds);
    try testMergeAncestry(.xit, .{ .is_test = true }, .tags);
}

fn testMergeAncestry(
    comptime repo_kind: rp.RepoKind,
    comptime repo_opts: rp.RepoOpts(repo_kind),
    comptime case: enum { basic, equal_timestamps, clock_skew, criss_cross, diamonds, tags },
) !void {
    const io = std.testing.io;
    const allocator = std.testing.allocator;
    errdefer std.debug.print("merge ancestry: {s}, {s}\n", .{ @tagName(repo_kind), @tagName(case) });

    var temp = std.testing.tmpDir(.{});
    defer temp.cleanup();
    const temp_path = try temp.dir.realPathFileAlloc(io, ".", allocator);
    defer allocator.free(temp_path);
    const work_path = try std.fs.path.join(allocator, &.{ temp_path, "repo" });
    defer allocator.free(work_path);
    var repo = try rp.Repo(repo_kind, repo_opts).init(io, allocator, .{ .path = work_path });
    defer repo.deinit(io, allocator);

    const parents: []const []const usize = switch (case) {
        .basic => &.{ &.{}, &.{0}, &.{0}, &.{ 1, 2 }, &.{3}, &.{} },
        // a--b--c, with d's parents [b, c], so c is the base of c and d
        .equal_timestamps => &.{ &.{}, &.{0}, &.{1}, &.{ 1, 2 } },
        // d merges b and c, and both tips descend from d despite their dates
        .clock_skew => &.{ &.{}, &.{0}, &.{0}, &.{ 2, 1 }, &.{ 3, 2 }, &.{ 1, 4 }, &.{ 3, 2 } },
        // b and c are incomparable best bases of the two merge commits
        .criss_cross => &.{ &.{}, &.{0}, &.{0}, &.{ 1, 2 }, &.{ 2, 1 } },
        // many paths through a small graph must not cause repeated reads
        .diamonds => &.{
            &.{},         &.{0},        &.{0},        &.{ 1, 2 },   &.{ 1, 2 },
            &.{ 3, 4 },   &.{ 3, 4 },   &.{ 5, 6 },   &.{ 5, 6 },   &.{ 7, 8 },
            &.{ 7, 8 },   &.{ 9, 10 },  &.{ 9, 10 },  &.{ 11, 12 }, &.{ 11, 12 },
            &.{ 13, 14 }, &.{ 13, 14 }, &.{ 15, 16 }, &.{ 15, 16 }, &.{ 17, 18 },
            &.{ 17, 18 }, &.{ 19, 20 }, &.{ 19, 20 }, &.{ 21, 22 }, &.{ 21, 22 },
            &.{},
        },
        .tags => &.{ &.{}, &.{0} },
    };
    const oid_count = parents.len + (if (case == .tags) 2 else 0);
    var oids: [oid_count][hash.hexLen(repo_opts.hash)]u8 = undefined;
    for (parents, 0..) |parent_indices, i| {
        var parent_oids: [2][hash.hexLen(repo_opts.hash)]u8 = undefined;
        for (parent_indices, 0..) |parent, j| parent_oids[j] = oids[parent];
        const message = [_]u8{'a' + @as(u8, @intCast(i))};
        if (case == .tags) try addFile(repo_kind, repo_opts, &repo, io, allocator, "f.txt", &message);
        oids[i] = try repo.commit(io, allocator, .{
            .message = &message,
            .parent_oids = parent_oids[0..parent_indices.len],
            .allow_empty = true,
            .timestamp = switch (case) {
                .equal_timestamps => 100,
                .clock_skew => ([_]u64{ 161, 137, 173, 146, 117, 166, 120 })[i],
                else => 100 + i,
            },
        });
    }
    if (case == .tags) {
        oids[2] = try repo.addTag(io, allocator, .{ .name = "tag", .message = "annotated" });
        try repo.resetAdd(io, .{ .oid = &oids[2] });
        oids[3] = try repo.addTag(io, allocator, .{ .name = "nested", .message = "annotated" });
        try repo.resetAdd(io, .{ .oid = &oids[1] });
    }

    var moment = try repo.core.latestMoment();
    const state = rp.Repo(repo_kind, repo_opts).State(.read_only){ .core = &repo.core, .extra = .{ .moment = &moment } };
    // count open object readers through Io
    var files = struct {
        threaded: std.Io.Threaded,
        open_count: usize = 0,
        read_count: usize = 0,

        fn open(userdata: ?*anyopaque, dir: std.Io.Dir, path: []const u8, opts: std.Io.Dir.OpenFileOptions) std.Io.File.OpenError!std.Io.File {
            const file = try std.testing.io.vtable.dirOpenFile(userdata, dir, path, opts);
            const threaded: *std.Io.Threaded = @ptrCast(@alignCast(userdata.?));
            const self: *@This() = @fieldParentPtr("threaded", threaded);
            self.open_count += 1;
            self.read_count += 1;
            return file;
        }

        fn close(userdata: ?*anyopaque, handles: []const std.Io.File) void {
            const threaded: *std.Io.Threaded = @ptrCast(@alignCast(userdata.?));
            const self: *@This() = @fieldParentPtr("threaded", threaded);
            self.open_count -= handles.len;
            std.testing.io.vtable.fileClose(userdata, handles);
        }
    }{ .threaded = std.Io.Threaded.init(allocator, .{}) };
    defer files.threaded.deinit();
    var vtable = std.testing.io.vtable.*;
    vtable.dirOpenFile = @TypeOf(files).open;
    vtable.fileClose = @TypeOf(files).close;
    const ancestry_io: std.Io = .{ .userdata = &files.threaded, .vtable = &vtable };

    const Query = struct { a: usize, b: usize, ancestor: anyerror!usize, descendent: ?usize, max_reads: usize = oid_count };
    const queries: []const Query = switch (case) {
        .basic => &.{
            .{ .a = 0, .b = 0, .ancestor = 0, .descendent = 0, .max_reads = 1 },
            .{ .a = 0, .b = 4, .ancestor = 0, .descendent = 4 },
            .{ .a = 3, .b = 4, .ancestor = 3, .descendent = 4 },
            .{ .a = 1, .b = 2, .ancestor = 0, .descendent = null },
            .{ .a = 2, .b = 4, .ancestor = 2, .descendent = 4 },
            .{ .a = 4, .b = 5, .ancestor = error.NoCommonAncestor, .descendent = null },
        },
        .equal_timestamps => &.{.{ .a = 2, .b = 3, .ancestor = 2, .descendent = 3 }},
        .clock_skew => &.{.{ .a = 5, .b = 6, .ancestor = 3, .descendent = null }},
        .criss_cross => &.{.{ .a = 3, .b = 4, .ancestor = error.MultipleMergeBases, .descendent = null }},
        .diamonds => &.{
            .{ .a = 21, .b = 23, .ancestor = 21, .descendent = 23, .max_reads = 3 },
            .{ .a = 0, .b = 23, .ancestor = 0, .descendent = 23 },
            .{ .a = 23, .b = 24, .ancestor = error.MultipleMergeBases, .descendent = null },
            .{ .a = 23, .b = 25, .ancestor = error.NoCommonAncestor, .descendent = null },
        },
        .tags => &.{
            .{ .a = 0, .b = 2, .ancestor = 0, .descendent = 1 },
            .{ .a = 1, .b = 2, .ancestor = 1, .descendent = 1, .max_reads = 2 },
            .{ .a = 2, .b = 2, .ancestor = 1, .descendent = 1, .max_reads = 2 },
            .{ .a = 2, .b = 3, .ancestor = 1, .descendent = 1, .max_reads = 3 },
            .{ .a = 3, .b = 3, .ancestor = 1, .descendent = 1, .max_reads = 3 },
        },
    };
    for (queries) |query| {
        for ([_][2]usize{ .{ query.a, query.b }, .{ query.b, query.a } }) |pair| {
            errdefer std.debug.print("commits: {d}, {d}\n", .{ pair[0], pair[1] });
            files.read_count = 0;
            const descendent = mrg.getDescendent(repo_kind, repo_opts, state, ancestry_io, allocator, &oids[pair[0]], &oids[pair[1]]);
            try std.testing.expectEqual(0, files.open_count);
            try std.testing.expect(files.read_count <= query.max_reads);
            if (query.descendent) |expected| {
                try std.testing.expectEqualStrings(&oids[expected], &(try descendent));
            } else {
                try std.testing.expectError(error.DescendentNotFound, descendent);
            }
            files.read_count = 0;
            const ancestor = mrg.commonAncestor(repo_kind, repo_opts, state, ancestry_io, allocator, &oids[pair[0]], &oids[pair[1]]);
            try std.testing.expectEqual(0, files.open_count);
            try std.testing.expect(files.read_count <= query.max_reads);
            if (query.ancestor) |expected| {
                try std.testing.expectEqualStrings(&oids[expected], &(try ancestor));
            } else |err| {
                try std.testing.expectError(err, ancestor);
            }
        }
    }
    if (case == .criss_cross) {
        try repo.core.work_dir.writeFile(io, .{ .sub_path = "local.txt", .data = "local" });
        try std.testing.expectError(error.MultipleMergeBases, repo.merge(io, allocator, .{ .kind = .full, .action = .{ .new = .{ .source = &.{.{ .oid = &oids[3] }} } } }, null));
        try std.testing.expectEqual(oids[4], (try repo.readRef(io, .{ .kind = .none, .name = "HEAD" })).?);
        try std.testing.expectEqual(null, try repo.readRef(io, .{ .kind = .none, .name = "MERGE_HEAD" }));
        var status = try repo.status(io, allocator);
        defer status.deinit(allocator);
        try std.testing.expectEqual(0, status.index.entries.count());
        const content = try repo.core.work_dir.readFileAlloc(io, "local.txt", allocator, .limited(1024));
        defer allocator.free(content);
        try std.testing.expectEqualStrings("local", content);
    }
    if (case == .tags) {
        var reset = try repo.resetDir(io, allocator, .{ .target = .{ .oid = &oids[0] } });
        defer reset.deinit();
        try repo.addBranch(io, .{ .name = "target" });
        var at_ref = try repo.mergeAtRef(io, allocator, .{ .kind = .full, .action = .{ .new = .{ .source = &.{.{ .oid = &oids[2] }} } } }, .{ .kind = .head, .name = "target" }, null);
        defer at_ref.deinit();
        try std.testing.expect(at_ref.result == .fast_forward);
        try std.testing.expectEqual(oids[1], (try repo.readRef(io, .{ .kind = .head, .name = "target" })).?);
        var merge = try repo.merge(io, allocator, .{ .kind = .full, .action = .{ .new = .{ .source = &.{.{ .oid = &oids[3] }} } } }, null);
        defer merge.deinit();
        try std.testing.expect(merge.result == .fast_forward);
        try std.testing.expectEqual(oids[1], (try repo.readRef(io, .{ .kind = .none, .name = "HEAD" })).?);
        const content = try repo.core.work_dir.readFileAlloc(io, "f.txt", allocator, .limited(1024));
        defer allocator.free(content);
        try std.testing.expectEqualStrings("b", content);
    }
}

test "merge local changes" {
    try testMergeLocalChanges(.git, .{ .is_test = true }, .unstaged);
    try testMergeLocalChanges(.git, .{ .is_test = true }, .staged);
    try testMergeLocalChanges(.git, .{ .is_test = true }, .untracked);
    try testMergeLocalChanges(.git, .{ .is_test = true }, .deleted);
    try testMergeLocalChanges(.git, .{ .is_test = true }, .unrelated);
    try testMergeLocalChanges(.git, .{ .is_test = true }, .unrelated_staged);
    try testMergeLocalChanges(.git, .{ .is_test = true }, .unborn);
    try testMergeLocalChanges(.git, .{ .is_test = true }, .unborn_clean);
    try testMergeLocalChanges(.git, .{ .is_test = true }, .backup);
    try testMergeLocalChanges(.git, .{ .is_test = true }, .backup_incoming);
    try testMergeLocalChanges(.git, .{ .is_test = true }, .backup_directory);

    try testMergeLocalChanges(.xit, .{ .is_test = true }, .unstaged);
    try testMergeLocalChanges(.xit, .{ .is_test = true }, .staged);
    try testMergeLocalChanges(.xit, .{ .is_test = true }, .untracked);
    try testMergeLocalChanges(.xit, .{ .is_test = true }, .deleted);
    try testMergeLocalChanges(.xit, .{ .is_test = true }, .unrelated);
    try testMergeLocalChanges(.xit, .{ .is_test = true }, .unrelated_staged);
    try testMergeLocalChanges(.xit, .{ .is_test = true }, .unborn);
    try testMergeLocalChanges(.xit, .{ .is_test = true }, .unborn_clean);
    try testMergeLocalChanges(.xit, .{ .is_test = true }, .backup);
    try testMergeLocalChanges(.xit, .{ .is_test = true }, .backup_incoming);
    try testMergeLocalChanges(.xit, .{ .is_test = true }, .backup_directory);
}

fn testMergeLocalChanges(
    comptime repo_kind: rp.RepoKind,
    comptime repo_opts: rp.RepoOpts(repo_kind),
    case: enum { unstaged, staged, untracked, deleted, unrelated, unrelated_staged, unborn, unborn_clean, backup, backup_incoming, backup_directory },
) !void {
    const io = std.testing.io;
    const allocator = std.testing.allocator;
    errdefer std.debug.print("merge local changes: {s}, {s}\n", .{ @tagName(repo_kind), @tagName(case) });
    const incoming_backup = case == .backup_incoming or case == .backup_directory;
    const backup = case == .backup or incoming_backup;

    var temp = std.testing.tmpDir(.{});
    defer temp.cleanup();
    const temp_path = try temp.dir.realPathFileAlloc(io, ".", allocator);
    defer allocator.free(temp_path);
    const work_path = try std.fs.path.join(allocator, &.{ temp_path, "repo" });
    defer allocator.free(work_path);
    var repo = try rp.Repo(repo_kind, repo_opts).init(io, allocator, .{ .path = work_path });
    defer repo.deinit(io, allocator);

    var target_oid: ?[hash.hexLen(repo_opts.hash)]u8 = null;
    const source_oid = if (case == .unborn or case == .unborn_clean) blk: {
        // create the source without giving HEAD a commit or leaving staged files
        try addFile(repo_kind, repo_opts, &repo, io, allocator, "f.txt", "source");
        var status = try repo.status(io, allocator);
        defer status.deinit(allocator);
        const entry = status.index.entries.get("f.txt").?[0].?;
        var tree = try obj.Tree.init(allocator);
        defer tree.deinit();
        try tree.addBlobEntry(entry.mode, "f.txt", &entry.oid);
        const oid = try repo.commitAtRef(io, allocator, .{ .message = "source", .timestamp = 1 }, &tree, .{ .kind = .head, .name = "source" });
        try repo.remove(io, allocator, &.{"f.txt"}, .{ .force = true });
        break :blk oid;
    } else blk: {
        if (case != .untracked and !backup) try addFile(repo_kind, repo_opts, &repo, io, allocator, "f.txt", "base");
        if (case == .unrelated or case == .unrelated_staged) try addFile(repo_kind, repo_opts, &repo, io, allocator, "other.txt", "base");
        const base_oid = try repo.commit(io, allocator, .{ .message = "base", .allow_empty = true, .timestamp = 1 });
        try addFile(repo_kind, repo_opts, &repo, io, allocator, if (backup) "f.txt/child" else "f.txt", "source");
        if (incoming_backup) try addFile(repo_kind, repo_opts, &repo, io, allocator, if (case == .backup_incoming) "f.txt~master" else "f.txt~master/child", "incoming");
        const oid = try repo.commit(io, allocator, .{ .message = "source", .timestamp = 2 });
        var result = try repo.resetDir(io, allocator, .{ .target = .{ .oid = &base_oid } });
        defer result.deinit();
        target_oid = base_oid;
        if (backup) {
            try addFile(repo_kind, repo_opts, &repo, io, allocator, "f.txt", "target");
            target_oid = try repo.commit(io, allocator, .{ .message = "target", .timestamp = 3 });
        }
        break :blk oid;
    };
    const local_path = switch (case) {
        .unrelated, .unrelated_staged, .unborn_clean, .backup_incoming, .backup_directory => "other.txt",
        .backup => "f.txt~master",
        else => "f.txt",
    };
    if (case == .deleted) {
        try repo.core.work_dir.deleteFile(io, local_path);
    } else {
        try repo.core.work_dir.writeFile(io, .{ .sub_path = local_path, .data = "local" });
    }
    if (case == .staged or case == .unrelated_staged) try repo.add(io, allocator, &.{local_path});
    var before = try repo.status(io, allocator);
    defer before.deinit(allocator);

    const allowed = case == .unrelated or case == .unborn_clean;
    var result_or_err = repo.merge(io, allocator, .{ .kind = .full, .action = .{ .new = .{ .algo = .diff3, .source = &.{.{ .oid = &source_oid }} } } }, null);
    if (result_or_err) |*result| {
        defer result.deinit();
        try std.testing.expect(allowed);
        try std.testing.expect(result.result == .fast_forward);
    } else |err| {
        if (allowed) return err;
        try std.testing.expectEqual(if (incoming_backup) error.MergeBackupPathConflict else error.CannotMergeWithLocalChanges, err);
    }

    var after = try repo.status(io, allocator);
    defer after.deinit(allocator);
    if (case == .deleted) {
        try std.testing.expect(after.work_dir_deleted.contains(local_path));
    } else {
        const content = try repo.core.work_dir.readFileAlloc(io, local_path, allocator, .limited(1024));
        defer allocator.free(content);
        try std.testing.expectEqualStrings("local", content);
    }
    try std.testing.expectEqual(if (allowed) source_oid else target_oid, try repo.readRef(io, .{ .kind = .none, .name = "HEAD" }));
    if (allowed) {
        try std.testing.expectEqual(0, after.index_added.count() + after.index_modified.count() + after.index_deleted.count());
        const content = try repo.core.work_dir.readFileAlloc(io, "f.txt", allocator, .limited(1024));
        defer allocator.free(content);
        try std.testing.expectEqualStrings("source", content);
    } else {
        try std.testing.expectEqualDeep(before.index.entries.get("f.txt"), after.index.entries.get("f.txt"));
        try std.testing.expectEqualDeep(before.index.entries.get(local_path), after.index.entries.get(local_path));
    }
    try std.testing.expectEqual(null, try repo.readRef(io, .{ .kind = .none, .name = "MERGE_HEAD" }));
}

test "merge abort" {
    try testMergeAbort(.git, .{ .is_test = true }, .file_dir);
    try testMergeAbort(.git, .{ .is_test = true }, .dir_file);
    try testMergeAbort(.xit, .{ .is_test = true }, .file_dir);
    try testMergeAbort(.xit, .{ .is_test = true }, .dir_file);
}

fn testMergeAbort(comptime repo_kind: rp.RepoKind, comptime repo_opts: rp.RepoOpts(repo_kind), case: enum { file_dir, dir_file }) !void {
    const io = std.testing.io;
    const allocator = std.testing.allocator;
    errdefer std.debug.print("merge abort: {s}, {s}\n", .{ @tagName(repo_kind), @tagName(case) });

    var temp = std.testing.tmpDir(.{});
    defer temp.cleanup();
    const temp_path = try temp.dir.realPathFileAlloc(io, ".", allocator);
    defer allocator.free(temp_path);
    const work_path = try std.fs.path.join(allocator, &.{ temp_path, "repo" });
    defer allocator.free(work_path);
    var repo = try rp.Repo(repo_kind, repo_opts).init(io, allocator, .{ .path = work_path });
    defer repo.deinit(io, allocator);

    const target_path = if (case == .file_dir) "f.txt" else "f.txt/dir/g.txt";
    const source_path = if (case == .file_dir) "f.txt/dir/g.txt" else "f.txt";
    try addFile(repo_kind, repo_opts, &repo, io, allocator, "local.txt", "base");
    const base_oid = try repo.commit(io, allocator, .{ .message = "base", .timestamp = 1 });
    try addFile(repo_kind, repo_opts, &repo, io, allocator, source_path, "source");
    try addFile(repo_kind, repo_opts, &repo, io, allocator, "added.txt", "source");
    const source_oid = try repo.commit(io, allocator, .{ .message = "source", .timestamp = 2 });
    {
        var result = try repo.resetDir(io, allocator, .{ .target = .{ .oid = &base_oid } });
        defer result.deinit();
    }
    try addFile(repo_kind, repo_opts, &repo, io, allocator, target_path, "target");
    const target_oid = try repo.commit(io, allocator, .{ .message = "target", .timestamp = 3 });
    try repo.core.work_dir.writeFile(io, .{ .sub_path = "local.txt", .data = "local" });
    if (case == .dir_file) try repo.core.work_dir.writeFile(io, .{ .sub_path = "f.txt/local.txt", .data = "untracked" });
    {
        var merge = try repo.merge(io, allocator, .{ .kind = .full, .action = .{ .new = .{ .source = &.{.{ .oid = &source_oid }} } } }, null);
        defer merge.deinit();
        try std.testing.expect(merge.result == .conflict);
    }
    {
        var result = try repo.resetDir(io, allocator, .{ .target = null, .force = true });
        defer result.deinit();
    }
    var status = try repo.status(io, allocator);
    defer status.deinit(allocator);
    try std.testing.expectEqual(0, status.unresolved_conflicts.count() + status.index_added.count() + status.index_modified.count() + status.index_deleted.count() + status.work_dir_deleted.count());
    try std.testing.expectEqual(1, status.work_dir_modified.count());
    for ([_][]const u8{ target_path, "local.txt" }, [_][]const u8{ "target", "local" }) |path, expected| {
        const content = try repo.core.work_dir.readFileAlloc(io, path, allocator, .limited(1024));
        defer allocator.free(content);
        try std.testing.expectEqualStrings(expected, content);
    }
    try std.testing.expect(!status.untracked.contains("added.txt"));
    if (case == .dir_file) try std.testing.expect(status.untracked.contains("f.txt/local.txt"));
    try std.testing.expectEqual(target_oid, (try repo.readRef(io, .{ .kind = .none, .name = "HEAD" })).?);
    try std.testing.expectEqual(null, try repo.readRef(io, .{ .kind = .none, .name = "MERGE_HEAD" }));
}

test "merge conflict mode" {
    try testMergeConflictMode(.git, .{ .is_test = true }, .diff3);
    try testMergeConflictMode(.xit, .{ .is_test = true }, .diff3);
    try testMergeConflictMode(.xit, .{ .is_test = true }, .patch);
}

fn testMergeConflictMode(comptime repo_kind: rp.RepoKind, comptime repo_opts: rp.RepoOpts(repo_kind), algo: mrg.MergeAlgorithm) !void {
    const io = std.testing.io;
    const allocator = std.testing.allocator;
    errdefer std.debug.print("mode merge: {s}, {s}\n", .{ @tagName(repo_kind), @tagName(algo) });

    var temp = std.testing.tmpDir(.{});
    defer temp.cleanup();
    const temp_path = try temp.dir.realPathFileAlloc(io, ".", allocator);
    defer allocator.free(temp_path);
    const work_path = try std.fs.path.join(allocator, &.{ temp_path, "repo" });
    defer allocator.free(work_path);
    var repo = try rp.Repo(repo_kind, repo_opts).init(io, allocator, .{ .path = work_path });
    defer repo.deinit(io, allocator);

    // text edits merge cleanly, but changing a regular file to a symlink
    // on one side and making it executable on the other is a mode conflict
    // build trees directly so this also works without filesystem symlinks
    const names = [_][]const u8{ "base", "target", "source" };
    const modes = [_]u32{ 0o100644, 0o120000, 0o100755 };
    var oids: [3][hash.hexLen(repo_opts.hash)]u8 = undefined;
    for ([_][]const u8{ "a\nb\nc\nd\ne", "A\nb\nc\nd\ne", "a\nb\nc\nd\nE" }, 0..) |content, i| {
        try addFile(repo_kind, repo_opts, &repo, io, allocator, "f.txt", content);
        var status = try repo.status(io, allocator);
        defer status.deinit(allocator);
        var tree = try obj.Tree.init(allocator);
        defer tree.deinit();
        try tree.addBlobEntry(@bitCast(modes[i]), "f.txt", &status.index.entries.get("f.txt").?[0].?.oid);
        oids[i] = try repo.commitAtRef(io, allocator, .{
            .message = names[i],
            .parent_oids = if (i == 0) &.{} else &.{oids[0]},
            .timestamp = i + 1,
        }, &tree, .{ .kind = .head, .name = names[i] });
        if (repo_kind == .xit and i == 0) {
            // a mode-only commit inherits the entire file's patch state.
            try tree.addBlobEntry(@bitCast(@as(u32, 0o100755)), "f.txt", &status.index.entries.get("f.txt").?[0].?.oid);
            const mode_oid = try repo.commitAtRef(io, allocator, .{ .message = "mode only", .parent_oids = &.{oids[0]} }, &tree, .{ .kind = .head, .name = "mode_only" });
            try repo.patchAll(io, allocator, null);
            const moment = try repo.core.latestMoment();
            const snapshots = try rp.Repo(.xit, repo_opts).DB.HashMap(.read_only).init((try moment.getCursor(hash.hashInt(repo_opts.hash, "commit-id->snapshot"))).?);
            const before = (try snapshots.getCursor(try hash.hexToInt(repo_opts.hash, &oids[0]))).?;
            const after = (try snapshots.getCursor(try hash.hexToInt(repo_opts.hash, &mode_oid))).?;
            const path: []const rp.Repo(.xit, repo_opts).DB.PathPart(void) = &.{.{ .hash_map_get = .{ .value = hash.hashInt(repo_opts.hash, "f.txt") } }};
            try std.testing.expectEqualDeep(try before.readPathSlot(void, path), try after.readPathSlot(void, path));
        }
    }
    for ([_]usize{ 1, 2 }) |target| {
        const source = 3 - target;
        var merge = try repo.mergeAtRef(io, allocator, .{ .kind = .full, .action = .{ .new = .{ .algo = algo, .source = &.{.{ .oid = &oids[source] }} } } }, .{ .kind = .head, .name = names[target] }, null);
        defer merge.deinit();
        try std.testing.expect(merge.result == .conflict);
        const conflict = merge.result.conflict.conflicts.get("f.txt") orelse return error.ConflictNotFound;
        try std.testing.expectEqual(modes[0], @as(u32, @bitCast(conflict.base.?.mode)));
        try std.testing.expectEqual(modes[target], @as(u32, @bitCast(conflict.target.?.mode)));
        try std.testing.expectEqual(modes[source], @as(u32, @bitCast(conflict.source.?.mode)));
        try std.testing.expectEqual(oids[target], (try repo.readRef(io, .{ .kind = .head, .name = names[target] })).?);
    }
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

    // create the temp dir
    var temp = std.testing.tmpDir(.{});
    defer temp.cleanup();
    const temp_path = try temp.dir.realPathFileAlloc(io, ".", allocator);
    defer allocator.free(temp_path);

    const work_path = try std.fs.path.join(allocator, &.{ temp_path, "repo" });
    defer allocator.free(work_path);
    var repo = try rp.Repo(.xit, opts).init(io, allocator, .{ .path = work_path });
    defer repo.deinit(io, allocator);

    const initial = "a\nb\nc\nd\ne\nf\ng";
    try addFile(.xit, opts, &repo, io, allocator, "f.txt", initial);
    if (case == .multiple) try addFile(.xit, opts, &repo, io, allocator, "g.txt", initial);
    const root_oid = try repo.commit(io, allocator, .{ .message = "root", .timestamp = 1 });
    const base_oid = if (case == .second_parent) blk: {
        try addFile(.xit, opts, &repo, io, allocator, "f.txt", "a\nb\nc\nd\ne\nf\nbase");
        break :blk try repo.commit(io, allocator, .{ .message = "base", .timestamp = 2 });
    } else root_oid;
    try addFile(.xit, opts, &repo, io, allocator, "f.txt", if (case == .second_parent) "A\nb\nc\nd\ne\nf\nbase" else "A\nb\nc\nd\ne\nf\ng");
    if (case == .multiple) try addFile(.xit, opts, &repo, io, allocator, "g.txt", "target\nb\nc\nd\ne\nf\ng");
    _ = try repo.commit(io, allocator, .{ .message = "target", .timestamp = 3 });
    try repo.addBranch(io, .{ .name = "target" });

    const expected = switch (case) {
        .multiple, .dependent => blk: {
            // unrelated commits inherit the previous patch id, including the base's
            try addFile(.xit, opts, &repo, io, allocator, "f.txt", initial);
            if (case == .multiple) try addFile(.xit, opts, &repo, io, allocator, "g.txt", initial);
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
                // the files share a history but introduce different patches
                if (case == .multiple and i == 0) try addFile(.xit, opts, &repo, io, allocator, "g.txt", "a\nb\nc\nd\nsource\nf\ng");
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
    if (case == .multiple) {
        const other = try repo.core.work_dir.readFileAlloc(io, "g.txt", allocator, .limited(4096));
        defer allocator.free(other);
        try std.testing.expectEqualStrings("target\nb\nc\nd\nsource\nf\ng", other);
    }
}

test "applied patches" {
    try testAppliedPatches(.repeat);
    try testAppliedPatches(.history);
    try testAppliedPatches(.later_edit);
    try testAppliedPatches(.conflict);
    try testAppliedPatches(.rollback);
    try testAppliedPatches(.merge);
    try testMergeEdits(.{ .name = "shared replacement with context", .rebuild = true, .shared_gaps = true, .target = &.{ "a\nB\nc\nd\ne", "longer\nB\nc\nd\ne" }, .source = &.{"a\nB\nc\nd\nE"}, .shared_edits = 1, .expected = &.{.{ .text = "longer\nB\nc\nd\nE" }} });
    try testMergeEdits(.{ .name = "shared insertion with context", .target = &.{ "longer\nb\nc\nd\ne", "longer\nb\nX\nc\nd\ne" }, .source = &.{"a\nb\nX\nc\nd\nE"}, .shared_edits = 1, .expected = &.{.{ .text = "longer\nb\nX\nc\nd\nE" }} });
    try testMergeEdits(.{ .name = "different locations", .target = &.{"a\nX\nb\nc\nd\ne"}, .source = &.{"a\nb\nc\nX\nd\ne"}, .shared_edits = 0, .expected = &.{.{ .text = "a\nX\nb\nc\nX\nd\ne" }} });
    try testMergeEdits(.{ .name = "reinsertion", .max_position_depth = 3, .target = &.{ "a\nb\nX\nc\nd\ne", "a\nb\nY\nc\nd\ne", "a\nb\nc\nd\ne", "a\nb\nX\nc\nd\ne", "a\nb\nc\nd\ne", "a\nb\nX\nc\nd\ne" }, .source = &.{"a\nb\nc\nd\nE"}, .shared_edits = 0, .expected = &.{.{ .text = "a\nb\nX\nc\nd\nE" }} });
    try testMergeEdits(.{ .name = "delete earlier insertion", .target = &.{ "a\nb\nX\nc\nd\ne", "a\ne", "a\nE" }, .source = &.{"A\nb\nc\nd\ne"}, .expected = &.{.{ .text = "A\nE" }} });
    try testMergeEdits(.{ .name = "partially delete earlier insertion", .target = &.{ "a\nb\nX\nY\nc\nd\ne", "a\nY\nc\nd\ne", "a\nY\nc\nd\nE" }, .source = &.{"A\nb\nc\nd\ne"}, .expected = &.{.{ .text = "A\nY\nc\nd\nE" }} });
    try testMergeEdits(.{ .name = "delete earlier replacement", .target = &.{ "a\nb\nX\nc\nd\ne", "a\nb\nY\nc\nd\ne", "a\ne", "a\nE" }, .source = &.{"A\nb\nc\nd\ne"}, .expected = &.{.{ .text = "A\nE" }} });
    try testMergeEdits(.{ .name = "delete around removed insertion", .target = &.{ "a\nb\nX\nc\nd\ne", "a\nb\nc\nd\ne", "a\ne", "a\nE" }, .source = &.{"A\nb\nc\nd\ne"}, .expected = &.{.{ .text = "A\nE" }} });
    try testMergeEdits(.{ .name = "neighboring replacement preserves gap", .target = &.{ "a\nB\nc\nd\ne", "a\nB\nX\nc\nd\ne" }, .source = &.{"a\nb\nX\nc\nd\nE"}, .shared_edits = 1, .expected = &.{.{ .text = "a\nB\nX\nc\nd\nE" }} });
    try testMergeEdits(.{ .name = "shared deletion with context", .target = &.{ "a\nc\nd\ne", "A\nc\nd\ne" }, .source = &.{"a\nc\nd\nE"}, .shared_edits = 1, .expected = &.{.{ .text = "A\nc\nd\nE" }} });
    try testMergeEdits(.{ .name = "reordered deletions", .base = "a\ne", .rebuild = true, .max_position_depth = 3, .target = &.{ "a\nb\nc\nd\ne", "a\nb\nd\ne", "a\nd\ne", "a\ne", "a\nX\ne", "A\nX\ne" }, .source = &.{ "a\nb\nc\nd\ne", "a\nb\nd\ne", "a\nb\ne", "a\ne", "a\nX\ne", "a\nX\nE" }, .shared_edits = 5, .expected = &.{.{ .text = "A\nX\nE" }} });
    try testMergeEdits(.{ .name = "beginning and end", .max_position_depth = 3, .target = &.{ "X\na\nb\nc\nd\ne\nY", "a\nb\nc\nd\ne", "X\na\nb\nc\nd\ne\nY" }, .source = &.{"a\nB\nc\nd\ne"}, .expected = &.{.{ .text = "X\na\nB\nc\nd\ne\nY" }} });
    try testMergeEdits(.{ .name = "editing a replacement", .target = &.{ "a\nu\nv\nc\nd\ne", "a\nu\nx\nv\nc\nd\ne", "a\np\nq\nx\nv\nc\nd\ne" }, .source = &.{"A\nb\nc\nd\ne"}, .expected = &.{.{ .text = "A\np\nq\nx\nv\nc\nd\ne" }} });
    try testMergeEdits(.{ .name = "insertions in nested replacement", .target = &.{ "a\nu\nv\nd\ne", "a\nx\ny\nv\nd\ne", "a\nx\ny\nw\nv\nd\ne" }, .source = &.{ "a\nu\nv\nd\ne", "a\nx\ny\nv\nd\ne", "a\nx\nz\ny\nv\nd\ne" }, .expected = &.{.{ .text = "a\nx\nz\ny\nw\nv\nd\ne" }} });
    try testMergeEdits(.{ .name = "large edit record", .shared_gaps = true, .target = &.{"a\n" ++ ("B" ** 6000) ++ "\nc\nd\ne"}, .source = &.{"a\nb\nc\nd\nE"}, .expected = &.{.{ .text = "a\n" ++ ("B" ** 6000) ++ "\nc\nd\nE" }} });
    try testMergeEdits(.{ .name = "large edit list", .rebuild = true, .shared_gap_chunks = true, .base = ("a\nb\n" ** 220) ++ "c\nd", .target = &.{ ("A\nb\n" ** 220) ++ "c\nd", ("A\nb\n" ** 110) ++ "X\n" ++ ("A\nb\n" ** 110) ++ "c\nd" }, .source = &.{("a\nb\n" ** 220) ++ "c\nD"}, .expected = &.{.{ .text = ("A\nb\n" ** 110) ++ "X\n" ++ ("A\nb\n" ** 110) ++ "c\nD" }} });
}

fn testAppliedPatches(case: enum { repeat, history, later_edit, conflict, rollback, merge }) !void {
    const io = std.testing.io;
    const allocator = std.testing.allocator;
    const opts: rp.RepoOpts(.xit) = .{ .is_test = true };
    const DB = rp.Repo(.xit, opts).DB;
    errdefer std.debug.print("applied patches: {s}\n", .{@tagName(case)});

    // create the temp dir
    var temp = std.testing.tmpDir(.{});
    defer temp.cleanup();
    const temp_path = try temp.dir.realPathFileAlloc(io, ".", allocator);
    defer allocator.free(temp_path);

    const work_path = try std.fs.path.join(allocator, &.{ temp_path, "repo" });
    defer allocator.free(work_path);
    var repo = try rp.Repo(.xit, opts).init(io, allocator, .{ .path = work_path });
    defer repo.deinit(io, allocator);

    // both files should share patch ids, but track their application separately
    const paths = [_][]const u8{ "a.txt", "b.txt" };
    if (case == .history) {
        // the historical text alone exceeds the patch application's budget
        var old_text = [_]u8{'x'} ** 8192;
        for (0..64) |i| {
            _ = try std.fmt.bufPrint(old_text[0..8], "{d:0>8}", .{i});
            for (paths) |path| try addFile(.xit, opts, &repo, io, allocator, path, &old_text);
            _ = try repo.commit(io, allocator, .{ .message = "old text", .timestamp = 0 });
        }
        // the root below inserts a line after this replacement history
        for (paths) |path| try addFile(.xit, opts, &repo, io, allocator, path, "a\nb\nc\nd");
        _ = try repo.commit(io, allocator, .{ .message = "text", .timestamp = 0 });
    }

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
    const third_oid = if (case == .conflict or case == .history) blk: {
        try repo.addBranch(io, .{ .name = "source" });
        for (paths) |path| try addFile(.xit, opts, &repo, io, allocator, path, "a\nthird\nc\nd\ne");
        break :blk try repo.commit(io, allocator, .{ .message = "third", .parent_oids = &.{root_oid}, .timestamp = 4 });
    } else null;
    try repo.patchAll(io, allocator, null);
    if (case == .history) _ = try repo.garbageCollect(io, allocator, &.{});

    if (case == .merge) {
        // missing cache data should allow a merge, but damaged patches must fail.
        const Metadata = enum { depths, depth, invalid_depth, missing_patch, missing_edit };
        const MergeCtx = struct {
            core: *rp.Repo(.xit, opts).Core,
            source_oid: [hash.hexLen(opts.hash)]u8,
            metadata: Metadata,

            pub fn run(ctx: @This(), cursor: *DB.Cursor(.read_write)) !void {
                var moment = try DB.HashMap(.read_write).init(cursor.*);
                const state: rp.Repo(.xit, opts).State(.read_write) = .{ .core = ctx.core, .extra = .{ .moment = &moment } };
                const depth_key = hash.hashInt(opts.hash, obj.COMMIT_ID_TO_FIRST_PARENT_DEPTH_KEY);
                switch (ctx.metadata) {
                    .depths => {
                        _ = try moment.remove(depth_key);
                    },
                    .depth, .invalid_depth => {
                        const depths = try DB.HashMap(.read_write).init(try moment.putCursor(depth_key));
                        const id = try hash.hexToInt(opts.hash, &ctx.source_oid);
                        if (ctx.metadata == .depth) {
                            _ = try depths.remove(id);
                        } else try depths.put(id, .{ .bytes = "bad" });
                    },
                    .missing_patch, .missing_edit => {
                        const entry = (try moment.cursor.readPath(void, &.{
                            .{ .hash_map_get = .{ .value = hash.hashInt(opts.hash, "commit-id->snapshot") } },
                            .{ .hash_map_get = .{ .value = try hash.hexToInt(opts.hash, &ctx.source_oid) } },
                            .{ .hash_map_get = .{ .value = hash.hashInt(opts.hash, paths[0]) } },
                            .{ .array_list_get = @intFromEnum(patch.FileField.patch) },
                        })).?;
                        var bytes: [hash.byteLen(opts.hash)]u8 = undefined;
                        _ = try entry.readBytes(&bytes);
                        const patches = try DB.HashMap(.read_write).init(try moment.putCursor(hash.hashInt(opts.hash, "patch-id->edit-list")));
                        const id = hash.bytesToInt(opts.hash, &bytes);
                        if (ctx.metadata == .missing_patch) {
                            _ = try patches.remove(id);
                        } else {
                            _ = try (try patches.getCursor(id)).?.readBytes(&bytes);
                            const edits = try DB.HashMap(.read_write).init(try moment.putCursor(hash.hashInt(opts.hash, "edit-id->edit")));
                            _ = try edits.remove(hash.bytesToInt(opts.hash, &bytes));
                        }
                    },
                }
                const result = mrg.Merge(.xit, opts).init(state, io, allocator, .{ .kind = .full, .action = .{ .new = .{ .algo = .patch, .source = &.{.{ .oid = &ctx.source_oid }} } } }, .{ .kind = .head, .name = "target" }, null);
                switch (ctx.metadata) {
                    .invalid_depth => try std.testing.expectError(error.UnexpectedTag, result),
                    .missing_patch => try std.testing.expectError(error.PatchNotFound, result),
                    .missing_edit => try std.testing.expectError(error.EditNotFound, result),
                    else => {
                        var merge = try result;
                        defer merge.deinit();
                        try std.testing.expect(merge.result == .success);
                        for (paths) |path| {
                            var reader = try obj.ObjectReader(.xit, opts).init(state.readOnly(), io, allocator, &std.fmt.bytesToHex(merge.changes.get(path).?.new.?.oid, .lower));
                            defer reader.deinit();
                            var text: [9]u8 = undefined;
                            try reader.interface.readSliceAll(&text);
                            try std.testing.expectEqualStrings("a\nB\nc\nd\nE", &text);
                        }
                    },
                }
                // restore the metadata and target ref before the next merge.
                return error.CancelTransaction;
            }
        };
        const history = try DB.ArrayList(.read_write).init(repo.core.db.rootCursor());
        for ([_]Metadata{ .depths, .depth, .invalid_depth, .missing_patch, .missing_edit }) |metadata| {
            errdefer std.debug.print("merge metadata: {s}\n", .{@tagName(metadata)});
            try std.testing.expectError(error.CancelTransaction, history.appendContext(.{ .slot = try history.getSlot(-1) }, MergeCtx{ .core = &repo.core, .source_oid = source_oid, .metadata = metadata }));
        }
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
        third_oid: ?[hash.hexLen(opts.hash)]u8,
        corruption: enum { count, gap, placement, text } = .count,
        create: bool = false,

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
                    .{ .hash_map_get = .{ .value = hash.hashInt(opts.hash, path) } },
                    .{ .array_list_get = @intFromEnum(patch.FileField.patch) },
                })).?;
                _ = try patch_cursor.readBytes(patch_id);
            }
            try std.testing.expectEqualSlices(u8, &patch_ids[0], &patch_ids[1]);
            const patch_id = hash.bytesToInt(opts.hash, &patch_ids[0]);
            const path_hash = hash.hashInt(opts.hash, paths[0]);

            const edit_list = (try moment.cursor.readPath(void, &.{
                .{ .hash_map_get = .{ .value = hash.hashInt(opts.hash, "patch-id->edit-list") } },
                .{ .hash_map_get = .{ .value = patch_id } },
            })).?;
            const edit_bytes = try edit_list.readBytesAlloc(allocator, opts.max_read_size);
            defer allocator.free(edit_bytes);
            const edit_id = std.mem.readInt(hash.HashInt(opts.hash), edit_bytes[0..comptime hash.byteLen(opts.hash)], .big);
            if (ctx.case == .rollback) {
                // a malformed edit must leave the original snapshot intact
                const records = try DB.HashMap(.read_write).init(try moment.putCursor(hash.hashInt(opts.hash, "edit-id->edit")));
                switch (ctx.corruption) {
                    .count => try records.put(edit_id, .{ .bytes = "\xff\xff\xff\xff" }),
                    .gap => try records.put(edit_id, .{ .bytes = "\x00\x00\x00\x00" ++ "\x00\x00\x00\x01x" ++ "\xff\xff\xff\xff" }),
                    .placement, .text => {
                        // the returned allocation is owned by this test.
                        const bytes = @constCast(try (try records.getCursor(edit_id)).?.readBytesAlloc(allocator, opts.max_read_size));
                        defer allocator.free(bytes);
                        if (ctx.corruption == .placement) {
                            const offset = 4 + hash.byteLen(opts.hash) + 4 + 4;
                            std.mem.writeInt(u32, bytes[offset..][0..4], 1, .big);
                        } else bytes[bytes.len - 1] ^= 1;
                        try records.put(edit_id, .{ .bytes = bytes });
                    },
                }
            }
            var memory: [256 * 1024]u8 = undefined;
            var fixed = std.heap.FixedBufferAllocator.init(&memory);
            const patch_allocator = if (ctx.case == .history) fixed.allocator() else allocator;
            var read_moment = moment.readOnly();
            if (ctx.case != .later_edit) {
                const size_before = try cursor.db.core.length();
                var application = try patch.applyPatches(opts, &read_moment, snapshot.cursor.readOnly(), patch_allocator, paths[0], &.{patch_id}, if (ctx.create) .create else .merge);
                defer application.deinit(patch_allocator);
                try std.testing.expectEqual(size_before, try cursor.db.core.length());
                try application.save(&snapshot, patch_allocator, paths[0], .clear);
            }
            const membership = try snapshot.cursor.readPath(void, &.{
                .{ .hash_map_get = .{ .value = path_hash } },
                .{ .array_list_get = @intFromEnum(patch.FileField.edits) },
                .{ .hash_map_get = .{ .key = edit_id } },
            });
            try std.testing.expect(membership != null);
            if (ctx.third_oid) |oid| {
                const third_patch = (try moment.cursor.readPath(void, &.{
                    .{ .hash_map_get = .{ .value = hash.hashInt(opts.hash, "commit-id->snapshot") } },
                    .{ .hash_map_get = .{ .value = try hash.hexToInt(opts.hash, &oid) } },
                    .{ .hash_map_get = .{ .value = path_hash } },
                    .{ .array_list_get = @intFromEnum(patch.FileField.patch) },
                })).?;
                var id: [hash.byteLen(opts.hash)]u8 = undefined;
                _ = try third_patch.readBytes(&id);
                var application = try patch.applyPatches(opts, &read_moment, snapshot.cursor.readOnly(), patch_allocator, paths[0], &.{hash.bytesToInt(opts.hash, &id)}, .merge);
                defer application.deinit(patch_allocator);
                try std.testing.expectEqual(1, application.file.regions.items.len);
                try std.testing.expectEqual(@as(usize, if (ctx.case == .history) 6 else 7), application.file.lines.items.len);
                try application.save(&snapshot, patch_allocator, paths[0], .clear);
            }
            const line_list = try snapshot.cursor.readPath(void, &.{
                .{ .hash_map_get = .{ .value = path_hash } },
                .{ .array_list_get = @intFromEnum(patch.FileField.lines) },
            });
            try std.testing.expect(line_list != null);
            const gaps = try snapshot.cursor.readPathSlot(void, &.{
                .{ .hash_map_get = .{ .value = path_hash } },
                .{ .array_list_get = @intFromEnum(patch.FileField.gaps) },
            });
            try std.testing.expectEqual(ctx.case == .later_edit, gaps != null);
            var file = try patch.File(opts).load(&read_moment, snapshot.cursor.readOnly(), patch_allocator, path_hash);
            defer file.deinit();
            try std.testing.expectEqual(ctx.case == .conflict or ctx.case == .history, file.has_conflict);

            // freezing forces any writes to copy existing data.
            // applying the patch again should make no changes at all.
            try cursor.db.freeze();
            const size_before = try cursor.db.core.length();
            var application = try patch.applyPatches(opts, &read_moment, snapshot.cursor.readOnly(), patch_allocator, paths[0], &.{patch_id}, .merge);
            defer application.deinit(patch_allocator);
            try std.testing.expectEqual(0, application.edits.count());
            try application.save(&snapshot, patch_allocator, paths[0], .clear);
            try std.testing.expectEqual(size_before, try cursor.db.core.length());
            const gaps_after = try snapshot.cursor.readPathSlot(void, &.{
                .{ .hash_map_get = .{ .value = path_hash } },
                .{ .array_list_get = @intFromEnum(patch.FileField.gaps) },
            });
            try std.testing.expectEqualDeep(gaps, gaps_after);
        }
    };
    const ctx = Ctx{
        .third_oid = third_oid,
        .case = case,
        .snapshot_oid = if (case == .later_edit) source_oid else target_oid,
        .patch_oid = if (case == .later_edit) target_oid else source_oid,
    };
    const before = try repo.core.latestMoment();
    try repo.core.db_file.lock(io, .exclusive);
    defer repo.core.db_file.unlock(io);
    const history = try DB.ArrayList(.read_write).init(repo.core.db.rootCursor());
    if (case == .rollback) {
        for ([_]@TypeOf(ctx.corruption){ .count, .gap, .placement, .text }) |corruption| {
            for ([_]bool{ false, true }) |create| {
                var corrupt_ctx = ctx;
                corrupt_ctx.corruption = corruption;
                corrupt_ctx.create = create;
                try std.testing.expectError(if (corruption == .gap) error.InvalidGapList else error.InvalidEdit, history.appendContext(.{ .slot = try history.getSlot(-1) }, corrupt_ctx));
                const after = try repo.core.latestMoment();
                try std.testing.expectEqualDeep(before.cursor.slot(), after.cursor.slot());
            }
        }
    } else {
        try history.appendContext(.{ .slot = try history.getSlot(-1) }, ctx);
    }
}

const EditMergeCase = struct {
    name: []const u8,
    base: []const u8 = "a\nb\nc\nd\ne",
    target: []const []const u8,
    source: []const []const u8,
    expected: []const union(enum) {
        text: []const u8,
        conflict: [3]?[]const u8,
    },
    shared_edits: ?usize = null,
    shared_gaps: bool = false,
    shared_gap_chunks: bool = false,
    max_position_depth: ?usize = null,
    pick: bool = false,
    rebuild: bool = false,
};

fn testMergeEdits(case: EditMergeCase) !void {
    const io = std.testing.io;
    const allocator = std.testing.allocator;
    const opts: rp.RepoOpts(.xit) = .{ .is_test = true };
    errdefer std.debug.print("merge edits: {s}\n", .{case.name});
    var temp = std.testing.tmpDir(.{});
    defer temp.cleanup();
    const temp_path = try temp.dir.realPathFileAlloc(io, ".", allocator);
    defer allocator.free(temp_path);

    // check both directions, including the order of conflict alternatives
    for ([_]bool{ false, true }) |reverse| {
        if (case.pick and reverse) continue;
        const work_path = try std.fs.path.join(allocator, &.{ temp_path, if (reverse) "reverse" else "forward" });
        defer allocator.free(work_path);
        var repo = try rp.Repo(.xit, opts).init(io, allocator, .{ .path = work_path });
        defer repo.deinit(io, allocator);
        try addFile(.xit, opts, &repo, io, allocator, "f", case.base);
        const base_oid = try repo.commit(io, allocator, .{ .message = "base", .timestamp = 1 });
        const names = [_][]const u8{ "target", "source" };
        var oids: [2][hash.hexLen(opts.hash)]u8 = undefined;
        for ([_][]const []const u8{ case.target, case.source }, 0..) |history, side| {
            var parent = base_oid;
            for (history, 0..) |content, i| {
                try addFile(.xit, opts, &repo, io, allocator, "f", content);
                parent = try repo.commit(io, allocator, .{ .message = "edit", .parent_oids = &.{parent}, .timestamp = 2 + side * 100 + i });
                // each generated snapshot must reproduce the committed text
                try repo.patchAll(io, allocator, null);
                var moment = try repo.core.latestMoment();
                const snapshot = (try moment.cursor.readPath(void, &.{
                    .{ .hash_map_get = .{ .value = hash.hashInt(opts.hash, "commit-id->snapshot") } },
                    .{ .hash_map_get = .{ .value = try hash.hexToInt(opts.hash, &parent) } },
                })).?;
                var file = try patch.File(opts).load(&moment, snapshot, allocator, hash.hashInt(opts.hash, "f"));
                defer file.deinit();
                const text = try file.readText(allocator);
                defer allocator.free(text);
                try std.testing.expectEqualStrings(content, text);
                try std.testing.expect(!file.has_conflict);
                if (case.shared_gap_chunks) {
                    var reader = patch.File(opts).TextReader.init(&file, allocator);
                    defer reader.deinit();
                    // a failed allocation must leave the line readable on retry.
                    var failing = std.testing.FailingAllocator.init(allocator, .{ .fail_index = 0 });
                    try std.testing.expectError(error.OutOfMemory, reader.readLine(file.lines.items[0].id, failing.allocator()));
                    for ([_]usize{ 0, 63, 64, 65, 127, 128, 129, 0 }) |line_index| {
                        const id = file.lines.items[line_index].id;
                        var expected_lines = std.mem.splitScalar(u8, content, '\n');
                        for (0..line_index) |_| _ = expected_lines.next();
                        const actual_line = try reader.readLine(id, allocator);
                        defer allocator.free(actual_line);
                        try std.testing.expectEqualStrings(expected_lines.next().?, actual_line);
                    }
                }
                if (case.max_position_depth) |depth| {
                    for (file.lines.items) |line| try std.testing.expect(line.position.len <= depth * (hash.byteLen(opts.hash) + 8));
                }
            }
            oids[side] = parent;
            try repo.addBranch(io, .{ .name = names[side] });
        }
        try repo.patchAll(io, allocator, null);
        if (case.rebuild) {
            const DB = rp.Repo(.xit, opts).DB;
            const before = try repo.core.latestMoment();
            const Rebuild = struct {
                pub fn run(_: @This(), cursor: *DB.Cursor(.read_write)) !void {
                    const moment = try DB.HashMap(.read_write).init(cursor.*);
                    _ = try moment.remove(hash.hashInt(opts.hash, "commit-id->snapshot"));
                }
            };
            const history = try DB.ArrayList(.read_write).init(repo.core.db.rootCursor());
            try history.appendContext(.{ .slot = try history.getSlot(-1) }, Rebuild{});
            try repo.patchAll(io, allocator, null);
            const after = try repo.core.latestMoment();
            for (oids) |oid| {
                for ([_]patch.FileField{ .patch, .gaps }) |field| {
                    var bytes: [2][]const u8 = .{ &.{}, &.{} };
                    defer for (bytes) |value| allocator.free(value);
                    for ([_]DB.HashMap(.read_only){ before, after }, &bytes) |moment, *value| {
                        const cursor = (try moment.cursor.readPath(void, &.{
                            .{ .hash_map_get = .{ .value = hash.hashInt(opts.hash, "commit-id->snapshot") } },
                            .{ .hash_map_get = .{ .value = try hash.hexToInt(opts.hash, &oid) } },
                            .{ .hash_map_get = .{ .value = hash.hashInt(opts.hash, "f") } },
                            .{ .array_list_get = @intFromEnum(field) },
                        })).?;
                        if (field == .gaps) {
                            var buffer = std.Io.Writer.Allocating.init(allocator);
                            defer buffer.deinit();
                            const list = try DB.LinkedArrayList(.read_only).init(cursor);
                            var iter = try list.iterator();
                            while (try iter.next()) |entry| {
                                const bytes_value = try entry.readBytesAlloc(allocator, null);
                                defer allocator.free(bytes_value);
                                try buffer.writer.writeAll(bytes_value);
                            }
                            value.* = try buffer.toOwnedSlice();
                        } else value.* = try cursor.readBytesAlloc(allocator, opts.max_read_size);
                    }
                    try std.testing.expectEqualSlices(u8, bytes[0], bytes[1]);
                }
            }
        }
        // compare the stored gaps and applied edits between branches
        if (case.shared_edits != null or case.shared_gaps or case.shared_gap_chunks) {
            const DB = rp.Repo(.xit, opts).DB;
            const moment = try repo.core.latestMoment();
            var files: [2]DB.ArrayList(.read_only) = undefined;
            for (oids, &files) |oid, *fields| {
                fields.* = try DB.ArrayList(.read_only).init((try moment.cursor.readPath(void, &.{
                    .{ .hash_map_get = .{ .value = hash.hashInt(opts.hash, "commit-id->snapshot") } },
                    .{ .hash_map_get = .{ .value = try hash.hexToInt(opts.hash, &oid) } },
                    .{ .hash_map_get = .{ .value = hash.hashInt(opts.hash, "f") } },
                })).?);
            }
            if (case.shared_gaps) try std.testing.expectEqualDeep(
                (try files[0].getSlot(@intFromEnum(patch.FileField.gaps))).?,
                (try files[1].getSlot(@intFromEnum(patch.FileField.gaps))).?,
            );
            if (case.shared_gap_chunks) {
                var slots = std.AutoHashMap(u64, void).init(allocator);
                defer slots.deinit();
                var lists: [2]DB.LinkedArrayList(.read_only) = undefined;
                for (files, &lists) |fields, *list| list.* = try DB.LinkedArrayList(.read_only).init((try fields.getCursor(@intFromEnum(patch.FileField.gaps))).?);
                var left = try lists[0].iterator();
                while (try left.next()) |entry| try slots.put(entry.slot().value, {});
                var shared: usize = 0;
                var right = try lists[1].iterator();
                while (try right.next()) |entry| {
                    if (slots.contains(entry.slot().value)) shared += 1;
                }
                try std.testing.expect(shared > 0);
                try std.testing.expect(shared < try lists[0].count());
            }
            if (case.shared_edits) |expected| {
                var edits: [2]DB.HashSet(.read_only) = undefined;
                for (files, &edits) |fields, *set| {
                    set.* = try DB.HashSet(.read_only).init((try fields.getCursor(@intFromEnum(patch.FileField.edits))).?);
                }
                var shared: usize = 0;
                var edit_iter = try edits[0].iterator();
                while (try edit_iter.next()) |entry| {
                    if (try edits[1].getSlot((try entry.readKeyValuePair()).hash) != null) shared += 1;
                }
                try std.testing.expectEqual(expected + 1, shared);
            }
        }
        const target = names[@intFromBool(reverse)];
        const source = names[@intFromBool(!reverse)];
        var switched = try repo.switchDir(io, allocator, .{ .target = .{ .ref = .{ .kind = .head, .name = target } } });
        defer switched.deinit();
        var merge = try repo.merge(io, allocator, .{ .kind = if (case.pick) .pick else .full, .action = .{ .new = .{ .algo = .patch, .source = &.{.{ .ref = .{ .kind = .head, .name = source } }} } } }, null);
        defer merge.deinit();
        var arena = std.heap.ArenaAllocator.init(allocator);
        defer arena.deinit();
        const a = arena.allocator();
        var expected: std.ArrayList([]const u8) = .empty;
        var conflict = false;
        for (case.expected) |chunk| switch (chunk) {
            .text => |content| try expected.append(a, content),
            .conflict => |sides| {
                conflict = true;
                try expected.append(a, try std.fmt.allocPrint(a, "<<<<<<< target ({s})", .{target}));
                if (sides[if (reverse) 2 else 1]) |content| try expected.append(a, content);
                try expected.append(a, try std.fmt.allocPrint(a, "||||||| base ({s})", .{merge.base_oid}));
                if (sides[0]) |content| try expected.append(a, content);
                try expected.append(a, "=======");
                if (sides[if (reverse) 1 else 2]) |content| try expected.append(a, content);
                try expected.append(a, try std.fmt.allocPrint(a, ">>>>>>> source ({s})", .{source}));
            },
        };
        try std.testing.expectEqual(conflict, merge.result == .conflict);
        const content = try repo.core.work_dir.readFileAlloc(io, "f", allocator, .limited(64 * 1024));
        defer allocator.free(content);
        try std.testing.expectEqualStrings(try std.mem.join(a, "\n", expected.items), content);
    }
}

test "merge conflict edits" {
    try testMergeEdits(.{ .name = "overlapping deletions", .target = &.{"a\nd\ne"}, .source = &.{"a\nb\ne"}, .expected = &.{.{ .text = "a\ne" }} });
    try testMergeEdits(.{ .name = "delete and replace", .target = &.{"a\nc\nd\ne"}, .source = &.{"a\nB\nc\nd\ne"}, .expected = &.{ .{ .text = "a" }, .{ .conflict = .{ "b", null, "B" } }, .{ .text = "c\nd\ne" } } });
    try testMergeEdits(.{ .name = "insert inside deletion", .target = &.{"a\ne"}, .source = &.{"a\nb\nX\nc\nd\ne"}, .expected = &.{ .{ .text = "a" }, .{ .conflict = .{ "b\nc\nd", null, "b\nX\nc\nd" } }, .{ .text = "e" } } });
    try testMergeEdits(.{ .name = "replace insertion inside deletion", .target = &.{"a\ne"}, .source = &.{ "a\nb\nX\nc\nd\ne", "a\nb\nY\nc\nd\ne" }, .expected = &.{ .{ .text = "a" }, .{ .conflict = .{ "b\nc\nd", null, "b\nY\nc\nd" } }, .{ .text = "e" } } });
    try testMergeEdits(.{ .name = "insert at deletion boundaries", .target = &.{"a\ne"}, .source = &.{"a\nX\nb\nc\nd\nY\ne"}, .expected = &.{.{ .text = "a\nX\nY\ne" }} });
    try testMergeEdits(.{ .name = "same gap after deletion", .max_position_depth = 3, .target = &.{ "a\ne", "a\nX\ne", "a\ne", "a\nX\ne" }, .source = &.{ "a\ne", "a\nX\ne", "a\ne", "a\nY\ne" }, .expected = &.{ .{ .text = "a" }, .{ .conflict = .{ null, "X", "Y" } }, .{ .text = "e" } } });
    try testMergeEdits(.{ .name = "same gap in nested replacement", .target = &.{ "a\nu\nv\nd\ne", "a\nx\ny\nv\nd\ne", "a\nx\nw\ny\nv\nd\ne" }, .source = &.{ "a\nu\nv\nd\ne", "a\nx\ny\nv\nd\ne", "a\nx\nz\ny\nv\nd\ne" }, .expected = &.{ .{ .text = "a\nx" }, .{ .conflict = .{ null, "w", "z" } }, .{ .text = "y\nv\nd\ne" } } });
    try testMergeEdits(.{ .name = "later replacement", .target = &.{ "a\nB\nc\nd\ne", "a\nBB\nc\nd\ne" }, .source = &.{"a\nc\nd\ne"}, .expected = &.{ .{ .text = "a" }, .{ .conflict = .{ "b", "BB", null } }, .{ .text = "c\nd\ne" } } });
    try testMergeEdits(.{ .name = "multiple regions", .target = &.{"a\nc\ne"}, .source = &.{"a\nB\nc\nD\ne"}, .expected = &.{ .{ .text = "a" }, .{ .conflict = .{ "b", null, "B" } }, .{ .text = "c" }, .{ .conflict = .{ "d", null, "D" } }, .{ .text = "e" } } });
    try testMergeEdits(.{ .name = "whole file deletion", .base = "b", .target = &.{""}, .source = &.{"B"}, .expected = &.{.{ .conflict = .{ "b", "", "B" } }} });
    try testMergeEdits(.{ .name = "trailing newline", .base = "a\nb\nc\n", .target = &.{"a\nc\n"}, .source = &.{"a\nB\nc\n"}, .expected = &.{ .{ .text = "a" }, .{ .conflict = .{ "b", null, "B" } }, .{ .text = "c\n" } } });
    try testMergeEdits(.{ .name = "missing cherry-pick dependency", .pick = true, .target = &.{"a\nb\nc\nd\nE"}, .source = &.{ "a\nb\nX\nc\nd\ne", "a\nb\nY\nc\nd\ne" }, .expected = &.{ .{ .text = "a\nb" }, .{ .conflict = .{ "X", null, "Y" } }, .{ .text = "c\nd\nE" } } });
    try testMergeEdits(.{ .name = "several competing edits", .target = &.{ "a\nB\nc\nd\ne", "a\nBB\nc\nd\ne" }, .source = &.{ "a\nC\nc\nd\ne", "a\nCC\nc\nd\ne", "a\nCCC\nc\nd\ne" }, .expected = &.{ .{ .text = "a" }, .{ .conflict = .{ "b", "BB", "CCC" } }, .{ .text = "c\nd\ne" } } });
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

    var temp = std.testing.tmpDir(.{});
    defer temp.cleanup();
    const temp_path = try temp.dir.realPathFileAlloc(io, ".", allocator);
    defer allocator.free(temp_path);

    const work_path = try std.fs.path.join(allocator, &.{ temp_path, "repo" });
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

    // create the temp dir
    var temp = std.testing.tmpDir(.{});
    defer temp.cleanup();
    const temp_path = try temp.dir.realPathFileAlloc(io, ".", allocator);
    defer allocator.free(temp_path);

    const work_path = try std.fs.path.join(allocator, &.{ temp_path, "repo" });
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

        const dest_work_path = try std.fs.path.join(allocator, &.{ temp_path, "dest_repo" });
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

    // create the temp dir
    var temp = std.testing.tmpDir(.{});
    defer temp.cleanup();
    const temp_path = try temp.dir.realPathFileAlloc(io, ".", allocator);
    defer allocator.free(temp_path);

    const work_path = try std.fs.path.join(allocator, &.{ temp_path, "repo" });
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

    // create the temp dir
    var temp = std.testing.tmpDir(.{});
    defer temp.cleanup();
    const temp_path = try temp.dir.realPathFileAlloc(io, ".", allocator);
    defer allocator.free(temp_path);

    const work_path = try std.fs.path.join(allocator, &.{ temp_path, "repo" });
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

    // create the temp dir
    var temp = std.testing.tmpDir(.{});
    defer temp.cleanup();
    const temp_path = try temp.dir.realPathFileAlloc(io, ".", allocator);
    defer allocator.free(temp_path);

    const work_path = try std.fs.path.join(allocator, &.{ temp_path, "repo" });
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

    // create the temp dir
    var temp = std.testing.tmpDir(.{});
    defer temp.cleanup();
    const temp_path = try temp.dir.realPathFileAlloc(io, ".", allocator);
    defer allocator.free(temp_path);

    const work_path = try std.fs.path.join(allocator, &.{ temp_path, "repo" });
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

    // create the temp dir
    var temp = std.testing.tmpDir(.{});
    defer temp.cleanup();
    const temp_path = try temp.dir.realPathFileAlloc(io, ".", allocator);
    defer allocator.free(temp_path);

    const work_path = try std.fs.path.join(allocator, &.{ temp_path, "repo" });
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

    // create the temp dir
    var temp = std.testing.tmpDir(.{});
    defer temp.cleanup();
    const temp_path = try temp.dir.realPathFileAlloc(io, ".", allocator);
    defer allocator.free(temp_path);

    const work_path = try std.fs.path.join(allocator, &.{ temp_path, "repo" });
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

    // create the temp dir
    var temp = std.testing.tmpDir(.{});
    defer temp.cleanup();
    const temp_path = try temp.dir.realPathFileAlloc(io, ".", allocator);
    defer allocator.free(temp_path);

    const work_path = try std.fs.path.join(allocator, &.{ temp_path, "repo" });
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

    // create the temp dir
    var temp = std.testing.tmpDir(.{});
    defer temp.cleanup();
    const temp_path = try temp.dir.realPathFileAlloc(io, ".", allocator);
    defer allocator.free(temp_path);

    const work_path = try std.fs.path.join(allocator, &.{ temp_path, "repo" });
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

    // create the temp dir
    var temp = std.testing.tmpDir(.{});
    defer temp.cleanup();
    const temp_path = try temp.dir.realPathFileAlloc(io, ".", allocator);
    defer allocator.free(temp_path);

    const work_path = try std.fs.path.join(allocator, &.{ temp_path, "repo" });
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

    // create the temp dir
    var temp = std.testing.tmpDir(.{});
    defer temp.cleanup();
    const temp_path = try temp.dir.realPathFileAlloc(io, ".", allocator);
    defer allocator.free(temp_path);

    const work_path = try std.fs.path.join(allocator, &.{ temp_path, "repo" });
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
                    const entry = try snapshot.readPath(void, &.{
                        .{ .hash_map_get = .{ .value = hash.hashInt(repo_opts.hash, "bin") } },
                    });
                    const missing = case == .initial_binary and side == 0 and i < 3;
                    try std.testing.expectEqual(!missing, entry != null);
                    if (parent_snapshot_maybe) |parent_snapshot| {
                        const parent_entry = try parent_snapshot.readPath(void, &.{
                            .{ .hash_map_get = .{ .value = hash.hashInt(repo_opts.hash, "bin") } },
                        });
                        try std.testing.expectEqualDeep(if (parent_entry) |e| e.slot() else null, if (entry) |e| e.slot() else null);
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

    // create the temp dir
    var temp = std.testing.tmpDir(.{});
    defer temp.cleanup();
    const temp_path = try temp.dir.realPathFileAlloc(io, ".", allocator);
    defer allocator.free(temp_path);

    // from https://pijul.org/manual/why_pijul.html
    {
        const work_path = try std.fs.path.join(allocator, &.{ temp_path, "simple" });
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
        const work_path = try std.fs.path.join(allocator, &.{ temp_path, "concrete" });
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

    // create the temp dir
    var temp = std.testing.tmpDir(.{});
    defer temp.cleanup();
    const temp_path = try temp.dir.realPathFileAlloc(io, ".", allocator);
    defer allocator.free(temp_path);

    const work_path = try std.fs.path.join(allocator, &.{ temp_path, "repo" });
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
    const message = "d\n\nmessage body\n";
    for ([_][]const u8{ "bob <bob@example.com> nope +0000", "bob <bob@example.com> 123", "bob <bob@example.com> 123 +00x0", "bob <bob@example.com> 123 +0000 extra" }) |identity| {
        try std.testing.expectError(error.InvalidCommitIdentity, repo.commit(io, allocator, .{ .message = message, .committer = identity }));
    }
    const commit_d = try repo.commit(io, allocator, .{ .message = message, .author = "alice <alice@example.com> 123 +0530 \t", .committer = "bob <bob@example.com> 456 -0700 \t", .timestamp = 456 });
    try addFile(repo_kind, repo_opts, &repo, io, allocator, "readme.md", "e");
    _ = try repo.commit(io, allocator, .{ .message = "e" });
    {
        var result = try repo.switchDir(io, allocator, .{ .target = .{ .ref = .{ .kind = .head, .name = "master" } } });
        defer result.deinit();
    }

    // count open files through io, including files created by the merge
    var files = struct {
        threaded: std.Io.Threaded,
        count: usize = 0,

        fn open(userdata: ?*anyopaque, dir: std.Io.Dir, path: []const u8, opts: std.Io.Dir.OpenFileOptions) std.Io.File.OpenError!std.Io.File {
            const file = try std.testing.io.vtable.dirOpenFile(userdata, dir, path, opts);
            const threaded: *std.Io.Threaded = @ptrCast(@alignCast(userdata.?));
            const self: *@This() = @fieldParentPtr("threaded", threaded);
            self.count += 1;
            return file;
        }

        fn create(userdata: ?*anyopaque, dir: std.Io.Dir, path: []const u8, opts: std.Io.Dir.CreateFileOptions) std.Io.File.OpenError!std.Io.File {
            const file = try std.testing.io.vtable.dirCreateFile(userdata, dir, path, opts);
            const threaded: *std.Io.Threaded = @ptrCast(@alignCast(userdata.?));
            const self: *@This() = @fieldParentPtr("threaded", threaded);
            self.count += 1;
            return file;
        }

        fn close(userdata: ?*anyopaque, handles: []const std.Io.File) void {
            const threaded: *std.Io.Threaded = @ptrCast(@alignCast(userdata.?));
            const self: *@This() = @fieldParentPtr("threaded", threaded);
            self.count -= handles.len;
            std.testing.io.vtable.fileClose(userdata, handles);
        }
    }{ .threaded = std.Io.Threaded.init(allocator, .{}) };
    defer files.threaded.deinit();
    var vtable = std.testing.io.vtable.*;
    vtable.dirOpenFile = @TypeOf(files).open;
    vtable.dirCreateFile = @TypeOf(files).create;
    vtable.fileClose = @TypeOf(files).close;
    const merge_io: std.Io = .{ .userdata = &files.threaded, .vtable = &vtable };
    {
        var merge = try repo.merge(merge_io, allocator, .{ .kind = .pick, .action = .{ .new = .{ .source = &.{.{ .oid = &commit_d }} } } }, null);
        defer merge.deinit();
        try std.testing.expect(.success == merge.result);
    }
    try std.testing.expectEqual(0, files.count);
    {
        var iter = try repo.log(io, allocator, .{});
        defer iter.deinit();
        const commit = (try iter.next(allocator)).?;
        defer commit.deinit();
        var actual: std.ArrayList(u8) = .empty;
        defer actual.deinit(allocator);
        try commit.readMessage(allocator, &actual, .limited(4096));
        try std.testing.expectEqualStrings(message, actual.items);
        try std.testing.expectEqualStrings("alice <alice@example.com> 123 +0530", commit.content.commit.metadata.author.?);
        try std.testing.expectEqualStrings("radar <radar@roark> 0 +0000", commit.content.commit.metadata.committer.?);
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
    try testCherryPickConflict(.git, .{ .is_test = true }, false);
    try testCherryPickConflict(.xit, .{ .is_test = true }, false);
    try testCherryPickConflict(.git, .{ .is_test = true }, true);
    try testCherryPickConflict(.xit, .{ .is_test = true }, true);
}

fn testCherryPickConflict(comptime repo_kind: rp.RepoKind, comptime repo_opts: rp.RepoOpts(repo_kind), allow_empty: bool) !void {
    const io = std.testing.io;
    const allocator = std.testing.allocator;

    // create the temp dir
    var temp = std.testing.tmpDir(.{});
    defer temp.cleanup();
    const temp_path = try temp.dir.realPathFileAlloc(io, ".", allocator);
    defer allocator.free(temp_path);

    const work_path = try std.fs.path.join(allocator, &.{ temp_path, "repo" });
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
    const message = "d\n\nmessage body\n";
    const commit_d = try repo.commit(io, allocator, .{ .message = message, .author = "alice <alice@example.com> \t", .committer = "bob <bob@example.com> \t", .timestamp = 456 });
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
    try std.testing.expectError(error.UnfinishedMergeInProgress, repo.merge(io, allocator, .{ .kind = .pick, .action = .{ .new = .{ .source = &.{.{ .oid = &([_]u8{0} ** hash.hexLen(repo_opts.hash)) }} } } }, null));
    try std.testing.expectError(error.CannotContinueMergeWithUnresolvedConflicts, repo.merge(io, allocator, .{ .kind = .pick, .action = .cont }, null));

    // a failed continuation must preserve the cherry-pick state
    try addFile(repo_kind, repo_opts, &repo, io, allocator, "readme.md", "b");
    try std.testing.expectError(error.EmptyCommit, repo.merge(io, allocator, .{ .kind = .pick, .action = .cont }, null));
    const pick_head = (try repo.readRef(io, .{ .kind = .none, .name = "CHERRY_PICK_HEAD" })).?;
    try std.testing.expectEqualStrings(&commit_d, &pick_head);
    {
        const actual = try repo.core.repo_dir.readFileAlloc(io, "MERGE_MSG", allocator, .limited(4096));
        defer allocator.free(actual);
        try std.testing.expectEqualStrings(message, actual);
    }
    if (!allow_empty) try addFile(repo_kind, repo_opts, &repo, io, allocator, "readme.md", "e");

    // can't continue with .kind = merge
    try std.testing.expectError(error.OtherMergeInProgress, repo.merge(io, allocator, .{ .kind = .full, .action = .cont }, null));

    // continue cherry-pick
    {
        var merge = try repo.merge(io, allocator, .{ .kind = .pick, .action = .cont, .commit_metadata = .{ .allow_empty = allow_empty } }, null);
        defer merge.deinit();
        try std.testing.expect(.success == merge.result);
    }
    try std.testing.expectEqual(null, try repo.readRef(io, .{ .kind = .none, .name = "CHERRY_PICK_HEAD" }));
    try std.testing.expectError(error.FileNotFound, repo.core.repo_dir.access(io, "MERGE_MSG", .{}));
    {
        var iter = try repo.log(io, allocator, .{});
        defer iter.deinit();
        const commit = (try iter.next(allocator)).?;
        defer commit.deinit();
        var actual: std.ArrayList(u8) = .empty;
        defer actual.deinit(allocator);
        try commit.readMessage(allocator, &actual, .limited(4096));
        try std.testing.expectEqualStrings(message, actual.items);
        try std.testing.expectEqualStrings("alice <alice@example.com> 456 +0000", commit.content.commit.metadata.author.?);
        try std.testing.expectEqualStrings("radar <radar@roark> 0 +0000", commit.content.commit.metadata.committer.?);
    }
}

test "log" {
    try testLog(.git, .{ .is_test = true });
    try testLog(.xit, .{ .is_test = true });
}

fn testLog(comptime repo_kind: rp.RepoKind, comptime repo_opts: rp.RepoOpts(repo_kind)) !void {
    const io = std.testing.io;
    const allocator = std.testing.allocator;

    // create the temp dir
    var temp = std.testing.tmpDir(.{});
    defer temp.cleanup();
    const temp_path = try temp.dir.realPathFileAlloc(io, ".", allocator);
    defer allocator.free(temp_path);

    const work_path = try std.fs.path.join(allocator, &.{ temp_path, "repo" });
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
    const repo_opts = rp.RepoOpts(.xit){ .is_test = true };

    // create the temp dir
    var temp = std.testing.tmpDir(.{});
    defer temp.cleanup();
    const temp_path = try temp.dir.realPathFileAlloc(io, ".", allocator);
    defer allocator.free(temp_path);

    const work_path = try std.fs.path.join(allocator, &.{ temp_path, "repo" });
    defer allocator.free(work_path);

    var repo = try rp.Repo(.xit, repo_opts).init(io, allocator, .{ .path = work_path });
    defer repo.deinit(io, allocator);

    // A unified repo has no separate chunks entry.
    {
        var xit_dir = try temp.dir.openDir(io, "repo/.xit", .{});
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
