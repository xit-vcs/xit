//! tests that create repos via the Repo struct.
//! runs with both git and xit modes.

const std = @import("std");
const xit = @import("xit");
const hash = xit.hash;
const rp = xit.repo;
const rf = xit.ref;
const obj = xit.object;
const mrg = xit.merge;
const df = xit.diff;
const ui = xit.ui;

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

    {
        var root = try ui.rootWidget(repo_kind, repo_opts, &repo, io, allocator, .log);
        defer root.deinit();

        const grid = try root.getGrid().?.toString(allocator);
        defer allocator.free(grid);

        var grid_without_tabs = grid;
        for (0..3) |_| {
            grid_without_tabs = grid_without_tabs[std.mem.indexOfScalar(u8, grid_without_tabs, '\n').? + 1 ..];
        }

        try std.testing.expectEqualStrings(
            \\┌─┐                           ┌──────────────────────────────────────────────────────────┐
            \\│c│                           │                                                          │
            \\└─┘                           │ diff --git a/README.md b/README.md                       │
            \\                              │ deleted file mode 100644                                 │
            \\ b                            │ index 6b49ab7..0000000                                   │
            \\                              │ --- a/README.md                                          │
            \\                              │ +++ /dev/null                                            │
            \\ a                            │                                                          │
            \\                              │                                                          │
            \\                              │                                                          │
            \\                              │ @@ -0,1 +0,0 @@                                          │
            \\                              │ - Goodbye, world!                                        │
            \\                              │                                                          │
            \\                              │                                                          │
            \\                              └──────────────────────────────────────────────────────────┘
        , grid_without_tabs);
    }

    // can't add path that is outside repo
    try std.testing.expectError(error.PathIsOutsideRepo, repo.add(io, allocator, &.{"../README.md"}));

    // commits that haven't changed content are an error
    try std.testing.expectError(error.EmptyCommit, repo.commit(io, allocator, .{ .message = "d" }));

    // put oids in a set
    var oid_set = std.StringArrayHashMap(void).init(allocator);
    defer oid_set.deinit();
    try oid_set.put(&commit_a, {});
    try oid_set.put(&commit_b, {});
    try oid_set.put(&commit_c, {});

    // assert that all commits have been found in the log
    {
        var commit_iter = try repo.log(io, allocator, null);
        defer commit_iter.deinit();
        while (try commit_iter.next()) |commit_object| {
            defer commit_object.deinit();
            _ = oid_set.swapRemove(&commit_object.oid);
        }
        try std.testing.expectEqual(0, oid_set.count());
    }

    {
        var result = try repo.resetDir(io, allocator, .{ .target = .{ .oid = &commit_b } });
        defer result.deinit();
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

    _ = try repo.addTag(io, allocator, .{ .name = "1.0.0", .message = "hi" });

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

test "merge" {
    try testMerge(.git, .{ .is_test = true });
    try testMerge(.xit, .{ .is_test = true });
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
    _ = try repo.commit(io, allocator, .{ .message = "a" });
    try addFile(repo_kind, repo_opts, &repo, io, allocator, "master.md", "b");
    _ = try repo.commit(io, allocator, .{ .message = "b" });
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
    _ = try repo.commit(io, allocator, .{ .message = "c" });
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
        var obj_iter = try obj.ObjectIterator(repo_kind, repo_opts, .raw).init(state, io, allocator, .{ .kind = .all });
        defer obj_iter.deinit();
        try obj_iter.include(&commit_k);

        const dest_work_path = try std.fs.path.join(allocator, &.{ cwd_path, temp_dir_name, "dest_repo" });
        defer allocator.free(dest_work_path);

        var dest_repo = try rp.Repo(repo_kind, repo_opts).init(io, allocator, .{ .path = dest_work_path });
        defer dest_repo.deinit(io, allocator);
        try dest_repo.copyObjects(repo_kind, repo_opts, &obj_iter, io, null);

        var dest_obj_iter = try dest_repo.log(io, allocator, &.{commit_k});
        defer dest_obj_iter.deinit();
        const dest_commit_k = (try dest_obj_iter.next()) orelse return error.ExpectedObject;
        defer dest_commit_k.deinit();
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
        defer root.deinit();

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
        defer root.deinit();

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
        defer root.deinit();

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
        defer root.deinit();

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
        defer root.deinit();

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
        defer root.deinit();

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
        defer root.deinit();

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
        defer root.deinit();

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
        defer root.deinit();

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

        try ui.input(repo_kind, repo_opts, &root, .arrow_down);
        try ui.input(repo_kind, repo_opts, &root, .arrow_right);

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

        try ui.input(repo_kind, repo_opts, &root, .arrow_right);

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
        defer root.deinit();

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

        try ui.input(repo_kind, repo_opts, &root, .arrow_down);
        try ui.input(repo_kind, repo_opts, &root, .arrow_right);

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
    try testMergeConflictBinary(.git, .{ .is_test = true });
    try testMergeConflictBinary(.xit, .{ .is_test = true });
}

/// creates a merge conflict with binary files, asserting that
/// it will not attempt to insert conflict markers or auto-resolve.
pub fn testMergeConflictBinary(comptime repo_kind: rp.RepoKind, comptime repo_opts: rp.RepoOpts(repo_kind)) !void {
    const io = std.testing.io;
    const allocator = std.testing.allocator;
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
        var merge = try repo.merge(io, allocator, .{ .kind = .full, .action = .{ .new = .{ .source = &.{.{ .ref = .{ .kind = .head, .name = "foo" } }} } } }, null);
        defer merge.deinit();
        try std.testing.expect(.conflict == merge.result);
    }

    {
        var root = try ui.rootWidget(repo_kind, repo_opts, &repo, io, allocator, .status);
        defer root.deinit();

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
    var oid_set = std.StringArrayHashMap(void).init(allocator);
    defer oid_set.deinit();
    try oid_set.put(&commit_a, {});
    try oid_set.put(&commit_b, {});
    try oid_set.put(&commit_c, {});
    try oid_set.put(&commit_d, {});
    try oid_set.put(&commit_e, {});
    try oid_set.put(&commit_f, {});
    try oid_set.put(&commit_g, {});
    try oid_set.put(&commit_h, {});

    // assert that all commits have been found in the log
    // and they aren't repeated
    {
        var commit_iter = try repo.log(io, allocator, null);
        defer commit_iter.deinit();
        while (try commit_iter.next()) |commit_object| {
            defer commit_object.deinit();
            try std.testing.expect(oid_set.contains(&commit_object.oid));
            _ = oid_set.swapRemove(&commit_object.oid);
        }
        try std.testing.expectEqual(0, oid_set.count());
    }

    try oid_set.put(&commit_c, {});
    try oid_set.put(&commit_d, {});
    try oid_set.put(&commit_e, {});
    try oid_set.put(&commit_f, {});
    try oid_set.put(&commit_g, {});

    // assert that only some commits have been found in the log
    // and they aren't repeated
    {
        var commit_iter = try repo.log(io, allocator, &.{commit_g});
        defer commit_iter.deinit();
        try commit_iter.exclude(&commit_b);
        while (try commit_iter.next()) |commit_object| {
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
        var obj_iter = try obj.ObjectIterator(repo_kind, repo_opts, .full).init(state, io, allocator, .{ .kind = .all });
        defer obj_iter.deinit();
        try obj_iter.include(&commit_g);
        while (try obj_iter.next()) |object| {
            defer object.deinit();
            count += 1;
        }
        try std.testing.expectEqual(20, count);
    }
}
