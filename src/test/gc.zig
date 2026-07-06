//! tests for garbage collection (xit mode only)

const std = @import("std");
const builtin = @import("builtin");
const rp = @import("../repo.zig");
const obj = @import("../object.zig");

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

test "gc" {
    const io = std.testing.io;
    const allocator = std.testing.allocator;
    const temp_dir_name = "temp-test-repo-gc";
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

    // make random content, so the chunks are unique between tests
    // and cannot be compressed
    const content = try allocator.alloc(u8, 300_000);
    defer allocator.free(content);
    var prng = std.Random.DefaultPrng.init(43);
    prng.random().bytes(content);
    const keep_content = content[0..100_000];
    const side_content = content[100_000..250_000];
    const staged_content = content[250_000..];

    // commit a file on master, and another on a branch that is then deleted,
    // making its objects unreachable
    try addFile(.xit, repo_opts, &repo, io, allocator, "keep.bin", keep_content);
    _ = try repo.commit(io, allocator, .{ .message = "keep" });

    try repo.addBranch(io, .{ .name = "side" });
    {
        var result = try repo.switchDir(io, allocator, .{ .target = .{ .ref = .{ .kind = .head, .name = "side" } } });
        defer result.deinit();
    }
    try addFile(.xit, repo_opts, &repo, io, allocator, "side.bin", side_content);
    const side_commit = try repo.commit(io, allocator, .{ .message = "side" });
    {
        var result = try repo.switchDir(io, allocator, .{ .target = .{ .ref = .{ .kind = .head, .name = "master" } } });
        defer result.deinit();
    }
    try repo.removeBranch(io, .{ .name = "side" });

    // stage a file without committing it. its blob is only reachable
    // through the index, so this verifies the index is a gc root.
    try addFile(.xit, repo_opts, &repo, io, allocator, "staged.bin", staged_content);

    const result = try repo.garbageCollect(io, allocator);

    // the deleted branch's objects are gone, so both files shrank
    try std.testing.expect(result.db_size_after < result.db_size_before);
    try std.testing.expect(result.chunk_store_size_after < result.chunk_store_size_before);

    // the deleted branch's commit can no longer be loaded
    {
        var moment = try repo.core.latestMoment();
        const state = rp.Repo(.xit, repo_opts).State(.read_only){ .core = &repo.core, .extra = .{ .moment = &moment } };
        if (obj.Object(.xit, repo_opts).init(state, io, allocator, &side_commit)) |object| {
            var side_commit_object = object;
            side_commit_object.deinit();
            return error.ObjectNotExpected;
        } else |err| switch (err) {
            error.ObjectNotFound => {},
            else => |e| return e,
        }
    }

    // committed content survived and reads back through the rewritten
    // chunk info offsets
    {
        var work_dir = try temp_dir.openDir(io, "repo", .{});
        defer work_dir.close(io);

        try work_dir.deleteFile(io, "keep.bin");
        try repo.restore(io, allocator, "keep.bin");

        const actual = try work_dir.readFileAlloc(io, "keep.bin", allocator, .limited(keep_content.len * 2));
        defer allocator.free(actual);
        try std.testing.expectEqualSlices(u8, keep_content, actual);
    }

    // the write path still works on the adopted dbs: the staged blob
    // survived gc (via the index root) and can be committed and restored
    {
        _ = try repo.commit(io, allocator, .{ .message = "staged" });

        var work_dir = try temp_dir.openDir(io, "repo", .{});
        defer work_dir.close(io);

        try work_dir.deleteFile(io, "staged.bin");
        try repo.restore(io, allocator, "staged.bin");

        const actual = try work_dir.readFileAlloc(io, "staged.bin", allocator, .limited(staged_content.len * 2));
        defer allocator.free(actual);
        try std.testing.expectEqualSlices(u8, staged_content, actual);
    }

    // a second gc runs fine and everything still reads back
    {
        _ = try repo.garbageCollect(io, allocator);

        var work_dir = try temp_dir.openDir(io, "repo", .{});
        defer work_dir.close(io);

        try work_dir.deleteFile(io, "keep.bin");
        try repo.restore(io, allocator, "keep.bin");

        const actual = try work_dir.readFileAlloc(io, "keep.bin", allocator, .limited(keep_content.len * 2));
        defer allocator.free(actual);
        try std.testing.expectEqualSlices(u8, keep_content, actual);
    }
}

test "gc crash recovery" {
    const io = std.testing.io;
    const allocator = std.testing.allocator;
    const temp_dir_name = "temp-test-repo-gc-crash-recovery";
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

    {
        var repo = try rp.Repo(.xit, repo_opts).init(io, allocator, .{ .path = work_path });
        defer repo.deinit(io, allocator);
        try addFile(.xit, repo_opts, &repo, io, allocator, "hello.md", "hello, world!");
        _ = try repo.commit(io, allocator, .{ .message = "hello" });
    }

    var xit_dir = try temp_dir.openDir(io, "repo/.xit", .{});
    defer xit_dir.close(io);

    // simulate a gc that crashed after creating the marker but before
    // performing either rename: opening the repo must complete the swap
    {
        try xit_dir.rename("db", xit_dir, "db.gc", io);
        try xit_dir.rename("chunks", xit_dir, "chunks.gc", io);
        const marker_file = try xit_dir.createFile(io, "gc-pending", .{ .truncate = true });
        marker_file.close(io);

        var repo = try rp.Repo(.xit, repo_opts).open(io, allocator, .{ .path = work_path });
        defer repo.deinit(io, allocator);

        const actual = try repo.core.work_dir.readFileAlloc(io, "hello.md", allocator, .limited(1024));
        defer allocator.free(actual);
        try std.testing.expectEqualStrings("hello, world!", actual);
    }

    // simulate a crash between the two renames (the chunk store was
    // already renamed, the db wasn't)
    {
        try xit_dir.rename("db", xit_dir, "db.gc", io);
        const marker_file = try xit_dir.createFile(io, "gc-pending", .{ .truncate = true });
        marker_file.close(io);

        var repo = try rp.Repo(.xit, repo_opts).open(io, allocator, .{ .path = work_path });
        defer repo.deinit(io, allocator);

        const actual = try repo.core.work_dir.readFileAlloc(io, "hello.md", allocator, .limited(1024));
        defer allocator.free(actual);
        try std.testing.expectEqualStrings("hello, world!", actual);
    }

    // recovery removed the marker and the temp files
    for (&[_][]const u8{ "gc-pending", "db.gc", "chunks.gc" }) |name| {
        if (xit_dir.openFile(io, name, .{ .mode = .read_only })) |file| {
            file.close(io);
            return error.FileNotExpected;
        } else |err| switch (err) {
            error.FileNotFound => {},
            else => |e| return e,
        }
    }

    // stale temp files from a gc that crashed *before* creating the
    // marker are ignored on open and overwritten by the next gc
    {
        for (&[_][]const u8{ "db.gc0", "db.gc", "chunks.gc" }) |name| {
            const stale_file = try xit_dir.createFile(io, name, .{ .truncate = true });
            defer stale_file.close(io);
            try stale_file.writeStreamingAll(io, "junk");
        }

        var repo = try rp.Repo(.xit, repo_opts).open(io, allocator, .{ .path = work_path });
        defer repo.deinit(io, allocator);
        _ = try repo.garbageCollect(io, allocator);

        const actual = try repo.core.work_dir.readFileAlloc(io, "hello.md", allocator, .limited(1024));
        defer allocator.free(actual);
        try std.testing.expectEqualStrings("hello, world!", actual);
    }
}

test "gc shared chunk store not supported" {
    if (.windows == builtin.os.tag) return error.SkipZigTest; // creating symlinks requires priveleges on windows

    const io = std.testing.io;
    const allocator = std.testing.allocator;
    const temp_dir_name = "temp-test-repo-gc-shared";
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

    const work_path1 = try std.fs.path.join(allocator, &.{ cwd_path, temp_dir_name, "repo1" });
    defer allocator.free(work_path1);
    const work_path2 = try std.fs.path.join(allocator, &.{ cwd_path, temp_dir_name, "repo2" });
    defer allocator.free(work_path2);

    var repo1 = try rp.Repo(.xit, repo_opts).init(io, allocator, .{ .path = work_path1 });
    defer repo1.deinit(io, allocator);

    {
        var repo2 = try rp.Repo(.xit, repo_opts).init(io, allocator, .{ .path = work_path2 });
        repo2.deinit(io, allocator);
    }

    // point repo2's chunk store at repo1's
    {
        var repo2_xit_dir = try temp_dir.openDir(io, "repo2/.xit", .{});
        defer repo2_xit_dir.close(io);
        try repo2_xit_dir.deleteFile(io, "chunks");
        const store_path = try std.fs.path.join(allocator, &.{ work_path1, ".xit", "chunks" });
        defer allocator.free(store_path);
        try repo2_xit_dir.symLink(io, store_path, "chunks", .{});
    }

    var repo2 = try rp.Repo(.xit, repo_opts).open(io, allocator, .{ .path = work_path2 });
    defer repo2.deinit(io, allocator);

    try addFile(.xit, repo_opts, &repo2, io, allocator, "hello.md", "hello, world!");
    _ = try repo2.commit(io, allocator, .{ .message = "hello" });

    // a shared store contains chunks referenced by other repos, so
    // gc must refuse to run
    try std.testing.expectError(error.SharedChunkStoreNotSupported, repo2.garbageCollect(io, allocator));
}

test "gc with patches" {
    const io = std.testing.io;
    const allocator = std.testing.allocator;
    const temp_dir_name = "temp-test-repo-gc-patches";
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

    // A --- B [master]
    //  \
    //   `-- C [foo]
    //    \
    //     `-- D [trash] (deleted before gc)
    try addFile(.xit, repo_opts, &repo, io, allocator, "f.txt",
        \\a
        \\b
        \\c
        \\d
    );
    _ = try repo.commit(io, allocator, .{ .message = "a" });
    try repo.addBranch(io, .{ .name = "foo" });
    try repo.addBranch(io, .{ .name = "trash" });

    try addFile(.xit, repo_opts, &repo, io, allocator, "f.txt",
        \\a
        \\b
        \\e
        \\d
    );
    _ = try repo.commit(io, allocator, .{ .message = "b" });

    {
        var result = try repo.switchDir(io, allocator, .{ .target = .{ .ref = .{ .kind = .head, .name = "foo" } } });
        defer result.deinit();
    }
    try addFile(.xit, repo_opts, &repo, io, allocator, "f.txt",
        \\a
        \\f
        \\c
        \\d
    );
    _ = try repo.commit(io, allocator, .{ .message = "c" });

    {
        var result = try repo.switchDir(io, allocator, .{ .target = .{ .ref = .{ .kind = .head, .name = "trash" } } });
        defer result.deinit();
    }
    try addFile(.xit, repo_opts, &repo, io, allocator, "trash.txt", "garbage");
    _ = try repo.commit(io, allocator, .{ .message = "d" });

    {
        var result = try repo.switchDir(io, allocator, .{ .target = .{ .ref = .{ .kind = .head, .name = "master" } } });
        defer result.deinit();
    }
    try repo.removeBranch(io, .{ .name = "trash" });

    // create patches for all commits, then gc. the dead commit's patch
    // snapshot is removed, and the live ones must stay usable.
    try repo.patchAll(io, allocator, null);
    const result = try repo.garbageCollect(io, allocator);
    try std.testing.expect(result.db_size_after < result.db_size_before);

    // patch-based merging still works after gc
    {
        var merge = try repo.merge(io, allocator, .{ .kind = .full, .action = .{ .new = .{ .source = &.{.{ .ref = .{ .kind = .head, .name = "foo" } }} } } }, null);
        defer merge.deinit();
        try std.testing.expect(.success == merge.result);

        const f_txt_content = try repo.core.work_dir.readFileAlloc(io, "f.txt", allocator, .limited(1024));
        defer allocator.free(f_txt_content);
        try std.testing.expectEqualStrings(
            \\a
            \\f
            \\e
            \\d
        , f_txt_content);
    }
}
