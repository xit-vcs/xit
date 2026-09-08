//! tests for garbage collection (xit mode only)

const std = @import("std");
const rp = @import("../repo.zig");
const obj = @import("../object.zig");
const hash = @import("../hash.zig");

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
    const keep_commit = try repo.commit(io, allocator, .{ .message = "keep" });

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

    // an otherwise unreachable object survives while supplied as an extra root
    _ = try repo.garbageCollect(io, allocator, &.{side_commit});
    try std.testing.expectEqual(2, try repo.commitCount(io, allocator, .{ .oid = &side_commit }));
    {
        var moment = try repo.core.latestMoment();
        const state = rp.Repo(.xit, repo_opts).State(.read_only){ .core = &repo.core, .extra = .{ .moment = &moment } };
        var side_commit_object = try obj.Object(.xit, repo_opts).init(state, io, allocator, &side_commit);
        side_commit_object.deinit();
    }

    const result = try repo.garbageCollect(io, allocator, &.{});

    // the deleted branch's objects and chunks are gone, so the db shrank
    try std.testing.expect(result.size_after < result.size_before);

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

    // its derived depth entry was pruned with it, while the live commit's
    // entry remains available.
    {
        var moment = try repo.core.latestMoment();
        const depths_cursor = (try moment.getCursor(hash.hashInt(repo_opts.hash, obj.COMMIT_ID_TO_FIRST_PARENT_DEPTH_KEY))) orelse return error.CommitDepthNotFound;
        const depths = try rp.Repo(.xit, repo_opts).DB.HashMap(.read_only).init(depths_cursor);
        try std.testing.expectEqual(null, try depths.getCursor(try hash.hexToInt(repo_opts.hash, &side_commit)));
        try std.testing.expect((try depths.getCursor(try hash.hexToInt(repo_opts.hash, &keep_commit))) != null);
    }
    try std.testing.expectEqual(1, try repo.commitCount(io, allocator, .{ .oid = &keep_commit }));

    // committed content survived and reads back through the rewritten
    // chunk record positions
    {
        var work_dir = try temp.dir.openDir(io, "repo", .{});
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

        var work_dir = try temp.dir.openDir(io, "repo", .{});
        defer work_dir.close(io);

        try work_dir.deleteFile(io, "staged.bin");
        try repo.restore(io, allocator, "staged.bin");

        const actual = try work_dir.readFileAlloc(io, "staged.bin", allocator, .limited(staged_content.len * 2));
        defer allocator.free(actual);
        try std.testing.expectEqualSlices(u8, staged_content, actual);
    }

    // a second gc runs fine and everything still reads back
    {
        _ = try repo.garbageCollect(io, allocator, &.{});

        var work_dir = try temp.dir.openDir(io, "repo", .{});
        defer work_dir.close(io);

        try work_dir.deleteFile(io, "keep.bin");
        try repo.restore(io, allocator, "keep.bin");

        const actual = try work_dir.readFileAlloc(io, "keep.bin", allocator, .limited(keep_content.len * 2));
        defer allocator.free(actual);
        try std.testing.expectEqualSlices(u8, keep_content, actual);
    }
}

test "gc ignores a stale temporary db" {
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

    {
        var repo = try rp.Repo(.xit, repo_opts).init(io, allocator, .{ .path = work_path });
        defer repo.deinit(io, allocator);
        try addFile(.xit, repo_opts, &repo, io, allocator, "hello.md", "hello, world!");
        _ = try repo.commit(io, allocator, .{ .message = "hello" });
    }

    var xit_dir = try temp.dir.openDir(io, "repo/.xit", .{});
    defer xit_dir.close(io);

    // A crash before the rename can leave db.gc behind. Opening ignores it,
    // and the next collection truncates and replaces it.
    {
        const stale_file = try xit_dir.createFile(io, "db.gc", .{ .truncate = true });
        try stale_file.writeStreamingAll(io, "junk");
        stale_file.close(io);

        var repo = try rp.Repo(.xit, repo_opts).open(io, allocator, .{ .path = work_path });
        defer repo.deinit(io, allocator);
        _ = try repo.garbageCollect(io, allocator, &.{});

        const actual = try repo.core.work_dir.readFileAlloc(io, "hello.md", allocator, .limited(1024));
        defer allocator.free(actual);
        try std.testing.expectEqualStrings("hello, world!", actual);
    }
}

test "gc with patches" {
    const patch = @import("../patch.zig");
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

    // A --- B [master]
    //  \
    //   `-- C [foo]
    //    \
    //     `-- D [trash] (deleted before gc)
    const middle = "m\n" ** 128;
    try addFile(.xit, repo_opts, &repo, io, allocator, "f.txt", "a\nb\n" ++ middle ++ middle ++ "c\nd");
    _ = try repo.commit(io, allocator, .{ .message = "a" });
    try repo.addBranch(io, .{ .name = "foo" });
    try repo.addBranch(io, .{ .name = "trash" });

    // changing the line count replaces some gap chunks and shares the rest
    try addFile(.xit, repo_opts, &repo, io, allocator, "f.txt", "a\nb\n" ++ middle ++ middle ++ "e\nX\nd");
    const keep_oid = try repo.commit(io, allocator, .{ .message = "b" });

    {
        var result = try repo.switchDir(io, allocator, .{ .target = .{ .ref = .{ .kind = .head, .name = "foo" } } });
        defer result.deinit();
    }
    try addFile(.xit, repo_opts, &repo, io, allocator, "f.txt", "a\nf\n" ++ middle ++ middle ++ "c\nd");
    _ = try repo.commit(io, allocator, .{ .message = "c" });

    {
        var result = try repo.switchDir(io, allocator, .{ .target = .{ .ref = .{ .kind = .head, .name = "trash" } } });
        defer result.deinit();
    }
    try addFile(.xit, repo_opts, &repo, io, allocator, "trash.txt", "garbage");
    try addFile(.xit, repo_opts, &repo, io, allocator, "f.txt", "a\nb\n" ++ middle ++ middle ++ "c\ntrash");
    const trash_oid = try repo.commit(io, allocator, .{ .message = "d" });

    {
        var result = try repo.switchDir(io, allocator, .{ .target = .{ .ref = .{ .kind = .head, .name = "master" } } });
        defer result.deinit();
    }
    try repo.patchAll(io, allocator, null);
    try repo.removeBranch(io, .{ .name = "trash" });

    // keep the discarded branch through an extra root, then collect it.
    // its insertion and replacement records should both be removed.
    for ([_][]const [hash.hexLen(repo_opts.hash)]u8{ &.{trash_oid}, &.{} }, [_]usize{ 5, 3 }) |roots, expected| {
        const result = try repo.garbageCollect(io, allocator, roots);
        try std.testing.expect(result.size_after < result.size_before);
        const moment = try repo.core.latestMoment();
        for ([_][]const u8{ "patch-id->edit-list", "edit-id->edit" }) |name| {
            var iter = try (try moment.getCursor(hash.hashInt(repo_opts.hash, name))).?.iterator();
            var count: usize = 0;
            while (try iter.next()) |_| count += 1;
            try std.testing.expectEqual(expected, count);
        }
        const summaries = try rp.Repo(.xit, repo_opts).DB.HashMap(.read_only).init((try moment.getCursor(hash.hashInt(repo_opts.hash, patch.COMMIT_ID_TO_STATS_KEY))).?);
        try std.testing.expectEqual(roots.len > 0, try summaries.getCursor(try hash.hexToInt(repo_opts.hash, &trash_oid)) != null);
        try std.testing.expectEqualDeep(patch.CommitStats{ .lines_added = 1, .lines_changed = 1, .bytes_added = 2, .files_changed = 1 }, (try repo.commitStats(io, allocator, .{ .oid = &keep_oid })).?);
    }

    // create an insertion from the surviving gaps, then merge after gc
    try addFile(.xit, repo_opts, &repo, io, allocator, "f.txt", "a\nb\n" ++ middle ++ "Y\n" ++ middle ++ "e\nX\nd");
    _ = try repo.commit(io, allocator, .{ .message = "insert" });
    try repo.patchAll(io, allocator, null);
    {
        var merge = try repo.merge(io, allocator, .{ .kind = .full, .action = .{ .new = .{ .source = &.{.{ .ref = .{ .kind = .head, .name = "foo" } }} } } }, null);
        defer merge.deinit();
        try std.testing.expect(.success == merge.result);

        const f_txt_content = try repo.core.work_dir.readFileAlloc(io, "f.txt", allocator, .limited(1024));
        defer allocator.free(f_txt_content);
        try std.testing.expectEqualStrings("a\nf\n" ++ middle ++ "Y\n" ++ middle ++ "e\nX\nd", f_txt_content);
    }
}
