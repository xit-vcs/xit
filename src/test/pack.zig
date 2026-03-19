const std = @import("std");
const xit = @import("xit");
const hash = xit.hash;
const rp = xit.repo;
const obj = xit.object;
const pack = xit.pack;
const rf = xit.ref;

test "pack" {
    const allocator = std.testing.allocator;
    const temp_dir_name = "temp-test-pack";
    const repo_opts = rp.RepoOpts(.git){ .is_test = true };

    // create the temp dir
    const cwd = std.fs.cwd();
    var temp_dir_or_err = cwd.openDir(temp_dir_name, .{});
    if (temp_dir_or_err) |*temp_dir| {
        temp_dir.close();
        try cwd.deleteTree(temp_dir_name);
    } else |_| {}
    var temp_dir = try cwd.makeOpenPath(temp_dir_name, .{});
    defer cwd.deleteTree(temp_dir_name) catch {};
    defer temp_dir.close();

    // get the cwd path
    const cwd_path = try std.process.getCwdAlloc(allocator);
    defer allocator.free(cwd_path);

    // get work dir path
    const work_path = try std.fs.path.join(allocator, &.{ cwd_path, temp_dir_name, "repo" });
    defer allocator.free(work_path);

    // init repo
    var repo = try rp.Repo(.git, repo_opts).init(allocator, .{ .path = work_path });
    defer repo.deinit(allocator);

    // make sure the git dir was created
    var repo_dir = try repo.core.work_dir.openDir(".git", .{});
    defer repo_dir.close();

    // add and commit
    var commit_oid1: [hash.hexLen(repo_opts.hash)]u8 = undefined;
    {
        // make file
        var hello_txt = try repo.core.work_dir.createFile("hello.txt", .{});
        defer hello_txt.close();
        try hello_txt.writeAll("hello, world!");

        // make file
        var readme = try repo.core.work_dir.createFile("README", .{});
        defer readme.close();
        try readme.writeAll("My cool project");

        // add the files
        try repo.add(allocator, &.{ "hello.txt", "README" });

        // make the commit
        commit_oid1 = try repo.commit(allocator, .{ .message = "let there be light" });
    }

    // add and commit
    var commit_oid2: [hash.hexLen(repo_opts.hash)]u8 = undefined;
    {
        // make files
        var license = try repo.core.work_dir.createFile("LICENSE", .{});
        defer license.close();
        try license.writeAll("do whatever you want");
        var change_log = try repo.core.work_dir.createFile("CHANGELOG", .{});
        defer change_log.close();
        try change_log.writeAll("cha-cha-cha-changes");

        // change file
        const hello_txt = try repo.core.work_dir.openFile("hello.txt", .{ .mode = .read_write });
        defer hello_txt.close();
        try hello_txt.writeAll("goodbye, world!");
        try hello_txt.setEndPos(try hello_txt.getPos());

        // add the files
        try repo.add(allocator, &.{ "LICENSE", "CHANGELOG", "hello.txt" });

        // make the commit
        commit_oid2 = try repo.commit(allocator, .{ .message = "add license" });
    }

    // write and read a pack object
    {
        var r = try rp.Repo(.git, repo_opts).open(allocator, .{ .path = work_path });
        defer r.deinit(allocator);

        const head_oid = try rf.readHeadRecur(.git, repo_opts, .{ .core = &r.core, .extra = .{} });

        var obj_iter = try obj.ObjectIterator(.git, repo_opts, .raw).init(allocator, .{ .core = &r.core, .extra = .{} }, .{ .kind = .all });
        defer obj_iter.deinit();
        try obj_iter.include(&head_oid);

        var pack_writer = try pack.PackObjectWriter(.git, repo_opts).init(allocator, &obj_iter) orelse return error.PackWriterIsEmpty;
        defer pack_writer.deinit();

        var pack_file = try temp_dir.createFile("test.pack", .{});
        defer pack_file.close();

        var buffer = [_]u8{0} ** 1;
        while (true) {
            const size = try pack_writer.read(&buffer);
            try pack_file.writeAll(buffer[0..size]);
            if (size < buffer.len) {
                break;
            }
        }

        for (&[_]*const [hash.hexLen(repo_opts.hash)]u8{ &commit_oid1, &commit_oid2 }) |commit_oid_hex| {
            var pack_reader = try pack.PackObjectReader(.git, repo_opts).initWithPath(allocator, .{ .core = &r.core, .extra = .{} }, temp_dir, "test.pack", commit_oid_hex);
            defer pack_reader.deinit(allocator);

            // make sure the reader's position is at the beginning
            try std.testing.expectEqual(0, pack_reader.relative_position);
        }
    }

    // read packed refs
    {
        var r = try rp.Repo(.git, repo_opts).open(allocator, .{ .path = work_path });
        defer r.deinit(allocator);

        var packed_refs = try repo_dir.createFile("packed-refs", .{});
        defer packed_refs.close();
        try packed_refs.writeAll(
            \\# pack-refs with: peeled fully-peeled sorted
            \\5246e54744f4e1824ca280e6a2630a87959d7cf4 refs/remotes/origin/master
            \\1ea47a890400815b24a0073f110a41530322a44f refs/remotes/sync/chunk
            \\5246e54744f4e1824ca280e6a2630a87959d7cf4 refs/remotes/sync/master
            \\1f6190c71bd33b37cfd885491889a0410f849f5b refs/remotes/sync/zig-0.14.0
        );

        const oid_maybe = try r.readRef(.{ .kind = .{ .remote = "sync" }, .name = "master" });
        try std.testing.expectEqualStrings("5246e54744f4e1824ca280e6a2630a87959d7cf4", &oid_maybe.?);

        try std.testing.expect(null == try r.readRef(.{ .kind = .{ .remote = "sync" }, .name = "foo" }));
    }
}
