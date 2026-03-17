const std = @import("std");
const xit = @import("xit");
const hash = xit.hash;
const rp = xit.repo;
const obj = xit.object;
const pack = xit.pack;
const rf = xit.ref;

test "create and read pack" {
    const io = std.testing.io;
    const allocator = std.testing.allocator;
    const temp_dir_name = "temp-test-create-and-read-pack";
    const repo_opts = rp.RepoOpts(.git){ .is_test = true };

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

    // get the cwd path
    const cwd_path = try std.process.currentPathAlloc(io, allocator);
    defer allocator.free(cwd_path);

    // get work dir path
    const work_path = try std.fs.path.join(allocator, &.{ cwd_path, temp_dir_name, "repo" });
    defer allocator.free(work_path);

    // create the work dir
    var work_dir = try cwd.createDirPathOpen(io, work_path, .{});
    defer work_dir.close(io);

    // init repo
    var repo = try rp.Repo(.git, repo_opts).init(io, allocator, .{ .path = work_path });
    defer repo.deinit(io, allocator);

    // make sure the git dir was created
    var repo_dir = try work_dir.openDir(io, ".git", .{});
    defer repo_dir.close(io);

    // add and commit
    var commit_oid1: [hash.hexLen(repo_opts.hash)]u8 = undefined;
    {
        // make file
        var hello_txt = try work_dir.createFile(io, "hello.txt", .{});
        defer hello_txt.close(io);
        try hello_txt.writeStreamingAll(io, "hello, world!");

        // make file
        var readme = try work_dir.createFile(io, "README", .{});
        defer readme.close(io);
        try readme.writeStreamingAll(io, "My cool project");

        // add the files
        try repo.add(io, allocator, &.{ "hello.txt", "README" });

        // make the commit
        commit_oid1 = try repo.commit(io, allocator, .{ .message = "let there be light" });
    }

    // add and commit
    var commit_oid2: [hash.hexLen(repo_opts.hash)]u8 = undefined;
    {
        // make files
        var license = try work_dir.createFile(io, "LICENSE", .{});
        defer license.close(io);
        try license.writeStreamingAll(io, "do whatever you want");
        var change_log = try work_dir.createFile(io, "CHANGELOG", .{});
        defer change_log.close(io);
        try change_log.writeStreamingAll(io, "cha-cha-cha-changes");

        // change file
        const hello_txt = try work_dir.openFile(io, "hello.txt", .{ .mode = .read_write });
        defer hello_txt.close(io);
        try hello_txt.setLength(io, 0);
        try hello_txt.writeStreamingAll(io, "goodbye, world!");

        // add the files
        try repo.add(io, allocator, &.{ "LICENSE", "CHANGELOG", "hello.txt" });

        // make the commit
        commit_oid2 = try repo.commit(io, allocator, .{ .message = "add license" });
    }

    // write and read a pack object
    {
        var r = try rp.Repo(.git, repo_opts).open(io, allocator, .{ .path = work_path });
        defer r.deinit(io, allocator);

        const head_oid = try rf.readHeadRecur(.git, repo_opts, .{ .core = &r.core, .extra = .{} }, io);

        var obj_iter = try obj.ObjectIterator(.git, repo_opts, .raw).init(.{ .core = &r.core, .extra = .{} }, io, allocator, .{ .kind = .all });
        defer obj_iter.deinit();
        try obj_iter.include(&head_oid);

        var pack_writer = try pack.PackWriter(.git, repo_opts).init(allocator, &obj_iter) orelse return error.PackWriterIsEmpty;
        defer pack_writer.deinit();

        var pack_file = try temp_dir.createFile(io, "test.pack", .{});
        defer pack_file.close(io);

        var buffer = [_]u8{0} ** 1;
        while (true) {
            const size = try pack_writer.read(&buffer);
            try pack_file.writeStreamingAll(io, buffer[0..size]);
            if (size < buffer.len) {
                break;
            }
        }

        for (&[_]*const [hash.hexLen(repo_opts.hash)]u8{ &commit_oid1, &commit_oid2 }) |commit_oid_hex| {
            var pack_reader = try pack.PackReader.initFile(io, allocator, temp_dir, "test.pack");
            defer pack_reader.deinit();

            var pack_obj_rdr = try pack.PackObjectReader(.git, repo_opts).initWithoutIndex(io, allocator, .{ .core = &r.core, .extra = .{} }, &pack_reader, commit_oid_hex);
            defer pack_obj_rdr.deinit(io, allocator);

            // make sure the reader's position is at the beginning
            try std.testing.expectEqual(0, pack_obj_rdr.relative_position);
        }
    }
}

test "write pack file" {
    const io = std.testing.io;
    const allocator = std.testing.allocator;
    const temp_dir_name = "temp-test-write-pack-file";
    const repo_opts = rp.RepoOpts(.git){ .is_test = true };

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

    // get the cwd path
    const cwd_path = try std.process.currentPathAlloc(io, allocator);
    defer allocator.free(cwd_path);

    const client_path = try std.fs.path.join(allocator, &.{ cwd_path, temp_dir_name, "client" });
    defer allocator.free(client_path);

    var client_repo = try rp.Repo(.git, repo_opts).init(io, allocator, .{ .path = client_path });
    defer client_repo.deinit(io, allocator);

    var client_dir = try cwd.openDir(io, client_path, .{});
    defer client_dir.close(io);

    // copy files from current repo into client dir
    for (&[_][]const u8{ "src", "docs" }) |dir_name| {
        var src_repo_dir = try cwd.openDir(io, dir_name, .{ .iterate = true });
        defer src_repo_dir.close(io);

        var dest_repo_dir = try client_dir.createDirPathOpen(io, dir_name, .{});
        defer dest_repo_dir.close(io);

        try copyDir(io, src_repo_dir, dest_repo_dir);

        try client_repo.add(io, allocator, &.{dir_name});
    }

    _ = try client_repo.commit(io, allocator, .{ .message = "let there be light" });

    // change the files so git will send them as delta objects
    for (&[_][]const u8{ "src", "docs" }) |dir_name| {
        var dest_repo_dir = try client_dir.createDirPathOpen(io, dir_name, .{ .open_options = .{ .iterate = true } });
        defer dest_repo_dir.close(io);

        {
            var iter = dest_repo_dir.iterate();
            while (try iter.next(io)) |entry| {
                switch (entry.kind) {
                    .file => {
                        const file = try dest_repo_dir.openFile(io, entry.name, .{ .mode = .read_write });
                        defer file.close(io);
                        var writer = file.writer(io, &.{});
                        try writer.interface.writeAll("EDIT");
                    },
                    else => {},
                }
            }
        }

        try client_repo.add(io, allocator, &.{dir_name});
    }

    const commit2 = try client_repo.commit(io, allocator, .{ .message = "more stuff" });

    var pack_file = try temp_dir.createFile(io, "test.pack", .{});
    defer pack_file.close(io);

    var obj_iter = try obj.ObjectIterator(.git, repo_opts, .raw).init(.{ .core = &client_repo.core, .extra = .{} }, io, allocator, .{ .kind = .all });
    defer obj_iter.deinit();

    try obj_iter.include(&commit2);

    // write pack file
    var pack_writer_maybe = try pack.PackWriter(.git, repo_opts).init(allocator, &obj_iter);
    if (pack_writer_maybe) |*pack_writer| {
        defer pack_writer.deinit();

        var read_buffer = [_]u8{0} ** repo_opts.read_size;

        while (true) {
            const size = try pack_writer.read(&read_buffer);
            if (size == 0) {
                break;
            }

            const pack_data = read_buffer[0..size];
            try pack_file.writeStreamingAll(io, pack_data);
        }
    }

    // make sure the pack file is valid
    {
        const server_path = try std.fs.path.join(allocator, &.{ cwd_path, temp_dir_name, "server" });
        defer allocator.free(server_path);

        var server_repo = try rp.Repo(.git, .{ .is_test = true }).init(io, allocator, .{ .path = server_path });
        defer server_repo.deinit(io, allocator);

        var pack_reader = try pack.PackReader.initFile(io, allocator, temp_dir, "test.pack");
        defer pack_reader.deinit();

        var pack_iter = try pack.PackIterator(.git, repo_opts).init(io, allocator, &pack_reader);
        try obj.copyFromPackIterator(.git, repo_opts, .{ .core = &server_repo.core, .extra = .{} }, io, allocator, &pack_iter, null);
    }
}

fn copyDir(io: std.Io, src_dir: std.Io.Dir, dest_dir: std.Io.Dir) !void {
    var iter = src_dir.iterate();
    while (try iter.next(io)) |entry| {
        switch (entry.kind) {
            .file => try src_dir.copyFile(entry.name, dest_dir, entry.name, io, .{}),
            .directory => {
                try dest_dir.createDirPath(io, entry.name);
                var dest_entry_dir = try dest_dir.openDir(io, entry.name, .{ .access_sub_paths = true, .iterate = true, .follow_symlinks = false });
                defer dest_entry_dir.close(io);
                var src_entry_dir = try src_dir.openDir(io, entry.name, .{ .access_sub_paths = true, .iterate = true, .follow_symlinks = false });
                defer src_entry_dir.close(io);
                try copyDir(io, src_entry_dir, dest_entry_dir);
            },
            else => {},
        }
    }
}

test "iterate pack from file" {
    const io = std.testing.io;
    const allocator = std.testing.allocator;
    const temp_dir_name = "temp-test-iterate-file-packreader";
    const repo_opts = rp.RepoOpts(.git){ .is_test = true };

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

    // get the cwd path
    const cwd_path = try std.process.currentPathAlloc(io, allocator);
    defer allocator.free(cwd_path);

    // get work dir path
    const work_path = try std.fs.path.join(allocator, &.{ cwd_path, temp_dir_name, "repo" });
    defer allocator.free(work_path);

    var r = try rp.Repo(.git, repo_opts).init(io, allocator, .{ .path = work_path });
    defer r.deinit(io, allocator);

    var pack_dir = try cwd.openDir(io, "src/test/data", .{});
    defer pack_dir.close(io);

    var pack_reader = try pack.PackReader.initFile(io, allocator, pack_dir, "pack-b7f085e431fc05b0bca3d5c306dc148d7bbed2f4.pack");
    defer pack_reader.deinit();

    var pack_iter = try pack.PackIterator(.git, repo_opts).init(io, allocator, &pack_reader);

    try obj.copyFromPackIterator(.git, repo_opts, .{ .core = &r.core, .extra = .{} }, io, allocator, &pack_iter, null);
}

test "iterate pack from stream" {
    const io = std.testing.io;
    const allocator = std.testing.allocator;
    const temp_dir_name = "temp-test-iterate-stream-packreader";
    const repo_opts = rp.RepoOpts(.git){ .is_test = true };

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

    // get the cwd path
    const cwd_path = try std.process.currentPathAlloc(io, allocator);
    defer allocator.free(cwd_path);

    // get work dir path
    const work_path = try std.fs.path.join(allocator, &.{ cwd_path, temp_dir_name, "repo" });
    defer allocator.free(work_path);

    var r = try rp.Repo(.git, repo_opts).init(io, allocator, .{ .path = work_path });
    defer r.deinit(io, allocator);

    var pack_dir = try cwd.openDir(io, "src/test/data", .{});
    defer pack_dir.close(io);

    const pack_file = try pack_dir.openFile(io, "pack-b7f085e431fc05b0bca3d5c306dc148d7bbed2f4.pack", .{ .mode = .read_only });
    defer pack_file.close(io);

    var buffer: [repo_opts.buffer_size]u8 = undefined;
    var reader = pack_file.reader(io, &buffer);

    var counting_buf: [repo_opts.buffer_size]u8 = undefined;
    var counting_reader = pack.CountingReader.init(&reader.interface, &counting_buf);
    var pack_reader = pack.PackReader.initStream(&counting_reader);
    defer pack_reader.deinit();

    var pack_iter = try pack.PackIterator(.git, repo_opts).init(io, allocator, &pack_reader);

    try obj.copyFromPackIterator(.git, repo_opts, .{ .core = &r.core, .extra = .{} }, io, allocator, &pack_iter, null);
}

test "read packed refs" {
    const io = std.testing.io;
    const allocator = std.testing.allocator;
    const temp_dir_name = "temp-test-read-packed-refs";
    const repo_opts = rp.RepoOpts(.git){ .is_test = true };

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

    // get the cwd path
    const cwd_path = try std.process.currentPathAlloc(io, allocator);
    defer allocator.free(cwd_path);

    // get work dir path
    const work_path = try std.fs.path.join(allocator, &.{ cwd_path, temp_dir_name, "repo" });
    defer allocator.free(work_path);

    // create the work dir
    var work_dir = try cwd.createDirPathOpen(io, work_path, .{});
    defer work_dir.close(io);

    var r = try rp.Repo(.git, repo_opts).init(io, allocator, .{ .path = work_path });
    defer r.deinit(io, allocator);

    // make sure the git dir was created
    var repo_dir = try work_dir.openDir(io, ".git", .{});
    defer repo_dir.close(io);

    var packed_refs = try repo_dir.createFile(io, "packed-refs", .{});
    defer packed_refs.close(io);
    try packed_refs.writeStreamingAll(io,
        \\# pack-refs with: peeled fully-peeled sorted
        \\5246e54744f4e1824ca280e6a2630a87959d7cf4 refs/remotes/origin/master
        \\1ea47a890400815b24a0073f110a41530322a44f refs/remotes/sync/chunk
        \\5246e54744f4e1824ca280e6a2630a87959d7cf4 refs/remotes/sync/master
        \\1f6190c71bd33b37cfd885491889a0410f849f5b refs/remotes/sync/zig-0.14.0
    );

    const oid_maybe = try r.readRef(io, .{ .kind = .{ .remote = "sync" }, .name = "master" });
    try std.testing.expectEqualStrings("5246e54744f4e1824ca280e6a2630a87959d7cf4", &oid_maybe.?);

    try std.testing.expect(null == try r.readRef(io, .{ .kind = .{ .remote = "sync" }, .name = "foo" }));
}
