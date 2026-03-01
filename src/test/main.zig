//! end-to-end test using the main entrypoint: `main.run`.
//! runs with both git and xit modes, using libgit2 to
//! validate git mode.

const std = @import("std");
const builtin = @import("builtin");
const xit = @import("xit");
const main = xit.main;
const hash = xit.hash;
const idx = xit.index;
const obj = xit.object;
const rf = xit.ref;
const rp = xit.repo;
const df = xit.diff;
const mrg = xit.merge;

const c = @cImport({
    @cInclude("git2.h");
});

test "main" {
    // read and write objects in small increments to help uncover bugs
    const last_hash_git = try testMain(.git, .{ .hash = .sha1, .read_size = 1, .is_test = true });
    const last_hash_xit = try testMain(.xit, .{ .hash = .sha1, .read_size = 1, .is_test = true, .extra = .{
        .chunk_opts = .{ .min_size = 1, .avg_size = 2, .max_size = 4, .normalization = .level1 },
    } });
    try std.testing.expectEqualStrings(&last_hash_git, &last_hash_xit);

    // make sure sha256 works on the xit side
    _ = try testMain(.xit, .{ .hash = .sha256, .is_test = true });
}

fn testMain(comptime repo_kind: rp.RepoKind, comptime any_repo_opts: rp.AnyRepoOpts(repo_kind)) ![hash.hexLen(any_repo_opts.hash.?)]u8 {
    const io = std.testing.io;
    const allocator = std.testing.allocator;
    const temp_dir_name = "temp-test-main";

    var null_writer = std.Io.Writer.Discarding.init(&.{});
    const writers = main.Writers{ .out = &null_writer.writer, .err = &null_writer.writer };

    // start libgit
    if (repo_kind == .git) _ = c.git_libgit2_init();
    defer _ = if (repo_kind == .git) c.git_libgit2_shutdown();

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

    const temp_path = try std.fs.path.join(allocator, &.{ cwd_path, temp_dir_name });
    defer allocator.free(temp_path);

    // init repo
    try main.run(repo_kind, any_repo_opts, io, allocator, &.{ "init", "repo" }, temp_path, writers);

    // get work dir path (null-terminated because it's used by libgit)
    const work_path = try std.fs.path.joinZ(allocator, &.{ temp_path, "repo" });
    defer allocator.free(work_path);

    // get the work dir
    var work_dir = try cwd.openDir(io, work_path, .{});
    defer work_dir.close(io);

    // init repo-specific state
    const TestState = switch (repo_kind) {
        .git => struct {
            repo_dir: std.Io.Dir,
        },
        .xit => struct {
            repo_dir: std.Io.Dir,
            db_file: std.Io.File,
        },
    };
    var test_state: TestState = switch (repo_kind) {
        .git => .{
            .repo_dir = try work_dir.openDir(io, ".git", .{}),
        },
        .xit => blk: {
            const repo_dir = try work_dir.openDir(io, ".xit", .{});
            break :blk .{
                .repo_dir = repo_dir,
                .db_file = try repo_dir.openFile(io, "db", .{ .mode = .read_write }),
            };
        },
    };
    defer switch (repo_kind) {
        .git => test_state.repo_dir.close(io),
        .xit => {
            test_state.db_file.close(io);
            test_state.repo_dir.close(io);
        },
    };

    // make sure we can get status before first commit
    {
        var repo = try rp.Repo(repo_kind, any_repo_opts.toRepoOpts()).open(io, allocator, .{ .path = work_path });
        defer repo.deinit(io, allocator);
        var status = try repo.status(io, allocator);
        defer status.deinit(allocator);
    }

    const hello_txt_content =
        \\1
        \\2
        \\3
        \\4
        \\5
        \\6
        \\7
        \\8
        \\9
        \\10
        \\11
        \\12
        \\13
        \\14
        \\15
        \\16
        \\17
        \\18
        \\19
    ;

    // add and commit
    {
        // make file
        var hello_txt = try work_dir.createFile(io, "hello.txt", .{});
        defer hello_txt.close(io);
        try hello_txt.writeStreamingAll(io, hello_txt_content);

        // make file
        var readme = try work_dir.createFile(io, "README", .{ .read = true });
        defer readme.close(io);
        try readme.writeStreamingAll(io, "My cool project");

        // make file
        var license = try work_dir.createFile(io, "LICENSE", .{});
        defer license.close(io);
        try license.writeStreamingAll(io, "do whatever you want");

        // make file
        var tests = try work_dir.createFile(io, "tests", .{});
        defer tests.close(io);
        try tests.writeStreamingAll(io, "testing...");

        // make file
        var run_sh = try work_dir.createFile(io, "run.sh", .{});
        defer run_sh.close(io);
        try run_sh.writeStreamingAll(io, "#!/bin/sh");

        // make file in a dir
        var docs_dir = try work_dir.createDirPathOpen(io, "docs", .{});
        defer docs_dir.close(io);
        var design_md = try docs_dir.createFile(io, "design.md", .{});
        defer design_md.close(io);
        try design_md.writeStreamingAll(io, "design stuff");

        // add the files
        try main.run(repo_kind, any_repo_opts, io, allocator, &.{ "add", "." }, work_path, writers);

        // make a commit
        // we're calling this one differently to test a few things:
        // 1. setting the hash to null causes it to autodetect the repo's hash.
        // 2. the cwd is docs_path, to make sure we can run commands in any sub dir.
        // 3. we're using runPrint instead of run, which prints user-friendly errors
        //    (no difference in the tests but I just want to make sure it works)
        const docs_path = try std.fs.path.join(allocator, &.{ work_path, "docs" });
        defer allocator.free(docs_path);
        const repo_opts_no_hash = comptime ro_blk: {
            var ro = any_repo_opts;
            ro.hash = null;
            break :ro_blk ro;
        };
        try main.runPrint(repo_kind, repo_opts_no_hash, io, allocator, &.{ "commit", "-m", "first commit" }, docs_path, writers);

        switch (repo_kind) {
            .git => {
                // check that the commit object was created
                {
                    var repo = try rp.Repo(repo_kind, any_repo_opts.toRepoOpts()).open(io, allocator, .{ .path = work_path });
                    defer repo.deinit(io, allocator);
                    const head_file_buffer = try rf.readHeadRecur(repo_kind, any_repo_opts.toRepoOpts(), .{ .core = &repo.core, .extra = .{} }, io);
                    var objects_dir = try test_state.repo_dir.openDir(io, "objects", .{});
                    defer objects_dir.close(io);
                    var hash_prefix_dir = try objects_dir.openDir(io, head_file_buffer[0..2], .{});
                    defer hash_prefix_dir.close(io);
                    var hash_suffix_file = try hash_prefix_dir.openFile(io, head_file_buffer[2..], .{});
                    defer hash_suffix_file.close(io);
                }

                // read the commit with libgit
                {
                    var repo: ?*c.git_repository = null;
                    try std.testing.expectEqual(0, c.git_repository_open(&repo, work_path));
                    defer c.git_repository_free(repo);
                    var head: ?*c.git_reference = null;
                    try std.testing.expectEqual(0, c.git_repository_head(&head, repo));
                    defer c.git_reference_free(head);
                    const oid = c.git_reference_target(head);
                    try std.testing.expect(null != oid);
                    var commit: ?*c.git_commit = null;
                    try std.testing.expectEqual(0, c.git_commit_lookup(&commit, repo, oid));
                    defer c.git_commit_free(commit);
                    try std.testing.expectEqualStrings("first commit", std.mem.sliceTo(c.git_commit_message(commit), 0));
                }

                // make sure we are hashing files the same way git does
                {
                    const file_size = try readme.length(io);
                    const header = try std.fmt.allocPrint(allocator, "blob {}\x00", .{file_size});
                    defer allocator.free(header);

                    var reader_buffer = [_]u8{0} ** 1024;
                    var reader = readme.reader(io, &reader_buffer);
                    try reader.seekTo(0);

                    var sha1_bytes_buffer = [_]u8{0} ** hash.byteLen(any_repo_opts.hash.?);
                    try hash.hashReader(any_repo_opts.hash.?, any_repo_opts.read_size, &reader.interface, header, &sha1_bytes_buffer);
                    const sha1_hex = std.fmt.bytesToHex(&sha1_bytes_buffer, .lower);

                    var oid: c.git_oid = undefined;
                    try std.testing.expectEqual(0, c.git_odb_hashfile(&oid, temp_dir_name ++ "/repo/README", c.GIT_OBJECT_BLOB));
                    const oid_str = c.git_oid_tostr_s(&oid);
                    try std.testing.expect(oid_str != null);

                    try std.testing.expectEqualStrings(&sha1_hex, std.mem.sliceTo(oid_str, 0));
                }
            },
            .xit => {
                // check that the commit object was created
                var repo = try rp.Repo(repo_kind, any_repo_opts.toRepoOpts()).open(io, allocator, .{ .path = work_path });
                defer repo.deinit(io, allocator);
                var moment = try repo.core.latestMoment();
                const state = rp.Repo(repo_kind, any_repo_opts.toRepoOpts()).State(.read_only){ .core = &repo.core, .extra = .{ .moment = &moment } };
                const head_file_buffer = try rf.readHeadRecur(repo_kind, any_repo_opts.toRepoOpts(), state, io);
                const chunk_info_cursor_maybe = try moment.cursor.readPath(void, &.{
                    .{ .hash_map_get = .{ .value = hash.hashInt(any_repo_opts.hash.?, "object-id->chunk-info") } },
                    .{ .hash_map_get = .{ .value = try hash.hexToInt(any_repo_opts.hash.?, &head_file_buffer) } },
                });
                try std.testing.expect(chunk_info_cursor_maybe != null);
            },
        }
    }

    // get HEAD contents
    const commit1 = blk: {
        var repo = try rp.Repo(repo_kind, any_repo_opts.toRepoOpts()).open(io, allocator, .{ .path = work_path });
        defer repo.deinit(io, allocator);
        var moment = try repo.core.latestMoment();
        const state = rp.Repo(repo_kind, any_repo_opts.toRepoOpts()).State(.read_only){ .core = &repo.core, .extra = .{ .moment = &moment } };
        break :blk try rf.readHeadRecur(repo_kind, any_repo_opts.toRepoOpts(), state, io);
    };

    const new_hello_txt_content =
        \\1
        \\2
        \\3
        \\4
        \\5.0
        \\6
        \\7
        \\8
        \\9.0
        \\10.0
        \\11
        \\12
        \\13
        \\14
        \\15.0
        \\16
        \\17
        \\18
        \\19
    ;

    // make another commit
    {
        // change a file
        const hello_txt = try work_dir.openFile(io, "hello.txt", .{ .mode = .read_write });
        defer hello_txt.close(io);
        try hello_txt.setLength(io, 0);
        try hello_txt.writeStreamingAll(io, new_hello_txt_content);

        // replace a file with a directory
        try work_dir.deleteFile(io, "tests");
        var tests_dir = try work_dir.createDirPathOpen(io, "tests", .{});
        defer tests_dir.close(io);
        var main_test_zig = try tests_dir.createFile(io, "main_test.zig", .{});
        defer main_test_zig.close(io);

        // make a few dirs
        var src_dir = try work_dir.createDirPathOpen(io, "src", .{});
        defer src_dir.close(io);
        var src_zig_dir = try src_dir.createDirPathOpen(io, "zig", .{});
        defer src_zig_dir.close(io);

        // make a file in the dir
        var main_zig = try src_zig_dir.createFile(io, "main.zig", .{});
        defer main_zig.close(io);
        try main_zig.writeStreamingAll(io, "pub fn main() !void {}");

        // make file in a nested dir
        var two_dir = try work_dir.createDirPathOpen(io, "one/two", .{});
        defer two_dir.close(io);
        var three_txt = try two_dir.createFile(io, "three.txt", .{});
        defer three_txt.close(io);
        try three_txt.writeStreamingAll(io, "one, two, three!");

        // make run.sh an executable
        if (.windows != builtin.os.tag) {
            const run_sh = try work_dir.openFile(io, "run.sh", .{ .mode = .read_write });
            defer run_sh.close(io);
            try run_sh.setPermissions(io, .executable_file);
        }

        // make symlink
        switch (builtin.os.tag) {
            .windows => {
                var fake_symlink = try work_dir.createFile(io, "three.txt", .{});
                defer fake_symlink.close(io);
                try fake_symlink.writeStreamingAll(io, "one/two/three.txt");
            },
            else => try work_dir.symLink(io, "one/two/three.txt", "three.txt", .{}),
        }

        // work dir diff
        {
            var repo = try rp.Repo(repo_kind, any_repo_opts.toRepoOpts()).open(io, allocator, .{ .path = work_path });
            defer repo.deinit(io, allocator);
            var status = try repo.status(io, allocator);
            defer status.deinit(allocator);
            var file_iter = try repo.filePairs(io, allocator, .{
                .work_dir = .{
                    .conflict_diff_kind = .target,
                    .status = &status,
                },
            });

            while (try file_iter.next()) |*line_iter_pair_ptr| {
                var line_iter_pair = line_iter_pair_ptr.*;
                defer line_iter_pair.deinit();
                var hunk_iter = try df.HunkIterator(repo_kind, any_repo_opts.toRepoOpts()).init(allocator, &line_iter_pair.a, &line_iter_pair.b);
                defer hunk_iter.deinit(allocator);
                if (std.mem.eql(u8, "hello.txt", line_iter_pair.path)) {
                    try std.testing.expectEqualStrings("diff --git a/hello.txt b/hello.txt", hunk_iter.header_lines.items[0]);
                    const expected_hunks = &[_][]const df.Edit{
                        &[_]df.Edit{
                            .{ .eql = .{ .old_line = .{ .num = 1 }, .new_line = .{ .num = 1 } } },
                            .{ .eql = .{ .old_line = .{ .num = 2 }, .new_line = .{ .num = 2 } } },
                            .{ .eql = .{ .old_line = .{ .num = 3 }, .new_line = .{ .num = 3 } } },
                            .{ .del = .{ .old_line = .{ .num = 4 } } },
                            .{ .ins = .{ .new_line = .{ .num = 4 } } },
                            .{ .eql = .{ .old_line = .{ .num = 5 }, .new_line = .{ .num = 5 } } },
                            .{ .eql = .{ .old_line = .{ .num = 6 }, .new_line = .{ .num = 6 } } },
                            .{ .eql = .{ .old_line = .{ .num = 7 }, .new_line = .{ .num = 7 } } },
                        },
                        &[_]df.Edit{
                            .{ .del = .{ .old_line = .{ .num = 8 } } },
                            .{ .del = .{ .old_line = .{ .num = 9 } } },
                            .{ .ins = .{ .new_line = .{ .num = 8 } } },
                            .{ .ins = .{ .new_line = .{ .num = 9 } } },
                            .{ .eql = .{ .old_line = .{ .num = 10 }, .new_line = .{ .num = 10 } } },
                            .{ .eql = .{ .old_line = .{ .num = 11 }, .new_line = .{ .num = 11 } } },
                            .{ .eql = .{ .old_line = .{ .num = 12 }, .new_line = .{ .num = 12 } } },
                        },
                        &[_]df.Edit{
                            .{ .eql = .{ .old_line = .{ .num = 13 }, .new_line = .{ .num = 13 } } },
                            .{ .del = .{ .old_line = .{ .num = 14 } } },
                            .{ .ins = .{ .new_line = .{ .num = 14 } } },
                            .{ .eql = .{ .old_line = .{ .num = 15 }, .new_line = .{ .num = 15 } } },
                            .{ .eql = .{ .old_line = .{ .num = 16 }, .new_line = .{ .num = 16 } } },
                            .{ .eql = .{ .old_line = .{ .num = 17 }, .new_line = .{ .num = 17 } } },
                        },
                    };
                    for (expected_hunks) |expected_hunk| {
                        if (try hunk_iter.next(allocator)) |*actual_hunk_ptr| {
                            var actual_hunk = actual_hunk_ptr.*;
                            defer actual_hunk.deinit(allocator);
                            for (expected_hunk, actual_hunk.edits.items) |expected_edit, actual_edit| {
                                try std.testing.expectEqualDeep(expected_edit, actual_edit.withoutOffset());
                            }
                        } else {
                            return error.NullHunk;
                        }
                    }
                } else if (std.mem.eql(u8, "run.sh", line_iter_pair.path)) {
                    try std.testing.expectEqualStrings("diff --git a/run.sh b/run.sh", hunk_iter.header_lines.items[0]);
                    try std.testing.expectEqualStrings("old mode 100644", hunk_iter.header_lines.items[1]);
                    try std.testing.expectEqualStrings("new mode 100755", hunk_iter.header_lines.items[2]);
                } else if (std.mem.eql(u8, "tests", line_iter_pair.path)) {
                    try std.testing.expectEqualStrings("diff --git a/tests b/tests", hunk_iter.header_lines.items[0]);
                    try std.testing.expectEqualStrings("deleted file mode 100644", hunk_iter.header_lines.items[1]);
                } else {
                    return error.EntryNotExpected;
                }
            }

            switch (builtin.os.tag) {
                // on windows, permissions can't be changed so run.sh doesn't show up as modified
                .windows => try std.testing.expectEqual(2, file_iter.next_index),
                else => try std.testing.expectEqual(3, file_iter.next_index),
            }
        }

        // delete a file
        try work_dir.deleteFile(io, "LICENSE");
        try main.run(repo_kind, any_repo_opts, io, allocator, &.{ "add", "LICENSE" }, work_path, writers);

        // delete a file and dir
        try work_dir.deleteTree(io, "docs");
        try main.run(repo_kind, any_repo_opts, io, allocator, &.{ "add", "docs/design.md" }, work_path, writers);

        // add new and modified files
        try main.run(repo_kind, any_repo_opts, io, allocator, &.{ "add", "hello.txt", "run.sh", "src/zig/main.zig" }, work_path, writers);

        // index diff
        {
            var repo = try rp.Repo(repo_kind, any_repo_opts.toRepoOpts()).open(io, allocator, .{ .path = work_path });
            defer repo.deinit(io, allocator);
            var status = try repo.status(io, allocator);
            defer status.deinit(allocator);
            var file_iter = try repo.filePairs(io, allocator, .{
                .index = .{ .status = &status },
            });

            while (try file_iter.next()) |*line_iter_pair_ptr| {
                var line_iter_pair = line_iter_pair_ptr.*;
                defer line_iter_pair.deinit();
                var hunk_iter = try df.HunkIterator(repo_kind, any_repo_opts.toRepoOpts()).init(allocator, &line_iter_pair.a, &line_iter_pair.b);
                defer hunk_iter.deinit(allocator);
                if (std.mem.eql(u8, "LICENSE", line_iter_pair.path)) {
                    try std.testing.expectEqualStrings("diff --git a/LICENSE b/LICENSE", hunk_iter.header_lines.items[0]);
                    try std.testing.expectEqualStrings("deleted file mode 100644", hunk_iter.header_lines.items[1]);
                } else if (std.mem.eql(u8, "docs/design.md", line_iter_pair.path)) {
                    try std.testing.expectEqualStrings("diff --git a/docs/design.md b/docs/design.md", hunk_iter.header_lines.items[0]);
                    try std.testing.expectEqualStrings("deleted file mode 100644", hunk_iter.header_lines.items[1]);
                } else if (std.mem.eql(u8, "hello.txt", line_iter_pair.path)) {
                    try std.testing.expectEqualStrings("diff --git a/hello.txt b/hello.txt", hunk_iter.header_lines.items[0]);
                } else if (std.mem.eql(u8, "run.sh", line_iter_pair.path)) {
                    try std.testing.expectEqualStrings("diff --git a/run.sh b/run.sh", hunk_iter.header_lines.items[0]);
                    try std.testing.expectEqualStrings("old mode 100644", hunk_iter.header_lines.items[1]);
                    try std.testing.expectEqualStrings("new mode 100755", hunk_iter.header_lines.items[2]);
                } else if (std.mem.eql(u8, "src/zig/main.zig", line_iter_pair.path)) {
                    try std.testing.expectEqualStrings("diff --git a/src/zig/main.zig b/src/zig/main.zig", hunk_iter.header_lines.items[0]);
                    try std.testing.expectEqualStrings("new file mode 100644", hunk_iter.header_lines.items[1]);
                } else {
                    return error.EntryNotExpected;
                }
            }

            switch (builtin.os.tag) {
                // on windows, permissions can't be changed so run.sh doesn't show up as modified
                .windows => try std.testing.expectEqual(4, file_iter.next_index),
                else => try std.testing.expectEqual(5, file_iter.next_index),
            }
        }

        // add the remaining files
        try main.run(repo_kind, any_repo_opts, io, allocator, &.{ "add", "." }, work_path, writers);

        // make another commit
        try main.run(repo_kind, any_repo_opts, io, allocator, &.{ "commit", "-m", "second commit" }, work_path, writers);

        switch (repo_kind) {
            .git => {
                // check that the commit object was created
                {
                    var repo = try rp.Repo(repo_kind, any_repo_opts.toRepoOpts()).open(io, allocator, .{ .path = work_path });
                    defer repo.deinit(io, allocator);
                    const head_file_buffer = try rf.readHeadRecur(repo_kind, any_repo_opts.toRepoOpts(), .{ .core = &repo.core, .extra = .{} }, io);
                    var objects_dir = try test_state.repo_dir.openDir(io, "objects", .{});
                    defer objects_dir.close(io);
                    var hash_prefix_dir = try objects_dir.openDir(io, head_file_buffer[0..2], .{});
                    defer hash_prefix_dir.close(io);
                    var hash_suffix_file = try hash_prefix_dir.openFile(io, head_file_buffer[2..], .{});
                    defer hash_suffix_file.close(io);
                }

                // read the commit with libgit
                {
                    var repo: ?*c.git_repository = null;
                    try std.testing.expectEqual(0, c.git_repository_open(&repo, work_path));
                    defer c.git_repository_free(repo);
                    var head: ?*c.git_reference = null;
                    try std.testing.expectEqual(0, c.git_repository_head(&head, repo));
                    defer c.git_reference_free(head);
                    const oid = c.git_reference_target(head);
                    try std.testing.expect(null != oid);
                    var commit: ?*c.git_commit = null;
                    try std.testing.expectEqual(0, c.git_commit_lookup(&commit, repo, oid));
                    defer c.git_commit_free(commit);
                    try std.testing.expectEqualStrings("second commit", std.mem.sliceTo(c.git_commit_message(commit), 0));
                }
            },
            .xit => {
                // check that the commit object was created
                var repo = try rp.Repo(repo_kind, any_repo_opts.toRepoOpts()).open(io, allocator, .{ .path = work_path });
                defer repo.deinit(io, allocator);
                var moment = try repo.core.latestMoment();
                const state = rp.Repo(repo_kind, any_repo_opts.toRepoOpts()).State(.read_only){ .core = &repo.core, .extra = .{ .moment = &moment } };
                const head_file_buffer = try rf.readHeadRecur(repo_kind, any_repo_opts.toRepoOpts(), state, io);
                const chunk_info_cursor_maybe = try moment.cursor.readPath(void, &.{
                    .{ .hash_map_get = .{ .value = hash.hashInt(any_repo_opts.hash.?, "object-id->chunk-info") } },
                    .{ .hash_map_get = .{ .value = try hash.hexToInt(any_repo_opts.hash.?, &head_file_buffer) } },
                });
                try std.testing.expect(chunk_info_cursor_maybe != null);
            },
        }
    }

    // get HEAD contents
    const commit2 = blk: {
        var repo = try rp.Repo(repo_kind, any_repo_opts.toRepoOpts()).open(io, allocator, .{ .path = work_path });
        defer repo.deinit(io, allocator);
        var moment = try repo.core.latestMoment();
        const state = rp.Repo(repo_kind, any_repo_opts.toRepoOpts()).State(.read_only){ .core = &repo.core, .extra = .{ .moment = &moment } };
        break :blk try rf.readHeadRecur(repo_kind, any_repo_opts.toRepoOpts(), state, io);
    };

    // tree diff
    {
        var repo = try rp.Repo(repo_kind, any_repo_opts.toRepoOpts()).open(io, allocator, .{ .path = work_path });
        defer repo.deinit(io, allocator);
        var tree_diff = try repo.treeDiff(io, allocator, &commit1, &commit2);
        defer tree_diff.deinit();
        var file_iter = try repo.filePairs(io, allocator, .{
            .tree = .{ .tree_diff = &tree_diff },
        });

        while (try file_iter.next()) |*line_iter_pair_ptr| {
            var line_iter_pair = line_iter_pair_ptr.*;
            defer line_iter_pair.deinit();
            var hunk_iter = try df.HunkIterator(repo_kind, any_repo_opts.toRepoOpts()).init(allocator, &line_iter_pair.a, &line_iter_pair.b);
            defer hunk_iter.deinit(allocator);
            if (std.mem.eql(u8, "LICENSE", line_iter_pair.path)) {
                try std.testing.expectEqualStrings("diff --git a/LICENSE b/LICENSE", hunk_iter.header_lines.items[0]);
                try std.testing.expectEqualStrings("deleted file mode 100644", hunk_iter.header_lines.items[1]);
            } else if (std.mem.eql(u8, "docs/design.md", line_iter_pair.path)) {
                try std.testing.expectEqualStrings("diff --git a/docs/design.md b/docs/design.md", hunk_iter.header_lines.items[0]);
                try std.testing.expectEqualStrings("deleted file mode 100644", hunk_iter.header_lines.items[1]);
            } else if (std.mem.eql(u8, "hello.txt", line_iter_pair.path)) {
                try std.testing.expectEqualStrings("diff --git a/hello.txt b/hello.txt", hunk_iter.header_lines.items[0]);
            } else if (std.mem.eql(u8, "run.sh", line_iter_pair.path)) {
                try std.testing.expectEqualStrings("diff --git a/run.sh b/run.sh", hunk_iter.header_lines.items[0]);
                try std.testing.expectEqualStrings("old mode 100644", hunk_iter.header_lines.items[1]);
                try std.testing.expectEqualStrings("new mode 100755", hunk_iter.header_lines.items[2]);
            } else if (std.mem.eql(u8, "src/zig/main.zig", line_iter_pair.path)) {
                try std.testing.expectEqualStrings("diff --git a/src/zig/main.zig b/src/zig/main.zig", hunk_iter.header_lines.items[0]);
                try std.testing.expectEqualStrings("new file mode 100644", hunk_iter.header_lines.items[1]);
            } else if (std.mem.eql(u8, "tests/main_test.zig", line_iter_pair.path)) {
                try std.testing.expectEqualStrings("diff --git a/tests/main_test.zig b/tests/main_test.zig", hunk_iter.header_lines.items[0]);
                try std.testing.expectEqualStrings("new file mode 100644", hunk_iter.header_lines.items[1]);
            } else if (std.mem.eql(u8, "tests", line_iter_pair.path)) {
                try std.testing.expectEqualStrings("diff --git a/tests b/tests", hunk_iter.header_lines.items[0]);
                try std.testing.expectEqualStrings("deleted file mode 100644", hunk_iter.header_lines.items[1]);
            } else if (std.mem.eql(u8, "one/two/three.txt", line_iter_pair.path)) {
                try std.testing.expectEqualStrings("diff --git a/one/two/three.txt b/one/two/three.txt", hunk_iter.header_lines.items[0]);
                try std.testing.expectEqualStrings("new file mode 100644", hunk_iter.header_lines.items[1]);
            } else if (std.mem.eql(u8, "three.txt", line_iter_pair.path)) {
                try std.testing.expectEqualStrings("diff --git a/three.txt b/three.txt", hunk_iter.header_lines.items[0]);
                // on windows, it is not a symlink
                switch (builtin.os.tag) {
                    .windows => try std.testing.expectEqualStrings("new file mode 100644", hunk_iter.header_lines.items[1]),
                    else => try std.testing.expectEqualStrings("new file mode 120000", hunk_iter.header_lines.items[1]),
                }
            } else {
                return error.EntryNotExpected;
            }
        }

        switch (builtin.os.tag) {
            // on windows, permissions can't be changed so run.sh doesn't show up as modified
            .windows => try std.testing.expectEqual(8, file_iter.next_index),
            else => try std.testing.expectEqual(9, file_iter.next_index),
        }
    }

    // try to switch to first commit after making conflicting change
    {
        {
            // make a new file (and add it to the index) that conflicts with one from commit1
            {
                var license = try work_dir.createFile(io, "LICENSE", .{});
                defer license.close(io);
                try license.writeStreamingAll(io, "different license");
                try main.run(repo_kind, any_repo_opts, io, allocator, &.{ "add", "LICENSE" }, work_path, writers);
            }

            // check out commit1 and make sure the conflict is found
            {
                var repo = try rp.Repo(repo_kind, any_repo_opts.toRepoOpts()).open(io, allocator, .{ .path = work_path });
                defer repo.deinit(io, allocator);
                var switch_result = try repo.switchDir(io, allocator, .{ .target = .{ .oid = &commit1 } });
                defer switch_result.deinit();
                try std.testing.expect(.conflict == switch_result.result);
                try std.testing.expectEqual(1, switch_result.result.conflict.stale_files.count());
            }

            // delete the file
            {
                try work_dir.deleteFile(io, "LICENSE");
                try main.run(repo_kind, any_repo_opts, io, allocator, &.{ "add", "LICENSE" }, work_path, writers);
            }
        }

        {
            // make a new file (only in the work dir) that conflicts with the descendent of a file from commit1
            {
                var docs = try work_dir.createFile(io, "docs", .{});
                defer docs.close(io);
                try docs.writeStreamingAll(io, "i conflict with the docs dir in the first commit");
            }

            // check out commit1 and make sure the conflict is found
            {
                var repo = try rp.Repo(repo_kind, any_repo_opts.toRepoOpts()).open(io, allocator, .{ .path = work_path });
                defer repo.deinit(io, allocator);
                var switch_result = try repo.switchDir(io, allocator, .{ .target = .{ .oid = &commit1 } });
                defer switch_result.deinit();
                try std.testing.expect(.conflict == switch_result.result);
            }

            // delete the file
            try work_dir.deleteFile(io, "docs");
        }

        {
            // change a file so it conflicts with the one in commit1
            {
                const hello_txt = try work_dir.openFile(io, "hello.txt", .{ .mode = .read_write });
                defer hello_txt.close(io);
                try hello_txt.setLength(io, 0);
                try hello_txt.writeStreamingAll(io, "12345");
            }

            // check out commit1 and make sure the conflict is found
            {
                var repo = try rp.Repo(repo_kind, any_repo_opts.toRepoOpts()).open(io, allocator, .{ .path = work_path });
                defer repo.deinit(io, allocator);
                var switch_result = try repo.switchDir(io, allocator, .{ .target = .{ .oid = &commit1 } });
                defer switch_result.deinit();
                try std.testing.expect(.conflict == switch_result.result);
                try std.testing.expectEqual(1, switch_result.result.conflict.stale_files.count());
            }

            // change the file back
            {
                const hello_txt = try work_dir.openFile(io, "hello.txt", .{ .mode = .read_write });
                defer hello_txt.close(io);
                try hello_txt.setLength(io, 0);
                try hello_txt.writeStreamingAll(io, new_hello_txt_content);
            }
        }

        {
            // create a dir with a file that conflicts with one in commit1
            {
                var license_dir = try work_dir.createDirPathOpen(io, "LICENSE", .{});
                defer license_dir.close(io);
                const foo_txt = try license_dir.createFile(io, "foo.txt", .{});
                defer foo_txt.close(io);
                try foo_txt.writeStreamingAll(io, "foo");
            }

            // check out commit1 and make sure the conflict is found
            {
                var repo = try rp.Repo(repo_kind, any_repo_opts.toRepoOpts()).open(io, allocator, .{ .path = work_path });
                defer repo.deinit(io, allocator);
                var switch_result = try repo.switchDir(io, allocator, .{ .target = .{ .oid = &commit1 } });
                defer switch_result.deinit();
                try std.testing.expect(.conflict == switch_result.result);
                try std.testing.expectEqual(1, switch_result.result.conflict.stale_dirs.count());
            }

            // delete the dir
            try work_dir.deleteTree(io, "LICENSE");
        }
    }

    // switch to first commit
    try main.run(repo_kind, any_repo_opts, io, allocator, &.{ "switch", &commit1 }, work_path, writers);

    // the work dir was updated
    {
        const content = try work_dir.readFileAlloc(io, "hello.txt", allocator, .limited(1024));
        defer allocator.free(content);
        try std.testing.expectEqualStrings(hello_txt_content, content);

        const license = try work_dir.openFile(io, "LICENSE", .{ .mode = .read_only });
        defer license.close(io);

        var two_dir_or_err = work_dir.openDir(io, "one/two", .{});
        if (two_dir_or_err) |*dir| {
            dir.close(io);
            return error.UnexpectedDir;
        } else |_| {}

        var one_dir_or_err = work_dir.openDir(io, "one", .{});
        if (one_dir_or_err) |*dir| {
            dir.close(io);
            return error.UnexpectedDir;
        } else |_| {}
    }

    // switch to master
    try main.run(repo_kind, any_repo_opts, io, allocator, &.{ "switch", "master" }, work_path, writers);

    // the work dir was updated
    {
        const content = try work_dir.readFileAlloc(io, "hello.txt", allocator, .limited(1024));
        defer allocator.free(content);
        try std.testing.expectEqualStrings(new_hello_txt_content, content);

        const license_or_err = work_dir.openFile(io, "LICENSE", .{ .mode = .read_only });
        try std.testing.expectEqual(error.FileNotFound, license_or_err);
    }

    // replacing file with dir and dir with file
    {
        // replace file with directory
        {
            try work_dir.deleteFile(io, "hello.txt");
            var hello_txt_dir = try work_dir.createDirPathOpen(io, "hello.txt", .{});
            defer hello_txt_dir.close(io);
            var nested_txt = try hello_txt_dir.createFile(io, "nested.txt", .{});
            defer nested_txt.close(io);
            var nested2_txt = try hello_txt_dir.createFile(io, "nested2.txt", .{});
            defer nested2_txt.close(io);
        }

        // add the new dir
        try main.run(repo_kind, any_repo_opts, io, allocator, &.{ "add", "hello.txt" }, work_path, writers);

        // read index
        {
            var repo = try rp.Repo(repo_kind, any_repo_opts.toRepoOpts()).open(io, allocator, .{ .path = work_path });
            defer repo.deinit(io, allocator);
            var moment = try repo.core.latestMoment();
            const state = rp.Repo(repo_kind, any_repo_opts.toRepoOpts()).State(.read_only){ .core = &repo.core, .extra = .{ .moment = &moment } };
            var index = try idx.Index(repo_kind, any_repo_opts.toRepoOpts()).init(state, io, allocator);
            defer index.deinit();
            try std.testing.expectEqual(8, index.entries.count());
            try std.testing.expect(index.entries.contains("README"));
            try std.testing.expect(index.entries.contains("src/zig/main.zig"));
            try std.testing.expect(index.entries.contains("tests/main_test.zig"));
            try std.testing.expect(index.entries.contains("hello.txt/nested.txt"));
            try std.testing.expect(index.entries.contains("hello.txt/nested2.txt"));
            try std.testing.expect(index.entries.contains("run.sh"));
            try std.testing.expect(index.entries.contains("one/two/three.txt"));
            try std.testing.expect(index.entries.contains("three.txt"));
        }

        switch (repo_kind) {
            .git => {
                // read index with libgit
                var repo: ?*c.git_repository = null;
                try std.testing.expectEqual(0, c.git_repository_open(&repo, work_path));
                defer c.git_repository_free(repo);
                var index: ?*c.git_index = null;
                try std.testing.expectEqual(0, c.git_repository_index(&index, repo));
                defer c.git_index_free(index);
                try std.testing.expectEqual(8, c.git_index_entrycount(index));
            },
            .xit => {
                // read the index in xitdb
                var repo = try rp.Repo(repo_kind, any_repo_opts.toRepoOpts()).open(io, allocator, .{ .path = work_path });
                defer repo.deinit(io, allocator);
                var count: u32 = 0;
                var moment = try repo.core.latestMoment();
                if (try moment.getCursor(hash.hashInt(any_repo_opts.hash.?, "index"))) |index_cursor| {
                    var iter = try index_cursor.iterator();
                    while (try iter.next()) |_| {
                        count += 1;
                    }
                }
                try std.testing.expectEqual(8, count);
            },
        }

        // replace directory with file
        {
            var hello_txt_dir = try work_dir.openDir(io, "hello.txt", .{});
            defer hello_txt_dir.close(io);
            try hello_txt_dir.deleteFile(io, "nested.txt");
            try hello_txt_dir.deleteFile(io, "nested2.txt");
        }
        try work_dir.deleteDir(io, "hello.txt");
        var hello_txt2 = try work_dir.createFile(io, "hello.txt", .{});
        defer hello_txt2.close(io);

        // add the new file
        try main.run(repo_kind, any_repo_opts, io, allocator, &.{ "add", "hello.txt" }, work_path, writers);

        // read index
        {
            var repo = try rp.Repo(repo_kind, any_repo_opts.toRepoOpts()).open(io, allocator, .{ .path = work_path });
            defer repo.deinit(io, allocator);
            var moment = try repo.core.latestMoment();
            const state = rp.Repo(repo_kind, any_repo_opts.toRepoOpts()).State(.read_only){ .core = &repo.core, .extra = .{ .moment = &moment } };
            var index = try idx.Index(repo_kind, any_repo_opts.toRepoOpts()).init(state, io, allocator);
            defer index.deinit();
            try std.testing.expectEqual(7, index.entries.count());
            try std.testing.expect(index.entries.contains("README"));
            try std.testing.expect(index.entries.contains("src/zig/main.zig"));
            try std.testing.expect(index.entries.contains("tests/main_test.zig"));
            try std.testing.expect(index.entries.contains("hello.txt"));
            try std.testing.expect(index.entries.contains("run.sh"));
            try std.testing.expect(index.entries.contains("one/two/three.txt"));
            try std.testing.expect(index.entries.contains("three.txt"));
        }

        switch (repo_kind) {
            .git => {
                // read index with libgit
                var repo: ?*c.git_repository = null;
                try std.testing.expectEqual(0, c.git_repository_open(&repo, work_path));
                defer c.git_repository_free(repo);
                var index: ?*c.git_index = null;
                try std.testing.expectEqual(0, c.git_repository_index(&index, repo));
                defer c.git_index_free(index);
                try std.testing.expectEqual(7, c.git_index_entrycount(index));
            },
            .xit => {
                // read the index in xitdb
                var repo = try rp.Repo(repo_kind, any_repo_opts.toRepoOpts()).open(io, allocator, .{ .path = work_path });
                defer repo.deinit(io, allocator);
                var count: u32 = 0;
                var moment = try repo.core.latestMoment();
                if (try moment.getCursor(hash.hashInt(any_repo_opts.hash.?, "index"))) |index_cursor| {
                    var iter = try index_cursor.iterator();
                    while (try iter.next()) |_| {
                        count += 1;
                    }
                }
                try std.testing.expectEqual(7, count);
            },
        }

        // a stale index lock file isn't hanging around
        if (repo_kind == .git) {
            const lock_file_or_err = test_state.repo_dir.openFile(io, "index.lock", .{ .mode = .read_only });
            try std.testing.expectEqual(error.FileNotFound, lock_file_or_err);
        }
    }

    // changing the index
    {
        // can't add a non-existent file
        try std.testing.expectEqual(error.AddIndexPathNotFound, main.run(repo_kind, any_repo_opts, io, allocator, &.{ "add", "no-such-file" }, work_path, writers));

        // can't remove non-existent file
        try std.testing.expectEqual(error.RemoveIndexPathNotFound, main.run(repo_kind, any_repo_opts, io, allocator, &.{ "rm", "no-such-file" }, work_path, writers));

        // modify a file
        {
            const three_txt = try work_dir.openFile(io, "one/two/three.txt", .{ .mode = .read_write });
            defer three_txt.close(io);
            try three_txt.setLength(io, 0);
            try three_txt.writeStreamingAll(io, "this is now modified");
        }

        // can't remove a file with unstaged changes
        try std.testing.expectEqual(error.CannotRemoveFileWithUnstagedChanges, main.run(repo_kind, any_repo_opts, io, allocator, &.{ "rm", "one/two/three.txt" }, work_path, writers));

        // stage the changes
        try main.run(repo_kind, any_repo_opts, io, allocator, &.{ "add", "one/two/three.txt" }, work_path, writers);

        // modify it again
        {
            const three_txt = try work_dir.openFile(io, "one/two/three.txt", .{ .mode = .read_write });
            defer three_txt.close(io);
            try three_txt.setLength(io, 0);
            try three_txt.writeStreamingAll(io, "this is now modified again");
        }

        // can't untrack a file with staged and unstaged changes
        try std.testing.expectEqual(error.CannotRemoveFileWithStagedAndUnstagedChanges, main.run(repo_kind, any_repo_opts, io, allocator, &.{ "untrack", "one/two/three.txt" }, work_path, writers));

        // add dir
        try main.run(repo_kind, any_repo_opts, io, allocator, &.{ "add", "one" }, work_path, writers);

        // can't untrack a dir without -r
        try std.testing.expectEqual(error.RecursiveOptionRequired, main.run(repo_kind, any_repo_opts, io, allocator, &.{ "untrack", "one" }, work_path, writers));

        // can't unadd a dir without -r
        try std.testing.expectEqual(error.RecursiveOptionRequired, main.run(repo_kind, any_repo_opts, io, allocator, &.{ "unadd", "one" }, work_path, writers));

        // unadd dir
        try main.run(repo_kind, any_repo_opts, io, allocator, &.{ "unadd", "-r", "one" }, work_path, writers);

        // still tracked because unadd just resets it back to the state from HEAD
        {
            var repo = try rp.Repo(repo_kind, any_repo_opts.toRepoOpts()).open(io, allocator, .{ .path = work_path });
            defer repo.deinit(io, allocator);
            var moment = try repo.core.latestMoment();
            const state = rp.Repo(repo_kind, any_repo_opts.toRepoOpts()).State(.read_only){ .core = &repo.core, .extra = .{ .moment = &moment } };
            var index = try idx.Index(repo_kind, any_repo_opts.toRepoOpts()).init(state, io, allocator);
            defer index.deinit();

            try std.testing.expect(index.entries.contains("one/two/three.txt"));
            try std.testing.expectEqual("one, two, three!".len, index.entries.get("one/two/three.txt").?[0].?.file_size);
        }

        try main.run(repo_kind, any_repo_opts, io, allocator, &.{ "untrack", "one/two/three.txt" }, work_path, writers);

        // not tracked anymore
        {
            var repo = try rp.Repo(repo_kind, any_repo_opts.toRepoOpts()).open(io, allocator, .{ .path = work_path });
            defer repo.deinit(io, allocator);
            var moment = try repo.core.latestMoment();
            const state = rp.Repo(repo_kind, any_repo_opts.toRepoOpts()).State(.read_only){ .core = &repo.core, .extra = .{ .moment = &moment } };
            var index = try idx.Index(repo_kind, any_repo_opts.toRepoOpts()).init(state, io, allocator);
            defer index.deinit();

            try std.testing.expect(!index.entries.contains("one/two/three.txt"));
        }

        // stage the changes to the file
        try main.run(repo_kind, any_repo_opts, io, allocator, &.{ "add", "one/two/three.txt" }, work_path, writers);

        // can't remove a file with staged changes
        try std.testing.expectEqual(error.CannotRemoveFileWithStagedChanges, main.run(repo_kind, any_repo_opts, io, allocator, &.{ "rm", "one/two/three.txt" }, work_path, writers));

        // remove file by force
        try main.run(repo_kind, any_repo_opts, io, allocator, &.{ "rm", "one/two/three.txt", "-f" }, work_path, writers);

        // restore file's original content
        {
            var two_dir = try work_dir.createDirPathOpen(io, "one/two", .{});
            defer two_dir.close(io);

            const three_txt = try work_dir.createFile(io, "one/two/three.txt", .{});
            defer three_txt.close(io);
            try three_txt.setLength(io, 0);
            try three_txt.writeStreamingAll(io, "one, two, three!");

            try main.run(repo_kind, any_repo_opts, io, allocator, &.{ "add", "one/two/three.txt" }, work_path, writers);
        }

        // remove a file
        {
            try main.run(repo_kind, any_repo_opts, io, allocator, &.{ "rm", "one/two/three.txt" }, work_path, writers);

            var file_or_err = work_dir.openFile(io, "one/two/three.txt", .{ .mode = .read_only });
            if (file_or_err) |*file| {
                file.close(io);
                return error.UnexpectedFile;
            } else |_| {}
        }
    }

    // status
    {
        // make file
        var goodbye_txt = try work_dir.createFile(io, "goodbye.txt", .{});
        defer goodbye_txt.close(io);
        try goodbye_txt.writeStreamingAll(io, "Goodbye");

        // make dirs
        var a_dir = try work_dir.createDirPathOpen(io, "a", .{});
        defer a_dir.close(io);
        var b_dir = try work_dir.createDirPathOpen(io, "b", .{});
        defer b_dir.close(io);
        var c_dir = try work_dir.createDirPathOpen(io, "c", .{});
        defer c_dir.close(io);

        // make file in dir
        var farewell_txt = try a_dir.createFile(io, "farewell.txt", .{});
        defer farewell_txt.close(io);
        try farewell_txt.writeStreamingAll(io, "Farewell");

        // modify indexed files
        {
            const hello_txt = try work_dir.openFile(io, "hello.txt", .{ .mode = .read_write });
            defer hello_txt.close(io);
            try hello_txt.writeStreamingAll(io, "hello, world again!");

            const readme = try work_dir.openFile(io, "README", .{ .mode = .read_write });
            defer readme.close(io);
            try readme.writeStreamingAll(io, "My code project"); // size doesn't change

            var src_dir = try work_dir.openDir(io, "src", .{});
            defer src_dir.close(io);
            var zig_dir = try src_dir.openDir(io, "zig", .{});
            defer zig_dir.close(io);
            try zig_dir.deleteFile(io, "main.zig");
        }

        // work dir changes
        {
            // get status
            var repo = try rp.Repo(repo_kind, any_repo_opts.toRepoOpts()).open(io, allocator, .{ .path = work_path });
            defer repo.deinit(io, allocator);
            var status = try repo.status(io, allocator);
            defer status.deinit(allocator);

            // check the untracked entries
            try std.testing.expectEqual(2, status.untracked.count());
            try std.testing.expect(status.untracked.contains("a"));
            try std.testing.expect(status.untracked.contains("goodbye.txt"));

            // check the work_dir_modified entries
            try std.testing.expectEqual(2, status.work_dir_modified.count());
            try std.testing.expect(status.work_dir_modified.contains("hello.txt"));
            try std.testing.expect(status.work_dir_modified.contains("README"));

            // check the work_dir_deleted entries
            try std.testing.expectEqual(1, status.work_dir_deleted.count());
            try std.testing.expect(status.work_dir_deleted.contains("src/zig/main.zig"));
        }

        // get status with libgit
        if (repo_kind == .git) {
            var repo: ?*c.git_repository = null;
            try std.testing.expectEqual(0, c.git_repository_open(&repo, work_path));
            defer c.git_repository_free(repo);
            var status_list: ?*c.git_status_list = null;
            var status_options: c.git_status_options = undefined;
            try std.testing.expectEqual(0, c.git_status_options_init(&status_options, c.GIT_STATUS_OPTIONS_VERSION));
            status_options.show = c.GIT_STATUS_SHOW_WORKDIR_ONLY;
            status_options.flags = c.GIT_STATUS_OPT_INCLUDE_UNTRACKED;
            try std.testing.expectEqual(0, c.git_status_list_new(&status_list, repo, &status_options));
            defer c.git_status_list_free(status_list);
            switch (builtin.os.tag) {
                .windows => try std.testing.expectEqual(5, c.git_status_list_entrycount(status_list)),
                // libgit2 detects the symlink as worktree modified...I'm not sure why
                else => try std.testing.expectEqual(6, c.git_status_list_entrycount(status_list)),
            }
        }

        // index changes
        {
            // add file to index
            var d_txt = try c_dir.createFile(io, "d.txt", .{});
            defer d_txt.close(io);
            try main.run(repo_kind, any_repo_opts, io, allocator, &.{ "add", "c/d.txt" }, work_path, writers);

            // remove file from index
            try main.run(repo_kind, any_repo_opts, io, allocator, &.{ "add", "src/zig/main.zig" }, work_path, writers);

            // get status
            var repo = try rp.Repo(repo_kind, any_repo_opts.toRepoOpts()).open(io, allocator, .{ .path = work_path });
            defer repo.deinit(io, allocator);
            var status = try repo.status(io, allocator);
            defer status.deinit(allocator);

            // check the index_added entries
            try std.testing.expectEqual(1, status.index_added.count());
            try std.testing.expect(status.index_added.contains("c/d.txt"));

            // check the index_modified entries
            try std.testing.expectEqual(1, status.index_modified.count());
            try std.testing.expect(status.index_modified.contains("hello.txt"));

            // check the index_deleted entries
            try std.testing.expectEqual(2, status.index_deleted.count());
            try std.testing.expect(status.index_deleted.contains("src/zig/main.zig"));
            try std.testing.expect(status.index_deleted.contains("one/two/three.txt"));
        }
    }

    // restore
    {
        // there are two modified and two deleted files remaining
        {
            var repo = try rp.Repo(repo_kind, any_repo_opts.toRepoOpts()).open(io, allocator, .{ .path = work_path });
            defer repo.deinit(io, allocator);
            var status = try repo.status(io, allocator);
            defer status.deinit(allocator);

            try std.testing.expectEqual(2, status.work_dir_modified.count());
            try std.testing.expectEqual(2, status.index_deleted.count());
        }

        try main.run(repo_kind, any_repo_opts, io, allocator, &.{ "restore", "README" }, work_path, writers);

        try main.run(repo_kind, any_repo_opts, io, allocator, &.{ "restore", "hello.txt" }, work_path, writers);

        // directories can be restored
        try main.run(repo_kind, any_repo_opts, io, allocator, &.{ "restore", "src" }, work_path, writers);

        // nested paths can be restored
        try main.run(repo_kind, any_repo_opts, io, allocator, &.{ "restore", "one/two/three.txt" }, work_path, writers);

        // remove changes to index
        try main.run(repo_kind, any_repo_opts, io, allocator, &.{ "add", "hello.txt", "src", "one" }, work_path, writers);

        // there are no modified or deleted files remaining
        {
            var repo = try rp.Repo(repo_kind, any_repo_opts.toRepoOpts()).open(io, allocator, .{ .path = work_path });
            defer repo.deinit(io, allocator);
            var status = try repo.status(io, allocator);
            defer status.deinit(allocator);

            try std.testing.expectEqual(0, status.work_dir_modified.count());
            try std.testing.expectEqual(0, status.index_deleted.count());
        }
    }

    // parse objects
    {
        var repo = try rp.Repo(repo_kind, any_repo_opts.toRepoOpts()).open(io, allocator, .{ .path = work_path });
        defer repo.deinit(io, allocator);
        var moment = try repo.core.latestMoment();
        const state = rp.Repo(repo_kind, any_repo_opts.toRepoOpts()).State(.read_only){ .core = &repo.core, .extra = .{ .moment = &moment } };

        // read commit
        var commit_object = try obj.Object(repo_kind, any_repo_opts.toRepoOpts(), .full).init(state, io, allocator, &commit2);
        defer commit_object.deinit();
        try std.testing.expectEqualStrings("second commit", commit_object.content.commit.metadata.message.?);

        // read tree
        var tree_object = try obj.Object(repo_kind, any_repo_opts.toRepoOpts(), .full).init(state, io, allocator, &commit_object.content.commit.tree);
        defer tree_object.deinit();
        try std.testing.expectEqual(7, tree_object.content.tree.entries.count());
    }

    // remove dir from index
    {
        // make a nested dir with a few files
        {
            var bar_dir = try work_dir.createDirPathOpen(io, "foo/bar", .{});
            defer bar_dir.close(io);
            var hi_txt = try bar_dir.createFile(io, "hi.txt", .{});
            defer hi_txt.close(io);
            try hi_txt.writeStreamingAll(io, "hi hi");
            var baz_dir = try work_dir.createDirPathOpen(io, "foo/bar/baz", .{});
            defer baz_dir.close(io);
            var bye_txt = try baz_dir.createFile(io, "bye.txt", .{});
            defer bye_txt.close(io);
            try bye_txt.writeStreamingAll(io, "bye bye");
        }

        // can't remove unindexed file
        try std.testing.expectEqual(error.RemoveIndexPathNotFound, main.run(repo_kind, any_repo_opts, io, allocator, &.{ "rm", "foo/bar/hi.txt" }, work_path, writers));

        // add dir
        try main.run(repo_kind, any_repo_opts, io, allocator, &.{ "add", "foo" }, work_path, writers);

        // make a commit
        try main.run(repo_kind, any_repo_opts, io, allocator, &.{ "commit", "-m", "third commit" }, work_path, writers);

        // untrack hi.txt
        try main.run(repo_kind, any_repo_opts, io, allocator, &.{ "untrack", "foo/bar/hi.txt" }, work_path, writers);

        // can't remove subdir without -r
        try std.testing.expectEqual(error.RecursiveOptionRequired, main.run(repo_kind, any_repo_opts, io, allocator, &.{ "rm", "foo" }, work_path, writers));

        // remove subdir with -r
        try main.run(repo_kind, any_repo_opts, io, allocator, &.{ "rm", "-r", "foo" }, work_path, writers);

        // make sure it was deleted
        var dir_or_err = work_dir.openDir(io, "foo/bar/baz", .{});
        if (dir_or_err) |*dir| {
            dir.close(io);
            return error.UnexpectedDir;
        } else |_| {}

        // but hi.txt was not deleted, because it wasn't in the index
        var hi_txt = try work_dir.openFile(io, "foo/bar/hi.txt", .{});
        defer hi_txt.close(io);

        // add hi.txt back to the index
        try main.run(repo_kind, any_repo_opts, io, allocator, &.{ "add", "foo/bar/hi.txt" }, work_path, writers);
    }

    // get HEAD contents
    const commit3 = blk: {
        var repo = try rp.Repo(repo_kind, any_repo_opts.toRepoOpts()).open(io, allocator, .{ .path = work_path });
        defer repo.deinit(io, allocator);
        var moment = try repo.core.latestMoment();
        const state = rp.Repo(repo_kind, any_repo_opts.toRepoOpts()).State(.read_only){ .core = &repo.core, .extra = .{ .moment = &moment } };
        break :blk try rf.readHeadRecur(repo_kind, any_repo_opts.toRepoOpts(), state, io);
    };

    // create a branch
    try main.run(repo_kind, any_repo_opts, io, allocator, &.{ "branch", "add", "stuff" }, work_path, writers);

    // switch to the branch
    try main.run(repo_kind, any_repo_opts, io, allocator, &.{ "switch", "stuff" }, work_path, writers);

    // check the refs
    {
        var repo = try rp.Repo(repo_kind, any_repo_opts.toRepoOpts()).open(io, allocator, .{ .path = work_path });
        defer repo.deinit(io, allocator);
        var moment = try repo.core.latestMoment();
        const state = rp.Repo(repo_kind, any_repo_opts.toRepoOpts()).State(.read_only){ .core = &repo.core, .extra = .{ .moment = &moment } };
        try std.testing.expectEqual(commit3, try rf.readHeadRecur(repo_kind, any_repo_opts.toRepoOpts(), state, io));
        try std.testing.expectEqual(commit3, try rf.readRecur(repo_kind, any_repo_opts.toRepoOpts(), state, io, .{ .ref = .{ .kind = .head, .name = "stuff" } }));
    }

    // list all branches
    {
        var repo = try rp.Repo(repo_kind, any_repo_opts.toRepoOpts()).open(io, allocator, .{ .path = work_path });
        defer repo.deinit(io, allocator);
        var ref_iter = try repo.listBranches(io, allocator);
        defer ref_iter.deinit(io);
        var count: usize = 0;
        while (try ref_iter.next(io)) |_| count += 1;
        try std.testing.expectEqual(2, count);
    }

    // get the current branch
    {
        var repo = try rp.Repo(repo_kind, any_repo_opts.toRepoOpts()).open(io, allocator, .{ .path = work_path });
        defer repo.deinit(io, allocator);
        var current_branch_buffer = [_]u8{0} ** rf.MAX_REF_CONTENT_SIZE;
        const head = try repo.head(io, &current_branch_buffer);
        try std.testing.expectEqualStrings("stuff", head.ref.name);
    }

    // get the current branch with libgit
    if (repo_kind == .git) {
        var repo: ?*c.git_repository = null;
        try std.testing.expectEqual(0, c.git_repository_open(&repo, work_path));
        defer c.git_repository_free(repo);
        var head: ?*c.git_reference = null;
        try std.testing.expectEqual(0, c.git_repository_head(&head, repo));
        defer c.git_reference_free(head);
        const branch_name = c.git_reference_shorthand(head);
        try std.testing.expectEqualStrings("stuff", std.mem.sliceTo(branch_name, 0));
    }

    // can't delete current branch
    {
        var repo = try rp.Repo(repo_kind, any_repo_opts.toRepoOpts()).open(io, allocator, .{ .path = work_path });
        defer repo.deinit(io, allocator);
        try std.testing.expectEqual(error.CannotDeleteCurrentBranch, repo.removeBranch(io, .{ .name = "stuff" }));
    }

    // make a few commits on the stuff branch
    {
        const hello_txt = try work_dir.openFile(io, "hello.txt", .{ .mode = .read_write });
        defer hello_txt.close(io);

        try hello_txt.setLength(io, 0);
        try hello_txt.writeStreamingAll(io, "hello, world on the stuff branch, commit 3!");

        // add the files
        try main.run(repo_kind, any_repo_opts, io, allocator, &.{ "add", "hello.txt" }, work_path, writers);

        // make a commit
        try main.run(repo_kind, any_repo_opts, io, allocator, &.{ "commit", "-m", "third commit" }, work_path, writers);

        var stuff_txt = try work_dir.createFile(io, "stuff.txt", .{});
        defer stuff_txt.close(io);
        try stuff_txt.writeStreamingAll(io, "this was made on the stuff branch, commit 4!");

        // add the files
        try main.run(repo_kind, any_repo_opts, io, allocator, &.{ "add", "stuff.txt" }, work_path, writers);

        // make a commit
        try main.run(repo_kind, any_repo_opts, io, allocator, &.{ "commit", "-m", "fourth commit" }, work_path, writers);
    }

    // get HEAD contents
    const commit4_stuff = blk: {
        var repo = try rp.Repo(repo_kind, any_repo_opts.toRepoOpts()).open(io, allocator, .{ .path = work_path });
        defer repo.deinit(io, allocator);
        var moment = try repo.core.latestMoment();
        const state = rp.Repo(repo_kind, any_repo_opts.toRepoOpts()).State(.read_only){ .core = &repo.core, .extra = .{ .moment = &moment } };
        break :blk try rf.readHeadRecur(repo_kind, any_repo_opts.toRepoOpts(), state, io);
    };

    // create a branch with slashes
    try main.run(repo_kind, any_repo_opts, io, allocator, &.{ "branch", "add", "a/b/c" }, work_path, writers);

    // make sure the ref is created with subdirs
    if (repo_kind == .git) {
        const ref_file = try test_state.repo_dir.openFile(io, "refs/heads/a/b/c", .{});
        defer ref_file.close(io);
    }

    // list all branches
    {
        var repo = try rp.Repo(repo_kind, any_repo_opts.toRepoOpts()).open(io, allocator, .{ .path = work_path });
        defer repo.deinit(io, allocator);
        var ref_iter = try repo.listBranches(io, allocator);
        defer ref_iter.deinit(io);
        var names = std.StringArrayHashMap(void).init(allocator);
        defer names.deinit();
        while (try ref_iter.next(io)) |ref| try names.put(ref.name, {});
        try std.testing.expectEqual(3, names.count());
        try std.testing.expect(names.contains("a/b/c"));
        try std.testing.expect(names.contains("stuff"));
        try std.testing.expect(names.contains("master"));
    }

    // remove the branch
    try main.run(repo_kind, any_repo_opts, io, allocator, &.{ "branch", "rm", "a/b/c" }, work_path, writers);

    // make sure the subdirs are deleted
    if (repo_kind == .git) {
        try std.testing.expectEqual(error.FileNotFound, test_state.repo_dir.openFile(io, "refs/heads/a/b/c", .{}));
        try std.testing.expectEqual(error.FileNotFound, test_state.repo_dir.openDir(io, "refs/heads/a/b", .{}));
        try std.testing.expectEqual(error.FileNotFound, test_state.repo_dir.openDir(io, "refs/heads/a", .{}));
    }

    // switch to master
    try main.run(repo_kind, any_repo_opts, io, allocator, &.{ "switch", "master" }, work_path, writers);

    // modify files and commit
    {
        const hello_txt = try work_dir.openFile(io, "hello.txt", .{ .mode = .read_write });
        defer hello_txt.close(io);

        try hello_txt.setLength(io, 0);
        try hello_txt.writeStreamingAll(io, "hello, world once again!");

        const goodbye_txt = try work_dir.openFile(io, "goodbye.txt", .{ .mode = .read_write });
        defer goodbye_txt.close(io);

        try goodbye_txt.setLength(io, 0);
        try goodbye_txt.writeStreamingAll(io, "goodbye, world once again!");

        // add the files
        try main.run(repo_kind, any_repo_opts, io, allocator, &.{ "add", "hello.txt", "goodbye.txt" }, work_path, writers);

        // make a commit
        try main.run(repo_kind, any_repo_opts, io, allocator, &.{ "commit", "-m", "fourth commit" }, work_path, writers);
    }

    // get HEAD contents
    const commit4 = blk: {
        var repo = try rp.Repo(repo_kind, any_repo_opts.toRepoOpts()).open(io, allocator, .{ .path = work_path });
        defer repo.deinit(io, allocator);
        var moment = try repo.core.latestMoment();
        const state = rp.Repo(repo_kind, any_repo_opts.toRepoOpts()).State(.read_only){ .core = &repo.core, .extra = .{ .moment = &moment } };
        break :blk try rf.readHeadRecur(repo_kind, any_repo_opts.toRepoOpts(), state, io);
    };

    // make sure the most recent branch name points to the most recent commit
    {
        var repo = try rp.Repo(repo_kind, any_repo_opts.toRepoOpts()).open(io, allocator, .{ .path = work_path });
        defer repo.deinit(io, allocator);
        var moment = try repo.core.latestMoment();
        const state = rp.Repo(repo_kind, any_repo_opts.toRepoOpts()).State(.read_only){ .core = &repo.core, .extra = .{ .moment = &moment } };
        try std.testing.expectEqual(commit4, try rf.readRecur(repo_kind, any_repo_opts.toRepoOpts(), state, io, .{ .ref = .{ .kind = .head, .name = "master" } }));
    }

    // log
    {
        var repo = try rp.Repo(repo_kind, any_repo_opts.toRepoOpts()).open(io, allocator, .{ .path = work_path });
        defer repo.deinit(io, allocator);
        var iter = try repo.log(io, allocator, null);
        defer iter.deinit();

        {
            var object = try iter.next() orelse return error.ExpectedObject;
            defer object.deinit();
            try std.testing.expectEqual(commit4, object.oid);

            try object.object_reader.seekTo(object.content.commit.message_position);
            const message = try object.object_reader.interface.allocRemaining(allocator, .limited(any_repo_opts.max_read_size));
            defer allocator.free(message);
            try std.testing.expectEqualStrings("fourth commit", message);
        }

        {
            var object = try iter.next() orelse return error.ExpectedObject;
            defer object.deinit();
            try std.testing.expectEqual(commit3, object.oid);

            try object.object_reader.seekTo(object.content.commit.message_position);
            const message = try object.object_reader.interface.allocRemaining(allocator, .limited(any_repo_opts.max_read_size));
            defer allocator.free(message);
            try std.testing.expectEqualStrings("third commit", message);
        }

        {
            var object = try iter.next() orelse return error.ExpectedObject;
            defer object.deinit();
            try std.testing.expectEqual(commit2, object.oid);

            try object.object_reader.seekTo(object.content.commit.message_position);
            const message = try object.object_reader.interface.allocRemaining(allocator, .limited(any_repo_opts.max_read_size));
            defer allocator.free(message);
            try std.testing.expectEqualStrings("second commit", message);
        }

        {
            var object = try iter.next() orelse return error.ExpectedObject;
            defer object.deinit();
            try std.testing.expectEqual(commit1, object.oid);

            try object.object_reader.seekTo(object.content.commit.message_position);
            const message = try object.object_reader.interface.allocRemaining(allocator, .limited(any_repo_opts.max_read_size));
            defer allocator.free(message);
            try std.testing.expectEqualStrings("first commit", message);
        }

        try std.testing.expectEqual(null, try iter.next());
    }

    // common ancestor
    {
        var repo = try rp.Repo(repo_kind, any_repo_opts.toRepoOpts()).open(io, allocator, .{ .path = work_path });
        defer repo.deinit(io, allocator);
        var moment = try repo.core.latestMoment();
        const state = rp.Repo(repo_kind, any_repo_opts.toRepoOpts()).State(.read_only){ .core = &repo.core, .extra = .{ .moment = &moment } };
        const ancestor_commit = try mrg.commonAncestor(repo_kind, any_repo_opts.toRepoOpts(), state, io, allocator, &commit4, &commit4_stuff);
        try std.testing.expectEqualStrings(&commit3, &ancestor_commit);
    }

    // merge
    {
        // both branches modified hello.txt, so there is a conflict
        try std.testing.expectError(error.HandledError, main.run(repo_kind, any_repo_opts, io, allocator, &.{ "merge", "stuff" }, work_path, writers));

        // there are conflicts in the index
        {
            var repo = try rp.Repo(repo_kind, any_repo_opts.toRepoOpts()).open(io, allocator, .{ .path = work_path });
            defer repo.deinit(io, allocator);
            var status = try repo.status(io, allocator);
            defer status.deinit(allocator);
            try std.testing.expect(status.unresolved_conflicts.count() > 0);
        }

        // abort the merge
        try main.run(repo_kind, any_repo_opts, io, allocator, &.{ "merge", "--abort" }, work_path, writers);

        // there are no conflicts in the index
        {
            var repo = try rp.Repo(repo_kind, any_repo_opts.toRepoOpts()).open(io, allocator, .{ .path = work_path });
            defer repo.deinit(io, allocator);
            var status = try repo.status(io, allocator);
            defer status.deinit(allocator);
            try std.testing.expectEqual(0, status.unresolved_conflicts.count());
        }

        // merge again
        try std.testing.expectError(error.HandledError, main.run(repo_kind, any_repo_opts, io, allocator, &.{ "merge", "stuff" }, work_path, writers));

        // solve the conflict
        {
            const hello_txt = try work_dir.openFile(io, "hello.txt", .{ .mode = .read_write });
            defer hello_txt.close(io);

            try hello_txt.setLength(io, 0);
            try hello_txt.writeStreamingAll(io, "hello, world once again!");

            try main.run(repo_kind, any_repo_opts, io, allocator, &.{ "add", "hello.txt" }, work_path, writers);

            try main.run(repo_kind, any_repo_opts, io, allocator, &.{ "merge", "--continue" }, work_path, writers);
        }

        // change from stuff exists
        {
            const content = try work_dir.readFileAlloc(io, "stuff.txt", allocator, .limited(1024));
            defer allocator.free(content);
            try std.testing.expectEqualStrings("this was made on the stuff branch, commit 4!", content);
        }

        // change from master still exists
        {
            const content = try work_dir.readFileAlloc(io, "goodbye.txt", allocator, .limited(1024));
            defer allocator.free(content);
            try std.testing.expectEqualStrings("goodbye, world once again!", content);
        }
    }

    // get HEAD contents
    const commit5 = blk: {
        var repo = try rp.Repo(repo_kind, any_repo_opts.toRepoOpts()).open(io, allocator, .{ .path = work_path });
        defer repo.deinit(io, allocator);
        var moment = try repo.core.latestMoment();
        const state = rp.Repo(repo_kind, any_repo_opts.toRepoOpts()).State(.read_only){ .core = &repo.core, .extra = .{ .moment = &moment } };
        break :blk try rf.readHeadRecur(repo_kind, any_repo_opts.toRepoOpts(), state, io);
    };

    // config
    {
        try main.run(repo_kind, any_repo_opts, io, allocator, &.{ "config", "add", "core.editor", "vim" }, work_path, writers);
        try main.run(repo_kind, any_repo_opts, io, allocator, &.{ "config", "add", "branch.master.remote", "origin" }, work_path, writers);
        {
            var repo = try rp.Repo(repo_kind, any_repo_opts.toRepoOpts()).open(io, allocator, .{ .path = work_path });
            defer repo.deinit(io, allocator);

            var config = try repo.listConfig(io, allocator);
            defer config.deinit();

            const core_section = config.sections.get("core").?;
            try std.testing.expectEqual(1, core_section.count());

            const branch_master_section = config.sections.get("branch.master").?;
            try std.testing.expectEqual(1, branch_master_section.count());
            try std.testing.expectEqualStrings("origin", branch_master_section.get("remote").?);
        }

        try main.run(repo_kind, any_repo_opts, io, allocator, &.{ "config", "rm", "branch.master.remote" }, work_path, writers);
        {
            var repo = try rp.Repo(repo_kind, any_repo_opts.toRepoOpts()).open(io, allocator, .{ .path = work_path });
            defer repo.deinit(io, allocator);

            var config = try repo.listConfig(io, allocator);
            defer config.deinit();

            try std.testing.expectEqual(null, config.sections.get("branch.master"));
        }

        // don't allow invalid names
        try std.testing.expectEqual(error.InvalidConfigName, main.run(repo_kind, any_repo_opts, io, allocator, &.{ "config", "add", "core.editor#hi", "vim" }, work_path, writers));

        // do allow values with spaces
        try main.run(repo_kind, any_repo_opts, io, allocator, &.{ "config", "add", "user.name", "radar roark" }, work_path, writers);
        {
            var repo = try rp.Repo(repo_kind, any_repo_opts.toRepoOpts()).open(io, allocator, .{ .path = work_path });
            defer repo.deinit(io, allocator);

            var config = try repo.listConfig(io, allocator);
            defer config.deinit();

            const user_section = config.sections.get("user").?;
            try std.testing.expectEqualStrings("radar roark", user_section.get("name").?);
        }

        // do allow additional characters in subsection names
        try main.run(repo_kind, any_repo_opts, io, allocator, &.{ "config", "add", "branch.\"hello.world\".remote", "radar roark" }, work_path, writers);
        {
            var repo = try rp.Repo(repo_kind, any_repo_opts.toRepoOpts()).open(io, allocator, .{ .path = work_path });
            defer repo.deinit(io, allocator);

            var config = try repo.listConfig(io, allocator);
            defer config.deinit();

            const branch_hi_section = config.sections.get("branch.\"hello.world\"").?;
            try std.testing.expectEqual(1, branch_hi_section.count());
        }

        // section and var names are forcibly lower-cased, but not the subsection name
        try main.run(repo_kind, any_repo_opts, io, allocator, &.{ "config", "add", "BRANCH.MASTER.REMOTE", "origin" }, work_path, writers);
        {
            var repo = try rp.Repo(repo_kind, any_repo_opts.toRepoOpts()).open(io, allocator, .{ .path = work_path });
            defer repo.deinit(io, allocator);

            var config = try repo.listConfig(io, allocator);
            defer config.deinit();

            const branch_master_section = config.sections.get("branch.MASTER").?;
            try std.testing.expectEqual(1, branch_master_section.count());
            try std.testing.expectEqualStrings("origin", branch_master_section.get("remote").?);
        }

        try main.run(repo_kind, any_repo_opts, io, allocator, &.{ "config", "list" }, work_path, writers);
    }

    // remote
    {
        try main.run(repo_kind, any_repo_opts, io, allocator, &.{ "remote", "add", "origin", "http://localhost:3000" }, work_path, writers);
        {
            var repo = try rp.Repo(repo_kind, any_repo_opts.toRepoOpts()).open(io, allocator, .{ .path = work_path });
            defer repo.deinit(io, allocator);

            var remote = try repo.listRemotes(io, allocator);
            defer remote.deinit();

            try std.testing.expect(null != remote.sections.get("origin"));
        }

        try main.run(repo_kind, any_repo_opts, io, allocator, &.{ "remote", "rm", "origin" }, work_path, writers);
        {
            var repo = try rp.Repo(repo_kind, any_repo_opts.toRepoOpts()).open(io, allocator, .{ .path = work_path });
            defer repo.deinit(io, allocator);

            var remote = try repo.listRemotes(io, allocator);
            defer remote.deinit();

            try std.testing.expectEqual(null, remote.sections.get("origin"));
        }

        try main.run(repo_kind, any_repo_opts, io, allocator, &.{ "remote", "list" }, work_path, writers);
    }

    // tag
    {
        try main.run(repo_kind, any_repo_opts, io, allocator, &.{ "tag", "add", "ann", "-m", "this is an annotated tag" }, work_path, writers);

        {
            var repo = try rp.Repo(repo_kind, any_repo_opts.toRepoOpts()).open(io, allocator, .{ .path = work_path });
            defer repo.deinit(io, allocator);
            var moment = try repo.core.latestMoment();
            const state = rp.Repo(repo_kind, any_repo_opts.toRepoOpts()).State(.read_only){ .core = &repo.core, .extra = .{ .moment = &moment } };

            const tag_oid = (try rf.readRecur(repo_kind, any_repo_opts.toRepoOpts(), state, io, .{ .ref = .{ .kind = .tag, .name = "ann" } })) orelse return error.TagNotFound;
            var tag_object = try obj.Object(repo_kind, any_repo_opts.toRepoOpts(), .full).init(state, io, allocator, &tag_oid);
            defer tag_object.deinit();

            try tag_object.object_reader.seekTo(tag_object.content.tag.message_position);
            const message = try tag_object.object_reader.interface.allocRemaining(allocator, .limited(any_repo_opts.max_read_size));
            defer allocator.free(message);
            try std.testing.expectEqualStrings("this is an annotated tag", message);

            // common ancester with a tag
            const ancestor_commit = try mrg.commonAncestor(repo_kind, any_repo_opts.toRepoOpts(), state, io, allocator, &tag_oid, &commit4_stuff);
            try std.testing.expectEqualStrings(&commit4_stuff, &ancestor_commit);
        }

        try main.run(repo_kind, any_repo_opts, io, allocator, &.{ "tag", "list" }, work_path, writers);

        try main.run(repo_kind, any_repo_opts, io, allocator, &.{ "tag", "rm", "ann" }, work_path, writers);
    }

    return commit5;
}
