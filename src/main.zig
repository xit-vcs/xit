//! you're looking at my hopeless attempt to implement
//! the successor to git. behold the three rules of xit:
//!
//! 1. keep the codebase small and stupid.
//! 2. prefer simple 80% solutions over complex 100% solutions.
//! 3. never take yourself too seriously. be a dork, and you'll
//! attract dorks. together, we'll make a glorious pack of strays.
//!
//! "C'mon Alex! You always dreamt about going on a big adventure!
//!  Let this be our first!" -- Lunar: Silver Star Story

const std = @import("std");
const builtin = @import("builtin");
const cmd = @import("./command.zig");
const rp = @import("./repo.zig");
const ui = @import("./ui.zig");
const hash = @import("./hash.zig");
const df = @import("./diff.zig");
const work = @import("./workdir.zig");
const mrg = @import("./merge.zig");
const obj = @import("./object.zig");
const tr = @import("./tree.zig");
const rf = @import("./ref.zig");
const net_refspec = @import("./net/refspec.zig");
const server_common = @import("./net/server/common.zig");
const server_http_backend = @import("./net/server/http_backend.zig");

pub const RunOpts = struct {
    out: *std.Io.Writer,
    err: *std.Io.Writer,
    environ_map: *std.process.Environ.Map,
};

const ProgressCtx = struct {
    run_opts: RunOpts,
    clear_line: *bool,
    node: *?std.Progress.Node,

    pub fn run(self: @This(), io: std.Io, event: rp.ProgressEvent) !void {
        switch (event) {
            .start => |start| {
                if (self.node.*) |node| {
                    node.end();
                }
                const name = switch (start.kind) {
                    .writing_object_from_pack => "Writing object from pack",
                    .writing_object => "Writing object",
                    .writing_patch => "Writing patch",
                    .sending_bytes => "Sending bytes",
                };
                self.node.* = std.Progress.start(io, .{ .root_name = name, .estimated_total_items = start.estimated_total_items });
            },
            .complete_one => if (self.node.*) |node| node.completeOne(),
            .complete_total => |complete_total| if (self.node.*) |node| node.setCompletedItems(complete_total.count),
            .child_text => |text| if (self.node.*) |node| {
                _ = node.start(text, 0);
            },
            .end => if (self.node.*) |node| {
                node.end();
                self.node.* = null;
            },
            .text => |text| {
                if (self.clear_line.*) {
                    try self.run_opts.out.print("\x1B[F", .{});
                }
                try self.run_opts.out.print("{s}\n", .{text});
                self.clear_line.* = true;
            },
        }
    }
};

/// this is meant to be the main entry point if you wanted to use xit
/// as a CLI tool. to use xit programmatically, build a Repo struct
/// and call methods on it directly. to use xit subconsciously, just
/// think about it really often and eventually you'll dream about it.
pub fn run(
    comptime repo_kind: rp.RepoKind,
    comptime any_repo_opts: rp.AnyRepoOpts(repo_kind),
    io: std.Io,
    allocator: std.mem.Allocator,
    args: []const []const u8,
    cwd_path: []const u8,
    run_opts: RunOpts,
) !void {
    var cmd_args = try cmd.CommandArgs.init(allocator, args);
    defer cmd_args.deinit();

    switch (try cmd.CommandDispatch(repo_kind, any_repo_opts.toRepoOpts().hash).init(&cmd_args)) {
        .invalid => |invalid| switch (invalid) {
            .command => |command| {
                try run_opts.err.print("\"{s}\" is not a valid command\n\n", .{command});
                try cmd.printHelp(null, run_opts.err);
                return error.HandledError;
            },
            .argument => |argument| {
                try run_opts.err.print("\"{s}\" is not a valid argument\n\n", .{argument.value});
                try cmd.printHelp(argument.command, run_opts.err);
                return error.HandledError;
            },
        },
        .help => |cmd_kind_maybe| try cmd.printHelp(cmd_kind_maybe, run_opts.out),
        .tui => |cmd_kind_maybe| if (any_repo_opts.hash) |hash_kind| {
            var repo = try rp.Repo(repo_kind, any_repo_opts.toRepoOptsWithHash(hash_kind)).open(io, allocator, .{ .path = cwd_path });
            defer repo.deinit(io, allocator);
            try ui.start(repo_kind, any_repo_opts.toRepoOptsWithHash(hash_kind), &repo, io, allocator, cmd_kind_maybe);
        } else {
            // if no hash was specified, use AnyRepo to detect the hash being used
            var any_repo = try rp.AnyRepo(repo_kind, any_repo_opts).open(io, allocator, .{ .path = cwd_path });
            defer any_repo.deinit(io, allocator);
            switch (any_repo) {
                inline else => |*repo| try ui.start(repo.self_repo_kind, repo.self_repo_opts, repo, io, allocator, cmd_kind_maybe),
            }
        },
        .cli => |cli_cmd| switch (cli_cmd) {
            .init => |init_cmd| {
                const repo_opts = comptime if (any_repo_opts.hash) |hash_kind|
                    any_repo_opts.toRepoOptsWithHash(hash_kind)
                else
                    // if no hash was specified, just use the default hash
                    any_repo_opts.toRepoOpts();
                const work_path = try std.fs.path.resolve(allocator, &.{ cwd_path, init_cmd.dir });
                defer allocator.free(work_path);
                var repo = try rp.Repo(repo_kind, repo_opts).init(io, allocator, .{ .cwd_path = cwd_path, .path = work_path });
                defer repo.deinit(io, allocator);

                try run_opts.out.print(
                    \\congrats, you just created a new repo! aren't you special.
                    \\try setting your name and email like this:
                    \\
                    \\    xit config add user.name foo
                    \\    xit config add user.email foo@bar
                    \\
                , .{});
            },
            .clone => |clone_cmd| {
                const work_path = try std.fs.path.resolve(allocator, &.{ cwd_path, clone_cmd.local_path });
                defer allocator.free(work_path);
                var clear_line = false;
                var progress_node: ?std.Progress.Node = null;
                var repo = try rp.Repo(repo_kind, any_repo_opts.toRepoOpts()).clone(
                    io,
                    allocator,
                    clone_cmd.url,
                    cwd_path,
                    work_path,
                    .{ .progress_ctx = if (any_repo_opts.ProgressCtx == void) {} else .{ .run_opts = run_opts, .clear_line = &clear_line, .node = &progress_node } },
                );
                defer repo.deinit(io, allocator);

                if (repo_kind == .xit) {
                    try run_opts.out.print(
                        \\
                        \\clone complete!
                        \\
                    , .{});
                }
            },
            else => {
                // some commands allow the path to be specified. for all others, just use the cwd path.
                const work_path_maybe = switch (cli_cmd) {
                    .upload_pack => |upload_pack| try std.fs.path.resolve(allocator, &.{ cwd_path, upload_pack.dir }),
                    .receive_pack => |receive_pack| try std.fs.path.resolve(allocator, &.{ cwd_path, receive_pack.dir }),
                    .http_backend => server_http_backend.resolveDir(allocator, cwd_path, run_opts.environ_map) catch {
                        var http_stdout_buf: [any_repo_opts.buffer_size]u8 = undefined;
                        var http_stdout_writer = std.Io.File.stdout().writer(io, &http_stdout_buf);
                        try server_http_backend.sendNotFound(&http_stdout_writer.interface);
                        return;
                    },
                    else => null,
                };
                defer if (work_path_maybe) |work_path| allocator.free(work_path);
                const work_path = work_path_maybe orelse cwd_path;

                if (any_repo_opts.hash) |hash_kind| {
                    var repo = try rp.Repo(repo_kind, any_repo_opts.toRepoOptsWithHash(hash_kind)).open(io, allocator, .{ .path = work_path });
                    defer repo.deinit(io, allocator);
                    try runCommand(repo_kind, any_repo_opts.toRepoOptsWithHash(hash_kind), &repo, io, allocator, cli_cmd, run_opts);
                } else {
                    // if no hash was specified, use AnyRepo to detect the hash being used
                    var any_repo = try rp.AnyRepo(repo_kind, any_repo_opts).open(io, allocator, .{ .path = work_path });
                    defer any_repo.deinit(io, allocator);
                    switch (any_repo) {
                        inline else => |*repo| {
                            const cmd_maybe = try cmd.Command(repo.self_repo_kind, repo.self_repo_opts.hash).initMaybe(&cmd_args);
                            try runCommand(repo.self_repo_kind, repo.self_repo_opts, repo, io, allocator, cmd_maybe orelse return error.InvalidCommand, run_opts);
                        },
                    }
                }
            },
        },
    }
}

/// like `run` except it prints user-friendly error messages
pub fn runPrint(
    comptime repo_kind: rp.RepoKind,
    comptime any_repo_opts: rp.AnyRepoOpts(repo_kind),
    io: std.Io,
    allocator: std.mem.Allocator,
    args: []const []const u8,
    cwd_path: []const u8,
    run_opts: RunOpts,
) !void {
    run(repo_kind, any_repo_opts, io, allocator, args, cwd_path, run_opts) catch |err| switch (err) {
        error.RepoNotFound => {
            try run_opts.err.print(
                \\repo not found, dummy.
                \\either you're in the wrong place or you need to make a new one like this:
                \\
                \\
            , .{});
            try cmd.printHelp(.init, run_opts.err);
            return error.HandledError;
        },
        error.RepoAlreadyExists => {
            try run_opts.err.print(
                \\repo already exists, dummy.
                \\two repos in the same directory makes no sense.
                \\think about it.
                \\
            , .{});
            return error.HandledError;
        },
        error.CannotRemoveFileWithStagedAndUnstagedChanges, error.CannotRemoveFileWithStagedChanges, error.CannotRemoveFileWithUnstagedChanges => {
            try run_opts.err.print("a file has uncommitted changes. if you really want to do it, throw caution into the wind by adding the -f flag.\n", .{});
            return error.HandledError;
        },
        error.EmptyCommit => {
            try run_opts.err.print("you haven't added anything to commit yet. if you really want to commit anyway, add the --allow-empty flag and no one will judge you.\n", .{});
            return error.HandledError;
        },
        error.AddIndexPathNotFound => {
            try run_opts.err.print("a path you are adding does not exist\n", .{});
            return error.HandledError;
        },
        error.RemoveIndexPathNotFound => {
            try run_opts.err.print("a path you are removing does not exist\n", .{});
            return error.HandledError;
        },
        error.RecursiveOptionRequired => {
            try run_opts.err.print("to do this on a dir, add the -r flag\n", .{});
            return error.HandledError;
        },
        error.RefNotFound => {
            try run_opts.err.print("ref does not exist\n", .{});
            return error.HandledError;
        },
        error.BranchAlreadyExists => {
            try run_opts.err.print("branch already exists\n", .{});
            return error.HandledError;
        },
        error.UserConfigNotFound => {
            try run_opts.err.print(
                \\you need to set your name and email, mystery man. you can do it like this:
                \\
                \\    xit config add user.name foo
                \\    xit config add user.email foo@bar
                \\
            , .{});
            return error.HandledError;
        },
        error.SubmodulesNotSupported => {
            try run_opts.err.print("repos with submodules aren't supported right now, sowwy\n", .{});
            return error.HandledError;
        },
        error.InvalidMergeSource => {
            try run_opts.err.print("your merge source doesn't look right and you should feel bad\n", .{});
            return error.HandledError;
        },
        error.InvalidSwitchTarget => {
            try run_opts.err.print("your switch target doesn't look right and you should feel bad\n", .{});
            return error.HandledError;
        },
        error.UnfinishedMergeInProgress => {
            try run_opts.err.print("there is an unfinished merge in progress! use `--continue` or `--abort` to finish it.\n", .{});
            return error.HandledError;
        },
        error.OtherMergeInProgress => {
            try run_opts.err.print("there's another merge already in progress! use `--continue` or `--abort` to finish it.\n", .{});
            return error.HandledError;
        },
        error.CannotContinueMergeWithUnresolvedConflicts => {
            try run_opts.err.print("you haven't resolved all the conflicts! after fixing, run `xit add` on them.\n", .{});
            return error.HandledError;
        },
        error.RemoteRefContainsCommitsNotFoundLocally => {
            try run_opts.err.print(
                \\a ref you are pushing to contains commits you don't have locally.
                \\you either need to retrieve them with `xit fetch` and then `xit merge`,
                \\or if you want to obliterate them like a badass, run this command with `-f`.
                \\
            , .{});
            return error.HandledError;
        },
        error.RemoteRefContainsIncompatibleHistory => {
            try run_opts.err.print(
                \\a ref you are pushing to has commits with an incompatible history.
                \\if you want to obliterate them like a badass, run this command with `-f`.
                \\
            , .{});
            return error.HandledError;
        },
        error.BrokenPipe => {},
        else => |e| return e,
    };
}

/// executes a command on the given repo
fn runCommand(
    comptime repo_kind: rp.RepoKind,
    comptime repo_opts: rp.RepoOpts(repo_kind),
    repo: *rp.Repo(repo_kind, repo_opts),
    io: std.Io,
    allocator: std.mem.Allocator,
    command: cmd.Command(repo_kind, repo_opts.hash),
    run_opts: RunOpts,
) !void {
    switch (command) {
        .init => {},
        .add => |add_cmd| try repo.add(io, allocator, add_cmd.paths),
        .unadd => |unadd_cmd| try repo.unadd(io, allocator, unadd_cmd.paths, unadd_cmd.opts),
        .untrack => |untrack_cmd| try repo.untrack(io, allocator, untrack_cmd.paths, untrack_cmd.opts),
        .rm => |rm_cmd| try repo.remove(io, allocator, rm_cmd.paths, rm_cmd.opts),
        .commit => |commit_cmd| _ = try repo.commit(io, allocator, commit_cmd),
        .tag => |tag_cmd| switch (tag_cmd) {
            .list => {
                var ref_iter = try repo.listTags(io, allocator);
                defer ref_iter.deinit(io);

                while (try ref_iter.next(io)) |ref| {
                    try run_opts.out.print("{s}\n", .{ref.name});
                }
            },
            .add => |add_tag| _ = try repo.addTag(io, allocator, add_tag),
            .remove => |rm_tag| try repo.removeTag(io, rm_tag),
        },
        .status => {
            var head_buffer = [_]u8{0} ** rf.MAX_REF_CONTENT_SIZE;
            switch (try repo.head(io, &head_buffer)) {
                .ref => |ref| try run_opts.out.print("on branch {s}\n\n", .{ref.name}),
                .oid => |oid| try run_opts.out.print("HEAD detached at {s}\n\n", .{oid}),
            }

            var stat = try repo.status(io, allocator);
            defer stat.deinit(allocator);

            for (stat.untracked.values()) |entry| {
                try run_opts.out.print("?? {s}\n", .{entry.path});
            }

            for (stat.work_dir_modified.values()) |entry| {
                try run_opts.out.print(" M {s}\n", .{entry.path});
            }

            for (stat.work_dir_deleted.keys()) |path| {
                try run_opts.out.print(" D {s}\n", .{path});
            }

            for (stat.index_added.keys()) |path| {
                try run_opts.out.print("A  {s}\n", .{path});
            }

            for (stat.index_modified.keys()) |path| {
                try run_opts.out.print("M  {s}\n", .{path});
            }

            for (stat.index_deleted.keys()) |path| {
                try run_opts.out.print("D  {s}\n", .{path});
            }

            for (stat.unresolved_conflicts.keys(), stat.unresolved_conflicts.values()) |path, conflict| {
                if (conflict.base) {
                    if (conflict.target) {
                        if (conflict.source) {
                            try run_opts.out.print("UU {s}\n", .{path}); // both modified
                        } else {
                            try run_opts.out.print("UD {s}\n", .{path}); // deleted by them
                        }
                    } else {
                        if (conflict.source) {
                            try run_opts.out.print("DU {s}\n", .{path}); // deleted by us
                        } else {
                            return error.InvalidConflict;
                        }
                    }
                } else {
                    if (conflict.target) {
                        if (conflict.source) {
                            try run_opts.out.print("AA {s}\n", .{path}); // both added
                        } else {
                            try run_opts.out.print("AU {s}\n", .{path}); // added by us
                        }
                    } else {
                        if (conflict.source) {
                            try run_opts.out.print("UA {s}\n", .{path}); // added by them
                        } else {
                            return error.InvalidConflict;
                        }
                    }
                }
            }
        },
        .diff_dir, .diff_added => |diff_cmd| {
            const DiffState = union(df.DiffKind) {
                work_dir: work.Status(repo_kind, repo_opts),
                index: work.Status(repo_kind, repo_opts),
                tree: tr.TreeDiff(repo_kind, repo_opts),

                fn deinit(diff_state: *@This(), inner_allocator: std.mem.Allocator) void {
                    switch (diff_state.*) {
                        .work_dir => diff_state.work_dir.deinit(inner_allocator),
                        .index => diff_state.index.deinit(inner_allocator),
                        .tree => diff_state.tree.deinit(),
                    }
                }
            };
            var diff_state: DiffState = switch (diff_cmd) {
                .work_dir => .{ .work_dir = try repo.status(io, allocator) },
                .index => .{ .index = try repo.status(io, allocator) },
                .tree => |tree| .{
                    .tree = try repo.treeDiff(io, allocator, if (tree.old) |old| &old else null, if (tree.new) |new| &new else null),
                },
            };
            defer diff_state.deinit(allocator);
            var diff_iter = try repo.filePairs(io, allocator, switch (diff_cmd) {
                .work_dir => |work_dir| .{
                    .work_dir = .{
                        .conflict_diff_kind = work_dir.conflict_diff_kind,
                        .status = &diff_state.work_dir,
                    },
                },
                .index => .{
                    .index = .{ .status = &diff_state.index },
                },
                .tree => .{
                    .tree = .{ .tree_diff = &diff_state.tree },
                },
            });

            while (try diff_iter.next()) |*line_iter_pair_ptr| {
                var line_iter_pair = line_iter_pair_ptr.*;
                defer line_iter_pair.deinit();
                var hunk_iter = try df.HunkIterator(repo_kind, repo_opts).init(allocator, &line_iter_pair.a, &line_iter_pair.b);
                defer hunk_iter.deinit(allocator);
                for (hunk_iter.header_lines.items) |header_line| {
                    try run_opts.out.print("{s}\n", .{header_line});
                }
                while (try hunk_iter.next(allocator)) |*hunk_ptr| {
                    var hunk = hunk_ptr.*;
                    defer hunk.deinit(allocator);
                    const offsets = hunk.offsets();
                    try run_opts.out.print("@@ -{},{} +{},{} @@\n", .{
                        offsets.del_start,
                        offsets.del_count,
                        offsets.ins_start,
                        offsets.ins_count,
                    });
                    for (hunk.edits.items) |edit| {
                        const line = switch (edit) {
                            .eql => |eql| try hunk_iter.line_iter_b.get(eql.new_line.num),
                            .ins => |ins| try hunk_iter.line_iter_b.get(ins.new_line.num),
                            .del => |del| try hunk_iter.line_iter_a.get(del.old_line.num),
                        };
                        defer switch (edit) {
                            .eql => hunk_iter.line_iter_b.free(line),
                            .ins => hunk_iter.line_iter_b.free(line),
                            .del => hunk_iter.line_iter_a.free(line),
                        };
                        try run_opts.out.print("{s} {s}\n", .{
                            switch (edit) {
                                .eql => " ",
                                .ins => "+",
                                .del => "-",
                            },
                            line,
                        });
                    }
                }
            }
        },
        .branch => |branch_cmd| {
            switch (branch_cmd) {
                .list => {
                    var head_buffer = [_]u8{0} ** rf.MAX_REF_CONTENT_SIZE;
                    const current_branch_name = switch (try repo.head(io, &head_buffer)) {
                        .ref => |ref| ref.name,
                        .oid => "",
                    };

                    var ref_iter = try repo.listBranches(io, allocator);
                    defer ref_iter.deinit(io);

                    while (try ref_iter.next(io)) |ref| {
                        const prefix = if (std.mem.eql(u8, current_branch_name, ref.name)) "*" else " ";
                        try run_opts.out.print("{s} {s}\n", .{ prefix, ref.name });
                    }
                },
                .add => |add_branch| try repo.addBranch(io, add_branch),
                .remove => |rm_branch| try repo.removeBranch(io, rm_branch),
            }
        },
        .switch_dir, .reset, .reset_dir => |switch_dir_cmd| {
            var switch_result = try repo.switchDir(io, allocator, switch_dir_cmd);
            defer switch_result.deinit();
            switch (switch_result.result) {
                .success => {},
                .conflict => |conflict| {
                    try run_opts.err.print(
                        \\conflicts detected in the following file paths:
                        \\
                    , .{});
                    for (conflict.stale_files.keys()) |path| {
                        try run_opts.err.print("  {s}\n", .{path});
                    }
                    for (conflict.stale_dirs.keys()) |path| {
                        try run_opts.err.print("  {s}\n", .{path});
                    }
                    for (conflict.untracked_overwritten.keys()) |path| {
                        try run_opts.err.print("  {s}\n", .{path});
                    }
                    for (conflict.untracked_removed.keys()) |path| {
                        try run_opts.err.print("  {s}\n", .{path});
                    }
                    try run_opts.err.print("if you really want to continue, throw caution into the wind by adding the -f flag\n", .{});
                    return error.HandledError;
                },
            }
        },
        .reset_add => |reset_add_cmd| try repo.resetAdd(io, reset_add_cmd),
        .restore => |restore_cmd| try repo.restore(io, allocator, restore_cmd.path),
        .log => |heads| {
            var start_oids = try std.ArrayList([hash.hexLen(repo_opts.hash)]u8).initCapacity(allocator, heads.len);
            defer start_oids.deinit(allocator);
            for (heads) |ref_or_oid| {
                const oid_maybe = switch (ref_or_oid) {
                    .ref => |ref| try repo.readRef(io, ref),
                    .oid => |oid| oid.*,
                };
                const oid = oid_maybe orelse {
                    var ref_path_buffer = [_]u8{0} ** rf.MAX_REF_CONTENT_SIZE;
                    try run_opts.err.print("invalid ref: {s}\n", .{switch (ref_or_oid) {
                        .oid => |oid| oid,
                        .ref => |ref| try ref.toPath(&ref_path_buffer),
                    }});
                    return error.HandledError;
                };
                start_oids.appendAssumeCapacity(oid);
            }

            var commit_iter = try repo.log(io, allocator, if (start_oids.items.len > 0) start_oids.items else null);
            defer commit_iter.deinit();
            while (try commit_iter.next()) |commit_object| {
                defer commit_object.deinit();
                try run_opts.out.print("commit {s}\n", .{commit_object.oid});
                if (commit_object.content.commit.metadata.author) |author| {
                    try run_opts.out.print("author: {s}\n", .{author});
                }
                try run_opts.out.print("\n", .{});

                try commit_object.object_reader.seekTo(commit_object.content.commit.message_position);

                // for each line...
                while (commit_object.object_reader.interface.peekByte()) |_| {
                    var line_writer = std.Io.Writer.Allocating.init(allocator);
                    defer line_writer.deinit();
                    _ = try commit_object.object_reader.interface.streamDelimiterLimit(&line_writer.writer, '\n', .limited(repo_opts.max_line_size));

                    // skip delimiter
                    if (commit_object.object_reader.interface.bufferedLen() > 0) {
                        commit_object.object_reader.interface.toss(1);
                    }

                    try run_opts.out.print("    {s}\n", .{line_writer.written()});
                } else |err| switch (err) {
                    error.EndOfStream => {},
                    else => |e| return e,
                }

                try run_opts.out.print("\n", .{});
            }
        },
        .merge, .cherry_pick => |merge_cmd| {
            var clear_line = false;
            var progress_node: ?std.Progress.Node = null;
            var result = try repo.merge(
                io,
                allocator,
                merge_cmd,
                if (repo_opts.ProgressCtx == void) {} else .{ .run_opts = run_opts, .clear_line = &clear_line, .node = &progress_node },
            );
            defer result.deinit();
            try printMergeResult(repo_kind, repo_opts, &result, run_opts);
        },
        .config => |config_cmd| switch (config_cmd) {
            .list => {
                var conf = try repo.listConfig(io, allocator);
                defer conf.deinit();

                for (conf.sections.keys(), conf.sections.values()) |section_name, variables| {
                    for (variables.keys(), variables.values()) |name, value| {
                        try run_opts.out.print("{s}.{s}={s}\n", .{ section_name, name, value });
                    }
                }
            },
            .add => |config_add_cmd| try repo.addConfig(io, allocator, config_add_cmd),
            .remove => |config_remove_cmd| try repo.removeConfig(io, allocator, config_remove_cmd),
        },
        .remote => |remote_cmd| switch (remote_cmd) {
            .list => {
                var rem = try repo.listRemotes(io, allocator);
                defer rem.deinit();

                for (rem.sections.keys(), rem.sections.values()) |section_name, variables| {
                    for (variables.keys(), variables.values()) |name, value| {
                        try run_opts.out.print("{s}.{s}={s}\n", .{ section_name, name, value });
                    }
                }
            },
            .add => |remote_add_cmd| try repo.addRemote(io, allocator, remote_add_cmd),
            .remove => |remote_remove_cmd| try repo.removeRemote(io, allocator, remote_remove_cmd),
        },
        .clone => {},
        .fetch => |fetch_cmd| {
            var clear_line = false;
            var progress_node: ?std.Progress.Node = null;
            var refspecs = try std.ArrayList([]const u8).initCapacity(allocator, fetch_cmd.refspec_strs.len);
            defer {
                for (refspecs.items) |refspec| allocator.free(refspec);
                refspecs.deinit(allocator);
            }
            for (fetch_cmd.refspec_strs) |refspec_str| {
                var refspec = try net_refspec.RefSpec.init(allocator, refspec_str, .fetch);
                defer refspec.deinit(allocator);
                // Use the same name as src if not specified
                if (refspec.dst.len == 0) {
                    allocator.free(refspec.dst);
                    refspec.dst = try allocator.dupe(u8, refspec.src);
                }
                const refspec_normalized = try refspec.normalize(allocator);
                refspecs.appendAssumeCapacity(refspec_normalized);
            }

            try repo.fetch(
                io,
                allocator,
                fetch_cmd.remote_name,
                .{
                    .progress_ctx = if (repo_opts.ProgressCtx == void) {} else .{ .run_opts = run_opts, .clear_line = &clear_line, .node = &progress_node },
                    .refspecs = if (refspecs.items.len > 0) refspecs.items else null,
                },
            );
        },
        .push => |push_cmd| {
            var clear_line = false;
            var progress_node: ?std.Progress.Node = null;
            try repo.push(
                io,
                allocator,
                push_cmd.remote_name,
                push_cmd.refspec,
                push_cmd.force,
                .{ .progress_ctx = if (repo_opts.ProgressCtx == void) {} else .{ .run_opts = run_opts, .clear_line = &clear_line, .node = &progress_node } },
            );
        },
        .upload_pack => |upload_pack_cmd| {
            var options = upload_pack_cmd.options;
            options.protocol_version = server_common.detectProtocolVersion(run_opts.environ_map);
            var stdin_buf: [repo_opts.net_buffer_size]u8 = undefined;
            var stdin_reader = std.Io.File.stdin().reader(io, &stdin_buf);
            var stdout_buf: [repo_opts.net_buffer_size]u8 = undefined;
            var stdout_writer = std.Io.File.stdout().writer(io, &stdout_buf);
            try repo.uploadPack(io, allocator, &stdin_reader.interface, &stdout_writer.interface, options);
        },
        .receive_pack => |receive_pack_cmd| {
            var options = receive_pack_cmd.options;
            options.protocol_version = server_common.detectProtocolVersion(run_opts.environ_map);
            var stdin_buf: [repo_opts.net_buffer_size]u8 = undefined;
            var stdin_reader = std.Io.File.stdin().reader(io, &stdin_buf);
            var stdout_buf: [repo_opts.net_buffer_size]u8 = undefined;
            var stdout_writer = std.Io.File.stdout().writer(io, &stdout_buf);
            try repo.receivePack(io, allocator, &stdin_reader.interface, &stdout_writer.interface, options);
        },
        .http_backend => {
            const environ_map = run_opts.environ_map;
            var path_buf: [std.Io.Dir.max_path_bytes]u8 = undefined;
            const path = try server_http_backend.resolveRepoPath(environ_map, &path_buf);

            var stdout_buf: [repo_opts.net_buffer_size]u8 = undefined;
            var stdout_writer = std.Io.File.stdout().writer(io, &stdout_buf);

            const handler, const suffix = for (&server_http_backend.routes) |*svc| {
                if (std.mem.endsWith(u8, path, svc.suffix))
                    break .{ svc.handler, svc.suffix };
            } else {
                try server_http_backend.sendNotFound(&stdout_writer.interface);
                return;
            };

            const request_method: std.http.Method = blk: {
                const method_str = environ_map.get("REQUEST_METHOD") orelse break :blk .GET;
                const method = std.meta.stringToEnum(std.http.Method, method_str) orelse break :blk .GET;
                break :blk if (method == .HEAD) .GET else method;
            };

            var stdin_buf: [repo_opts.net_buffer_size]u8 = undefined;
            var stdin_reader = std.Io.File.stdin().reader(io, &stdin_buf);
            try repo.httpBackend(io, allocator, &stdin_reader.interface, &stdout_writer.interface, .{
                .request_method = request_method,
                .handler = handler,
                .suffix = suffix,
                .query_string = environ_map.get("QUERY_STRING") orelse "",
                .content_type = environ_map.get("CONTENT_TYPE") orelse "",
                .has_remote_user = environ_map.get("REMOTE_USER") != null,
                .protocol_version = server_common.detectProtocolVersion(environ_map),
            });
        },
        .patch => |patch_cmd| switch (repo_kind) {
            .git => {
                try run_opts.err.print("command not valid for this backend\n", .{});
                return error.HandledError;
            },
            .xit => switch (patch_cmd) {
                .on => try repo.setMergeAlgorithm(io, allocator, .patch),
                .off => try repo.setMergeAlgorithm(io, allocator, .diff3),
                .all => {
                    var clear_line = false;
                    var progress_node: ?std.Progress.Node = null;
                    try repo.patchAll(
                        io,
                        allocator,
                        if (repo_opts.ProgressCtx == void) {} else .{ .run_opts = run_opts, .clear_line = &clear_line, .node = &progress_node },
                    );
                },
            },
        },
    }
}

fn printMergeResult(
    comptime repo_kind: rp.RepoKind,
    comptime repo_opts: rp.RepoOpts(repo_kind),
    merge_result: *const mrg.Merge(repo_kind, repo_opts),
    run_opts: RunOpts,
) !void {
    for (merge_result.auto_resolved_conflicts.keys()) |path| {
        if (merge_result.changes.contains(path)) {
            try run_opts.out.print("auto-merging {s}\n", .{path});
        }
    }
    switch (merge_result.result) {
        .success => {},
        .nothing => {
            try run_opts.out.print("already up to date\n", .{});
        },
        .fast_forward => {
            try run_opts.out.print("fast-forward\n", .{});
        },
        .conflict => |result_conflict| {
            for (result_conflict.conflicts.keys(), result_conflict.conflicts.values()) |path, conflict| {
                if (conflict.renamed) |renamed| {
                    const conflict_type = if (conflict.target != null)
                        "file/directory"
                    else
                        "directory/file";
                    const dir_branch_name = if (conflict.target != null)
                        merge_result.source_name
                    else
                        merge_result.target_name;
                    try run_opts.err.print("CONFLICT ({s}): there is a directory with name {s} in {s}. adding {s} as {s}\n", .{ conflict_type, path, dir_branch_name, path, renamed.path });
                } else {
                    if (merge_result.changes.contains(path)) {
                        try run_opts.out.print("auto-merging {s}\n", .{path});
                    }
                    if (conflict.target != null and conflict.source != null) {
                        const conflict_type = if (conflict.base != null)
                            "content"
                        else
                            "add/add";
                        try run_opts.err.print("CONFLICT ({s}): merge conflict in {s}\n", .{ conflict_type, path });
                    } else {
                        const conflict_type = if (conflict.target != null)
                            "modify/delete"
                        else
                            "delete/modify";
                        const deleted_branch_name, const modified_branch_name = if (conflict.target != null)
                            .{ merge_result.source_name, merge_result.target_name }
                        else
                            .{ merge_result.target_name, merge_result.source_name };
                        try run_opts.err.print("CONFLICT ({s}): {s} deleted in {s} and modified in {s}\n", .{ conflict_type, path, deleted_branch_name, modified_branch_name });
                    }
                }
            }
            return error.HandledError;
        },
    }
}

/// this is the main "main". it's even mainier than "run".
/// this is the real deal. there is no main more main than this.
/// at least, not that i know of. i guess internally zig probably
/// has an earlier entrypoint which is even mainier than this.
pub fn main(init: std.process.Init) !u8 {
    var debug_allocator: std.heap.DebugAllocator(.{}) = .init;
    const allocator = if (builtin.mode == .Debug) debug_allocator.allocator() else std.heap.smp_allocator;
    defer if (builtin.mode == .Debug) {
        _ = debug_allocator.deinit();
    };

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var args: std.ArrayList([]const u8) = .empty;
    defer args.deinit(allocator);

    var arg_it = try init.minimal.args.iterateAllocator(allocator);
    defer arg_it.deinit();
    _ = arg_it.skip();
    while (arg_it.next()) |arg| {
        try args.append(allocator, arg);
    }

    var stdout_writer = std.Io.File.stdout().writer(io, &.{});
    var stderr_writer = std.Io.File.stderr().writer(io, &.{});
    const run_opts = RunOpts{ .out = &stdout_writer.interface, .err = &stderr_writer.interface, .environ_map = init.environ_map };

    const cwd_path = try std.process.currentPathAlloc(io, allocator);
    defer allocator.free(cwd_path);

    runPrint(.xit, .{ .ProgressCtx = ProgressCtx }, io, allocator, args.items, cwd_path, run_opts) catch |err| switch (err) {
        error.HandledError => return 1,
        else => |e| return e,
    };

    return 0;
}
