const std = @import("std");
const rp = @import("./repo.zig");
const df = @import("./diff.zig");
const mrg = @import("./merge.zig");
const idx = @import("./index.zig");
const obj = @import("./object.zig");
const cfg = @import("./config.zig");
const bch = @import("./branch.zig");
const rf = @import("./ref.zig");
const hash = @import("./hash.zig");
const work = @import("./workdir.zig");
const tg = @import("./tag.zig");

pub const CommandKind = enum {
    init,
    patch,
    add,
    unadd,
    untrack,
    rm,
    commit,
    tag,
    status,
    diff_dir,
    diff_added,
    branch,
    switch_dir,
    reset,
    reset_dir,
    reset_add,
    restore,
    log,
    merge,
    cherry_pick,
    config,
    remote,
    clone,
    fetch,
    push,
};

const Help = struct {
    name: []const u8,
    descrip: []const u8,
    example: []const u8,
};

fn commandHelp(command_kind: CommandKind) Help {
    return switch (command_kind) {
        .init => .{
            .name = "init",
            .descrip =
            \\create an empty xit repository.
            ,
            .example =
            \\in the current dir:
            \\    xit init
            \\in a new dir:
            \\    xit init myproject
            ,
        },
        .patch => .{
            .name = "patch",
            .descrip =
            \\enable or disable patch-based merging.
            ,
            .example =
            \\enable:
            \\    xit patch on
            \\enable and generate patches for all commits immediately:
            \\    xit patch all
            \\disable:
            \\    xit patch off
            ,
        },
        .add => .{
            .name = "add",
            .descrip =
            \\add file contents to the index.
            ,
            .example =
            \\xit add myfile.txt
            ,
        },
        .unadd => .{
            .name = "unadd",
            .descrip =
            \\remove any changes to a file that were added to the index.
            \\similar to `git reset HEAD`.
            ,
            .example =
            \\xit unadd myfile.txt
            \\xit unadd -r mydir
            ,
        },
        .untrack => .{
            .name = "untrack",
            .descrip =
            \\no longer track file in the index, but leave it in the work dir.
            \\similar to `git rm --cached`.
            ,
            .example =
            \\xit untrack myfile.txt
            \\xit untrack -r mydir
            ,
        },
        .rm => .{
            .name = "rm",
            .descrip =
            \\no longer track file in the index *and* remove it from the work dir.
            ,
            .example =
            \\xit rm myfile.txt
            \\xit rm -r mydir
            ,
        },
        .commit => .{
            .name = "commit",
            .descrip =
            \\create a new commit.
            ,
            .example =
            \\xit commit -m "my commit message"
            ,
        },
        .tag => .{
            .name = "tag",
            .descrip =
            \\add, remove, and list tags.
            ,
            .example =
            \\add tag:
            \\    xit tag add mytag
            \\remove tag:
            \\    xit tag rm mytag
            \\list tag:
            \\    xit tag list
            ,
        },
        .status => .{
            .name = "status",
            .descrip =
            \\show the status of uncommitted changes.
            ,
            .example =
            \\display in TUI:
            \\    xit status
            \\display in CLI:
            \\    xit status --cli
            ,
        },
        .diff_dir => .{
            .name = "diff",
            .descrip =
            \\show changes between the last commit and the work dir that haven't been added to the index.
            ,
            .example =
            \\display in TUI:
            \\    xit diff
            \\display in CLI:
            \\    xit diff --cli
            ,
        },
        .diff_added => .{
            .name = "diff-added",
            .descrip =
            \\show changes between the last commit and what has been added to the index.
            \\similar to `git diff --cached`.
            ,
            .example =
            \\display in TUI:
            \\    xit diff-added
            \\display in CLI:
            \\    xit diff-added --cli
            ,
        },
        .branch => .{
            .name = "branch",
            .descrip =
            \\add, remove, and list branches.
            ,
            .example =
            \\add branch:
            \\    xit branch add mybranch
            \\remove branch:
            \\    xit branch rm mybranch
            \\list branches:
            \\    xit branch list
            ,
        },
        .switch_dir => .{
            .name = "switch",
            .descrip =
            \\switch to a branch or commit id.
            \\updates both the index and the work dir.
            ,
            .example =
            \\switch to branch:
            \\    xit switch mybranch
            \\switch to commit id:
            \\    xit switch a1b2c3...
            ,
        },
        .reset => .{
            .name = "reset",
            .descrip =
            \\make the current branch point to a new commit id.
            \\updates the index, but the files in the work dir are left alone.
            ,
            .example =
            \\reset current branch to match another branch:
            \\    xit reset mybranch
            \\reset current branch to point to a new commit id:
            \\    xit reset 1a2b3c...
            ,
        },
        .reset_dir => .{
            .name = "reset-dir",
            .descrip =
            \\make the current branch point to a new commit id.
            \\updates both the index and the work dir.
            \\similar to `git reset --hard`.
            ,
            .example =
            \\reset current branch to match another branch:
            \\    xit reset-dir mybranch
            \\reset current branch to point to a new commit id:
            \\    xit reset-dir 1a2b3c...
            ,
        },
        .reset_add => .{
            .name = "reset-add",
            .descrip =
            \\make the current branch point to a new commit id.
            \\does not update the index or the work dir.
            \\this is like calling reset and then adding everything to the index.
            \\similar to `git reset --soft`.
            ,
            .example =
            \\reset current branch to point to a new commit id:
            \\    xit reset-add 1a2b3c...
            ,
        },
        .restore => .{
            .name = "restore",
            .descrip =
            \\restore files in the work dir.
            ,
            .example =
            \\xit restore myfile.txt
            ,
        },
        .log => .{
            .name = "log",
            .descrip =
            \\show commit logs.
            ,
            .example =
            \\display in TUI:
            \\    xit log
            \\display in CLI:
            \\    xit log --cli
            \\display specified branch
            \\    xit log branch_name
            ,
        },
        .merge => .{
            .name = "merge",
            .descrip =
            \\join two or more development histories together.
            ,
            .example =
            \\merge branch:
            \\    xit merge mybranch
            \\merge commit id:
            \\    xit merge a1b2c3...
            \\continue after merge conflict resolution:
            \\    xit merge --continue
            \\abort merge:
            \\    xit merge --abort
            ,
        },
        .cherry_pick => .{
            .name = "cherry-pick",
            .descrip =
            \\apply the changes introduced by an existing commit.
            ,
            .example =
            \\cherry pick a commit:
            \\    xit cherry-pick a1b2c3...
            \\continue after merge conflict resolution:
            \\    xit cherry-pick --continue
            \\abort cherry-pick:
            \\    xit cherry-pick --abort
            ,
        },
        .config => .{
            .name = "config",
            .descrip =
            \\add, remove, and list config options.
            ,
            .example =
            \\display in TUI:
            \\    xit config
            \\add config:
            \\    xit config add core.editor vim
            \\remove config:
            \\    xit config rm core.editor
            \\list configs:
            \\    xit config list
            ,
        },
        .remote => .{
            .name = "remote",
            .descrip =
            \\add, remove, and list remotes.
            ,
            .example =
            \\add remote:
            \\    xit remote add origin https://github.com/...
            \\remove remote:
            \\    xit remote rm origin
            \\list remotes:
            \\    xit remote list
            ,
        },
        .clone => .{
            .name = "clone",
            .descrip =
            \\clone a repository into a new directory.
            ,
            .example =
            \\clone with a url:
            \\    xit clone https://github.com/... mydir
            ,
        },
        .fetch => .{
            .name = "fetch",
            .descrip =
            \\download objects and refs from another repository.
            ,
            .example =
            \\fetch from a specific remote:
            \\    xit fetch origin
            \\fetch from specific refs from remote origin:
            \\    xit fetch origin refspecs
            ,
        },
        .push => .{
            .name = "push",
            .descrip =
            \\update remote refs along with associated objects.
            ,
            .example =
            \\push to a specific remote and branch:
            \\    xit push origin master
            \\delete a remote branch:
            \\    xit push origin :master
            \\force push:
            \\    xit push origin master -f
            ,
        },
    };
}

pub fn printHelp(cmd_kind_maybe: ?CommandKind, writer: *std.Io.Writer) !void {
    const print_indent = comptime blk: {
        var indent = 0;
        for (0..@typeInfo(CommandKind).@"enum".fields.len) |i| {
            indent = @max(commandHelp(@enumFromInt(i)).name.len, indent);
        }
        indent += 2;
        break :blk indent;
    };

    if (cmd_kind_maybe) |cmd_kind| {
        const help = commandHelp(cmd_kind);
        // name and description
        try writer.print("{s}", .{help.name});
        for (0..print_indent - help.name.len) |_| try writer.print(" ", .{});
        var split_iter = std.mem.splitScalar(u8, help.descrip, '\n');
        try writer.print("{s}\n", .{split_iter.first()});
        while (split_iter.next()) |line| {
            for (0..print_indent) |_| try writer.print(" ", .{});
            try writer.print("{s}\n", .{line});
        }
        try writer.print("\n", .{});
        // example
        split_iter = std.mem.splitScalar(u8, help.example, '\n');
        while (split_iter.next()) |line| {
            for (0..print_indent) |_| try writer.print(" ", .{});
            try writer.print("{s}\n", .{line});
        }
    } else {
        try writer.print("help: xit <command> [<args>]\n\n", .{});
        inline for (@typeInfo(CommandKind).@"enum".fields) |field| {
            const help = commandHelp(@enumFromInt(field.value));
            // name and description
            try writer.print("{s}", .{help.name});
            for (0..print_indent - help.name.len) |_| try writer.print(" ", .{});
            var split_iter = std.mem.splitScalar(u8, help.descrip, '\n');
            try writer.print("{s}\n", .{split_iter.first()});
            while (split_iter.next()) |line| {
                for (0..print_indent) |_| try writer.print(" ", .{});
                try writer.print("{s}\n", .{line});
            }
        }
    }
}

pub const CommandArgs = struct {
    allocator: std.mem.Allocator,
    arena: *std.heap.ArenaAllocator,
    command_kind: ?CommandKind,
    command_name: ?[]const u8,
    positional_args: []const []const u8,
    map_args: std.StringArrayHashMap(?[]const u8),
    unused_args: std.StringArrayHashMap(void),

    // flags that can have a value associated with them
    // must be included here
    const value_flags = std.StaticStringMap(void).initComptime(.{
        .{"-m"},
    });

    pub fn init(allocator: std.mem.Allocator, args: []const []const u8) !CommandArgs {
        const arena = try allocator.create(std.heap.ArenaAllocator);
        arena.* = std.heap.ArenaAllocator.init(allocator);
        errdefer {
            arena.deinit();
            allocator.destroy(arena);
        }

        var positional_args = std.ArrayList([]const u8){};
        var map_args = std.StringArrayHashMap(?[]const u8).init(arena.allocator());
        var unused_args = std.StringArrayHashMap(void).init(arena.allocator());

        for (args) |arg| {
            if (arg.len > 1 and arg[0] == '-') {
                try map_args.put(arg, null);
                try unused_args.put(arg, {});
            } else {
                // if the last key is a value flag and doesn't have a value yet,
                // set this arg as its value
                const keys = map_args.keys();
                if (keys.len > 0) {
                    const last_key = keys[keys.len - 1];
                    if (map_args.get(last_key)) |last_val| {
                        if (value_flags.has(last_key) and last_val == null) {
                            try map_args.put(last_key, arg);
                            continue;
                        }
                    }
                }

                // in any other case, just consider it a positional arg
                try positional_args.append(arena.allocator(), arg);
            }
        }

        const args_slice = try positional_args.toOwnedSlice(arena.allocator());
        if (args_slice.len == 0) {
            return .{
                .allocator = allocator,
                .arena = arena,
                .command_kind = null,
                .command_name = null,
                .positional_args = args_slice,
                .map_args = map_args,
                .unused_args = unused_args,
            };
        } else {
            const command_name = args_slice[0];
            const extra_args = args_slice[1..];

            const command_kind: ?CommandKind = inline for (0..@typeInfo(CommandKind).@"enum".fields.len) |i| {
                if (std.mem.eql(u8, command_name, commandHelp(@enumFromInt(i)).name)) {
                    break @enumFromInt(i);
                }
            } else null;

            return .{
                .allocator = allocator,
                .arena = arena,
                .command_kind = command_kind,
                .command_name = command_name,
                .positional_args = extra_args,
                .map_args = map_args,
                .unused_args = unused_args,
            };
        }
    }

    pub fn deinit(self: *CommandArgs) void {
        self.arena.deinit();
        self.allocator.destroy(self.arena);
    }

    pub fn contains(self: *CommandArgs, arg: []const u8) bool {
        _ = self.unused_args.orderedRemove(arg);
        return self.map_args.contains(arg);
    }

    pub fn get(self: *CommandArgs, comptime arg: []const u8) ??[]const u8 {
        comptime std.debug.assert(value_flags.has(arg)); // can only call `get` with flags included in `value_flags`
        _ = self.unused_args.orderedRemove(arg);
        return self.map_args.get(arg);
    }
};

/// parses the args into a format that can be directly used by a repo.
/// if any additional allocation needs to be done, the arena inside the cmd args will be used.
pub fn Command(comptime repo_kind: rp.RepoKind, comptime hash_kind: hash.HashKind) type {
    return union(CommandKind) {
        init: struct {
            dir: []const u8,
        },
        patch: enum {
            on,
            off,
            all,
        },
        add: struct {
            paths: []const []const u8,
        },
        unadd: struct {
            paths: []const []const u8,
            opts: work.UnaddOptions,
        },
        untrack: struct {
            paths: []const []const u8,
            opts: work.UntrackOptions,
        },
        rm: struct {
            paths: []const []const u8,
            opts: work.RemoveOptions,
        },
        commit: obj.CommitMetadata(hash_kind),
        tag: tg.TagCommand,
        status,
        diff_dir: df.BasicDiffOptions(hash_kind),
        diff_added: df.BasicDiffOptions(hash_kind),
        branch: bch.BranchCommand,
        switch_dir: work.SwitchInput(hash_kind),
        reset: work.SwitchInput(hash_kind),
        reset_dir: work.SwitchInput(hash_kind),
        reset_add: rf.RefOrOid(hash_kind),
        restore: struct {
            path: []const u8,
        },
        log: []const rf.RefOrOid(hash_kind),
        merge: mrg.MergeInput(hash_kind),
        cherry_pick: mrg.MergeInput(hash_kind),
        config: cfg.ConfigCommand,
        remote: cfg.ConfigCommand,
        clone: struct {
            url: []const u8,
            local_path: []const u8,
        },
        fetch: struct {
            remote_name: []const u8,
            refspec_strs: []const []const u8,
        },
        push: struct {
            remote_name: []const u8,
            refspec: []const u8,
            force: bool,
        },

        pub fn initMaybe(cmd_args: *CommandArgs) !?Command(repo_kind, hash_kind) {
            const command_kind = cmd_args.command_kind orelse return null;
            switch (command_kind) {
                .init => {
                    if (cmd_args.positional_args.len == 0) {
                        return .{ .init = .{ .dir = "." } };
                    } else if (cmd_args.positional_args.len == 1) {
                        return .{ .init = .{ .dir = cmd_args.positional_args[0] } };
                    } else {
                        return null;
                    }
                },
                .patch => {
                    if (cmd_args.positional_args.len != 1) return null;

                    const option = cmd_args.positional_args[0];

                    return .{ .patch = if (std.mem.eql(u8, "on", option)) .on else if (std.mem.eql(u8, "off", option)) .off else if (std.mem.eql(u8, "all", option)) .all else return null };
                },
                .add => {
                    if (cmd_args.positional_args.len == 0) return null;

                    return .{ .add = .{ .paths = cmd_args.positional_args } };
                },
                .unadd => {
                    if (cmd_args.positional_args.len == 0) return null;

                    return .{ .unadd = .{
                        .paths = cmd_args.positional_args,
                        .opts = .{
                            .recursive = cmd_args.contains("-r"),
                        },
                    } };
                },
                .untrack => {
                    if (cmd_args.positional_args.len == 0) return null;

                    return .{ .untrack = .{
                        .paths = cmd_args.positional_args,
                        .opts = .{
                            .force = cmd_args.contains("-f"),
                            .recursive = cmd_args.contains("-r"),
                        },
                    } };
                },
                .rm => {
                    if (cmd_args.positional_args.len == 0) return null;

                    return .{ .rm = .{
                        .paths = cmd_args.positional_args,
                        .opts = .{
                            .force = cmd_args.contains("-f"),
                            .recursive = cmd_args.contains("-r"),
                            .update_work_dir = true,
                        },
                    } };
                },
                .commit => {
                    if (cmd_args.positional_args.len > 0) return null;
                    // if a message is included, it must have a non-null value
                    const message_maybe = if (cmd_args.get("-m")) |msg| (msg orelse return error.CommitMessageNotFound) else null;
                    return .{ .commit = .{
                        .message = message_maybe,
                        .allow_empty = cmd_args.contains("--allow-empty"),
                    } };
                },
                .tag => {
                    if (cmd_args.positional_args.len == 0) return null;

                    const cmd_name = cmd_args.positional_args[0];

                    var cmd: tg.TagCommand = undefined;
                    if (std.mem.eql(u8, "list", cmd_name)) {
                        cmd = .list;
                    } else if (std.mem.eql(u8, "add", cmd_name)) {
                        if (cmd_args.positional_args.len != 2) {
                            return null;
                        }
                        // if a message is included, it must have a non-null value
                        const message_maybe = if (cmd_args.get("-m")) |msg| (msg orelse return error.TagMessageNotFound) else null;
                        cmd = .{ .add = .{
                            .name = cmd_args.positional_args[1],
                            .message = message_maybe,
                        } };
                    } else if (std.mem.eql(u8, "rm", cmd_name)) {
                        if (cmd_args.positional_args.len != 2) {
                            return null;
                        }
                        cmd = .{ .remove = .{ .name = cmd_args.positional_args[1] } };
                    } else {
                        try cmd_args.unused_args.put(cmd_name, {});
                        return null;
                    }

                    return .{ .tag = cmd };
                },
                .status => return .status,
                .diff_dir => {
                    const conflict_diff_kind: df.ConflictDiffKind =
                        if (cmd_args.contains("--base"))
                            .base
                        else if (cmd_args.contains("--target"))
                            .target
                        else if (cmd_args.contains("--source"))
                            .source
                        else
                            .target;
                    return .{ .diff_dir = .{ .work_dir = .{ .conflict_diff_kind = conflict_diff_kind } } };
                },
                .diff_added => return .{ .diff_added = .index },
                .branch => {
                    if (cmd_args.positional_args.len == 0) return null;

                    const cmd_name = cmd_args.positional_args[0];

                    var cmd: bch.BranchCommand = undefined;
                    if (std.mem.eql(u8, "list", cmd_name)) {
                        cmd = .list;
                    } else if (std.mem.eql(u8, "add", cmd_name)) {
                        if (cmd_args.positional_args.len != 2) {
                            return null;
                        }
                        cmd = .{ .add = .{ .name = cmd_args.positional_args[1] } };
                    } else if (std.mem.eql(u8, "rm", cmd_name)) {
                        if (cmd_args.positional_args.len != 2) {
                            return null;
                        }
                        cmd = .{ .remove = .{ .name = cmd_args.positional_args[1] } };
                    } else {
                        try cmd_args.unused_args.put(cmd_name, {});
                        return null;
                    }

                    return .{ .branch = cmd };
                },
                .switch_dir => {
                    if (cmd_args.positional_args.len != 1) return null;
                    const target = cmd_args.positional_args[0];

                    return .{ .switch_dir = .{
                        .kind = .@"switch",
                        .target = rf.RefOrOid(hash_kind).initFromUser(target) orelse return null,
                        .update_work_dir = true,
                        .force = cmd_args.contains("-f"),
                    } };
                },
                .reset => {
                    if (cmd_args.positional_args.len != 1) return null;
                    const target = cmd_args.positional_args[0];

                    return .{ .reset = .{
                        .kind = .reset,
                        .target = rf.RefOrOid(hash_kind).initFromUser(target) orelse return null,
                        .update_work_dir = false,
                        .force = cmd_args.contains("-f"),
                    } };
                },
                .reset_dir => {
                    if (cmd_args.positional_args.len != 1) return null;
                    const target = cmd_args.positional_args[0];

                    return .{ .reset_dir = .{
                        .kind = .reset,
                        .target = rf.RefOrOid(hash_kind).initFromUser(target) orelse return null,
                        .update_work_dir = true,
                        .force = cmd_args.contains("-f"),
                    } };
                },
                .reset_add => {
                    if (cmd_args.positional_args.len != 1) return null;
                    const target = cmd_args.positional_args[0];
                    const ref_or_oid = rf.RefOrOid(hash_kind).initFromUser(target) orelse return null;
                    if (ref_or_oid != .oid) return null;
                    return .{ .reset_add = ref_or_oid };
                },
                .restore => {
                    if (cmd_args.positional_args.len != 1) return null;

                    return .{ .restore = .{ .path = cmd_args.positional_args[0] } };
                },
                .log => {
                    var source = std.ArrayList(rf.RefOrOid(hash_kind)){};
                    for (cmd_args.positional_args) |arg| {
                        const ref_or_oid = rf.RefOrOid(hash_kind).initFromUser(arg) orelse return error.InvalidRefOrOid;
                        try source.append(cmd_args.arena.allocator(), ref_or_oid);
                    }

                    return .{ .log = try source.toOwnedSlice(cmd_args.arena.allocator()) };
                },
                inline .merge, .cherry_pick => |cmd_kind| {
                    var merge_action: mrg.MergeAction(hash_kind) = undefined;

                    if (cmd_args.contains("--continue")) {
                        if (cmd_args.positional_args.len != 0) return null;
                        merge_action = .cont;
                    } else if (cmd_args.contains("--abort")) {
                        if (cmd_args.positional_args.len != 0) return null;
                        return .{ .reset_dir = .{
                            .kind = .reset,
                            .target = null,
                            .update_work_dir = true,
                            .force = true,
                        } };
                    } else {
                        if (cmd_args.positional_args.len == 0) return null;
                        var source = std.ArrayList(rf.RefOrOid(hash_kind)){};
                        for (cmd_args.positional_args) |arg| {
                            try source.append(cmd_args.arena.allocator(), rf.RefOrOid(hash_kind).initFromUser(arg) orelse return error.InvalidRefOrOid);
                        }
                        merge_action = .{ .new = .{ .source = try source.toOwnedSlice(cmd_args.arena.allocator()) } };
                    }

                    return .{
                        .merge = .{
                            .kind = switch (cmd_kind) {
                                .merge => .full,
                                .cherry_pick => .pick,
                                else => comptime unreachable,
                            },
                            .action = merge_action,
                        },
                    };
                },
                inline .config, .remote => |cmd_kind| {
                    if (cmd_args.positional_args.len == 0) return null;

                    const cmd_name = cmd_args.positional_args[0];

                    var cmd: cfg.ConfigCommand = undefined;
                    if (std.mem.eql(u8, "list", cmd_name)) {
                        cmd = .list;
                    } else if (std.mem.eql(u8, "add", cmd_name)) {
                        if (cmd_args.positional_args.len < 3) {
                            return null;
                        }
                        cmd = .{ .add = .{
                            .name = cmd_args.positional_args[1],
                            .value = if (cmd_args.positional_args.len == 3)
                                cmd_args.positional_args[2]
                            else
                                try std.mem.join(cmd_args.arena.allocator(), " ", cmd_args.positional_args[2..]),
                        } };
                    } else if (std.mem.eql(u8, "rm", cmd_name)) {
                        if (cmd_args.positional_args.len != 2) {
                            return null;
                        }
                        cmd = .{ .remove = .{
                            .name = cmd_args.positional_args[1],
                        } };
                    } else {
                        try cmd_args.unused_args.put(cmd_name, {});
                        return null;
                    }

                    return switch (cmd_kind) {
                        .config => .{ .config = cmd },
                        .remote => .{ .remote = cmd },
                        else => comptime unreachable,
                    };
                },
                .clone => {
                    if (cmd_args.positional_args.len != 2) return null;

                    return .{ .clone = .{
                        .url = cmd_args.positional_args[0],
                        .local_path = cmd_args.positional_args[1],
                    } };
                },
                .fetch => {
                    if (cmd_args.positional_args.len < 1) return null;

                    return .{ .fetch = .{
                        .remote_name = cmd_args.positional_args[0],
                        .refspec_strs = if (cmd_args.positional_args.len > 1) cmd_args.positional_args[1..] else &.{},
                    } };
                },
                .push => {
                    if (cmd_args.positional_args.len != 2) return null;

                    return .{ .push = .{
                        .remote_name = cmd_args.positional_args[0],
                        .refspec = cmd_args.positional_args[1],
                        .force = cmd_args.contains("-f"),
                    } };
                },
            }
        }
    };
}

/// parses the given args into a command if valid, and determines how it should be run
/// (via the TUI or CLI).
pub fn CommandDispatch(comptime repo_kind: rp.RepoKind, comptime hash_kind: hash.HashKind) type {
    return union(enum) {
        invalid: union(enum) {
            command: []const u8,
            argument: struct {
                command: ?CommandKind,
                value: []const u8,
            },
        },
        help: ?CommandKind,
        tui: ?CommandKind,
        cli: Command(repo_kind, hash_kind),

        pub fn init(cmd_args: *CommandArgs) !CommandDispatch(repo_kind, hash_kind) {
            const dispatch = try initIgnoreUnused(cmd_args);
            if (cmd_args.unused_args.count() > 0) {
                return .{
                    .invalid = .{
                        .argument = .{
                            .command = switch (dispatch) {
                                .invalid => return dispatch, // if there was already an error, return it instead
                                .help, .tui => |cmd_kind_maybe| cmd_kind_maybe,
                                .cli => |command| command,
                            },
                            .value = cmd_args.unused_args.keys()[0],
                        },
                    },
                };
            }
            return dispatch;
        }

        pub fn initIgnoreUnused(cmd_args: *CommandArgs) !CommandDispatch(repo_kind, hash_kind) {
            const show_help = cmd_args.contains("--help");
            const force_cli = cmd_args.contains("--cli");

            if (cmd_args.command_kind) |command_kind| {
                if (show_help) {
                    return .{ .help = command_kind };
                } else if (cmd_args.positional_args.len == 0 and !force_cli and switch (command_kind) {
                    .status, .diff_dir, .diff_added, .log, .config => true,
                    else => false,
                }) {
                    return .{ .tui = command_kind };
                } else if (try Command(repo_kind, hash_kind).initMaybe(cmd_args)) |cmd| {
                    return .{ .cli = cmd };
                } else {
                    return .{ .help = command_kind };
                }
            } else if (cmd_args.command_name) |command_name| {
                return .{ .invalid = .{ .command = command_name } };
            } else if (show_help) {
                return .{ .help = null };
            } else if (!force_cli) {
                return .{ .tui = null };
            } else {
                return .{ .help = null };
            }
        }
    };
}

test "command" {
    const repo_kind = rp.RepoKind.git;
    const hash_kind = hash.HashKind.sha1;
    const allocator = std.testing.allocator;

    {
        var cmd_args = try CommandArgs.init(allocator, &.{ "add", "--cli" });
        defer cmd_args.deinit();
        const command = try CommandDispatch(repo_kind, hash_kind).init(&cmd_args);
        try std.testing.expectEqualStrings("help", @tagName(command));
    }

    {
        var cmd_args = try CommandArgs.init(allocator, &.{ "add", "file.txt" });
        defer cmd_args.deinit();
        const command = try CommandDispatch(repo_kind, hash_kind).init(&cmd_args);
        try std.testing.expectEqualStrings("cli", @tagName(command));
        try std.testing.expectEqualStrings("add", @tagName(command.cli));
    }

    // arg requires value
    {
        var cmd_args = try CommandArgs.init(allocator, &.{ "commit", "-m" });
        defer cmd_args.deinit();
        const command_or_err = CommandDispatch(repo_kind, hash_kind).init(&cmd_args);
        try std.testing.expectError(error.CommitMessageNotFound, command_or_err);
    }

    {
        var cmd_args = try CommandArgs.init(allocator, &.{ "commit", "-m", "let there be light" });
        defer cmd_args.deinit();
        const command = try CommandDispatch(repo_kind, hash_kind).init(&cmd_args);
        try std.testing.expectEqualStrings("cli", @tagName(command));
        try std.testing.expectEqualStrings("let there be light", command.cli.commit.message.?);
    }

    // extra config add args are joined
    {
        var cmd_args = try CommandArgs.init(allocator, &.{ "config", "add", "user.name", "radar", "roark" });
        defer cmd_args.deinit();
        const command = try CommandDispatch(repo_kind, hash_kind).init(&cmd_args);
        try std.testing.expectEqualStrings("cli", @tagName(command));
        try std.testing.expectEqualStrings("radar roark", command.cli.config.add.value);
    }

    // invalid command and arg
    {
        var cmd_args = try CommandArgs.init(allocator, &.{ "stats", "--clii" });
        defer cmd_args.deinit();
        const command = try CommandDispatch(repo_kind, hash_kind).init(&cmd_args);
        try std.testing.expectEqualStrings("invalid", @tagName(command));
        try std.testing.expectEqualStrings("command", @tagName(command.invalid));
        try std.testing.expectEqualStrings("stats", command.invalid.command);
    }

    // invalid arg
    {
        var cmd_args = try CommandArgs.init(allocator, &.{ "status", "--clii" });
        defer cmd_args.deinit();
        const command = try CommandDispatch(repo_kind, hash_kind).init(&cmd_args);
        try std.testing.expectEqualStrings("invalid", @tagName(command));
        try std.testing.expectEqualStrings("argument", @tagName(command.invalid));
        try std.testing.expectEqualStrings("status", @tagName(command.invalid.argument.command.?));
        try std.testing.expectEqualStrings("--clii", command.invalid.argument.value);
    }
}
