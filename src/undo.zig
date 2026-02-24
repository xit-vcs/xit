const std = @import("std");
const cmd = @import("./command.zig");
const rp = @import("./repo.zig");
const hash = @import("./hash.zig");
const bch = @import("./branch.zig");
const obj = @import("./object.zig");
const tg = @import("./tag.zig");
const mrg = @import("./merge.zig");
const cfg = @import("./config.zig");
const work = @import("./workdir.zig");
const rf = @import("./ref.zig");

fn bufPrint(buf: []u8, comptime fmt: []const u8, args: anytype) []u8 {
    return std.fmt.bufPrint(buf, fmt, args) catch |err| switch (err) {
        error.NoSpaceLeft => buf,
    };
}

pub fn UndoCommand(comptime hash_kind: hash.HashKind) type {
    return union(enum) {
        patch: enum {
            on,
            off,
            all,
        },
        add: struct {
            paths: []const []const u8,
            allocator: std.mem.Allocator,
        },
        unadd: struct {
            paths: []const []const u8,
            allocator: std.mem.Allocator,
        },
        rm: struct {
            paths: []const []const u8,
            opts: work.RemoveOptions,
            allocator: std.mem.Allocator,
        },
        commit: obj.CommitMetadata(hash_kind),
        tag: tg.TagCommand,
        branch: bch.BranchCommand,
        switch_dir: work.SwitchInput(hash_kind),
        reset_add: rf.RefOrOid(hash_kind),
        merge: struct {
            input: mrg.MergeInput(hash_kind),
            allocator: std.mem.Allocator,
        },
        config: cfg.ConfigCommand,
        remote: cfg.ConfigCommand,
        clone: struct {
            url: []const u8,
        },
        fetch: struct {
            remote_name: []const u8,
        },
        copy_objects,
    };
}

pub fn writeMessage(
    comptime repo_opts: rp.RepoOpts(.xit),
    state: rp.Repo(.xit, repo_opts).State(.read_write),
    command: UndoCommand(repo_opts.hash),
) !void {
    var message_buffer = [_]u8{0} ** 2048;

    const message = switch (command) {
        .patch => |patch_cmd| switch (patch_cmd) {
            .on => bufPrint(&message_buffer, "patch on", .{}),
            .off => bufPrint(&message_buffer, "patch off", .{}),
            .all => bufPrint(&message_buffer, "patch all", .{}),
        },
        .add => |add_cmd| blk: {
            const joined_paths = try std.mem.join(add_cmd.allocator, " ", add_cmd.paths);
            defer add_cmd.allocator.free(joined_paths);
            break :blk bufPrint(&message_buffer, "add {s}", .{joined_paths});
        },
        .unadd => |unadd_cmd| blk: {
            const joined_paths = try std.mem.join(unadd_cmd.allocator, " ", unadd_cmd.paths);
            defer unadd_cmd.allocator.free(joined_paths);
            break :blk bufPrint(&message_buffer, "unadd {s}", .{joined_paths});
        },
        .rm => |rm_cmd| blk: {
            const joined_paths = try std.mem.join(rm_cmd.allocator, " ", rm_cmd.paths);
            defer rm_cmd.allocator.free(joined_paths);
            if (rm_cmd.opts.update_work_dir) {
                break :blk bufPrint(&message_buffer, "rm {s}", .{joined_paths});
            } else {
                break :blk bufPrint(&message_buffer, "untrack {s}", .{joined_paths});
            }
        },
        .branch => |branch_cmd| switch (branch_cmd) {
            .list => return error.NotImplemented,
            .add => |add_branch| bufPrint(&message_buffer, "branch add {s}", .{add_branch.name}),
            .remove => |rm_branch| bufPrint(&message_buffer, "branch rm {s}", .{rm_branch.name}),
        },
        .switch_dir => |switch_cmd| blk: {
            const target_name = if (switch_cmd.target) |target|
                target.name()
            else
                "HEAD";
            break :blk switch (switch_cmd.kind) {
                .@"switch" => bufPrint(&message_buffer, "switch {s}", .{target_name}),
                .reset => if (switch_cmd.update_work_dir)
                    bufPrint(&message_buffer, "reset-dir {s}", .{target_name})
                else
                    bufPrint(&message_buffer, "reset {s}", .{target_name}),
            };
        },
        .reset_add => |reset_add_cmd| bufPrint(&message_buffer, "reset-add {s}", .{reset_add_cmd.name()}),
        .commit => |commit_cmd| if (commit_cmd.message) |message|
            bufPrint(&message_buffer, "commit -m \"{s}\"", .{message})
        else
            bufPrint(&message_buffer, "commit", .{}),
        .tag => |tag_cmd| switch (tag_cmd) {
            .list => return error.NotImplemented,
            .add => |add_tag| bufPrint(&message_buffer, "tag add {s}", .{add_tag.name}),
            .remove => |rm_tag| bufPrint(&message_buffer, "tag rm {s}", .{rm_tag.name}),
        },
        .merge => |merge_cmd| switch (merge_cmd.input.action) {
            .new => |new| blk: {
                var sources = std.ArrayList([]const u8){};
                defer sources.deinit(merge_cmd.allocator);
                for (new.source) |source| {
                    try sources.append(merge_cmd.allocator, source.name());
                }
                const joined_sources = try std.mem.join(merge_cmd.allocator, " ", sources.items);
                defer merge_cmd.allocator.free(joined_sources);
                break :blk switch (merge_cmd.input.kind) {
                    .full => bufPrint(&message_buffer, "merge {s}", .{joined_sources}),
                    .pick => bufPrint(&message_buffer, "cherry-pick {s}", .{joined_sources}),
                };
            },
            .cont => switch (merge_cmd.input.kind) {
                .full => bufPrint(&message_buffer, "merge --continue", .{}),
                .pick => bufPrint(&message_buffer, "cherry-pick --continue", .{}),
            },
        },
        .config => |config_cmd| switch (config_cmd) {
            .list => return error.NotImplemented,
            .add => |add_config| bufPrint(&message_buffer, "config add {s}", .{add_config.name}),
            .remove => |rm_config| bufPrint(&message_buffer, "config rm {s}", .{rm_config.name}),
        },
        .remote => |remote_cmd| switch (remote_cmd) {
            .list => return error.NotImplemented,
            .add => |add_remote| bufPrint(&message_buffer, "remote add {s}", .{add_remote.name}),
            .remove => |rm_remote| bufPrint(&message_buffer, "remote rm {s}", .{rm_remote.name}),
        },
        .clone => |clone_cmd| bufPrint(&message_buffer, "clone {s}", .{clone_cmd.url}),
        .fetch => |fetch_cmd| bufPrint(&message_buffer, "fetch {s}", .{fetch_cmd.remote_name}),
        .copy_objects => bufPrint(&message_buffer, "copy objects", .{}),
    };

    try state.extra.moment.put(hash.hashInt(repo_opts.hash, "undo-message"), .{ .bytes = message });
}
