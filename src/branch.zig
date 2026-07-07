const std = @import("std");
const hash = @import("./hash.zig");
const rf = @import("./ref.zig");
const fs = @import("./fs.zig");
const rp = @import("./repo.zig");

pub const BranchCommand = union(enum) {
    list,
    add: AddBranchInput,
    remove: RemoveBranchInput,
};

pub const AddBranchInput = struct {
    name: []const u8,
    target: union(enum) {
        none,
        head,
    } = .head,
};

pub const RemoveBranchInput = struct {
    name: []const u8,
};

pub fn validateName(name: []const u8) bool {
    return rf.validateName(name) and !std.mem.eql(u8, "HEAD", name);
}

pub fn add(
    comptime repo_kind: rp.RepoKind,
    comptime repo_opts: rp.RepoOpts(repo_kind),
    state: rp.Repo(repo_kind, repo_opts).State(.read_write),
    io: std.Io,
    input: AddBranchInput,
) !void {
    const name = input.name;
    if (!validateName(name)) {
        return error.InvalidBranchName;
    }

    if (try rf.exists(repo_kind, repo_opts, state.readOnly(), io, .{ .kind = .head, .name = input.name })) {
        return error.BranchAlreadyExists;
    }

    const oid_maybe = switch (input.target) {
        .none => null,
        .head => rf.readHeadRecurMaybe(repo_kind, repo_opts, state.readOnly(), io) catch |err| switch (err) {
            error.RefNotFound => null,
            else => |e| return e,
        },
    };

    if (oid_maybe) |oid| {
        var ref_path_buffer = [_]u8{0} ** rf.MAX_REF_CONTENT_SIZE;
        const ref_path = try (rf.Ref{ .kind = .head, .name = name }).toPath(&ref_path_buffer);
        try rf.write(repo_kind, repo_opts, state, io, ref_path, .{ .oid = &oid });
    } else switch (repo_kind) {
        // a branch without a target does nothing on the git backend
        .git => {},
        .xit => {
            const DB = rp.Repo(repo_kind, repo_opts).DB;

            // create an empty ref (a key with no content) in refs/heads/{refname}
            const refs_cursor = try state.extra.moment.putCursor(hash.hashInt(repo_opts.hash, "refs"));
            const refs = try DB.SortedMap(.read_write).init(refs_cursor);
            const heads_cursor = try refs.putCursor("heads");
            const heads = try DB.SortedMap(.read_write).init(heads_cursor);
            _ = try heads.putCursor(name);
        },
    }
}

pub fn remove(
    comptime repo_kind: rp.RepoKind,
    comptime repo_opts: rp.RepoOpts(repo_kind),
    state: rp.Repo(repo_kind, repo_opts).State(.read_write),
    io: std.Io,
    input: RemoveBranchInput,
) !void {
    // don't allow current branch to be deleted
    var current_branch_buffer = [_]u8{0} ** rf.MAX_REF_CONTENT_SIZE;
    if (try rf.readHead(repo_kind, repo_opts, state.readOnly(), io, &current_branch_buffer)) |current_branch| {
        switch (current_branch) {
            .ref => |ref| if (std.mem.eql(u8, input.name, ref.name)) {
                return error.CannotDeleteCurrentBranch;
            },
            .oid => {},
        }
    }

    switch (repo_kind) {
        .git => {
            var refs_dir = try state.core.repo_dir.openDir(io, "refs", .{});
            defer refs_dir.close(io);
            var heads_dir = try refs_dir.createDirPathOpen(io, "heads", .{});
            defer heads_dir.close(io);

            // create lock file for HEAD
            var head_lock = try fs.LockFile.init(io, state.core.repo_dir, "HEAD");
            defer head_lock.deinit(io);

            try heads_dir.deleteFile(io, input.name);
            try fs.deleteEmptyParents(io, heads_dir, input.name);
        },
        .xit => {
            const DB = rp.Repo(repo_kind, repo_opts).DB;

            // remove from refs/heads/{name}
            const refs_cursor = try state.extra.moment.putCursor(hash.hashInt(repo_opts.hash, "refs"));
            const refs = try DB.SortedMap(.read_write).init(refs_cursor);
            const heads_cursor = try refs.putCursor("heads");
            const heads = try DB.SortedMap(.read_write).init(heads_cursor);
            _ = try heads.remove(input.name);
        },
    }
}
