const std = @import("std");
const hash = @import("./hash.zig");
const rf = @import("./ref.zig");
const rp = @import("./repo.zig");
const obj = @import("./object.zig");

pub const TagCommand = union(enum) {
    list,
    add: AddTagInput,
    remove: RemoveTagInput,
};

pub const AddTagInput = struct {
    name: []const u8,
    tagger: ?[]const u8 = null,
    message: ?[]const u8 = null,
};

pub const RemoveTagInput = struct {
    name: []const u8,
};

pub fn add(
    comptime repo_kind: rp.RepoKind,
    comptime repo_opts: rp.RepoOpts(repo_kind),
    state: rp.Repo(repo_kind, repo_opts).State(.read_write),
    io: std.Io,
    allocator: std.mem.Allocator,
    input: AddTagInput,
) ![hash.hexLen(repo_opts.hash)]u8 {
    if (!rf.validateName(input.name)) {
        return error.InvalidTagName;
    }

    const ref_path = try std.fmt.allocPrint(allocator, "refs/tags/{s}", .{input.name});
    defer allocator.free(ref_path);

    const target = try rf.readHeadRecur(repo_kind, repo_opts, state.readOnly(), io);
    const tag_oid = try obj.writeTag(repo_kind, repo_opts, state, io, allocator, input, &target);
    try rf.write(repo_kind, repo_opts, state, io, ref_path, .{ .oid = &tag_oid });

    return tag_oid;
}

pub fn remove(
    comptime repo_kind: rp.RepoKind,
    comptime repo_opts: rp.RepoOpts(repo_kind),
    state: rp.Repo(repo_kind, repo_opts).State(.read_write),
    io: std.Io,
    input: RemoveTagInput,
) !void {
    switch (repo_kind) {
        .git => {
            var refs_dir = try state.core.repo_dir.openDir(io, "refs", .{});
            defer refs_dir.close(io);
            var tags_dir = try refs_dir.createDirPathOpen(io, "tags", .{});
            defer tags_dir.close(io);

            // delete file
            try tags_dir.deleteFile(io, input.name);

            // delete parent dirs
            // this is only necessary because tags with a slash
            // in their name are stored on disk as subdirectories
            var parent_path_maybe = std.fs.path.dirname(input.name);
            while (parent_path_maybe) |parent_path| {
                tags_dir.deleteDir(io, parent_path) catch |err| switch (err) {
                    error.DirNotEmpty => break,
                    else => |e| return e,
                };
                parent_path_maybe = std.fs.path.dirname(parent_path);
            }
        },
        .xit => {
            const name_hash = hash.hashInt(repo_opts.hash, input.name);

            // remove from refs/tags/{name}
            const refs_cursor = try state.extra.moment.putCursor(hash.hashInt(repo_opts.hash, "refs"));
            const refs = try rp.Repo(repo_kind, repo_opts).DB.HashMap(.read_write).init(refs_cursor);
            const tags_cursor = try refs.putCursor(hash.hashInt(repo_opts.hash, "tags"));
            const tags = try rp.Repo(repo_kind, repo_opts).DB.HashMap(.read_write).init(tags_cursor);
            if (!try tags.remove(name_hash)) {
                return error.TagNotFound;
            }
        },
    }
}
