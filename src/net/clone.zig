const std = @import("std");
const builtin = @import("builtin");
const net = @import("../net.zig");
const net_transport = @import("./transport.zig");
const rp = @import("../repo.zig");
const work = @import("../workdir.zig");
const rf = @import("../ref.zig");

fn checkoutBranch(
    comptime repo_kind: rp.RepoKind,
    comptime repo_opts: rp.RepoOpts(repo_kind),
    state: rp.Repo(repo_kind, repo_opts).State(.read_write),
    io: std.Io,
    allocator: std.mem.Allocator,
    remote: *net.Remote(repo_kind, repo_opts),
) !void {
    try rf.replaceHead(repo_kind, repo_opts, state, io, .{ .ref = .{ .kind = .head, .name = "master" } });
    const heads = if (remote.transport) |*transport| try transport.getHeads() else return error.RemoteNotConnected;
    for (heads) |head| {
        if (!std.mem.eql(u8, head.name, "HEAD") or std.mem.allEqual(u8, &head.oid, '0')) continue;
        // the unborn HEAD makes checkout compare against an empty tree.
        var switch_result = try work.Switch(repo_kind, repo_opts).init(state, io, allocator, .{
            .kind = .@"switch",
            .target = .{ .oid = &head.oid },
        });
        defer switch_result.deinit();
        if (.conflict == switch_result.result) return error.UnexpectedFilesInTargetDirectory;
        break;
    }
    try setHead(repo_kind, repo_opts, state, io, remote);
}

fn setHead(
    comptime repo_kind: rp.RepoKind,
    comptime repo_opts: rp.RepoOpts(repo_kind),
    state: rp.Repo(repo_kind, repo_opts).State(.read_write),
    io: std.Io,
    remote: *net.Remote(repo_kind, repo_opts),
) !void {
    const heads = if (remote.transport) |*transport| try transport.getHeads() else return error.RemoteNotConnected;
    for (heads) |head| {
        if (!std.mem.eql(u8, head.name, "HEAD")) continue;
        if (head.symref) |symref| {
            const ref = rf.Ref.initFromPath(symref, .head) orelse return error.InvalidRef;
            try rf.replaceHead(repo_kind, repo_opts, state, io, .{ .ref = ref });
            if (!std.mem.allEqual(u8, &head.oid, '0')) try rf.updateHead(repo_kind, repo_opts, state, io, &head.oid);
            return;
        }
        if (!std.mem.allEqual(u8, &head.oid, '0')) {
            return rf.replaceHead(repo_kind, repo_opts, state, io, .{ .oid = &head.oid });
        }
    }
    try rf.replaceHead(repo_kind, repo_opts, state, io, .{ .ref = .{ .kind = .head, .name = "master" } });
}

pub fn cloneRemote(
    comptime repo_kind: rp.RepoKind,
    comptime repo_opts: rp.RepoOpts(repo_kind),
    state: rp.Repo(repo_kind, repo_opts).State(.read_write),
    io: std.Io,
    allocator: std.mem.Allocator,
    url: []const u8,
    transport_def: net_transport.TransportDefinition,
    transport_opts: net_transport.Opts(repo_opts.ProgressCtx),
) !void {
    if (try net.resolveRefPath(repo_kind, repo_opts, state.readOnly(), io, allocator, "HEAD")) |_| {
        return error.RepoIsNotEmpty;
    }

    const is_bare = try state.isBare(io, allocator);
    const fetch_refspec = if (is_bare) "+refs/heads/*:refs/heads/*" else "+refs/heads/*:refs/remotes/origin/*";
    var remote = try net.Remote(repo_kind, repo_opts).init(state, io, allocator, "origin", url, fetch_refspec);
    defer remote.deinit(io, allocator);

    var fetch_opts = transport_opts;
    var specs: std.ArrayList([]const u8) = .empty;
    defer specs.deinit(allocator);
    if (transport_opts.refspecs) |configured| {
        try specs.appendSlice(allocator, configured);
    } else {
        try specs.append(allocator, fetch_refspec);
    }
    try specs.append(allocator, "HEAD");
    fetch_opts.refspecs = specs.items;

    switch (transport_def) {
        .file => {
            try net.fetch(repo_kind, repo_opts, state, io, allocator, &remote, fetch_opts);

            if (is_bare) {
                try setHead(repo_kind, repo_opts, state, io, &remote);
            } else {
                try checkoutBranch(repo_kind, repo_opts, state, io, allocator, &remote);
            }
        },
        .wire => {
            var remote_copy = try remote.dupe(allocator);
            defer remote_copy.deinit(io, allocator);

            try net.connect(repo_kind, repo_opts, state.readOnly(), io, allocator, &remote_copy, .fetch, fetch_opts);

            try net.fetch(repo_kind, repo_opts, state, io, allocator, &remote_copy, fetch_opts);

            if (is_bare) {
                try setHead(repo_kind, repo_opts, state, io, &remote_copy);
            } else {
                try checkoutBranch(repo_kind, repo_opts, state, io, allocator, &remote_copy);
            }
        },
    }
}
