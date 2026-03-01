const std = @import("std");
const builtin = @import("builtin");
const net = @import("../net.zig");
const net_transport = @import("./transport.zig");
const rp = @import("../repo.zig");
const work = @import("../workdir.zig");
const rf = @import("../ref.zig");

fn defaultBranch(
    comptime repo_kind: rp.RepoKind,
    comptime repo_opts: rp.RepoOpts(repo_kind),
    allocator: std.mem.Allocator,
    remote: *net.Remote(repo_kind, repo_opts),
    out: *std.ArrayList(u8),
) !void {
    const heads = if (remote.transport) |*transport| try transport.getHeads() else return error.RemoteNotConnected;

    if (0 == heads.len or !std.mem.eql(u8, heads[0].name, "HEAD")) {
        return error.DefaultBranchNotFound;
    }

    if (heads[0].symref) |symref| {
        try out.appendSlice(allocator, symref);
        return;
    }

    const head_id = &heads[0].oid;

    var head_maybe: ?*const net.RemoteHead(repo_kind, repo_opts) = null;
    for (heads[1..]) |*head| {
        if (!std.mem.eql(u8, head_id, &head.oid)) {
            continue;
        }

        if (!std.mem.startsWith(u8, head.name, "refs/heads/")) {
            continue;
        }

        if (null == head_maybe) {
            head_maybe = head;
            continue;
        }
    }

    if (head_maybe) |head| {
        try out.appendSlice(allocator, head.name);
    } else {
        return error.DefaultBranchNotFound;
    }
}

fn checkoutBranch(
    comptime repo_kind: rp.RepoKind,
    comptime repo_opts: rp.RepoOpts(repo_kind),
    state: rp.Repo(repo_kind, repo_opts).State(.read_write),
    io: std.Io,
    allocator: std.mem.Allocator,
    remote: *net.Remote(repo_kind, repo_opts),
) !void {
    const remote_name = remote.name orelse return error.RemoteNameNotFound;

    var default_branch = std.ArrayList(u8){};
    defer default_branch.deinit(allocator);
    try defaultBranch(repo_kind, repo_opts, allocator, remote, &default_branch);

    const default_branch_ref = rf.Ref.initFromPath(default_branch.items, .head) orelse return error.InvalidRef;
    const remote_branch_name = default_branch_ref.name;

    try rf.replaceHead(repo_kind, repo_opts, state, io, .{ .ref = .{ .kind = .head, .name = remote_branch_name } });

    const target_oid = try rf.readRecur(
        repo_kind,
        repo_opts,
        state.readOnly(),
        io,
        .{ .ref = .{ .kind = .{ .remote = remote_name }, .name = remote_branch_name } },
    ) orelse return error.InvalidRef;

    var switch_result = try work.Switch(repo_kind, repo_opts).init(state, io, allocator, .{
        .kind = .reset,
        .target = .{ .oid = &target_oid },
    });
    defer switch_result.deinit();
    if (.conflict == switch_result.result) {
        return error.UnexpectedFilesInTargetDirectory;
    }
}

pub fn cloneFile(
    comptime repo_kind: rp.RepoKind,
    comptime repo_opts: rp.RepoOpts(repo_kind),
    state: rp.Repo(repo_kind, repo_opts).State(.read_write),
    io: std.Io,
    allocator: std.mem.Allocator,
    remote: *net.Remote(repo_kind, repo_opts),
    transport_opts: net_transport.Opts(repo_opts.ProgressCtx),
) !void {
    if (try net.resolveRefPath(repo_kind, repo_opts, state.readOnly(), io, allocator, "HEAD")) |_| {
        return error.RepoIsNotEmpty;
    }

    try net.fetch(repo_kind, repo_opts, state, io, allocator, remote, transport_opts);

    try checkoutBranch(repo_kind, repo_opts, state, io, allocator, remote);
}

pub fn cloneWire(
    comptime repo_kind: rp.RepoKind,
    comptime repo_opts: rp.RepoOpts(repo_kind),
    state: rp.Repo(repo_kind, repo_opts).State(.read_write),
    io: std.Io,
    allocator: std.mem.Allocator,
    remote: *net.Remote(repo_kind, repo_opts),
    transport_opts: net_transport.Opts(repo_opts.ProgressCtx),
) !void {
    if (try net.resolveRefPath(repo_kind, repo_opts, state.readOnly(), io, allocator, "HEAD")) |_| {
        return error.RepoIsNotEmpty;
    }

    var remote_copy = try remote.dupe(allocator);
    defer remote_copy.deinit(io, allocator);

    try net.connect(repo_kind, repo_opts, state.readOnly(), io, allocator, &remote_copy, .fetch, transport_opts);

    try net.fetch(repo_kind, repo_opts, state, io, allocator, &remote_copy, transport_opts);

    try checkoutBranch(repo_kind, repo_opts, state, io, allocator, &remote_copy);
}
