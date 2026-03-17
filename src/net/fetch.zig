const std = @import("std");
const net = @import("../net.zig");
const net_transport = @import("./transport.zig");
const net_refspec = @import("./refspec.zig");
const rp = @import("../repo.zig");
const rf = @import("../ref.zig");
const hash = @import("../hash.zig");

pub fn FetchNegotiation(comptime repo_kind: rp.RepoKind, comptime repo_opts: rp.RepoOpts(repo_kind)) type {
    return struct {
        refs: []net.RemoteHead(repo_kind, repo_opts),
    };
}

pub fn negotiate(
    comptime repo_kind: rp.RepoKind,
    comptime repo_opts: rp.RepoOpts(repo_kind),
    state: rp.Repo(repo_kind, repo_opts).State(.read_only),
    io: std.Io,
    allocator: std.mem.Allocator,
    remote: *net.Remote(repo_kind, repo_opts),
) !void {
    remote.requires_fetch = false;

    {
        remote.heads.clearAndFree(allocator);

        var tagspec = try net_refspec.RefSpec.init(allocator, net_refspec.git_refspec_tags, .fetch);
        defer tagspec.deinit(allocator);

        if (remote.active_refspecs.items.len == 0) {
            var head = try net_refspec.RefSpec.init(allocator, "HEAD", .fetch);
            errdefer head.deinit(allocator);
            try remote.active_refspecs.append(allocator, head);
        }

        const heads = if (remote.transport) |*transport| try transport.getHeads() else return error.RemoteNotConnected;

        const remote_caps = if (remote.transport) |*transport|
            transport.capabilities()
        else
            return error.RemoteNotConnected;

        for (heads) |*head| {
            if (!rf.validateName(head.name)) {
                continue;
            }

            if (!net_refspec.matches(tagspec.src, head.name) and null == net.matchingRefSpec(repo_kind, repo_opts, remote, .src, head.name)) {
                continue;
            }

            try remote.heads.put(allocator, head.name, head.*);
        }

        for (remote.active_refspecs.items) |*spec| {
            if (!rf.isOid(repo_opts.hash, spec.src)) {
                continue;
            }

            if (!remote_caps.fetch_by_oid or !remote_caps.fetch_reachable) {
                return error.CannotFetchSpecificObjectFromRemote;
            }

            var oid_head = net.RemoteHead(repo_kind, repo_opts).init(spec.dst);
            oid_head.oid = spec.src[0..comptime hash.hexLen(repo_opts.hash)].*;
            try remote.heads.put(allocator, oid_head.name, oid_head);
        }

        try remote.setLocalHeads(state, io, allocator);
    }

    if (!remote.requires_fetch) {
        return;
    }

    remote.nego.refs = remote.heads.values();

    const t = if (remote.transport) |*transport| transport else return error.NotConnected;
    try t.negotiateFetch(state, io, allocator, &remote.nego);
}

pub fn downloadPack(
    comptime repo_kind: rp.RepoKind,
    comptime repo_opts: rp.RepoOpts(repo_kind),
    state: rp.Repo(repo_kind, repo_opts).State(.read_write),
    io: std.Io,
    allocator: std.mem.Allocator,
    remote: *net.Remote(repo_kind, repo_opts),
) !void {
    if (!remote.requires_fetch) {
        return;
    }

    if (remote.transport) |*transport| {
        try transport.downloadPack(state, io, allocator);
    } else {
        return error.TransportNotFound;
    }
}
