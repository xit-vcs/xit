const std = @import("std");
const net_fetch = @import("./net/fetch.zig");
const net_transport = @import("./net/transport.zig");
const net_push = @import("./net/push.zig");
const net_refspec = @import("./net/refspec.zig");
const net_clone = @import("./net/clone.zig");
const rp = @import("./repo.zig");
const rf = @import("./ref.zig");
const hash = @import("./hash.zig");
const cfg = @import("./config.zig");
const obj = @import("./object.zig");
const fs = @import("./fs.zig");

pub const Direction = enum {
    fetch,
    push,
};

pub const Opts = net_transport.Opts;
pub const TransportDefinition = net_transport.TransportDefinition;

pub fn RemoteHead(comptime repo_kind: rp.RepoKind, comptime repo_opts: rp.RepoOpts(repo_kind)) type {
    return struct {
        oid: [hash.hexLen(repo_opts.hash)]u8,
        loid: [hash.hexLen(repo_opts.hash)]u8,
        is_local: bool,
        name: []u8,
        symref: ?[]u8,

        pub fn init(name: []u8) RemoteHead(repo_kind, repo_opts) {
            return .{
                .oid = [_]u8{'0'} ** hash.hexLen(repo_opts.hash),
                .loid = [_]u8{'0'} ** hash.hexLen(repo_opts.hash),
                .is_local = false,
                .name = name,
                .symref = null,
            };
        }

        pub fn deinit(self: *RemoteHead(repo_kind, repo_opts), allocator: std.mem.Allocator) void {
            allocator.free(self.name);
            if (self.symref) |target| allocator.free(target);
        }
    };
}

pub fn Remote(comptime repo_kind: rp.RepoKind, comptime repo_opts: rp.RepoOpts(repo_kind)) type {
    return struct {
        name: ?[]const u8,
        url: ?[]const u8,
        push_url: ?[]const u8,
        heads: std.StringArrayHashMapUnmanaged(RemoteHead(repo_kind, repo_opts)),
        refspecs: std.ArrayList(net_refspec.RefSpec),
        active_refspecs: std.ArrayList(net_refspec.RefSpec),
        transport: ?net_transport.Transport(repo_kind, repo_opts),
        requires_fetch: bool,
        nego: net_fetch.FetchNegotiation(repo_kind, repo_opts),

        pub fn init(
            state: rp.Repo(repo_kind, repo_opts).State(.read_write),
            io: std.Io,
            allocator: std.mem.Allocator,
            name: []const u8,
            url: []const u8,
        ) !Remote(repo_kind, repo_opts) {
            switch (repo_kind) {
                .git => {
                    var lock = try fs.LockFile.init(io, state.core.repo_dir, "config");
                    defer lock.deinit(io);

                    try addConfig(.{ .core = state.core, .extra = .{ .lock_file_maybe = lock.lock_file } }, io, allocator, name, url);

                    lock.success = true;
                },
                .xit => try addConfig(state, io, allocator, name, url),
            }

            return try open(state.readOnly(), io, allocator, name);
        }

        pub fn open(
            state: rp.Repo(repo_kind, repo_opts).State(.read_only),
            io: std.Io,
            allocator: std.mem.Allocator,
            name: []const u8,
        ) !Remote(repo_kind, repo_opts) {
            if (!rf.validateName(name)) {
                return error.InvalidRemoteName;
            }

            var config = try cfg.Config(repo_kind, repo_opts).init(state, io, allocator);
            defer config.deinit();

            var self: Remote(repo_kind, repo_opts) = .{
                .name = null,
                .url = null,
                .push_url = null,
                .heads = undefined,
                .refspecs = std.ArrayList(net_refspec.RefSpec){},
                .active_refspecs = std.ArrayList(net_refspec.RefSpec){},
                .transport = null,
                .requires_fetch = false,
                .nego = undefined,
            };
            errdefer {
                clearRefSpecs(allocator, &self.refspecs);
                self.refspecs.deinit(allocator);

                clearRefSpecs(allocator, &self.active_refspecs);
                self.active_refspecs.deinit(allocator);
            }

            const name_copy = try allocator.dupe(u8, name);
            errdefer allocator.free(name_copy);
            self.name = name_copy;

            self.heads = try std.StringArrayHashMapUnmanaged(RemoteHead(repo_kind, repo_opts)).init(allocator, &.{}, &.{});
            errdefer self.heads.deinit(allocator);

            const remote_section_name = try std.fmt.allocPrint(allocator, "remote.{s}", .{name});
            defer allocator.free(remote_section_name);

            const remote_vars = config.sections.get(remote_section_name) orelse return error.ConfigNotFound;
            var found_remote = false;

            if (remote_vars.get("url")) |remote_url| {
                found_remote = true;
                self.url = try allocator.dupe(u8, remote_url);
            }
            errdefer if (self.url) |remote_url| allocator.free(remote_url);

            if (remote_vars.get("pushurl")) |remote_push_url| {
                found_remote = true;
                self.push_url = try allocator.dupe(u8, remote_push_url);
            }
            errdefer if (self.push_url) |remote_push_url| allocator.free(remote_push_url);

            if (!found_remote) {
                return error.RemoteNotFound;
            }

            if (remote_vars.get("fetch")) |spec_str| {
                var spec = try net_refspec.RefSpec.init(allocator, spec_str, .fetch);
                errdefer spec.deinit(allocator);
                try self.refspecs.append(allocator, spec);
            }

            if (remote_vars.get("push")) |spec_str| {
                var spec = try net_refspec.RefSpec.init(allocator, spec_str, .push);
                errdefer spec.deinit(allocator);
                try self.refspecs.append(allocator, spec);
            }

            for (self.refspecs.items) |*spec| {
                var spec_dupe = try spec.dupe(allocator);
                errdefer spec_dupe.deinit(allocator);
                try self.active_refspecs.append(allocator, spec_dupe);
            }

            return self;
        }

        pub fn deinit(self: *Remote(repo_kind, repo_opts), io: std.Io, allocator: std.mem.Allocator) void {
            if (self.name) |name| allocator.free(name);
            if (self.url) |url| allocator.free(url);
            if (self.push_url) |push_url| allocator.free(push_url);

            self.heads.deinit(allocator);

            clearRefSpecs(allocator, &self.refspecs);
            self.refspecs.deinit(allocator);

            clearRefSpecs(allocator, &self.active_refspecs);
            self.active_refspecs.deinit(allocator);

            if (self.transport) |*transport| {
                self.disconnect(io, allocator);

                transport.deinit(io, allocator);

                self.transport = null;
            }
        }

        pub fn addConfig(
            state: rp.Repo(repo_kind, repo_opts).State(.read_write),
            io: std.Io,
            allocator: std.mem.Allocator,
            name: []const u8,
            url: []const u8,
        ) !void {
            var config = try cfg.Config(repo_kind, repo_opts).init(state.readOnly(), io, allocator);
            defer config.deinit();

            {
                const config_name = try std.fmt.allocPrint(allocator, "remote.{s}.url", .{name});
                defer allocator.free(config_name);

                try config.add(state, io, .{ .name = config_name, .value = url });
            }

            {
                const config_name = try std.fmt.allocPrint(allocator, "remote.{s}.fetch", .{name});
                defer allocator.free(config_name);

                const config_value = try std.fmt.allocPrint(allocator, "+refs/heads/*:refs/remotes/{s}/*", .{name});
                defer allocator.free(config_value);

                try config.add(state, io, .{ .name = config_name, .value = config_value });
            }
        }

        pub fn removeConfig(
            state: rp.Repo(repo_kind, repo_opts).State(.read_write),
            io: std.Io,
            allocator: std.mem.Allocator,
            name: []const u8,
        ) !void {
            var config = try cfg.Config(repo_kind, repo_opts).init(state.readOnly(), io, allocator);
            defer config.deinit();

            {
                const config_name = try std.fmt.allocPrint(allocator, "remote.{s}.url", .{name});
                defer allocator.free(config_name);

                try config.remove(state, io, .{ .name = config_name });
            }

            {
                const config_name = try std.fmt.allocPrint(allocator, "remote.{s}.fetch", .{name});
                defer allocator.free(config_name);

                try config.remove(state, io, .{ .name = config_name });
            }
        }

        pub fn dupe(self: *const Remote(repo_kind, repo_opts), allocator: std.mem.Allocator) !Remote(repo_kind, repo_opts) {
            var remote = std.mem.zeroInit(Remote(repo_kind, repo_opts), .{});

            if (self.name) |name| {
                remote.name = try allocator.dupe(u8, name);
            }

            if (self.url) |url| {
                remote.url = try allocator.dupe(u8, url);
            }

            if (self.push_url) |push_url| {
                remote.push_url = try allocator.dupe(u8, push_url);
            }

            remote.heads = try std.StringArrayHashMapUnmanaged(RemoteHead(repo_kind, repo_opts)).init(allocator, &.{}, &.{});
            remote.refspecs = std.ArrayList(net_refspec.RefSpec){};
            remote.active_refspecs = std.ArrayList(net_refspec.RefSpec){};

            for (self.refspecs.items) |*spec| {
                var spec_dupe = try spec.dupe(allocator);
                errdefer spec_dupe.deinit(allocator);
                try remote.refspecs.append(allocator, spec_dupe);
            }

            return remote;
        }

        pub fn connected(self: *const Remote(repo_kind, repo_opts)) bool {
            if (self.transport) |*transport| {
                return transport.isConnected();
            }

            return false;
        }

        pub fn stop(self: *Remote(repo_kind, repo_opts)) void {
            if (self.transport) |*transport| {
                transport.cancel();
            }
        }

        pub fn disconnect(self: *Remote(repo_kind, repo_opts), io: std.Io, allocator: std.mem.Allocator) void {
            if (self.connected()) {
                if (self.transport) |*transport| {
                    transport.close(io, allocator);
                }
            }
        }

        pub fn setLocalHeads(
            self: *Remote(repo_kind, repo_opts),
            state: rp.Repo(repo_kind, repo_opts).State(.read_only),
            io: std.Io,
            allocator: std.mem.Allocator,
        ) !void {
            for (self.heads.values()) |*head| {
                var obj_exists = true;
                var object_or_err = obj.Object(repo_kind, repo_opts, .raw).init(state, io, allocator, &head.oid);
                if (object_or_err) |*object| {
                    defer object.deinit();
                } else |err| switch (err) {
                    error.ObjectNotFound => obj_exists = false,
                    else => |e| return e,
                }

                if (obj_exists) {
                    head.is_local = true;
                } else {
                    self.requires_fetch = true;
                }
            }
        }
    };
}

pub fn validateUrl(io: std.Io, cwd: std.Io.Dir, url: []const u8) bool {
    return net_transport.TransportDefinition.init(io, cwd, url) != null;
}

pub fn matchingRefSpec(
    comptime repo_kind: rp.RepoKind,
    comptime repo_opts: rp.RepoOpts(repo_kind),
    remote: *Remote(repo_kind, repo_opts),
    comptime kind: enum { dst, src },
    refname: []const u8,
) ?*net_refspec.RefSpec {
    for (remote.active_refspecs.items) |*spec| {
        if (.push == spec.direction) {
            continue;
        }
        const target = switch (kind) {
            .dst => spec.dst,
            .src => spec.src,
        };
        if (net_refspec.matches(target, refname)) {
            return spec;
        }
    }
    return null;
}

pub fn clearRefSpecs(allocator: std.mem.Allocator, arr: *std.ArrayList(net_refspec.RefSpec)) void {
    for (arr.items) |*spec| {
        spec.deinit(allocator);
    }
    arr.clearAndFree(allocator);
}

fn getHeads(
    comptime repo_kind: rp.RepoKind,
    comptime repo_opts: rp.RepoOpts(repo_kind),
    remote: *Remote(repo_kind, repo_opts),
    allocator: std.mem.Allocator,
) !std.StringArrayHashMapUnmanaged(RemoteHead(repo_kind, repo_opts)) {
    var refs = try std.StringArrayHashMapUnmanaged(RemoteHead(repo_kind, repo_opts)).init(allocator, &.{}, &.{});
    errdefer refs.deinit(allocator);

    const heads = if (remote.transport) |*transport| try transport.getHeads() else return error.RemoteNotConnected;

    for (heads) |*head| {
        try refs.put(allocator, head.name, head.*);
    }

    return refs;
}

pub fn connect(
    comptime repo_kind: rp.RepoKind,
    comptime repo_opts: rp.RepoOpts(repo_kind),
    state: rp.Repo(repo_kind, repo_opts).State(.read_only),
    io: std.Io,
    allocator: std.mem.Allocator,
    remote: *Remote(repo_kind, repo_opts),
    direction: Direction,
    transport_opts: Opts(repo_opts.ProgressCtx),
) !void {
    const url = switch (direction) {
        .fetch => remote.url,
        .push => remote.push_url orelse remote.url,
    } orelse return error.UrlNotFound;

    if (remote.transport) |*transport| {
        try transport.connect(state, io, allocator, url, direction);
    } else {
        var t = try net_transport.Transport(repo_kind, repo_opts).init(state, io, allocator, url, transport_opts);
        errdefer t.deinit(io, allocator);
        try t.connect(state, io, allocator, url, direction);
        remote.transport = t;
    }
}

fn updateRef(
    comptime repo_kind: rp.RepoKind,
    comptime repo_opts: rp.RepoOpts(repo_kind),
    state: rp.Repo(repo_kind, repo_opts).State(.read_write),
    io: std.Io,
    ref_path: []const u8,
    oid_hex: *const [hash.hexLen(repo_opts.hash)]u8,
) !void {
    const ref = rf.Ref.initFromPath(ref_path, null) orelse return error.InvalidRefPath;
    const existing_oid_maybe = try rf.readRecur(repo_kind, repo_opts, state.readOnly(), io, .{ .ref = ref });

    if (existing_oid_maybe) |*existing_oid| {
        if (std.mem.eql(u8, existing_oid, oid_hex)) {
            return;
        }
        // TODO: assert that `old_id` is the content of the ref.
        // this will be unnecessary when repo_kind is .xit because
        // everything will be in a transaction, but with git the
        // file may have been modified after we read it.
    }

    try rf.write(repo_kind, repo_opts, state, io, ref_path, .{ .oid = oid_hex });
}

pub fn resolveRef(
    comptime repo_kind: rp.RepoKind,
    comptime repo_opts: rp.RepoOpts(repo_kind),
    state: rp.Repo(repo_kind, repo_opts).State(.read_only),
    io: std.Io,
    allocator: std.mem.Allocator,
    ref: rf.Ref,
) !?[hash.hexLen(repo_opts.hash)]u8 {
    const oid = try rf.readRecur(repo_kind, repo_opts, state, io, .{ .ref = ref }) orelse return null;
    var object = obj.Object(repo_kind, repo_opts, .raw).init(state, io, allocator, &oid) catch |err| switch (err) {
        error.ObjectNotFound => return null,
        else => |e| return e,
    };
    defer object.deinit();
    return oid;
}

pub fn resolveRefPath(
    comptime repo_kind: rp.RepoKind,
    comptime repo_opts: rp.RepoOpts(repo_kind),
    state: rp.Repo(repo_kind, repo_opts).State(.read_only),
    io: std.Io,
    allocator: std.mem.Allocator,
    ref_path: []const u8,
) !?[hash.hexLen(repo_opts.hash)]u8 {
    const ref = rf.Ref.initFromPath(ref_path, null) orelse return error.InvalidRefPath;
    return try resolveRef(repo_kind, repo_opts, state, io, allocator, ref);
}

fn updateHead(
    comptime repo_kind: rp.RepoKind,
    comptime repo_opts: rp.RepoOpts(repo_kind),
    state: rp.Repo(repo_kind, repo_opts).State(.read_write),
    io: std.Io,
    allocator: std.mem.Allocator,
    spec: *net_refspec.RefSpec,
    head: *RemoteHead(repo_kind, repo_opts),
    tagspec: *net_refspec.RefSpec,
) !void {
    var ref_path = std.ArrayList(u8){};
    defer ref_path.deinit(allocator);

    if (!net_refspec.validateName(head.name, false)) {
        return;
    }

    if (net_refspec.matches(tagspec.src, head.name)) {
        try ref_path.appendSlice(allocator, head.name);
    }

    if (net_refspec.matches(spec.src, head.name)) {
        if (spec.dst.len > 0) {
            try net_refspec.transform(allocator, &ref_path, spec, head.name);
        } else {
            return;
        }
    }

    if (0 == ref_path.items.len) {
        return;
    }

    const oid_maybe = try resolveRefPath(repo_kind, repo_opts, state.readOnly(), io, allocator, ref_path.items);

    if (oid_maybe) |*oid| {
        if (!spec.is_force) {
            // TODO: return early if head.oid is a descendent of oid
            _ = oid;
        }
    }

    try rf.write(repo_kind, repo_opts, state, io, ref_path.items, .{ .oid = &head.oid });
}

fn updateRefs(
    comptime repo_kind: rp.RepoKind,
    comptime repo_opts: rp.RepoOpts(repo_kind),
    state: rp.Repo(repo_kind, repo_opts).State(.read_write),
    io: std.Io,
    allocator: std.mem.Allocator,
    spec: *net_refspec.RefSpec,
    refs: *std.StringArrayHashMapUnmanaged(RemoteHead(repo_kind, repo_opts)),
) !void {
    var tagspec = try net_refspec.RefSpec.init(allocator, net_refspec.git_refspec_tags, .fetch);
    defer tagspec.deinit(allocator);

    for (refs.values()) |*head| {
        try updateHead(repo_kind, repo_opts, state, io, allocator, spec, head, &tagspec);
    }

    if (rf.isOid(repo_opts.hash, spec.src)) {
        if (spec.dst.len > 0) {
            try updateRef(repo_kind, repo_opts, state, io, spec.dst, spec.src[0..comptime hash.hexLen(repo_opts.hash)]);
        }
    }
}

fn updateHeads(
    comptime repo_kind: rp.RepoKind,
    comptime repo_opts: rp.RepoOpts(repo_kind),
    state: rp.Repo(repo_kind, repo_opts).State(.read_write),
    io: std.Io,
    allocator: std.mem.Allocator,
    remote: *Remote(repo_kind, repo_opts),
) !void {
    var tagspec = try net_refspec.RefSpec.init(allocator, net_refspec.git_refspec_tags, .fetch);
    defer tagspec.deinit(allocator);

    var refs = try getHeads(repo_kind, repo_opts, remote, allocator);
    defer refs.deinit(allocator);

    try updateRefs(repo_kind, repo_opts, state, io, allocator, &tagspec, &refs);

    for (remote.active_refspecs.items) |*spec| {
        if (.push == spec.direction) {
            continue;
        }
        try updateRefs(repo_kind, repo_opts, state, io, allocator, spec, &refs);
    }
}

pub fn fetch(
    comptime repo_kind: rp.RepoKind,
    comptime repo_opts: rp.RepoOpts(repo_kind),
    state: rp.Repo(repo_kind, repo_opts).State(.read_write),
    io: std.Io,
    allocator: std.mem.Allocator,
    remote: *Remote(repo_kind, repo_opts),
    transport_opts: Opts(repo_opts.ProgressCtx),
) !void {
    if (!remote.connected()) {
        try connect(repo_kind, repo_opts, state.readOnly(), io, allocator, remote, .fetch, transport_opts);
    }
    defer remote.disconnect(io, allocator);

    var refs = try getHeads(repo_kind, repo_opts, remote, allocator);
    defer refs.deinit(allocator);

    var specs = std.ArrayList(net_refspec.RefSpec){};
    defer {
        clearRefSpecs(allocator, &specs);
        specs.deinit(allocator);
    }

    const new_active_refspecs: *std.ArrayList(net_refspec.RefSpec) =
        if (transport_opts.refspecs) |refspecs| blk: {
            if (refspecs.len == 0) {
                break :blk &remote.refspecs;
            } else {
                for (refspecs) |refspec| {
                    var spec = try net_refspec.RefSpec.init(allocator, refspec, .fetch);
                    errdefer spec.deinit(allocator);
                    try specs.append(allocator, spec);
                }
                break :blk &specs;
            }
        } else &remote.refspecs;

    clearRefSpecs(allocator, &remote.active_refspecs);
    for (new_active_refspecs.items) |*spec| {
        var spec_dupe = try spec.dupe(allocator);
        errdefer spec_dupe.deinit(allocator);
        try remote.active_refspecs.append(allocator, spec_dupe);
    }

    try net_fetch.negotiate(repo_kind, repo_opts, state.readOnly(), io, allocator, remote);

    try net_fetch.downloadPack(repo_kind, repo_opts, state, io, allocator, remote);

    try updateHeads(repo_kind, repo_opts, state, io, allocator, remote);
}

pub fn push(
    comptime repo_kind: rp.RepoKind,
    comptime repo_opts: rp.RepoOpts(repo_kind),
    state: rp.Repo(repo_kind, repo_opts).State(.read_only),
    io: std.Io,
    allocator: std.mem.Allocator,
    remote: *Remote(repo_kind, repo_opts),
    transport_opts: Opts(repo_opts.ProgressCtx),
) !void {
    if (!remote.connected()) {
        try connect(repo_kind, repo_opts, state, io, allocator, remote, .push, transport_opts);
    }

    clearRefSpecs(allocator, &remote.active_refspecs);
    for (remote.refspecs.items) |*spec| {
        var spec_dupe = try spec.dupe(allocator);
        errdefer spec_dupe.deinit(allocator);
        try remote.active_refspecs.append(allocator, spec_dupe);
    }

    var remote_push = try net_push.Push(repo_kind, repo_opts).init(state, remote, io, allocator);
    defer remote_push.deinit(allocator);

    var added_refspecs = false;
    if (transport_opts.refspecs) |refspecs| {
        for (refspecs) |refspec| {
            try remote_push.addRefSpec(state, io, allocator, refspec);
            added_refspecs = true;
        }
    }
    if (!added_refspecs) {
        for (remote.refspecs.items) |*spec| {
            if (.fetch == spec.direction) {
                continue;
            }
            try remote_push.addRefSpec(state, io, allocator, spec.full);
        }
    }

    try remote_push.complete(state, io, allocator);

    defer remote.disconnect(io, allocator);
}

pub fn clone(
    comptime repo_kind: rp.RepoKind,
    comptime repo_opts: rp.RepoOpts(repo_kind),
    io: std.Io,
    allocator: std.mem.Allocator,
    url: []const u8,
    cwd_path: []const u8,
    work_path: []const u8,
    transport_opts: Opts(repo_opts.ProgressCtx),
) !rp.Repo(repo_kind, repo_opts) {
    var repo = try rp.Repo(repo_kind, repo_opts).init(io, allocator, .{
        .cwd_path = cwd_path,
        .path = work_path,
        .create_default_branch = null,
    });
    errdefer repo.deinit(io, allocator);

    var cwd = try std.Io.Dir.openDirAbsolute(io, cwd_path, .{});
    defer cwd.close(io);

    const transport_def = net_transport.TransportDefinition.init(io, cwd, url) orelse return error.UnsupportedUrl;

    switch (repo_kind) {
        .git => {
            var remote = try Remote(repo_kind, repo_opts).init(
                .{ .core = &repo.core, .extra = .{} },
                io,
                allocator,
                "origin",
                url,
            );
            defer remote.deinit(io, allocator);

            switch (transport_def) {
                .file => try net_clone.cloneFile(
                    repo_kind,
                    repo_opts,
                    .{ .core = &repo.core, .extra = .{} },
                    io,
                    allocator,
                    &remote,
                    transport_opts,
                ),
                .wire => try net_clone.cloneWire(
                    repo_kind,
                    repo_opts,
                    .{ .core = &repo.core, .extra = .{} },
                    io,
                    allocator,
                    &remote,
                    transport_opts,
                ),
            }
        },
        .xit => {
            const Ctx = struct {
                core: *rp.Repo(repo_kind, repo_opts).Core,
                transport_def: net_transport.TransportDefinition,
                io: std.Io,
                allocator: std.mem.Allocator,
                url: []const u8,
                transport_opts: Opts(repo_opts.ProgressCtx),

                pub fn run(ctx: @This(), cursor: *rp.Repo(repo_kind, repo_opts).DB.Cursor(.read_write)) !void {
                    var moment = try rp.Repo(repo_kind, repo_opts).DB.HashMap(.read_write).init(cursor.*);
                    const state = rp.Repo(repo_kind, repo_opts).State(.read_write){ .core = ctx.core, .extra = .{ .moment = &moment } };

                    var remote = try Remote(repo_kind, repo_opts).init(state, ctx.io, ctx.allocator, "origin", ctx.url);
                    defer remote.deinit(ctx.io, ctx.allocator);

                    switch (ctx.transport_def) {
                        .file => try net_clone.cloneFile(
                            repo_kind,
                            repo_opts,
                            state,
                            ctx.io,
                            ctx.allocator,
                            &remote,
                            ctx.transport_opts,
                        ),
                        .wire => try net_clone.cloneWire(
                            repo_kind,
                            repo_opts,
                            state,
                            ctx.io,
                            ctx.allocator,
                            &remote,
                            ctx.transport_opts,
                        ),
                    }

                    const un = @import("./undo.zig");
                    try un.writeMessage(repo_opts, state, .{ .clone = .{ .url = ctx.url } });
                }
            };

            const history = try rp.Repo(repo_kind, repo_opts).DB.ArrayList(.read_write).init(repo.core.db.rootCursor());
            try history.appendContext(
                .{ .slot = try history.getSlot(-1) },
                Ctx{
                    .core = &repo.core,
                    .transport_def = transport_def,
                    .io = io,
                    .allocator = allocator,
                    .url = url,
                    .transport_opts = transport_opts,
                },
            );
        },
    }

    return repo;
}
