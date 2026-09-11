const std = @import("std");
const net_fetch = @import("./net/fetch.zig");
const net_transport = @import("./net/transport.zig");
const net_push = @import("./net/push.zig");
const net_refspec = @import("./net/refspec.zig");
const net_wire = @import("./net/wire.zig");
const net_file = @import("./net/file.zig");
const net_ssh = @import("./net/ssh.zig");
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

pub fn RemoteHead(comptime hash_kind: hash.HashKind) type {
    return struct {
        oid: [hash.hexLen(hash_kind)]u8,
        is_local: bool,
        name: []u8,
        symref: ?[]u8,

        pub fn init(name: []u8) RemoteHead(hash_kind) {
            return .{
                .oid = [_]u8{'0'} ** hash.hexLen(hash_kind),
                .is_local = false,
                .name = name,
                .symref = null,
            };
        }

        pub fn deinit(self: *RemoteHead(hash_kind), allocator: std.mem.Allocator) void {
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
        heads: std.StringArrayHashMapUnmanaged(RemoteHead(repo_opts.hash)),
        refspecs: std.ArrayList(net_refspec.RefSpec),
        active_refspecs: std.ArrayList(net_refspec.RefSpec),
        transport: ?net_transport.Transport(repo_kind, repo_opts),
        requires_fetch: bool,

        pub fn init(
            state: rp.Repo(repo_kind, repo_opts).State(.read_write),
            io: std.Io,
            allocator: std.mem.Allocator,
            name: []const u8,
            url: []const u8,
            fetch_refspec: ?[]const u8,
        ) !Remote(repo_kind, repo_opts) {
            switch (repo_kind) {
                .git => {
                    var lock = try fs.LockFile.init(io, state.core.repo_dir, "config");
                    defer lock.deinit(io);

                    try addConfig(.{ .core = state.core, .extra = .{ .lock_file_maybe = lock.lock_file } }, io, allocator, name, url, fetch_refspec);

                    lock.success = true;
                },
                .xit => try addConfig(state, io, allocator, name, url, fetch_refspec),
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
                .refspecs = .empty,
                .active_refspecs = .empty,
                .transport = null,
                .requires_fetch = false,
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

            self.heads = try std.StringArrayHashMapUnmanaged(RemoteHead(repo_opts.hash)).init(allocator, &.{}, &.{});
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
            fetch_refspec: ?[]const u8,
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

                const config_value = fetch_refspec orelse try std.fmt.allocPrint(allocator, "+refs/heads/*:refs/remotes/{s}/*", .{name});
                defer if (fetch_refspec == null) allocator.free(config_value);

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
                var object_reader_or_err = obj.ObjectReader(repo_kind, repo_opts).init(state, io, allocator, &head.oid);
                if (object_reader_or_err) |*object_reader| {
                    defer object_reader.deinit();
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
    refname: []const u8,
) ?*net_refspec.RefSpec {
    for (remote.active_refspecs.items) |*spec| {
        if (.push == spec.direction) {
            continue;
        }
        if (net_refspec.matches(spec.src, refname)) {
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
) !std.StringArrayHashMapUnmanaged(RemoteHead(repo_opts.hash)) {
    var refs = try std.StringArrayHashMapUnmanaged(RemoteHead(repo_opts.hash)).init(allocator, &.{}, &.{});
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
    var object_reader = obj.ObjectReader(repo_kind, repo_opts).init(state, io, allocator, &oid) catch |err| switch (err) {
        error.ObjectNotFound => return null,
        else => |e| return e,
    };
    defer object_reader.deinit();
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
    head: *RemoteHead(repo_opts.hash),
    tagspec: *net_refspec.RefSpec,
) !void {
    var ref_path: std.ArrayList(u8) = .empty;
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
    refs: *std.StringArrayHashMapUnmanaged(RemoteHead(repo_opts.hash)),
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

    var specs: std.ArrayList(net_refspec.RefSpec) = .empty;
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

pub fn CloneOpts(comptime ProgressCtx: type) type {
    return struct {
        bare: bool = false,
        transport: Opts(ProgressCtx) = .{},
    };
}

pub fn clone(
    comptime repo_kind: rp.RepoKind,
    comptime repo_opts: rp.RepoOpts(repo_kind),
    io: std.Io,
    allocator: std.mem.Allocator,
    url: []const u8,
    cwd_path: []const u8,
    work_path: []const u8,
    global_config_path: ?[]const u8,
    clone_opts: CloneOpts(repo_opts.ProgressCtx),
) !rp.Repo(repo_kind, repo_opts) {
    var prepared: ?net_transport.Transport(repo_kind, repo_opts) = null;
    return cloneWithTransport(repo_kind, repo_opts, io, allocator, url, cwd_path, work_path, global_config_path, clone_opts, &prepared);
}

fn cloneWithTransport(
    comptime repo_kind: rp.RepoKind,
    comptime repo_opts: rp.RepoOpts(repo_kind),
    io: std.Io,
    allocator: std.mem.Allocator,
    url: []const u8,
    cwd_path: []const u8,
    work_path: []const u8,
    global_config_path: ?[]const u8,
    clone_opts: CloneOpts(repo_opts.ProgressCtx),
    prepared: *?net_transport.Transport(repo_kind, repo_opts),
) !rp.Repo(repo_kind, repo_opts) {
    var repo = try rp.Repo(repo_kind, repo_opts).init(io, allocator, .{
        .bare = clone_opts.bare,
        .cwd_path = cwd_path,
        .path = work_path,
        .create_default_branch = null,
        .global_config_path = global_config_path,
    });
    errdefer repo.deinit(io, allocator);

    switch (repo_kind) {
        .git => try net_clone.cloneRemote(repo_kind, repo_opts, .{ .core = &repo.core, .extra = .{} }, io, allocator, url, clone_opts.transport, prepared),
        .xit => {
            const Ctx = struct {
                core: *rp.Repo(repo_kind, repo_opts).Core,
                io: std.Io,
                allocator: std.mem.Allocator,
                url: []const u8,
                transport_opts: Opts(repo_opts.ProgressCtx),
                prepared: *?net_transport.Transport(repo_kind, repo_opts),

                pub fn run(ctx: @This(), cursor: *rp.Repo(repo_kind, repo_opts).DB.Cursor(.read_write)) !void {
                    var moment = try rp.Repo(repo_kind, repo_opts).DB.HashMap(.read_write).init(cursor.*);
                    const state = rp.Repo(repo_kind, repo_opts).State(.read_write){ .core = ctx.core, .extra = .{ .moment = &moment } };

                    try net_clone.cloneRemote(repo_kind, repo_opts, state, ctx.io, ctx.allocator, ctx.url, ctx.transport_opts, ctx.prepared);

                    const un = @import("./undo.zig");
                    try un.writeMessage(repo_opts, state, .{ .clone = .{ .url = ctx.url } });
                }
            };

            const history = try rp.Repo(repo_kind, repo_opts).DB.ArrayList(.read_write).init(repo.core.db.rootCursor());
            try history.appendContext(
                .{ .slot = try history.getSlot(-1) },
                Ctx{
                    .core = &repo.core,
                    .io = io,
                    .allocator = allocator,
                    .url = url,
                    .transport_opts = clone_opts.transport,
                    .prepared = prepared,
                },
            );
        },
    }

    return repo;
}

pub fn cloneAuto(
    comptime repo_kind: rp.RepoKind,
    comptime any_repo_opts: rp.AnyRepoOpts(repo_kind),
    io: std.Io,
    allocator: std.mem.Allocator,
    url: []const u8,
    cwd_path: []const u8,
    work_path: []const u8,
    global_config_path: ?[]const u8,
    opts: CloneOpts(any_repo_opts.ProgressCtx),
) !rp.AnyRepo(repo_kind, any_repo_opts) {
    var cwd = try std.Io.Dir.openDirAbsolute(io, cwd_path, .{});
    defer cwd.close(io);
    const transport_def = TransportDefinition.init(io, cwd, url) orelse return error.UnsupportedUrl;
    switch (transport_def) {
        .file => switch (try net_file.sourceHash(io, allocator, cwd_path, url)) {
            inline else => |kind| return @unionInit(rp.AnyRepo(repo_kind, any_repo_opts), @tagName(kind), try clone(repo_kind, any_repo_opts.toRepoOptsWithHash(kind), io, allocator, url, cwd_path, work_path, global_config_path, opts)),
        },
        .wire => |wire_kind| {
            var arena = std.heap.ArenaAllocator.init(allocator);
            defer arena.deinit();
            var wire_opts = opts.transport.wire;
            if (wire_kind == .ssh and wire_opts.ssh.command == null) {
                const sections = try cfg.readGlobal(repo_kind, any_repo_opts.toRepoOpts(), io, allocator, arena.allocator(), global_config_path);
                wire_opts.ssh.command = net_ssh.commandFromConfig(sections);
            }
            var connection = try net_wire.Connection(any_repo_opts.net_buffer_size).init(io, allocator, wire_kind, wire_opts);
            var owns_connection = true;
            defer if (owns_connection) connection.deinit(io, allocator);
            try connection.start(io, allocator, url, .list_upload_pack);
            switch (try connection.discoverHash(io, allocator, any_repo_opts.ProgressCtx, opts.transport.progress_ctx)) {
                inline else => |kind| {
                    const repo_opts = comptime any_repo_opts.toRepoOptsWithHash(kind);
                    var prepared: ?net_transport.Transport(repo_kind, repo_opts) = .{
                        .wire = net_wire.WireTransport(repo_kind, repo_opts).initConnection(connection, opts.transport),
                    };
                    owns_connection = false;
                    defer if (prepared) |*transport| transport.deinit(io, allocator);
                    if (prepared) |*transport| try transport.wire.finishConnect(io, allocator);
                    return @unionInit(rp.AnyRepo(repo_kind, any_repo_opts), @tagName(kind), try cloneWithTransport(repo_kind, repo_opts, io, allocator, url, cwd_path, work_path, global_config_path, opts, &prepared));
                },
            }
        },
    }
}
