const std = @import("std");
const builtin = @import("builtin");
const net = @import("../net.zig");
const net_transport = @import("./transport.zig");
const net_refspec = @import("./refspec.zig");
const rp = @import("../repo.zig");
const hash = @import("../hash.zig");
const rf = @import("../ref.zig");
const mrg = @import("../merge.zig");

pub fn Push(comptime repo_kind: rp.RepoKind, comptime repo_opts: rp.RepoOpts(repo_kind)) type {
    return struct {
        remote: *net.Remote(repo_kind, repo_opts),
        unpack_ok: bool,
        ref_rejected: bool,
        includes: std.ArrayList([hash.hexLen(repo_opts.hash)]u8),
        excludes: std.ArrayList([hash.hexLen(repo_opts.hash)]u8),

        specs: std.ArrayList(PushSpec(repo_kind, repo_opts)),

        pub fn init(remote: *net.Remote(repo_kind, repo_opts)) Push(repo_kind, repo_opts) {
            return Push(repo_kind, repo_opts){
                .remote = remote,
                .unpack_ok = false,
                .ref_rejected = false,
                .includes = .empty,
                .excludes = .empty,
                .specs = .empty,
            };
        }

        pub fn deinit(
            self: *Push(repo_kind, repo_opts),
            allocator: std.mem.Allocator,
        ) void {
            self.includes.deinit(allocator);
            self.excludes.deinit(allocator);

            for (self.specs.items) |*spec| {
                spec.deinit(allocator);
            }
            self.specs.deinit(allocator);
        }

        pub fn addRefSpec(
            self: *Push(repo_kind, repo_opts),
            state: rp.Repo(repo_kind, repo_opts).State(.read_only),
            io: std.Io,
            allocator: std.mem.Allocator,
            refspec: []const u8,
        ) !void {
            var spec = try PushSpec(repo_kind, repo_opts).init(state, io, allocator, refspec);
            errdefer spec.deinit(allocator);
            try self.specs.append(allocator, spec);
        }

        fn initOids(
            self: *Push(repo_kind, repo_opts),
            state: rp.Repo(repo_kind, repo_opts).State(.read_only),
            io: std.Io,
            allocator: std.mem.Allocator,
        ) !void {
            for (self.specs.items) |*spec| {
                if (std.mem.allEqual(u8, &spec.loid, '0')) {
                    continue;
                }

                if (std.mem.eql(u8, &spec.loid, &spec.roid)) {
                    continue;
                }

                try self.includes.append(allocator, spec.loid);

                if (!spec.refspec.is_force) {
                    if (std.mem.allEqual(u8, &spec.roid, '0')) {
                        continue;
                    }

                    if (mrg.getDescendent(repo_kind, repo_opts, state, io, allocator, &spec.loid, &spec.roid)) |descendent| {
                        if (!std.mem.eql(u8, &descendent, &spec.loid)) {
                            // remote is the descendent, meaning local is behind remote
                            return error.RemoteRefContainsCommitsNotFoundLocally;
                        }
                    } else |err| switch (err) {
                        error.ObjectNotFound => return error.RemoteRefContainsCommitsNotFoundLocally,
                        error.DescendentNotFound => return error.RemoteRefContainsIncompatibleHistory,
                        else => |e| return e,
                    }
                }
            }

            for (self.remote.heads.values()) |*head| {
                if (std.mem.allEqual(u8, &head.oid, '0')) {
                    continue;
                }

                try self.excludes.append(allocator, head.oid);
            }
        }

        fn initSpecs(
            self: *Push(repo_kind, repo_opts),
            state: rp.Repo(repo_kind, repo_opts).State(.read_only),
            io: std.Io,
            allocator: std.mem.Allocator,
        ) !void {
            for (self.specs.items) |*spec| {
                if (spec.refspec.src.len > 0) {
                    spec.loid = try net.resolveRefPath(repo_kind, repo_opts, state, io, allocator, spec.refspec.src) orelse return error.ObjectNotFound;
                }

                for (self.remote.heads.values()) |*head| {
                    if (std.mem.eql(u8, spec.refspec.dst, head.name)) {
                        spec.roid = head.oid;
                        break;
                    }
                }
            }
        }

        pub fn complete(
            self: *Push(repo_kind, repo_opts),
            state: rp.Repo(repo_kind, repo_opts).State(.read_only),
            io: std.Io,
            allocator: std.mem.Allocator,
        ) !void {
            if (!self.remote.connected()) {
                return error.RemoteNotConnected;
            }

            self.remote.heads.clearAndFree(allocator);

            const heads = if (self.remote.transport) |*transport| try transport.getHeads() else return error.RemoteNotConnected;

            for (heads) |*head| {
                try self.remote.heads.put(allocator, std.mem.sliceTo(head.name, 0), head.*);
            }

            const transport = if (self.remote.transport) |*transport| transport else return error.NotConnected;

            try self.initSpecs(state, io, allocator);
            try self.initOids(state, io, allocator);
            try transport.push(state, io, allocator, self);

            if (!self.unpack_ok) {
                return error.RemoteFailedToUnpack;
            }

            if (self.ref_rejected) {
                return error.RemoteRejectedRef;
            }
        }
    };
}

pub fn PushSpec(comptime repo_kind: rp.RepoKind, comptime repo_opts: rp.RepoOpts(repo_kind)) type {
    return struct {
        refspec: net_refspec.RefSpec,
        loid: [hash.hexLen(repo_opts.hash)]u8,
        roid: [hash.hexLen(repo_opts.hash)]u8,

        fn init(
            state: rp.Repo(repo_kind, repo_opts).State(.read_only),
            io: std.Io,
            allocator: std.mem.Allocator,
            str: []const u8,
        ) !PushSpec(repo_kind, repo_opts) {
            var self = PushSpec(repo_kind, repo_opts){
                .refspec = undefined,
                .loid = @splat('0'),
                .roid = @splat('0'),
            };

            self.refspec = try net_refspec.RefSpec.init(allocator, str, .push);
            errdefer self.refspec.deinit(allocator);

            if (self.refspec.src.len > 0) {
                _ = try net.resolveRefPath(repo_kind, repo_opts, state, io, allocator, self.refspec.src) orelse return error.ObjectNotFound;
            }

            if (!std.mem.startsWith(u8, self.refspec.dst, "refs/")) {
                return error.InvalidRef;
            }

            return self;
        }

        fn deinit(self: *PushSpec(repo_kind, repo_opts), allocator: std.mem.Allocator) void {
            self.refspec.deinit(allocator);
        }
    };
}
