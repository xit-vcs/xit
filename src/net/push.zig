const std = @import("std");
const builtin = @import("builtin");
const net = @import("../net.zig");
const net_transport = @import("./transport.zig");
const net_refspec = @import("./refspec.zig");
const rp = @import("../repo.zig");
const hash = @import("../hash.zig");
const obj = @import("../object.zig");
const rf = @import("../ref.zig");
const mrg = @import("../merge.zig");

pub fn Push(comptime repo_kind: rp.RepoKind, comptime repo_opts: rp.RepoOpts(repo_kind)) type {
    return struct {
        remote: *net.Remote(repo_kind, repo_opts),
        unpack_ok: bool,
        obj_iter: obj.ObjectIterator(repo_kind, repo_opts, .raw),

        specs: std.ArrayList(PushSpec(repo_kind, repo_opts)),

        pub fn init(
            state: rp.Repo(repo_kind, repo_opts).State(.read_only),
            remote: *net.Remote(repo_kind, repo_opts),
            allocator: std.mem.Allocator,
        ) !Push(repo_kind, repo_opts) {
            var obj_iter = try obj.ObjectIterator(repo_kind, repo_opts, .raw).init(allocator, state, .{ .kind = .all });
            errdefer obj_iter.deinit();

            return Push(repo_kind, repo_opts){
                .remote = remote,
                .unpack_ok = false,
                .obj_iter = obj_iter,
                .specs = std.ArrayList(PushSpec(repo_kind, repo_opts)){},
            };
        }

        pub fn deinit(
            self: *Push(repo_kind, repo_opts),
            allocator: std.mem.Allocator,
        ) void {
            self.obj_iter.deinit();

            for (self.specs.items) |*spec| {
                spec.deinit(allocator);
            }
            self.specs.deinit(allocator);
        }

        pub fn addRefSpec(
            self: *Push(repo_kind, repo_opts),
            state: rp.Repo(repo_kind, repo_opts).State(.read_only),
            allocator: std.mem.Allocator,
            refspec: []const u8,
        ) !void {
            var spec = try PushSpec(repo_kind, repo_opts).init(state, allocator, refspec);
            errdefer spec.deinit(allocator);
            try self.specs.append(allocator, spec);
        }

        fn initObjectIterator(
            self: *Push(repo_kind, repo_opts),
            state: rp.Repo(repo_kind, repo_opts).State(.read_only),
            allocator: std.mem.Allocator,
        ) !void {
            var obj_iter = &self.obj_iter;

            for (self.specs.items) |*spec| {
                if (std.mem.allEqual(u8, &spec.loid, '0')) {
                    continue;
                }

                if (std.mem.eql(u8, &spec.loid, &spec.roid)) {
                    continue;
                }

                try obj_iter.include(&spec.loid);

                if (!spec.refspec.is_force) {
                    if (std.mem.allEqual(u8, &spec.roid, '0')) {
                        continue;
                    }

                    if (mrg.getDescendent(repo_kind, repo_opts, allocator, state, &spec.loid, &spec.roid)) |descendent| {
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

                obj_iter.exclude(&head.oid) catch |err| switch (err) {
                    error.ObjectNotFound => {},
                    else => |e| return e,
                };
            }
        }

        fn initSpecs(
            self: *Push(repo_kind, repo_opts),
            state: rp.Repo(repo_kind, repo_opts).State(.read_only),
            allocator: std.mem.Allocator,
        ) !void {
            for (self.specs.items) |*spec| {
                if (spec.refspec.src.len > 0) {
                    spec.loid = try net.resolveRefPath(repo_kind, repo_opts, state, allocator, spec.refspec.src) orelse return error.ObjectNotFound;
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

            try self.initSpecs(state, allocator);
            try self.initObjectIterator(state, allocator);
            try transport.push(state, allocator, self);

            if (!self.unpack_ok) {
                return error.RemoteFailedToUnpack;
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
            allocator: std.mem.Allocator,
            str: []const u8,
        ) !PushSpec(repo_kind, repo_opts) {
            var self = PushSpec(repo_kind, repo_opts){
                .refspec = undefined,
                .loid = [_]u8{'0'} ** hash.hexLen(repo_opts.hash),
                .roid = [_]u8{'0'} ** hash.hexLen(repo_opts.hash),
            };

            self.refspec = try net_refspec.RefSpec.init(allocator, str, .push);
            errdefer self.refspec.deinit(allocator);

            if (self.refspec.src.len > 0) {
                _ = try net.resolveRefPath(repo_kind, repo_opts, state, allocator, self.refspec.src) orelse return error.ObjectNotFound;
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
