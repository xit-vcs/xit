const std = @import("std");
const builtin = @import("builtin");
const net = @import("../net.zig");
const net_push = @import("./push.zig");
const net_fetch = @import("./fetch.zig");
const net_transport = @import("./transport.zig");
const rp = @import("../repo.zig");
const obj = @import("../object.zig");
const hash = @import("../hash.zig");
const rf = @import("../ref.zig");

pub fn FileTransport(comptime repo_kind: rp.RepoKind, comptime repo_opts: rp.RepoOpts(repo_kind)) type {
    return struct {
        url: ?[]u8,
        direction: net.Direction,
        heads: std.ArrayList(net.RemoteHead(repo_kind, repo_opts)),
        connected: bool,
        remote_repo: ?rp.Repo(.git, remote_repo_opts),
        opts: net_transport.Opts(repo_opts.ProgressCtx),

        const remote_repo_opts: rp.RepoOpts(.git) = .{ .hash = repo_opts.hash };

        pub fn init(opts: net_transport.Opts(repo_opts.ProgressCtx)) !FileTransport(repo_kind, repo_opts) {
            return .{
                .url = null,
                .direction = .fetch,
                .heads = std.ArrayList(net.RemoteHead(repo_kind, repo_opts)){},
                .connected = false,
                .remote_repo = null,
                .opts = opts,
            };
        }

        pub fn deinit(self: *FileTransport(repo_kind, repo_opts), allocator: std.mem.Allocator) void {
            for (self.heads.items) |*head| {
                head.deinit(allocator);
            }
            self.heads.deinit(allocator);
            self.close(allocator);
            if (self.remote_repo) |*remote_repo| {
                remote_repo.deinit(allocator);
                self.remote_repo = null;
            }
        }

        fn parsePath(url: []const u8) ![]const u8 {
            if (std.mem.startsWith(u8, url, "file://")) {
                const uri = try std.Uri.parse(url);
                const path = switch (uri.path) {
                    .raw => |s| s,
                    .percent_encoded => |s| s,
                };
                if (.windows == builtin.os.tag and path[0] == '/') {
                    return path[1..];
                } else {
                    return path;
                }
            } else {
                return url;
            }
        }

        pub fn connect(
            self: *FileTransport(repo_kind, repo_opts),
            state: rp.Repo(repo_kind, repo_opts).State(.read_only),
            allocator: std.mem.Allocator,
            url: []const u8,
            direction: net.Direction,
        ) !void {
            if (self.connected) {
                return;
            }

            for (self.heads.items) |*head| {
                head.deinit(allocator);
            }
            self.heads.clearAndFree(allocator);

            self.url = try allocator.dupe(u8, url);
            self.direction = direction;

            const path = try parsePath(url);

            const work_path = try std.fs.path.resolve(allocator, &.{ state.core.cwd_path, path });
            defer allocator.free(work_path);

            var remote_repo = try rp.Repo(.git, remote_repo_opts).open(allocator, .{ .path = work_path });
            errdefer remote_repo.deinit(allocator);

            try self.addRefs(.{ .core = &remote_repo.core, .extra = .{} }, allocator);

            self.connected = true;
            self.remote_repo = remote_repo;
        }

        pub fn capabilities(_: *const FileTransport(repo_kind, repo_opts)) net_transport.Capabilities {
            return .{
                .fetch_by_oid = true,
                .fetch_reachable = true,
            };
        }

        pub fn getHeads(self: *const FileTransport(repo_kind, repo_opts)) ![]net.RemoteHead(repo_kind, repo_opts) {
            return self.heads.items;
        }

        pub fn push(
            self: *FileTransport(repo_kind, repo_opts),
            state: rp.Repo(repo_kind, repo_opts).State(.read_only),
            allocator: std.mem.Allocator,
            git_push: *net_push.Push(repo_kind, repo_opts),
        ) !void {
            const path = try parsePath(git_push.remote.url orelse return error.UrlNotFound);

            {
                const work_path = try std.fs.path.resolve(allocator, &.{ state.core.cwd_path, path });
                defer allocator.free(work_path);

                var any_repo = try rp.AnyRepo(.git, .{ .hash = null, .ProgressCtx = repo_opts.ProgressCtx }).open(allocator, .{ .path = work_path });
                defer any_repo.deinit(allocator);

                const obj_iter: *obj.ObjectIterator(repo_kind, repo_opts, .raw) = &git_push.obj_iter;

                switch (any_repo) {
                    inline else => |*repo| try repo.copyObjects(repo_kind, repo_opts, obj_iter, self.opts.progress_ctx),
                }
            }

            git_push.unpack_ok = true;

            const remote_repo = if (self.remote_repo) |*repo| repo else return error.NotConnected;

            for (git_push.specs.items) |*spec| {
                const lref = spec.refspec.src;
                const rref = spec.refspec.dst;
                const loid = &spec.loid;

                if (lref.len > 0) {
                    try rf.write(.git, remote_repo_opts, .{ .core = &remote_repo.core, .extra = .{} }, rref, .{ .oid = loid });
                } else {
                    try rf.remove(.git, remote_repo_opts, .{ .core = &remote_repo.core, .extra = .{} }, rref);
                }
            }

            if (git_push.specs.items.len > 0) {
                const url = try allocator.dupe(u8, self.url orelse return error.NotConnected);
                defer allocator.free(url);
                self.close(allocator);
                try self.connect(state, allocator, url, .push);
            }
        }

        pub fn negotiateFetch(
            self: *FileTransport(repo_kind, repo_opts),
            state: rp.Repo(repo_kind, repo_opts).State(.read_only),
            allocator: std.mem.Allocator,
        ) !void {
            for (self.heads.items) |*head| {
                if (try net.resolveRefPath(repo_kind, repo_opts, state, allocator, head.name)) |oid| {
                    head.loid = oid;
                }
            }
        }

        pub fn downloadPack(
            self: *FileTransport(repo_kind, repo_opts),
            state: rp.Repo(repo_kind, repo_opts).State(.read_write),
            allocator: std.mem.Allocator,
        ) !void {
            const path = try parsePath(self.url orelse return error.NotConnected);

            const work_path = try std.fs.path.resolve(allocator, &.{ state.core.cwd_path, path });
            defer allocator.free(work_path);

            var repo = try rp.Repo(.git, remote_repo_opts).open(allocator, .{ .path = work_path });
            defer repo.deinit(allocator);

            var obj_iter = try repo.logRaw(allocator, .{ .kind = .all });
            defer obj_iter.deinit();

            for (self.heads.items) |*head| {
                try obj_iter.include(&head.oid);
            }

            try obj.copyFromObjectIterator(
                repo_kind,
                repo_opts,
                state,
                repo.self_repo_kind,
                repo.self_repo_opts,
                &obj_iter,
                self.opts.progress_ctx,
            );
        }

        pub fn isConnected(self: *const FileTransport(repo_kind, repo_opts)) bool {
            return self.connected;
        }

        pub fn close(self: *FileTransport(repo_kind, repo_opts), allocator: std.mem.Allocator) void {
            self.connected = false;

            if (self.url) |url| {
                allocator.free(url);
                self.url = null;
            }

            if (self.remote_repo) |*remote_repo| {
                remote_repo.deinit(allocator);
                self.remote_repo = null;
            }
        }

        fn addHead(
            self: *FileTransport(repo_kind, repo_opts),
            state: rp.Repo(.git, remote_repo_opts).State(.read_only),
            allocator: std.mem.Allocator,
            ref: rf.Ref,
        ) !void {
            var ref_path_buffer = [_]u8{0} ** rf.MAX_REF_CONTENT_SIZE;
            const ref_path = try ref.toPath(&ref_path_buffer);

            const oid_maybe = try net.resolveRef(.git, remote_repo_opts, state, allocator, ref);
            const oid = oid_maybe orelse (if (std.mem.eql(u8, ref_path, "HEAD")) return else return error.InvalidRefPath);

            var head: net.RemoteHead(repo_kind, repo_opts) = undefined;
            {
                const head_name = try allocator.dupe(u8, ref_path);
                errdefer allocator.free(head_name);

                head = net.RemoteHead(repo_kind, repo_opts).init(head_name);
                head.oid = oid;

                // if it's a symbolic ref, store the target ref path
                var ref_buffer = [_]u8{0} ** rf.MAX_REF_CONTENT_SIZE;
                if (try rf.read(.git, remote_repo_opts, state, ref_path, &ref_buffer)) |ref_or_oid| switch (ref_or_oid) {
                    .ref => |target_ref| {
                        var target_ref_path_buffer = [_]u8{0} ** rf.MAX_REF_CONTENT_SIZE;
                        const target_ref_path = try target_ref.toPath(&target_ref_path_buffer);
                        head.symref = try allocator.dupe(u8, target_ref_path);
                    },
                    .oid => {},
                };
                errdefer if (head.symref) |target| allocator.free(target);

                try self.heads.append(allocator, head);
            }

            if (ref.kind != .tag) {
                return;
            }

            var object = try obj.Object(.git, remote_repo_opts, .full).init(allocator, state, &head.oid);
            defer object.deinit();

            if (object.content != .tag or self.direction != .fetch) {
                return;
            }

            {
                var head_name = std.ArrayList(u8){};
                errdefer head_name.deinit(allocator);
                try head_name.appendSlice(allocator, ref_path);
                try head_name.appendSlice(allocator, "^{}");

                head = net.RemoteHead(repo_kind, repo_opts).init(try head_name.toOwnedSlice(allocator));
                head.oid = object.content.tag.target;

                try self.heads.append(allocator, head);
            }
        }

        fn addRefs(
            self: *FileTransport(repo_kind, repo_opts),
            state: rp.Repo(.git, remote_repo_opts).State(.read_only),
            allocator: std.mem.Allocator,
        ) !void {
            for (self.heads.items) |*head| {
                head.deinit(allocator);
            }
            self.heads.clearAndFree(allocator);

            if (self.direction == .fetch) {
                try self.addHead(state, allocator, .{ .kind = .none, .name = "HEAD" });
            }

            var tags = try rf.RefList.init(.git, remote_repo_opts, state, allocator, .tag);
            defer tags.deinit();

            for (tags.refs.values()) |ref| {
                try self.addHead(state, allocator, ref);
            }

            var heads = try rf.RefList.init(.git, remote_repo_opts, state, allocator, .head);
            defer heads.deinit();

            for (heads.refs.values()) |ref| {
                try self.addHead(state, allocator, ref);
            }
        }
    };
}
