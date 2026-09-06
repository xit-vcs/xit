const std = @import("std");
const builtin = @import("builtin");
const net = @import("../net.zig");
const net_push = @import("./push.zig");
const net_fetch = @import("./fetch.zig");
const net_transport = @import("./transport.zig");
const rp = @import("../repo.zig");
const obj = @import("../object.zig");
const pack = @import("../pack.zig");
const server_pkt = @import("./server/pkt.zig");
const net_pkt = @import("./pkt.zig");
const hash = @import("../hash.zig");
const rf = @import("../ref.zig");

pub fn FileTransport(comptime repo_kind: rp.RepoKind, comptime repo_opts: rp.RepoOpts(repo_kind)) type {
    return struct {
        url: ?[]u8,
        direction: net.Direction,
        heads: std.ArrayList(net.RemoteHead(repo_kind, repo_opts)),
        connected: bool,
        remote_repo: ?LocalRepo,
        opts: net_transport.Opts(repo_opts.ProgressCtx),

        const LocalRepo = union(rp.RepoKind) {
            git: rp.Repo(.git, .{ .hash = repo_opts.hash }),
            xit: rp.Repo(.xit, .{ .hash = repo_opts.hash }),

            fn deinit(self: *@This(), io: std.Io, allocator: std.mem.Allocator) void {
                switch (self.*) {
                    inline else => |*repo| repo.deinit(io, allocator),
                }
            }

            fn open(io: std.Io, allocator: std.mem.Allocator, path: []const u8) !@This() {
                const kind: rp.RepoKind = blk: {
                    const dir = try std.Io.Dir.openDirAbsolute(io, path, .{});
                    defer dir.close(io);
                    if (std.mem.eql(u8, std.fs.path.basename(path), ".git")) break :blk .git;
                    if (std.mem.eql(u8, std.fs.path.basename(path), ".xit")) break :blk .xit;
                    if (dir.openDir(io, ".xit", .{})) |xit_dir| {
                        xit_dir.close(io);
                        break :blk .xit;
                    } else |err| if (err != error.FileNotFound) return err;
                    break :blk .git;
                };
                switch (kind) {
                    inline else => |rk| {
                        var any_repo = try rp.AnyRepo(rk, .{}).open(io, allocator, .{ .path = path, .require_repo_root = true });
                        switch (any_repo) {
                            inline else => |*repo| {
                                if (comptime repo.self_repo_opts.hash != repo_opts.hash) {
                                    repo.deinit(io, allocator);
                                    return error.UnexpectedHashKind;
                                } else return @unionInit(@This(), @tagName(rk), repo.*);
                            },
                        }
                    },
                }
            }
        };

        pub fn init(opts: net_transport.Opts(repo_opts.ProgressCtx)) !FileTransport(repo_kind, repo_opts) {
            return .{
                .url = null,
                .direction = .fetch,
                .heads = .empty,
                .connected = false,
                .remote_repo = null,
                .opts = opts,
            };
        }

        pub fn deinit(self: *FileTransport(repo_kind, repo_opts), io: std.Io, allocator: std.mem.Allocator) void {
            for (self.heads.items) |*head| {
                head.deinit(allocator);
            }
            self.heads.deinit(allocator);
            self.close(io, allocator);
            if (self.remote_repo) |*remote_repo| {
                remote_repo.deinit(io, allocator);
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
            io: std.Io,
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

            var remote_repo = try LocalRepo.open(io, allocator, work_path);
            errdefer remote_repo.deinit(io, allocator);

            switch (remote_repo) {
                inline else => |*repo| {
                    var moment = try repo.core.latestMoment();
                    try self.addRefs(repo.self_repo_kind, repo.self_repo_opts, .{ .core = &repo.core, .extra = .{ .moment = &moment } }, io, allocator);
                },
            }

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
            io: std.Io,
            allocator: std.mem.Allocator,
            git_push: *net_push.Push(repo_kind, repo_opts),
        ) !void {
            _ = state;
            const remote_repo = if (self.remote_repo) |*repo| repo else return error.NotConnected;
            if (git_push.specs.items.len == 0) {
                git_push.unpack_ok = true;
                return;
            }
            var prefix = std.Io.Writer.Allocating.init(allocator);
            defer prefix.deinit();
            for (git_push.specs.items, 0..) |spec, i| {
                try server_pkt.writePktLineFmt(&prefix.writer, "{s} {s} {s}{s}\n", .{
                    &spec.roid,                                                                                                                                                                                                             &spec.loid, spec.refspec.dst,
                    if (i == 0) (if (remote_repo.* == .xit) "\x00side-band-64k report-status atomic object-format=" ++ @tagName(repo_opts.hash) else "\x00side-band-64k report-status object-format=" ++ @tagName(repo_opts.hash)) else "",
                });
            }
            try prefix.writer.writeAll("0000");
            const need_pack = for (git_push.specs.items) |spec| {
                if (!std.mem.allEqual(u8, &spec.loid, '0')) break true;
            } else false;
            var pack_writer = if (need_pack) try pack.PackWriter(repo_kind, repo_opts).init(allocator, &git_push.obj_iter, .{}) else null;
            defer if (pack_writer) |*writer| writer.deinit();
            if (need_pack and pack_writer == null) {
                try prefix.writer.writeAll(&pack.emptyPack(repo_opts.hash));
            }

            // stream the request prefix followed by the pack without buffering the pack.
            const Request = struct {
                prefix: []const u8,
                pack_writer: ?*pack.PackWriter(repo_kind, repo_opts),
                failure: ?anyerror = null,
                interface: std.Io.Reader,

                fn stream(r: *std.Io.Reader, w: *std.Io.Writer, limit: std.Io.Limit) std.Io.Reader.StreamError!usize {
                    const self_request: *@This() = @alignCast(@fieldParentPtr("interface", r));
                    if (self_request.prefix.len > 0) {
                        const n = try w.write(limit.sliceConst(self_request.prefix));
                        self_request.prefix = self_request.prefix[n..];
                        return n;
                    }
                    const writer = self_request.pack_writer orelse return error.EndOfStream;
                    const buf = limit.slice(try w.writableSliceGreedy(1));
                    const n = writer.read(buf) catch |err| {
                        self_request.failure = err;
                        return error.ReadFailed;
                    };
                    if (n == 0) return error.EndOfStream;
                    w.advance(n);
                    return n;
                }
            };
            var request_buffer: [repo_opts.buffer_size]u8 = undefined;
            var request = Request{
                .prefix = prefix.written(),
                .pack_writer = if (pack_writer) |*writer| writer else null,
                .interface = .{ .buffer = &request_buffer, .seek = 0, .end = 0, .vtable = &.{ .stream = Request.stream } },
            };
            var response = std.Io.Writer.Allocating.init(allocator);
            defer response.deinit();
            switch (remote_repo.*) {
                inline else => |*repo| repo.receivePack(io, allocator, &request.interface, &response.writer, .{
                    .is_stateless = true,
                }) catch |err| return request.failure orelse err,
            }
            var status = std.Io.Writer.Allocating.init(allocator);
            defer status.deinit();
            var remaining = response.written();
            var found_capabilities = false;
            // status packets may span multiple sideband packets; preserve every byte.
            while (remaining.len > 0) {
                var consumed: usize = 0;
                var packet = try net_pkt.Pkt(repo_kind, repo_opts).initMaybe(allocator, remaining, &found_capabilities, &consumed) orelse return error.ProtocolError;
                defer packet.deinit(allocator);
                remaining = remaining[consumed..];
                switch (packet) {
                    .data => |data| try status.writer.writeAll(data),
                    .progress => |message| if (repo_opts.ProgressCtx != void) {
                        if (self.opts.progress_ctx) |ctx| try ctx.run(io, .{ .text = message });
                    },
                    .err => return error.ServerReportedError,
                    .flush => break,
                    else => return error.ProtocolError,
                }
            }
            var packet_buffer: [server_pkt.LARGE_PACKET_MAX]u8 = undefined;
            var status_reader = std.Io.Reader.fixed(status.written());
            while (try server_pkt.readPktLine(&status_reader, &packet_buffer)) |line| {
                if (std.mem.eql(u8, line, "unpack ok")) {
                    git_push.unpack_ok = true;
                } else if (std.mem.startsWith(u8, line, "ng ")) {
                    git_push.ref_rejected = true;
                    if (repo_opts.ProgressCtx != void) {
                        if (self.opts.progress_ctx) |ctx| try ctx.run(io, .{ .text = line });
                    }
                } else if (!std.mem.startsWith(u8, line, "ok ")) return error.ProtocolError;
            }
        }

        pub fn negotiateFetch(
            self: *FileTransport(repo_kind, repo_opts),
            state: rp.Repo(repo_kind, repo_opts).State(.read_only),
            io: std.Io,
            allocator: std.mem.Allocator,
        ) !void {
            // the file transport has nothing to negotiate
            _ = self;
            _ = state;
            _ = io;
            _ = allocator;
        }

        pub fn downloadPack(
            self: *FileTransport(repo_kind, repo_opts),
            state: rp.Repo(repo_kind, repo_opts).State(.read_write),
            io: std.Io,
            allocator: std.mem.Allocator,
        ) !void {
            const remote_repo = if (self.remote_repo) |*repo| repo else return error.NotConnected;
            switch (remote_repo.*) {
                inline else => |*repo| {
                    var moment = try repo.core.latestMoment();
                    var obj_iter = try obj.ObjectIterator(repo.self_repo_kind, repo.self_repo_opts).init(.{
                        .core = &repo.core,
                        .extra = .{ .moment = &moment },
                    }, io, allocator, .{ .kind = .all });
                    defer obj_iter.deinit();
                    for (self.heads.items) |*head| {
                        if (!std.mem.allEqual(u8, &head.oid, '0')) try obj_iter.include(&head.oid);
                    }
                    try obj.copyFromObjectIterator(repo_kind, repo_opts, state, repo.self_repo_kind, repo.self_repo_opts, &obj_iter, io, self.opts.progress_ctx);
                },
            }
        }

        pub fn isConnected(self: *const FileTransport(repo_kind, repo_opts)) bool {
            return self.connected;
        }

        pub fn close(self: *FileTransport(repo_kind, repo_opts), io: std.Io, allocator: std.mem.Allocator) void {
            self.connected = false;

            if (self.url) |url| {
                allocator.free(url);
                self.url = null;
            }

            if (self.remote_repo) |*remote_repo| {
                remote_repo.deinit(io, allocator);
                self.remote_repo = null;
            }
        }

        fn addHead(
            self: *FileTransport(repo_kind, repo_opts),
            comptime remote_kind: rp.RepoKind,
            comptime remote_opts: rp.RepoOpts(remote_kind),
            state: rp.Repo(remote_kind, remote_opts).State(.read_only),
            io: std.Io,
            allocator: std.mem.Allocator,
            ref: rf.Ref,
        ) !void {
            var ref_path_buffer = [_]u8{0} ** rf.MAX_REF_CONTENT_SIZE;
            const ref_path = try ref.toPath(&ref_path_buffer);

            const oid_maybe = try net.resolveRef(remote_kind, remote_opts, state, io, allocator, ref);
            const oid = oid_maybe orelse (if (std.mem.eql(u8, ref_path, "HEAD")) [_]u8{'0'} ** hash.hexLen(repo_opts.hash) else return);

            var head: net.RemoteHead(repo_kind, repo_opts) = undefined;
            {
                const head_name = try allocator.dupe(u8, ref_path);
                errdefer allocator.free(head_name);

                head = net.RemoteHead(repo_kind, repo_opts).init(head_name);
                head.oid = oid;

                // if it's a symbolic ref, store the target ref path
                var ref_buffer = [_]u8{0} ** rf.MAX_REF_CONTENT_SIZE;
                if (try rf.read(remote_kind, remote_opts, state, io, ref_path, &ref_buffer)) |ref_or_oid| switch (ref_or_oid) {
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

            var object = try obj.Object(remote_kind, remote_opts).init(state, io, allocator, &head.oid);
            defer object.deinit();

            if (object.content != .tag or self.direction != .fetch) {
                return;
            }

            {
                var head_name: std.ArrayList(u8) = .empty;
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
            comptime remote_kind: rp.RepoKind,
            comptime remote_opts: rp.RepoOpts(remote_kind),
            state: rp.Repo(remote_kind, remote_opts).State(.read_only),
            io: std.Io,
            allocator: std.mem.Allocator,
        ) !void {
            for (self.heads.items) |*head| {
                head.deinit(allocator);
            }
            self.heads.clearAndFree(allocator);

            if (self.direction == .fetch) {
                try self.addHead(remote_kind, remote_opts, state, io, allocator, .{ .kind = .none, .name = "HEAD" });
            }

            for ([_]rf.RefKind{ .head, .tag }) |ref_kind| {
                var iter = try rf.RefIterator(remote_kind, remote_opts).init(state, io, allocator, ref_kind, .beginning);
                defer iter.deinit();

                while (try iter.next()) |ref| {
                    try self.addHead(remote_kind, remote_opts, state, io, allocator, ref);
                }
            }
        }
    };
}
