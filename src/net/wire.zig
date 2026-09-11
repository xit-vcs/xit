const std = @import("std");
const builtin = @import("builtin");
const net = @import("../net.zig");
const net_raw = @import("./raw.zig");
const net_http = @import("./http.zig");
const net_ssh = @import("./ssh.zig");
const net_push = @import("./push.zig");
const net_refspec = @import("./refspec.zig");
const net_pkt = @import("./pkt.zig");
const net_transport = @import("./transport.zig");
const rp = @import("../repo.zig");
const obj = @import("../object.zig");
const pack = @import("../pack.zig");
const rf = @import("../ref.zig");
const hash = @import("../hash.zig");
const cfg = @import("../config.zig");
const fs = @import("../fs.zig");

pub const Opts = struct {
    ssh: net_ssh.Opts = .{},
};

pub const WireKind = enum {
    http,
    raw,
    ssh,
};

pub const WireState = union(WireKind) {
    http: net_http.HttpState,
    raw: net_raw.RawState,
    ssh: net_ssh.SshState,

    pub fn close(self: *WireState, io: std.Io) !void {
        switch (self.*) {
            .http => |*http| http.close(),
            .raw => |*raw| try raw.close(),
            .ssh => |*ssh| try ssh.close(io),
        }
    }

    pub fn deinit(self: *WireState) void {
        switch (self.*) {
            .http => |*http| http.deinit(),
            .raw => |*raw| raw.deinit(),
            .ssh => |*ssh| ssh.deinit(),
        }
    }
};

pub const WireAction = enum {
    list_upload_pack,
    list_receive_pack,
    upload_pack,
    receive_pack,
};

pub const WireStream = union(WireKind) {
    http: net_http.HttpStream,
    raw: net_raw.RawStream,
    ssh: net_ssh.SshStream,

    pub fn initMaybe(
        io: std.Io,
        allocator: std.mem.Allocator,
        wire_state: *WireState,
        url: []const u8,
        wire_action: WireAction,
    ) !?WireStream {
        return switch (wire_state.*) {
            .http => |*http| .{ .http = try net_http.HttpStream.init(http, url, wire_action) },
            .raw => if (try net_raw.RawStream.initMaybe(io, allocator, url, wire_action)) |stream| .{ .raw = stream } else null,
            .ssh => |*ssh| if (try net_ssh.SshStream.initMaybe(ssh, url, wire_action)) |stream| .{ .ssh = stream } else null,
        };
    }

    pub fn read(
        self: *WireStream,
        allocator: std.mem.Allocator,
        buffer: [*]u8,
        buf_size: usize,
    ) !usize {
        return switch (self.*) {
            .http => |*http| try http.read(allocator, buffer, buf_size),
            .raw => |*raw| try raw.read(buffer, buf_size),
            .ssh => |*ssh| try ssh.read(buffer, buf_size),
        };
    }

    pub fn write(
        self: *WireStream,
        allocator: std.mem.Allocator,
        buffer: [*]const u8,
        len: usize,
    ) !void {
        switch (self.*) {
            .http => |*http| try http.write(allocator, buffer, len),
            .raw => |*raw| try raw.write(buffer, len),
            .ssh => |*ssh| try ssh.write(buffer, len),
        }
    }

    pub fn deinit(self: *WireStream, allocator: std.mem.Allocator) void {
        switch (self.*) {
            .http => |*http| http.deinit(),
            .raw => |*raw| raw.deinit(allocator),
            .ssh => |*ssh| ssh.deinit(),
        }
    }
};

fn Buffer(comptime size: usize) type {
    return struct {
        len: usize,
        data: [size]u8,

        fn consume(self: *Buffer(size), consumed: usize) void {
            if (consumed > 0 and consumed <= self.len) {
                const new_len = self.len - consumed;
                std.mem.copyForwards(u8, self.data[0..new_len], self.data[consumed..self.len]);
                self.data[new_len] = '\x00';
                self.len = new_len;
            }
        }
    };
}

pub fn Connection(comptime buffer_size: usize) type {
    return struct {
        wire_state: *WireState,
        wire_stream: ?WireStream = null,
        url: ?[]u8 = null,
        buffer: *Buffer(buffer_size),
        flushes: c_int = 0,

        pub fn init(io: std.Io, allocator: std.mem.Allocator, kind: WireKind, opts: Opts) !@This() {
            const state = try allocator.create(WireState);
            errdefer allocator.destroy(state);
            state.* = switch (kind) {
                .http => .{ .http = try net_http.HttpState.init(io, allocator) },
                .raw => .{ .raw = net_raw.RawState.init() },
                .ssh => .{ .ssh = try net_ssh.SshState.init(io, allocator, opts.ssh) },
            };
            errdefer state.deinit();
            const buffer = try allocator.create(Buffer(buffer_size));
            buffer.len = 0;
            return .{ .wire_state = state, .buffer = buffer };
        }

        pub fn deinit(self: *@This(), io: std.Io, allocator: std.mem.Allocator) void {
            self.close(io, allocator);
            self.wire_state.deinit();
            allocator.destroy(self.wire_state);
            allocator.destroy(self.buffer);
        }

        fn close(self: *@This(), io: std.Io, allocator: std.mem.Allocator) void {
            self.clearStream(allocator);
            self.wire_state.close(io) catch {};
            if (self.url) |url| allocator.free(url);
            self.url = null;
            self.buffer.len = 0;
        }

        fn clearStream(self: *@This(), allocator: std.mem.Allocator) void {
            if (self.wire_stream) |*stream| stream.deinit(allocator);
            self.wire_stream = null;
        }

        pub fn start(self: *@This(), io: std.Io, allocator: std.mem.Allocator, url: []const u8, action: WireAction) !void {
            self.close(io, allocator);
            const owned_url = try allocator.dupe(u8, url);
            self.url = owned_url;
            self.wire_stream = try WireStream.initMaybe(io, allocator, self.wire_state, owned_url, action);
            self.flushes = if (self.wire_state.* == .http) 2 else 1;
        }

        fn openStream(self: *@This(), io: std.Io, allocator: std.mem.Allocator, action: WireAction) !void {
            if (self.wire_state.* == .http) {
                self.clearStream(allocator);
                try self.wire_state.close(io);
            }
            if (try WireStream.initMaybe(io, allocator, self.wire_state, self.url orelse return error.NotConnected, action)) |stream| {
                self.clearStream(allocator);
                self.wire_stream = stream;
            }
        }

        fn recv(self: *@This(), allocator: std.mem.Allocator) !usize {
            if (self.buffer.len >= self.buffer.data.len) return error.OutOfBufferSpace;
            const available = self.buffer.data[self.buffer.len..];
            const stream = &(self.wire_stream orelse return error.StreamNotFound);
            const size = try stream.read(allocator, available.ptr, available.len);
            std.debug.assert(size <= available.len);
            self.buffer.len += size;
            return size;
        }

        pub fn discoverHash(self: *@This(), io: std.Io, allocator: std.mem.Allocator, comptime ProgressCtx: type, progress_ctx: ?ProgressCtx) !hash.HashKind {
            while (true) {
                if (try net_pkt.Frame.initMaybe(self.buffer.data[0..self.buffer.len])) |frame| {
                    if (frame.content.len == 0) {
                        self.flushes -= 1;
                        if (self.flushes == 0) return error.InvalidRefs;
                    } else if (std.mem.startsWith(u8, frame.content, "ERR ")) {
                        if (ProgressCtx != void) {
                            if (progress_ctx) |ctx| try ctx.run(io, .{ .text = frame.content[4..] });
                        }
                        return error.ServerReportedError;
                    } else if (frame.content[0] != '#') {
                        // leave the first ref and all read-ahead bytes for the typed parser.
                        return net_pkt.refObjectFormat(frame.content);
                    }
                    self.buffer.consume(frame.len);
                } else if (try self.recv(allocator) == 0) {
                    return error.CouldNotReadRefsFromRemoteRepo;
                }
            }
        }
    };
}

pub fn WireTransport(comptime repo_kind: rp.RepoKind, comptime repo_opts: rp.RepoOpts(repo_kind)) type {
    return struct {
        connection: Connection(repo_opts.net_buffer_size),
        direction: net.Direction,
        caps: Capabilities,
        refs: std.ArrayList(net_pkt.Ref(repo_opts.hash)),
        heads: std.ArrayList(net.RemoteHead(repo_opts.hash)),
        common: std.ArrayList(net_pkt.Pkt(repo_opts.hash)),
        is_stateless: bool,
        have_refs: bool,
        connected: bool,
        request_sent: bool,
        opts: net_transport.Opts(repo_opts.ProgressCtx),

        pub fn init(
            state: rp.Repo(repo_kind, repo_opts).State(.read_only),
            io: std.Io,
            allocator: std.mem.Allocator,
            wire_kind: WireKind,
            opts: net_transport.Opts(repo_opts.ProgressCtx),
        ) !WireTransport(repo_kind, repo_opts) {
            var wire_opts = opts.wire;
            if (wire_kind == .ssh and wire_opts.ssh.command == null) {
                var config = try cfg.Config(repo_kind, repo_opts).init(state, io, allocator);
                defer config.deinit();
                wire_opts.ssh.command = net_ssh.commandFromConfig(config.sections);
                return initConnection(try Connection(repo_opts.net_buffer_size).init(io, allocator, wire_kind, wire_opts), opts);
            }
            return initConnection(try Connection(repo_opts.net_buffer_size).init(io, allocator, wire_kind, wire_opts), opts);
        }

        pub fn initConnection(connection: Connection(repo_opts.net_buffer_size), opts: net_transport.Opts(repo_opts.ProgressCtx)) @This() {
            return .{
                .connection = connection,
                .direction = .fetch,
                .caps = .{},
                .refs = .empty,
                .heads = .empty,
                .common = .empty,
                .is_stateless = connection.wire_state.* == .http,
                .have_refs = false,
                .connected = false,
                .request_sent = false,
                .opts = opts,
            };
        }

        pub fn deinit(self: *WireTransport(repo_kind, repo_opts), io: std.Io, allocator: std.mem.Allocator) void {
            self.close(io, allocator);

            self.connection.deinit(io, allocator);

            self.heads.deinit(allocator);

            for (self.refs.items) |*ref| {
                ref.deinit(allocator);
            }
            self.refs.deinit(allocator);

            self.common.deinit(allocator);
        }

        pub fn connect(
            self: *WireTransport(repo_kind, repo_opts),
            io: std.Io,
            allocator: std.mem.Allocator,
            url: []const u8,
            direction: net.Direction,
        ) !void {
            self.direction = direction;
            try self.connection.start(io, allocator, url, switch (direction) {
                .fetch => .list_upload_pack,
                .push => .list_receive_pack,
            });
            try self.finishConnect(io, allocator);
        }

        pub fn finishConnect(self: *@This(), io: std.Io, allocator: std.mem.Allocator) !void {
            try self.addRefs(io, allocator, self.connection.flushes);

            self.have_refs = true;

            var first_ref = if (self.refs.items.len > 0) self.refs.items[0] else return error.InvalidRefs;

            var symrefs: std.ArrayList(net_refspec.RefSpec) = .empty;
            defer {
                for (symrefs.items) |*spec| {
                    spec.deinit(allocator);
                }
                symrefs.deinit(allocator);
            }

            self.caps = try Capabilities.init(allocator, if (first_ref.capabilities) |caps| caps else null, &symrefs);

            if (!self.caps.side_band and !self.caps.side_band_64k) {
                return error.SidebandProtocolRequired;
            }

            if (1 == self.refs.items.len and
                !std.mem.eql(u8, first_ref.head.name, "capabilities^{}") and
                std.mem.allEqual(u8, &first_ref.head.oid, '0'))
            {
                for (self.refs.items) |*ref| {
                    ref.deinit(allocator);
                }
                self.refs.clearAndFree(allocator);
            }

            try self.updateHeads(allocator, symrefs.items);

            if (self.is_stateless) {
                self.connection.clearStream(allocator);
            }

            self.connected = true;
            self.request_sent = false;
        }

        pub fn capabilities(self: *const WireTransport(repo_kind, repo_opts)) net_transport.Capabilities {
            return .{
                .fetch_by_oid = self.caps.allow_tip_sha1_in_want,
                .fetch_reachable = self.caps.allow_reachable_sha1_in_want,
            };
        }

        pub fn getHeads(self: *const WireTransport(repo_kind, repo_opts)) ![]net.RemoteHead(repo_opts.hash) {
            if (!self.have_refs) {
                return error.RefsNotLoaded;
            }

            return self.heads.items;
        }

        pub fn push(
            self: *WireTransport(repo_kind, repo_opts),
            io: std.Io,
            allocator: std.mem.Allocator,
            git_push: *net_push.Push(repo_kind, repo_opts),
        ) !void {
            var need_pack = false;
            for (git_push.specs.items) |*spec| {
                if (spec.refspec.src.len > 0) {
                    need_pack = true;
                    break;
                }
            }

            if (.push != self.direction) {
                return error.InvalidDirection;
            }

            try self.connection.openStream(io, allocator, .receive_pack);

            const stream = &(self.connection.wire_stream orelse return error.StreamNotFound);

            var buffer: std.ArrayList(u8) = .empty;
            defer buffer.deinit(allocator);

            try pktline(allocator, &buffer, git_push.specs.items, self.caps.object_format);
            try stream.write(allocator, buffer.items.ptr, buffer.items.len);

            if (need_pack) {
                var pack_writer_maybe = try pack.PackWriter(repo_kind, repo_opts).init(allocator, &git_push.obj_iter, .{ .allow_ofs_delta = self.caps.ofs_delta });
                if (pack_writer_maybe) |*pack_writer| {
                    defer pack_writer.deinit();

                    if (repo_opts.ProgressCtx != void) {
                        if (self.opts.progress_ctx) |progress_ctx| {
                            try progress_ctx.run(io, .{ .start = .{
                                .kind = .sending_bytes,
                                .estimated_total_items = 0,
                            } });
                        }
                    }

                    var read_buffer = [_]u8{0} ** repo_opts.read_size;
                    var total_size: usize = 0;

                    while (true) {
                        const size = try pack_writer.read(&read_buffer);
                        if (size == 0) {
                            break;
                        }

                        try stream.write(allocator, &read_buffer, size);

                        if (repo_opts.ProgressCtx != void) {
                            if (self.opts.progress_ctx) |progress_ctx| {
                                total_size += size;
                                try progress_ctx.run(io, .{ .complete_total = .{ .kind = .sending_bytes, .count = total_size } });
                            }
                        }
                    }
                } else {
                    const empty = pack.emptyPack(repo_opts.hash);
                    try stream.write(allocator, &empty, empty.len);
                }
            }

            self.request_sent = true;

            if (0 == git_push.specs.items.len) {
                git_push.unpack_ok = true;
            } else {
                try self.handlePushPkts(io, allocator, git_push);
            }
        }

        pub fn negotiateFetch(
            self: *WireTransport(repo_kind, repo_opts),
            state: rp.Repo(repo_kind, repo_opts).State(.read_only),
            io: std.Io,
            allocator: std.mem.Allocator,
            heads: []const net.RemoteHead(repo_opts.hash),
        ) !void {
            self.caps.shallow = false;

            var buffer: std.ArrayList(u8) = .empty;
            defer buffer.deinit(allocator);

            try net_pkt.bufferWants(repo_opts.hash, allocator, heads, &self.caps, &buffer);

            var obj_iter = try obj.ObjectIterator(repo_kind, repo_opts).init(state, io, allocator, .{ .kind = .all });
            defer obj_iter.deinit();

            for ([_]rf.RefKind{ .head, .tag }) |ref_kind| {
                var iter = try rf.RefIterator(repo_kind, repo_opts).init(state, io, allocator, ref_kind, .beginning);
                defer iter.deinit();

                while (try iter.next()) |ref| {
                    if (try rf.readRecur(repo_kind, repo_opts, state, io, .{ .ref = ref })) |*oid| {
                        try obj_iter.include(oid);
                    }
                }
            }

            var i: usize = 0;
            while (i < 256) {
                const object = try obj_iter.next(allocator) orelse break;
                defer object.deinit();
                try net_pkt.bufferHave(repo_opts.hash, allocator, &object.oid, &buffer);

                i += 1;
                if (i % 20 == 0) {
                    try buffer.appendSlice(allocator, "0000");

                    try self.negotiationStep(io, allocator, buffer.items);

                    buffer.clearAndFree(allocator);

                    if (self.caps.multi_ack or self.caps.multi_ack_detailed) {
                        while (true) {
                            var pkt = try self.recvPkt(allocator);
                            if (pkt != .ack) {
                                pkt.deinit(allocator);
                                break;
                            } else {
                                errdefer pkt.deinit(allocator);
                                try self.common.append(allocator, pkt);
                            }
                        }
                    } else {
                        var pkt = try self.recvPkt(allocator);
                        defer pkt.deinit(allocator);

                        switch (pkt) {
                            .ack => break,
                            .nak => continue,
                            else => return error.UnexpectedPktType,
                        }
                    }
                }

                if (self.common.items.len > 0) {
                    break;
                }

                if (i % 20 == 0 and self.is_stateless) {
                    try net_pkt.bufferWants(repo_opts.hash, allocator, heads, &self.caps, &buffer);

                    for (self.common.items) |*pkt| {
                        try net_pkt.bufferHave(repo_opts.hash, allocator, &pkt.ack.oid, &buffer);
                    }
                }
            }

            if (self.is_stateless and self.common.items.len > 0) {
                try net_pkt.bufferWants(repo_opts.hash, allocator, heads, &self.caps, &buffer);

                for (self.common.items) |*pkt| {
                    try net_pkt.bufferHave(repo_opts.hash, allocator, &pkt.ack.oid, &buffer);
                }
            }

            try buffer.appendSlice(allocator, "0009done\n");

            try self.negotiationStep(io, allocator, buffer.items);
            self.request_sent = true;

            if (!self.caps.multi_ack and !self.caps.multi_ack_detailed) {
                var pkt = try self.recvPkt(allocator);
                defer pkt.deinit(allocator);

                switch (pkt) {
                    .ack, .nak => {},
                    else => return error.UnexpectedPktType,
                }
            } else {
                try self.waitAck(allocator);
            }
        }

        fn pktline(allocator: std.mem.Allocator, buffer: *std.ArrayList(u8), specs: []net_push.PushSpec(repo_kind, repo_opts), object_format: bool) !void {
            for (specs, 0..) |*spec, i| {
                if (i == 0) {
                    try net_pkt.appendPktLine(allocator, buffer, "{s} {s} {s}\x00 report-status side-band-64k{s}\n", .{ &spec.roid, &spec.loid, spec.refspec.dst, if (object_format) " object-format=" ++ @tagName(repo_opts.hash) else "" });
                } else {
                    try net_pkt.appendPktLine(allocator, buffer, "{s} {s} {s}\n", .{ &spec.roid, &spec.loid, spec.refspec.dst });
                }
            }

            try buffer.appendSlice(allocator, "0000");
        }

        fn negotiationStep(
            self: *WireTransport(repo_kind, repo_opts),
            io: std.Io,
            allocator: std.mem.Allocator,
            buffer: []const u8,
        ) !void {
            if (.fetch != self.direction) {
                return error.InvalidDirection;
            }

            try self.connection.openStream(io, allocator, .upload_pack);

            if (self.connection.wire_stream) |*stream| {
                try stream.write(allocator, buffer.ptr, buffer.len);
            }
        }

        pub fn downloadPack(
            self: *WireTransport(repo_kind, repo_opts),
            state: rp.Repo(repo_kind, repo_opts).State(.read_write),
            io: std.Io,
            allocator: std.mem.Allocator,
        ) !void {
            const temp_pack_name = "temp.pack";

            // receive pack file
            {
                var temp_pack = try fs.LockFile.init(io, state.core.repo_dir, temp_pack_name);
                defer temp_pack.deinit(io);

                while (true) {
                    var pkt = try self.recvPkt(allocator);
                    defer pkt.deinit(allocator);

                    switch (pkt) {
                        .progress => |progress| if (repo_opts.ProgressCtx != void) {
                            if (self.opts.progress_ctx) |progress_ctx| {
                                try progress_ctx.run(io, .{ .text = progress });
                            }
                        },
                        .data => |data| if (data.len > 0) {
                            try temp_pack.lock_file.writeStreamingAll(io, data);
                        },
                        .flush => break,
                        else => {},
                    }
                }

                temp_pack.success = true;
            }

            // iterate over pack file
            {
                defer state.core.repo_dir.deleteFile(io, temp_pack_name) catch {};

                var pack_reader = try pack.PackReader.initFile(io, allocator, state.core.repo_dir, temp_pack_name);
                defer pack_reader.deinit();

                var pack_iter = try pack.PackIterator(repo_kind, repo_opts).init(io, allocator, &pack_reader);

                try obj.copyFromPackIterator(repo_kind, repo_opts, state, io, allocator, &pack_iter, self.opts.progress_ctx);
            }
        }

        fn addRefs(
            self: *WireTransport(repo_kind, repo_opts),
            io: std.Io,
            allocator: std.mem.Allocator,
            flushes: c_int,
        ) !void {
            for (self.refs.items) |*ref| {
                ref.deinit(allocator);
            }
            self.refs.clearAndFree(allocator);

            var flush: c_int = 0;
            var found_capabilities = false;
            var consumed: usize = 0;
            while (true) {
                var pkt_maybe = try net_pkt.Pkt(repo_opts.hash).initMaybe(allocator, self.connection.buffer.data[0..self.connection.buffer.len], &found_capabilities, &consumed);

                if (pkt_maybe) |*pkt| {
                    self.connection.buffer.consume(consumed);

                    switch (pkt.*) {
                        .err => |msg| {
                            if (repo_opts.ProgressCtx != void) {
                                if (self.opts.progress_ctx) |progress_ctx| {
                                    try progress_ctx.run(io, .{ .text = msg });
                                }
                            }
                            pkt.deinit(allocator);
                            return error.ServerReportedError;
                        },
                        .flush => {
                            flush += 1;
                            pkt.deinit(allocator);
                        },
                        .ref => |*ref| {
                            errdefer ref.deinit(allocator);
                            try self.refs.append(allocator, ref.*);
                        },
                        else => pkt.deinit(allocator),
                    }

                    if (flush < flushes) {
                        continue;
                    } else {
                        break;
                    }
                } else {
                    const recvd = try self.connection.recv(allocator);

                    if (recvd == 0) {
                        return error.CouldNotReadRefsFromRemoteRepo;
                    }
                }
            }
        }

        fn recvPkt(
            self: *WireTransport(repo_kind, repo_opts),
            allocator: std.mem.Allocator,
        ) !net_pkt.Pkt(repo_opts.hash) {
            var found_capabilities = true;
            var consumed: usize = 0;

            while (true) {
                if (try net_pkt.Pkt(repo_opts.hash).initMaybe(allocator, self.connection.buffer.data[0..self.connection.buffer.len], &found_capabilities, &consumed)) |pkt| {
                    self.connection.buffer.consume(consumed);
                    return pkt;
                }

                const bytes_read = try self.connection.recv(allocator);
                if (bytes_read == 0) {
                    return error.CouldNotReadFromRemoteRepo;
                }
            }
        }

        fn waitAck(
            self: *WireTransport(repo_kind, repo_opts),
            allocator: std.mem.Allocator,
        ) !void {
            while (true) {
                var pkt = try self.recvPkt(allocator);
                defer pkt.deinit(allocator);

                switch (pkt) {
                    .nak => break,
                    .ack => |ack| if (ack.status == null) {
                        break;
                    },
                    else => {},
                }
            }
        }

        pub fn isConnected(self: *const WireTransport(repo_kind, repo_opts)) bool {
            return self.connected;
        }

        pub fn close(
            self: *WireTransport(repo_kind, repo_opts),
            io: std.Io,
            allocator: std.mem.Allocator,
        ) void {
            const flush = "0000";
            // the server may have closed after the request.
            if (self.connected and !self.is_stateless and !self.request_sent) {
                if (self.connection.wire_stream) |*stream| {
                    stream.write(allocator, flush, flush.len) catch {};
                }
            }

            self.connection.close(io, allocator);

            for (self.common.items) |*pkt| {
                pkt.deinit(allocator);
            }
            self.common.clearAndFree(allocator);

            self.connected = false;
        }

        fn updateHeads(self: *WireTransport(repo_kind, repo_opts), allocator: std.mem.Allocator, symrefs: []net_refspec.RefSpec) !void {
            self.heads.clearAndFree(allocator);

            for (self.refs.items) |*ref| {
                var buffer: std.ArrayList(u8) = .empty;
                defer buffer.deinit(allocator);

                for (symrefs) |*spec| {
                    buffer.clearAndFree(allocator);
                    if (net_refspec.matches(spec.src, ref.head.name)) {
                        try net_refspec.transform(allocator, &buffer, spec, ref.head.name);
                        if (ref.head.symref) |target| allocator.free(target);
                        ref.head.symref = try allocator.dupe(u8, buffer.items);
                    }
                }

                try self.heads.append(allocator, ref.head);
            }
            // an unborn HEAD can be advertised only through its symref capability.
            for (symrefs) |spec| {
                if (!std.mem.eql(u8, spec.src, "HEAD")) continue;
                const has_head = for (self.heads.items) |head| {
                    if (std.mem.eql(u8, head.name, "HEAD")) break true;
                } else false;
                if (has_head) continue;
                var head = net.RemoteHead(repo_opts.hash).init(try allocator.dupe(u8, "HEAD"));
                errdefer allocator.free(head.name);
                const symref = try allocator.dupe(u8, spec.dst);
                errdefer allocator.free(symref);
                head.symref = symref;
                try self.refs.ensureUnusedCapacity(allocator, 1);
                try self.heads.ensureUnusedCapacity(allocator, 1);
                self.refs.appendAssumeCapacity(.{ .head = head, .capabilities = null });
                self.heads.appendAssumeCapacity(head);
            }
        }

        fn handlePushPkts(
            self: *WireTransport(repo_kind, repo_opts),
            io: std.Io,
            allocator: std.mem.Allocator,
            git_push: *net_push.Push(repo_kind, repo_opts),
        ) !void {
            var found_capabilities = false;
            var consumed: usize = 0;

            while (true) {
                var pkt_maybe = try net_pkt.Pkt(repo_opts.hash).initMaybe(allocator, self.connection.buffer.data[0..self.connection.buffer.len], &found_capabilities, &consumed);

                if (pkt_maybe) |*pkt| {
                    defer pkt.deinit(allocator);

                    self.connection.buffer.consume(consumed);

                    var iter_over = false;

                    switch (pkt.*) {
                        .data => |data| try self.handlePushSidebandPkt(io, allocator, git_push, data),
                        .err => |msg| {
                            if (repo_opts.ProgressCtx != void) {
                                if (self.opts.progress_ctx) |progress_ctx| {
                                    try progress_ctx.run(io, .{ .text = msg });
                                }
                            }
                            return error.ServerReportedError;
                        },
                        .progress => |progress| if (repo_opts.ProgressCtx != void) {
                            if (self.opts.progress_ctx) |progress_ctx| {
                                try progress_ctx.run(io, .{ .text = progress });
                            }
                        },
                        else => iter_over = try self.handlePushPkt(io, git_push, pkt),
                    }

                    if (iter_over) {
                        return;
                    }
                } else {
                    const recvd = try self.connection.recv(allocator);

                    if (recvd == 0) {
                        return error.CouldNotReadFromRemoteRepo;
                    }
                }
            }
        }

        fn handlePushPkt(
            self: *WireTransport(repo_kind, repo_opts),
            io: std.Io,
            git_push: *net_push.Push(repo_kind, repo_opts),
            pkt: *net_pkt.Pkt(repo_opts.hash),
        ) !bool {
            switch (pkt.*) {
                .ok => {},
                .ng => |msg| {
                    git_push.ref_rejected = true;
                    if (repo_opts.ProgressCtx != void) {
                        if (self.opts.progress_ctx) |progress_ctx| {
                            try progress_ctx.run(io, .{ .text = msg });
                        }
                    }
                },
                .unpack => |unpack| git_push.unpack_ok = unpack.unpack_ok,
                .flush => return true,
                else => return error.ProtocolError,
            }
            return false;
        }

        fn handlePushSidebandPkt(
            self: *WireTransport(repo_kind, repo_opts),
            io: std.Io,
            allocator: std.mem.Allocator,
            git_push: *net_push.Push(repo_kind, repo_opts),
            data_pkt: []const u8,
        ) !void {
            var line = data_pkt;
            var found_capabilities = false;
            var consumed: usize = 0;

            while (line.len > 0) {
                var pkt = try net_pkt.Pkt(repo_opts.hash).initMaybe(allocator, line, &found_capabilities, &consumed) orelse return;
                defer pkt.deinit(allocator);

                line = line[consumed..];

                _ = try self.handlePushPkt(io, git_push, &pkt);
            }
        }
    };
}

pub const Capabilities = struct {
    object_format: bool = false,
    allow_tip_sha1_in_want: bool = false,
    allow_reachable_sha1_in_want: bool = false,
    ofs_delta: bool = false,
    multi_ack: bool = false,
    multi_ack_detailed: bool = false,
    side_band: bool = false,
    side_band_64k: bool = false,
    include_tag: bool = false,
    thin_pack: bool = false,
    shallow: bool = false,
    common: bool = false,

    fn init(allocator: std.mem.Allocator, caps_maybe: ?[]const u8, symrefs: *std.ArrayList(net_refspec.RefSpec)) !Capabilities {
        var self = Capabilities{};
        var iter = std.mem.tokenizeAny(u8, caps_maybe orelse return self, " \t\r\n");

        while (iter.next()) |cap| {
            if (std.mem.startsWith(u8, cap, "ofs-delta")) {
                self.ofs_delta = true;
                self.common = true;
            } else if (std.mem.startsWith(u8, cap, "multi_ack_detailed")) {
                self.multi_ack_detailed = true;
                self.common = true;
            } else if (std.mem.startsWith(u8, cap, "multi_ack")) {
                self.multi_ack = true;
                self.common = true;
            } else if (std.mem.startsWith(u8, cap, "include-tag")) {
                self.include_tag = true;
                self.common = true;
            } else if (std.mem.startsWith(u8, cap, "side-band-64k")) {
                self.side_band_64k = true;
                self.common = true;
            } else if (std.mem.startsWith(u8, cap, "side-band")) {
                self.side_band = true;
                self.common = true;
            } else if (std.mem.startsWith(u8, cap, "delete-refs")) {
                self.common = true;
            } else if (std.mem.startsWith(u8, cap, "push-options")) {
                self.common = true;
            } else if (std.mem.startsWith(u8, cap, "thin-pack")) {
                self.thin_pack = true;
                self.common = true;
            } else if (std.mem.startsWith(u8, cap, "symref=")) {
                const symref = cap["symref=".len..];

                var spec = try net_refspec.RefSpec.init(allocator, symref, .fetch);
                errdefer spec.deinit(allocator);

                try symrefs.append(allocator, spec);
            } else if (std.mem.startsWith(u8, cap, "allow-tip-sha1-in-want")) {
                self.allow_tip_sha1_in_want = true;
                self.common = true;
            } else if (std.mem.startsWith(u8, cap, "allow-reachable-sha1-in-want")) {
                self.allow_reachable_sha1_in_want = true;
                self.common = true;
            } else if (std.mem.startsWith(u8, cap, "object-format=")) {
                self.object_format = true;
                self.common = true;
            } else if (std.mem.startsWith(u8, cap, "agent=")) {
                // currently ignored
            } else if (std.mem.startsWith(u8, cap, "shallow")) {
                self.shallow = true;
                self.common = true;
            }
        }

        return self;
    }
};
