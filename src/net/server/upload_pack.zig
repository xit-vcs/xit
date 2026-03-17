const std = @import("std");
const common = @import("./common.zig");
const pkt = @import("./pkt.zig");

const rp = @import("../../repo.zig");
const obj = @import("../../object.zig");
const pack = @import("../../pack.zig");
const hash = @import("../../hash.zig");
const rf = @import("../../ref.zig");
const cfg = @import("../../config.zig");

pub const Options = struct {
    protocol_version: common.ProtocolVersion = .v0,
    advertise_refs: bool = false,
    is_stateless: bool = false,
};

pub fn run(
    comptime repo_kind: rp.RepoKind,
    comptime repo_opts: rp.RepoOpts(repo_kind),
    state: rp.Repo(repo_kind, repo_opts).State(.read_only),
    io: std.Io,
    allocator: std.mem.Allocator,
    reader: *std.Io.Reader,
    writer: *std.Io.Writer,
    options: Options,
) !void {

    switch (options.protocol_version) {
        .v2 => {
            var v2_config = V2Config{};
            {
                var config = try cfg.Config(repo_kind, repo_opts).init(state, io, allocator);
                defer config.deinit();
                if (config.sections.get("uploadpack")) |vars| {
                    if (vars.get("allowfilter")) |v| {
                        v2_config.allow_filter = common.parseBool(v);
                    }
                    if (vars.get("allowrefinwant")) |v| {
                        v2_config.allow_ref_in_want = common.parseBool(v);
                    }
                    if (vars.get("allowsidebandall")) |v| {
                        v2_config.allow_sideband_all = common.parseBool(v);
                    }
                    if (vars.get("blobpackfileuri")) |_| {
                        v2_config.allow_packfile_uris = true;
                    }
                    if (vars.get("advertisebundleuris")) |v| {
                        v2_config.advertise_bundle_uris = common.parseBool(v);
                    }
                }
                if (config.sections.get("lsrefs")) |vars| {
                    if (vars.get("unborn")) |v| {
                        v2_config.advertise_unborn = std.mem.eql(u8, v, "advertise");
                    }
                }
                if (config.sections.get("transfer")) |vars| {
                    if (vars.get("advertisesid")) |v| {
                        v2_config.advertise_sid = common.parseBool(v);
                    }
                    if (vars.get("advertiseobjectinfo")) |v| {
                        v2_config.advertise_object_info = common.parseBool(v);
                    }
                }
            }
            if (options.advertise_refs) {
                try protocolV2AdvertiseCapabilities(writer, repo_opts.hash, &v2_config);
            } else {
                if (!options.is_stateless) {
                    try protocolV2AdvertiseCapabilities(writer, repo_opts.hash, &v2_config);
                }

                if (options.is_stateless) {
                    _ = try processRequest(writer, repo_kind, repo_opts, state, io, allocator, &v2_config, reader);
                } else {
                    while (true) {
                        if (try processRequest(writer, repo_kind, repo_opts, state, io, allocator, &v2_config, reader)) break;
                    }
                }
            }
        },
        .v1 => {
            if (options.advertise_refs or !options.is_stateless) {
                try pkt.writePktLineFmt(writer, "version 1\n", .{});
            }

            try uploadPack(writer, repo_kind, repo_opts, state, io, allocator, options, reader);
        },
        .v0 => {
            try uploadPack(writer, repo_kind, repo_opts, state, io, allocator, options, reader);
        },
    }
}

fn uploadPack(
    writer: *std.Io.Writer,
    comptime repo_kind: rp.RepoKind,
    comptime repo_opts: rp.RepoOpts(repo_kind),
    state: rp.Repo(repo_kind, repo_opts).State(.read_only),
    io: std.Io,
    allocator: std.mem.Allocator,
    options: Options,
    stdin_reader: *std.Io.Reader,
) !void {
    const hex_len = comptime hash.hexLen(repo_opts.hash);
    var upload_pack = UploadPack.init(allocator);
    defer upload_pack.deinit();
    var our_refs = std.AutoHashMap([hex_len]u8, void).init(allocator);
    defer our_refs.deinit();
    var shallow_oids = std.AutoHashMap([hex_len]u8, void).init(allocator);
    defer shallow_oids.deinit();
    var deepen_not = std.AutoHashMap([hex_len]u8, void).init(allocator);
    defer deepen_not.deinit();
    var want_obj: std.ArrayList([hex_len]u8) = .empty;
    defer want_obj.deinit(allocator);
    var have_obj: std.ArrayList([hex_len]u8) = .empty;
    defer have_obj.deinit(allocator);

    try upload_pack.readConfig(repo_kind, repo_opts, state, io, allocator);

    upload_pack.is_stateless = options.is_stateless;

    {
        var head_buf = [_]u8{0} ** rf.MAX_REF_CONTENT_SIZE;
        if (try rf.readHead(repo_kind, repo_opts, state, io, &head_buf)) |head_ref_or_oid| {
            switch (head_ref_or_oid) {
                .ref => |ref| {
                    var target_buf = [_]u8{0} ** rf.MAX_REF_CONTENT_SIZE;
                    const target = try ref.toPath(&target_buf);
                    try upload_pack.symrefs.append(upload_pack.arena.allocator(), .{
                        .name = "HEAD",
                        .target = try upload_pack.arena.allocator().dupe(u8, target),
                    });
                },
                .oid => {},
            }
        }
    }

    if (options.advertise_refs or !upload_pack.is_stateless) {
        if (options.advertise_refs) {
            upload_pack.no_done = true;
        }

        // head
        if (try rf.readHeadRecurMaybe(repo_kind, repo_opts, state, io)) |*head_oid| {
            try upload_pack.writeV0Ref(repo_kind, repo_opts, state, io, allocator, writer, &our_refs, "HEAD", head_oid);
        }

        // heads
        {
            var heads = try rf.RefIterator(repo_kind, repo_opts).init(state, io, allocator, .head);
            defer heads.deinit(io);
            while (try heads.next(io)) |ref| {
                if (try rf.readRecur(repo_kind, repo_opts, state, io, .{ .ref = ref })) |*oid| {
                    var path_buf = [_]u8{0} ** rf.MAX_REF_CONTENT_SIZE;
                    const ref_path = try ref.toPath(&path_buf);
                    try upload_pack.writeV0Ref(repo_kind, repo_opts, state, io, allocator, writer, &our_refs, ref_path, oid);
                }
            }
        }

        // tags
        {
            var tags = try rf.RefIterator(repo_kind, repo_opts).init(state, io, allocator, .tag);
            defer tags.deinit(io);
            while (try tags.next(io)) |ref| {
                if (try rf.readRecur(repo_kind, repo_opts, state, io, .{ .ref = ref })) |*oid| {
                    var path_buf = [_]u8{0} ** rf.MAX_REF_CONTENT_SIZE;
                    const ref_path = try ref.toPath(&path_buf);
                    try upload_pack.writeV0Ref(repo_kind, repo_opts, state, io, allocator, writer, &our_refs, ref_path, oid);
                }
            }
        }

        if (!upload_pack.sent_capabilities) {
            try upload_pack.writeV0Ref(repo_kind, repo_opts, state, io, allocator, writer, &our_refs, "capabilities^{}", &[_]u8{'0'} ** hash.hexLen(repo_opts.hash));
        }

        try pkt.writePktFlush(writer);
    } else {
        // mark HEAD
        if (try rf.readHeadRecurMaybe(repo_kind, repo_opts, state, io)) |*head_oid| {
            try our_refs.put(head_oid.*, {});
        }
        // mark heads
        {
            var heads = try rf.RefIterator(repo_kind, repo_opts).init(state, io, allocator, .head);
            defer heads.deinit(io);
            while (try heads.next(io)) |ref| {
                if (try rf.readRecur(repo_kind, repo_opts, state, io, .{ .ref = ref })) |*oid| {
                    try our_refs.put(oid.*, {});
                }
            }
        }
        // mark tags
        {
            var tags = try rf.RefIterator(repo_kind, repo_opts).init(state, io, allocator, .tag);
            defer tags.deinit(io);
            while (try tags.next(io)) |ref| {
                if (try rf.readRecur(repo_kind, repo_opts, state, io, .{ .ref = ref })) |*oid| {
                    try our_refs.put(oid.*, {});
                }
            }
        }
    }

    if (!options.advertise_refs) {
        try upload_pack.receiveNeeds(writer, repo_kind, repo_opts, state, io, allocator, &our_refs, stdin_reader, &shallow_oids, &deepen_not, &want_obj);

        if (!upload_pack.use_sideband) return error.SidebandProtocolRequired;

        if (want_obj.items.len != 0) {
            // peek for eof before entering common commit negotiation
            var peek_buf: [pkt.LARGE_PACKET_MAX]u8 = undefined;
            switch (try pkt.readPktLineEx(stdin_reader, &peek_buf)) {
                .eof => {},
                .data => |line| {
                    try upload_pack.getCommonCommits(repo_kind, repo_opts, state, io, writer, allocator, stdin_reader, &have_obj, &want_obj, line);
                    try writePack(repo_kind, repo_opts, state, io, allocator, writer, &want_obj);
                },
                .flush => {
                    // flush with no negotiation; proceed directly to pack
                    try upload_pack.getCommonCommits(repo_kind, repo_opts, state, io, writer, allocator, stdin_reader, &have_obj, &want_obj, null);
                    try writePack(repo_kind, repo_opts, state, io, allocator, writer, &want_obj);
                },
                .delim => return error.UnexpectedDelim,
                .response_end => return error.UnexpectedResponseEnd,
            }
        }
    }
}

fn writePack(
    comptime repo_kind: rp.RepoKind,
    comptime repo_opts: rp.RepoOpts(repo_kind),
    state: rp.Repo(repo_kind, repo_opts).State(.read_only),
    io: std.Io,
    allocator: std.mem.Allocator,
    writer: *std.Io.Writer,
    want_obj: *const std.ArrayList([hash.hexLen(repo_opts.hash)]u8),
) !void {
    var obj_iter = try obj.ObjectIterator(repo_kind, repo_opts, .raw).init(state, io, allocator, .{ .kind = .all });
    defer obj_iter.deinit();

    for (want_obj.items) |*item| {
        try obj_iter.include(item);
    }

    var pack_writer_maybe = try pack.PackWriter(repo_kind, repo_opts).init(allocator, &obj_iter);
    if (pack_writer_maybe) |*pack_writer| {
        defer pack_writer.deinit();

        var read_buffer = [_]u8{0} ** repo_opts.read_size;

        while (true) {
            const size = try pack_writer.read(&read_buffer);
            if (size == 0) break;
            try pkt.writePktLineSB(writer, 1, read_buffer[0..size]);
        }
    }

    try pkt.writePktFlush(writer);
}

const UploadPack = struct {
    // config
    allow_uor: AllowUor = .{},
    allow_filter: bool = false,
    allow_ref_in_want: bool = false,
    allow_sideband_all: bool = false,
    allow_packfile_uris: bool = false,

    // capabilities negotiated with client
    multi_ack: MultiAck = .none,
    use_sideband: bool = false,
    writer_use_sideband: bool = false,
    no_done: bool = false,
    is_stateless: bool = false,
    filter_capability_requested: bool = false,
    sent_capabilities: bool = false,
    symrefs: std.ArrayList(Symref) = .empty,
    uri_protocols: std.ArrayList([]const u8) = .empty,

    // shallow/deepen state
    depth: usize = 0,
    deepen_since: u64 = 0,
    deepen_rev_list: bool = false,
    deepen_relative: bool = false,

    // request state
    filter_options: FilterOptions = .none,
    wait_for_done: bool = false,
    done: bool = false,
    seen_haves: bool = false,

    arena: std.heap.ArenaAllocator,

    fn init(allocator: std.mem.Allocator) UploadPack {
        return .{ .arena = std.heap.ArenaAllocator.init(allocator) };
    }

    fn deinit(self: *UploadPack) void {
        self.arena.deinit();
    }

    fn readConfig(
        self: *UploadPack,
        comptime repo_kind: rp.RepoKind,
        comptime repo_opts: rp.RepoOpts(repo_kind),
        state: rp.Repo(repo_kind, repo_opts).State(.read_only),
        io: std.Io,
        allocator: std.mem.Allocator,
    ) !void {
        var config = try cfg.Config(repo_kind, repo_opts).init(state, io, allocator);
        defer config.deinit();

        if (config.sections.get("uploadpack")) |vars| {
            if (vars.get("allowtipsha1inwant")) |v| {
                self.allow_uor.tip_sha1 = common.parseBool(v);
            }
            if (vars.get("allowreachablesha1inwant")) |v| {
                self.allow_uor.reachable_sha1 = common.parseBool(v);
            }
            if (vars.get("allowanysha1inwant")) |v| {
                const allow = common.parseBool(v);
                self.allow_uor = .{
                    .tip_sha1 = allow,
                    .reachable_sha1 = allow,
                    .any_sha1 = allow,
                };
            }
            if (vars.get("allowfilter")) |v| {
                self.allow_filter = common.parseBool(v);
            }
            if (vars.get("allowrefinwant")) |v| {
                self.allow_ref_in_want = common.parseBool(v);
            }
            if (vars.get("allowsidebandall")) |v| {
                self.allow_sideband_all = common.parseBool(v);
            }
            if (vars.get("blobpackfileuri")) |_| {
                self.allow_packfile_uris = true;
            }
        }
    }

    fn writeV0Ref(
        self: *UploadPack,
        comptime repo_kind: rp.RepoKind,
        comptime repo_opts: rp.RepoOpts(repo_kind),
        state: rp.Repo(repo_kind, repo_opts).State(.read_only),
        io: std.Io,
        allocator: std.mem.Allocator,
        writer: *std.Io.Writer,
        our_refs: *std.AutoHashMap([hash.hexLen(repo_opts.hash)]u8, void),
        refname_nons: []const u8,
        oid: *const [hash.hexLen(repo_opts.hash)]u8,
    ) !void {
        const v0_capabilities = "multi_ack thin-pack side-band side-band-64k ofs-delta shallow deepen-since deepen-not deepen-relative no-progress include-tag multi_ack_detailed";

        try our_refs.put(oid.*, {});

        if (!self.sent_capabilities) {
            var line_buf: [pkt.LARGE_PACKET_MAX]u8 = undefined;
            var line: std.Io.Writer = .fixed(&line_buf);
            try line.print("{s} {s}", .{ oid, refname_nons });
            try line.writeByte(0);
            try line.writeAll(v0_capabilities);
            if (self.allow_uor.tip_sha1) {
                try line.writeAll(" allow-tip-sha1-in-want");
            }
            if (self.allow_uor.reachable_sha1) {
                try line.writeAll(" allow-reachable-sha1-in-want");
            }
            if (self.no_done) {
                try line.writeAll(" no-done");
            }
            for (self.symrefs.items) |entry|
                try line.print(" symref={s}:{s}", .{ entry.name, entry.target });
            if (self.allow_filter) {
                try line.writeAll(" filter");
            }
            try line.print(" object-format={s} agent={s}\n", .{
                common.hashName(repo_opts.hash),
                "git/2.51.2",
            });
            try pkt.writePktLine(writer, line.buffered());
            self.sent_capabilities = true;
        } else {
            try pkt.writePktLineFmt(writer, "{s} {s}\n", .{ oid, refname_nons });
        }

        var peeled_oid = oid.*;
        const peeled = try peelToNonTag(repo_kind, repo_opts, state, io, allocator, &peeled_oid);
        if (peeled) {
            try pkt.writePktLineFmt(writer, "{s} {s}^{{}}\n", .{ &peeled_oid, refname_nons });
        }
    }

    fn sendShallow(
        self: *UploadPack,
        comptime hex_len: usize,
        writer: *std.Io.Writer,
        boundary_oids: []const [hex_len]u8,
        shallow_oids: *const std.AutoHashMap([hex_len]u8, void),
        not_shallow_oids: *std.AutoHashMap([hex_len]u8, void),
    ) !void {
        for (boundary_oids) |oid| {
            // remove from not_shallow so boundary commits get marked shallow
            _ = not_shallow_oids.remove(oid);

            if (!shallow_oids.contains(oid)) {
                try writePktResponse(writer, self.writer_use_sideband, "shallow {s}", .{&oid});
            }
        }
    }

    fn sendUnshallow(
        self: *UploadPack,
        comptime repo_kind: rp.RepoKind,
        comptime repo_opts: rp.RepoOpts(repo_kind),
        state: rp.Repo(repo_kind, repo_opts).State(.read_only),
        io: std.Io,
        writer: *std.Io.Writer,
        allocator: std.mem.Allocator,
        shallow_oids: *const std.AutoHashMap([hash.hexLen(repo_opts.hash)]u8, void),
        not_shallow_oids: *const std.AutoHashMap([hash.hexLen(repo_opts.hash)]u8, void),
        want_obj: *std.ArrayList([hash.hexLen(repo_opts.hash)]u8),
    ) !void {
        var it = shallow_oids.keyIterator();
        while (it.next()) |oid| {
            if (not_shallow_oids.contains(oid.*)) {
                try writePktResponse(writer, self.writer_use_sideband, "unshallow {s}", .{oid});
                var object = obj.Object(repo_kind, repo_opts, .full).init(state, io, allocator, oid) catch |err| switch (err) {
                    error.ObjectNotFound => continue,
                    else => |e| return e,
                };
                defer object.deinit();
                switch (object.content) {
                    .commit => |commit| {
                        if (commit.metadata.parent_oids) |parent_oids| {
                            for (parent_oids) |parent_oid| {
                                try want_obj.append(allocator, parent_oid);
                            }
                        }
                    },
                    else => {},
                }
            }
        }
    }

    fn deepenByRevList(
        self: *UploadPack,
        writer: *std.Io.Writer,
        comptime repo_kind: rp.RepoKind,
        comptime repo_opts: rp.RepoOpts(repo_kind),
        state: rp.Repo(repo_kind, repo_opts).State(.read_only),
        io: std.Io,
        allocator: std.mem.Allocator,
        shallow_oids: *const std.AutoHashMap([hash.hexLen(repo_opts.hash)]u8, void),
        deepen_not: *const std.AutoHashMap([hash.hexLen(repo_opts.hash)]u8, void),
        want_obj: *std.ArrayList([hash.hexLen(repo_opts.hash)]u8),
    ) !void {
        const hex_len = comptime hash.hexLen(repo_opts.hash);

        // walk commits reachable from wants
        var obj_iter = try obj.ObjectIterator(repo_kind, repo_opts, .full).init(state, io, allocator, .{ .kind = .commit });
        defer obj_iter.deinit();

        // build exclude set from deepen-not refs
        if (deepen_not.count() != 0) {
            var exclude_iter = try obj.ObjectIterator(repo_kind, repo_opts, .raw).init(state, io, allocator, .{ .kind = .commit });
            defer exclude_iter.deinit();

            var it = deepen_not.keyIterator();
            while (it.next()) |oid| {
                try exclude_iter.include(oid);
            }

            while (try exclude_iter.next()) |excluded_obj| {
                excluded_obj.deinit();
            }

            // transfer visited oids to main iterator's excludes
            var exclude_it = exclude_iter.oid_excludes.iterator();
            while (exclude_it.next()) |entry| {
                try obj_iter.oid_excludes.put(entry.key_ptr.*, {});
            }
        }

        // include all want oids
        for (want_obj.items) |*item| {
            try obj_iter.include(item);
        }

        // collect reachable commits and their parents
        var not_shallow_oids = std.AutoHashMap([hex_len]u8, void).init(allocator);
        defer not_shallow_oids.deinit();

        var parent_arena = std.heap.ArenaAllocator.init(allocator);
        defer parent_arena.deinit();

        const ParentEntry = struct { oid: [hex_len]u8, parents: []const [hex_len]u8 };
        var reachable_commits: std.ArrayList(ParentEntry) = .empty;
        defer reachable_commits.deinit(allocator);

        while (try obj_iter.next()) |object| {
            defer object.deinit();

            // skip commits older than deepen-since cutoff
            if (self.deepen_since != 0 and object.content.commit.metadata.timestamp < self.deepen_since) continue;

            try not_shallow_oids.put(object.oid, {});

            // save parents (copy into arena since object will be deinited)
            if (object.content.commit.metadata.parent_oids) |parents| {
                const saved = try parent_arena.allocator().dupe([hex_len]u8, parents);
                try reachable_commits.append(allocator, .{ .oid = object.oid, .parents = saved });
            } else {
                try reachable_commits.append(allocator, .{ .oid = object.oid, .parents = &.{} });
            }
        }

        if (not_shallow_oids.count() == 0) return error.NoCommitsForShallow;

        // boundary: commits with at least one parent not in not_shallow_oids
        var boundary_oids: std.ArrayList([hex_len]u8) = .empty;
        defer boundary_oids.deinit(allocator);

        for (reachable_commits.items) |entry| {
            for (entry.parents) |parent_oid| {
                if (!not_shallow_oids.contains(parent_oid)) {
                    try boundary_oids.append(allocator, entry.oid);
                    break;
                }
            }
        }

        // send shallow markers
        try self.sendShallow(hex_len, writer, boundary_oids.items, shallow_oids, &not_shallow_oids);

        // send unshallow for client shallows that are now reachable
        try self.sendUnshallow(repo_kind, repo_opts, state, io, writer, allocator, shallow_oids, &not_shallow_oids, want_obj);
    }

    fn deepen(
        self: *UploadPack,
        writer: *std.Io.Writer,
        comptime repo_kind: rp.RepoKind,
        comptime repo_opts: rp.RepoOpts(repo_kind),
        state: rp.Repo(repo_kind, repo_opts).State(.read_only),
        io: std.Io,
        allocator: std.mem.Allocator,
        our_refs: *std.AutoHashMap([hash.hexLen(repo_opts.hash)]u8, void),
        depth: usize,
        shallow_oids: *const std.AutoHashMap([hash.hexLen(repo_opts.hash)]u8, void),
        want_obj: *std.ArrayList([hash.hexLen(repo_opts.hash)]u8),
    ) !void {
        const hex_len = comptime hash.hexLen(repo_opts.hash);

        // track reachable (not shallow) oids
        var not_shallow_oids = std.AutoHashMap([hex_len]u8, void).init(allocator);
        defer not_shallow_oids.deinit();

        if (depth == infinite_depth) {
            var it = shallow_oids.keyIterator();
            while (it.next()) |oid| {
                try not_shallow_oids.put(oid.*, {});
            }
        } else if (self.deepen_relative) {
            var reachable_shallows: std.ArrayList([hex_len]u8) = .empty;
            defer reachable_shallows.deinit(allocator);
            // head
            if (try rf.readHeadRecurMaybe(repo_kind, repo_opts, state, io)) |*head_oid| {
                try our_refs.put(head_oid.*, {});
            }
            // heads
            {
                var heads = try rf.RefIterator(repo_kind, repo_opts).init(state, io, allocator, .head);
                defer heads.deinit(io);
                while (try heads.next(io)) |ref| {
                    if (try rf.readRecur(repo_kind, repo_opts, state, io, .{ .ref = ref })) |*oid| {
                        try our_refs.put(oid.*, {});
                    }
                }
            }
            // tags
            {
                var tags = try rf.RefIterator(repo_kind, repo_opts).init(state, io, allocator, .tag);
                defer tags.deinit(io);
                while (try tags.next(io)) |ref| {
                    if (try rf.readRecur(repo_kind, repo_opts, state, io, .{ .ref = ref })) |*oid| {
                        try our_refs.put(oid.*, {});
                    }
                }
            }
            try getReachableShallows(repo_kind, repo_opts, state, io, allocator, shallow_oids, our_refs, &reachable_shallows);
            var depth_iter = try obj.ObjectIterator(repo_kind, repo_opts, .full).init(state, io, allocator, .{ .kind = .commit, .max_depth = depth });
            defer depth_iter.deinit();
            for (reachable_shallows.items) |*oid| {
                try depth_iter.includeAtDepth(oid, 0);
            }
            while (try depth_iter.next()) |object| {
                defer object.deinit();
                if (depth_iter.depth == depth) {
                    if (!shallow_oids.contains(object.oid) and !not_shallow_oids.contains(object.oid)) {
                        try writePktResponse(writer, self.writer_use_sideband, "shallow {s}", .{&object.oid});
                    }
                } else {
                    try not_shallow_oids.put(object.oid, {});
                }
            }
        } else {
            const max_depth: usize = depth - 1;
            var depth_iter = try obj.ObjectIterator(repo_kind, repo_opts, .full).init(state, io, allocator, .{ .kind = .commit, .max_depth = max_depth });
            defer depth_iter.deinit();
            for (want_obj.items) |*item| {
                try depth_iter.includeAtDepth(item, 0);
            }
            while (try depth_iter.next()) |object| {
                defer object.deinit();
                if (depth_iter.depth == max_depth) {
                    if (!shallow_oids.contains(object.oid) and !not_shallow_oids.contains(object.oid)) {
                        try writePktResponse(writer, self.writer_use_sideband, "shallow {s}", .{&object.oid});
                    }
                } else {
                    try not_shallow_oids.put(object.oid, {});
                }
            }
        }

        try self.sendUnshallow(repo_kind, repo_opts, state, io, writer, allocator, shallow_oids, &not_shallow_oids, want_obj);
    }

    fn sendShallowList(
        self: *UploadPack,
        writer: *std.Io.Writer,
        comptime repo_kind: rp.RepoKind,
        comptime repo_opts: rp.RepoOpts(repo_kind),
        state: rp.Repo(repo_kind, repo_opts).State(.read_only),
        io: std.Io,
        allocator: std.mem.Allocator,
        our_refs: *std.AutoHashMap([hash.hexLen(repo_opts.hash)]u8, void),
        shallow_oids: *const std.AutoHashMap([hash.hexLen(repo_opts.hash)]u8, void),
        deepen_not: *const std.AutoHashMap([hash.hexLen(repo_opts.hash)]u8, void),
        want_obj: *std.ArrayList([hash.hexLen(repo_opts.hash)]u8),
    ) !bool {
        if (self.depth > 0 and self.deepen_rev_list) return error.ConflictingDeepenOptions;

        if (self.depth > 0) {
            try self.deepen(writer, repo_kind, repo_opts, state, io, allocator, our_refs, self.depth, shallow_oids, want_obj);
            return true;
        } else if (self.deepen_rev_list) {
            try self.deepenByRevList(writer, repo_kind, repo_opts, state, io, allocator, shallow_oids, deepen_not, want_obj);
            return true;
        }

        return false;
    }

    fn processArgs(
        self: *UploadPack,
        comptime repo_kind: rp.RepoKind,
        comptime repo_opts: rp.RepoOpts(repo_kind),
        state: rp.Repo(repo_kind, repo_opts).State(.read_only),
        io: std.Io,
        writer: *std.Io.Writer,
        reader: *std.Io.Reader,
        allocator: std.mem.Allocator,
        shallow_oids: *std.AutoHashMap([hash.hexLen(repo_opts.hash)]u8, void),
        deepen_not: *std.AutoHashMap([hash.hexLen(repo_opts.hash)]u8, void),
        wanted_refs: *std.StringHashMap([hash.hexLen(repo_opts.hash)]u8),
        want_obj: *std.ArrayList([hash.hexLen(repo_opts.hash)]u8),
        have_obj: *std.ArrayList([hash.hexLen(repo_opts.hash)]u8),
    ) !void {
        const hex_len = comptime hash.hexLen(repo_opts.hash);
        var wanted_oids = std.AutoHashMap([hex_len]u8, void).init(allocator);
        defer wanted_oids.deinit();
        var line_buf: [pkt.LARGE_PACKET_MAX]u8 = undefined;
        while (true) {
            switch (try pkt.readPktLineEx(reader, &line_buf)) {
                .flush => break,
                .eof => return error.UnexpectedEof,
                .delim => return error.UnexpectedDelim,
                .response_end => return error.UnexpectedResponseEnd,
                .data => |arg| {
                    if (std.mem.startsWith(u8, arg, "want ")) {
                        const want_arg = arg["want ".len..];
                        if (want_arg.len < hex_len) return error.ProtocolErrorExpectedOid;
                        const oid_bytes = want_arg[0..hex_len].*;

                        if (!try objectExists(repo_kind, repo_opts, state, io, allocator, &oid_bytes)) {
                            try writePktError(writer, self.writer_use_sideband, "upload-pack: not our ref {s}", .{&oid_bytes});
                            return error.ClientError;
                        }

                        if (!wanted_oids.contains(oid_bytes)) {
                            try wanted_oids.put(oid_bytes, {});
                            try want_obj.append(allocator, oid_bytes);
                        }

                        continue;
                    }
                    if (self.allow_ref_in_want and std.mem.startsWith(u8, arg, "want-ref ")) {
                        const refname_nons = arg["want-ref ".len..];

                        const ref_val = rf.Ref.initFromPath(refname_nons, null) orelse {
                            try writePktError(writer, self.writer_use_sideband, "unknown ref {s}", .{refname_nons});
                            return error.ClientError;
                        };
                        const oid_bytes = try rf.readRecur(repo_kind, repo_opts, state, io, .{ .ref = ref_val }) orelse {
                            try writePktError(writer, self.writer_use_sideband, "unknown ref {s}", .{refname_nons});
                            return error.ClientError;
                        };

                        if (wanted_refs.contains(refname_nons)) {
                            try writePktError(writer, self.writer_use_sideband, "duplicate want-ref {s}", .{refname_nons});
                            return error.ClientError;
                        }

                        const key = try self.arena.allocator().dupe(u8, refname_nons);
                        try wanted_refs.put(key, oid_bytes);

                        if (!wanted_oids.contains(oid_bytes)) {
                            try wanted_oids.put(oid_bytes, {});
                            try want_obj.append(allocator, oid_bytes);
                        }

                        continue;
                    }
                    if (std.mem.startsWith(u8, arg, "have ")) {
                        const have_arg = arg["have ".len..];
                        if (have_arg.len < hex_len) return error.InvalidObjectId;
                        _ = try appendIfExists(repo_kind, repo_opts, state, io, hex_len, allocator, have_arg[0..hex_len], have_obj);
                        self.seen_haves = true;
                        continue;
                    }

                    if (std.mem.eql(u8, arg, "thin-pack")) continue;
                    if (std.mem.eql(u8, arg, "ofs-delta")) continue;
                    if (std.mem.eql(u8, arg, "no-progress")) continue;
                    if (std.mem.eql(u8, arg, "include-tag")) continue;
                    if (std.mem.eql(u8, arg, "done")) {
                        self.done = true;
                        continue;
                    }
                    if (std.mem.eql(u8, arg, "wait-for-done")) {
                        self.wait_for_done = true;
                        continue;
                    }

                    if (try processShallow(repo_kind, repo_opts, state, io, allocator, arg)) |oid| {
                        try shallow_oids.put(oid, {});
                        continue;
                    }
                    if (try processDeepen(arg)) |val| {
                        self.depth = val;
                        continue;
                    }
                    if (try processDeepenSince(arg)) |val| {
                        self.deepen_since = val;
                        self.deepen_rev_list = true;
                        continue;
                    }
                    if (try processDeepenNot(repo_kind, repo_opts, state, io, arg)) |oid| {
                        try deepen_not.put(oid, {});
                        self.deepen_rev_list = true;
                        continue;
                    }
                    if (std.mem.eql(u8, arg, "deepen-relative")) {
                        self.deepen_relative = true;
                        continue;
                    }

                    if (self.allow_filter and std.mem.startsWith(u8, arg, "filter ")) {
                        if (self.filter_options != .none) return error.FilterAlreadySet;
                        self.filter_options = parseFilterSpec(self.arena.allocator(), arg["filter ".len..]) catch
                            return error.InvalidFilterSpec;
                        continue;
                    }

                    if (self.allow_sideband_all and std.mem.eql(u8, arg, "sideband-all")) {
                        self.writer_use_sideband = true;
                        continue;
                    }

                    if (self.allow_packfile_uris) {
                        if (std.mem.startsWith(u8, arg, "packfile-uris ")) {
                            if (self.uri_protocols.items.len != 0) {
                                try writePktError(writer, self.writer_use_sideband, "multiple packfile-uris lines forbidden", .{});
                                return error.ClientError;
                            }
                            var iter = std.mem.splitScalar(u8, arg["packfile-uris ".len..], ',');
                            while (iter.next()) |protocol| {
                                try self.uri_protocols.append(self.arena.allocator(), try self.arena.allocator().dupe(u8, protocol));
                            }
                            continue;
                        }
                    }

                    return error.UnexpectedLine;
                },
            }
        }

        if (self.uri_protocols.items.len != 0 and !self.writer_use_sideband) {
            self.uri_protocols.clearRetainingCapacity();
        }
    }

    fn sendAcks(
        self: *UploadPack,
        comptime repo_kind: rp.RepoKind,
        comptime repo_opts: rp.RepoOpts(repo_kind),
        state: rp.Repo(repo_kind, repo_opts).State(.read_only),
        io: std.Io,
        writer: *std.Io.Writer,
        allocator: std.mem.Allocator,
        have_obj: *const std.ArrayList([hash.hexLen(repo_opts.hash)]u8),
        want_obj: *const std.ArrayList([hash.hexLen(repo_opts.hash)]u8),
    ) !bool {
        try writePktResponse(writer, self.writer_use_sideband, "acknowledgments\n", .{});

        if (have_obj.items.len == 0) {
            try writePktResponse(writer, self.writer_use_sideband, "NAK\n", .{});
        }

        for (have_obj.items) |*ack| {
            try writePktResponse(writer, self.writer_use_sideband, "ACK {s}\n", .{ack});
        }

        if (!self.wait_for_done and try allWantsReachable(repo_kind, repo_opts, state, io, allocator, have_obj, want_obj)) {
            try writePktResponse(writer, self.writer_use_sideband, "ready\n", .{});
            return true;
        }

        return false;
    }

    fn processHavesAndSendAcks(
        self: *UploadPack,
        comptime repo_kind: rp.RepoKind,
        comptime repo_opts: rp.RepoOpts(repo_kind),
        state: rp.Repo(repo_kind, repo_opts).State(.read_only),
        io: std.Io,
        writer: *std.Io.Writer,
        allocator: std.mem.Allocator,
        have_obj: *const std.ArrayList([hash.hexLen(repo_opts.hash)]u8),
        want_obj: *const std.ArrayList([hash.hexLen(repo_opts.hash)]u8),
    ) !bool {
        if (self.done) {
            return true;
        } else if (try self.sendAcks(repo_kind, repo_opts, state, io, writer, allocator, have_obj, want_obj)) {
            try pkt.writePktDelim(writer);
            return true;
        } else {
            try pkt.writePktFlush(writer);
            return false;
        }
    }

    fn sendWantedRefInfo(self: *UploadPack, comptime hex_len: usize, writer: *std.Io.Writer, wanted_refs: *const std.StringHashMap([hex_len]u8)) !void {
        if (wanted_refs.count() == 0) return;

        try writePktResponse(writer, self.writer_use_sideband, "wanted-refs\n", .{});

        var it = wanted_refs.iterator();
        while (it.next()) |entry| {
            try writePktResponse(writer, self.writer_use_sideband, "{s} {s}\n", .{
                entry.value_ptr,
                entry.key_ptr.*,
            });
        }

        try pkt.writePktDelim(writer);
    }

    fn sendShallowInfo(
        self: *UploadPack,
        comptime hex_len: usize,
        writer: *std.Io.Writer,
        comptime repo_kind: rp.RepoKind,
        comptime repo_opts: rp.RepoOpts(repo_kind),
        state: rp.Repo(repo_kind, repo_opts).State(.read_only),
        io: std.Io,
        allocator: std.mem.Allocator,
        our_refs: *std.AutoHashMap([hash.hexLen(repo_opts.hash)]u8, void),
        shallow_oids: *const std.AutoHashMap([hash.hexLen(repo_opts.hash)]u8, void),
        deepen_not: *const std.AutoHashMap([hash.hexLen(repo_opts.hash)]u8, void),
        want_obj: *std.ArrayList([hex_len]u8),
    ) !void {
        if (self.depth == 0 and !self.deepen_rev_list and
            shallow_oids.count() == 0)
            return;

        try writePktResponse(writer, self.writer_use_sideband, "shallow-info\n", .{});

        _ = try self.sendShallowList(writer, repo_kind, repo_opts, state, io, allocator, our_refs, shallow_oids, deepen_not, want_obj);

        try pkt.writePktDelim(writer);
    }

    fn receiveNeeds(
        self: *UploadPack,
        writer: *std.Io.Writer,
        comptime repo_kind: rp.RepoKind,
        comptime repo_opts: rp.RepoOpts(repo_kind),
        state: rp.Repo(repo_kind, repo_opts).State(.read_only),
        io: std.Io,
        allocator: std.mem.Allocator,
        our_refs: *std.AutoHashMap([hash.hexLen(repo_opts.hash)]u8, void),
        stdin_reader: *std.Io.Reader,
        shallow_oids: *std.AutoHashMap([hash.hexLen(repo_opts.hash)]u8, void),
        deepen_not: *std.AutoHashMap([hash.hexLen(repo_opts.hash)]u8, void),
        want_obj: *std.ArrayList([hash.hexLen(repo_opts.hash)]u8),
    ) !void {
        const hex_len = comptime hash.hexLen(repo_opts.hash);
        var wanted_oids = std.AutoHashMap([hex_len]u8, void).init(allocator);
        defer wanted_oids.deinit();
        var line_buf: [pkt.LARGE_PACKET_MAX]u8 = undefined;

        while (true) {
            const line = try pkt.readPktLine(stdin_reader, &line_buf) orelse break;

            if (try processShallow(repo_kind, repo_opts, state, io, allocator, line)) |oid| {
                try shallow_oids.put(oid, {});
                continue;
            }
            if (try processDeepen(line)) |val| {
                self.depth = val;
                continue;
            }
            if (try processDeepenSince(line)) |val| {
                self.deepen_since = val;
                self.deepen_rev_list = true;
                continue;
            }
            if (try processDeepenNot(repo_kind, repo_opts, state, io, line)) |oid| {
                try deepen_not.put(oid, {});
                self.deepen_rev_list = true;
                continue;
            }

            if (std.mem.startsWith(u8, line, "filter ")) {
                if (!self.filter_capability_requested) return error.FilterNotNegotiated;
                if (self.filter_options != .none) return error.FilterAlreadySet;
                self.filter_options = parseFilterSpec(self.arena.allocator(), line["filter ".len..]) catch
                    return error.InvalidFilterSpec;
                continue;
            }

            if (!std.mem.startsWith(u8, line, "want ")) return error.ProtocolErrorExpectedOid;

            // v1 want line: "want <hex_oid>[ <features>]"
            const after_want = line["want ".len..];
            if (after_want.len < hex_len) return error.ProtocolErrorExpectedOid;
            const oid_bytes = after_want[0..hex_len].*;
            const features = after_want[hex_len..];

            if (common.hasFeature(features, "deepen-relative")) {
                self.deepen_relative = true;
            }
            if (common.hasFeature(features, "multi_ack_detailed")) {
                self.multi_ack = .multi_ack_detailed;
            } else if (common.hasFeature(features, "multi_ack")) {
                self.multi_ack = .multi_ack;
            }
            if (common.hasFeature(features, "no-done")) {
                self.no_done = true;
            }
            if (common.hasFeature(features, "side-band-64k") or
                common.hasFeature(features, "side-band"))
            {
                self.use_sideband = true;
            }
            if (self.allow_filter and common.hasFeature(features, "filter")) {
                self.filter_capability_requested = true;
            }

            if (!try objectExists(repo_kind, repo_opts, state, io, allocator, &oid_bytes)) {
                try writePktError(writer, self.writer_use_sideband, "upload-pack: not our ref {s}", .{&oid_bytes});
                return error.ClientError;
            }
            if (!wanted_oids.contains(oid_bytes)) {
                try wanted_oids.put(oid_bytes, {});
                try want_obj.append(allocator, oid_bytes);
            }
        }

        if (self.depth == 0 and !self.deepen_rev_list and shallow_oids.count() == 0) return;

        if (try self.sendShallowList(writer, repo_kind, repo_opts, state, io, allocator, our_refs, shallow_oids, deepen_not, want_obj)) {
            try pkt.writePktFlush(writer);
        }
    }

    fn getCommonCommits(
        self: *UploadPack,
        comptime repo_kind: rp.RepoKind,
        comptime repo_opts: rp.RepoOpts(repo_kind),
        state: rp.Repo(repo_kind, repo_opts).State(.read_only),
        io: std.Io,
        writer: *std.Io.Writer,
        allocator: std.mem.Allocator,
        stdin_reader: *std.Io.Reader,
        have_obj: *std.ArrayList([hash.hexLen(repo_opts.hash)]u8),
        want_obj: *const std.ArrayList([hash.hexLen(repo_opts.hash)]u8),
        first_line: ?[]const u8,
    ) !void {
        const hex_len = comptime hash.hexLen(repo_opts.hash);
        var last_hex: [hex_len]u8 = undefined;
        var got_common: bool = false;
        var got_other: bool = false;
        var sent_ready: bool = false;
        var line_buf: [pkt.LARGE_PACKET_MAX]u8 = undefined;
        var pending_line = first_line;

        while (true) {
            const line: ?[]const u8 = if (pending_line) |pl| blk: {
                pending_line = null;
                @memcpy(line_buf[0..pl.len], pl);
                break :blk line_buf[0..pl.len];
            } else pkt.readPktLine(stdin_reader, &line_buf) catch |err| return err;

            const data = line orelse {
                if (self.multi_ack == .multi_ack_detailed and
                    got_common and !got_other and try allWantsReachable(repo_kind, repo_opts, state, io, allocator, have_obj, want_obj))
                {
                    sent_ready = true;
                    try pkt.writePktLineFmt(writer, "ACK {s} ready\n", .{&last_hex});
                }
                if (have_obj.items.len == 0 or self.multi_ack != .none) {
                    try pkt.writePktLineFmt(writer, "NAK\n", .{});
                }

                if (self.no_done and sent_ready) {
                    try pkt.writePktLineFmt(writer, "ACK {s}\n", .{&last_hex});
                    return;
                }
                if (self.is_stateless) return error.StatelessServiceDone;
                got_common = false;
                got_other = false;
                continue;
            };

            if (std.mem.startsWith(u8, data, "have ")) {
                const have_arg = data["have ".len..];
                if (have_arg.len < hex_len) return error.ProtocolErrorExpectedSha1;
                const have_hex = have_arg[0..hex_len];
                if (try appendIfExists(repo_kind, repo_opts, state, io, hex_len, allocator, have_hex, have_obj)) {
                    got_common = true;
                    last_hex = have_hex.*;
                    if (self.multi_ack == .multi_ack_detailed) {
                        try pkt.writePktLineFmt(writer, "ACK {s} common\n", .{&last_hex});
                    } else if (self.multi_ack != .none) {
                        try pkt.writePktLineFmt(writer, "ACK {s} continue\n", .{&last_hex});
                    } else if (have_obj.items.len == 1) {
                        try pkt.writePktLineFmt(writer, "ACK {s}\n", .{&last_hex});
                    }
                } else {
                    got_other = true;
                    if (self.multi_ack != .none and try allWantsReachable(repo_kind, repo_opts, state, io, allocator, have_obj, want_obj)) {
                        if (self.multi_ack == .multi_ack_detailed) {
                            sent_ready = true;
                            try pkt.writePktLineFmt(writer, "ACK {s} ready\n", .{have_hex});
                        } else {
                            try pkt.writePktLineFmt(writer, "ACK {s} continue\n", .{have_hex});
                        }
                    }
                }
                continue;
            }
            if (std.mem.eql(u8, data, "done")) {
                if (have_obj.items.len > 0) {
                    if (self.multi_ack != .none) {
                        try pkt.writePktLineFmt(writer, "ACK {s}\n", .{&last_hex});
                    }
                    return;
                }
                try pkt.writePktLineFmt(writer, "NAK\n", .{});
                return;
            }
            return error.ProtocolErrorExpectedSha1;
        }
    }
};

const AllowUor = packed struct(u8) {
    tip_sha1: bool = false,
    reachable_sha1: bool = false,
    any_sha1: bool = false,
    _padding: u5 = 0,
};
const infinite_depth: usize = std.math.maxInt(usize);

const MultiAck = enum(u8) { none = 0, multi_ack = 1, multi_ack_detailed = 2 };

const Symref = struct {
    name: []const u8,
    target: []const u8,
};

const FilterOptions = union(enum) {
    none,
    blob_none,
    blob_limit: usize,
    tree_depth: usize,
    sparse_oid: []const u8,
    object_type: []const u8,
    combine: std.ArrayList(FilterOptions),
};

fn parseFilterSpec(allocator: std.mem.Allocator, spec: []const u8) !FilterOptions {
    if (std.mem.eql(u8, spec, "blob:none")) {
        return .blob_none;
    } else if (std.mem.startsWith(u8, spec, "blob:limit=")) {
        const val = spec["blob:limit=".len..];
        return .{ .blob_limit = std.fmt.parseInt(usize, val, 10) catch return error.InvalidFilterSpec };
    } else if (std.mem.startsWith(u8, spec, "tree:")) {
        const val = spec["tree:".len..];
        return .{ .tree_depth = std.fmt.parseInt(usize, val, 10) catch return error.InvalidFilterSpec };
    } else if (std.mem.startsWith(u8, spec, "sparse:oid=")) {
        const val = spec["sparse:oid=".len..];
        return .{ .sparse_oid = try allocator.dupe(u8, val) };
    } else if (std.mem.startsWith(u8, spec, "object:type=")) {
        const val = spec["object:type=".len..];
        return .{ .object_type = try allocator.dupe(u8, val) };
    } else if (std.mem.startsWith(u8, spec, "combine:")) {
        const val = spec["combine:".len..];
        var subs: std.ArrayList(FilterOptions) = .empty;
        var iter = std.mem.splitScalar(u8, val, '+');
        while (iter.next()) |sub_spec| {
            const buf = try allocator.dupe(u8, sub_spec);
            const decoded = std.Uri.percentDecodeInPlace(buf);
            const sub = try parseFilterSpec(allocator, decoded);
            try subs.append(allocator, sub);
        }
        return .{ .combine = subs };
    } else {
        return error.InvalidFilterSpec;
    }
}

fn writePktResponse(writer: *std.Io.Writer, use_sideband: bool, comptime fmt: []const u8, args: anytype) std.Io.Writer.Error!void {
    if (use_sideband) {
        try pkt.writePktLineSBFmt(writer, 1, fmt, args);
    } else {
        try pkt.writePktLineFmt(writer, fmt, args);
    }
}

fn writePktError(writer: *std.Io.Writer, use_sideband: bool, comptime fmt: []const u8, args: anytype) std.Io.Writer.Error!void {
    if (use_sideband) {
        try pkt.writePktLineSBFmt(writer, 3, fmt, args);
    } else {
        var buf: [pkt.LARGE_PACKET_MAX]u8 = undefined;
        var fixed: std.Io.Writer = .fixed(&buf);
        try fixed.writeAll("ERR ");
        try fixed.print(fmt, args);
        try pkt.writePktLine(writer, fixed.buffered());
    }
}

fn lsRefs(
    writer: *std.Io.Writer,
    comptime repo_kind: rp.RepoKind,
    comptime repo_opts: rp.RepoOpts(repo_kind),
    state: rp.Repo(repo_kind, repo_opts).State(.read_only),
    io: std.Io,
    allocator: std.mem.Allocator,
    reader: *std.Io.Reader,
) !void {
    const hex_len = comptime hash.hexLen(repo_opts.hash);

    var should_peel = false;
    var should_symrefs = false;
    var should_unborn = false;
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();

    var prefixes: std.ArrayList([]const u8) = .empty;
    defer prefixes.deinit(arena.allocator());

    // parse args
    var line_buf: [pkt.LARGE_PACKET_MAX]u8 = undefined;
    while (true) {
        switch (try pkt.readPktLineEx(reader, &line_buf)) {
            .flush => break,
            .eof => return error.UnexpectedEof,
            .delim => return error.UnexpectedDelim,
            .response_end => return error.UnexpectedResponseEnd,
            .data => |arg| {
                if (std.mem.eql(u8, arg, "peel")) {
                    should_peel = true;
                } else if (std.mem.eql(u8, arg, "symrefs")) {
                    should_symrefs = true;
                } else if (std.mem.startsWith(u8, arg, "ref-prefix ")) {
                    if (prefixes.items.len < 65536) {
                        try prefixes.append(arena.allocator(), try arena.allocator().dupe(u8, arg["ref-prefix ".len..]));
                    }
                } else if (std.mem.eql(u8, arg, "unborn")) {
                    // allowed unless lsrefs.unborn is "ignore"
                    var config = try cfg.Config(repo_kind, repo_opts).init(state, io, allocator);
                    defer config.deinit();
                    if (config.sections.get("lsrefs")) |vars| {
                        if (vars.get("unborn")) |v| {
                            if (!std.mem.eql(u8, v, "ignore")) {
                                should_unborn = true;
                            }
                        } else {
                            should_unborn = true;
                        }
                    } else {
                        should_unborn = true;
                    }
                }
            },
        }
    }

    // too many prefixes; match all
    if (prefixes.items.len >= 65536) {
        prefixes.clearRetainingCapacity();
    }

    // head (possibly unborn)
    {
        var head_buf = [_]u8{0} ** rf.MAX_REF_CONTENT_SIZE;
        if (try rf.readHead(repo_kind, repo_opts, state, io, &head_buf)) |head_ref_or_oid| {
            switch (head_ref_or_oid) {
                .oid => |oid| {
                    if (refMatch(prefixes.items, "HEAD")) {
                        try sendLsRef(hex_len, writer, "HEAD", oid, should_peel, should_symrefs, null, repo_kind, repo_opts, state, io, allocator);
                    }
                },
                .ref => |ref| {
                    // symref: resolve to oid
                    if (refMatch(prefixes.items, "HEAD")) {
                        if (try rf.readRecur(repo_kind, repo_opts, state, io, .{ .ref = ref })) |*oid| {
                            var target_buf = [_]u8{0} ** rf.MAX_REF_CONTENT_SIZE;
                            const target = try ref.toPath(&target_buf);
                            try sendLsRef(hex_len, writer, "HEAD", oid, should_peel, should_symrefs, target, repo_kind, repo_opts, state, io, allocator);
                        } else if (should_unborn and should_symrefs) {
                            // unborn
                            var target_buf = [_]u8{0} ** rf.MAX_REF_CONTENT_SIZE;
                            const target = try ref.toPath(&target_buf);
                            try pkt.writePktLineFmt(writer, "unborn {s} symref-target:{s}\n", .{ "HEAD", target });
                        }
                    }
                },
            }
        }
    }

    // heads
    {
        var heads = try rf.RefIterator(repo_kind, repo_opts).init(state, io, allocator, .head);
        defer heads.deinit(io);
        while (try heads.next(io)) |ref| {
            var path_buf = [_]u8{0} ** rf.MAX_REF_CONTENT_SIZE;
            const ref_path = try ref.toPath(&path_buf);
            if (!refMatch(prefixes.items, ref_path)) continue;
            if (try rf.readRecur(repo_kind, repo_opts, state, io, .{ .ref = ref })) |*oid| {
                try sendLsRef(hex_len, writer, ref_path, oid, should_peel, should_symrefs, null, repo_kind, repo_opts, state, io, allocator);
            }
        }
    }

    // tags
    {
        var tags = try rf.RefIterator(repo_kind, repo_opts).init(state, io, allocator, .tag);
        defer tags.deinit(io);
        while (try tags.next(io)) |ref| {
            var path_buf = [_]u8{0} ** rf.MAX_REF_CONTENT_SIZE;
            const ref_path = try ref.toPath(&path_buf);
            if (!refMatch(prefixes.items, ref_path)) continue;
            if (try rf.readRecur(repo_kind, repo_opts, state, io, .{ .ref = ref })) |*oid| {
                try sendLsRef(hex_len, writer, ref_path, oid, should_peel, should_symrefs, null, repo_kind, repo_opts, state, io, allocator);
            }
        }
    }

    try pkt.writePktFlush(writer);
}

fn refMatch(prefixes: []const []const u8, refname: []const u8) bool {
    if (prefixes.len == 0) return true;
    for (prefixes) |prefix| {
        if (std.mem.startsWith(u8, refname, prefix)) return true;
    }
    return false;
}

fn sendLsRef(
    comptime hex_len: usize,
    writer: *std.Io.Writer,
    refname: []const u8,
    oid: *const [hex_len]u8,
    should_peel: bool,
    should_symrefs: bool,
    symref_target: ?[]const u8,
    comptime repo_kind: rp.RepoKind,
    comptime repo_opts: rp.RepoOpts(repo_kind),
    state: rp.Repo(repo_kind, repo_opts).State(.read_only),
    io: std.Io,
    allocator: std.mem.Allocator,
) !void {
    var buf: [pkt.LARGE_PACKET_MAX]u8 = undefined;
    var fixed: std.Io.Writer = .fixed(&buf);
    try fixed.print("{s} {s}", .{ oid, refname });
    if (should_symrefs) {
        if (symref_target) |target| {
            try fixed.print(" symref-target:{s}", .{target});
        }
    }
    if (should_peel) {
        var peeled = oid.*;
        if (try peelToNonTag(repo_kind, repo_opts, state, io, allocator, &peeled)) {
            try fixed.print(" peeled:{s}", .{&peeled});
        }
    }
    try fixed.print("\n", .{});
    try pkt.writePktLine(writer, fixed.buffered());
}

fn objectInfo(
    writer: *std.Io.Writer,
    comptime repo_kind: rp.RepoKind,
    comptime repo_opts: rp.RepoOpts(repo_kind),
    state: rp.Repo(repo_kind, repo_opts).State(.read_only),
    io: std.Io,
    allocator: std.mem.Allocator,
    reader: *std.Io.Reader,
) !void {
    const hex_len = comptime hash.hexLen(repo_opts.hash);

    var want_size = false;

    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();

    var oid_strs: std.ArrayList([]const u8) = .empty;
    defer oid_strs.deinit(arena.allocator());

    var line_buf: [pkt.LARGE_PACKET_MAX]u8 = undefined;
    while (true) {
        switch (try pkt.readPktLineEx(reader, &line_buf)) {
            .flush => break,
            .eof => return error.UnexpectedEof,
            .delim => return error.UnexpectedDelim,
            .response_end => return error.UnexpectedResponseEnd,
            .data => |line| {
                if (std.mem.eql(u8, line, "size")) {
                    want_size = true;
                } else if (std.mem.startsWith(u8, line, "oid ")) {
                    try oid_strs.append(arena.allocator(), try arena.allocator().dupe(u8, line["oid ".len..]));
                } else {
                    try pkt.writePktLineFmt(writer, "ERR object-info: unexpected line: '{s}'", .{line});
                }
            },
        }
    }

    if (oid_strs.items.len == 0) return;

    if (want_size) {
        try pkt.writePktLineFmt(writer, "size", .{});
    }

    for (oid_strs.items) |oid_str| {
        if (oid_str.len != hex_len) {
            try pkt.writePktLineFmt(writer, "ERR object-info: protocol error, expected to get oid, not '{s}'", .{oid_str});
            continue;
        }

        if (want_size) {
            var obj_rdr = obj.ObjectReader(repo_kind, repo_opts).init(state, io, allocator, oid_str[0..hex_len]) catch |err| switch (err) {
                error.ObjectNotFound => {
                    try pkt.writePktLineFmt(writer, "{s} ", .{oid_str});
                    continue;
                },
                else => |e| return e,
            };
            defer obj_rdr.deinit();
            try pkt.writePktLineFmt(writer, "{s} {}", .{ oid_str, obj_rdr.header().size });
        } else {
            try pkt.writePktLineFmt(writer, "{s}", .{oid_str});
        }
    }

    try pkt.writePktFlush(writer);
}

fn uploadPackV2(
    writer: *std.Io.Writer,
    comptime repo_kind: rp.RepoKind,
    comptime repo_opts: rp.RepoOpts(repo_kind),
    state: rp.Repo(repo_kind, repo_opts).State(.read_only),
    io: std.Io,
    allocator: std.mem.Allocator,
    reader: *std.Io.Reader,
) !void {
    const hex_len = comptime hash.hexLen(repo_opts.hash);
    var upload_pack = UploadPack.init(allocator);
    defer upload_pack.deinit();
    var our_refs = std.AutoHashMap([hex_len]u8, void).init(allocator);
    defer our_refs.deinit();
    var shallow_oids = std.AutoHashMap([hex_len]u8, void).init(allocator);
    defer shallow_oids.deinit();
    var deepen_not = std.AutoHashMap([hex_len]u8, void).init(allocator);
    defer deepen_not.deinit();
    var wanted_refs = std.StringHashMap([hex_len]u8).init(allocator);
    defer wanted_refs.deinit();
    var want_obj: std.ArrayList([hex_len]u8) = .empty;
    defer want_obj.deinit(allocator);
    var have_obj: std.ArrayList([hex_len]u8) = .empty;
    defer have_obj.deinit(allocator);

    upload_pack.use_sideband = true;
    try upload_pack.readConfig(repo_kind, repo_opts, state, io, allocator);

    const UploadPackV2State = enum { process_args, send_acks, send_pack };

    upload_pack: switch (UploadPackV2State.process_args) {
        .process_args => {
            try upload_pack.processArgs(repo_kind, repo_opts, state, io, writer, reader, allocator, &shallow_oids, &deepen_not, &wanted_refs, &want_obj, &have_obj);

            if (want_obj.items.len == 0 and !upload_pack.wait_for_done) {
                break :upload_pack;
            } else if (upload_pack.seen_haves) {
                continue :upload_pack .send_acks;
            } else {
                continue :upload_pack .send_pack;
            }
        },
        .send_acks => {
            if (try upload_pack.processHavesAndSendAcks(repo_kind, repo_opts, state, io, writer, allocator, &have_obj, &want_obj))
                continue :upload_pack .send_pack
            else
                break :upload_pack;
        },
        .send_pack => {
            try upload_pack.sendWantedRefInfo(hex_len, writer, &wanted_refs);
            try upload_pack.sendShallowInfo(hex_len, writer, repo_kind, repo_opts, state, io, allocator, &our_refs, &shallow_oids, &deepen_not, &want_obj);

            try writePktResponse(writer, upload_pack.writer_use_sideband, "packfile\n", .{});
            try writePack(repo_kind, repo_opts, state, io, allocator, writer, &want_obj);
            break :upload_pack;
        },
    }
}

const V2Config = struct {
    advertise_sid: bool = false,
    advertise_object_info: bool = false,
    advertise_bundle_uris: bool = false,
    advertise_unborn: bool = true,
    client_hash_algo: hash.HashKind = .sha1,
    allow_filter: bool = false,
    allow_ref_in_want: bool = false,
    allow_sideband_all: bool = false,
    allow_packfile_uris: bool = false,
};

const ProtocolCapability = enum {
    agent,
    ls_refs,
    fetch,
    server_option,
    object_format,
    session_id,
    object_info,
    bundle_uri,

    const all = [_]ProtocolCapability{
        .agent,
        .ls_refs,
        .fetch,
        .server_option,
        .object_format,
        .session_id,
        .object_info,
        .bundle_uri,
    };

    fn name(self: ProtocolCapability) []const u8 {
        return switch (self) {
            .agent => "agent",
            .ls_refs => "ls-refs",
            .fetch => "fetch",
            .server_option => "server-option",
            .object_format => "object-format",
            .session_id => "session-id",
            .object_info => "object-info",
            .bundle_uri => "bundle-uri",
        };
    }

    fn advertise(self: ProtocolCapability, comptime hash_kind: hash.HashKind, value: *std.Io.Writer, v2_config: *const V2Config) std.Io.Writer.Error!bool {
        return switch (self) {
            .agent => {
                try value.writeAll("git/2.51.2");
                return true;
            },
            .ls_refs => {
                if (v2_config.advertise_unborn) {
                    try value.writeAll("unborn");
                }
                return true;
            },
            .fetch => {
                try value.writeAll("shallow wait-for-done");

                if (v2_config.allow_filter) {
                    try value.writeAll(" filter");
                }

                if (v2_config.allow_ref_in_want) {
                    try value.writeAll(" ref-in-want");
                }

                if (v2_config.allow_sideband_all) {
                    try value.writeAll(" sideband-all");
                }

                if (v2_config.allow_packfile_uris) {
                    try value.writeAll(" packfile-uris");
                }

                return true;
            },
            .server_option => true,
            .object_format => {
                try value.writeAll(common.hashName(hash_kind));
                return true;
            },
            .session_id => v2_config.advertise_sid,
            .object_info => v2_config.advertise_object_info,
            .bundle_uri => v2_config.advertise_bundle_uris,
        };
    }

    fn parse(comptime hash_kind: hash.HashKind, key: []const u8, v2_config: *const V2Config) !?ProtocolCapability {
        if (std.mem.startsWith(u8, key, "command=")) {
            const rest = key["command=".len..];

            const cap, const value = getCapability(rest) orelse
                return error.InvalidCommand;

            var discard_buf: [pkt.LARGE_PACKET_DATA_MAX]u8 = undefined;
            var discard: std.Io.Writer = .fixed(&discard_buf);
            if (!(try cap.advertise(hash_kind, &discard, v2_config)) or !cap.hasCommand() or value != null) return error.InvalidCommand;

            return cap;
        }

        return null;
    }

    fn hasCommand(self: ProtocolCapability) bool {
        return switch (self) {
            .ls_refs, .fetch, .object_info, .bundle_uri => true,
            .agent, .server_option, .object_format, .session_id => false,
        };
    }

    fn command(
        self: ProtocolCapability,
        writer: *std.Io.Writer,
        comptime repo_kind: rp.RepoKind,
        comptime repo_opts: rp.RepoOpts(repo_kind),
        state: rp.Repo(repo_kind, repo_opts).State(.read_only),
        io: std.Io,
        allocator: std.mem.Allocator,
        reader: *std.Io.Reader,
    ) !void {
        return switch (self) {
            .ls_refs => try lsRefs(writer, repo_kind, repo_opts, state, io, allocator, reader),
            .fetch => try uploadPackV2(writer, repo_kind, repo_opts, state, io, allocator, reader),
            .object_info => try objectInfo(writer, repo_kind, repo_opts, state, io, allocator, reader),
            .bundle_uri => {
                var line_buf: [pkt.LARGE_PACKET_MAX]u8 = undefined;
                while (true) {
                    switch (try pkt.readPktLineEx(reader, &line_buf)) {
                        .data => {},
                        .flush => break,
                        .eof => return error.UnexpectedEof,
                        .delim => return error.UnexpectedDelim,
                        .response_end => return error.UnexpectedResponseEnd,
                    }
                }

                var config = try cfg.Config(repo_kind, repo_opts).init(state, io, allocator);
                defer config.deinit();
                for (config.sections.keys(), config.sections.values()) |section, vars| {
                    if (std.mem.startsWith(u8, section, "bundle")) {
                        for (vars.keys(), vars.values()) |key, val| {
                            try pkt.writePktLineFmt(writer, "{s}.{s}={s}", .{ section, key, val });
                        }
                    }
                }
                try pkt.writePktFlush(writer);
            },
            .agent, .server_option, .object_format, .session_id => unreachable,
        };
    }

    fn receive(self: ProtocolCapability, value: ?[]const u8, v2_config: *V2Config) !void {
        switch (self) {
            .object_format => {
                const algo_name = value orelse return error.MissingObjectFormatArg;
                if (std.mem.eql(u8, algo_name, "sha1")) {
                    v2_config.client_hash_algo = .sha1;
                } else if (std.mem.eql(u8, algo_name, "sha256")) {
                    v2_config.client_hash_algo = .sha256;
                } else return error.UnknownObjectFormat;
            },
            .session_id => {},
            .agent, .ls_refs, .fetch, .server_option, .object_info, .bundle_uri => {},
        }
    }
};

fn getCapability(key: []const u8) ?struct { ProtocolCapability, ?[]const u8 } {
    for (ProtocolCapability.all) |cap| {
        const cap_name = cap.name();
        if (std.mem.startsWith(u8, key, cap_name)) {
            const rest = key[cap_name.len..];
            if (rest.len == 0) {
                return .{ cap, null };
            }
            if (rest[0] == '=') {
                return .{ cap, rest[1..] };
            }
        }
    }

    return null;
}

fn receiveClientCapability(comptime hash_kind: hash.HashKind, key: []const u8, v2_config: *V2Config) !bool {
    const cap, const value = getCapability(key) orelse return false;

    var discard_buf: [pkt.LARGE_PACKET_DATA_MAX]u8 = undefined;
    var discard: std.Io.Writer = .fixed(&discard_buf);
    if (cap.hasCommand() or !(try cap.advertise(hash_kind, &discard, v2_config))) return false;

    try cap.receive(value, v2_config);

    return true;
}

fn processRequest(
    writer: *std.Io.Writer,
    comptime repo_kind: rp.RepoKind,
    comptime repo_opts: rp.RepoOpts(repo_kind),
    state: rp.Repo(repo_kind, repo_opts).State(.read_only),
    io: std.Io,
    allocator: std.mem.Allocator,
    v2_config: *V2Config,
    stdin_reader: *std.Io.Reader,
) !bool {
    var done = false;
    var seen_capability_or_command = false;
    var command_maybe: ?ProtocolCapability = null;
    var line_buf: [pkt.LARGE_PACKET_MAX]u8 = undefined;

    while (!done) {
        switch (try pkt.readPktLineEx(stdin_reader, &line_buf)) {
            .eof => {
                if (!seen_capability_or_command) return true;
                return error.UnexpectedEof;
            },
            .data => |line| {
                if (try ProtocolCapability.parse(repo_opts.hash, line, v2_config)) |cmd| {
                    if (command_maybe != null) return error.DuplicateCommand;
                    command_maybe = cmd;
                    seen_capability_or_command = true;
                } else if (try receiveClientCapability(repo_opts.hash, line, v2_config)) {
                    seen_capability_or_command = true;
                } else {
                    return error.UnknownCapability;
                }
            },
            .flush => {
                if (!seen_capability_or_command) return true;
                done = true;
            },
            .delim => {
                done = true;
            },
            .response_end => return error.UnexpectedResponseEnd,
        }
    }

    const cmd = command_maybe orelse return error.NoCommandRequested;

    if (v2_config.client_hash_algo != repo_opts.hash) return error.ObjectFormatMismatch;

    try cmd.command(writer, repo_kind, repo_opts, state, io, allocator, stdin_reader);

    return false;
}

fn protocolV2AdvertiseCapabilities(writer: *std.Io.Writer, comptime hash_kind: hash.HashKind, v2_config: *const V2Config) !void {
    var cap_buf: [pkt.LARGE_PACKET_DATA_MAX]u8 = undefined;
    var val_buf: [pkt.LARGE_PACKET_DATA_MAX]u8 = undefined;

    try pkt.writePktLineFmt(writer, "version 2\n", .{});

    for (ProtocolCapability.all) |cap| {
        var value: std.Io.Writer = .fixed(&val_buf);
        if (try cap.advertise(hash_kind, &value, v2_config)) {
            var capability: std.Io.Writer = .fixed(&cap_buf);
            try capability.writeAll(cap.name());
            const val = value.buffered();
            if (val.len > 0) {
                try capability.writeByte('=');
                try capability.writeAll(val);
            }
            try capability.writeByte('\n');
            try pkt.writePktLine(writer, capability.buffered());
        }
    }

    try pkt.writePktFlush(writer);
}

fn peelToNonTag(
    comptime repo_kind: rp.RepoKind,
    comptime repo_opts: rp.RepoOpts(repo_kind),
    state: rp.Repo(repo_kind, repo_opts).State(.read_only),
    io: std.Io,
    allocator: std.mem.Allocator,
    oid: *[hash.hexLen(repo_opts.hash)]u8,
) !bool {
    const orig = oid.*;
    for (0..64) |_| {
        var object = obj.Object(repo_kind, repo_opts, .full).init(state, io, allocator, oid) catch |err| switch (err) {
            error.ObjectNotFound => return false,
            else => |e| return e,
        };
        defer object.deinit();
        switch (object.content) {
            .tag => |tag| oid.* = tag.target,
            else => return !std.mem.eql(u8, &orig, oid),
        }
    } else return error.TagChainTooLong;
}

fn getReachableShallows(
    comptime repo_kind: rp.RepoKind,
    comptime repo_opts: rp.RepoOpts(repo_kind),
    state: rp.Repo(repo_kind, repo_opts).State(.read_only),
    io: std.Io,
    allocator: std.mem.Allocator,
    shallow_oids: *const std.AutoHashMap([hash.hexLen(repo_opts.hash)]u8, void),
    our_refs: *std.AutoHashMap([hash.hexLen(repo_opts.hash)]u8, void),
    reachable: *std.ArrayList([hash.hexLen(repo_opts.hash)]u8),
) !void {
    const hex_len = comptime hash.hexLen(repo_opts.hash);

    // shallows already in our refs are immediately reachable
    var remaining = std.AutoHashMap([hex_len]u8, void).init(allocator);
    defer remaining.deinit();

    {
        var it = shallow_oids.keyIterator();
        while (it.next()) |oid| {
            if (our_refs.contains(oid.*)) {
                try reachable.append(allocator, oid.*);
                continue;
            }
            try remaining.put(oid.*, {});
        }
    }

    if (remaining.count() == 0) return;

    // walk from our ref tips to find remaining reachable shallows
    var obj_iter = try obj.ObjectIterator(repo_kind, repo_opts, .raw).init(state, io, allocator, .{ .kind = .commit });
    defer obj_iter.deinit();

    {
        var it = our_refs.keyIterator();
        while (it.next()) |oid| {
            try obj_iter.include(oid);
        }
    }

    while (try obj_iter.next()) |object| {
        if (remaining.contains(object.oid)) {
            try reachable.append(allocator, object.oid);
            _ = remaining.remove(object.oid);
            if (remaining.count() == 0) return;
        }
    }
}

fn objectExists(
    comptime repo_kind: rp.RepoKind,
    comptime repo_opts: rp.RepoOpts(repo_kind),
    state: rp.Repo(repo_kind, repo_opts).State(.read_only),
    io: std.Io,
    allocator: std.mem.Allocator,
    oid: *const [hash.hexLen(repo_opts.hash)]u8,
) !bool {
    var obj_rdr = obj.ObjectReader(repo_kind, repo_opts).init(state, io, allocator, oid) catch |err| switch (err) {
        error.ObjectNotFound => return false,
        else => |e| return e,
    };
    obj_rdr.deinit();
    return true;
}

fn processShallow(
    comptime repo_kind: rp.RepoKind,
    comptime repo_opts: rp.RepoOpts(repo_kind),
    state: rp.Repo(repo_kind, repo_opts).State(.read_only),
    io: std.Io,
    allocator: std.mem.Allocator,
    line: []const u8,
) !?[hash.hexLen(repo_opts.hash)]u8 {
    const hex_len = comptime hash.hexLen(repo_opts.hash);
    if (std.mem.startsWith(u8, line, "shallow ")) {
        const arg = line["shallow ".len..];
        if (arg.len < hex_len) return error.InvalidShallowLine;
        var obj_rdr = obj.ObjectReader(repo_kind, repo_opts).init(state, io, allocator, arg[0..hex_len]) catch |err| switch (err) {
            error.ObjectNotFound => return null,
            else => |e| return e,
        };
        defer obj_rdr.deinit();
        if (obj_rdr.header().kind != .commit) return error.InvalidShallowObject;
        return arg[0..hex_len].*;
    }
    return null;
}

fn processDeepen(line: []const u8) !?usize {
    if (std.mem.startsWith(u8, line, "deepen ")) {
        const val = std.fmt.parseInt(usize, line["deepen ".len..], 10) catch
            return error.InvalidDeepen;
        if (val == 0) return error.InvalidDeepen;
        return val;
    }
    return null;
}

fn processDeepenSince(line: []const u8) !?u64 {
    if (std.mem.startsWith(u8, line, "deepen-since ")) {
        const val = std.fmt.parseInt(u64, line["deepen-since ".len..], 10) catch
            return error.InvalidDeepenSince;
        if (val == 0 or val == std.math.maxInt(u64)) return error.InvalidDeepenSince;
        return val;
    }
    return null;
}

fn processDeepenNot(
    comptime repo_kind: rp.RepoKind,
    comptime repo_opts: rp.RepoOpts(repo_kind),
    state: rp.Repo(repo_kind, repo_opts).State(.read_only),
    io: std.Io,
    line: []const u8,
) !?[hash.hexLen(repo_opts.hash)]u8 {
    if (std.mem.startsWith(u8, line, "deepen-not ")) {
        const arg = line["deepen-not ".len..];
        // resolve as full ref path, then branch, then tag
        const oid = if (rf.Ref.initFromPath(arg, null)) |ref|
            try rf.readRecur(repo_kind, repo_opts, state, io, .{ .ref = ref })
        else
            null;
        return oid orelse
            try rf.readRecur(repo_kind, repo_opts, state, io, .{ .ref = .{ .kind = .head, .name = arg } }) orelse
            try rf.readRecur(repo_kind, repo_opts, state, io, .{ .ref = .{ .kind = .tag, .name = arg } }) orelse
            return error.DeepenNotIsNotRef;
    }
    return null;
}

fn appendIfExists(
    comptime repo_kind: rp.RepoKind,
    comptime repo_opts: rp.RepoOpts(repo_kind),
    state: rp.Repo(repo_kind, repo_opts).State(.read_only),
    io: std.Io,
    comptime hex_len: usize,
    allocator: std.mem.Allocator,
    hex: *const [hex_len]u8,
    have_obj: *std.ArrayList([hex_len]u8),
) !bool {
    if (!try objectExists(repo_kind, repo_opts, state, io, allocator, hex)) return false;
    try have_obj.append(allocator, hex.*);
    return true;
}

fn allWantsReachable(
    comptime repo_kind: rp.RepoKind,
    comptime repo_opts: rp.RepoOpts(repo_kind),
    state: rp.Repo(repo_kind, repo_opts).State(.read_only),
    io: std.Io,
    allocator: std.mem.Allocator,
    have_obj: *const std.ArrayList([hash.hexLen(repo_opts.hash)]u8),
    want_obj: *const std.ArrayList([hash.hexLen(repo_opts.hash)]u8),
) !bool {
    if (have_obj.items.len == 0) return false;
    return allReachableFromHaves(repo_kind, repo_opts, state, io, allocator, have_obj, want_obj);
}

fn allReachableFromHaves(
    comptime repo_kind: rp.RepoKind,
    comptime repo_opts: rp.RepoOpts(repo_kind),
    state: rp.Repo(repo_kind, repo_opts).State(.read_only),
    io: std.Io,
    allocator: std.mem.Allocator,
    have_obj: *const std.ArrayList([hash.hexLen(repo_opts.hash)]u8),
    want_obj: *const std.ArrayList([hash.hexLen(repo_opts.hash)]u8),
) !bool {
    const hex_len = comptime hash.hexLen(repo_opts.hash);

    // build have set
    var have_oids = std.AutoHashMap([hex_len]u8, void).init(allocator);
    defer have_oids.deinit();
    for (have_obj.items) |*item| {
        try have_oids.put(item.*, {});
    }

    // check each want is reachable from a have
    for (want_obj.items) |*item| {
        if (have_oids.contains(item.*)) continue;

        // walk ancestors looking for a have
        var obj_iter = try obj.ObjectIterator(repo_kind, repo_opts, .raw).init(state, io, allocator, .{ .kind = .commit });
        defer obj_iter.deinit();
        try obj_iter.include(item);

        var found = false;
        while (try obj_iter.next()) |object| {
            defer object.deinit();
            if (have_oids.contains(object.oid)) {
                found = true;
                break;
            }
        }
        if (!found) return false;
    }
    return true;
}
