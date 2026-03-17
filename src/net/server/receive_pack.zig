const std = @import("std");
const common = @import("./common.zig");
const pkt = @import("./pkt.zig");

const rp = @import("../../repo.zig");
const obj = @import("../../object.zig");
const pack = @import("../../pack.zig");
const hash = @import("../../hash.zig");
const rf = @import("../../ref.zig");
const work = @import("../../workdir.zig");
const cfg = @import("../../config.zig");
const mrg = @import("../../merge.zig");

pub const Options = struct {
    protocol_version: common.ProtocolVersion = .v0,
    skip_connectivity_check: bool = false,
    advertise_refs: bool = false,
    is_stateless: bool = false,
};

pub fn run(
    comptime repo_kind: rp.RepoKind,
    comptime repo_opts: rp.RepoOpts(repo_kind),
    state: rp.Repo(repo_kind, repo_opts).State(.read_write),
    io: std.Io,
    allocator: std.mem.Allocator,
    reader: *std.Io.Reader,
    writer: *std.Io.Writer,
    options: Options,
) !void {
    var receive_pack = ReceivePack{};

    try receive_pack.readConfig(repo_kind, repo_opts, state.readOnly(), io, allocator);

    switch (options.protocol_version) {
        .v2 => {},
        .v1 => {
            if (options.advertise_refs or !options.is_stateless) {
                try pkt.writePktLineFmt(writer, "version 1\n", .{});
            }
        },
        .v0 => {},
    }

    if (options.advertise_refs or !options.is_stateless) {
        try receive_pack.advertiseRefs(repo_kind, repo_opts, state.readOnly(), io, allocator, writer);
    }
    if (options.advertise_refs) return;

    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();

    const ref_updates = try receive_pack.readRefUpdates(repo_opts.hash, &arena, reader);

    if (ref_updates.items.len != 0) {
        {
            const delete_only = for (ref_updates.items) |update| {
                if (!isNullOid(&update.new_oid)) break false;
            } else true;

            if (!delete_only) {
                var counting_buf: [repo_opts.buffer_size]u8 = undefined;
                var counting_reader = pack.CountingReader.init(reader, &counting_buf);
                var pack_reader = pack.PackReader.initStream(&counting_reader);
                defer pack_reader.deinit();

                var pack_iter = try pack.PackIterator(repo_kind, repo_opts).init(io, allocator, &pack_reader);

                try obj.copyFromPackIterator(repo_kind, repo_opts, state, io, allocator, &pack_iter, null);
            }
        }

        try receive_pack.executeRefUpdates(writer, repo_kind, repo_opts, state, io, allocator, ref_updates.items, options);

        if (receive_pack.report_status_v2) {
            var buf: std.ArrayList(u8) = .empty;
            defer buf.deinit(allocator);

            try pkt.bufPktLineFmt(&buf, allocator, "unpack {s}\n", .{"ok"});

            for (ref_updates.items) |update| {
                if (update.error_message) |err_msg| {
                    try pkt.bufPktLineFmt(&buf, allocator, "ng {s} {s}\n", .{ update.ref_name, err_msg });
                    continue;
                }

                try pkt.bufPktLineFmt(&buf, allocator, "ok {s}\n", .{update.ref_name});
            }
            try pkt.bufPktFlush(&buf, allocator);

            try pkt.sendSideband(writer, 1, buf.items);
        } else if (receive_pack.report_status) {
            var buf: std.ArrayList(u8) = .empty;
            defer buf.deinit(allocator);

            try pkt.bufPktLineFmt(&buf, allocator, "unpack {s}\n", .{"ok"});

            for (ref_updates.items) |update| {
                if (update.error_message) |err_msg| {
                    try pkt.bufPktLineFmt(&buf, allocator, "ng {s} {s}\n", .{ update.ref_name, err_msg });
                } else {
                    try pkt.bufPktLineFmt(&buf, allocator, "ok {s}\n", .{update.ref_name});
                }
            }
            try pkt.bufPktFlush(&buf, allocator);

            try pkt.sendSideband(writer, 1, buf.items);
        }
    }
    try pkt.writePktFlush(writer);
}

const ReceivePack = struct {
    // config
    prefer_ofs_delta: bool = true,
    is_bare: bool = false,
    deny_deletes: bool = false,
    deny_non_fast_forwards: bool = false,
    deny_current_branch: Deny = .unconfigured,
    deny_delete_current: Deny = .unconfigured,

    // protocol state
    sent_capabilities: bool = false,
    use_sideband: bool = false,
    report_status: bool = false,
    report_status_v2: bool = false,
    head_name: ?[]const u8 = null,

    fn readConfig(self: *ReceivePack, comptime repo_kind: rp.RepoKind, comptime repo_opts: rp.RepoOpts(repo_kind), state: rp.Repo(repo_kind, repo_opts).State(.read_only), io: std.Io, allocator: std.mem.Allocator) !void {
        var config = try cfg.Config(repo_kind, repo_opts).init(state, io, allocator);
        defer config.deinit();

        if (config.sections.get("receive")) |vars| {
            if (vars.get("denydeletes")) |v| {
                self.deny_deletes = common.parseBool(v);
            }
            if (vars.get("denynonfastforwards")) |v| {
                self.deny_non_fast_forwards = common.parseBool(v);
            }
            if (vars.get("denycurrentbranch")) |v| {
                self.deny_current_branch = Deny.parse(v);
            }
            if (vars.get("denydeletecurrent")) |v| {
                self.deny_delete_current = Deny.parse(v);
            }
        }
        if (config.sections.get("repack")) |vars| {
            if (vars.get("usedeltabaseoffset")) |v| {
                self.prefer_ofs_delta = common.parseBool(v);
            }
        }
        if (config.sections.get("core")) |vars| {
            if (vars.get("bare")) |v| {
                self.is_bare = common.parseBool(v);
            }
        }
    }

    fn advertiseRef(
        self: *ReceivePack,
        comptime repo_kind: rp.RepoKind,
        comptime repo_opts: rp.RepoOpts(repo_kind),
        writer: *std.Io.Writer,
        path: []const u8,
        oid: *const [hash.hexLen(repo_opts.hash)]u8,
    ) !void {
        if (self.sent_capabilities) {
            try pkt.writePktLineFmt(writer, "{s} {s}\n", .{ oid, path });
        } else {
            var line_buf: [pkt.LARGE_PACKET_MAX]u8 = undefined;
            var line: std.Io.Writer = .fixed(&line_buf);
            try line.print("{s} {s}", .{ oid, path });
            try line.writeByte(0);
            try line.writeAll("report-status report-status-v2 delete-refs side-band-64k quiet atomic");
            if (self.prefer_ofs_delta) {
                try line.writeAll(" ofs-delta");
            }
            try line.print(" object-format={s}\n", .{common.hashName(repo_opts.hash)});
            try pkt.writePktLine(writer, line.buffered());
            self.sent_capabilities = true;
        }
    }

    fn advertiseRefs(
        self: *ReceivePack,
        comptime repo_kind: rp.RepoKind,
        comptime repo_opts: rp.RepoOpts(repo_kind),
        state: rp.Repo(repo_kind, repo_opts).State(.read_only),
        io: std.Io,
        allocator: std.mem.Allocator,
        writer: *std.Io.Writer,
    ) !void {
        // head
        if (try rf.readHeadRecurMaybe(repo_kind, repo_opts, state, io)) |*head_oid| {
            try self.advertiseRef(repo_kind, repo_opts, writer, "HEAD", head_oid);
        }

        // heads
        {
            var heads = try rf.RefIterator(repo_kind, repo_opts).init(state, io, allocator, .head);
            defer heads.deinit(io);

            while (try heads.next(io)) |ref| {
                if (try rf.readRecur(repo_kind, repo_opts, state, io, .{ .ref = ref })) |*oid| {
                    var path_buf = [_]u8{0} ** rf.MAX_REF_CONTENT_SIZE;
                    const ref_path = try ref.toPath(&path_buf);
                    try self.advertiseRef(repo_kind, repo_opts, writer, ref_path, oid);
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
                    try self.advertiseRef(repo_kind, repo_opts, writer, ref_path, oid);
                }
            }
        }

        if (!self.sent_capabilities) {
            try self.advertiseRef(repo_kind, repo_opts, writer, "capabilities^{}", &[_]u8{'0'} ** hash.hexLen(repo_opts.hash));
        }

        try pkt.writePktFlush(writer);
    }

    fn readRefUpdates(
        self: *ReceivePack,
        comptime hash_kind: hash.HashKind,
        arena: *std.heap.ArenaAllocator,
        reader: *std.Io.Reader,
    ) !std.ArrayList(RefUpdate(hash_kind)) {
        const hex_len = comptime hash.hexLen(hash_kind);

        var ref_updates: std.ArrayList(RefUpdate(hash_kind)) = .empty;
        while (true) {
            var buf: [pkt.LARGE_PACKET_MAX]u8 = undefined;
            const line = try pkt.readPktLine(reader, &buf) orelse break;

            const null_pos = std.mem.indexOfScalar(u8, line, 0);
            const line_data = if (null_pos) |pos| line[0..pos] else line;

            if (null_pos) |pos| {
                if (pos < line.len) {
                    const features = line[pos + 1 ..];
                    if (common.hasFeature(features, "report-status")) {
                        self.report_status = true;
                    }
                    if (common.hasFeature(features, "report-status-v2")) {
                        self.report_status_v2 = true;
                    }
                    if (common.hasFeature(features, "side-band-64k")) {
                        self.use_sideband = true;
                    }
                    const obj_hash = common.getFeatureValue(features, "object-format") orelse "sha1";
                    const repo_hash_name = common.hashName(hash_kind);
                    if (!std.mem.eql(u8, repo_hash_name, obj_hash)) return error.UnsupportedObjectFormat;
                }
            }

            // parse "<old_oid> <new_oid> <refname>" and append
            {
                if (line_data.len < hex_len + 1 + hex_len + 1) return error.QueueRefUpdateError;

                const old_oid = line_data[0..hex_len].*;
                if (line_data[hex_len] != ' ') return error.QueueRefUpdateError;

                const new_oid = line_data[hex_len + 1 ..][0..hex_len].*;
                if (line_data[hex_len + 1 + hex_len] != ' ') return error.QueueRefUpdateError;

                const ref_data = line_data[hex_len + 1 + hex_len + 1 ..];

                try ref_updates.append(arena.allocator(), .{
                    .error_message = null,
                    .skip_update = false,
                    .old_oid = old_oid,
                    .new_oid = new_oid,
                    .ref_name = try arena.allocator().dupe(u8, ref_data),
                });
            }
        }

        if (!self.use_sideband) return error.SidebandProtocolNotSupported;

        return ref_updates;
    }

    fn executeRefUpdates(
        self: *ReceivePack,
        writer: *std.Io.Writer,
        comptime repo_kind: rp.RepoKind,
        comptime repo_opts: rp.RepoOpts(repo_kind),
        state: rp.Repo(repo_kind, repo_opts).State(.read_write),
        io: std.Io,
        allocator: std.mem.Allocator,
        ref_updates: []RefUpdate(repo_opts.hash),
        options: Options,
    ) !void {
        if (!options.skip_connectivity_check) {
            const all_connected = blk: {
                var obj_iter = try obj.ObjectIterator(repo_kind, repo_opts, .raw).init(
                    state.readOnly(),
                    io,
                    allocator,
                    .{ .kind = .all },
                );
                defer obj_iter.deinit();

                for (ref_updates) |*update| {
                    if (!isNullOid(&update.new_oid) and !update.skip_update) {
                        try obj_iter.include(&update.new_oid);
                    }
                }

                while (true) {
                    const maybe_obj = obj_iter.next() catch |err| switch (err) {
                        error.ObjectNotFound => break :blk false,
                        else => return err,
                    };
                    const next_obj = maybe_obj orelse break;
                    next_obj.deinit();
                }
                break :blk true;
            };

            if (!all_connected) {
                for (ref_updates) |*update| {
                    if (isNullOid(&update.new_oid)) continue;

                    const connected = per_update: {
                        var obj_iter = try obj.ObjectIterator(repo_kind, repo_opts, .raw).init(
                            state.readOnly(),
                            io,
                            allocator,
                            .{ .kind = .all },
                        );
                        defer obj_iter.deinit();

                        try obj_iter.include(&update.new_oid);

                        while (true) {
                            const maybe_obj = obj_iter.next() catch |err| switch (err) {
                                error.ObjectNotFound => break :per_update false,
                                else => return err,
                            };
                            const next_obj = maybe_obj orelse break;
                            next_obj.deinit();
                        }
                        break :per_update true;
                    };

                    if (!connected) {
                        update.error_message = "missing necessary objects";
                    }
                }
            }
        }

        // skip if all ref updates already have errors
        {
            for (ref_updates) |update| {
                if (update.error_message == null) break;
            } else return;
        }

        // detect conflicting symref updates
        {
            var ref_list = std.StringHashMap(usize).init(allocator);
            defer ref_list.deinit();

            for (ref_updates, 0..) |*update, i| {
                try ref_list.put(update.ref_name, i);
            }

            for (ref_updates) |*update| {
                if (update.error_message == null) {
                    blk: {
                        var read_buf: [rf.MAX_REF_CONTENT_SIZE]u8 = undefined;
                        const ref_or_oid = rf.read(repo_kind, repo_opts, state.readOnly(), io, update.ref_name, &read_buf) catch |err| switch (err) {
                            error.RefNotFound => break :blk,
                            else => |e| return e,
                        };

                        // only symrefs can alias
                        const target_ref = switch (ref_or_oid orelse break :blk) {
                            .ref => |ref| ref,
                            .oid => break :blk,
                        };

                        var dst_path_buf: [rf.MAX_REF_CONTENT_SIZE]u8 = undefined;
                        const dst_name = try target_ref.toPath(&dst_path_buf);

                        const dst_index = ref_list.get(dst_name) orelse
                            break :blk;
                        const dst_update = &ref_updates[dst_index];

                        update.skip_update = true;

                        if (std.mem.eql(u8, &update.old_oid, &dst_update.old_oid) and
                            std.mem.eql(u8, &update.new_oid, &dst_update.new_oid)) break :blk;

                        dst_update.skip_update = true;

                        const abbrev: usize = 7;
                        try writeError(
                            writer,
                            "refusing inconsistent update between symref '{s}' ({s}..{s}) and its target '{s}' ({s}..{s})",
                            .{
                                update.ref_name,
                                update.old_oid[0..abbrev],
                                update.new_oid[0..abbrev],
                                dst_update.ref_name,
                                dst_update.old_oid[0..abbrev],
                                dst_update.new_oid[0..abbrev],
                            },
                        );

                        update.error_message = "inconsistent aliased update";
                        dst_update.error_message = update.error_message;
                    }
                }
            }
        }

        var head_read_buf: [rf.MAX_REF_CONTENT_SIZE]u8 = undefined;
        var head_path_buf: [rf.MAX_REF_CONTENT_SIZE]u8 = undefined;
        self.head_name = blk: {
            const ref_or_oid = rf.read(repo_kind, repo_opts, state.readOnly(), io, "HEAD", &head_read_buf) catch |err| switch (err) {
                error.RefNotFound => break :blk null,
                else => |e| return e,
            };
            const target_ref = switch (ref_or_oid orelse break :blk null) {
                .ref => |ref| ref,
                .oid => break :blk null,
            };
            break :blk try target_ref.toPath(&head_path_buf);
        };

        for (ref_updates) |*update| {
            if (update.error_message != null or update.skip_update) continue;

            update.error_message = try self.applyRefUpdate(writer, repo_kind, repo_opts, state, io, allocator, update);
        }
    }

    fn applyRefUpdate(
        self: *ReceivePack,
        writer: *std.Io.Writer,
        comptime repo_kind: rp.RepoKind,
        comptime repo_opts: rp.RepoOpts(repo_kind),
        state: rp.Repo(repo_kind, repo_opts).State(.read_write),
        io: std.Io,
        allocator: std.mem.Allocator,
        ref_update: *RefUpdate(repo_opts.hash),
    ) !?[]const u8 {
        const name = ref_update.ref_name;

        const name_after_refs = name["refs/".len..];
        if (!std.mem.startsWith(u8, name, "refs/") or
            !rf.validateName(name_after_refs) or
            (!isNullOid(&ref_update.new_oid) and std.mem.indexOfScalar(u8, name_after_refs, '/') == null))
        {
            try writeError(writer, "refusing to update funny ref '{s}' remotely", .{name});
            return "funny refname";
        }

        var should_update_worktree = false;

        if (self.head_name) |head_name| {
            if (std.mem.eql(u8, name, head_name)) {
                switch (self.deny_current_branch) {
                    .ignore => {},
                    .warn => try writeWarning(writer, "updating the current branch", .{}),
                    .refuse, .unconfigured => {
                        try writeError(writer, "refusing to update checked out branch: {s}", .{name});
                        if (self.deny_current_branch == .unconfigured) {
                            try writeError(writer, deny_current_branch_msg, .{});
                        }
                        return "branch is currently checked out";
                    },
                    .update_instead => {
                        should_update_worktree = true;
                    },
                }
            }
        }

        if (!isNullOid(&ref_update.new_oid)) {
            var object_or_err = obj.Object(repo_kind, repo_opts, .raw).init(state.readOnly(), io, allocator, &ref_update.new_oid);
            if (object_or_err) |*object| {
                object.deinit();
            } else |err| switch (err) {
                error.ObjectNotFound => return "bad pack",
                else => |e| return e,
            }
        }

        if (!isNullOid(&ref_update.old_oid) and isNullOid(&ref_update.new_oid)) {
            if (self.deny_deletes and std.mem.startsWith(u8, name, "refs/heads/")) {
                try writeError(writer, "denying ref deletion for {s}", .{name});
                return "deletion prohibited";
            }

            if (self.head_name) |head_name| {
                if (std.mem.eql(u8, name, head_name)) {
                    switch (self.deny_delete_current) {
                        .ignore => {},
                        .warn => try writeWarning(writer, "deleting the current branch", .{}),
                        .refuse, .unconfigured, .update_instead => {
                            if (self.deny_delete_current == .unconfigured) {
                                try writeError(writer, deny_delete_current_msg, .{});
                            }
                            try writeError(writer, "refusing to delete the current branch: {s}", .{name});
                            return "deletion of the current branch prohibited";
                        },
                    }
                }
            }
        }

        if (self.deny_non_fast_forwards and !isNullOid(&ref_update.new_oid) and
            !isNullOid(&ref_update.old_oid) and
            std.mem.startsWith(u8, name, "refs/heads/"))
        {
            const descendent = mrg.getDescendent(repo_kind, repo_opts, state.readOnly(), io, allocator, &ref_update.old_oid, &ref_update.new_oid) catch |err| switch (err) {
                error.DescendentNotFound => return "bad ref",
                else => |e| return e,
            };

            if (!std.mem.eql(u8, &descendent, &ref_update.new_oid)) {
                try writeError(writer, "denying non-fast-forward {s} (you should pull first)", .{name});
                return "non-fast-forward";
            }
        }

        if (should_update_worktree) {
            if (self.is_bare) return "denyCurrentBranch = updateInstead needs a worktree";

            var res = try work.Switch(repo_kind, repo_opts).init(state, io, allocator, .{ .kind = .reset, .target = .{ .oid = &ref_update.new_oid } });
            defer res.deinit();
        }

        if (isNullOid(&ref_update.new_oid)) {
            try rf.remove(repo_kind, repo_opts, state, io, name);
        } else {
            try rf.write(repo_kind, repo_opts, state, io, name, .{ .oid = &ref_update.new_oid });
        }

        return null;
    }
};

const Deny = enum {
    unconfigured,
    ignore,
    warn,
    refuse,
    update_instead,

    fn parse(value: []const u8) Deny {
        if (std.ascii.eqlIgnoreCase(value, "ignore")) return .ignore;
        if (std.ascii.eqlIgnoreCase(value, "warn")) return .warn;
        if (std.ascii.eqlIgnoreCase(value, "refuse")) return .refuse;
        if (std.ascii.eqlIgnoreCase(value, "updateinstead")) return .update_instead;
        if (common.parseBool(value)) return .refuse;
        return .ignore;
    }
};

fn writeMessage(writer: *std.Io.Writer, comptime prefix: [:0]const u8, comptime err: [:0]const u8, params: anytype) !void {
    var buffer = [_]u8{0} ** 4096;
    var fixed: std.Io.Writer = .fixed(&buffer);

    try fixed.print(prefix ++ err ++ "\n", params);

    const msg = fixed.buffered();
    try pkt.sendSideband(writer, 2, msg);
}

fn writeWarning(writer: *std.Io.Writer, comptime err: [:0]const u8, params: anytype) !void {
    try writeMessage(writer, "warning: ", err, params);
}

fn writeError(writer: *std.Io.Writer, comptime err: [:0]const u8, params: anytype) !void {
    try writeMessage(writer, "error: ", err, params);
}

fn RefUpdate(comptime hash_kind: hash.HashKind) type {
    const hex_len = hash.hexLen(hash_kind);
    return struct {
        error_message: ?[]const u8,
        skip_update: bool,
        old_oid: [hex_len]u8,
        new_oid: [hex_len]u8,
        ref_name: []u8,
    };
}

fn isNullOid(oid: []const u8) bool {
    for (oid) |b| {
        if (b != '0') return false;
    }
    return true;
}

const deny_current_branch_msg =
    \\By default, updating the current branch in a non-bare repository
    \\is denied, because it will make the index and work tree inconsistent
    \\with what you pushed, and will require 'git reset --hard' to match
    \\the work tree to HEAD.
    \\
    \\You can set the 'receive.denyCurrentBranch' configuration variable
    \\to 'ignore' or 'warn' in the remote repository to allow pushing into
    \\its current branch; however, this is not recommended unless you
    \\arranged to update its work tree to match what you pushed in some
    \\other way.
    \\
    \\To squelch this message and still keep the default behaviour, set
    \\'receive.denyCurrentBranch' configuration variable to 'refuse'."
;

const deny_delete_current_msg =
    \\By default, deleting the current branch is denied, because the next
    \\'git clone' won't result in any file checked out, causing confusion.
    \\
    \\You can set 'receive.denyDeleteCurrent' configuration variable to
    \\'warn' or 'ignore' in the remote repository to allow deleting the
    \\current branch, with or without a warning message.
    \\
    \\To squelch this message, you can set it to 'refuse'.
;
