const std = @import("std");
const rp = @import("./repo.zig");
const hash = @import("./hash.zig");
const bch = @import("./branch.zig");
const tg = @import("./tag.zig");
const mrg = @import("./merge.zig");
const cfg = @import("./config.zig");
const work = @import("./workdir.zig");
const rf = @import("./ref.zig");

/// the actions an undo record can name. a custom action is written under a
/// name of its own, which must not be one of these
pub const ActionKind = enum {
    patch,
    add,
    unadd,
    rm,
    commit,
    tag,
    branch,
    switch_dir,
    reset_add,
    merge,
    config,
    remote,
    clone,
    fetch,
    copy_objects,
    gc,
    undo,
    receive_pack,
    custom,
};

pub fn Action(comptime hash_kind: hash.HashKind) type {
    return union(ActionKind) {
        patch: struct {
            status: enum { on, off, all },
        },
        add: struct {
            paths: []const []const u8,
        },
        unadd: struct {
            paths: []const []const u8,
        },
        rm: struct {
            paths: []const []const u8,
            opts: work.RemoveOptions,
        },
        commit: Commit,
        tag: struct { action: tg.TagCommand },
        branch: struct { action: bch.BranchCommand },
        switch_dir: work.SwitchInput(hash_kind),
        reset_add: struct { target: rf.RefOrOid(hash_kind) },
        merge: struct {
            kind: mrg.MergeKind,
            action: mrg.MergeAction(hash_kind),
            oid: ?[hash.hexLen(hash_kind)]u8,
        },
        config: struct { action: cfg.ConfigCommand },
        remote: struct { action: cfg.ConfigCommand },
        clone: struct {
            url: []const u8,
        },
        fetch: struct {
            remote_name: []const u8,
        },
        copy_objects: struct {},
        gc: struct {},
        undo: Undo,
        receive_pack: struct {},
        custom: struct {
            action_kind: []const u8,
            payload: std.json.ObjectMap = .empty,
        },

        pub const Commit = struct {
            message: []const u8,
            oid: [hash.hexLen(hash_kind)]u8,

            pub fn init(message: []const u8, oid: [hash.hexLen(hash_kind)]u8, max_record_size: usize) !Commit {
                const overhead = @sizeOf(i64) + "commit".len + 1 + "{\"message\":\"\",\"oid\":\"\"}".len + oid.len;
                if (max_record_size < overhead) return error.UndoRecordTooLarge;
                const max_json_len = @min(2048, max_record_size - overhead);
                var end: usize = 0;
                var json_len: usize = 0;
                for (message) |byte| {
                    if (byte == '\n') break;
                    // count the bytes the json serializer will write.
                    const size: usize = switch (byte) {
                        '"', '\\', '\t', '\r', 0x08, 0x0c => 2,
                        0...7, 0x0b, 0x0e...0x1f => 6,
                        else => 1,
                    };
                    if (json_len + size > max_json_len) break;
                    json_len += size;
                    end += 1;
                }
                // avoid splitting a utf-8 character at the truncation boundary.
                if (end < message.len) {
                    while (end > 0 and message[end] & 0xc0 == 0x80) end -= 1;
                }
                const summary = message[0..end];
                if (!std.unicode.utf8ValidateSlice(summary)) return error.InvalidUtf8;
                return .{ .message = summary, .oid = oid };
            }
        };

        pub fn format(
            self: Action(hash_kind),
            comptime repo_opts: rp.RepoOpts(.xit),
            core: *rp.Repo(.xit, repo_opts).Core,
            allocator: std.mem.Allocator,
            writer: *std.Io.Writer,
        ) !void {
            var current = self;
            var parsed: ?std.json.Parsed(Action(hash_kind)) = null;
            defer if (parsed) |value| value.deinit();
            if (self == .undo) {
                const record_buffer = try allocator.alloc(u8, repo_opts.max_read_size);
                defer allocator.free(record_buffer);
                const target = try undoneTarget(repo_opts, core, allocator, self.undo, record_buffer);
                try writer.print("{s}: {} - ", .{ if (target.redo) "redo" else "undo", target.index });

                // describe the transaction the chain ended on
                const record = target.record orelse return writer.writeAll("(empty description)");
                const next = try parseAction(hash_kind, allocator, record) orelse return writer.print("{s} {s}", .{ record.action_kind, record.payload });
                parsed = next;
                current = next.value;
            }
            switch (current) {
                .patch => |patch_cmd| try writer.print("patch {s}", .{@tagName(patch_cmd.status)}),
                .add => |add_cmd| try formatPaths(writer, "add", add_cmd.paths),
                .unadd => |unadd_cmd| try formatPaths(writer, "unadd", unadd_cmd.paths),
                .rm => |rm_cmd| try formatPaths(writer, if (rm_cmd.opts.update_work_dir) "rm" else "untrack", rm_cmd.paths),
                inline .branch, .tag, .config, .remote => |command, tag| switch (command.action) {
                    .list => return error.NotImplemented,
                    .add => |input| try writer.print("{s} add {s}", .{ @tagName(tag), input.name }),
                    .remove => |input| try writer.print("{s} rm {s}", .{ @tagName(tag), input.name }),
                },
                .switch_dir => |switch_cmd| {
                    const target_name = if (switch_cmd.target) |target| target.name() else "HEAD";
                    const name = switch (switch_cmd.kind) {
                        .@"switch" => "switch",
                        .reset => if (switch_cmd.update_work_dir) "reset-dir" else "reset",
                    };
                    try writer.print("{s} {s}", .{ name, target_name });
                },
                .reset_add => |reset_add_cmd| try writer.print("reset-add {s}", .{reset_add_cmd.target.name()}),
                .commit => |commit_cmd| if (commit_cmd.message.len != 0)
                    try writer.print("commit -m \"{s}\"", .{commit_cmd.message})
                else
                    try writer.writeAll("commit"),
                .merge => |merge_cmd| {
                    try writer.writeAll(switch (merge_cmd.kind) {
                        .full => "merge",
                        .pick => "cherry-pick",
                    });
                    switch (merge_cmd.action) {
                        .new => |new| {
                            for (new.source) |source| try writer.print(" {s}", .{source.name()});
                        },
                        .cont => try writer.writeAll(" --continue"),
                    }
                },
                .clone => |clone_cmd| try writer.print("clone {s}", .{clone_cmd.url}),
                .fetch => |fetch_cmd| try writer.print("fetch {s}", .{fetch_cmd.remote_name}),
                .copy_objects => try writer.writeAll("copy objects"),
                .gc => try writer.writeAll("gc"),
                .undo => unreachable,
                .receive_pack => try writer.writeAll("receive-pack"),
                .custom => |custom| {
                    try writer.print("{s} ", .{custom.action_kind});
                    try std.json.Stringify.value(std.json.Value{ .object = custom.payload }, .{}, writer);
                },
            }
        }
    };
}

pub const Undo = struct {
    /// the transaction the undo restored
    index: u64,
    /// the last transaction it discarded, which a redo restores
    last_index: u64,
};

/// where a chain of undos ends
pub const Target = struct {
    /// the transaction the chain restored
    index: u64,
    /// true when an undo of an undo made it a redo, which restores the end of
    /// the range the inner one discarded
    redo: bool,
    /// the transaction at `index`, borrowing `record_buffer`
    record: ?Record,
};

/// follows the transactions an undo points at, until one that is not itself
/// an undo. a record that cannot be read or parsed ends the chain where it is
pub fn undoneTarget(
    comptime repo_opts: rp.RepoOpts(.xit),
    core: *rp.Repo(.xit, repo_opts).Core,
    allocator: std.mem.Allocator,
    undo: Undo,
    record_buffer: []u8,
) !Target {
    var target = Target{ .index = undo.index, .redo = false, .record = null };
    while (true) {
        const moment = try core.momentAt(target.index);
        target.record = try read(repo_opts, moment, record_buffer);
        const record = target.record orelse break;
        const parsed = try parseAction(repo_opts.hash, allocator, record) orelse break;
        defer parsed.deinit();
        if (parsed.value != .undo) break;
        target.redo = !target.redo;
        // undo follows the start of a range; redo restores its end.
        target.index = if (target.redo) parsed.value.undo.last_index else parsed.value.undo.index;
    }
    return target;
}

pub const Record = struct {
    timestamp: i64,
    action_kind: []const u8,
    payload: []const u8,

    // the action kind and payload borrow their bytes from data.
    pub fn decode(data: []const u8) !Record {
        if (data.len < 8) return error.InvalidUndoRecord;
        const kind_end = std.mem.indexOfScalarPos(u8, data, 8, 0) orelse return error.InvalidUndoRecord;
        if (kind_end == 8) return error.InvalidUndoRecord;
        return .{
            .timestamp = std.mem.readInt(i64, data[0..8], .big),
            .action_kind = data[8..kind_end],
            .payload = data[kind_end + 1 ..],
        };
    }
};

// the returned record borrows its action and payload from buffer.
pub fn read(
    comptime repo_opts: rp.RepoOpts(.xit),
    moment: rp.Repo(.xit, repo_opts).DB.HashMap(.read_only),
    buffer: []u8,
) !?Record {
    const cursor = try moment.getCursor(hash.hashInt(repo_opts.hash, "undo")) orelse return null;
    return try Record.decode(try cursor.readBytes(buffer));
}

pub fn write(
    comptime repo_opts: rp.RepoOpts(.xit),
    state: rp.Repo(.xit, repo_opts).State(.read_write),
    timestamp: i64,
    action: Action(repo_opts.hash),
) !void {
    const action_kind = switch (action) {
        .custom => |custom| blk: {
            if (!std.unicode.utf8ValidateSlice(custom.action_kind)) return error.InvalidUtf8;
            if (custom.action_kind.len == 0 or std.mem.indexOfScalar(u8, custom.action_kind, 0) != null) return error.InvalidUndoActionKind;
            // otherwise the record reads back as the action of that name
            if (std.meta.stringToEnum(ActionKind, custom.action_kind) != null) return error.ReservedUndoActionKind;
            try validateJsonUtf8(.{ .object = custom.payload });
            break :blk custom.action_kind;
        },
        else => @tagName(action),
    };
    var buffer: [repo_opts.max_read_size]u8 = undefined;
    var writer = std.Io.Writer.fixed(&buffer);
    writer.writeInt(i64, timestamp, .big) catch return error.UndoRecordTooLarge;
    writer.writeAll(action_kind) catch return error.UndoRecordTooLarge;
    writer.writeByte(0) catch return error.UndoRecordTooLarge;
    (switch (action) {
        .custom => |custom| std.json.Stringify.value(std.json.Value{ .object = custom.payload }, .{}, &writer),
        inline else => |payload| std.json.Stringify.value(payload, .{}, &writer),
    }) catch return error.UndoRecordTooLarge;
    try state.extra.moment.put(hash.hashInt(repo_opts.hash, "undo"), .{ .bytes = writer.buffered() });
}

fn validateJsonUtf8(value: std.json.Value) error{InvalidUtf8}!void {
    switch (value) {
        .string, .number_string => |text| if (!std.unicode.utf8ValidateSlice(text)) return error.InvalidUtf8,
        .array => |array| for (array.items) |item| {
            try validateJsonUtf8(item);
        },
        .object => |object| {
            for (object.keys(), object.values()) |key, item| {
                if (!std.unicode.utf8ValidateSlice(key)) return error.InvalidUtf8;
                try validateJsonUtf8(item);
            }
        },
        else => {},
    }
}

pub fn format(
    comptime repo_opts: rp.RepoOpts(.xit),
    core: *rp.Repo(.xit, repo_opts).Core,
    allocator: std.mem.Allocator,
    record: Record,
    writer: *std.Io.Writer,
) !void {
    const parsed = try parseAction(repo_opts.hash, allocator, record) orelse
        return writer.print("{s} {s}", .{ record.action_kind, record.payload });
    defer parsed.deinit();
    try parsed.value.format(repo_opts, core, allocator, writer);
}

fn parseAction(
    comptime hash_kind: hash.HashKind,
    allocator: std.mem.Allocator,
    record: Record,
) !?std.json.Parsed(Action(hash_kind)) {
    const Command = Action(hash_kind);
    const action_kind = std.meta.stringToEnum(ActionKind, record.action_kind) orelse return null;
    switch (action_kind) {
        .custom => return null,
        inline else => |tag| {
            const Payload = @FieldType(Command, @tagName(tag));
            const parsed = std.json.parseFromSlice(Payload, allocator, record.payload, .{ .allocate = .alloc_always }) catch |err| switch (err) {
                error.OutOfMemory => return err,
                else => return null,
            };
            return .{ .arena = parsed.arena, .value = @unionInit(Command, @tagName(tag), parsed.value) };
        },
    }
}

fn formatPaths(writer: *std.Io.Writer, name: []const u8, paths: []const []const u8) !void {
    try writer.print("{s} ", .{name});
    for (paths, 0..) |path, i| {
        if (i != 0) try writer.writeByte(' ');
        try writer.writeAll(path);
    }
}
