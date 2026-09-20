const std = @import("std");
const rp = @import("./repo.zig");
const hash = @import("./hash.zig");
const bch = @import("./branch.zig");
const tg = @import("./tag.zig");
const mrg = @import("./merge.zig");
const cfg = @import("./config.zig");
const work = @import("./workdir.zig");
const rf = @import("./ref.zig");

pub fn UndoCommand(comptime hash_kind: hash.HashKind) type {
    return union(enum) {
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
        undo: struct { index: u64, last_index: u64 },
        receive_pack: struct {},
        custom: struct {
            action: []const u8,
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
            self: UndoCommand(hash_kind),
            comptime repo_opts: rp.RepoOpts(.xit),
            db: *rp.Repo(.xit, repo_opts).DB,
            allocator: std.mem.Allocator,
            writer: *std.Io.Writer,
        ) !void {
            var current = self;
            var parsed: ?std.json.Parsed(UndoCommand(hash_kind)) = null;
            defer if (parsed) |value| value.deinit();
            if (self == .undo) {
                var target_index = self.undo.index;
                var redo = false;
                const DB = rp.Repo(.xit, repo_opts).DB;
                const history = try DB.ArrayList(.read_only).init(db.rootCursor().readOnly());
                const record_buffer = try allocator.alloc(u8, repo_opts.max_read_size);
                defer allocator.free(record_buffer);
                var record: ?UndoRecord = null;
                while (true) {
                    const moment_cursor = try history.getCursor(target_index) orelse return error.TransactionNotFound;
                    const moment = try DB.HashMap(.read_only).init(moment_cursor);
                    record = try read(repo_opts, moment, record_buffer);
                    const next = if (record) |value| try parseCommand(hash_kind, allocator, value) else null;
                    if (parsed) |value| value.deinit();
                    parsed = next;
                    const value = next orelse break;
                    current = value.value;
                    if (current != .undo) break;
                    redo = !redo;
                    // undo follows the start of a range; redo restores its end.
                    target_index = if (redo) current.undo.last_index else current.undo.index;
                }
                try writer.print("{s}: {} - ", .{ if (redo) "redo" else "undo", target_index });
                if (parsed == null) {
                    if (record) |value| {
                        try writer.print("{s} {s}", .{ value.action, value.payload });
                    } else {
                        try writer.writeAll("(empty description)");
                    }
                    return;
                }
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
                    try writer.print("{s} ", .{custom.action});
                    try std.json.Stringify.value(std.json.Value{ .object = custom.payload }, .{}, writer);
                },
            }
        }
    };
}

pub const UndoRecord = struct {
    timestamp: i64,
    action: []const u8,
    payload: []const u8,

    // the action and payload borrow their bytes from data.
    pub fn decode(data: []const u8) !UndoRecord {
        if (data.len < 8) return error.InvalidUndoRecord;
        const action_end = std.mem.indexOfScalarPos(u8, data, 8, 0) orelse return error.InvalidUndoRecord;
        if (action_end == 8) return error.InvalidUndoRecord;
        return .{
            .timestamp = std.mem.readInt(i64, data[0..8], .big),
            .action = data[8..action_end],
            .payload = data[action_end + 1 ..],
        };
    }
};

// the returned record borrows its action and payload from buffer.
pub fn read(
    comptime repo_opts: rp.RepoOpts(.xit),
    moment: rp.Repo(.xit, repo_opts).DB.HashMap(.read_only),
    buffer: []u8,
) !?UndoRecord {
    const cursor = try moment.getCursor(hash.hashInt(repo_opts.hash, "undo")) orelse return null;
    return try UndoRecord.decode(try cursor.readBytes(buffer));
}

pub fn write(
    comptime repo_opts: rp.RepoOpts(.xit),
    state: rp.Repo(.xit, repo_opts).State(.read_write),
    timestamp: i64,
    command: UndoCommand(repo_opts.hash),
) !void {
    const action = switch (command) {
        .custom => |custom| blk: {
            if (!std.unicode.utf8ValidateSlice(custom.action)) return error.InvalidUtf8;
            if (custom.action.len == 0 or std.mem.indexOfScalar(u8, custom.action, 0) != null) return error.InvalidUndoAction;
            try validateJsonUtf8(.{ .object = custom.payload });
            break :blk custom.action;
        },
        else => @tagName(command),
    };
    var buffer: [repo_opts.max_read_size]u8 = undefined;
    var writer = std.Io.Writer.fixed(&buffer);
    writer.writeInt(i64, timestamp, .big) catch return error.UndoRecordTooLarge;
    writer.writeAll(action) catch return error.UndoRecordTooLarge;
    writer.writeByte(0) catch return error.UndoRecordTooLarge;
    (switch (command) {
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
    db: *rp.Repo(.xit, repo_opts).DB,
    allocator: std.mem.Allocator,
    record: UndoRecord,
    writer: *std.Io.Writer,
) !void {
    const parsed = try parseCommand(repo_opts.hash, allocator, record) orelse
        return writer.print("{s} {s}", .{ record.action, record.payload });
    defer parsed.deinit();
    try parsed.value.format(repo_opts, db, allocator, writer);
}

fn parseCommand(
    comptime hash_kind: hash.HashKind,
    allocator: std.mem.Allocator,
    record: UndoRecord,
) !?std.json.Parsed(UndoCommand(hash_kind)) {
    const Command = UndoCommand(hash_kind);
    const action = std.meta.stringToEnum(std.meta.Tag(Command), record.action) orelse return null;
    switch (action) {
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
