const std = @import("std");
const hash = @import("./hash.zig");
const obj = @import("./object.zig");
const idx = @import("./index.zig");
const rf = @import("./ref.zig");
const work = @import("./workdir.zig");
const fs = @import("./fs.zig");
const rp = @import("./repo.zig");
const df = @import("./diff.zig");
const tr = @import("./tree.zig");
const cfg = @import("./config.zig");

fn CommitParent(comptime hash_kind: hash.HashKind) type {
    return struct {
        oid: [hash.hexLen(hash_kind)]u8,
        kind: enum { one, two, stale },
        timestamp: u64,
    };
}

fn CommitParentsQueue(comptime hash_kind: hash.HashKind) type {
    const compareFn = struct {
        fn compareCommitParents(_: void, a: CommitParent(hash_kind), b: CommitParent(hash_kind)) std.math.Order {
            return std.math.order(b.timestamp, a.timestamp); // Pop latest first
        }
    }.compareCommitParents;

    return std.PriorityQueue(
        CommitParent(hash_kind),
        void,
        compareFn,
    );
}

pub fn getDescendent(
    comptime repo_kind: rp.RepoKind,
    comptime repo_opts: rp.RepoOpts(repo_kind),
    state: rp.Repo(repo_kind, repo_opts).State(.read_only),
    io: std.Io,
    allocator: std.mem.Allocator,
    oid1: *const [hash.hexLen(repo_opts.hash)]u8,
    oid2: *const [hash.hexLen(repo_opts.hash)]u8,
) ![hash.hexLen(repo_opts.hash)]u8 {
    if (std.mem.eql(u8, oid1, oid2)) {
        return oid1.*;
    }

    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();

    var queue: CommitParentsQueue(repo_opts.hash) = .empty;

    {
        const object = try obj.Object(repo_kind, repo_opts, .full).initCommit(state, io, arena.allocator(), oid1);
        if (object.content.commit.metadata.parent_oids) |parent_oids| {
            for (parent_oids) |parent_oid| {
                const parent_object = try obj.Object(repo_kind, repo_opts, .full).initCommit(state, io, arena.allocator(), &parent_oid);
                try queue.push(arena.allocator(), .{ .oid = parent_oid, .kind = .one, .timestamp = parent_object.content.commit.metadata.timestamp });
            }
        }
    }

    {
        const object = try obj.Object(repo_kind, repo_opts, .full).initCommit(state, io, arena.allocator(), oid2);
        if (object.content.commit.metadata.parent_oids) |parent_oids| {
            for (parent_oids) |parent_oid| {
                const parent_object = try obj.Object(repo_kind, repo_opts, .full).initCommit(state, io, arena.allocator(), &parent_oid);
                try queue.push(arena.allocator(), .{ .oid = parent_oid, .kind = .two, .timestamp = parent_object.content.commit.metadata.timestamp });
            }
        }
    }

    while (queue.pop()) |node| {
        switch (node.kind) {
            .one => {
                if (std.mem.eql(u8, oid2, &node.oid)) {
                    return oid1.*;
                } else if (std.mem.eql(u8, oid1, &node.oid)) {
                    continue; // this oid was already added to the queue
                }
            },
            .two => {
                if (std.mem.eql(u8, oid1, &node.oid)) {
                    return oid2.*;
                } else if (std.mem.eql(u8, oid2, &node.oid)) {
                    continue; // this oid was already added to the queue
                }
            },
            .stale => unreachable,
        }

        const object = try obj.Object(repo_kind, repo_opts, .full).initCommit(state, io, arena.allocator(), &node.oid);
        if (object.content.commit.metadata.parent_oids) |parent_oids| {
            for (parent_oids) |parent_oid| {
                const parent_object = try obj.Object(repo_kind, repo_opts, .full).initCommit(state, io, arena.allocator(), &parent_oid);
                try queue.push(arena.allocator(), .{ .oid = parent_oid, .kind = node.kind, .timestamp = parent_object.content.commit.metadata.timestamp });
            }
        }
    }

    return error.DescendentNotFound;
}

pub fn commonAncestor(
    comptime repo_kind: rp.RepoKind,
    comptime repo_opts: rp.RepoOpts(repo_kind),
    state: rp.Repo(repo_kind, repo_opts).State(.read_only),
    io: std.Io,
    allocator: std.mem.Allocator,
    oid1: *const [hash.hexLen(repo_opts.hash)]u8,
    oid2: *const [hash.hexLen(repo_opts.hash)]u8,
) ![hash.hexLen(repo_opts.hash)]u8 {
    if (std.mem.eql(u8, oid1, oid2)) {
        return oid1.*;
    }

    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();

    var queue: CommitParentsQueue(repo_opts.hash) = .empty;

    {
        const object = try obj.Object(repo_kind, repo_opts, .full).initCommit(state, io, arena.allocator(), oid1);
        try queue.push(arena.allocator(), .{ .oid = oid1.*, .kind = .one, .timestamp = object.content.commit.metadata.timestamp });
    }

    {
        const object = try obj.Object(repo_kind, repo_opts, .full).initCommit(state, io, arena.allocator(), oid2);
        try queue.push(arena.allocator(), .{ .oid = oid2.*, .kind = .two, .timestamp = object.content.commit.metadata.timestamp });
    }

    var parents_of_1 = std.StringHashMap(void).init(arena.allocator());
    var parents_of_2 = std.StringHashMap(void).init(arena.allocator());
    var parents_of_both = std.StringArrayHashMap(void).init(arena.allocator());
    var stale_oids = std.StringHashMap(void).init(arena.allocator());

    while (queue.pop()) |node| {
        switch (node.kind) {
            .one => {
                if (std.mem.eql(u8, &node.oid, oid2)) {
                    return oid2.*;
                } else if (parents_of_2.contains(&node.oid)) {
                    try parents_of_both.put(try arena.allocator().dupe(u8, &node.oid), {});
                } else if (parents_of_1.contains(&node.oid)) {
                    continue; // this oid was already added to the queue
                } else {
                    try parents_of_1.put(try arena.allocator().dupe(u8, &node.oid), {});
                }
            },
            .two => {
                if (std.mem.eql(u8, &node.oid, oid1)) {
                    return oid1.*;
                } else if (parents_of_1.contains(&node.oid)) {
                    try parents_of_both.put(try arena.allocator().dupe(u8, &node.oid), {});
                } else if (parents_of_2.contains(&node.oid)) {
                    continue; // this oid was already added to the queue
                } else {
                    try parents_of_2.put(try arena.allocator().dupe(u8, &node.oid), {});
                }
            },
            .stale => {
                try stale_oids.put(try arena.allocator().dupe(u8, &node.oid), {});
            },
        }

        const is_base_ancestor = parents_of_both.contains(&node.oid);

        const object = try obj.Object(repo_kind, repo_opts, .full).initCommit(state, io, arena.allocator(), &node.oid);
        if (object.content.commit.metadata.parent_oids) |parent_oids| {
            parents: for (parent_oids) |parent_oid| {
                const is_stale = is_base_ancestor or stale_oids.contains(&parent_oid);
                if (is_stale) {
                    var iter = queue.iterator();
                    while (iter.next()) |node_in_queue| {
                        // Catch up with another side, update node's kind in the queue
                        // to avoid confusion which could lead to endless loop
                        if (std.mem.eql(u8, &node_in_queue.oid, &parent_oid)) {
                            try queue.update(node_in_queue, .{ .oid = node_in_queue.oid, .kind = .stale, .timestamp = node_in_queue.timestamp });
                            continue :parents;
                        }
                    }
                }
                const parent_object = try obj.Object(repo_kind, repo_opts, .full).initCommit(state, io, arena.allocator(), &parent_oid);
                try queue.push(arena.allocator(), .{ .oid = parent_oid, .kind = if (is_stale) .stale else node.kind, .timestamp = parent_object.content.commit.metadata.timestamp });
            }
        }

        // stop if queue only has stale nodes
        var queue_is_stale = true;
        var iter = queue.iterator();
        while (iter.next()) |next_node| {
            if (next_node.kind != .stale) {
                queue_is_stale = false;
                break;
            }
        }
        if (queue_is_stale) {
            break;
        }
    }

    const base_ancestor_count = parents_of_both.count();
    if (base_ancestor_count > 1) {
        var oid = parents_of_both.keys()[0][0..comptime hash.hexLen(repo_opts.hash)].*;
        for (parents_of_both.keys()[1..]) |next_oid| {
            oid = try getDescendent(repo_kind, repo_opts, state, io, allocator, oid[0..comptime hash.hexLen(repo_opts.hash)], next_oid[0..comptime hash.hexLen(repo_opts.hash)]);
        }
        return oid;
    } else if (base_ancestor_count == 1) {
        return parents_of_both.keys()[0][0..comptime hash.hexLen(repo_opts.hash)].*;
    } else {
        return error.NoCommonAncestor;
    }
}

pub fn RenamedEntry(comptime hash_kind: hash.HashKind) type {
    return struct {
        path: []const u8,
        tree_entry: tr.TreeEntry(hash_kind),
    };
}

pub fn MergeConflict(comptime hash_kind: hash.HashKind) type {
    return struct {
        base: ?tr.TreeEntry(hash_kind),
        target: ?tr.TreeEntry(hash_kind),
        source: ?tr.TreeEntry(hash_kind),
        renamed: ?RenamedEntry(hash_kind),
    };
}

fn writeBlobWithDiff3(
    comptime repo_kind: rp.RepoKind,
    comptime repo_opts: rp.RepoOpts(repo_kind),
    state: rp.Repo(repo_kind, repo_opts).State(.read_write),
    io: std.Io,
    allocator: std.mem.Allocator,
    base_file_oid_maybe: ?*const [hash.byteLen(repo_opts.hash)]u8,
    target_file_oid: *const [hash.byteLen(repo_opts.hash)]u8,
    source_file_oid: *const [hash.byteLen(repo_opts.hash)]u8,
    base_oid: *const [hash.hexLen(repo_opts.hash)]u8,
    target_name: []const u8,
    source_name: []const u8,
    has_conflict: *bool,
) ![hash.byteLen(repo_opts.hash)]u8 {
    var base_iter = if (base_file_oid_maybe) |base_file_oid|
        try df.LineIterator(repo_kind, repo_opts).initFromOid(state.readOnly(), io, allocator, "", base_file_oid, null)
    else
        try df.LineIterator(repo_kind, repo_opts).initFromNothing(io, allocator, "");
    defer base_iter.deinit();

    var target_iter = try df.LineIterator(repo_kind, repo_opts).initFromOid(state.readOnly(), io, allocator, "", target_file_oid, null);
    defer target_iter.deinit();

    var source_iter = try df.LineIterator(repo_kind, repo_opts).initFromOid(state.readOnly(), io, allocator, "", source_file_oid, null);
    defer source_iter.deinit();

    // if any file is binary, just return the source oid because there is no point in trying to merge them
    if (base_iter.source == .binary or target_iter.source == .binary or source_iter.source == .binary) {
        has_conflict.* = true;
        return source_file_oid.*;
    }

    var diff3_iter = try df.Diff3Iterator(repo_kind, repo_opts).init(allocator, &base_iter, &target_iter, &source_iter);
    defer diff3_iter.deinit();

    var line_buffer = std.ArrayList([]const u8){};
    defer {
        for (line_buffer.items) |buffer| {
            allocator.free(buffer);
        }
        line_buffer.deinit(allocator);
    }

    const LineRange = struct {
        lines: std.ArrayList([]const u8),

        fn init(inner_allocator: std.mem.Allocator, iter: *df.LineIterator(repo_kind, repo_opts), range_maybe: ?df.Diff3Iterator(repo_kind, repo_opts).Range) !@This() {
            var lines = std.ArrayList([]const u8){};
            errdefer {
                for (lines.items) |line| {
                    inner_allocator.free(line);
                }
                lines.deinit(inner_allocator);
            }
            if (range_maybe) |range| {
                for (range.begin..range.end) |line_num| {
                    const line = try iter.get(line_num);
                    defer iter.free(line);
                    {
                        const line_dupe = try inner_allocator.dupe(u8, line);
                        errdefer inner_allocator.free(line_dupe);
                        try lines.append(inner_allocator, line_dupe);
                    }
                }
            }
            return .{
                .lines = lines,
            };
        }

        fn deinit(self: *@This(), inner_allocator: std.mem.Allocator) void {
            for (self.lines.items) |line| {
                inner_allocator.free(line);
            }
            self.lines.deinit(inner_allocator);
        }

        fn eql(self: @This(), other: @This()) bool {
            if (self.lines.items.len != other.lines.items.len) {
                return false;
            }
            for (self.lines.items, other.lines.items) |our_line, their_line| {
                if (!std.mem.eql(u8, our_line, their_line)) {
                    return false;
                }
            }
            return true;
        }
    };

    const Stream = struct {
        allocator: std.mem.Allocator,
        target_marker: []u8,
        base_marker: []u8,
        separate_marker: []u8,
        source_marker: []u8,
        base_iter: *df.LineIterator(repo_kind, repo_opts),
        target_iter: *df.LineIterator(repo_kind, repo_opts),
        source_iter: *df.LineIterator(repo_kind, repo_opts),
        diff3_iter: *df.Diff3Iterator(repo_kind, repo_opts),
        line_buffer: *std.ArrayList([]const u8),
        current_line: ?[]const u8,
        has_conflict: bool,
        interface: std.Io.Reader,

        const Parent = @This();

        pub const Reader = struct {
            parent: *Parent,

            pub fn read(self: @This(), buf: []u8) !usize {
                var size: usize = 0;
                while (size < buf.len) {
                    const read_size = try self.readStep(buf[size..]);
                    if (read_size == 0) {
                        break;
                    }
                    size += read_size;
                }
                return size;
            }

            pub fn readByte(self: @This()) !u8 {
                var buffer = [_]u8{0} ** 1;
                const size = try self.read(&buffer);
                if (size == 0) {
                    return error.EndOfStream;
                } else {
                    return buffer[0];
                }
            }

            pub fn readNoEof(self: @This(), dest: []u8) !void {
                const size = try self.read(dest);
                if (size != dest.len) {
                    return error.EndOfStream;
                }
            }

            fn readStep(self: @This(), buf: []u8) !usize {
                if (self.parent.current_line) |current_line| {
                    const size = @min(buf.len, current_line.len);
                    var line_finished = current_line.len == 0;
                    if (size > 0) {
                        // copy as much from the current line as we can
                        @memcpy(buf[0..size], current_line[0..size]);
                        const new_current_line = current_line[size..];
                        line_finished = new_current_line.len == 0;
                        self.parent.current_line = new_current_line;
                    }
                    // if we have copied the entire line
                    if (line_finished) {
                        // if there is room for the newline character
                        if (buf.len > size) {
                            // remove the line from the line buffer
                            const line = self.parent.line_buffer.orderedRemove(0);
                            self.parent.allocator.free(line);
                            if (self.parent.line_buffer.items.len > 0) {
                                self.parent.current_line = self.parent.line_buffer.items[0];
                            } else {
                                self.parent.current_line = null;
                            }
                            // if we aren't at the very last line, add a newline character
                            if (self.parent.current_line != null or !self.parent.diff3_iter.finished) {
                                buf[size] = '\n';
                                return size + 1;
                            }
                        }
                    }
                    return size;
                }

                if (try self.parent.diff3_iter.next()) |chunk| {
                    switch (chunk) {
                        .clean => |clean| {
                            for (clean.begin..clean.end) |line_num| {
                                const line = try self.parent.base_iter.get(line_num);
                                defer self.parent.base_iter.free(line);
                                {
                                    const line_dupe = try self.parent.allocator.dupe(u8, line);
                                    errdefer self.parent.allocator.free(line_dupe);
                                    try self.parent.line_buffer.append(self.parent.allocator, line_dupe);
                                }
                                self.parent.current_line = self.parent.line_buffer.items[0];
                            }
                        },
                        .conflict => |conflict| {
                            var base_lines = try LineRange.init(self.parent.allocator, self.parent.base_iter, conflict.o_range);
                            defer base_lines.deinit(self.parent.allocator);
                            var target_lines = try LineRange.init(self.parent.allocator, self.parent.target_iter, conflict.a_range);
                            defer target_lines.deinit(self.parent.allocator);
                            var source_lines = try LineRange.init(self.parent.allocator, self.parent.source_iter, conflict.b_range);
                            defer source_lines.deinit(self.parent.allocator);

                            // if base == target or target == source, return source to autoresolve conflict
                            if (base_lines.eql(target_lines) or target_lines.eql(source_lines)) {
                                if (source_lines.lines.items.len > 0) {
                                    try self.parent.line_buffer.appendSlice(self.parent.allocator, source_lines.lines.items);
                                    self.parent.current_line = self.parent.line_buffer.items[0];
                                    source_lines.lines.clearAndFree(self.parent.allocator);
                                }
                                return self.readStep(buf);
                            }
                            // if base == source, return target to autoresolve conflict
                            else if (base_lines.eql(source_lines)) {
                                if (target_lines.lines.items.len > 0) {
                                    try self.parent.line_buffer.appendSlice(self.parent.allocator, target_lines.lines.items);
                                    self.parent.current_line = self.parent.line_buffer.items[0];
                                    target_lines.lines.clearAndFree(self.parent.allocator);
                                }
                                return self.readStep(buf);
                            }

                            // return conflict

                            const target_marker = try self.parent.allocator.dupe(u8, self.parent.target_marker);
                            {
                                errdefer self.parent.allocator.free(target_marker);
                                try self.parent.line_buffer.append(self.parent.allocator, target_marker);
                            }
                            try self.parent.line_buffer.appendSlice(self.parent.allocator, target_lines.lines.items);
                            target_lines.lines.clearAndFree(self.parent.allocator);

                            const base_marker = try self.parent.allocator.dupe(u8, self.parent.base_marker);
                            {
                                errdefer self.parent.allocator.free(base_marker);
                                try self.parent.line_buffer.append(self.parent.allocator, base_marker);
                            }
                            try self.parent.line_buffer.appendSlice(self.parent.allocator, base_lines.lines.items);
                            base_lines.lines.clearAndFree(self.parent.allocator);

                            const separate_marker = try self.parent.allocator.dupe(u8, self.parent.separate_marker);
                            {
                                errdefer self.parent.allocator.free(separate_marker);
                                try self.parent.line_buffer.append(self.parent.allocator, separate_marker);
                            }

                            try self.parent.line_buffer.appendSlice(self.parent.allocator, source_lines.lines.items);
                            source_lines.lines.clearAndFree(self.parent.allocator);
                            const source_marker = try self.parent.allocator.dupe(u8, self.parent.source_marker);
                            {
                                errdefer self.parent.allocator.free(source_marker);
                                try self.parent.line_buffer.append(self.parent.allocator, source_marker);
                            }

                            self.parent.current_line = self.parent.line_buffer.items[0];
                            self.parent.has_conflict = true;
                        },
                    }
                    return self.readStep(buf);
                } else {
                    return 0;
                }
            }
        };

        pub fn seekTo(self: *@This(), offset: usize) !void {
            try self.base_iter.reset();
            try self.target_iter.reset();
            try self.source_iter.reset();
            try self.diff3_iter.reset();
            for (self.line_buffer.items) |buffer| {
                self.allocator.free(buffer);
            }
            self.line_buffer.clearAndFree(self.allocator);
            self.current_line = null;
            self.has_conflict = false;
            self.interface.seek = 0;
            self.interface.end = 0;

            for (0..offset) |_| {
                _ = try self.reader().readByte();
            }
        }

        pub fn reader(self: *@This()) Reader {
            return Reader{
                .parent = self,
            };
        }

        pub fn count(self: *@This()) !usize {
            var n: usize = 0;
            var read_buffer = [_]u8{0} ** repo_opts.read_size;
            try self.seekTo(0);
            while (true) {
                const size = try self.reader().read(&read_buffer);
                if (size == 0) {
                    break;
                }
                n += size;
            }
            return n;
        }

        fn stream(io_r: *std.Io.Reader, io_w: *std.Io.Writer, limit: std.Io.Limit) std.Io.Reader.StreamError!usize {
            const r: *@This() = @alignCast(@fieldParentPtr("interface", io_r));
            const dest = limit.slice(try io_w.writableSliceGreedy(1));
            const size = r.reader().read(dest) catch return error.ReadFailed;
            if (size == 0) return error.EndOfStream;
            io_w.advance(size);
            return size;
        }
    };

    const target_marker = try std.fmt.allocPrint(allocator, "<<<<<<< target ({s})", .{target_name});
    defer allocator.free(target_marker);
    const base_marker = try std.fmt.allocPrint(allocator, "||||||| base ({s})", .{base_oid});
    defer allocator.free(base_marker);
    const separate_marker = try std.fmt.allocPrint(allocator, "=======", .{});
    defer allocator.free(separate_marker);
    const source_marker = try std.fmt.allocPrint(allocator, ">>>>>>> source ({s})", .{source_name});
    defer allocator.free(source_marker);

    var stream_buffer = [_]u8{0} ** repo_opts.buffer_size;
    var stream = Stream{
        .allocator = allocator,
        .target_marker = target_marker,
        .base_marker = base_marker,
        .separate_marker = separate_marker,
        .source_marker = source_marker,
        .base_iter = &base_iter,
        .target_iter = &target_iter,
        .source_iter = &source_iter,
        .diff3_iter = &diff3_iter,
        .line_buffer = &line_buffer,
        .current_line = null,
        .has_conflict = false,
        .interface = .{
            .vtable = &.{ .stream = Stream.stream },
            .buffer = &stream_buffer,
            .seek = 0,
            .end = 0,
        },
    };

    const header = obj.ObjectHeader{ .kind = .blob, .size = try stream.count() };
    has_conflict.* = stream.has_conflict;
    try stream.seekTo(0);

    var oid = [_]u8{0} ** hash.byteLen(repo_opts.hash);
    try obj.writeObject(repo_kind, repo_opts, state, io, &stream.interface, header, &oid);
    return oid;
}

fn writeBlobWithPatches(
    comptime repo_kind: rp.RepoKind,
    comptime repo_opts: rp.RepoOpts(repo_kind),
    state: rp.Repo(repo_kind, repo_opts).State(.read_write),
    io: std.Io,
    allocator: std.mem.Allocator,
    source_file_oid: *const [hash.byteLen(repo_opts.hash)]u8,
    base_oid: *const [hash.hexLen(repo_opts.hash)]u8,
    target_oid: *const [hash.hexLen(repo_opts.hash)]u8,
    source_oid: *const [hash.hexLen(repo_opts.hash)]u8,
    target_name: []const u8,
    source_name: []const u8,
    has_conflict: *bool,
    path: []const u8,
) ![hash.byteLen(repo_opts.hash)]u8 {
    if (repo_kind != .xit) return error.PatchBasedMergeRequiresXitBackend;

    //get commit-id->snapshot
    const commit_id_to_snapshot_cursor = try state.extra.moment.putCursor(hash.hashInt(repo_opts.hash, "commit-id->snapshot"));
    const commit_id_to_snapshot = try rp.Repo(.xit, repo_opts).DB.HashMap(.read_write).init(commit_id_to_snapshot_cursor);

    // get base snapshot
    const base_snapshot_cursor = (try commit_id_to_snapshot.getCursor(try hash.hexToInt(repo_opts.hash, base_oid))) orelse return error.KeyNotFound;
    const base_snapshot = try rp.Repo(.xit, repo_opts).DB.HashMap(.read_only).init(base_snapshot_cursor);

    // get target snapshot
    const target_snapshot_cursor = (try commit_id_to_snapshot.getCursor(try hash.hexToInt(repo_opts.hash, target_oid))) orelse return error.KeyNotFound;
    const target_snapshot = try rp.Repo(.xit, repo_opts).DB.HashMap(.read_only).init(target_snapshot_cursor);

    // get source snapshot
    const source_snapshot_cursor = (try commit_id_to_snapshot.getCursor(try hash.hexToInt(repo_opts.hash, source_oid))) orelse return error.KeyNotFound;
    const source_snapshot = try rp.Repo(.xit, repo_opts).DB.HashMap(.read_only).init(source_snapshot_cursor);

    var patch_ids = std.ArrayList(hash.HashInt(repo_opts.hash)){};
    defer patch_ids.deinit(allocator);

    const path_hash = hash.hashInt(repo_opts.hash, path);

    // get all the patch ids from source
    {
        var iter = try obj.ObjectIterator(.xit, repo_opts, .full).init(state.readOnly(), io, allocator, .{ .kind = .commit });
        defer iter.deinit();
        try iter.include(source_oid);

        const source_path_to_patch_id_cursor_maybe = try source_snapshot.getCursor(hash.hashInt(repo_opts.hash, "path->patch-id"));

        while (try iter.next()) |object| {
            defer object.deinit();

            if (std.mem.eql(u8, base_oid, &object.oid)) {
                break;
            }

            if (source_path_to_patch_id_cursor_maybe) |path_to_patch_id_cursor| {
                const path_to_patch_id = try rp.Repo(.xit, repo_opts).DB.HashMap(.read_only).init(path_to_patch_id_cursor);
                if (try path_to_patch_id.getCursor(path_hash)) |patch_id_cursor| {
                    var patch_id_buffer = [_]u8{0} ** hash.byteLen(repo_opts.hash);
                    _ = try patch_id_cursor.readBytes(&patch_id_buffer);
                    const patch_id = hash.bytesToInt(repo_opts.hash, &patch_id_buffer);
                    try patch_ids.append(allocator, patch_id);
                }
            }
        }
    }

    // if there are no patches, it is most likely because the file was determined to be binary,
    // so just return the source oid because there is no point in trying to merge them
    if (patch_ids.items.len == 0) {
        has_conflict.* = true;
        return source_file_oid.*;
    }

    // put target snapshot in temp location
    const merge_in_progress_cursor = try state.extra.moment.putCursor(hash.hashInt(repo_opts.hash, "merge-in-progress"));
    const merge_in_progress = try rp.Repo(.xit, repo_opts).DB.HashMap(.read_write).init(merge_in_progress_cursor);
    var merge_snapshot_cursor = try merge_in_progress.putCursor(hash.hashInt(repo_opts.hash, "snapshot"));
    try merge_snapshot_cursor.writeIfEmpty(.{ .slot = target_snapshot_cursor.slot() });
    const merge_snapshot = try rp.Repo(.xit, repo_opts).DB.HashMap(.read_write).init(merge_snapshot_cursor);

    const patch = @import("./patch.zig");

    for (0..patch_ids.items.len) |i| {
        const patch_id = patch_ids.items[patch_ids.items.len - i - 1];
        try patch.applyPatch(repo_opts, state.readOnly().extra.moment, &merge_snapshot, allocator, path_hash, patch_id);
    }

    const merge_path_to_live_parent_to_children_cursor = (try merge_snapshot.getCursor(hash.hashInt(repo_opts.hash, "path->live-parent->children"))) orelse return error.KeyNotFound;
    const merge_path_to_live_parent_to_children = try rp.Repo(.xit, repo_opts).DB.HashMap(.read_only).init(merge_path_to_live_parent_to_children_cursor);
    const merge_live_parent_to_children_cursor = (try merge_path_to_live_parent_to_children.getCursor(path_hash)) orelse return error.KeyNotFound;
    const merge_live_parent_to_children = try rp.Repo(.xit, repo_opts).DB.HashMap(.read_only).init(merge_live_parent_to_children_cursor);

    var base_live_parent_to_children_maybe: ?rp.Repo(.xit, repo_opts).DB.HashMap(.read_only) = null;
    if (try base_snapshot.getCursor(hash.hashInt(repo_opts.hash, "path->live-parent->children"))) |base_path_to_live_parent_to_children_cursor| {
        const base_path_to_live_parent_to_children = try rp.Repo(.xit, repo_opts).DB.HashMap(.read_only).init(base_path_to_live_parent_to_children_cursor);
        if (try base_path_to_live_parent_to_children.getCursor(path_hash)) |base_live_parent_to_children_cursor| {
            base_live_parent_to_children_maybe = try rp.Repo(.xit, repo_opts).DB.HashMap(.read_only).init(base_live_parent_to_children_cursor);
        }
    }

    const target_path_to_live_parent_to_children_cursor = (try target_snapshot.getCursor(hash.hashInt(repo_opts.hash, "path->live-parent->children"))) orelse return error.KeyNotFound;
    const target_path_to_live_parent_to_children = try rp.Repo(.xit, repo_opts).DB.HashMap(.read_only).init(target_path_to_live_parent_to_children_cursor);
    const target_live_parent_to_children_cursor = (try target_path_to_live_parent_to_children.getCursor(path_hash)) orelse return error.KeyNotFound;
    const target_live_parent_to_children = try rp.Repo(.xit, repo_opts).DB.HashMap(.read_only).init(target_live_parent_to_children_cursor);

    const source_path_to_live_parent_to_children_cursor = (try source_snapshot.getCursor(hash.hashInt(repo_opts.hash, "path->live-parent->children"))) orelse return error.KeyNotFound;
    const source_path_to_live_parent_to_children = try rp.Repo(.xit, repo_opts).DB.HashMap(.read_only).init(source_path_to_live_parent_to_children_cursor);
    const source_live_parent_to_children_cursor = (try source_path_to_live_parent_to_children.getCursor(path_hash)) orelse return error.KeyNotFound;
    const source_live_parent_to_children = try rp.Repo(.xit, repo_opts).DB.HashMap(.read_only).init(source_live_parent_to_children_cursor);

    const patch_id_to_offset_list_cursor = (try state.extra.moment.getCursor(hash.hashInt(repo_opts.hash, "patch-id->offset-list"))) orelse return error.KeyNotFound;
    const patch_id_to_offset_list = try rp.Repo(.xit, repo_opts).DB.HashMap(.read_only).init(patch_id_to_offset_list_cursor);

    var line_buffer = std.ArrayList([]const u8){};
    defer {
        for (line_buffer.items) |buffer| {
            allocator.free(buffer);
        }
        line_buffer.deinit(allocator);
    }

    const readLine = struct {
        fn readLine(
            inner_state: rp.Repo(.xit, repo_opts).State(.read_only),
            inner_io: std.Io,
            inner_allocator: std.mem.Allocator,
            offset_list_cursor: *rp.Repo(.xit, repo_opts).DB.Cursor(.read_only),
            line_id: patch.LineId(repo_opts.hash),
        ) ![]const u8 {
            var read_buffer: [repo_opts.buffer_size]u8 = undefined;
            var offset_list_reader = try offset_list_cursor.reader(&read_buffer);

            const hash_size = comptime hash.byteLen(repo_opts.hash);
            const offset_size = @bitSizeOf(u64) / 8;

            const oid = try offset_list_reader.interface.takeArray(hash_size);
            const oid_hex = std.fmt.bytesToHex(oid, .lower);
            try offset_list_reader.seekTo(hash_size + line_id.line * offset_size);
            const change_offset = try offset_list_reader.interface.takeInt(u64, .big);

            var obj_rdr = try obj.ObjectReader(.xit, repo_opts).init(inner_state, inner_io, inner_allocator, &oid_hex);
            defer obj_rdr.deinit();
            try obj_rdr.seekTo(change_offset);

            if (obj_rdr.interface.peekByte()) |_| {
                var line_writer = std.Io.Writer.Allocating.init(inner_allocator);
                errdefer line_writer.deinit();
                _ = try obj_rdr.interface.streamDelimiterLimit(&line_writer.writer, '\n', .limited(repo_opts.max_line_size));

                // skip delimiter
                if (obj_rdr.interface.bufferedLen() > 0) {
                    obj_rdr.interface.toss(1);
                }

                return line_writer.toOwnedSlice();
            } else |err| switch (err) {
                // empty line at the end of the file
                error.EndOfStream => return try inner_allocator.dupe(u8, ""),
                else => |e| return e,
            }
        }
    }.readLine;

    const LineRange = struct {
        lines: std.ArrayList([]const u8),

        fn init(
            inner_state: rp.Repo(.xit, repo_opts).State(.read_only),
            inner_io: std.Io,
            inner_allocator: std.mem.Allocator,
            patch_id_to_offset_list_ptr: *const rp.Repo(.xit, repo_opts).DB.HashMap(.read_only),
            line_ids: []patch.LineId(repo_opts.hash),
        ) !@This() {
            var lines = std.ArrayList([]const u8){};
            errdefer {
                for (lines.items) |line| {
                    inner_allocator.free(line);
                }
                lines.deinit(inner_allocator);
            }
            for (line_ids) |line_id| {
                var offset_list_cursor = (try patch_id_to_offset_list_ptr.getCursor(line_id.patch_id)) orelse return error.KeyNotFound;
                const line = try readLine(inner_state, inner_io, inner_allocator, &offset_list_cursor, line_id);
                errdefer inner_allocator.free(line);
                try lines.append(inner_allocator, line);
            }
            return .{
                .lines = lines,
            };
        }

        fn deinit(self: *@This(), inner_allocator: std.mem.Allocator) void {
            for (self.lines.items) |line| {
                inner_allocator.free(line);
            }
            self.lines.deinit(inner_allocator);
        }

        fn eql(self: @This(), other: @This()) bool {
            if (self.lines.items.len != other.lines.items.len) {
                return false;
            }
            for (self.lines.items, other.lines.items) |our_line, their_line| {
                if (!std.mem.eql(u8, our_line, their_line)) {
                    return false;
                }
            }
            return true;
        }
    };

    const Stream = struct {
        state: rp.Repo(.xit, repo_opts).State(.read_only),
        io: std.Io,
        allocator: std.mem.Allocator,
        target_marker: []u8,
        base_marker: []u8,
        separate_marker: []u8,
        source_marker: []u8,
        merge_live_parent_to_children: *const rp.Repo(.xit, repo_opts).DB.HashMap(.read_only),
        base_live_parent_to_children: ?*const rp.Repo(.xit, repo_opts).DB.HashMap(.read_only),
        target_live_parent_to_children: *const rp.Repo(.xit, repo_opts).DB.HashMap(.read_only),
        source_live_parent_to_children: *const rp.Repo(.xit, repo_opts).DB.HashMap(.read_only),
        patch_id_to_offset_list: *const rp.Repo(.xit, repo_opts).DB.HashMap(.read_only),
        line_buffer: *std.ArrayList([]const u8),
        current_line: ?[]const u8,
        current_line_id_hash: ?hash.HashInt(repo_opts.hash),
        has_conflict: bool,
        interface: std.Io.Reader,

        const Parent = @This();

        pub const Reader = struct {
            parent: *Parent,

            pub fn read(self: @This(), buf: []u8) !usize {
                var size: usize = 0;
                while (size < buf.len) {
                    const read_size = try self.readStep(buf[size..]);
                    if (read_size == 0) {
                        break;
                    }
                    size += read_size;
                }
                return size;
            }

            pub fn readByte(self: @This()) !u8 {
                var buffer = [_]u8{0} ** 1;
                const size = try self.read(&buffer);
                if (size == 0) {
                    return error.EndOfStream;
                } else {
                    return buffer[0];
                }
            }

            pub fn readNoEof(self: @This(), dest: []u8) !void {
                const size = try self.read(dest);
                if (size != dest.len) {
                    return error.EndOfStream;
                }
            }

            fn readStep(self: @This(), buf: []u8) !usize {
                if (self.parent.current_line) |current_line| {
                    const size = @min(buf.len, current_line.len);
                    var line_finished = current_line.len == 0;
                    if (size > 0) {
                        // copy as much from the current line as we can
                        @memcpy(buf[0..size], current_line[0..size]);
                        const new_current_line = current_line[size..];
                        line_finished = new_current_line.len == 0;
                        self.parent.current_line = new_current_line;
                    }
                    // if we have copied the entire line
                    if (line_finished) {
                        // if there is room for the newline character
                        if (buf.len > size) {
                            // remove the line from the line buffer
                            const line = self.parent.line_buffer.orderedRemove(0);
                            self.parent.allocator.free(line);
                            if (self.parent.line_buffer.items.len > 0) {
                                self.parent.current_line = self.parent.line_buffer.items[0];
                            } else {
                                self.parent.current_line = null;
                            }
                            // if we aren't at the very last line, add a newline character
                            if (self.parent.current_line != null or self.parent.current_line_id_hash != null) {
                                buf[size] = '\n';
                                return size + 1;
                            }
                        }
                    }
                    return size;
                }

                if (self.parent.current_line_id_hash) |current_line_id_hash| {
                    const children_cursor = (try self.parent.merge_live_parent_to_children.getCursor(current_line_id_hash)) orelse return error.KeyNotFound;
                    var children_iter = try children_cursor.iterator();

                    const first_child_cursor = (try children_iter.next()) orelse return error.ExpectedChild;
                    const first_kv_pair = try first_child_cursor.readKeyValuePair();
                    var first_child_bytes = [_]u8{0} ** patch.LineId(repo_opts.hash).byte_size;
                    const first_child_slice = try first_kv_pair.key_cursor.readBytes(&first_child_bytes);
                    const first_line_id: patch.LineId(repo_opts.hash) = blk: {
                        var line_id_reader = std.Io.Reader.fixed(first_child_slice);
                        break :blk @bitCast(try line_id_reader.takeInt(patch.LineId(repo_opts.hash).Int, .big));
                    };
                    const first_line_id_hash = hash.hashInt(repo_opts.hash, first_child_slice);

                    if (try children_iter.next()) |second_child_cursor| {
                        if (try children_iter.next() != null) return error.MoreThanTwoChildrenFound;

                        const second_kv_pair = try second_child_cursor.readKeyValuePair();
                        var second_child_bytes = [_]u8{0} ** patch.LineId(repo_opts.hash).byte_size;
                        const second_child_slice = try second_kv_pair.key_cursor.readBytes(&second_child_bytes);
                        const second_line_id: patch.LineId(repo_opts.hash) = blk: {
                            var line_id_reader = std.Io.Reader.fixed(second_child_slice);
                            break :blk @bitCast(try line_id_reader.takeInt(patch.LineId(repo_opts.hash).Int, .big));
                        };
                        const second_line_id_hash = hash.hashInt(repo_opts.hash, second_child_slice);

                        const target_line_id, const target_line_id_hash, const source_line_id, const source_line_id_hash =
                            if (try self.parent.target_live_parent_to_children.getCursor(first_line_id_hash) != null)
                                .{ first_line_id, first_line_id_hash, second_line_id, second_line_id_hash }
                            else
                                .{ second_line_id, second_line_id_hash, first_line_id, first_line_id_hash };

                        var target_line_ids = std.ArrayList(patch.LineId(repo_opts.hash)){};
                        defer target_line_ids.deinit(self.parent.allocator);

                        var join_line_id_hash_maybe: ?hash.HashInt(repo_opts.hash) = null;

                        // find the target line ids that aren't in source
                        var next_line_id = target_line_id;
                        var next_line_id_hash = target_line_id_hash;
                        while (try self.parent.target_live_parent_to_children.getCursor(next_line_id_hash)) |next_children_cursor| {
                            if (null == try self.parent.source_live_parent_to_children.getCursor(next_line_id_hash)) {
                                try target_line_ids.append(self.parent.allocator, next_line_id);
                            } else {
                                join_line_id_hash_maybe = next_line_id_hash;
                                break;
                            }
                            var next_children_iter = try next_children_cursor.iterator();
                            if (try next_children_iter.next()) |next_child_cursor| {
                                if (try next_children_iter.next() != null) return error.ExpectedOneChild;
                                const next_kv_pair = try next_child_cursor.readKeyValuePair();
                                var next_child_bytes = [_]u8{0} ** patch.LineId(repo_opts.hash).byte_size;
                                const next_child_slice = try next_kv_pair.key_cursor.readBytes(&next_child_bytes);
                                next_line_id = blk: {
                                    var line_id_reader = std.Io.Reader.fixed(next_child_slice);
                                    break :blk @bitCast(try line_id_reader.takeInt(patch.LineId(repo_opts.hash).Int, .big));
                                };
                                next_line_id_hash = hash.hashInt(repo_opts.hash, next_child_slice);
                            } else {
                                break;
                            }
                        }

                        var source_line_ids = std.ArrayList(patch.LineId(repo_opts.hash)){};
                        defer source_line_ids.deinit(self.parent.allocator);

                        // find the source line ids that aren't in target
                        next_line_id = source_line_id;
                        next_line_id_hash = source_line_id_hash;
                        while (try self.parent.source_live_parent_to_children.getCursor(next_line_id_hash)) |next_children_cursor| {
                            if (null == try self.parent.target_live_parent_to_children.getCursor(next_line_id_hash)) {
                                try source_line_ids.append(self.parent.allocator, next_line_id);
                            } else {
                                if (next_line_id_hash != join_line_id_hash_maybe) return error.ExpectedJoinLine;
                                break;
                            }
                            var next_children_iter = try next_children_cursor.iterator();
                            if (try next_children_iter.next()) |next_child_cursor| {
                                if (try next_children_iter.next() != null) return error.ExpectedOneChild;
                                const next_kv_pair = try next_child_cursor.readKeyValuePair();
                                var next_child_bytes = [_]u8{0} ** patch.LineId(repo_opts.hash).byte_size;
                                const next_child_slice = try next_kv_pair.key_cursor.readBytes(&next_child_bytes);
                                next_line_id = blk: {
                                    var line_id_reader = std.Io.Reader.fixed(next_child_slice);
                                    break :blk @bitCast(try line_id_reader.takeInt(patch.LineId(repo_opts.hash).Int, .big));
                                };
                                next_line_id_hash = hash.hashInt(repo_opts.hash, next_child_slice);
                            } else {
                                break;
                            }
                        }

                        var base_line_ids = std.ArrayList(patch.LineId(repo_opts.hash)){};
                        defer base_line_ids.deinit(self.parent.allocator);

                        // find the base line ids up to (but not including) the join line id if it exists,
                        // or until the end of the file
                        next_line_id_hash = current_line_id_hash;
                        if (self.parent.base_live_parent_to_children) |base_live_parent_to_children| {
                            while (try base_live_parent_to_children.getCursor(next_line_id_hash)) |next_children_cursor| {
                                var next_children_iter = try next_children_cursor.iterator();
                                if (try next_children_iter.next()) |next_child_cursor| {
                                    if (try next_children_iter.next() != null) return error.ExpectedOneChild;
                                    const next_kv_pair = try next_child_cursor.readKeyValuePair();
                                    var next_child_bytes = [_]u8{0} ** patch.LineId(repo_opts.hash).byte_size;
                                    const next_child_slice = try next_kv_pair.key_cursor.readBytes(&next_child_bytes);
                                    next_line_id = blk: {
                                        var line_id_reader = std.Io.Reader.fixed(next_child_slice);
                                        break :blk @bitCast(try line_id_reader.takeInt(patch.LineId(repo_opts.hash).Int, .big));
                                    };
                                    next_line_id_hash = hash.hashInt(repo_opts.hash, next_child_slice);
                                    if (join_line_id_hash_maybe) |join_line_id_hash| {
                                        if (next_line_id_hash != join_line_id_hash) {
                                            try base_line_ids.append(self.parent.allocator, next_line_id);
                                        } else {
                                            break;
                                        }
                                    } else {
                                        try base_line_ids.append(self.parent.allocator, next_line_id);
                                    }
                                } else {
                                    break;
                                }
                            }
                        }

                        // set the current line id to be the parent of the join line id if it exists,
                        // otherwise we're at the end of the file
                        if (join_line_id_hash_maybe) |join_line_id_hash| {
                            if (source_line_ids.items.len == 0) return error.ExpectedAtLeastOneSourceLineId;
                            const join_parent_line_id = source_line_ids.items[source_line_ids.items.len - 1];
                            var join_parent_bytes = [_]u8{0} ** patch.LineId(repo_opts.hash).byte_size;
                            {
                                var line_id_writer = std.Io.Writer.fixed(&join_parent_bytes);
                                try line_id_writer.writeInt(patch.LineId(repo_opts.hash).Int, @bitCast(join_parent_line_id), .big);
                            }
                            const join_parent_line_id_hash = hash.hashInt(repo_opts.hash, &join_parent_bytes);
                            self.parent.current_line_id_hash = join_parent_line_id_hash;

                            // TODO: is it actually guaranteed that the join line is in base?
                            if (self.parent.base_live_parent_to_children) |base_live_parent_to_children| {
                                if (null == try base_live_parent_to_children.getCursor(join_line_id_hash)) return error.ExpectedBaseToContainJoinLine;
                            }
                        } else {
                            self.parent.current_line_id_hash = null;
                        }

                        var base_lines = try LineRange.init(self.parent.state, self.parent.io, self.parent.allocator, self.parent.patch_id_to_offset_list, base_line_ids.items);
                        defer base_lines.deinit(self.parent.allocator);
                        var target_lines = try LineRange.init(self.parent.state, self.parent.io, self.parent.allocator, self.parent.patch_id_to_offset_list, target_line_ids.items);
                        defer target_lines.deinit(self.parent.allocator);
                        var source_lines = try LineRange.init(self.parent.state, self.parent.io, self.parent.allocator, self.parent.patch_id_to_offset_list, source_line_ids.items);
                        defer source_lines.deinit(self.parent.allocator);

                        // if base == target or target == source, return source to autoresolve conflict
                        if (base_lines.eql(target_lines) or target_lines.eql(source_lines)) {
                            if (source_lines.lines.items.len > 0) {
                                try self.parent.line_buffer.appendSlice(self.parent.allocator, source_lines.lines.items);
                                self.parent.current_line = self.parent.line_buffer.items[0];
                                source_lines.lines.clearAndFree(self.parent.allocator);
                            }
                            return self.readStep(buf);
                        }
                        // if base == source, return target to autoresolve conflict
                        else if (base_lines.eql(source_lines)) {
                            if (target_lines.lines.items.len > 0) {
                                try self.parent.line_buffer.appendSlice(self.parent.allocator, target_lines.lines.items);
                                self.parent.current_line = self.parent.line_buffer.items[0];
                                target_lines.lines.clearAndFree(self.parent.allocator);
                            }
                            return self.readStep(buf);
                        }

                        // return conflict

                        const target_marker = try self.parent.allocator.dupe(u8, self.parent.target_marker);
                        {
                            errdefer self.parent.allocator.free(target_marker);
                            try self.parent.line_buffer.append(self.parent.allocator, target_marker);
                        }
                        try self.parent.line_buffer.appendSlice(self.parent.allocator, target_lines.lines.items);
                        target_lines.lines.clearAndFree(self.parent.allocator);

                        const base_marker = try self.parent.allocator.dupe(u8, self.parent.base_marker);
                        {
                            errdefer self.parent.allocator.free(base_marker);
                            try self.parent.line_buffer.append(self.parent.allocator, base_marker);
                        }
                        try self.parent.line_buffer.appendSlice(self.parent.allocator, base_lines.lines.items);
                        base_lines.lines.clearAndFree(self.parent.allocator);

                        const separate_marker = try self.parent.allocator.dupe(u8, self.parent.separate_marker);
                        {
                            errdefer self.parent.allocator.free(separate_marker);
                            try self.parent.line_buffer.append(self.parent.allocator, separate_marker);
                        }

                        try self.parent.line_buffer.appendSlice(self.parent.allocator, source_lines.lines.items);
                        source_lines.lines.clearAndFree(self.parent.allocator);
                        const source_marker = try self.parent.allocator.dupe(u8, self.parent.source_marker);
                        {
                            errdefer self.parent.allocator.free(source_marker);
                            try self.parent.line_buffer.append(self.parent.allocator, source_marker);
                        }

                        self.parent.current_line = self.parent.line_buffer.items[0];
                        self.parent.has_conflict = true;
                    } else {
                        var offset_list_cursor = (try self.parent.patch_id_to_offset_list.getCursor(first_line_id.patch_id)) orelse return error.KeyNotFound;
                        const line = try readLine(self.parent.state, self.parent.io, self.parent.allocator, &offset_list_cursor, first_line_id);
                        errdefer self.parent.allocator.free(line);
                        try self.parent.line_buffer.append(self.parent.allocator, line);
                        self.parent.current_line = self.parent.line_buffer.items[0];

                        const next_children_cursor = (try self.parent.merge_live_parent_to_children.getCursor(first_line_id_hash)) orelse return error.KeyNotFound;
                        var next_children_iter = try next_children_cursor.iterator();
                        if (try next_children_iter.next()) |_| {
                            self.parent.current_line_id_hash = first_line_id_hash;
                        } else {
                            self.parent.current_line_id_hash = null;
                        }
                    }
                    return self.readStep(buf);
                } else {
                    return 0;
                }
            }
        };

        pub fn seekTo(self: *@This(), offset: usize) !void {
            for (self.line_buffer.items) |buffer| {
                self.allocator.free(buffer);
            }
            self.line_buffer.clearAndFree(self.allocator);
            self.current_line = null;
            self.current_line_id_hash = hash.hashInt(repo_opts.hash, &patch.LineId(repo_opts.hash).first_bytes);
            self.has_conflict = false;
            self.interface.seek = 0;
            self.interface.end = 0;

            for (0..offset) |_| {
                _ = try self.reader().readByte();
            }
        }

        pub fn reader(self: *@This()) Reader {
            return Reader{
                .parent = self,
            };
        }

        pub fn count(self: *@This()) !usize {
            var n: usize = 0;
            var read_buffer = [_]u8{0} ** repo_opts.read_size;
            try self.seekTo(0);
            while (true) {
                const size = try self.reader().read(&read_buffer);
                if (size == 0) {
                    break;
                }
                n += size;
            }
            return n;
        }

        fn stream(io_r: *std.Io.Reader, io_w: *std.Io.Writer, limit: std.Io.Limit) std.Io.Reader.StreamError!usize {
            const r: *@This() = @alignCast(@fieldParentPtr("interface", io_r));
            const dest = limit.slice(try io_w.writableSliceGreedy(1));
            const size = r.reader().read(dest) catch return error.ReadFailed;
            if (size == 0) return error.EndOfStream;
            io_w.advance(size);
            return size;
        }
    };

    const target_marker = try std.fmt.allocPrint(allocator, "<<<<<<< target ({s})", .{target_name});
    defer allocator.free(target_marker);
    const base_marker = try std.fmt.allocPrint(allocator, "||||||| base ({s})", .{base_oid});
    defer allocator.free(base_marker);
    const separate_marker = try std.fmt.allocPrint(allocator, "=======", .{});
    defer allocator.free(separate_marker);
    const source_marker = try std.fmt.allocPrint(allocator, ">>>>>>> source ({s})", .{source_name});
    defer allocator.free(source_marker);

    var stream_buffer = [_]u8{0} ** repo_opts.buffer_size;
    var stream = Stream{
        .state = state.readOnly(),
        .io = io,
        .allocator = allocator,
        .target_marker = target_marker,
        .base_marker = base_marker,
        .separate_marker = separate_marker,
        .source_marker = source_marker,
        .merge_live_parent_to_children = &merge_live_parent_to_children,
        .base_live_parent_to_children = if (base_live_parent_to_children_maybe) |*map| map else null,
        .target_live_parent_to_children = &target_live_parent_to_children,
        .source_live_parent_to_children = &source_live_parent_to_children,
        .patch_id_to_offset_list = &patch_id_to_offset_list,
        .line_buffer = &line_buffer,
        .current_line = null,
        .current_line_id_hash = hash.hashInt(repo_opts.hash, &patch.LineId(repo_opts.hash).first_bytes),
        .has_conflict = false,
        .interface = .{
            .vtable = &.{ .stream = Stream.stream },
            .buffer = &stream_buffer,
            .seek = 0,
            .end = 0,
        },
    };

    const header = obj.ObjectHeader{ .kind = .blob, .size = try stream.count() };
    has_conflict.* = stream.has_conflict;
    try stream.seekTo(0);

    var oid = [_]u8{0} ** hash.byteLen(repo_opts.hash);
    try obj.writeObject(.xit, repo_opts, state, io, &stream.interface, header, &oid);
    return oid;
}

pub fn SamePathConflictResult(comptime hash_kind: hash.HashKind) type {
    return struct {
        change: ?tr.Change(hash_kind),
        conflict: ?MergeConflict(hash_kind),
    };
}

fn samePathConflict(
    comptime repo_kind: rp.RepoKind,
    comptime repo_opts: rp.RepoOpts(repo_kind),
    state: rp.Repo(repo_kind, repo_opts).State(.read_write),
    io: std.Io,
    allocator: std.mem.Allocator,
    base_oid: *const [hash.hexLen(repo_opts.hash)]u8,
    target_oid: *const [hash.hexLen(repo_opts.hash)]u8,
    source_oid: *const [hash.hexLen(repo_opts.hash)]u8,
    target_name: []const u8,
    source_name: []const u8,
    target_change_maybe: ?tr.Change(repo_opts.hash),
    source_change: tr.Change(repo_opts.hash),
    path: []const u8,
    merge_algo: MergeAlgorithm,
) !SamePathConflictResult(repo_opts.hash) {
    if (target_change_maybe) |target_change| {
        const base_entry_maybe = source_change.old;

        if (target_change.new) |target_entry| {
            if (source_change.new) |source_entry| {
                if (target_entry.eql(source_entry)) {
                    // the target and source changes are the same,
                    // so no need to do anything
                    return .{ .change = null, .conflict = null };
                }

                // three-way merge of the oids
                const oid_maybe = blk: {
                    if (std.mem.eql(u8, &target_entry.oid, &source_entry.oid)) {
                        break :blk target_entry.oid;
                    } else if (base_entry_maybe) |base_entry| {
                        if (std.mem.eql(u8, &base_entry.oid, &target_entry.oid)) {
                            break :blk source_entry.oid;
                        } else if (std.mem.eql(u8, &base_entry.oid, &source_entry.oid)) {
                            break :blk target_entry.oid;
                        }
                    }
                    break :blk null;
                };

                // three-way merge of the modes
                const mode_maybe = blk: {
                    if (target_entry.mode.eqlExact(source_entry.mode)) {
                        break :blk target_entry.mode;
                    } else if (base_entry_maybe) |base_entry| {
                        if (base_entry.mode.eqlExact(target_entry.mode)) {
                            break :blk source_entry.mode;
                        } else if (base_entry.mode.eqlExact(source_entry.mode)) {
                            break :blk target_entry.mode;
                        }
                    }
                    break :blk null;
                };

                var has_conflict = oid_maybe == null or mode_maybe == null;

                const base_file_oid_maybe = if (base_entry_maybe) |base_entry| &base_entry.oid else null;
                const oid = oid_maybe orelse switch (merge_algo) {
                    .diff3 => try writeBlobWithDiff3(repo_kind, repo_opts, state, io, allocator, base_file_oid_maybe, &target_entry.oid, &source_entry.oid, base_oid, target_name, source_name, &has_conflict),
                    .patch => try writeBlobWithPatches(repo_kind, repo_opts, state, io, allocator, &source_entry.oid, base_oid, target_oid, source_oid, target_name, source_name, &has_conflict, path),
                };
                const mode = mode_maybe orelse target_entry.mode;

                return .{
                    .change = .{
                        .old = target_change.new,
                        .new = .{ .oid = oid, .mode = mode },
                    },
                    .conflict = if (has_conflict)
                        .{
                            .base = base_entry_maybe,
                            .target = target_entry,
                            .source = source_entry,
                            .renamed = null,
                        }
                    else
                        null,
                };
            } else {
                // source is null so just use the target oid and mode
                return .{
                    .change = .{
                        .old = target_change.new,
                        .new = .{ .oid = target_entry.oid, .mode = target_entry.mode },
                    },
                    .conflict = .{
                        .base = base_entry_maybe,
                        .target = target_entry,
                        .source = null,
                        .renamed = null,
                    },
                };
            }
        } else {
            if (source_change.new) |source_entry| {
                // target is null so just use the source oid and mode
                return .{
                    .change = .{
                        .old = target_change.new,
                        .new = .{ .oid = source_entry.oid, .mode = source_entry.mode },
                    },
                    .conflict = .{
                        .base = base_entry_maybe,
                        .target = null,
                        .source = source_entry,
                        .renamed = null,
                    },
                };
            } else {
                // deleted in target and source change,
                // so no need to do anything
                return .{ .change = null, .conflict = null };
            }
        }
    } else {
        // no conflict because the target diff doesn't touch this path
        return .{ .change = source_change, .conflict = null };
    }
}

fn fileDirConflict(
    arena: *std.heap.ArenaAllocator,
    comptime repo_kind: rp.RepoKind,
    comptime repo_opts: rp.RepoOpts(repo_kind),
    path: []const u8,
    diff: *tr.TreeDiff(repo_kind, repo_opts),
    diff_kind: enum { target, source },
    branch_name: []const u8,
    conflicts: *std.StringArrayHashMap(MergeConflict(repo_opts.hash)),
    clean_diff: *tr.TreeDiff(repo_kind, repo_opts),
) !void {
    var parent_path_maybe = std.fs.path.dirname(path);
    while (parent_path_maybe) |parent_path| {
        if (diff.changes.get(parent_path)) |change| {
            if (change.new) |new| {
                const new_path = try std.fmt.allocPrint(arena.allocator(), "{s}~{s}", .{ parent_path, branch_name });
                switch (diff_kind) {
                    .target => {
                        // add the conflict
                        try conflicts.put(parent_path, .{
                            .base = change.old,
                            .target = new,
                            .source = null,
                            .renamed = .{
                                .path = new_path,
                                .tree_entry = new,
                            },
                        });
                        // remove from the work dir
                        try clean_diff.changes.put(parent_path, .{ .old = new, .new = null });
                    },
                    .source => {
                        // add the conflict
                        try conflicts.put(parent_path, .{
                            .base = change.old,
                            .target = null,
                            .source = new,
                            .renamed = .{
                                .path = new_path,
                                .tree_entry = new,
                            },
                        });
                        // prevent from being added to work dir
                        _ = clean_diff.changes.swapRemove(parent_path);
                    },
                }
            }
        }
        parent_path_maybe = std.fs.path.dirname(parent_path);
    }
}

const merge_head_names = &[_][]const u8{ "MERGE_HEAD", "CHERRY_PICK_HEAD" };
const merge_msg_name = "MERGE_MSG";

pub fn checkForUnfinishedMerge(
    comptime repo_kind: rp.RepoKind,
    comptime repo_opts: rp.RepoOpts(repo_kind),
    state: rp.Repo(repo_kind, repo_opts).State(.read_only),
    io: std.Io,
) !void {
    for (merge_head_names) |head_name| {
        if (null != try rf.readRecur(repo_kind, repo_opts, state, io, .{ .ref = .{ .kind = .none, .name = head_name } })) {
            return error.UnfinishedMergeInProgress;
        }
    }
}

pub fn checkForOtherMerge(
    comptime repo_kind: rp.RepoKind,
    comptime repo_opts: rp.RepoOpts(repo_kind),
    state: rp.Repo(repo_kind, repo_opts).State(.read_only),
    io: std.Io,
    merge_head_name: []const u8,
) !void {
    for (merge_head_names) |head_name| {
        if (std.mem.eql(u8, merge_head_name, head_name)) {
            continue;
        }
        if (null != try rf.readRecur(repo_kind, repo_opts, state, io, .{ .ref = .{ .kind = .none, .name = head_name } })) {
            return error.OtherMergeInProgress;
        }
    }
}

pub fn readAnyMergeHead(
    comptime repo_kind: rp.RepoKind,
    comptime repo_opts: rp.RepoOpts(repo_kind),
    state: rp.Repo(repo_kind, repo_opts).State(.read_only),
    io: std.Io,
) !?[hash.hexLen(repo_opts.hash)]u8 {
    for (merge_head_names) |head_name| {
        if (try rf.readRecur(repo_kind, repo_opts, state, io, .{ .ref = .{ .kind = .none, .name = head_name } })) |source_oid| {
            return source_oid;
        }
    }
    return null;
}

pub fn removeMergeState(
    comptime repo_kind: rp.RepoKind,
    comptime repo_opts: rp.RepoOpts(repo_kind),
    state: rp.Repo(repo_kind, repo_opts).State(.read_write),
    io: std.Io,
) !void {
    for (merge_head_names) |merge_head_name| {
        rf.remove(repo_kind, repo_opts, state, io, merge_head_name) catch |err| switch (err) {
            error.RefNotFound => {},
            else => |e| return e,
        };
    }

    state.core.repo_dir.deleteFile(io, merge_msg_name) catch |err| switch (err) {
        error.FileNotFound => {},
        else => |e| return e,
    };

    if (.xit == repo_kind) {
        _ = try state.extra.moment.remove(hash.hashInt(repo_opts.hash, "merge-in-progress"));
    }
}

pub const MergeKind = enum {
    full, // merge
    pick, // cherry-pick
};

pub const MergeAlgorithm = enum {
    diff3, // three-way merge
    patch, // patch-based (xit only)
};

pub fn MergeAction(comptime hash_kind: hash.HashKind) type {
    return union(enum) {
        new: struct {
            source: []const rf.RefOrOid(hash_kind),
            algo: ?MergeAlgorithm = null,
        },
        cont,
    };
}

pub fn MergeInput(comptime hash_kind: hash.HashKind) type {
    return struct {
        kind: MergeKind,
        action: MergeAction(hash_kind),
        commit_metadata: ?obj.CommitMetadata(hash_kind) = null,
    };
}

pub fn Merge(comptime repo_kind: rp.RepoKind, comptime repo_opts: rp.RepoOpts(repo_kind)) type {
    return struct {
        arena: *std.heap.ArenaAllocator,
        allocator: std.mem.Allocator,
        changes: std.StringArrayHashMap(tr.Change(repo_opts.hash)),
        auto_resolved_conflicts: std.StringArrayHashMap(void),
        base_oid: [hash.hexLen(repo_opts.hash)]u8,
        target_name: []const u8,
        source_name: []const u8,
        result: union(enum) {
            success: struct {
                oid: [hash.hexLen(repo_opts.hash)]u8,
            },
            nothing,
            fast_forward,
            conflict: struct {
                conflicts: std.StringArrayHashMap(MergeConflict(repo_opts.hash)),
            },
        },

        pub fn init(
            state: rp.Repo(repo_kind, repo_opts).State(.read_write),
            io: std.Io,
            allocator: std.mem.Allocator,
            merge_input: MergeInput(repo_opts.hash),
            progress_ctx_maybe: ?repo_opts.ProgressCtx,
        ) !Merge(repo_kind, repo_opts) {
            // TODO: exit early if work dir is dirty

            const arena = try allocator.create(std.heap.ArenaAllocator);
            arena.* = std.heap.ArenaAllocator.init(allocator);
            errdefer {
                arena.deinit();
                allocator.destroy(arena);
            }

            // get the current branch name and oid
            const target_buffer = try arena.allocator().alloc(u8, rf.MAX_REF_CONTENT_SIZE);
            const target_ref_or_oid = try rf.readHead(repo_kind, repo_opts, state.readOnly(), io, target_buffer) orelse return error.TargetNotFound;
            const target_name = switch (target_ref_or_oid) {
                .ref => |ref| ref.name,
                .oid => |oid| oid,
            };
            const target_oid_maybe = try rf.readRecur(repo_kind, repo_opts, state.readOnly(), io, target_ref_or_oid);

            // init the diff that we will use for the migration and the conflicts maps.
            // they're using the arena because they'll be included in the result.
            var clean_diff = tr.TreeDiff(repo_kind, repo_opts).init(arena.allocator());
            var auto_resolved_conflicts = std.StringArrayHashMap(void).init(arena.allocator());
            var conflicts = std.StringArrayHashMap(MergeConflict(repo_opts.hash)).init(arena.allocator());

            const merge_head_name = switch (merge_input.kind) {
                .full => merge_head_names[0],
                .pick => merge_head_names[1],
            };

            switch (merge_input.action) {
                .new => |action| {
                    const source_ref_or_oid = switch (action.source.len) {
                        0 => return error.InvalidNumberOfSources,
                        1 => action.source[0],
                        else => return error.OctopusMergeNotYetSupported,
                    };

                    // make sure there is no unfinished merge in progress
                    try checkForUnfinishedMerge(repo_kind, repo_opts, state.readOnly(), io);

                    const merge_algo: MergeAlgorithm = action.algo orelse switch (repo_kind) {
                        .git => .diff3,
                        .xit => blk: {
                            var config = try cfg.Config(repo_kind, repo_opts).init(state.readOnly(), io, allocator);
                            defer config.deinit();

                            if (config.sections.get("merge")) |merge_section| {
                                if (merge_section.get("algorithm")) |algo| {
                                    if (std.mem.eql(u8, "diff3", algo)) {
                                        break :blk .diff3;
                                    } else if (std.mem.eql(u8, "patch", algo)) {
                                        break :blk .patch;
                                    } else {
                                        return error.InvalidMergeAlgorithm;
                                    }
                                }
                            }

                            break :blk .patch;
                        },
                    };

                    // we need to return the source name so copy it into a new buffer
                    // so we an ensure it lives as long as the rest of the return struct
                    const source_name = try arena.allocator().dupe(u8, switch (source_ref_or_oid) {
                        .ref => |ref| ref.name,
                        .oid => |oid| oid,
                    });

                    // get the source and target oid
                    const source_oid = try rf.readRecur(repo_kind, repo_opts, state.readOnly(), io, source_ref_or_oid) orelse return error.InvalidMergeSource;
                    const target_oid = target_oid_maybe orelse {
                        // the target branch is completely empty, so just set it to the source oid
                        try rf.writeRecur(repo_kind, repo_opts, state, io, "HEAD", &source_oid);

                        // make a TreeDiff that adds all files from source
                        try clean_diff.compare(state.readOnly(), io, null, &source_oid, null);

                        // read index
                        var index = try idx.Index(repo_kind, repo_opts).init(state.readOnly(), io, allocator);
                        defer index.deinit();

                        // update the work dir
                        try work.migrate(repo_kind, repo_opts, state, io, allocator, clean_diff, &index, true, null);

                        return .{
                            .arena = arena,
                            .allocator = allocator,
                            .changes = clean_diff.changes,
                            .auto_resolved_conflicts = auto_resolved_conflicts,
                            .base_oid = [_]u8{0} ** hash.hexLen(repo_opts.hash),
                            .target_name = target_name,
                            .source_name = source_name,
                            .result = .fast_forward,
                        };
                    };

                    // get the base oid
                    var base_oid: [hash.hexLen(repo_opts.hash)]u8 = undefined;
                    switch (merge_input.kind) {
                        .full => base_oid = try commonAncestor(repo_kind, repo_opts, state.readOnly(), io, allocator, &target_oid, &source_oid),
                        .pick => {
                            var object = try obj.Object(repo_kind, repo_opts, .full).init(state.readOnly(), io, allocator, &source_oid);
                            defer object.deinit();
                            const parent_oid = object.content.commit.metadata.firstParent() orelse return error.CommitMustHaveOneParent;
                            switch (object.content) {
                                .commit => base_oid = parent_oid.*,
                                else => return error.CommitObjectNotFound,
                            }
                        },
                    }

                    // if the base ancestor is the source oid, do nothing
                    if (std.mem.eql(u8, &source_oid, &base_oid)) {
                        return .{
                            .arena = arena,
                            .allocator = allocator,
                            .changes = clean_diff.changes,
                            .auto_resolved_conflicts = auto_resolved_conflicts,
                            .base_oid = base_oid,
                            .target_name = target_name,
                            .source_name = source_name,
                            .result = .nothing,
                        };
                    }

                    // Lazy patch generation
                    if (repo_kind == .xit and merge_algo == .patch) {
                        try writePossiblePatches(repo_opts, state, io, allocator, &target_oid, &source_oid, progress_ctx_maybe);
                    }

                    // diff the base ancestor with the target oid
                    var target_diff = tr.TreeDiff(repo_kind, repo_opts).init(arena.allocator());
                    try target_diff.compare(state.readOnly(), io, &base_oid, &target_oid, null);

                    // diff the base ancestor with the source oid
                    var source_diff = tr.TreeDiff(repo_kind, repo_opts).init(arena.allocator());
                    try source_diff.compare(state.readOnly(), io, &base_oid, &source_oid, null);

                    // look for same path conflicts while populating the clean diff
                    for (source_diff.changes.keys(), source_diff.changes.values()) |path, source_change| {
                        const same_path_result = try samePathConflict(repo_kind, repo_opts, state, io, allocator, &base_oid, &target_oid, &source_oid, target_name, source_name, target_diff.changes.get(path), source_change, path, merge_algo);
                        if (same_path_result.change) |change| {
                            try clean_diff.changes.put(path, change);
                        }
                        if (same_path_result.conflict) |conflict| {
                            try conflicts.put(path, conflict);
                        } else {
                            try auto_resolved_conflicts.put(path, {});
                        }
                    }

                    // look for file/dir conflicts
                    for (source_diff.changes.keys(), source_diff.changes.values()) |path, source_change| {
                        if (source_change.new) |_| {
                            try fileDirConflict(arena, repo_kind, repo_opts, path, &target_diff, .target, target_name, &conflicts, &clean_diff);
                        }
                    }
                    for (target_diff.changes.keys(), target_diff.changes.values()) |path, target_change| {
                        if (target_change.new) |_| {
                            try fileDirConflict(arena, repo_kind, repo_opts, path, &source_diff, .source, source_name, &conflicts, &clean_diff);
                        }
                    }

                    // create commit message
                    var commit_metadata: obj.CommitMetadata(repo_opts.hash) = merge_input.commit_metadata orelse switch (merge_input.kind) {
                        .full => .{
                            .message = try std.fmt.allocPrint(arena.allocator(), "merge from {s}", .{source_name}),
                        },
                        .pick => blk: {
                            const object = try obj.Object(repo_kind, repo_opts, .full).init(state.readOnly(), io, arena.allocator(), &source_oid);
                            switch (object.content) {
                                .commit => break :blk object.content.commit.metadata,
                                else => return error.CommitObjectNotFound,
                            }
                        },
                    };

                    switch (repo_kind) {
                        .git => {
                            // create lock file
                            var lock = try fs.LockFile.init(io, state.core.repo_dir, "index");
                            defer lock.deinit(io);

                            // read index
                            var index = try idx.Index(repo_kind, repo_opts).init(state.readOnly(), io, allocator);
                            defer index.deinit();

                            // update the work dir
                            try work.migrate(repo_kind, repo_opts, state, io, allocator, clean_diff, &index, true, null);

                            for (conflicts.keys(), conflicts.values()) |path, conflict| {
                                // add conflict to index
                                try index.addConflictEntries(path, .{ conflict.base, conflict.target, conflict.source });
                                // write renamed file if necessary
                                if (conflict.renamed) |renamed| {
                                    try work.objectToFile(repo_kind, repo_opts, state.readOnly(), io, allocator, renamed.path, renamed.tree_entry);
                                }
                            }

                            // update the index
                            try index.write(allocator, .{ .core = state.core, .extra = .{ .lock_file_maybe = lock.lock_file } }, io);

                            // finish lock
                            lock.success = true;

                            // exit early if there were conflicts
                            if (conflicts.count() > 0) {
                                try rf.write(repo_kind, repo_opts, state, io, merge_head_name, .{ .oid = &source_oid });

                                const merge_msg = try state.core.repo_dir.createFile(io, merge_msg_name, .{ .truncate = true, .lock = .exclusive });
                                defer merge_msg.close(io);
                                try merge_msg.writeStreamingAll(io, commit_metadata.message orelse "");

                                return .{
                                    .arena = arena,
                                    .allocator = allocator,
                                    .changes = clean_diff.changes,
                                    .auto_resolved_conflicts = auto_resolved_conflicts,
                                    .base_oid = base_oid,
                                    .target_name = target_name,
                                    .source_name = source_name,
                                    .result = .{ .conflict = .{ .conflicts = conflicts } },
                                };
                            }
                        },
                        .xit => {
                            // read index
                            var index = try idx.Index(repo_kind, repo_opts).init(state.readOnly(), io, allocator);
                            defer index.deinit();

                            // update the work dir
                            try work.migrate(repo_kind, repo_opts, state, io, allocator, clean_diff, &index, true, null);

                            for (conflicts.keys(), conflicts.values()) |path, conflict| {
                                // add conflict to index
                                try index.addConflictEntries(path, .{ conflict.base, conflict.target, conflict.source });
                                // write renamed file if necessary
                                if (conflict.renamed) |renamed| {
                                    try work.objectToFile(repo_kind, repo_opts, state.readOnly(), io, allocator, renamed.path, renamed.tree_entry);
                                }
                            }

                            // add conflicts to index
                            for (conflicts.keys(), conflicts.values()) |path, conflict| {
                                try index.addConflictEntries(path, .{ conflict.base, conflict.target, conflict.source });
                            }

                            // update the index
                            try index.write(allocator, state, io);

                            // exit early if there were conflicts
                            if (conflicts.count() > 0) {
                                try rf.write(repo_kind, repo_opts, state, io, merge_head_name, .{ .oid = &source_oid });

                                const merge_msg = try state.core.repo_dir.createFile(io, merge_msg_name, .{ .truncate = true, .lock = .exclusive });
                                defer merge_msg.close(io);
                                try merge_msg.writeStreamingAll(io, commit_metadata.message orelse "");

                                return .{
                                    .arena = arena,
                                    .allocator = allocator,
                                    .changes = clean_diff.changes,
                                    .auto_resolved_conflicts = auto_resolved_conflicts,
                                    .base_oid = base_oid,
                                    .target_name = target_name,
                                    .source_name = source_name,
                                    .result = .{ .conflict = .{ .conflicts = conflicts } },
                                };
                            } else {
                                // if any file conflicts were auto-resolved, there will be temporary state that must be cleaned up
                                try removeMergeState(repo_kind, repo_opts, state, io);
                            }
                        },
                    }

                    if (std.mem.eql(u8, &target_oid, &base_oid)) {
                        // the base ancestor is the target oid, so just update HEAD
                        try rf.writeRecur(repo_kind, repo_opts, state, io, "HEAD", &source_oid);
                        return .{
                            .arena = arena,
                            .allocator = allocator,
                            .changes = clean_diff.changes,
                            .auto_resolved_conflicts = auto_resolved_conflicts,
                            .base_oid = base_oid,
                            .target_name = target_name,
                            .source_name = source_name,
                            .result = .fast_forward,
                        };
                    }

                    // commit the change
                    commit_metadata.parent_oids = switch (merge_input.kind) {
                        .full => &.{ target_oid, source_oid },
                        .pick => &.{target_oid},
                    };
                    const commit_oid = try obj.writeCommit(repo_kind, repo_opts, state, io, allocator, commit_metadata);

                    return .{
                        .arena = arena,
                        .allocator = allocator,
                        .changes = clean_diff.changes,
                        .auto_resolved_conflicts = auto_resolved_conflicts,
                        .base_oid = base_oid,
                        .target_name = target_name,
                        .source_name = source_name,
                        .result = .{ .success = .{ .oid = commit_oid } },
                    };
                },
                .cont => {
                    // ensure there are no conflict entries in the index
                    {
                        var index = try idx.Index(repo_kind, repo_opts).init(state.readOnly(), io, allocator);
                        defer index.deinit();

                        for (index.entries.values()) |*entries_for_path| {
                            if (null == entries_for_path[0]) {
                                return error.CannotContinueMergeWithUnresolvedConflicts;
                            }
                        }
                    }

                    // make sure there isn't another kind of merge in progress
                    try checkForOtherMerge(repo_kind, repo_opts, state.readOnly(), io, merge_head_name);

                    const source_oid = try rf.readRecur(repo_kind, repo_opts, state.readOnly(), io, .{ .ref = .{ .kind = .none, .name = merge_head_name } }) orelse return error.MergeHeadNotFound;

                    // read the merge message
                    var commit_metadata: obj.CommitMetadata(repo_opts.hash) = merge_input.commit_metadata orelse .{};
                    commit_metadata.message = state.core.repo_dir.readFileAlloc(io, merge_msg_name, arena.allocator(), .limited(repo_opts.max_read_size)) catch |err| switch (err) {
                        error.FileNotFound => return error.MergeMessageNotFound,
                        else => |e| return e,
                    };

                    // we need to return the source name but we don't have it,
                    // so just copy the source oid into a buffer and return that instead
                    const source_name = try arena.allocator().dupe(u8, &source_oid);

                    // get the base oid
                    var base_oid: [hash.hexLen(repo_opts.hash)]u8 = undefined;
                    const target_oid = target_oid_maybe orelse return error.TargetOidNotFound;
                    switch (merge_input.kind) {
                        .full => base_oid = try commonAncestor(repo_kind, repo_opts, state.readOnly(), io, allocator, &target_oid, &source_oid),
                        .pick => {
                            var object = try obj.Object(repo_kind, repo_opts, .full).init(state.readOnly(), io, allocator, &source_oid);
                            defer object.deinit();
                            const parent_oid = object.content.commit.metadata.firstParent() orelse return error.CommitMustHaveOneParent;
                            switch (object.content) {
                                .commit => base_oid = parent_oid.*,
                                else => return error.CommitObjectNotFound,
                            }
                        },
                    }

                    // clean up the stored merge state
                    try removeMergeState(repo_kind, repo_opts, state, io);

                    // commit the change
                    commit_metadata.parent_oids = switch (merge_input.kind) {
                        .full => &.{ target_oid, source_oid },
                        .pick => &.{target_oid},
                    };
                    const commit_oid = try obj.writeCommit(repo_kind, repo_opts, state, io, allocator, commit_metadata);

                    return .{
                        .arena = arena,
                        .allocator = allocator,
                        .changes = clean_diff.changes,
                        .auto_resolved_conflicts = auto_resolved_conflicts,
                        .base_oid = base_oid,
                        .target_name = target_name,
                        .source_name = source_name,
                        .result = .{ .success = .{ .oid = commit_oid } },
                    };
                },
            }
        }

        pub fn deinit(self: *Merge(repo_kind, repo_opts)) void {
            self.arena.deinit();
            self.allocator.destroy(self.arena);
        }
    };
}

fn writePossiblePatches(
    comptime repo_opts: rp.RepoOpts(.xit),
    state: rp.Repo(.xit, repo_opts).State(.read_write),
    io: std.Io,
    allocator: std.mem.Allocator,
    target_oid: *const [hash.hexLen(repo_opts.hash)]u8,
    source_oid: *const [hash.hexLen(repo_opts.hash)]u8,
    progress_ctx_maybe: ?repo_opts.ProgressCtx,
) !void {
    const patch = @import("./patch.zig");

    var patch_writer = try patch.PatchWriter(repo_opts).init(state.readOnly(), io, allocator);
    defer patch_writer.deinit(io, allocator);

    var source_iter = try obj.ObjectIterator(.xit, repo_opts, .full).init(state.readOnly(), io, allocator, .{ .kind = .commit });
    defer source_iter.deinit();
    try source_iter.include(source_oid);
    while (try source_iter.next()) |commit_object| {
        defer commit_object.deinit();

        const oid = try hash.hexToBytes(repo_opts.hash, commit_object.oid);
        try patch_writer.add(state.readOnly(), io, allocator, &oid);
    }

    var target_iter = try obj.ObjectIterator(.xit, repo_opts, .full).init(state.readOnly(), io, allocator, .{ .kind = .commit });
    defer target_iter.deinit();
    try target_iter.include(target_oid);
    while (try target_iter.next()) |commit_object| {
        defer commit_object.deinit();

        const oid = try hash.hexToBytes(repo_opts.hash, commit_object.oid);
        try patch_writer.add(state.readOnly(), io, allocator, &oid);
    }

    try patch_writer.write(state, io, allocator, progress_ctx_maybe);
}
