const std = @import("std");
const patch = @import("./patch.zig");
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

// commit relationships and traversal shared by ancestry queries and merges.
fn Ancestry(comptime repo_kind: rp.RepoKind, comptime repo_opts: rp.RepoOpts(repo_kind)) type {
    return struct {
        const Self = @This();
        const Oid = [hash.hexLen(repo_opts.hash)]u8;
        const one = 1;
        const two = 2;
        const both = one | two;
        const stale = 4;

        const Node = struct {
            parents: []const Oid = &.{},
            timestamp: u64 = 0,
            tag_target: ?Oid = null,
            flags: u3 = 0,
            queued: bool = false,
        };

        const QueueEntry = struct {
            oid: Oid,
            timestamp: u64,

            fn compare(_: void, a: QueueEntry, b: QueueEntry) std.math.Order {
                // timestamps only choose the work order
                const order = std.math.order(b.timestamp, a.timestamp);
                return if (order == .eq) std.mem.order(u8, &a.oid, &b.oid) else order;
            }
        };

        state: rp.Repo(repo_kind, repo_opts).State(.read_only),
        io: std.Io,
        allocator: std.mem.Allocator,
        arena: std.heap.ArenaAllocator,
        nodes: std.AutoHashMapUnmanaged(Oid, Node) = .empty,
        queue: std.PriorityQueue(QueueEntry, void, QueueEntry.compare) = .empty,
        tips: [2]Oid = undefined,
        // queued commits that haven't been marked stale
        pending: usize = 0,
        base_count: usize = 0,

        fn init(
            state: rp.Repo(repo_kind, repo_opts).State(.read_only),
            io: std.Io,
            allocator: std.mem.Allocator,
            oid1: *const Oid,
            oid2: *const Oid,
        ) !Self {
            var self = Self{ .state = state, .io = io, .allocator = allocator, .arena = std.heap.ArenaAllocator.init(allocator) };
            errdefer self.deinit();
            self.tips = .{ try self.peel(oid1.*), try self.peel(oid2.*) };
            try self.paint(self.tips[0], one);
            try self.paint(self.tips[1], two);
            return self;
        }

        fn deinit(self: *Self) void {
            self.queue.deinit(self.allocator);
            self.nodes.deinit(self.allocator);
            self.arena.deinit();
        }

        fn load(self: *Self, oid: Oid) !*Node {
            const entry = try self.nodes.getOrPut(self.allocator, oid);
            if (entry.found_existing) return entry.value_ptr;
            errdefer _ = self.nodes.remove(oid);

            var object = try obj.Object(repo_kind, repo_opts).init(self.state, self.io, self.allocator, &oid);
            defer object.deinit();
            entry.value_ptr.* = switch (object.content) {
                .commit => |commit| .{
                    .parents = try self.arena.allocator().dupe(Oid, commit.metadata.parent_oids orelse &.{}),
                    .timestamp = commit.metadata.timestamp,
                },
                .tag => |tag| .{ .tag_target = tag.target },
                else => return error.CommitNotFound,
            };
            return entry.value_ptr;
        }

        fn peel(self: *Self, oid: Oid) !Oid {
            var current = oid;
            while ((try self.load(current)).tag_target) |target| current = target;
            return current;
        }

        fn paint(self: *Self, oid: Oid, flags: u3) !void {
            const node = try self.load(oid);
            if (node.tag_target != null) return error.CommitNotFound;
            const combined = node.flags | flags;
            if (combined == node.flags) return;

            if (node.flags == both) self.base_count -= 1;
            if (combined == both) self.base_count += 1;
            if (node.queued and node.flags & stale == 0 and combined & stale != 0) self.pending -= 1;
            node.flags = combined;
            if (!node.queued) {
                try self.queue.push(self.allocator, .{ .oid = oid, .timestamp = node.timestamp });
                node.queued = true;
                if (combined & stale == 0) self.pending += 1;
            }
        }

        fn step(self: *Self) !bool {
            const entry = self.queue.pop() orelse return false;
            const node = self.nodes.getPtr(entry.oid) orelse unreachable;
            node.queued = false;
            if (node.flags & stale == 0) self.pending -= 1;

            // ancestors of a common ancestor cannot be best merge bases
            const flags = node.flags | @as(u3, if (node.flags & both == both) stale else 0);
            // loading parents can move the map, so don't retain a pointer into it
            const parents = node.parents;
            for (parents) |parent| try self.paint(parent, flags);
            return true;
        }

        fn tipIsCommon(self: *const Self, side: usize) bool {
            const node = self.nodes.get(self.tips[side]) orelse unreachable;
            return node.flags & both == both;
        }

        fn commonAncestor(self: *Self) !Oid {
            while (true) {
                if (self.tipIsCommon(0)) return self.tips[0];
                if (self.tipIsCommon(1)) return self.tips[1];
                // stale work still needs to eliminate redundant candidates when there are several
                if (self.pending == 0 and self.base_count <= 1) break;
                if (!try self.step()) break;
            }
            if (self.base_count > 1) return error.MultipleMergeBases;
            var iter = self.nodes.iterator();
            while (iter.next()) |entry| {
                if (entry.value_ptr.flags == both) return entry.key_ptr.*;
            }
            return error.NoCommonAncestor;
        }
    };
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
    var ancestry = try Ancestry(repo_kind, repo_opts).init(state, io, allocator, oid1, oid2);
    defer ancestry.deinit();
    while (true) {
        if (ancestry.tipIsCommon(0)) return ancestry.tips[1];
        if (ancestry.tipIsCommon(1)) return ancestry.tips[0];
        if (ancestry.pending == 0 or !try ancestry.step()) return error.DescendentNotFound;
    }
}

/// returns the unique best common ancestor, rejecting multiple incomparable bases
pub fn commonAncestor(
    comptime repo_kind: rp.RepoKind,
    comptime repo_opts: rp.RepoOpts(repo_kind),
    state: rp.Repo(repo_kind, repo_opts).State(.read_only),
    io: std.Io,
    allocator: std.mem.Allocator,
    oid1: *const [hash.hexLen(repo_opts.hash)]u8,
    oid2: *const [hash.hexLen(repo_opts.hash)]u8,
) ![hash.hexLen(repo_opts.hash)]u8 {
    var ancestry = try Ancestry(repo_kind, repo_opts).init(state, io, allocator, oid1, oid2);
    defer ancestry.deinit();
    return ancestry.commonAncestor();
}

// state shared by all files in a merge: ancestry and cached patch snapshots.
fn MergeContext(comptime repo_kind: rp.RepoKind, comptime repo_opts: rp.RepoOpts(repo_kind)) type {
    return struct {
        const Self = @This();
        const Oid = [hash.hexLen(repo_opts.hash)]u8;

        ancestry: Ancestry(repo_kind, repo_opts),
        arena: std.heap.ArenaAllocator,
        patch_snapshots: switch (repo_kind) {
            .git => enum { uninitialized },
            .xit => union(enum) {
                uninitialized,
                unavailable,
                ready: PatchSnapshots,
            },
        } = .uninitialized,

        // the base, target, and source snapshots used by patch merging.
        const PatchSnapshots = struct {
            const Cursor = rp.Repo(repo_kind, repo_opts).DB.Cursor(.read_only);

            base: Cursor,
            target: Cursor,
            source: []const Cursor, // oldest first
            has_boundary: bool,

            fn load(
                ancestry: *Ancestry(repo_kind, repo_opts),
                allocator: std.mem.Allocator,
                base_oid: *const Oid,
            ) !?PatchSnapshots {
                const DB = rp.Repo(repo_kind, repo_opts).DB;

                // missing derived metadata selects diff3; malformed data and I/O errors propagate.
                const cursor = (try ancestry.state.extra.moment.getCursor(hash.hashInt(repo_opts.hash, "commit-id->snapshot"))) orelse return null;
                const commit_id_to_snapshot = try DB.HashMap(.read_only).init(cursor);
                const target = (try commit_id_to_snapshot.getCursor(try hash.hexToInt(repo_opts.hash, &ancestry.tips[0]))) orelse return null;
                const base = (try commit_id_to_snapshot.getCursor(try hash.hexToInt(repo_opts.hash, base_oid))) orelse return null;

                // the base may not be in source's first-parent history.
                // use the stored depths to find their common first-parent ancestor.
                const patch_base_oid_maybe: ?Oid = ancestor: {
                    const depths_cursor = (try ancestry.state.extra.moment.getCursor(hash.hashInt(repo_opts.hash, obj.COMMIT_ID_TO_FIRST_PARENT_DEPTH_KEY))) orelse return null;
                    const depths = try DB.HashMap(.read_only).init(depths_cursor);
                    var oids = [2]Oid{ base_oid.*, ancestry.tips[1] };
                    var counts: [2]u64 = undefined;
                    for (oids, &counts) |oid, *count| {
                        const depth = (try depths.getCursor(try hash.hexToInt(repo_opts.hash, &oid))) orelse return null;
                        count.* = try depth.readUint();
                    }
                    while (!std.mem.eql(u8, &oids[0], &oids[1])) {
                        const side: usize = if (counts[0] >= counts[1]) 0 else 1;
                        const parents = (try ancestry.load(oids[side])).parents;
                        if (parents.len == 0) break :ancestor null;
                        oids[side] = parents[0];
                        counts[side] = std.math.sub(u64, counts[side], 1) catch return error.InvalidCommitDepth;
                    }
                    break :ancestor oids[0];
                };

                // changes from other parents are already included in a merge commit
                var snapshots: std.ArrayList(Cursor) = .empty;
                var oid_maybe: ?Oid = ancestry.tips[1];
                while (oid_maybe) |oid| {
                    try snapshots.append(allocator, (try commit_id_to_snapshot.getCursor(try hash.hexToInt(repo_opts.hash, &oid))) orelse return null);
                    if (patch_base_oid_maybe) |*patch_base_oid| {
                        if (std.mem.eql(u8, patch_base_oid, &oid)) break;
                    }
                    const parents = (try ancestry.load(oid)).parents;
                    oid_maybe = if (parents.len > 0) parents[0] else null;
                }
                // store application order once for all files in this merge
                std.mem.reverse(Cursor, snapshots.items);
                return .{ .base = base, .target = target, .source = snapshots.items, .has_boundary = patch_base_oid_maybe != null };
            }
        };

        fn init(
            state: rp.Repo(repo_kind, repo_opts).State(.read_only),
            io: std.Io,
            allocator: std.mem.Allocator,
            oid1: *const Oid,
            oid2: *const Oid,
        ) !Self {
            return .{
                .ancestry = try Ancestry(repo_kind, repo_opts).init(state, io, allocator, oid1, oid2),
                .arena = std.heap.ArenaAllocator.init(allocator),
            };
        }

        fn deinit(self: *Self) void {
            self.arena.deinit();
            self.ancestry.deinit();
        }

        fn mergeBase(self: *Self, kind: MergeKind) !Oid {
            const ancestry = &self.ancestry;
            if (kind == .full) return ancestry.commonAncestor();
            const parents = (ancestry.nodes.get(ancestry.tips[1]) orelse unreachable).parents;
            return if (parents.len > 0) parents[0] else error.CommitMustHaveOneParent;
        }

        // shared by all files in one merge, with fixed tips and base. load after
        // patch generation; subsequent blob writes don't change these snapshots.
        fn firstParentSnapshots(self: *Self, base_oid: *const Oid) !?PatchSnapshots {
            switch (self.patch_snapshots) {
                .uninitialized => {},
                .unavailable => return null,
                .ready => |snapshots| return snapshots,
            }

            const result = try PatchSnapshots.load(&self.ancestry, self.arena.allocator(), base_oid);
            self.patch_snapshots = if (result) |snapshots| .{ .ready = snapshots } else .unavailable;
            return result;
        }
    };
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

/// the lines from one side of a conflicted region
const LineRange = struct {
    lines: std.ArrayList([]const u8),

    fn deinit(self: *LineRange, allocator: std.mem.Allocator) void {
        for (self.lines.items) |line| {
            allocator.free(line);
        }
        self.lines.deinit(allocator);
    }

    fn eql(self: LineRange, other: LineRange) bool {
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

/// the marker lines that surround a conflicted region in the merged file
const ConflictMarkers = struct {
    target: []u8,
    base: []u8,
    source: []u8,

    const separate = "=======";

    fn init(allocator: std.mem.Allocator, base_oid: []const u8, target_name: []const u8, source_name: []const u8) !ConflictMarkers {
        const target = try std.fmt.allocPrint(allocator, "<<<<<<< target ({s})", .{target_name});
        errdefer allocator.free(target);
        const base = try std.fmt.allocPrint(allocator, "||||||| base ({s})", .{base_oid});
        errdefer allocator.free(base);
        const source = try std.fmt.allocPrint(allocator, ">>>>>>> source ({s})", .{source_name});
        errdefer allocator.free(source);
        return .{ .target = target, .base = base, .source = source };
    }

    fn deinit(self: *ConflictMarkers, allocator: std.mem.Allocator) void {
        allocator.free(self.target);
        allocator.free(self.base);
        allocator.free(self.source);
    }
};

/// append the resolution of a conflicted region to the line buffer: the
/// autoresolved side if two sides agree, otherwise all three sides wrapped
/// in conflict markers. returns true if there was a conflict. the lines are
/// moved (not copied) out of the given ranges.
fn appendResolvedOrConflict(
    allocator: std.mem.Allocator,
    line_buffer: *std.ArrayList([]const u8),
    markers: *const ConflictMarkers,
    base_lines: *LineRange,
    target_lines: *LineRange,
    source_lines: *LineRange,
) !bool {
    // if base == target or target == source, return source to autoresolve conflict
    if (base_lines.eql(target_lines.*) or target_lines.eql(source_lines.*)) {
        try line_buffer.appendSlice(allocator, source_lines.lines.items);
        source_lines.lines.clearAndFree(allocator);
        return false;
    }
    // if base == source, return target to autoresolve conflict
    else if (base_lines.eql(source_lines.*)) {
        try line_buffer.appendSlice(allocator, target_lines.lines.items);
        target_lines.lines.clearAndFree(allocator);
        return false;
    }

    // return conflict

    const target_marker = try allocator.dupe(u8, markers.target);
    {
        errdefer allocator.free(target_marker);
        try line_buffer.append(allocator, target_marker);
    }
    try line_buffer.appendSlice(allocator, target_lines.lines.items);
    target_lines.lines.clearAndFree(allocator);

    const base_marker = try allocator.dupe(u8, markers.base);
    {
        errdefer allocator.free(base_marker);
        try line_buffer.append(allocator, base_marker);
    }
    try line_buffer.appendSlice(allocator, base_lines.lines.items);
    base_lines.lines.clearAndFree(allocator);

    const separate_marker = try allocator.dupe(u8, ConflictMarkers.separate);
    {
        errdefer allocator.free(separate_marker);
        try line_buffer.append(allocator, separate_marker);
    }

    try line_buffer.appendSlice(allocator, source_lines.lines.items);
    source_lines.lines.clearAndFree(allocator);
    const source_marker = try allocator.dupe(u8, markers.source);
    {
        errdefer allocator.free(source_marker);
        try line_buffer.append(allocator, source_marker);
    }

    return true;
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

    const initLineRange = struct {
        fn init(inner_allocator: std.mem.Allocator, iter: *df.LineIterator(repo_kind, repo_opts), range_maybe: ?df.Diff3Iterator(repo_kind, repo_opts).Range) !LineRange {
            var lines: std.ArrayList([]const u8) = .empty;
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
    }.init;

    const Stream = struct {
        allocator: std.mem.Allocator,
        markers: *const ConflictMarkers,
        base_iter: *df.LineIterator(repo_kind, repo_opts),
        target_iter: *df.LineIterator(repo_kind, repo_opts),
        source_iter: *df.LineIterator(repo_kind, repo_opts),
        diff3_iter: *df.Diff3Iterator(repo_kind, repo_opts),
        line_buffer: std.ArrayList([]const u8) = .empty,
        line_index: usize = 0,
        current_line: ?[]const u8,
        needs_newline: bool = false,
        has_conflict: bool,
        interface: std.Io.Reader,

        fn read(self: *@This(), buf: []u8) !usize {
            var size: usize = 0;
            while (size < buf.len) {
                if (self.current_line != null) {
                    if (self.needs_newline) {
                        buf[size] = '\n';
                        size += 1;
                        self.needs_newline = false;
                    } else {
                        size += self.drainCurrentLine(buf[size..]);
                    }
                    continue;
                }

                const chunk = try self.diff3_iter.next() orelse break;
                switch (chunk) {
                    .clean => |clean| {
                        for (clean.begin..clean.end) |line_num| {
                            const line = try self.base_iter.get(line_num);
                            defer self.base_iter.free(line);
                            {
                                const line_dupe = try self.allocator.dupe(u8, line);
                                errdefer self.allocator.free(line_dupe);
                                try self.line_buffer.append(self.allocator, line_dupe);
                            }
                        }
                    },
                    .conflict => |conflict| {
                        var base_lines = try initLineRange(self.allocator, self.base_iter, conflict.o_range);
                        defer base_lines.deinit(self.allocator);
                        var target_lines = try initLineRange(self.allocator, self.target_iter, conflict.a_range);
                        defer target_lines.deinit(self.allocator);
                        var source_lines = try initLineRange(self.allocator, self.source_iter, conflict.b_range);
                        defer source_lines.deinit(self.allocator);

                        if (try appendResolvedOrConflict(self.allocator, &self.line_buffer, self.markers, &base_lines, &target_lines, &source_lines)) {
                            self.has_conflict = true;
                        }
                    },
                }
                if (self.line_buffer.items.len > 0) {
                    self.current_line = self.line_buffer.items[0];
                }
            }
            return size;
        }

        /// copy from the current line and defer the newline until another line follows
        fn drainCurrentLine(self: *@This(), buf: []u8) usize {
            const current_line = self.current_line orelse return 0;
            const size = @min(buf.len, current_line.len);
            @memcpy(buf[0..size], current_line[0..size]);
            self.current_line = current_line[size..];
            if (size < current_line.len) return size;

            self.allocator.free(self.line_buffer.items[self.line_index]);
            self.line_index += 1;
            if (self.line_index < self.line_buffer.items.len) {
                self.current_line = self.line_buffer.items[self.line_index];
            } else {
                self.line_buffer.clearRetainingCapacity();
                self.line_index = 0;
                self.current_line = null;
            }
            self.needs_newline = true;
            return size;
        }

        pub fn reset(self: *@This()) !void {
            try self.base_iter.reset();
            try self.target_iter.reset();
            try self.source_iter.reset();
            try self.diff3_iter.reset();
            for (self.line_buffer.items[self.line_index..]) |buffer| {
                self.allocator.free(buffer);
            }
            self.line_buffer.clearAndFree(self.allocator);
            self.line_index = 0;
            self.current_line = null;
            self.needs_newline = false;
            self.has_conflict = false;
            self.interface.seek = 0;
            self.interface.end = 0;
        }

        pub fn count(self: *@This()) !usize {
            var n: usize = 0;
            var read_buffer = [_]u8{0} ** repo_opts.read_size;
            try self.reset();
            while (true) {
                const size = try self.read(&read_buffer);
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
            const size = r.read(dest) catch return error.ReadFailed;
            if (size == 0) return error.EndOfStream;
            io_w.advance(size);
            return size;
        }
    };

    var markers = try ConflictMarkers.init(allocator, base_oid, target_name, source_name);
    defer markers.deinit(allocator);

    var stream_buffer = [_]u8{0} ** repo_opts.buffer_size;
    var stream = Stream{
        .allocator = allocator,
        .markers = &markers,
        .base_iter = &base_iter,
        .target_iter = &target_iter,
        .source_iter = &source_iter,
        .diff3_iter = &diff3_iter,
        .current_line = null,
        .has_conflict = false,
        .interface = .{
            .vtable = &.{ .stream = Stream.stream },
            .buffer = &stream_buffer,
            .seek = 0,
            .end = 0,
        },
    };
    defer {
        for (stream.line_buffer.items[stream.line_index..]) |buffer| allocator.free(buffer);
        stream.line_buffer.deinit(allocator);
    }

    const header = obj.ObjectHeader{ .kind = .blob, .size = try stream.count() };
    has_conflict.* = stream.has_conflict;
    try stream.reset();

    var oid = [_]u8{0} ** hash.byteLen(repo_opts.hash);
    try obj.writeObject(repo_kind, repo_opts, state, io, allocator, &stream.interface, header, &oid);
    return oid;
}

fn writeBlobWithPatches(
    comptime repo_opts: rp.RepoOpts(.xit),
    state: rp.Repo(.xit, repo_opts).State(.read_write),
    io: std.Io,
    allocator: std.mem.Allocator,
    base_file_oid_maybe: ?*const [hash.byteLen(repo_opts.hash)]u8,
    target_file_oid: *const [hash.byteLen(repo_opts.hash)]u8,
    source_file_oid: *const [hash.byteLen(repo_opts.hash)]u8,
    base_oid: *const [hash.hexLen(repo_opts.hash)]u8,
    target_name: []const u8,
    source_name: []const u8,
    has_conflict: *bool,
    path: []const u8,
    context: *MergeContext(.xit, repo_opts),
) !?[hash.byteLen(repo_opts.hash)]u8 {
    // a binary file may still have a snapshot from its last text version
    for ([_]?*const [hash.byteLen(repo_opts.hash)]u8{ base_file_oid_maybe, target_file_oid, source_file_oid }) |file_oid_maybe| {
        const file_oid = file_oid_maybe orelse continue;
        var iter = try df.LineIterator(.xit, repo_opts).initFromOid(state.readOnly(), io, allocator, path, file_oid, null);
        defer iter.deinit();
        if (iter.source == .binary) {
            has_conflict.* = true;
            return source_file_oid.*;
        }
    }

    const snapshots = (try context.firstParentSnapshots(base_oid)) orelse return null;

    var patch_ids: std.ArrayList(hash.HashInt(repo_opts.hash)) = .empty;
    defer patch_ids.deinit(allocator);

    const path_hash = hash.hashInt(repo_opts.hash, path);

    // scan oldest first so patches are already in application order
    var parent_patch_id_maybe: ?hash.HashInt(repo_opts.hash) = null;
    for (snapshots.source, 0..) |snapshot, i| {
        // get this file's patch id from each snapshot
        const patch_id_maybe = blk: {
            const patch_id_cursor = (try snapshot.readPath(void, &.{
                .{ .hash_map_get = .{ .value = path_hash } },
                .{ .array_list_get = @intFromEnum(patch.FileField.patch) },
            })) orelse break :blk null;
            var patch_id_bytes: [hash.byteLen(repo_opts.hash)]u8 = undefined;
            _ = try patch_id_cursor.readBytes(&patch_id_bytes);
            break :blk hash.bytesToInt(repo_opts.hash, &patch_id_bytes);
        };

        // skip the boundary ancestor, but include an unrelated root's patch
        if (patch_id_maybe) |patch_id| {
            if (patch_id != parent_patch_id_maybe and (i > 0 or !snapshots.has_boundary)) {
                try patch_ids.append(allocator, patch_id);
            }
        }
        parent_patch_id_maybe = patch_id_maybe;
    }

    if (patch_ids.items.len == 0) return null;

    // apply patches together to check their dependencies
    var application = patch.applyPatches(repo_opts, state.readOnly().extra.moment, snapshots.target, allocator, path, patch_ids.items, .merge) catch |err| switch (err) {
        error.MissingPatchDependency => return null,
        else => return err,
    };
    defer application.deinit(allocator);
    const merged_file = &application.file;
    var text_reader = patch.File(repo_opts).TextReader.init(merged_file, allocator);
    defer text_reader.deinit();

    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    const render_allocator = arena.allocator();
    var lines: std.ArrayList([]const u8) = .empty;
    has_conflict.* = false;
    var index: usize = 0;
    if (merged_file.has_conflict) {
        const markers = try ConflictMarkers.init(render_allocator, base_oid, target_name, source_name);
        var base_file = try patch.File(repo_opts).load(state.readOnly().extra.moment, snapshots.base, allocator, path_hash);
        defer base_file.deinit();
        var target_file = try patch.File(repo_opts).load(state.readOnly().extra.moment, snapshots.target, allocator, path_hash);
        defer target_file.deinit();
        var source_file = try patch.File(repo_opts).load(state.readOnly().extra.moment, snapshots.source[snapshots.source.len - 1], allocator, path_hash);
        defer source_file.deinit();
        var readers = [_]patch.File(repo_opts).TextReader{
            .init(&base_file, allocator),
            .init(&target_file, allocator),
            .init(&source_file, allocator),
        };
        defer for (&readers) |*reader| reader.deinit();
        for (merged_file.regions.items) |region| {
            while (index < merged_file.lines.items.len and std.mem.order(u8, merged_file.lines.items[index].position, region.start) == .lt) : (index += 1) {
                try lines.append(render_allocator, try text_reader.readLine(merged_file.lines.items[index].id, render_allocator));
            }
            var ranges = [_]LineRange{.{ .lines = .empty }} ** 3;
            for (&readers, &ranges) |*reader, *range| {
                for (reader.file.lines.items) |line| {
                    if (region.contains(line.position)) try range.lines.append(render_allocator, try reader.readLine(line.id, render_allocator));
                }
            }
            if (try appendResolvedOrConflict(render_allocator, &lines, &markers, &ranges[0], &ranges[1], &ranges[2])) has_conflict.* = true;
            while (index < merged_file.lines.items.len and region.contains(merged_file.lines.items[index].position)) : (index += 1) {}
        }
    }
    for (merged_file.lines.items[index..]) |line| try lines.append(render_allocator, try text_reader.readLine(line.id, render_allocator));
    const content = try std.mem.join(render_allocator, "\n", lines.items);
    var reader = std.Io.Reader.fixed(content);
    var oid: [hash.byteLen(repo_opts.hash)]u8 = undefined;
    try obj.writeObject(.xit, repo_opts, state, io, allocator, &reader, .{ .kind = .blob, .size = content.len }, &oid);
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
    target_name: []const u8,
    source_name: []const u8,
    target_change_maybe: ?tr.Change(repo_opts.hash),
    source_change: tr.Change(repo_opts.hash),
    path: []const u8,
    merge_algo: MergeAlgorithm,
    context: *MergeContext(repo_kind, repo_opts),
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

                var has_content_conflict = false;

                const base_file_oid_maybe = if (base_entry_maybe) |base_entry| &base_entry.oid else null;
                const patch_oid_maybe = if (oid_maybe == null and merge_algo == .patch) blk: {
                    if (repo_kind != .xit) return error.PatchBasedMergeRequiresXitBackend;
                    break :blk try writeBlobWithPatches(repo_opts, state, io, allocator, base_file_oid_maybe, &target_entry.oid, &source_entry.oid, base_oid, target_name, source_name, &has_content_conflict, path, context);
                } else null;
                const oid = oid_maybe orelse patch_oid_maybe orelse try writeBlobWithDiff3(repo_kind, repo_opts, state, io, allocator, base_file_oid_maybe, &target_entry.oid, &source_entry.oid, base_oid, target_name, source_name, &has_content_conflict);
                const mode = mode_maybe orelse target_entry.mode;

                return .{
                    .change = .{
                        .old = target_change.new,
                        .new = .{ .oid = oid, .mode = mode },
                    },
                    .conflict = if (has_content_conflict or mode_maybe == null)
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
    conflicts: *std.StringArrayHashMapUnmanaged(MergeConflict(repo_opts.hash)),
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
                        try conflicts.put(arena.allocator(), parent_path, .{
                            .base = change.old,
                            .target = new,
                            .source = null,
                            .renamed = .{
                                .path = new_path,
                                .tree_entry = new,
                            },
                        });
                        // remove from the work dir
                        try clean_diff.changes.put(clean_diff.allocator, parent_path, .{ .old = new, .new = null });
                    },
                    .source => {
                        // add the conflict
                        try conflicts.put(arena.allocator(), parent_path, .{
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

fn migrateWorktree(
    comptime repo_kind: rp.RepoKind,
    comptime repo_opts: rp.RepoOpts(repo_kind),
    state: rp.Repo(repo_kind, repo_opts).State(.read_write),
    io: std.Io,
    allocator: std.mem.Allocator,
    diff: tr.TreeDiff(repo_kind, repo_opts),
    conflicts: std.StringArrayHashMapUnmanaged(MergeConflict(repo_opts.hash)),
) !void {
    // release the index lock before the caller updates refs or writes a commit
    var lock_maybe: ?fs.LockFile = null;
    defer if (lock_maybe) |*lock| lock.deinit(io);
    const write_state: rp.Repo(repo_kind, repo_opts).State(.read_write) = switch (repo_kind) {
        .git => blk: {
            const lock = try fs.LockFile.init(io, state.core.repo_dir, "index");
            lock_maybe = lock;
            break :blk .{ .core = state.core, .extra = .{ .lock_file_maybe = lock.lock_file } };
        },
        .xit => state,
    };
    var index = try idx.Index(repo_kind, repo_opts).init(state.readOnly(), io, allocator);
    defer index.deinit();

    // a merge commit must not include unrelated staged changes
    var head_tree = try tr.Tree(repo_kind, repo_opts).init(state.readOnly(), io, allocator, null);
    defer head_tree.deinit();
    if (index.entries.count() != head_tree.entries.count()) return error.CannotMergeWithLocalChanges;
    for (head_tree.entries.keys(), head_tree.entries.values()) |path, entry| {
        const staged = (index.entries.get(path) orelse return error.CannotMergeWithLocalChanges)[0] orelse return error.CannotMergeWithLocalChanges;
        if (!entry.eql(.{ .oid = staged.oid, .mode = staged.mode })) return error.CannotMergeWithLocalChanges;
    }

    var check_diff = tr.TreeDiff(repo_kind, repo_opts).init(allocator);
    defer check_diff.deinit();
    check_diff.changes = try diff.changes.clone(allocator);
    for (diff.changes.keys(), diff.changes.values()) |path, change| {
        // checkout allows missing tracked files, but merging must preserve local deletions
        if (change.old != null) {
            _ = state.core.work_dir.statFile(io, path, .{ .follow_symlinks = false }) catch |err| switch (err) {
                error.FileNotFound, error.NotDir => return error.CannotMergeWithLocalChanges,
                else => return err,
            };
        }
    }
    for (conflicts.values()) |conflict| {
        if (conflict.renamed) |renamed| {
            for (check_diff.changes.keys(), check_diff.changes.values()) |path, change| {
                if (change.new == null) continue;
                const shorter, const longer = if (path.len <= renamed.path.len) .{ path, renamed.path } else .{ renamed.path, path };
                if (std.mem.startsWith(u8, longer, shorter) and
                    (longer.len == shorter.len or longer[shorter.len] == '/'))
                {
                    return error.MergeBackupPathConflict;
                }
            }
            try check_diff.changes.put(allocator, renamed.path, .{ .old = null, .new = renamed.tree_entry });
        }
    }
    var check = work.Switch(repo_kind, repo_opts){ .arena = &check_diff.arena, .allocator = allocator, .result = .success };
    try work.migrate(repo_kind, repo_opts, state, io, allocator, check_diff, &index, true, true, &check);
    if (check.result == .conflict) return error.CannotMergeWithLocalChanges;

    try work.migrate(repo_kind, repo_opts, state, io, allocator, diff, &index, true, false, null);
    for (conflicts.keys(), conflicts.values()) |path, conflict| {
        try index.addConflictEntries(path, .{ conflict.base, conflict.target, conflict.source });
        if (conflict.renamed) |renamed| {
            try work.objectToFile(repo_kind, repo_opts, state.readOnly(), io, allocator, renamed.path, renamed.tree_entry);
        }
    }
    try index.write(allocator, write_state, io);
    if (lock_maybe) |*lock| lock.success = true;
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
        changes: std.StringArrayHashMapUnmanaged(tr.Change(repo_opts.hash)),
        auto_resolved_conflicts: std.StringArrayHashMapUnmanaged(void),
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
                conflicts: std.StringArrayHashMapUnmanaged(MergeConflict(repo_opts.hash)),
            },
        },

        pub fn init(
            state: rp.Repo(repo_kind, repo_opts).State(.read_write),
            io: std.Io,
            allocator: std.mem.Allocator,
            merge_input: MergeInput(repo_opts.hash),
            target_ref_maybe: ?rf.Ref, // null means HEAD
            progress_ctx_maybe: ?repo_opts.ProgressCtx,
        ) !Merge(repo_kind, repo_opts) {
            if (target_ref_maybe != null) switch (merge_input.action) {
                .new => {},
                .cont => return error.CannotContinueMergeAtRef,
            };

            const arena = try allocator.create(std.heap.ArenaAllocator);
            arena.* = std.heap.ArenaAllocator.init(allocator);
            errdefer {
                arena.deinit();
                allocator.destroy(arena);
            }

            // get the target name, path, and oid
            const target_buffer = try arena.allocator().alloc(u8, rf.MAX_REF_CONTENT_SIZE);
            const target_name, const target_path, const target_oid_maybe = if (target_ref_maybe) |target_ref| blk: {
                const target_path = try target_ref.toPath(target_buffer);
                break :blk .{
                    try arena.allocator().dupe(u8, target_ref.name),
                    target_path,
                    try rf.readRecur(repo_kind, repo_opts, state.readOnly(), io, .{ .ref = target_ref }),
                };
            } else blk: {
                const target_ref_or_oid = try rf.readHead(repo_kind, repo_opts, state.readOnly(), io, target_buffer) orelse return error.TargetNotFound;
                break :blk .{
                    switch (target_ref_or_oid) {
                        .ref => |ref| ref.name,
                        .oid => |oid| oid,
                    },
                    "HEAD",
                    try rf.readRecur(repo_kind, repo_opts, state.readOnly(), io, target_ref_or_oid),
                };
            };

            // init the diff that we will use for the migration and the conflicts maps.
            // they're using the arena because they'll be included in the result.
            var clean_diff = tr.TreeDiff(repo_kind, repo_opts).init(arena.allocator());
            var auto_resolved_conflicts: std.StringArrayHashMapUnmanaged(void) = .empty;
            var conflicts: std.StringArrayHashMapUnmanaged(MergeConflict(repo_opts.hash)) = .empty;

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

                    const source_ref_oid = try rf.readRecur(repo_kind, repo_opts, state.readOnly(), io, source_ref_or_oid) orelse return error.InvalidMergeSource;
                    var context = try MergeContext(repo_kind, repo_opts).init(state.readOnly(), io, allocator, &(target_oid_maybe orelse source_ref_oid), &source_ref_oid);
                    defer context.deinit();

                    // use commit oids for diffs, refs, and parents when a tip is a tag
                    const source_oid = context.ancestry.tips[1];
                    const target_oid = if (target_oid_maybe != null) context.ancestry.tips[0] else {
                        // make a TreeDiff that adds all files from source
                        try clean_diff.compare(state.readOnly(), io, null, &source_oid, null);

                        if (target_ref_maybe == null) {
                            try migrateWorktree(repo_kind, repo_opts, state, io, allocator, clean_diff, conflicts);
                        }

                        // update the empty branch only after the work dir checks succeed
                        try rf.writeRecur(repo_kind, repo_opts, state, io, target_path, &source_oid);

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

                    const base_oid = try context.mergeBase(merge_input.kind);

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
                        const same_path_result = try samePathConflict(repo_kind, repo_opts, state, io, allocator, &base_oid, target_name, source_name, target_diff.changes.get(path), source_change, path, merge_algo, &context);
                        if (same_path_result.change) |change| {
                            try clean_diff.changes.put(clean_diff.allocator, path, change);
                        }
                        if (same_path_result.conflict) |conflict| {
                            try conflicts.put(arena.allocator(), path, conflict);
                        } else {
                            try auto_resolved_conflicts.put(arena.allocator(), path, {});
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
                    var commit_metadata: obj.CommitMetadata(repo_opts.hash) = merge_input.commit_metadata orelse .{};
                    switch (merge_input.kind) {
                        .full => if (merge_input.commit_metadata == null) {
                            commit_metadata.message = try std.fmt.allocPrint(arena.allocator(), "merge from {s}", .{source_name});
                        },
                        .pick => {
                            // preserve the author and message, with a new committer and date
                            var object = try obj.Object(repo_kind, repo_opts).initCommit(state.readOnly(), io, allocator, &source_oid);
                            defer object.deinit();
                            const metadata = object.content.commit.metadata;
                            if (commit_metadata.author == null) {
                                commit_metadata.author = if (metadata.author) |author| try arena.allocator().dupe(u8, author) else null;
                            }
                            if (commit_metadata.message.len == 0) {
                                var message: std.ArrayList(u8) = .empty;
                                try object.readMessage(arena.allocator(), &message, .limited(repo_opts.max_read_size));
                                commit_metadata.message = message.items;
                            }
                        },
                    }

                    if (target_ref_maybe == null) {
                        try migrateWorktree(repo_kind, repo_opts, state, io, allocator, clean_diff, conflicts);
                    }

                    // exit early if there were conflicts
                    if (conflicts.count() > 0) {
                        if (target_ref_maybe == null) {
                            try rf.write(repo_kind, repo_opts, state, io, merge_head_name, .{ .oid = &source_oid });

                            const merge_msg = try state.core.repo_dir.createFile(io, merge_msg_name, .{ .truncate = true, .lock = .exclusive });
                            defer merge_msg.close(io);
                            try merge_msg.writeStreamingAll(io, commit_metadata.message);
                        }
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

                    if (std.mem.eql(u8, &target_oid, &base_oid)) {
                        // the base ancestor is the target oid, so just update the target
                        try rf.writeRecur(repo_kind, repo_opts, state, io, target_path, &source_oid);
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
                    // build the merged tree without changing the index or work dir
                    const commit_oid = if (target_ref_maybe) |target_ref| blk: {
                        var index = try idx.Index(repo_kind, repo_opts).initFromCommit(state.readOnly(), io, allocator, &target_oid);
                        defer index.deinit();
                        try work.migrate(repo_kind, repo_opts, state, io, allocator, clean_diff, &index, false, false, null);

                        var tree = try obj.Tree.initFromIndex(repo_kind, repo_opts, state, io, allocator, &index);
                        defer tree.deinit();
                        break :blk try obj.writeCommit(repo_kind, repo_opts, state, io, allocator, commit_metadata, &tree, target_ref);
                    } else try obj.writeCommitAtHead(repo_kind, repo_opts, state, io, allocator, commit_metadata);

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
                    var index = try idx.Index(repo_kind, repo_opts).init(state.readOnly(), io, allocator);
                    defer index.deinit();

                    for (index.entries.values()) |*entries_for_path| {
                        if (null == entries_for_path[0]) {
                            return error.CannotContinueMergeWithUnresolvedConflicts;
                        }
                    }

                    // make sure there isn't another kind of merge in progress
                    try checkForOtherMerge(repo_kind, repo_opts, state.readOnly(), io, merge_head_name);

                    const source_head_oid = try rf.readRecur(repo_kind, repo_opts, state.readOnly(), io, .{ .ref = .{ .kind = .none, .name = merge_head_name } }) orelse return error.MergeHeadNotFound;

                    // read the merge message
                    var commit_metadata: obj.CommitMetadata(repo_opts.hash) = merge_input.commit_metadata orelse .{};
                    if (merge_input.kind == .pick) {
                        var object = try obj.Object(repo_kind, repo_opts).initCommit(state.readOnly(), io, allocator, &source_head_oid);
                        defer object.deinit();
                        const metadata = object.content.commit.metadata;
                        if (commit_metadata.author == null) {
                            commit_metadata.author = if (metadata.author) |author| try arena.allocator().dupe(u8, author) else null;
                        }
                    }
                    commit_metadata.message = state.core.repo_dir.readFileAlloc(io, merge_msg_name, arena.allocator(), .limited(repo_opts.max_read_size)) catch |err| switch (err) {
                        error.FileNotFound => return error.MergeMessageNotFound,
                        else => |e| return e,
                    };

                    // we need to return the source name but we don't have it,
                    // so just copy the source oid into a buffer and return that instead
                    const source_name = try arena.allocator().dupe(u8, &source_head_oid);

                    // get the source, target, and base oids
                    const source_oid, const target_oid, const base_oid = blk: {
                        const target_ref_oid = target_oid_maybe orelse return error.TargetOidNotFound;
                        var context = try MergeContext(repo_kind, repo_opts).init(state.readOnly(), io, allocator, &target_ref_oid, &source_head_oid);
                        defer context.deinit();
                        break :blk .{ context.ancestry.tips[1], context.ancestry.tips[0], try context.mergeBase(merge_input.kind) };
                    };

                    // commit the change
                    commit_metadata.parent_oids = switch (merge_input.kind) {
                        .full => &.{ target_oid, source_oid },
                        .pick => &.{target_oid},
                    };
                    var tree = try obj.Tree.initFromIndex(repo_kind, repo_opts, state, io, allocator, &index);
                    defer tree.deinit();
                    const commit_oid = try obj.writeCommit(repo_kind, repo_opts, state, io, allocator, commit_metadata, &tree, .{ .kind = .none, .name = "HEAD" });

                    // clean up the stored merge state after the commit succeeds
                    try removeMergeState(repo_kind, repo_opts, state, io);

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
    var patch_writer = try patch.PatchWriter(repo_opts).init(state.readOnly(), io, allocator);
    defer patch_writer.deinit(io, allocator);

    var iter = try obj.ObjectIterator(.xit, repo_opts).init(state.readOnly(), io, allocator, .{ .kind = .commit });
    defer iter.deinit();
    try iter.include(source_oid);
    try iter.include(target_oid);
    while (try iter.next(allocator)) |commit_object| {
        defer commit_object.deinit();

        const oid = try hash.hexToBytes(repo_opts.hash, commit_object.oid);
        try patch_writer.add(state.readOnly(), io, allocator, &oid);
    }

    try patch_writer.write(state, io, allocator, progress_ctx_maybe);
}
