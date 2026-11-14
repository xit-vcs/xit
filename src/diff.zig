const std = @import("std");
const xitui = @import("xitui");
const rp = @import("./repo.zig");
const work = @import("./workdir.zig");
const hash = @import("./hash.zig");
const fs = @import("./fs.zig");
const idx = @import("./index.zig");
const obj = @import("./object.zig");
const tr = @import("./tree.zig");

pub fn LineIterator(comptime repo_kind: rp.RepoKind, comptime repo_opts: rp.RepoOpts(repo_kind)) type {
    return struct {
        allocator: std.mem.Allocator,
        path: []const u8,
        oid: [hash.byteLen(repo_opts.hash)]u8,
        oid_hex: [hash.hexLen(repo_opts.hash)]u8,
        mode: ?fs.Mode,
        size: u64,
        line_offsets: []const usize,
        current_line: usize,
        source: Source,

        const Self = @This();

        // text is read once and kept in memory. lines are slices of the content.
        const Source = union(enum) {
            buffer: []const u8,
            nothing,
            binary,

            fn deinit(self: *Source, allocator: std.mem.Allocator) void {
                switch (self.*) {
                    .buffer => |buffer| allocator.free(buffer),
                    .nothing => {},
                    .binary => {},
                }
            }
        };

        pub fn initFromIndex(
            state: rp.Repo(repo_kind, repo_opts).State(.read_only),
            io: std.Io,
            allocator: std.mem.Allocator,
            entry: idx.Index(repo_kind, repo_opts).Entry,
        ) !Self {
            return initFromOid(state, io, allocator, entry.path, &entry.oid, entry.mode);
        }

        pub fn initFromWorkDir(
            state: rp.Repo(repo_kind, repo_opts).State(.read_only),
            io: std.Io,
            allocator: std.mem.Allocator,
            path: []const u8,
            mode: fs.Mode,
        ) !Self {
            switch (mode.content.object_type) {
                .regular_file => {
                    var file = try state.core.work_dir.openFile(io, path, .{ .mode = .read_only, .allow_directory = false });
                    defer file.close(io);
                    const file_size = try file.length(io);
                    const header = try allocator.print("blob {}\x00", .{file_size});
                    defer allocator.free(header);

                    var reader_buffer: [repo_opts.buffer_size]u8 = @splat(0);
                    var reader = file.reader(io, &reader_buffer);

                    var oid: [hash.byteLen(repo_opts.hash)]u8 = @splat(0);
                    hash.hashReader(repo_opts.hash, repo_opts.read_size, &reader.interface, header, &oid) catch |err| switch (err) {
                        error.ReadFailed => |e| return reader.err orelse e,
                        else => |e| return e,
                    };
                    try reader.seekTo(0);

                    var iter = Self{
                        .allocator = allocator,
                        .path = path,
                        .oid = oid,
                        .oid_hex = std.fmt.bytesToHex(&oid, .lower),
                        .mode = mode,
                        .size = file_size,
                        .line_offsets = undefined,
                        .current_line = 0,
                        .source = undefined,
                    };
                    iter.readLines(&reader.interface, true) catch |err| switch (err) {
                        error.ReadFailed => |e| return reader.err orelse e,
                        else => |e| return e,
                    };
                    return iter;
                },
                .symbolic_link => {
                    var target_path_buffer: [std.Io.Dir.max_path_bytes]u8 = @splat(0);
                    const target_path_size = try state.core.work_dir.readLink(io, path, &target_path_buffer);
                    const target_path = target_path_buffer[0..target_path_size];

                    // make reader
                    var reader = std.Io.Reader.fixed(target_path);

                    // create blob header
                    var header_buffer: [256]u8 = @splat(0); // should be plenty of space
                    const header = try std.mem.print(&header_buffer, "blob {}\x00", .{target_path.len});

                    var oid: [hash.byteLen(repo_opts.hash)]u8 = @splat(0);
                    try hash.hashReader(repo_opts.hash, repo_opts.read_size, &reader, header, &oid);

                    return try initFromBuffer(allocator, path, &oid, mode, target_path);
                },
                else => return error.UnexpectedFileKind,
            }
        }

        pub fn initFromNothing(allocator: std.mem.Allocator, path: []const u8) !Self {
            return .{
                .allocator = allocator,
                .path = path,
                .oid = @splat(0),
                .oid_hex = @splat('0'),
                .mode = null,
                .size = 0,
                .line_offsets = &.{},
                .current_line = 0,
                .source = .nothing,
            };
        }

        pub fn initFromTree(
            state: rp.Repo(repo_kind, repo_opts).State(.read_only),
            io: std.Io,
            allocator: std.mem.Allocator,
            path: []const u8,
            entry: tr.TreeEntry(repo_opts.hash),
        ) !Self {
            return initFromOid(state, io, allocator, path, &entry.oid, entry.mode);
        }

        pub fn initFromOid(
            state: rp.Repo(repo_kind, repo_opts).State(.read_only),
            io: std.Io,
            allocator: std.mem.Allocator,
            path: []const u8,
            oid: *const [hash.byteLen(repo_opts.hash)]u8,
            mode_maybe: ?fs.Mode,
        ) !Self {
            const oid_hex = std.fmt.bytesToHex(oid, .lower);

            // treat submodules as binary files so they are ignored in diffs and patches
            if (mode_maybe) |mode| {
                if (mode.content.object_type == .gitlink) {
                    return .{
                        .allocator = allocator,
                        .path = path,
                        .oid = oid.*,
                        .oid_hex = oid_hex,
                        .mode = mode_maybe,
                        .size = 0,
                        .line_offsets = &.{},
                        .current_line = 0,
                        .source = .binary,
                    };
                }
            }

            return initFromObject(state, io, allocator, path, oid, mode_maybe, true);
        }

        // for a blob that was already accepted as text, like one a patch snapshot
        // describes. the limits only classify new blobs, so they don't apply.
        pub fn initFromTextOid(
            state: rp.Repo(repo_kind, repo_opts).State(.read_only),
            io: std.Io,
            allocator: std.mem.Allocator,
            path: []const u8,
            oid: *const [hash.byteLen(repo_opts.hash)]u8,
        ) !Self {
            return initFromObject(state, io, allocator, path, oid, null, false);
        }

        fn initFromObject(
            state: rp.Repo(repo_kind, repo_opts).State(.read_only),
            io: std.Io,
            allocator: std.mem.Allocator,
            path: []const u8,
            oid: *const [hash.byteLen(repo_opts.hash)]u8,
            mode_maybe: ?fs.Mode,
            limited: bool,
        ) !Self {
            const oid_hex = std.fmt.bytesToHex(oid, .lower);
            var object_reader = try obj.ObjectReader(repo_kind, repo_opts).init(state, io, allocator, &oid_hex);
            defer object_reader.deinit();
            var iter = Self{
                .allocator = allocator,
                .path = path,
                .oid = oid.*,
                .oid_hex = oid_hex,
                .mode = mode_maybe,
                .size = object_reader.header().size,
                .line_offsets = undefined,
                .current_line = 0,
                .source = undefined,
            };
            try iter.readLines(&object_reader.interface, limited);
            return iter;
        }

        // buffers hold text that was already accepted, so line size isn't limited
        pub fn initFromBuffer(
            allocator: std.mem.Allocator,
            path: []const u8,
            oid: *const [hash.byteLen(repo_opts.hash)]u8,
            mode_maybe: ?fs.Mode,
            buffer: []const u8,
        ) !Self {
            var reader = std.Io.Reader.fixed(buffer);
            var iter = Self{
                .allocator = allocator,
                .path = path,
                .oid = oid.*,
                .oid_hex = std.fmt.bytesToHex(oid, .lower),
                .mode = mode_maybe,
                .size = buffer.len,
                .line_offsets = undefined,
                .current_line = 0,
                .source = undefined,
            };
            try iter.readLines(&reader, false);
            return iter;
        }

        pub fn initFromTestBuffer(
            allocator: std.mem.Allocator,
            buffer: []const u8,
        ) !Self {
            const zero_oid: [hash.byteLen(repo_opts.hash)]u8 = @splat(0);
            return try initFromBuffer(allocator, "", &zero_oid, null, buffer);
        }

        /// reads every line into memory, including the empty line after a final
        /// newline. invalid utf-8 makes the file binary, and reading stops there.
        /// limited sources are also binary when the file or a line is too large
        /// or there are too many lines; other sources were already accepted.
        fn readLines(self: *Self, reader: *std.Io.Reader, limited: bool) !void {
            self.source = .binary;
            self.line_offsets = &.{};
            if (limited and self.size > repo_opts.max_text_size) return;

            // the size is known, so reserve it once instead of growing by copies
            var content = try std.Io.Writer.Allocating.initCapacity(self.allocator, @intCast(self.size));
            errdefer content.deinit();
            var offsets: std.ArrayList(usize) = .empty;
            errdefer offsets.deinit(self.allocator);
            const limit: std.Io.Limit = if (limited) .limited(repo_opts.max_line_size) else .unlimited;

            const is_text = while (true) {
                const start = content.written().len;
                _ = reader.streamDelimiterLimit(&content.writer, '\n', limit) catch |err| switch (err) {
                    error.StreamTooLong => break false,
                    else => |e| return e,
                };
                if ((limited and offsets.items.len == repo_opts.max_line_count) or !std.unicode.utf8ValidateSlice(content.written()[start..])) break false;
                try offsets.append(self.allocator, start);
                // the stream stopped at a newline or at the end
                _ = reader.peekByte() catch |err| switch (err) {
                    error.EndOfStream => break true,
                    else => |e| return e,
                };
                reader.toss(1);
                try content.writer.writeByte('\n');
            };

            if (is_text) {
                self.line_offsets = try offsets.toOwnedSlice(self.allocator);
                self.source = .{ .buffer = try content.toOwnedSlice() };
            } else {
                content.deinit();
                offsets.clearAndFree(self.allocator);
            }
        }

        pub fn next(self: *Self) !?[]const u8 {
            const buffer = switch (self.source) {
                .buffer => |buffer| buffer,
                .nothing, .binary => return null,
            };
            if (self.current_line >= self.line_offsets.len) return null;
            const start = self.line_offsets[self.current_line];
            const end = if (self.current_line + 1 < self.line_offsets.len) self.line_offsets[self.current_line + 1] - 1 else buffer.len;
            self.current_line += 1;
            return buffer[start..end];
        }

        pub fn get(self: *Self, line_num: usize) ![]const u8 {
            self.current_line = line_num;
            return try self.next() orelse return error.ExpectedLine;
        }

        pub fn reset(self: *Self) void {
            self.current_line = 0;
        }

        pub fn count(self: *Self) usize {
            return self.line_offsets.len;
        }

        pub fn deinit(self: *Self) void {
            self.source.deinit(self.allocator);
            self.allocator.free(self.line_offsets);
        }
    };
}

pub const Line = struct {
    num: usize,
    offset: u64 = 0,
};

pub const Edit = union(enum) {
    eql: struct {
        old_line: Line,
        new_line: Line,
    },
    ins: struct {
        new_line: Line,
    },
    del: struct {
        old_line: Line,
    },

    pub fn withoutOffset(self: Edit) Edit {
        var new_self = self;
        switch (new_self) {
            .eql => |*eql| {
                eql.old_line.offset = 0;
                eql.new_line.offset = 0;
            },
            .ins => |*ins| ins.new_line.offset = 0,
            .del => |*del| del.old_line.offset = 0,
        }
        return new_self;
    }
};

/// myers diff computed eagerly in init. lines are mapped to ids, the common
/// prefix and suffix are trimmed, and lines with no equal line on the other
/// side are marked changed before the search, which keeps the diff minimal.
/// past `max_diff_work` search steps, each remaining subproblem is marked all
/// changed, so the diff stays valid but may not be minimal.
pub fn MyersDiffIterator(comptime repo_kind: rp.RepoKind, comptime repo_opts: rp.RepoOpts(repo_kind)) type {
    return struct {
        allocator: std.mem.Allocator,
        line_iter_a: *LineIterator(repo_kind, repo_opts),
        line_iter_b: *LineIterator(repo_kind, repo_opts),
        // the new line equal to each old line, or null for a deleted line
        new_lines: []?usize,
        x_index: usize,
        y_index: usize,

        const Self = @This();

        pub fn init(allocator: std.mem.Allocator, line_iter_a: *LineIterator(repo_kind, repo_opts), line_iter_b: *LineIterator(repo_kind, repo_opts)) !Self {
            const line_iters = [2]*LineIterator(repo_kind, repo_opts){ line_iter_a, line_iter_b };
            const counts = [2]usize{ line_iter_a.count(), line_iter_b.count() };

            var changed: [2][]bool = undefined;
            changed[0] = try allocator.alloc(bool, counts[0]);
            defer allocator.free(changed[0]);
            changed[1] = try allocator.alloc(bool, counts[1]);
            defer allocator.free(changed[1]);
            for (changed) |c| @memset(c, false);

            {
                // equal lines get equal ids
                var ids: [2][]u32 = undefined;
                ids[0] = try allocator.alloc(u32, counts[0]);
                defer allocator.free(ids[0]);
                ids[1] = try allocator.alloc(u32, counts[1]);
                defer allocator.free(ids[1]);
                var id_count: u32 = 0;
                {
                    var id_map: std.StringHashMapUnmanaged(u32) = .empty;
                    defer id_map.deinit(allocator);
                    try id_map.ensureTotalCapacity(allocator, @intCast(counts[0] + counts[1]));
                    for (line_iters, ids) |line_iter, side_ids| {
                        for (side_ids, 0..) |*id, line_num| {
                            const result = id_map.getOrPutAssumeCapacity(try line_iter.get(line_num));
                            if (!result.found_existing) {
                                result.value_ptr.* = id_count;
                                id_count += 1;
                            }
                            id.* = result.value_ptr.*;
                        }
                    }
                }

                // the common prefix and suffix stay unchanged
                var start: usize = 0;
                while (start < counts[0] and start < counts[1] and ids[0][start] == ids[1][start]) start += 1;
                var ends = counts;
                while (ends[0] > start and ends[1] > start and ids[0][ends[0] - 1] == ids[1][ends[1] - 1]) {
                    ends[0] -= 1;
                    ends[1] -= 1;
                }

                // a line with no equal line in the other middle is changed. the rest
                // are compacted to the front of the id arrays for the search.
                const sides = try allocator.alloc(u2, id_count);
                defer allocator.free(sides);
                @memset(sides, 0);
                for (ids, ends, 0..) |side_ids, end, side| {
                    for (side_ids[start..end]) |id| sides[id] |= @as(u2, 1) << @intCast(side);
                }
                var lines: [2][]usize = undefined;
                lines[0] = try allocator.alloc(usize, ends[0] - start);
                defer allocator.free(lines[0]);
                lines[1] = try allocator.alloc(usize, ends[1] - start);
                defer allocator.free(lines[1]);
                var lens: [2]usize = .{ 0, 0 };
                for (ids, changed, lines, &lens, ends, 0..) |side_ids, side_changed, side_lines, *len, end, side| {
                    const other: u2 = @as(u2, 1) << @intCast(1 - side);
                    for (start..end) |line_num| {
                        if (sides[side_ids[line_num]] & other == 0) {
                            side_changed[line_num] = true;
                            continue;
                        }
                        side_ids[len.*] = side_ids[line_num];
                        side_lines[len.*] = line_num;
                        len.* += 1;
                    }
                }

                try search(allocator, ids[0][0..lens[0]], ids[1][0..lens[1]], lines[0][0..lens[0]], lines[1][0..lens[1]], changed[0], changed[1]);
            }

            // pair the unchanged lines in order
            const new_lines = try allocator.alloc(?usize, counts[0]);
            var new_line: usize = 0;
            for (new_lines, changed[0]) |*new_line_maybe, old_changed| {
                if (old_changed) {
                    new_line_maybe.* = null;
                    continue;
                }
                while (changed[1][new_line]) new_line += 1;
                new_line_maybe.* = new_line;
                new_line += 1;
            }

            return .{
                .allocator = allocator,
                .line_iter_a = line_iter_a,
                .line_iter_b = line_iter_b,
                .new_lines = new_lines,
                .x_index = 0,
                .y_index = 0,
            };
        }

        /// linear-space myers over the remaining ids, marking changed lines
        fn search(
            allocator: std.mem.Allocator,
            ids_a: []const u32,
            ids_b: []const u32,
            lines_a: []const usize,
            lines_b: []const usize,
            changed_a: []bool,
            changed_b: []bool,
        ) !void {
            const furthest = try allocator.alloc(isize, 4 * (@min(ids_a.len, ids_b.len) + 1));
            defer allocator.free(furthest);
            var stack: std.ArrayList(isize) = .empty;
            defer stack.deinit(allocator);
            var steps: u64 = 0;

            var i: isize = 0;
            var j: isize = 0;
            var n: isize = @intCast(ids_a.len);
            var m: isize = @intCast(ids_b.len);

            while (true) {
                var z = 2 * (@min(n, m) + 1);
                z_block: while (n > 0 and m > 0) {
                    @memset(furthest[0..@intCast(2 * z)], 0);

                    const w = n - m;
                    const l = n + m;
                    const parity = l & 1;
                    const offsetx = i + n - 1;
                    const offsety = j + m - 1;
                    const hmax = @as(usize, @intCast(l + parity)) / 2;

                    h_loop: for (0..hmax + 1) |h| {
                        // past the budget, the subproblem is all changed
                        if (steps > repo_opts.max_diff_work) break :z_block;

                        const hh: isize = @intCast(h);
                        const kmin: isize = 2 * @max(0, hh - m) - hh;
                        const kmax: isize = hh - 2 * @max(0, hh - n);

                        // forwards
                        var k: isize = kmin;
                        while (k <= kmax) {
                            defer k += 2;
                            const gkm = furthest[@intCast(k - 1 - z * @divFloor(k - 1, z))];
                            const gkp = furthest[@intCast(k + 1 - z * @divFloor(k + 1, z))];
                            const u = if (k == -hh or (k != hh and gkm < gkp)) gkp else gkm + 1;
                            const v = u - k;
                            var x = u;
                            var y = v;
                            while (x < n and y < m and ids_a[@intCast(i + x)] == ids_b[@intCast(j + y)]) {
                                x += 1;
                                y += 1;
                            }
                            steps += @intCast(x - u + 1);
                            furthest[@intCast(k - z * @divFloor(k, z))] = x;
                            if (parity == 1) {
                                const zz = w - k;
                                if (zz >= 1 - hh and zz < hh and x + furthest[@intCast(z + zz - z * @divFloor(zz, z))] >= n) {
                                    if (h > 1 or x != u) {
                                        try stack.append(allocator, i + x);
                                        try stack.append(allocator, n - x);
                                        try stack.append(allocator, j + y);
                                        try stack.append(allocator, m - y);
                                        n = u;
                                        m = v;
                                        z = 2 * (@min(n, m) + 1);
                                        continue :z_block;
                                    } else break :h_loop;
                                }
                            }
                        }

                        // backwards
                        k = kmin;
                        while (k <= kmax) {
                            defer k += 2;
                            const pkm = furthest[@intCast(z + k - 1 - z * @divFloor(k - 1, z))];
                            const pkp = furthest[@intCast(z + k + 1 - z * @divFloor(k + 1, z))];
                            const u = if (k == -hh or (k != hh and pkm < pkp)) pkp else pkm + 1;
                            const v = u - k;
                            var x = u;
                            var y = v;
                            while (x < n and y < m and ids_a[@intCast(offsetx - x)] == ids_b[@intCast(offsety - y)]) {
                                x += 1;
                                y += 1;
                            }
                            steps += @intCast(x - u + 1);
                            furthest[@intCast(z + k - z * @divFloor(k, z))] = x;
                            if (parity == 0) {
                                const zz = w - k;
                                if (zz >= -hh and zz <= hh and x + furthest[@intCast(zz - z * @divFloor(zz, z))] >= n) {
                                    if (h > 0 or x != u) {
                                        try stack.append(allocator, i + n - u);
                                        try stack.append(allocator, u);
                                        try stack.append(allocator, j + m - v);
                                        try stack.append(allocator, v);
                                        n = n - x;
                                        m = m - y;
                                        z = 2 * (@min(n, m) + 1);
                                        continue :z_block;
                                    } else break :h_loop;
                                }
                            }
                        }
                    }

                    // at most one line differs, and it is after the common part
                    if (m > n) {
                        i += n;
                        j += n;
                        m -= n;
                        n = 0;
                    } else {
                        i += m;
                        j += m;
                        n -= m;
                        m = 0;
                    }
                    break;
                }

                for (lines_a[@intCast(i)..@intCast(i + n)]) |line_num| changed_a[line_num] = true;
                for (lines_b[@intCast(j)..@intCast(j + m)]) |line_num| changed_b[line_num] = true;

                if (stack.items.len == 0) return;
                m = stack.pop() orelse unreachable;
                j = stack.pop() orelse unreachable;
                n = stack.pop() orelse unreachable;
                i = stack.pop() orelse unreachable;
            }
        }

        pub fn next(self: *Self) !?Edit {
            const x = self.x_index;
            const y = self.y_index;
            if (x < self.new_lines.len) {
                const new_line = self.new_lines[x] orelse {
                    self.x_index += 1;
                    return .{ .del = .{ .old_line = .{ .num = x, .offset = self.line_iter_a.line_offsets[x] } } };
                };
                if (y == new_line) {
                    self.x_index += 1;
                    self.y_index += 1;
                    return .{ .eql = .{
                        .old_line = .{ .num = x, .offset = self.line_iter_a.line_offsets[x] },
                        .new_line = .{ .num = y, .offset = self.line_iter_b.line_offsets[y] },
                    } };
                }
            } else if (y == self.line_iter_b.count()) return null;
            self.y_index += 1;
            return .{ .ins = .{ .new_line = .{ .num = y, .offset = self.line_iter_b.line_offsets[y] } } };
        }

        pub fn get(self: *const Self, old_line: usize) ?usize {
            if (old_line >= self.new_lines.len) return null;
            return self.new_lines[old_line];
        }

        pub fn reset(self: *Self) void {
            self.line_iter_a.reset();
            self.line_iter_b.reset();
            self.x_index = 0;
            self.y_index = 0;
        }

        pub fn deinit(self: *Self) void {
            self.allocator.free(self.new_lines);
        }
    };
}

test "myers diff" {
    const repo_kind = rp.RepoKind.git;
    const repo_opts = rp.RepoOpts(.git){ .is_test = true };
    const allocator = std.testing.allocator;
    {
        const lines1 = "A\nB\nC\nA\nB\nB\nA";
        const lines2 = "C\nB\nA\nB\nA\nC";
        var line_iter1 = try LineIterator(repo_kind, repo_opts).initFromTestBuffer(allocator, lines1);
        defer line_iter1.deinit();
        var line_iter2 = try LineIterator(repo_kind, repo_opts).initFromTestBuffer(allocator, lines2);
        defer line_iter2.deinit();
        const expected_diff = [_]Edit{
            .{ .del = .{ .old_line = .{ .num = 0 } } },
            .{ .ins = .{ .new_line = .{ .num = 0 } } },
            .{ .eql = .{ .old_line = .{ .num = 1 }, .new_line = .{ .num = 1 } } },
            .{ .del = .{ .old_line = .{ .num = 2 } } },
            .{ .eql = .{ .old_line = .{ .num = 3 }, .new_line = .{ .num = 2 } } },
            .{ .eql = .{ .old_line = .{ .num = 4 }, .new_line = .{ .num = 3 } } },
            .{ .del = .{ .old_line = .{ .num = 5 } } },
            .{ .eql = .{ .old_line = .{ .num = 6 }, .new_line = .{ .num = 4 } } },
            .{ .ins = .{ .new_line = .{ .num = 5 } } },
        };
        var myers_diff_iter = try MyersDiffIterator(repo_kind, repo_opts).init(allocator, &line_iter1, &line_iter2);
        defer myers_diff_iter.deinit();
        var actual_diff: std.ArrayList(Edit) = .empty;
        defer actual_diff.deinit(allocator);
        while (try myers_diff_iter.next()) |edit| {
            try actual_diff.append(allocator, edit);
        }
        try std.testing.expectEqual(expected_diff.len, actual_diff.items.len);
        for (expected_diff, actual_diff.items) |expected, actual| {
            try std.testing.expectEqualDeep(expected, actual.withoutOffset());
        }
    }
    {
        const lines1 = "hello, world!";
        const lines2 = "goodbye, world!";
        var line_iter1 = try LineIterator(repo_kind, repo_opts).initFromTestBuffer(allocator, lines1);
        defer line_iter1.deinit();
        var line_iter2 = try LineIterator(repo_kind, repo_opts).initFromTestBuffer(allocator, lines2);
        defer line_iter2.deinit();
        const expected_diff = [_]Edit{
            .{ .del = .{ .old_line = .{ .num = 0 } } },
            .{ .ins = .{ .new_line = .{ .num = 0 } } },
        };
        var myers_diff_iter = try MyersDiffIterator(repo_kind, repo_opts).init(allocator, &line_iter1, &line_iter2);
        defer myers_diff_iter.deinit();
        var actual_diff: std.ArrayList(Edit) = .empty;
        defer actual_diff.deinit(allocator);
        while (try myers_diff_iter.next()) |edit| {
            try actual_diff.append(allocator, edit);
        }
        try std.testing.expectEqual(expected_diff.len, actual_diff.items.len);
        for (expected_diff, actual_diff.items) |expected, actual| {
            try std.testing.expectEqualDeep(expected, actual.withoutOffset());
        }
    }
}

pub fn Diff3Iterator(comptime repo_kind: rp.RepoKind, comptime repo_opts: rp.RepoOpts(repo_kind)) type {
    return struct {
        line_count_o: usize,
        line_count_a: usize,
        line_count_b: usize,
        line_o: usize,
        line_a: usize,
        line_b: usize,
        myers_diff_iter_a: MyersDiffIterator(repo_kind, repo_opts),
        myers_diff_iter_b: MyersDiffIterator(repo_kind, repo_opts),
        finished: bool,

        pub const Range = struct {
            begin: usize,
            end: usize,
        };

        pub const Chunk = union(enum) {
            clean: Range,
            conflict: struct {
                o_range: ?Range,
                a_range: ?Range,
                b_range: ?Range,
            },
        };

        pub fn init(
            allocator: std.mem.Allocator,
            line_iter_o: *LineIterator(repo_kind, repo_opts),
            line_iter_a: *LineIterator(repo_kind, repo_opts),
            line_iter_b: *LineIterator(repo_kind, repo_opts),
        ) !Diff3Iterator(repo_kind, repo_opts) {
            var myers_diff_iter_a = try MyersDiffIterator(repo_kind, repo_opts).init(allocator, line_iter_o, line_iter_a);
            errdefer myers_diff_iter_a.deinit();
            var myers_diff_iter_b = try MyersDiffIterator(repo_kind, repo_opts).init(allocator, line_iter_o, line_iter_b);
            errdefer myers_diff_iter_b.deinit();
            return .{
                .line_count_o = line_iter_o.count(),
                .line_count_a = line_iter_a.count(),
                .line_count_b = line_iter_b.count(),
                .line_o = 0,
                .line_a = 0,
                .line_b = 0,
                .myers_diff_iter_a = myers_diff_iter_a,
                .myers_diff_iter_b = myers_diff_iter_b,
                .finished = false,
            };
        }

        pub fn next(self: *Diff3Iterator(repo_kind, repo_opts)) !?Chunk {
            if (self.finished) {
                return null;
            }

            // find next mismatch
            var i: usize = 0;
            while (self.inBounds(i) and
                self.isMatch(&self.myers_diff_iter_a, self.line_a, i) and
                self.isMatch(&self.myers_diff_iter_b, self.line_b, i))
            {
                i += 1;
            }

            if (self.inBounds(i)) {
                if (i == 0) {
                    // find next match
                    var o = self.line_o;
                    while (o < self.line_count_o and (self.myers_diff_iter_a.get(o) == null or self.myers_diff_iter_b.get(o) == null)) {
                        o += 1;
                    }
                    if (self.myers_diff_iter_a.get(o)) |a| {
                        if (self.myers_diff_iter_b.get(o)) |b| {
                            // return mismatching chunk
                            const line_o = self.line_o;
                            const line_a = self.line_a;
                            const line_b = self.line_b;
                            self.line_o = o;
                            self.line_a = a;
                            self.line_b = b;
                            return chunk(
                                lineRange(line_o, self.line_o),
                                lineRange(line_a, self.line_a),
                                lineRange(line_b, self.line_b),
                                false,
                            );
                        }
                    }
                } else {
                    // return matching chunk
                    const line_o = self.line_o;
                    const line_a = self.line_a;
                    const line_b = self.line_b;
                    self.line_o += i;
                    self.line_a += i;
                    self.line_b += i;
                    return chunk(
                        lineRange(line_o, self.line_o),
                        lineRange(line_a, self.line_a),
                        lineRange(line_b, self.line_b),
                        true,
                    );
                }
            }

            // return final chunk
            self.finished = true;
            return chunk(
                lineRange(self.line_o, self.line_count_o),
                lineRange(self.line_a, self.line_count_a),
                lineRange(self.line_b, self.line_count_b),
                i > 0,
            );
        }

        pub fn reset(self: *Diff3Iterator(repo_kind, repo_opts)) !void {
            self.line_o = 0;
            self.line_a = 0;
            self.line_b = 0;
            self.myers_diff_iter_a.reset();
            self.myers_diff_iter_b.reset();
            self.finished = false;
        }

        pub fn deinit(self: *Diff3Iterator(repo_kind, repo_opts)) void {
            self.myers_diff_iter_a.deinit();
            self.myers_diff_iter_b.deinit();
        }

        fn inBounds(self: Diff3Iterator(repo_kind, repo_opts), i: usize) bool {
            return self.line_o + i < self.line_count_o or
                self.line_a + i < self.line_count_a or
                self.line_b + i < self.line_count_b;
        }

        fn isMatch(self: Diff3Iterator(repo_kind, repo_opts), myers_diff_iter: *const MyersDiffIterator(repo_kind, repo_opts), offset: usize, i: usize) bool {
            const line_num = myers_diff_iter.get(self.line_o + i) orelse return false;
            return line_num == offset + i;
        }

        fn lineRange(begin: usize, end: usize) ?Range {
            if (end > begin) {
                return .{ .begin = begin, .end = end };
            } else {
                return null;
            }
        }

        fn chunk(o_range_maybe: ?Range, a_range_maybe: ?Range, b_range_maybe: ?Range, match: bool) ?Chunk {
            if (match) {
                return .{
                    .clean = o_range_maybe orelse return null,
                };
            } else {
                return .{
                    .conflict = .{
                        .o_range = o_range_maybe,
                        .a_range = a_range_maybe,
                        .b_range = b_range_maybe,
                    },
                };
            }
        }
    };
}

test "diff3" {
    const repo_kind = rp.RepoKind.git;
    const repo_opts = rp.RepoOpts(.git){ .is_test = true };
    const allocator = std.testing.allocator;

    const orig_lines =
        \\celery
        \\garlic
        \\onions
        \\salmon
        \\tomatoes
        \\wine
    ;
    const alice_lines =
        \\celery
        \\salmon
        \\tomatoes
        \\garlic
        \\onions
        \\wine
        \\beer
    ;
    const bob_lines =
        \\celery
        \\salmon
        \\garlic
        \\onions
        \\tomatoes
        \\wine
        \\beer
    ;

    var orig_iter = try LineIterator(repo_kind, repo_opts).initFromTestBuffer(allocator, orig_lines);
    defer orig_iter.deinit();
    var alice_iter = try LineIterator(repo_kind, repo_opts).initFromTestBuffer(allocator, alice_lines);
    defer alice_iter.deinit();
    var bob_iter = try LineIterator(repo_kind, repo_opts).initFromTestBuffer(allocator, bob_lines);
    defer bob_iter.deinit();
    var diff3_iter = try Diff3Iterator(repo_kind, repo_opts).init(allocator, &orig_iter, &alice_iter, &bob_iter);
    defer diff3_iter.deinit();

    var chunk = (try diff3_iter.next()) orelse return error.ExpectedChunk;
    try std.testing.expect(.clean == chunk);

    chunk = (try diff3_iter.next()) orelse return error.ExpectedChunk;
    try std.testing.expect(.conflict == chunk);

    chunk = (try diff3_iter.next()) orelse return error.ExpectedChunk;
    try std.testing.expect(.clean == chunk);

    chunk = (try diff3_iter.next()) orelse return error.ExpectedChunk;
    try std.testing.expect(.conflict == chunk);

    chunk = (try diff3_iter.next()) orelse return error.ExpectedChunk;
    try std.testing.expect(.clean == chunk);

    // this is a conflict even though a and b are both "beer",
    // because the original does not contain it.
    // it is only marked as clean if all three are matches.
    // when outputting the conflict lines this should be
    // auto-resolved since we can compare a and b at that point.
    chunk = (try diff3_iter.next()) orelse return error.ExpectedChunk;
    try std.testing.expect(.conflict == chunk);

    try std.testing.expect(null == try diff3_iter.next());
}

pub fn Hunk(comptime repo_kind: rp.RepoKind, comptime repo_opts: rp.RepoOpts(repo_kind)) type {
    return struct {
        edits: std.ArrayList(Edit),

        pub fn deinit(self: *Hunk(repo_kind, repo_opts), allocator: std.mem.Allocator) void {
            self.edits.deinit(allocator);
        }

        pub const Offsets = struct {
            del_start: usize,
            del_count: usize,
            ins_start: usize,
            ins_count: usize,
        };

        // header lines count from 1, and a side with no lines starts at 0
        pub fn offsets(self: Hunk(repo_kind, repo_opts)) Offsets {
            var del_first: ?usize = null;
            var ins_first: ?usize = null;
            var o = Offsets{
                .del_start = 0,
                .del_count = 0,
                .ins_start = 0,
                .ins_count = 0,
            };
            for (self.edits.items) |edit| {
                switch (edit) {
                    .eql => |eql| {
                        if (ins_first == null) ins_first = eql.new_line.num;
                        o.ins_count += 1;
                        if (del_first == null) del_first = eql.old_line.num;
                        o.del_count += 1;
                    },
                    .ins => |ins| {
                        if (ins_first == null) ins_first = ins.new_line.num;
                        o.ins_count += 1;
                    },
                    .del => |del| {
                        if (del_first == null) del_first = del.old_line.num;
                        o.del_count += 1;
                    },
                }
            }
            if (del_first) |num| o.del_start = num + 1;
            if (ins_first) |num| o.ins_start = num + 1;
            return o;
        }
    };
}

pub fn HunkIterator(comptime repo_kind: rp.RepoKind, comptime repo_opts: rp.RepoOpts(repo_kind)) type {
    return struct {
        header_lines: std.ArrayList([]const u8),
        myers_diff: MyersDiffIterator(repo_kind, repo_opts),
        eof: bool,
        arena: *std.heap.ArenaAllocator,
        line_iter_a: *LineIterator(repo_kind, repo_opts),
        line_iter_b: *LineIterator(repo_kind, repo_opts),
        found_edit: bool,
        margin: usize,
        next_hunk: Hunk(repo_kind, repo_opts),

        pub fn init(allocator: std.mem.Allocator, line_iter_a: *LineIterator(repo_kind, repo_opts), line_iter_b: *LineIterator(repo_kind, repo_opts)) !HunkIterator(repo_kind, repo_opts) {
            const arena = try allocator.create(std.heap.ArenaAllocator);
            arena.* = std.heap.ArenaAllocator.init(allocator);
            errdefer {
                arena.deinit();
                allocator.destroy(arena);
            }

            var header_lines: std.ArrayList([]const u8) = .empty;

            try header_lines.append(arena.allocator(), try arena.allocator().print("diff --git a/{s} b/{s}", .{ line_iter_a.path, line_iter_b.path }));

            var mode_maybe: ?fs.Mode = null;

            if (line_iter_a.mode) |a_mode| {
                if (line_iter_b.mode) |b_mode| {
                    if (!a_mode.eqlExact(b_mode)) {
                        try header_lines.append(arena.allocator(), try arena.allocator().print("old mode {s}", .{a_mode.toStr()}));
                        try header_lines.append(arena.allocator(), try arena.allocator().print("new mode {s}", .{b_mode.toStr()}));
                    } else {
                        mode_maybe = a_mode;
                    }
                } else {
                    try header_lines.append(arena.allocator(), try arena.allocator().print("deleted file mode {s}", .{a_mode.toStr()}));
                }
            } else {
                if (line_iter_b.mode) |b_mode| {
                    try header_lines.append(arena.allocator(), try arena.allocator().print("new file mode {s}", .{b_mode.toStr()}));
                }
            }

            if (!std.mem.eql(u8, &line_iter_a.oid, &line_iter_b.oid)) {
                if (mode_maybe) |mode| {
                    try header_lines.append(arena.allocator(), try arena.allocator().print("index {s}..{s} {s}", .{
                        line_iter_a.oid_hex[0..7],
                        line_iter_b.oid_hex[0..7],
                        mode.toStr(),
                    }));
                } else {
                    try header_lines.append(arena.allocator(), try arena.allocator().print("index {s}..{s}", .{
                        line_iter_a.oid_hex[0..7],
                        line_iter_b.oid_hex[0..7],
                    }));
                }

                try header_lines.append(arena.allocator(), try arena.allocator().print("--- a/{s}", .{line_iter_a.path}));

                if (line_iter_b.mode != null) {
                    try header_lines.append(arena.allocator(), try arena.allocator().print("+++ b/{s}", .{line_iter_b.path}));
                } else {
                    try header_lines.append(arena.allocator(), "+++ /dev/null");
                }
            }

            var myers_diff = try MyersDiffIterator(repo_kind, repo_opts).init(allocator, line_iter_a, line_iter_b);
            errdefer myers_diff.deinit();

            return HunkIterator(repo_kind, repo_opts){
                .header_lines = header_lines,
                .myers_diff = myers_diff,
                .eof = false,
                .arena = arena,
                .line_iter_a = line_iter_a,
                .line_iter_b = line_iter_b,
                .found_edit = false,
                .margin = 0,
                .next_hunk = Hunk(repo_kind, repo_opts){
                    .edits = .empty,
                },
            };
        }

        pub fn next(self: *HunkIterator(repo_kind, repo_opts), allocator: std.mem.Allocator) !?Hunk(repo_kind, repo_opts) {
            // equal lines kept around each change. as in git, changes with at
            // most twice this many equal lines between them share a hunk.
            const context: usize = 3;

            while (!self.eof) {
                const edit = (try self.myers_diff.next()) orelse {
                    self.eof = true;
                    break;
                };
                try self.next_hunk.edits.append(allocator, edit);
                // a full hunk is returned, so a long change comes in pieces
                const full = if (repo_opts.max_hunk_edits) |max_edits| self.next_hunk.edits.items.len >= max_edits else false;

                if (edit == .eql) {
                    self.margin += 1;
                    if (!self.found_edit) {
                        // before a change, only its last equal lines are kept
                        if (self.margin > context) {
                            _ = self.next_hunk.edits.orderedRemove(0);
                            self.margin -= 1;
                        }
                        continue;
                    }
                    // keep adding while another change could still join this hunk
                    if (self.margin <= 2 * context and !full) continue;
                } else {
                    self.found_edit = true;
                    self.margin = 0;
                    if (!full) continue;
                }

                var hunk = self.next_hunk;
                self.next_hunk = .{ .edits = .empty };
                self.found_edit = false;
                if (self.margin > 2 * context) {
                    // the hunk keeps its context after the last change, and the
                    // equal lines just before the next change lead into its hunk
                    const items = hunk.edits.items;
                    try self.next_hunk.edits.appendSlice(allocator, items[items.len - context ..]);
                    hunk.edits.shrinkRetainingCapacity(items.len - (self.margin - context));
                    self.margin = context;
                } else {
                    self.margin = 0;
                }
                return hunk;
            }

            if (!self.found_edit) return null;
            // the last hunk, with only its context after the last change
            var hunk = self.next_hunk;
            self.next_hunk = .{ .edits = .empty };
            if (self.margin > context) hunk.edits.shrinkRetainingCapacity(hunk.edits.items.len - (self.margin - context));
            self.found_edit = false;
            self.margin = 0;
            return hunk;
        }

        pub fn writeHunk(self: *const HunkIterator(repo_kind, repo_opts), hunk: *const Hunk(repo_kind, repo_opts), writer: *std.Io.Writer, color: bool) !void {
            const offsets = hunk.offsets();
            try writer.print("@@ -{},{} +{},{} @@\n", .{
                offsets.del_start,
                offsets.del_count,
                offsets.ins_start,
                offsets.ins_count,
            });
            for (hunk.edits.items) |edit| {
                const line_iter, const line_num, const prefix, const style: ?xitui.widget.Style = switch (edit) {
                    .eql => |eql| .{ self.line_iter_b, eql.new_line.num, " ", null },
                    .ins => |ins| .{ self.line_iter_b, ins.new_line.num, "+", .{ .fg = .ansi(.green) } },
                    .del => |del| .{ self.line_iter_a, del.old_line.num, "-", .{ .fg = .ansi(.red) } },
                };
                if (color) if (style) |s| try xitui.terminal.writeStyle(writer, s);
                try writer.print("{s} {s}", .{ prefix, try line_iter.get(line_num) });
                if (color and style != null) try xitui.terminal.attributeReset(writer);
                try writer.writeAll("\n");
            }
        }

        pub fn deinit(self: *HunkIterator(repo_kind, repo_opts), allocator: std.mem.Allocator) void {
            self.myers_diff.deinit();
            self.arena.deinit();
            allocator.destroy(self.arena);
            self.next_hunk.deinit(allocator);
        }

        pub fn reset(self: *HunkIterator(repo_kind, repo_opts), allocator: std.mem.Allocator) !void {
            self.myers_diff.reset();
            self.eof = false;
            self.line_iter_a.reset();
            self.line_iter_b.reset();
            self.found_edit = false;
            self.margin = 0;
            self.next_hunk.deinit(allocator);
            self.next_hunk = Hunk(repo_kind, repo_opts){
                .edits = .empty,
            };
        }
    };
}

pub const ConflictDiffKind = enum {
    base,
    target, // ours
    source, // theirs
};

pub const DiffKind = enum {
    work_dir,
    index,
    tree,
};

pub fn BasicDiffOptions(comptime hash_kind: hash.HashKind) type {
    return union(DiffKind) {
        work_dir: struct {
            conflict_diff_kind: ConflictDiffKind,
        },
        index,
        tree: struct {
            old: ?[hash.hexLen(hash_kind)]u8,
            new: ?[hash.hexLen(hash_kind)]u8,
        },
    };
}

pub fn DiffOptions(comptime repo_kind: rp.RepoKind, comptime repo_opts: rp.RepoOpts(repo_kind)) type {
    return union(DiffKind) {
        work_dir: struct {
            conflict_diff_kind: ConflictDiffKind,
            status: *work.Status(repo_kind, repo_opts),
        },
        index: struct {
            status: *work.Status(repo_kind, repo_opts),
        },
        tree: struct {
            tree_diff: *tr.TreeDiff(repo_kind, repo_opts),
        },
    };
}

pub fn LineIteratorPair(comptime repo_kind: rp.RepoKind, comptime repo_opts: rp.RepoOpts(repo_kind)) type {
    return struct {
        path: []const u8,
        a: LineIterator(repo_kind, repo_opts),
        b: LineIterator(repo_kind, repo_opts),

        pub fn init(
            state: rp.Repo(repo_kind, repo_opts).State(.read_only),
            io: std.Io,
            allocator: std.mem.Allocator,
            path: []const u8,
            status_kind: work.StatusKind,
            stat: *work.Status(repo_kind, repo_opts),
        ) !LineIteratorPair(repo_kind, repo_opts) {
            switch (status_kind) {
                .added => |added| {
                    switch (added) {
                        .created => {
                            var a = try LineIterator(repo_kind, repo_opts).initFromNothing(allocator, path);
                            errdefer a.deinit();
                            const index_entries_for_path = stat.index.entries.get(path) orelse return error.EntryNotFound;
                            var b = try LineIterator(repo_kind, repo_opts).initFromIndex(state, io, allocator, index_entries_for_path[0] orelse return error.NullEntry);
                            errdefer b.deinit();
                            return .{ .path = path, .a = a, .b = b };
                        },
                        .modified => {
                            var a = try LineIterator(repo_kind, repo_opts).initFromTree(state, io, allocator, path, stat.head_tree.entries.get(path) orelse return error.EntryNotFound);
                            errdefer a.deinit();
                            const index_entries_for_path = stat.index.entries.get(path) orelse return error.EntryNotFound;
                            var b = try LineIterator(repo_kind, repo_opts).initFromIndex(state, io, allocator, index_entries_for_path[0] orelse return error.NullEntry);
                            errdefer b.deinit();
                            return .{ .path = path, .a = a, .b = b };
                        },
                        .deleted => {
                            var a = try LineIterator(repo_kind, repo_opts).initFromTree(state, io, allocator, path, stat.head_tree.entries.get(path) orelse return error.EntryNotFound);
                            errdefer a.deinit();
                            var b = try LineIterator(repo_kind, repo_opts).initFromNothing(allocator, path);
                            errdefer b.deinit();
                            return .{ .path = path, .a = a, .b = b };
                        },
                        .conflict => {
                            var a = try LineIterator(repo_kind, repo_opts).initFromTree(state, io, allocator, path, stat.resolved_conflicts.get(path) orelse return error.EntryNotFound);
                            errdefer a.deinit();
                            const index_entries_for_path = stat.index.entries.get(path) orelse return error.EntryNotFound;
                            var b = try LineIterator(repo_kind, repo_opts).initFromIndex(state, io, allocator, index_entries_for_path[0] orelse return error.NullEntry);
                            errdefer b.deinit();
                            return .{ .path = path, .a = a, .b = b };
                        },
                    }
                },
                .not_added => |not_added| {
                    switch (not_added) {
                        .modified => {
                            const meta = try fs.Metadata.init(io, state.core.work_dir, path);
                            const index_entries_for_path = stat.index.entries.get(path) orelse return error.EntryNotFound;
                            var a = try LineIterator(repo_kind, repo_opts).initFromIndex(state, io, allocator, index_entries_for_path[0] orelse return error.NullEntry);
                            errdefer a.deinit();
                            var b = try LineIterator(repo_kind, repo_opts).initFromWorkDir(state, io, allocator, path, meta.mode);
                            errdefer b.deinit();
                            return .{ .path = path, .a = a, .b = b };
                        },
                        .deleted => {
                            const index_entries_for_path = stat.index.entries.get(path) orelse return error.EntryNotFound;
                            var a = try LineIterator(repo_kind, repo_opts).initFromIndex(state, io, allocator, index_entries_for_path[0] orelse return error.NullEntry);
                            errdefer a.deinit();
                            var b = try LineIterator(repo_kind, repo_opts).initFromNothing(allocator, path);
                            errdefer b.deinit();
                            return .{ .path = path, .a = a, .b = b };
                        },
                        .conflict => {
                            const meta = try fs.Metadata.init(io, state.core.work_dir, path);
                            const index_entries_for_path = stat.index.entries.get(path) orelse return error.EntryNotFound;
                            const conflict_entry = index_entries_for_path[2] orelse index_entries_for_path[3] orelse return error.NullEntry;
                            var a = try LineIterator(repo_kind, repo_opts).initFromIndex(state, io, allocator, conflict_entry);
                            errdefer a.deinit();
                            var b = try LineIterator(repo_kind, repo_opts).initFromWorkDir(state, io, allocator, path, meta.mode);
                            errdefer b.deinit();
                            return .{ .path = path, .a = a, .b = b };
                        },
                    }
                },
                .not_tracked => {
                    const meta = try fs.Metadata.init(io, state.core.work_dir, path);
                    var a = try LineIterator(repo_kind, repo_opts).initFromNothing(allocator, path);
                    errdefer a.deinit();
                    var b = try LineIterator(repo_kind, repo_opts).initFromWorkDir(state, io, allocator, path, meta.mode);
                    errdefer b.deinit();
                    return .{ .path = path, .a = a, .b = b };
                },
            }
        }

        pub fn deinit(self: *LineIteratorPair(repo_kind, repo_opts)) void {
            self.a.deinit();
            self.b.deinit();
        }
    };
}

pub fn FileIterator(comptime repo_kind: rp.RepoKind, comptime repo_opts: rp.RepoOpts(repo_kind)) type {
    return struct {
        io: std.Io,
        allocator: std.mem.Allocator,
        core: *rp.Repo(repo_kind, repo_opts).Core,
        moment: rp.Repo(repo_kind, repo_opts).Moment(.read_only),
        diff_opts: DiffOptions(repo_kind, repo_opts),
        next_index: usize,
        total_line_count: usize,

        pub fn init(
            state: rp.Repo(repo_kind, repo_opts).State(.read_only),
            io: std.Io,
            allocator: std.mem.Allocator,
            diff_opts: DiffOptions(repo_kind, repo_opts),
        ) !FileIterator(repo_kind, repo_opts) {
            return .{
                .io = io,
                .allocator = allocator,
                .core = state.core,
                .moment = state.extra.moment.*,
                .diff_opts = diff_opts,
                .next_index = 0,
                .total_line_count = 0,
            };
        }

        pub fn next(self: *FileIterator(repo_kind, repo_opts)) !?LineIteratorPair(repo_kind, repo_opts) {
            var pair = try self.nextUnlimited() orelse return null;
            errdefer pair.deinit();

            // enforce the cumulative line budget across all files in this diff
            self.total_line_count += pair.a.count() + pair.b.count();
            if (self.total_line_count > repo_opts.max_total_line_count) {
                return error.DiffTooLarge;
            }

            return pair;
        }

        /// patch writing needs every file, so it skips the cumulative line budget
        pub fn nextUnlimited(self: *FileIterator(repo_kind, repo_opts)) !?LineIteratorPair(repo_kind, repo_opts) {
            const state = rp.Repo(repo_kind, repo_opts).State(.read_only){ .core = self.core, .extra = .{ .moment = &self.moment } };
            var next_index = self.next_index;
            switch (self.diff_opts) {
                .work_dir => |work_dir| {
                    if (next_index < work_dir.status.unresolved_conflicts.count()) {
                        const path = work_dir.status.unresolved_conflicts.keys()[next_index];
                        const meta = try fs.Metadata.init(self.io, self.core.work_dir, path);
                        const stage: usize = switch (work_dir.conflict_diff_kind) {
                            .base => 1,
                            .target => 2,
                            .source => 3,
                        };
                        const index_entries_for_path = work_dir.status.index.entries.get(path) orelse return error.EntryNotFound;
                        // if there is an entry for the stage we are diffing
                        if (index_entries_for_path[stage]) |index_entry| {
                            var a = try LineIterator(repo_kind, repo_opts).initFromIndex(state, self.io, self.allocator, index_entry);
                            errdefer a.deinit();
                            var b = switch (meta.kind) {
                                .file, .sym_link => try LineIterator(repo_kind, repo_opts).initFromWorkDir(state, self.io, self.allocator, path, meta.mode),
                                // in file/dir conflicts, `path` may be a directory which can't be diffed, so just make it nothing
                                else => try LineIterator(repo_kind, repo_opts).initFromNothing(self.allocator, path),
                            };
                            errdefer b.deinit();
                            self.next_index += 1;
                            return .{ .path = path, .a = a, .b = b };
                        }
                        // there is no entry, so just skip it and call this method recursively
                        else {
                            self.next_index += 1;
                            return try self.nextUnlimited();
                        }
                    } else {
                        next_index -= work_dir.status.unresolved_conflicts.count();
                    }

                    if (next_index < work_dir.status.work_dir_modified.count()) {
                        const entry = work_dir.status.work_dir_modified.values()[next_index];
                        const index_entries_for_path = work_dir.status.index.entries.get(entry.path) orelse return error.EntryNotFound;
                        var a = try LineIterator(repo_kind, repo_opts).initFromIndex(state, self.io, self.allocator, index_entries_for_path[0] orelse return error.NullEntry);
                        errdefer a.deinit();
                        var b = try LineIterator(repo_kind, repo_opts).initFromWorkDir(state, self.io, self.allocator, entry.path, entry.meta.mode);
                        errdefer b.deinit();
                        self.next_index += 1;
                        return .{ .path = entry.path, .a = a, .b = b };
                    } else {
                        next_index -= work_dir.status.work_dir_modified.count();
                    }

                    if (next_index < work_dir.status.work_dir_deleted.count()) {
                        const path = work_dir.status.work_dir_deleted.keys()[next_index];
                        const index_entries_for_path = work_dir.status.index.entries.get(path) orelse return error.EntryNotFound;
                        var a = try LineIterator(repo_kind, repo_opts).initFromIndex(state, self.io, self.allocator, index_entries_for_path[0] orelse return error.NullEntry);
                        errdefer a.deinit();
                        var b = try LineIterator(repo_kind, repo_opts).initFromNothing(self.allocator, path);
                        errdefer b.deinit();
                        self.next_index += 1;
                        return .{ .path = path, .a = a, .b = b };
                    }
                },
                .index => |index| {
                    if (next_index < index.status.index_added.count()) {
                        const path = index.status.index_added.keys()[next_index];
                        var a = try LineIterator(repo_kind, repo_opts).initFromNothing(self.allocator, path);
                        errdefer a.deinit();
                        const index_entries_for_path = index.status.index.entries.get(path) orelse return error.EntryNotFound;
                        var b = try LineIterator(repo_kind, repo_opts).initFromIndex(state, self.io, self.allocator, index_entries_for_path[0] orelse return error.NullEntry);
                        errdefer b.deinit();
                        self.next_index += 1;
                        return .{ .path = path, .a = a, .b = b };
                    } else {
                        next_index -= index.status.index_added.count();
                    }

                    if (next_index < index.status.index_modified.count()) {
                        const path = index.status.index_modified.keys()[next_index];
                        var a = try LineIterator(repo_kind, repo_opts).initFromTree(state, self.io, self.allocator, path, index.status.head_tree.entries.get(path) orelse return error.EntryNotFound);
                        errdefer a.deinit();
                        const index_entries_for_path = index.status.index.entries.get(path) orelse return error.EntryNotFound;
                        var b = try LineIterator(repo_kind, repo_opts).initFromIndex(state, self.io, self.allocator, index_entries_for_path[0] orelse return error.NullEntry);
                        errdefer b.deinit();
                        self.next_index += 1;
                        return .{ .path = path, .a = a, .b = b };
                    } else {
                        next_index -= index.status.index_modified.count();
                    }

                    if (next_index < index.status.index_deleted.count()) {
                        const path = index.status.index_deleted.keys()[next_index];
                        var a = try LineIterator(repo_kind, repo_opts).initFromTree(state, self.io, self.allocator, path, index.status.head_tree.entries.get(path) orelse return error.EntryNotFound);
                        errdefer a.deinit();
                        var b = try LineIterator(repo_kind, repo_opts).initFromNothing(self.allocator, path);
                        errdefer b.deinit();
                        self.next_index += 1;
                        return .{ .path = path, .a = a, .b = b };
                    }
                },
                .tree => |tree| {
                    if (next_index < tree.tree_diff.changes.count()) {
                        const path = tree.tree_diff.changes.keys()[next_index];
                        const change = tree.tree_diff.changes.values()[next_index];
                        var a = if (change.old) |old|
                            try LineIterator(repo_kind, repo_opts).initFromOid(state, self.io, self.allocator, path, &old.oid, old.mode)
                        else
                            try LineIterator(repo_kind, repo_opts).initFromNothing(self.allocator, path);
                        errdefer a.deinit();
                        var b = if (change.new) |new|
                            try LineIterator(repo_kind, repo_opts).initFromOid(state, self.io, self.allocator, path, &new.oid, new.mode)
                        else
                            try LineIterator(repo_kind, repo_opts).initFromNothing(self.allocator, path);
                        errdefer b.deinit();
                        self.next_index += 1;
                        return .{ .path = path, .a = a, .b = b };
                    }
                },
            }

            return null;
        }
    };
}
