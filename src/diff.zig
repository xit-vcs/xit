const std = @import("std");
const rp = @import("./repo.zig");
const work = @import("./workdir.zig");
const hash = @import("./hash.zig");
const fs = @import("./fs.zig");
const idx = @import("./index.zig");
const obj = @import("./object.zig");
const tr = @import("./tree.zig");

pub fn LineIterator(comptime repo_kind: rp.RepoKind, comptime repo_opts: rp.RepoOpts(repo_kind)) type {
    return struct {
        io: std.Io,
        allocator: std.mem.Allocator,
        path: []const u8,
        oid: [hash.byteLen(repo_opts.hash)]u8,
        oid_hex: [hash.hexLen(repo_opts.hash)]u8,
        mode: ?fs.Mode,
        line_offsets: []usize,
        current_line: usize,
        source: Source,

        const Source = union(enum) {
            object: struct {
                object_reader: obj.ObjectReader(repo_kind, repo_opts),
                eof: bool,
            },
            work_dir: struct {
                file: std.Io.File,
                pos: u64,
                eof: bool,
            },
            buffer: struct {
                arena: *std.heap.ArenaAllocator,
                lines: []const []const u8,
            },
            nothing,
            binary,

            fn deinit(self: *Source, io: std.Io, allocator: std.mem.Allocator) void {
                switch (self.*) {
                    .object => |*object| object.object_reader.deinit(),
                    .work_dir => |*work_dir| work_dir.file.close(io),
                    .buffer => |*buffer| {
                        buffer.arena.deinit();
                        allocator.destroy(buffer.arena);
                    },
                    .nothing => {},
                    .binary => {},
                }
            }
        };

        const in_memory = true;

        pub fn initFromIndex(
            state: rp.Repo(repo_kind, repo_opts).State(.read_only),
            io: std.Io,
            allocator: std.mem.Allocator,
            entry: idx.Index(repo_kind, repo_opts).Entry,
        ) !LineIterator(repo_kind, repo_opts) {
            const oid_hex = std.fmt.bytesToHex(&entry.oid, .lower);
            var object_reader = try obj.ObjectReader(repo_kind, repo_opts).init(state, io, allocator, &oid_hex);
            errdefer object_reader.deinit();
            var iter = LineIterator(repo_kind, repo_opts){
                .io = io,
                .allocator = allocator,
                .path = entry.path,
                .oid = entry.oid,
                .oid_hex = oid_hex,
                .mode = entry.mode,
                .line_offsets = undefined,
                .current_line = 0,
                .source = .{
                    .object = .{
                        .object_reader = object_reader,
                        .eof = false,
                    },
                },
            };

            try iter.validateLines();

            if (in_memory and iter.source == .object) {
                try iter.convertToBuffer();
            }

            return iter;
        }

        pub fn initFromWorkDir(
            state: rp.Repo(repo_kind, repo_opts).State(.read_only),
            io: std.Io,
            allocator: std.mem.Allocator,
            path: []const u8,
            mode: fs.Mode,
        ) !LineIterator(repo_kind, repo_opts) {
            switch (mode.content.object_type) {
                .regular_file => {
                    var file = try state.core.work_dir.openFile(io, path, .{ .mode = .read_only, .allow_directory = false });
                    errdefer file.close(io);
                    const file_size = try file.length(io);
                    const header = try std.fmt.allocPrint(allocator, "blob {}\x00", .{file_size});
                    defer allocator.free(header);

                    var reader_buffer = [_]u8{0} ** repo_opts.buffer_size;
                    var reader = file.reader(io, &reader_buffer);

                    var oid = [_]u8{0} ** hash.byteLen(repo_opts.hash);
                    hash.hashReader(repo_opts.hash, repo_opts.read_size, &reader.interface, header, &oid) catch |err| switch (err) {
                        error.ReadFailed => |e| return reader.err orelse e,
                        else => |e| return e,
                    };

                    var iter = LineIterator(repo_kind, repo_opts){
                        .io = io,
                        .allocator = allocator,
                        .path = path,
                        .oid = oid,
                        .oid_hex = std.fmt.bytesToHex(&oid, .lower),
                        .mode = mode,
                        .line_offsets = undefined,
                        .current_line = 0,
                        .source = .{
                            .work_dir = .{
                                .file = file,
                                .pos = 0,
                                .eof = false,
                            },
                        },
                    };

                    try iter.validateLines();

                    if (in_memory and iter.source == .work_dir) {
                        try iter.convertToBuffer();
                    }

                    return iter;
                },
                .symbolic_link => {
                    var target_path_buffer = [_]u8{0} ** std.fs.max_path_bytes;
                    const target_path_size = try state.core.work_dir.readLink(io, path, &target_path_buffer);
                    const target_path = target_path_buffer[0..target_path_size];

                    // make reader
                    var reader = std.Io.Reader.fixed(target_path);

                    // create blob header
                    var header_buffer = [_]u8{0} ** 256; // should be plenty of space
                    const header = try std.fmt.bufPrint(&header_buffer, "blob {}\x00", .{target_path.len});

                    var oid = [_]u8{0} ** hash.byteLen(repo_opts.hash);
                    try hash.hashReader(repo_opts.hash, repo_opts.read_size, &reader, header, &oid);

                    return try initFromBuffer(io, allocator, path, &oid, mode, target_path);
                },
                else => return error.UnexpectedFileKind,
            }
        }

        pub fn initFromNothing(io: std.Io, allocator: std.mem.Allocator, path: []const u8) !LineIterator(repo_kind, repo_opts) {
            var iter = LineIterator(repo_kind, repo_opts){
                .io = io,
                .allocator = allocator,
                .path = path,
                .oid = [_]u8{0} ** hash.byteLen(repo_opts.hash),
                .oid_hex = [_]u8{'0'} ** hash.hexLen(repo_opts.hash),
                .mode = null,
                .line_offsets = undefined,
                .current_line = 0,
                .source = .nothing,
            };
            try iter.validateLines();
            return iter;
        }

        pub fn initFromTree(
            state: rp.Repo(repo_kind, repo_opts).State(.read_only),
            io: std.Io,
            allocator: std.mem.Allocator,
            path: []const u8,
            entry: tr.TreeEntry(repo_opts.hash),
        ) !LineIterator(repo_kind, repo_opts) {
            const oid_hex = std.fmt.bytesToHex(&entry.oid, .lower);

            // treat submodules as binary files so they are ignored in diffs and patches
            if (entry.mode.content.object_type == .gitlink) {
                var offsets = std.ArrayList(usize){};
                errdefer offsets.deinit(allocator);
                return .{
                    .io = io,
                    .allocator = allocator,
                    .path = path,
                    .oid = entry.oid,
                    .oid_hex = oid_hex,
                    .mode = entry.mode,
                    .line_offsets = try offsets.toOwnedSlice(allocator),
                    .current_line = 0,
                    .source = .binary,
                };
            }

            var object_reader = try obj.ObjectReader(repo_kind, repo_opts).init(state, io, allocator, &oid_hex);
            errdefer object_reader.deinit();
            var iter = LineIterator(repo_kind, repo_opts){
                .io = io,
                .allocator = allocator,
                .path = path,
                .oid = entry.oid,
                .oid_hex = oid_hex,
                .mode = entry.mode,
                .line_offsets = undefined,
                .current_line = 0,
                .source = .{
                    .object = .{
                        .object_reader = object_reader,
                        .eof = false,
                    },
                },
            };

            try iter.validateLines();

            if (in_memory and iter.source == .object) {
                try iter.convertToBuffer();
            }

            return iter;
        }

        pub fn initFromOid(
            state: rp.Repo(repo_kind, repo_opts).State(.read_only),
            io: std.Io,
            allocator: std.mem.Allocator,
            path: []const u8,
            oid: *const [hash.byteLen(repo_opts.hash)]u8,
            mode_maybe: ?fs.Mode,
        ) !LineIterator(repo_kind, repo_opts) {
            const oid_hex = std.fmt.bytesToHex(oid, .lower);

            // treat submodules as binary files so they are ignored in diffs and patches
            if (mode_maybe) |mode| {
                if (mode.content.object_type == .gitlink) {
                    var offsets = std.ArrayList(usize){};
                    errdefer offsets.deinit(allocator);
                    return .{
                        .io = io,
                        .allocator = allocator,
                        .path = path,
                        .oid = oid.*,
                        .oid_hex = oid_hex,
                        .mode = mode_maybe,
                        .line_offsets = try offsets.toOwnedSlice(allocator),
                        .current_line = 0,
                        .source = .binary,
                    };
                }
            }

            var object_reader = try obj.ObjectReader(repo_kind, repo_opts).init(state, io, allocator, &oid_hex);
            errdefer object_reader.deinit();
            var iter = LineIterator(repo_kind, repo_opts){
                .io = io,
                .allocator = allocator,
                .path = path,
                .oid = oid.*,
                .oid_hex = oid_hex,
                .mode = mode_maybe,
                .line_offsets = undefined,
                .current_line = 0,
                .source = .{
                    .object = .{
                        .object_reader = object_reader,
                        .eof = false,
                    },
                },
            };

            try iter.validateLines();

            if (in_memory and iter.source == .object) {
                try iter.convertToBuffer();
            }

            return iter;
        }

        pub fn initFromBuffer(
            io: std.Io,
            allocator: std.mem.Allocator,
            path: []const u8,
            oid: *const [hash.byteLen(repo_opts.hash)]u8,
            mode_maybe: ?fs.Mode,
            buffer: []const u8,
        ) !LineIterator(repo_kind, repo_opts) {
            var reader = std.Io.Reader.fixed(buffer);

            const arena = try allocator.create(std.heap.ArenaAllocator);
            arena.* = std.heap.ArenaAllocator.init(allocator);
            errdefer {
                arena.deinit();
                allocator.destroy(arena);
            }

            var lines = std.ArrayList([]const u8){};
            errdefer lines.deinit(arena.allocator());

            // for each line...
            while (reader.peekByte()) |_| {
                var line_writer = std.Io.Writer.Allocating.init(arena.allocator());
                _ = try reader.streamDelimiterLimit(&line_writer.writer, '\n', .limited(repo_opts.max_line_size));

                // skip delimiter
                if (reader.bufferedLen() > 0) {
                    reader.toss(1);
                }

                try lines.append(arena.allocator(), line_writer.written());
            } else |err| switch (err) {
                error.EndOfStream => {},
                else => |e| return e,
            }

            var iter = LineIterator(repo_kind, repo_opts){
                .io = io,
                .allocator = allocator,
                .path = path,
                .oid = oid.*,
                .oid_hex = std.fmt.bytesToHex(oid, .lower),
                .mode = mode_maybe,
                .line_offsets = undefined,
                .current_line = 0,
                .source = .{
                    .buffer = .{
                        .arena = arena,
                        .lines = try lines.toOwnedSlice(arena.allocator()),
                    },
                },
            };

            try iter.validateLines();

            return iter;
        }

        pub fn initFromTestBuffer(
            io: std.Io,
            allocator: std.mem.Allocator,
            buffer: []const u8,
        ) !LineIterator(repo_kind, repo_opts) {
            return try initFromBuffer(io, allocator, "", &[_]u8{0} ** hash.byteLen(repo_opts.hash), null, buffer);
        }

        pub fn convertToBuffer(self: *LineIterator(repo_kind, repo_opts)) !void {
            const arena = try self.allocator.create(std.heap.ArenaAllocator);
            arena.* = std.heap.ArenaAllocator.init(self.allocator);
            errdefer {
                arena.deinit();
                self.allocator.destroy(arena);
            }

            var lines = std.ArrayList([]const u8){};
            errdefer lines.deinit(arena.allocator());

            try self.reset();

            while (try self.next()) |line| {
                defer self.free(line);
                const dupe = try arena.allocator().dupe(u8, line);
                try lines.append(arena.allocator(), dupe);
            }

            self.source.deinit(self.io, self.allocator);
            self.source = .{
                .buffer = .{
                    .arena = arena,
                    .lines = try lines.toOwnedSlice(arena.allocator()),
                },
            };
        }

        pub fn next(self: *LineIterator(repo_kind, repo_opts)) !?[]const u8 {
            switch (self.source) {
                .object => |*object| {
                    if (object.eof) {
                        return null;
                    }
                    var line_arr = std.ArrayList(u8){};
                    errdefer line_arr.deinit(self.allocator);
                    while (true) {
                        const byte = object.object_reader.interface.takeByte() catch |err| switch (err) {
                            error.EndOfStream => {
                                object.eof = true;
                                break;
                            },
                            else => |e| return e,
                        };
                        if (byte == '\n') {
                            break;
                        } else {
                            if (line_arr.items.len == repo_opts.max_line_size) {
                                return error.StreamTooLong;
                            }
                            try line_arr.append(self.allocator, byte);
                        }
                    }
                    const line = try line_arr.toOwnedSlice(self.allocator);
                    self.current_line += 1;
                    return line;
                },
                .work_dir => |*work_dir| {
                    if (work_dir.eof) {
                        return null;
                    }

                    var line_writer = std.Io.Writer.Allocating.init(self.allocator);
                    errdefer line_writer.deinit();

                    var reader_buffer = [_]u8{0} ** repo_opts.buffer_size;
                    var reader = work_dir.file.reader(self.io, &reader_buffer);
                    try reader.seekTo(work_dir.pos);
                    _ = try reader.interface.streamDelimiterLimit(&line_writer.writer, '\n', .limited(repo_opts.max_line_size));

                    // skip delimiter
                    if (reader.interface.bufferedLen() > 0) {
                        reader.interface.toss(1);
                    } else {
                        work_dir.eof = true;
                    }

                    // update file seek position
                    work_dir.pos = reader.logicalPos();

                    const line = try line_writer.toOwnedSlice();
                    self.current_line += 1;
                    return line;
                },
                .buffer => |*buffer| {
                    if (self.current_line < buffer.lines.len) {
                        const line = buffer.lines[self.current_line];
                        self.current_line += 1;
                        return line;
                    } else {
                        return null;
                    }
                },
                .nothing => return null,
                .binary => return null,
            }
        }

        pub fn free(self: *const LineIterator(repo_kind, repo_opts), line: []const u8) void {
            switch (self.source) {
                .object => self.allocator.free(line),
                .work_dir => self.allocator.free(line),
                .buffer => {},
                .nothing => {},
                .binary => {},
            }
        }

        pub fn get(self: *LineIterator(repo_kind, repo_opts), line_num: usize) ![]const u8 {
            try self.seekTo(line_num);
            return try self.next() orelse return error.ExpectedLine;
        }

        pub fn reset(self: *LineIterator(repo_kind, repo_opts)) !void {
            self.current_line = 0;
            switch (self.source) {
                .object => |*object| {
                    object.eof = false;
                    try object.object_reader.reset();
                },
                .work_dir => |*work_dir| {
                    work_dir.pos = 0;
                    work_dir.eof = false;
                },
                .buffer => {},
                .nothing => {},
                .binary => {},
            }
        }

        pub fn count(self: *LineIterator(repo_kind, repo_opts)) usize {
            return self.line_offsets.len;
        }

        pub fn deinit(self: *LineIterator(repo_kind, repo_opts)) void {
            self.source.deinit(self.io, self.allocator);
            self.allocator.free(self.line_offsets);
        }

        fn seekTo(self: *LineIterator(repo_kind, repo_opts), line_num: u64) !void {
            // optimization: if we're already on the correct line, there is no need to seek
            if (line_num == self.current_line) {
                return;
            }

            const position = self.line_offsets[line_num];

            switch (self.source) {
                .object => |*object| {
                    // we don't call reset here because ObjectReader.seekTo already calls it
                    object.eof = false;
                    try object.object_reader.seekTo(position);
                },
                .work_dir => |*work_dir| {
                    try self.reset();
                    work_dir.pos = position;
                },
                .buffer => {},
                .nothing => {},
                .binary => {},
            }

            self.current_line = line_num;
        }

        /// reads each line to populate line_offsets and ensure
        /// that there is no binary data.
        fn validateLines(self: *LineIterator(repo_kind, repo_opts)) !void {
            var offsets = std.ArrayList(usize){};
            errdefer offsets.deinit(self.allocator);
            var last_pos: usize = 0;
            var convert_to_binary = false;

            while (self.next() catch |err| switch (err) {
                error.StreamTooLong => blk: {
                    // if the line exceeds the max length, consider this file binary
                    convert_to_binary = true;
                    break :blk null;
                },
                else => |e| return e,
            }) |line| {
                defer self.free(line);

                // if line doesn't contain valid unicode or the line count has been exceeded,
                // consider this file binary
                if (!std.unicode.utf8ValidateSlice(line) or offsets.items.len == repo_opts.max_line_count) {
                    convert_to_binary = true;
                    break;
                }

                try offsets.append(self.allocator, last_pos);
                last_pos += line.len + 1;
            }

            if (convert_to_binary) {
                self.source.deinit(self.io, self.allocator);
                self.source = .binary;
                offsets.clearAndFree(self.allocator);
            }

            self.line_offsets = try offsets.toOwnedSlice(self.allocator);
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

pub fn MyersDiffIterator(comptime repo_kind: rp.RepoKind, comptime repo_opts: rp.RepoOpts(repo_kind)) type {
    return struct {
        allocator: std.mem.Allocator,
        cache: std.ArrayList(Edit),
        stack: std.ArrayList(isize),
        action: ?Action,
        b: []isize,
        i: isize,
        j: isize,
        n: isize,
        m: isize,
        z: isize,
        range_maybe: ?Range,
        deferred_range: Range,
        line_iter_a: *LineIterator(repo_kind, repo_opts),
        line_iter_b: *LineIterator(repo_kind, repo_opts),
        next_index: usize,
        x_index: usize,
        y_index: usize,

        fn eq(self: *const MyersDiffIterator(repo_kind, repo_opts), i: usize, j: usize) !bool {
            const line_a = try self.line_iter_a.get(i);
            defer self.line_iter_a.free(line_a);
            const line_b = try self.line_iter_b.get(j);
            defer self.line_iter_b.free(line_b);
            return std.mem.eql(u8, line_a, line_b);
        }

        pub const Action = enum {
            push,
            pop,
        };

        pub const Range = struct {
            del_start: usize,
            del_end: usize,
            ins_start: usize,
            ins_end: usize,
        };

        fn diff(self: *MyersDiffIterator(repo_kind, repo_opts), action: Action) !?Action {
            var i = self.i;
            var j = self.j;
            var n = self.n;
            var m = self.m;
            var z = self.z;

            action: switch (action) {
                .push => {
                    z_block: while (n > 0 and m > 0) {
                        @memset(self.b, 0);

                        const w = n - m;
                        const l = n + m;
                        const parity = l & 1;
                        const offsetx = i + n - 1;
                        const offsety = j + m - 1;
                        const hmax = @as(usize, @intCast(l + parity)) / 2;

                        h_loop: for (0..hmax + 1) |h| {
                            const hh: isize = @intCast(h);
                            const kmin: isize = 2 * @max(0, hh - m) - hh;
                            const kmax: isize = hh - 2 * @max(0, hh - n);

                            // forwards
                            var k: isize = kmin;
                            while (k <= kmax) {
                                defer k += 2;
                                const gkm = self.b[@intCast(k - 1 - z * @divFloor(k - 1, z))];
                                const gkp = self.b[@intCast(k + 1 - z * @divFloor(k + 1, z))];
                                const u = if (k == -hh or (k != hh and gkm < gkp)) gkp else gkm + 1;
                                const v = u - k;
                                var x = u;
                                var y = v;
                                while (x < n and y < m and try self.eq(@intCast(i + x), @intCast(j + y))) {
                                    x += 1;
                                    y += 1;
                                }
                                self.b[@intCast(k - z * @divFloor(k, z))] = x;
                                if (parity == 1) {
                                    const zz = w - k;
                                    if (zz >= 1 - hh and zz < hh and x + self.b[@intCast(z + zz - z * @divFloor(zz, z))] >= n) {
                                        if (h > 1 or x != u) {
                                            try self.stack.append(self.allocator, i + x);
                                            try self.stack.append(self.allocator, n - x);
                                            try self.stack.append(self.allocator, j + y);
                                            try self.stack.append(self.allocator, m - y);
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
                                const pkm = self.b[@intCast(z + k - 1 - z * @divFloor(k - 1, z))];
                                const pkp = self.b[@intCast(z + k + 1 - z * @divFloor(k + 1, z))];
                                const u = if (k == -hh or (k != hh and pkm < pkp)) pkp else pkm + 1;
                                const v = u - k;
                                var x = u;
                                var y = v;
                                while (x < n and y < m and try self.eq(@intCast(offsetx - x), @intCast(offsety - y))) {
                                    x += 1;
                                    y += 1;
                                }
                                self.b[@intCast(z + k - z * @divFloor(k, z))] = x;
                                if (parity == 0) {
                                    const zz = w - k;
                                    if (zz >= -hh and zz <= hh and x + self.b[@intCast(zz - z * @divFloor(zz, z))] >= n) {
                                        if (h > 0 or x != u) {
                                            try self.stack.append(self.allocator, i + n - u);
                                            try self.stack.append(self.allocator, u);
                                            try self.stack.append(self.allocator, j + m - v);
                                            try self.stack.append(self.allocator, v);
                                            n = n - x;
                                            m = m - y;
                                            z = 2 * (@min(n, m) + 1);
                                            continue :z_block;
                                        } else break :h_loop;
                                    }
                                }
                            }
                        }

                        if (n == m) {
                            continue;
                        }
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

                    if (n + m != 0) {
                        if (self.range_maybe) |*range| {
                            if (range.del_end == i or range.ins_end == j) {
                                range.del_end = @intCast(i + n);
                                range.ins_end = @intCast(j + m);
                                continue :action .pop;
                            }
                        }

                        const range_maybe = self.range_maybe;
                        self.range_maybe = .{
                            .del_start = @intCast(i),
                            .del_end = @intCast(i + n),
                            .ins_start = @intCast(j),
                            .ins_end = @intCast(j + m),
                        };

                        if (range_maybe) |range| {
                            self.deferred_range = range;
                            self.i = i;
                            self.n = n;
                            self.j = j;
                            self.m = m;
                            self.z = z;
                            return .pop;
                        }
                    }

                    continue :action .pop;
                },
                .pop => {
                    if (self.stack.items.len == 0) return null;

                    m = self.stack.pop() orelse unreachable;
                    j = self.stack.pop() orelse unreachable;
                    n = self.stack.pop() orelse unreachable;
                    i = self.stack.pop() orelse unreachable;
                    z = 2 * (@min(n, m) + 1);
                    continue :action .push;
                },
            }
        }

        pub fn init(allocator: std.mem.Allocator, line_iter_a: *LineIterator(repo_kind, repo_opts), line_iter_b: *LineIterator(repo_kind, repo_opts)) !MyersDiffIterator(repo_kind, repo_opts) {
            const i: usize = 0;
            const n = line_iter_a.count();
            const m = line_iter_b.count();
            const z = (@min(n, m) + 1) * 2;

            const b = try allocator.alloc(isize, 2 * z);
            errdefer allocator.free(b);
            @memset(b, 0);

            return MyersDiffIterator(repo_kind, repo_opts){
                .allocator = allocator,
                .cache = std.ArrayList(Edit){},
                .stack = std.ArrayList(isize){},
                .action = .push,
                .b = b,
                .i = @intCast(i),
                .j = @intCast(i),
                .n = @intCast(n),
                .m = @intCast(m),
                .z = @intCast(z),
                .range_maybe = null,
                .deferred_range = std.mem.zeroInit(Range, .{}),
                .line_iter_a = line_iter_a,
                .line_iter_b = line_iter_b,
                .next_index = 0,
                .x_index = 0,
                .y_index = 0,
            };
        }

        pub fn next(self: *MyersDiffIterator(repo_kind, repo_opts)) !?Edit {
            if (self.next_index >= self.cache.items.len) {
                const action = try self.diff(self.action orelse return null);
                self.action = action;

                const range = if (.pop == action)
                    self.deferred_range
                else if (self.range_maybe) |range|
                    range
                else
                    return null;

                const sx: usize = @intCast(range.del_start);
                const ex: usize = @intCast(range.del_end);
                const sy: usize = @intCast(range.ins_start);
                const ey: usize = @intCast(range.ins_end);

                for (self.x_index..sx, self.y_index..sy) |old_idx, new_idx| {
                    const old_offset = self.line_iter_a.line_offsets[old_idx];
                    const new_offset = self.line_iter_b.line_offsets[new_idx];
                    try self.cache.append(self.allocator, .{
                        .eql = .{
                            .old_line = .{ .num = old_idx, .offset = old_offset },
                            .new_line = .{ .num = new_idx, .offset = new_offset },
                        },
                    });
                }

                for (sx..ex) |old_idx| {
                    const old_offset = self.line_iter_a.line_offsets[old_idx];
                    try self.cache.append(self.allocator, .{
                        .del = .{
                            .old_line = .{ .num = old_idx, .offset = old_offset },
                        },
                    });
                }

                for (sy..ey) |new_idx| {
                    const new_offset = self.line_iter_b.line_offsets[new_idx];
                    try self.cache.append(self.allocator, .{
                        .ins = .{
                            .new_line = .{ .num = new_idx, .offset = new_offset },
                        },
                    });
                }

                if (null == action) {
                    for (ex..self.line_iter_a.count(), ey..self.line_iter_b.count()) |old_idx, new_idx| {
                        const old_offset = self.line_iter_a.line_offsets[old_idx];
                        const new_offset = self.line_iter_b.line_offsets[new_idx];
                        try self.cache.append(self.allocator, .{
                            .eql = .{
                                .old_line = .{ .num = old_idx, .offset = old_offset },
                                .new_line = .{ .num = new_idx, .offset = new_offset },
                            },
                        });
                    }
                }

                self.x_index = ex;
                self.y_index = ey;
            }

            const edit = self.cache.items[self.next_index];
            self.next_index += 1;
            return edit;
        }

        pub fn get(self: *MyersDiffIterator(repo_kind, repo_opts), old_line: usize) !?usize {
            while (try self.next()) |_| {}

            for (self.cache.items) |edit| {
                if (.eql == edit) {
                    if (edit.eql.old_line.num < old_line) {
                        continue;
                    } else if (edit.eql.old_line.num == old_line) {
                        return edit.eql.new_line.num;
                    } else {
                        break;
                    }
                }
            }
            return null;
        }

        pub fn contains(self: *MyersDiffIterator(repo_kind, repo_opts), old_line: usize) !bool {
            if (try self.get(old_line)) |_| {
                return true;
            } else {
                return false;
            }
        }

        pub fn reset(self: *MyersDiffIterator(repo_kind, repo_opts)) !void {
            try self.line_iter_a.reset();
            try self.line_iter_b.reset();
            self.next_index = 0;
        }

        pub fn deinit(self: *MyersDiffIterator(repo_kind, repo_opts)) void {
            self.allocator.free(self.b);
            self.cache.deinit(self.allocator);
            self.stack.deinit(self.allocator);
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
        var actual_diff = std.ArrayList(Edit){};
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
        var actual_diff = std.ArrayList(Edit){};
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
                try self.isMatch(&self.myers_diff_iter_a, self.line_a, i) and
                try self.isMatch(&self.myers_diff_iter_b, self.line_b, i))
            {
                i += 1;
            }

            if (self.inBounds(i)) {
                if (i == 0) {
                    // find next match
                    var o = self.line_o;
                    while (o < self.line_count_o and (!(try self.myers_diff_iter_a.contains(o)) or !(try self.myers_diff_iter_b.contains(o)))) {
                        o += 1;
                    }
                    if (try self.myers_diff_iter_a.get(o)) |a| {
                        if (try self.myers_diff_iter_b.get(o)) |b| {
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
            try self.myers_diff_iter_a.reset();
            try self.myers_diff_iter_b.reset();
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

        fn isMatch(self: Diff3Iterator(repo_kind, repo_opts), myers_diff_iter: *MyersDiffIterator(repo_kind, repo_opts), offset: usize, i: usize) !bool {
            if (try myers_diff_iter.get(self.line_o + i)) |line_num| {
                return line_num == offset + i;
            } else {
                return false;
            }
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

        pub fn offsets(self: Hunk(repo_kind, repo_opts)) Offsets {
            var o = Offsets{
                .del_start = 0,
                .del_count = 0,
                .ins_start = 0,
                .ins_count = 0,
            };
            for (self.edits.items) |edit| {
                switch (edit) {
                    .eql => |eql| {
                        if (o.ins_start == 0) o.ins_start = eql.new_line.num;
                        o.ins_count += 1;
                        if (o.del_start == 0) o.del_start = eql.old_line.num;
                        o.del_count += 1;
                    },
                    .ins => |ins| {
                        if (o.ins_start == 0) o.ins_start = ins.new_line.num;
                        o.ins_count += 1;
                    },
                    .del => |del| {
                        if (o.del_start == 0) o.del_start = del.old_line.num;
                        o.del_count += 1;
                    },
                }
            }
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

            var header_lines = std.ArrayList([]const u8){};

            try header_lines.append(arena.allocator(), try std.fmt.allocPrint(arena.allocator(), "diff --git a/{s} b/{s}", .{ line_iter_a.path, line_iter_b.path }));

            var mode_maybe: ?fs.Mode = null;

            if (line_iter_a.mode) |a_mode| {
                if (line_iter_b.mode) |b_mode| {
                    if (!a_mode.eqlExact(b_mode)) {
                        try header_lines.append(arena.allocator(), try std.fmt.allocPrint(arena.allocator(), "old mode {s}", .{a_mode.toStr()}));
                        try header_lines.append(arena.allocator(), try std.fmt.allocPrint(arena.allocator(), "new mode {s}", .{b_mode.toStr()}));
                    } else {
                        mode_maybe = a_mode;
                    }
                } else {
                    try header_lines.append(arena.allocator(), try std.fmt.allocPrint(arena.allocator(), "deleted file mode {s}", .{a_mode.toStr()}));
                }
            } else {
                if (line_iter_b.mode) |b_mode| {
                    try header_lines.append(arena.allocator(), try std.fmt.allocPrint(arena.allocator(), "new file mode {s}", .{b_mode.toStr()}));
                }
            }

            if (!std.mem.eql(u8, &line_iter_a.oid, &line_iter_b.oid)) {
                if (mode_maybe) |mode| {
                    try header_lines.append(arena.allocator(), try std.fmt.allocPrint(arena.allocator(), "index {s}..{s} {s}", .{
                        line_iter_a.oid_hex[0..7],
                        line_iter_b.oid_hex[0..7],
                        mode.toStr(),
                    }));
                } else {
                    try header_lines.append(arena.allocator(), try std.fmt.allocPrint(arena.allocator(), "index {s}..{s}", .{
                        line_iter_a.oid_hex[0..7],
                        line_iter_b.oid_hex[0..7],
                    }));
                }

                try header_lines.append(arena.allocator(), try std.fmt.allocPrint(arena.allocator(), "--- a/{s}", .{line_iter_a.path}));

                if (line_iter_b.mode != null) {
                    try header_lines.append(arena.allocator(), try std.fmt.allocPrint(arena.allocator(), "+++ b/{s}", .{line_iter_b.path}));
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
                    .edits = std.ArrayList(Edit){},
                },
            };
        }

        pub fn next(self: *HunkIterator(repo_kind, repo_opts), allocator: std.mem.Allocator) !?Hunk(repo_kind, repo_opts) {
            const max_margin: usize = 3;

            if (!self.eof) {
                while (true) {
                    if (try self.myers_diff.next()) |edit| {
                        try self.next_hunk.edits.append(allocator, edit);

                        if (edit == .eql) {
                            self.margin += 1;
                            if (self.found_edit) {
                                // if the end margin isn't the max,
                                // keep adding to the hunk
                                if (self.margin < max_margin) {
                                    continue;
                                }
                            }
                            // if the begin margin is over the max,
                            // remove the first line (which is
                            // guaranteed to be an eql edit)
                            else if (self.margin > max_margin) {
                                _ = self.next_hunk.edits.orderedRemove(0);
                                self.margin -= 1;
                                continue;
                            }
                        } else {
                            self.found_edit = true;
                            self.margin = 0;
                            continue;
                        }

                        // if the diff state contains an actual edit
                        // (that is, non-eql line)
                        if (self.found_edit) {
                            const hunk = self.next_hunk;
                            self.next_hunk = Hunk(repo_kind, repo_opts){
                                .edits = std.ArrayList(Edit){},
                            };
                            self.found_edit = false;
                            self.margin = 0;
                            return hunk;
                        } else {
                            continue;
                        }
                    } else {
                        self.eof = true; // ensure this method returns null in the future

                        if (self.found_edit) {
                            // return the last hunk
                            const hunk = self.next_hunk;
                            self.next_hunk = Hunk(repo_kind, repo_opts){
                                .edits = std.ArrayList(Edit){},
                            };
                            self.found_edit = false;
                            self.margin = 0;
                            return hunk;
                        } else {
                            return null;
                        }
                    }
                }
            } else {
                return null;
            }
        }

        pub fn deinit(self: *HunkIterator(repo_kind, repo_opts), allocator: std.mem.Allocator) void {
            self.myers_diff.deinit();
            self.arena.deinit();
            allocator.destroy(self.arena);
            self.next_hunk.deinit(allocator);
        }

        pub fn reset(self: *HunkIterator(repo_kind, repo_opts), allocator: std.mem.Allocator) !void {
            try self.myers_diff.reset();
            self.eof = false;
            try self.line_iter_a.reset();
            try self.line_iter_b.reset();
            self.found_edit = false;
            self.margin = 0;
            self.next_hunk.deinit(allocator);
            self.next_hunk = Hunk(repo_kind, repo_opts){
                .edits = std.ArrayList(Edit){},
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
                            var a = try LineIterator(repo_kind, repo_opts).initFromNothing(io, allocator, path);
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
                            var b = try LineIterator(repo_kind, repo_opts).initFromNothing(io, allocator, path);
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
                            var b = try LineIterator(repo_kind, repo_opts).initFromNothing(io, allocator, path);
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
                    var a = try LineIterator(repo_kind, repo_opts).initFromNothing(io, allocator, path);
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
            };
        }

        pub fn next(self: *FileIterator(repo_kind, repo_opts)) !?LineIteratorPair(repo_kind, repo_opts) {
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
                                else => try LineIterator(repo_kind, repo_opts).initFromNothing(self.io, self.allocator, path),
                            };
                            errdefer b.deinit();
                            self.next_index += 1;
                            return .{ .path = path, .a = a, .b = b };
                        }
                        // there is no entry, so just skip it and call this method recursively
                        else {
                            self.next_index += 1;
                            return try self.next();
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
                        var b = try LineIterator(repo_kind, repo_opts).initFromNothing(self.io, self.allocator, path);
                        errdefer b.deinit();
                        self.next_index += 1;
                        return .{ .path = path, .a = a, .b = b };
                    }
                },
                .index => |index| {
                    if (next_index < index.status.index_added.count()) {
                        const path = index.status.index_added.keys()[next_index];
                        var a = try LineIterator(repo_kind, repo_opts).initFromNothing(self.io, self.allocator, path);
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
                        var b = try LineIterator(repo_kind, repo_opts).initFromNothing(self.io, self.allocator, path);
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
                            try LineIterator(repo_kind, repo_opts).initFromNothing(self.io, self.allocator, path);
                        errdefer a.deinit();
                        var b = if (change.new) |new|
                            try LineIterator(repo_kind, repo_opts).initFromOid(state, self.io, self.allocator, path, &new.oid, new.mode)
                        else
                            try LineIterator(repo_kind, repo_opts).initFromNothing(self.io, self.allocator, path);
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
