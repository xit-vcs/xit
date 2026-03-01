const std = @import("std");
const builtin = @import("builtin");
const obj = @import("./object.zig");
const hash = @import("./hash.zig");
const fs = @import("./fs.zig");
const rp = @import("./repo.zig");
const tr = @import("./tree.zig");

pub fn Index(comptime repo_kind: rp.RepoKind, comptime repo_opts: rp.RepoOpts(repo_kind)) type {
    return struct {
        version: u32,
        // TODO: maybe store pointers to save space,
        // since usually only the first slot is used
        entries: std.StringArrayHashMap([4]?Entry),
        dir_to_paths: std.StringArrayHashMap(std.StringArrayHashMap(void)),
        dir_to_children: std.StringArrayHashMap(std.StringArrayHashMap(void)),
        root_children: std.StringArrayHashMap(void),
        io: std.Io,
        allocator: std.mem.Allocator,
        arena: *std.heap.ArenaAllocator,

        pub const Entry = struct {
            pub const Flags = packed struct(u16) {
                name_length: u12,
                stage: u2,
                extended: bool,
                assume_valid: bool,
            };

            pub const ExtendedFlags = packed struct(u16) {
                unused: u13,
                intent_to_add: bool,
                skip_worktree: bool,
                reserved: bool,
            };

            ctime_secs: u32,
            ctime_nsecs: u32,
            mtime_secs: u32,
            mtime_nsecs: u32,
            dev: u32,
            ino: u32,
            mode: fs.Mode,
            uid: u32,
            gid: u32,
            file_size: switch (repo_kind) {
                .git => u32,
                .xit => u64,
            },
            oid: [hash.byteLen(repo_opts.hash)]u8,
            flags: Flags,
            extended_flags: ?ExtendedFlags,
            path: []const u8,
        };

        pub fn init(
            state: rp.Repo(repo_kind, repo_opts).State(.read_only),
            io: std.Io,
            allocator: std.mem.Allocator,
        ) !Index(repo_kind, repo_opts) {
            const arena = try allocator.create(std.heap.ArenaAllocator);
            arena.* = std.heap.ArenaAllocator.init(allocator);
            var self = Index(repo_kind, repo_opts){
                .version = 2,
                .entries = std.StringArrayHashMap([4]?Entry).init(allocator),
                .dir_to_paths = std.StringArrayHashMap(std.StringArrayHashMap(void)).init(allocator),
                .dir_to_children = std.StringArrayHashMap(std.StringArrayHashMap(void)).init(allocator),
                .root_children = std.StringArrayHashMap(void).init(allocator),
                .io = io,
                .allocator = allocator,
                .arena = arena,
            };
            errdefer self.deinit();

            switch (repo_kind) {
                .git => {
                    // open index
                    const index_file = state.core.repo_dir.openFile(io, "index", .{ .mode = .read_only }) catch |err| switch (err) {
                        error.FileNotFound => return self,
                        else => |e| return e,
                    };
                    defer index_file.close(io);

                    var reader_buffer = [_]u8{0} ** repo_opts.buffer_size;
                    var reader = index_file.reader(io, &reader_buffer);

                    const signature = try reader.interface.takeArray(4);
                    if (!std.mem.eql(u8, "DIRC", signature)) {
                        return error.InvalidSignature;
                    }

                    // ignoring version 3 and 4 for now
                    self.version = try reader.interface.takeInt(u32, .big);
                    if (self.version != 2) {
                        return error.InvalidVersion;
                    }

                    var entry_count = try reader.interface.takeInt(u32, .big);

                    while (entry_count > 0) {
                        entry_count -= 1;
                        const start_pos = reader.logicalPos();
                        var entry = Entry{
                            .ctime_secs = try reader.interface.takeInt(u32, .big),
                            .ctime_nsecs = try reader.interface.takeInt(u32, .big),
                            .mtime_secs = try reader.interface.takeInt(u32, .big),
                            .mtime_nsecs = try reader.interface.takeInt(u32, .big),
                            .dev = try reader.interface.takeInt(u32, .big),
                            .ino = try reader.interface.takeInt(u32, .big),
                            .mode = @bitCast(try reader.interface.takeInt(u32, .big)),
                            .uid = try reader.interface.takeInt(u32, .big),
                            .gid = try reader.interface.takeInt(u32, .big),
                            .file_size = try reader.interface.takeInt(u32, .big),
                            .oid = (try reader.interface.takeArray(hash.byteLen(repo_opts.hash))).*,
                            .flags = @bitCast(try reader.interface.takeInt(u16, .big)),
                            .extended_flags = null, // TODO: read this if necessary
                            .path = blk: {
                                var writer = std.Io.Writer.Allocating.init(self.arena.allocator());
                                _ = try reader.interface.streamDelimiterLimit(&writer.writer, 0, .limited(repo_opts.max_read_size));
                                if (0 != try reader.interface.takeByte()) {
                                    return error.InvalidNullPadding;
                                }
                                break :blk writer.written();
                            },
                        };
                        if (entry.mode.content.unix_permission != 0o755) { // ensure mode is valid
                            entry.mode.content.unix_permission = 0o644;
                        }
                        if (entry.path.len != entry.flags.name_length) {
                            return error.InvalidPathSize;
                        }
                        const entry_size = reader.logicalPos() - start_pos;
                        const entry_zeroes = (8 - (entry_size % 8)) % 8;
                        for (0..entry_zeroes) |_| {
                            if (0 != try reader.interface.takeByte()) {
                                return error.InvalidNullPadding;
                            }
                        }
                        try self.addEntry(entry);
                    }

                    // TODO: check the checksum
                    // skipping for now because it will probably require changing
                    // how i read the data above. i need access to the raw bytes
                    // (before the big endian and type conversions) to do the hashing.
                    _ = try reader.interface.takeArray(hash.byteLen(.sha1));
                },
                .xit => {
                    if (try state.extra.moment.getCursor(hash.hashInt(repo_opts.hash, "index"))) |index_cursor| {
                        var iter = try index_cursor.iterator();
                        while (try iter.next()) |*next_cursor| {
                            const kv_pair = try next_cursor.readKeyValuePair();
                            const path = try kv_pair.key_cursor.readBytesAlloc(self.arena.allocator(), repo_opts.max_read_size);
                            const buffer = try kv_pair.value_cursor.readBytesAlloc(self.allocator, repo_opts.max_read_size);
                            defer self.allocator.free(buffer);

                            var reader = std.Io.Reader.fixed(buffer);
                            while (reader.seek < reader.end) {
                                var entry = Entry{
                                    .ctime_secs = try reader.takeInt(u32, .big),
                                    .ctime_nsecs = try reader.takeInt(u32, .big),
                                    .mtime_secs = try reader.takeInt(u32, .big),
                                    .mtime_nsecs = try reader.takeInt(u32, .big),
                                    .dev = try reader.takeInt(u32, .big),
                                    .ino = try reader.takeInt(u32, .big),
                                    .mode = @bitCast(try reader.takeInt(u32, .big)),
                                    .uid = try reader.takeInt(u32, .big),
                                    .gid = try reader.takeInt(u32, .big),
                                    .file_size = try reader.takeInt(u64, .big),
                                    .oid = (try reader.takeArray(hash.byteLen(repo_opts.hash))).*,
                                    .flags = @bitCast(try reader.takeInt(u16, .big)),
                                    .extended_flags = null, // TODO: read this if necessary
                                    .path = path,
                                };
                                if (entry.mode.content.unix_permission != 0o755) { // ensure mode is valid
                                    entry.mode.content.unix_permission = 0o644;
                                }
                                if (entry.path.len != entry.flags.name_length) {
                                    return error.InvalidPathSize;
                                }
                                try self.addEntry(entry);
                            }
                        }
                    }
                },
            }

            return self;
        }

        pub fn deinit(self: *Index(repo_kind, repo_opts)) void {
            self.arena.deinit();
            self.allocator.destroy(self.arena);
            self.entries.deinit();
            for (self.dir_to_paths.values()) |*paths| {
                paths.deinit();
            }
            self.dir_to_paths.deinit();
            for (self.dir_to_children.values()) |*paths| {
                paths.deinit();
            }
            self.dir_to_children.deinit();
            self.root_children.deinit();
        }

        /// if path is a file or symlink, adds it as an entry to the index struct.
        /// if path is a dir, adds its children recursively.
        pub fn addPath(
            self: *Index(repo_kind, repo_opts),
            state: rp.Repo(repo_kind, repo_opts).State(.read_write),
            io: std.Io,
            path: []const u8,
            // this param is only ever used on windows.
            // its purpose is to make the index entry have the same mode as the one in the tree,
            // rather than overwriting it with the mode from the windows work dir.
            // this is important to prevent windows users from accidently overwriting permissions
            // or changing symlinks into regular files.
            tree_entry_maybe: ?*const tr.TreeEntry(repo_opts.hash),
        ) !void {
            // remove entries that are parents of this path (directory replaces file)
            var parent_path_maybe = std.fs.path.dirname(path);
            while (parent_path_maybe) |parent_path| {
                if (self.entries.contains(parent_path)) {
                    try self.removePath(parent_path, null);
                }
                parent_path_maybe = std.fs.path.dirname(parent_path);
            }

            const meta = try fs.Metadata.init(io, state.core.work_dir, path);
            switch (meta.kind) {
                .file => {
                    // remove entries that are children of this path (file replaces directory)
                    try self.removeChildren(path, null);

                    // open file
                    const file = try state.core.work_dir.openFile(io, path, .{ .mode = .read_only });
                    defer file.close(io);

                    // make reader
                    var reader_buffer = [_]u8{0} ** repo_opts.buffer_size;
                    var reader = file.reader(self.io, &reader_buffer);

                    // write object
                    var oid = [_]u8{0} ** hash.byteLen(repo_opts.hash);
                    try obj.writeObject(repo_kind, repo_opts, state, self.io, &reader.interface, .{ .kind = .blob, .size = meta.size }, &oid);

                    // get the mode
                    // on windows, if a tree entry was supplied to this fn and its hash
                    // is the same, use its mode.
                    // otherwise, if there is an existing entry in the index and its hash
                    // is the same, use its mode.
                    // only if both are untrue should we use the mode from the disk.
                    var mode_maybe: ?fs.Mode = null;
                    if (.windows == builtin.os.tag) {
                        if (tree_entry_maybe) |tree_entry| {
                            if (std.mem.eql(u8, &oid, &tree_entry.oid)) {
                                mode_maybe = tree_entry.mode;
                            }
                        }

                        if (mode_maybe == null) {
                            if (self.entries.get(path)) |*entries_for_path| {
                                if (entries_for_path[0]) |*entry| {
                                    if (std.mem.eql(u8, &oid, &entry.oid)) {
                                        mode_maybe = entry.mode;
                                    }
                                }
                            }
                        }
                    }
                    const mode = mode_maybe orelse meta.mode;

                    // add entry
                    const entry = Entry{
                        .ctime_secs = meta.times.ctime_secs,
                        .ctime_nsecs = meta.times.ctime_nsecs,
                        .mtime_secs = meta.times.mtime_secs,
                        .mtime_nsecs = meta.times.mtime_nsecs,
                        .dev = meta.stat.dev,
                        .ino = meta.stat.ino,
                        .mode = mode,
                        .uid = meta.stat.uid,
                        .gid = meta.stat.gid,
                        .file_size = switch (repo_kind) {
                            .git => @truncate(meta.size), // git docs say that the file size is truncated
                            .xit => meta.size,
                        },
                        .oid = oid,
                        .flags = .{
                            .name_length = @intCast(path.len),
                            .stage = 0,
                            .extended = false,
                            .assume_valid = false,
                        },
                        .extended_flags = null,
                        .path = path,
                    };
                    try self.addEntry(entry);
                },
                .directory => {
                    var dir = try state.core.work_dir.openDir(io, path, .{ .iterate = true });
                    defer dir.close(io);
                    var iter = dir.iterate();
                    while (try iter.next(io)) |entry| {
                        // ignore repo dir
                        const repo_dir_name = switch (repo_kind) {
                            .git => ".git",
                            .xit => ".xit",
                        };
                        if (std.mem.eql(u8, repo_dir_name, entry.name)) {
                            continue;
                        }

                        const subpath = try fs.joinPath(self.arena.allocator(), &.{ path, entry.name });
                        try self.addPath(state, io, subpath, null);
                    }
                },
                .sym_link => {
                    // remove entries that are children of this path (file replaces directory)
                    try self.removeChildren(path, null);

                    // get the target path
                    var target_path_buffer = [_]u8{0} ** std.fs.max_path_bytes;
                    const target_path_size = try state.core.work_dir.readLink(io, path, &target_path_buffer);
                    const target_path = target_path_buffer[0..target_path_size];

                    // write object
                    var oid = [_]u8{0} ** hash.byteLen(repo_opts.hash);
                    var reader = std.Io.Reader.fixed(target_path);
                    try obj.writeObject(repo_kind, repo_opts, state, self.io, &reader, .{ .kind = .blob, .size = meta.size }, &oid);

                    const entry = Entry{
                        .ctime_secs = meta.times.ctime_secs,
                        .ctime_nsecs = meta.times.ctime_nsecs,
                        .mtime_secs = meta.times.mtime_secs,
                        .mtime_nsecs = meta.times.mtime_nsecs,
                        .dev = meta.stat.dev,
                        .ino = meta.stat.ino,
                        .mode = meta.mode,
                        .uid = meta.stat.uid,
                        .gid = meta.stat.gid,
                        .file_size = switch (repo_kind) {
                            .git => @truncate(meta.size), // git docs say that the file size is truncated
                            .xit => meta.size,
                        },
                        .oid = oid,
                        .flags = .{
                            .name_length = @intCast(path.len),
                            .stage = 0,
                            .extended = false,
                            .assume_valid = false,
                        },
                        .extended_flags = null,
                        .path = path,
                    };
                    try self.addEntry(entry);
                },
                else => return,
            }
        }

        fn addEntry(self: *Index(repo_kind, repo_opts), entry: Entry) !void {
            if (self.entries.getEntry(entry.path)) |map_entry| {
                // there is an existing slot for the given path,
                // so evict entries to ensure zero and non-zero stages don't coexist
                if (0 == entry.flags.stage) {
                    map_entry.value_ptr[1] = null;
                    map_entry.value_ptr[2] = null;
                    map_entry.value_ptr[3] = null;
                } else {
                    map_entry.value_ptr[0] = null;
                }
                // add the new entry
                map_entry.value_ptr[entry.flags.stage] = entry;
            } else {
                // there is no existing slot for the given path,
                // so create a new one with the entry included
                var entries_for_path = [4]?Entry{ null, null, null, null };
                entries_for_path[entry.flags.stage] = entry;
                try self.entries.put(entry.path, entries_for_path);
            }

            var child = std.fs.path.basename(entry.path);
            var parent_path_maybe = std.fs.path.dirname(entry.path);

            while (parent_path_maybe) |parent_path| {
                // populate dir_to_children
                const children_maybe = self.dir_to_children.getEntry(parent_path);
                if (children_maybe) |children| {
                    try children.value_ptr.*.put(child, {});
                } else {
                    var children = std.StringArrayHashMap(void).init(self.allocator);
                    try children.put(child, {});
                    try self.dir_to_children.put(parent_path, children);
                }

                // populate dir_to_paths
                const child_paths_maybe = self.dir_to_paths.getEntry(parent_path);
                if (child_paths_maybe) |child_paths| {
                    try child_paths.value_ptr.*.put(entry.path, {});
                } else {
                    var child_paths = std.StringArrayHashMap(void).init(self.allocator);
                    try child_paths.put(entry.path, {});
                    try self.dir_to_paths.put(parent_path, child_paths);
                }

                child = std.fs.path.basename(parent_path);
                parent_path_maybe = std.fs.path.dirname(parent_path);
            }

            try self.root_children.put(child, {});
        }

        pub fn addConflictEntries(self: *Index(repo_kind, repo_opts), path: []const u8, tree_entries: [3]?tr.TreeEntry(repo_opts.hash)) !void {
            const path_parts = try fs.splitPath(self.allocator, path);
            defer self.allocator.free(path_parts);
            for (tree_entries, 1..) |tree_entry_maybe, stage| {
                if (tree_entry_maybe) |*tree_entry| {
                    try self.addTreeEntryFile(tree_entry, path_parts, 0, @intCast(stage));
                }
            }
        }

        pub fn addTreeEntry(
            self: *Index(repo_kind, repo_opts),
            state: rp.Repo(repo_kind, repo_opts).State(.read_only),
            io: std.Io,
            allocator: std.mem.Allocator,
            tree_entry: *const tr.TreeEntry(repo_opts.hash),
            path_parts: []const []const u8,
        ) !void {
            const oid_hex = std.fmt.bytesToHex(tree_entry.oid, .lower);
            var object = try obj.Object(repo_kind, repo_opts, .full).init(state, io, allocator, &oid_hex);
            defer object.deinit();

            switch (object.content) {
                .blob => try self.addTreeEntryFile(tree_entry, path_parts, object.len, 0),
                .tree => |tree| {
                    for (tree.entries.keys(), tree.entries.values()) |path_part, *child_tree_entry| {
                        var child_path = std.ArrayList([]const u8){};
                        defer child_path.deinit(allocator);
                        try child_path.appendSlice(allocator, path_parts);
                        try child_path.append(allocator, path_part);
                        try self.addTreeEntry(state, io, allocator, child_tree_entry, child_path.items);
                    }
                },
                else => return error.InvalidObjectKind,
            }
        }

        pub fn addTreeEntryFile(
            self: *Index(repo_kind, repo_opts),
            tree_entry: *const tr.TreeEntry(repo_opts.hash),
            path_parts: []const []const u8,
            file_size: u64,
            stage: u2,
        ) !void {
            if (tree_entry.mode.content.object_type != .regular_file) {
                return error.InvalidObjectKind;
            }
            const path = if (path_parts.len == 0) return error.InvalidPath else try fs.joinPath(self.arena.allocator(), path_parts);
            const entry = Entry{
                .ctime_secs = 0,
                .ctime_nsecs = 0,
                .mtime_secs = 0,
                .mtime_nsecs = 0,
                .dev = 0,
                .ino = 0,
                .mode = tree_entry.mode,
                .uid = 0,
                .gid = 0,
                .file_size = switch (repo_kind) {
                    .git => @truncate(file_size), // git docs say that the file size is truncated
                    .xit => file_size,
                },
                .oid = tree_entry.oid,
                .flags = .{
                    .name_length = @intCast(path.len),
                    .stage = stage,
                    .extended = false,
                    .assume_valid = false,
                },
                .extended_flags = null,
                .path = path,
            };
            try self.addEntry(entry);
        }

        pub fn removePath(
            self: *Index(repo_kind, repo_opts),
            path: []const u8,
            removed_paths_maybe: ?*std.StringArrayHashMap(void),
        ) !void {
            const removed = self.entries.orderedRemove(path);

            if (removed) {
                if (removed_paths_maybe) |removed_paths| {
                    try removed_paths.put(path, {});
                }
            }

            // update dir_to_paths and dir_to_children
            var parent_path_maybe = std.fs.path.dirname(path);
            var basename = std.fs.path.basename(path);
            while (parent_path_maybe) |parent_path| {
                if (self.dir_to_paths.getEntry(parent_path)) |paths| {
                    _ = paths.value_ptr.*.orderedRemove(path);

                    // if there are no other children, remove the entry from
                    // dir_to_children as well
                    if (paths.value_ptr.count() == 0) {
                        if (self.dir_to_children.getEntry(parent_path)) |children| {
                            _ = children.value_ptr.*.orderedRemove(basename);
                        }
                    }
                }

                parent_path_maybe = std.fs.path.dirname(parent_path);
                basename = std.fs.path.basename(parent_path);
            }
        }

        pub fn removeChildren(
            self: *Index(repo_kind, repo_opts),
            path: []const u8,
            removed_paths_maybe: ?*std.StringArrayHashMap(void),
        ) !void {
            const child_paths_maybe = self.dir_to_paths.getEntry(path);
            if (child_paths_maybe) |child_paths| {
                const child_paths_array = child_paths.value_ptr.*.keys();
                // make a copy of the paths because removePath will modify it
                var child_paths_array_copy = std.ArrayList([]const u8){};
                defer child_paths_array_copy.deinit(self.allocator);
                for (child_paths_array) |child_path| {
                    try child_paths_array_copy.append(self.allocator, child_path);
                }
                for (child_paths_array_copy.items) |child_path| {
                    try self.removePath(child_path, removed_paths_maybe);
                }
            }
        }

        pub fn addOrRemovePath(
            self: *Index(repo_kind, repo_opts),
            state: rp.Repo(repo_kind, repo_opts).State(.read_write),
            io: std.Io,
            path_parts: []const []const u8,
            action: enum { add, rm },
            removed_paths_maybe: ?*std.StringArrayHashMap(void),
        ) !void {
            const path = try fs.joinPath(self.arena.allocator(), path_parts);

            // if the path doesn't exist, remove it, regardless of what the `action` is
            if (state.core.work_dir.openFile(io, path, .{ .mode = .read_only })) |file| {
                file.close(io);
            } else |err| {
                switch (err) {
                    error.FileNotFound => {
                        if (!self.entries.contains(path) and !self.dir_to_paths.contains(path)) {
                            return switch (action) {
                                .add => error.AddIndexPathNotFound,
                                .rm => error.RemoveIndexPathNotFound,
                            };
                        }
                        try self.removePath(path, removed_paths_maybe);
                        try self.removeChildren(path, removed_paths_maybe);
                        return;
                    },
                    else => |e| return e,
                }
            }

            // add or remove based on the `action`
            switch (action) {
                .add => try self.addPath(state, io, path, null),
                .rm => {
                    if (!self.entries.contains(path) and !self.dir_to_paths.contains(path)) {
                        return error.RemoveIndexPathNotFound;
                    }
                    try self.removePath(path, removed_paths_maybe);
                    try self.removeChildren(path, removed_paths_maybe);
                },
            }
        }

        pub fn write(
            self: *Index(repo_kind, repo_opts),
            allocator: std.mem.Allocator,
            state: rp.Repo(repo_kind, repo_opts).State(.read_write),
            io: std.Io,
        ) !void {
            switch (repo_kind) {
                .git => {
                    // sort the entries
                    const SortCtx = struct {
                        keys: [][]const u8,
                        pub fn lessThan(ctx: @This(), a_index: usize, b_index: usize) bool {
                            return std.mem.lessThan(u8, ctx.keys[a_index], ctx.keys[b_index]);
                        }
                    };
                    self.entries.sort(SortCtx{ .keys = self.entries.keys() });

                    // start the checksum
                    var hasher = hash.Hasher(.sha1).init();

                    // calculate entry count
                    var entry_count: u32 = 0;
                    for (self.entries.values()) |*entries_for_path| {
                        for (entries_for_path) |entry_maybe| {
                            if (entry_maybe != null) {
                                entry_count += 1;
                            }
                        }
                    }

                    const lock_file = state.extra.lock_file_maybe orelse return error.NoLockFile;
                    try io.vtable.fileSeekTo(io.userdata, lock_file, 0);
                    try lock_file.setLength(io, 0); // truncate file in case this method is called multiple times

                    // write the header
                    const version: u32 = 2;
                    const header = try std.fmt.allocPrint(allocator, "DIRC{s}{s}", .{
                        std.mem.asBytes(&std.mem.nativeToBig(u32, version)),
                        std.mem.asBytes(&std.mem.nativeToBig(u32, entry_count)),
                    });
                    defer allocator.free(header);
                    try lock_file.writeStreamingAll(io, header);
                    hasher.update(header);

                    // write the entries
                    for (self.entries.values()) |*entries_for_path| {
                        for (entries_for_path) |entry_maybe| {
                            if (entry_maybe) |entry| {
                                var entry_buffer_writer = std.Io.Writer.Allocating.init(allocator);
                                defer entry_buffer_writer.deinit();
                                try entry_buffer_writer.writer.writeInt(u32, entry.ctime_secs, .big);
                                try entry_buffer_writer.writer.writeInt(u32, entry.ctime_nsecs, .big);
                                try entry_buffer_writer.writer.writeInt(u32, entry.mtime_secs, .big);
                                try entry_buffer_writer.writer.writeInt(u32, entry.mtime_nsecs, .big);
                                try entry_buffer_writer.writer.writeInt(u32, entry.dev, .big);
                                try entry_buffer_writer.writer.writeInt(u32, entry.ino, .big);
                                try entry_buffer_writer.writer.writeInt(u32, @as(u32, @bitCast(entry.mode)), .big);
                                try entry_buffer_writer.writer.writeInt(u32, entry.uid, .big);
                                try entry_buffer_writer.writer.writeInt(u32, entry.gid, .big);
                                try entry_buffer_writer.writer.writeInt(u32, entry.file_size, .big);
                                try entry_buffer_writer.writer.writeAll(&entry.oid);
                                try entry_buffer_writer.writer.writeInt(u16, @as(u16, @bitCast(entry.flags)), .big);
                                try entry_buffer_writer.writer.writeAll(entry.path);
                                try entry_buffer_writer.writer.writeByte(0);
                                const entry_size = entry_buffer_writer.written().len;
                                const entry_zeroes = (8 - (entry_size % 8)) % 8;
                                for (0..entry_zeroes) |_| {
                                    try entry_buffer_writer.writer.writeByte(0);
                                }
                                try lock_file.writeStreamingAll(io, entry_buffer_writer.written());
                                hasher.update(entry_buffer_writer.written());
                            }
                        }
                    }

                    // write the checksum
                    var overall_sha1_buffer = [_]u8{0} ** hash.byteLen(.sha1);
                    hasher.final(&overall_sha1_buffer);
                    try lock_file.writeStreamingAll(io, &overall_sha1_buffer);
                },
                .xit => {
                    const index_cursor = try state.extra.moment.putCursor(hash.hashInt(repo_opts.hash, "index"));
                    var index = try rp.Repo(repo_kind, repo_opts).DB.HashMap(.read_write).init(index_cursor);

                    // remove items no longer in the index
                    var iter = try index.cursor.iterator();
                    while (try iter.next()) |*next_cursor| {
                        const kv_pair = try next_cursor.readKeyValuePair();
                        const path = try kv_pair.key_cursor.readBytesAlloc(allocator, repo_opts.max_read_size);
                        defer allocator.free(path);

                        if (!self.entries.contains(path)) {
                            _ = try index.remove(hash.hashInt(repo_opts.hash, path));
                        }
                    }

                    for (self.entries.keys(), self.entries.values()) |path, *entries_for_path| {
                        var entry_buffer_writer = std.Io.Writer.Allocating.init(allocator);
                        defer entry_buffer_writer.deinit();

                        for (entries_for_path) |entry_maybe| {
                            if (entry_maybe) |entry| {
                                try entry_buffer_writer.writer.writeInt(u32, entry.ctime_secs, .big);
                                try entry_buffer_writer.writer.writeInt(u32, entry.ctime_nsecs, .big);
                                try entry_buffer_writer.writer.writeInt(u32, entry.mtime_secs, .big);
                                try entry_buffer_writer.writer.writeInt(u32, entry.mtime_nsecs, .big);
                                try entry_buffer_writer.writer.writeInt(u32, entry.dev, .big);
                                try entry_buffer_writer.writer.writeInt(u32, entry.ino, .big);
                                try entry_buffer_writer.writer.writeInt(u32, @as(u32, @bitCast(entry.mode)), .big);
                                try entry_buffer_writer.writer.writeInt(u32, entry.uid, .big);
                                try entry_buffer_writer.writer.writeInt(u32, entry.gid, .big);
                                try entry_buffer_writer.writer.writeInt(u64, entry.file_size, .big);
                                try entry_buffer_writer.writer.writeAll(&entry.oid);
                                try entry_buffer_writer.writer.writeInt(u16, @as(u16, @bitCast(entry.flags)), .big);
                            }
                        }

                        const path_hash = hash.hashInt(repo_opts.hash, path);
                        if (try index.getKeyCursor(path_hash)) |existing_entry_cursor| {
                            const existing_entry = try existing_entry_cursor.readBytesAlloc(allocator, repo_opts.max_read_size);
                            defer allocator.free(existing_entry);
                            if (std.mem.eql(u8, entry_buffer_writer.written(), existing_entry)) {
                                continue;
                            }
                        }

                        const path_set_cursor = try state.extra.moment.putCursor(hash.hashInt(repo_opts.hash, "path-set"));
                        const path_set = try rp.Repo(repo_kind, repo_opts).DB.HashSet(.read_write).init(path_set_cursor);
                        var path_cursor = try path_set.putCursor(path_hash);
                        try path_cursor.writeIfEmpty(.{ .bytes = path });
                        try index.putKey(path_hash, .{ .slot = path_cursor.slot() });

                        const entry_buffer_set_cursor = try state.extra.moment.putCursor(hash.hashInt(repo_opts.hash, "entry-buffer-set"));
                        const entry_buffer_set = try rp.Repo(repo_kind, repo_opts).DB.HashSet(.read_write).init(entry_buffer_set_cursor);
                        var entry_buffer_cursor = try entry_buffer_set.putCursor(hash.hashInt(repo_opts.hash, entry_buffer_writer.written()));
                        try entry_buffer_cursor.writeIfEmpty(.{ .bytes = entry_buffer_writer.written() });
                        try index.put(path_hash, .{ .slot = entry_buffer_cursor.slot() });
                    }
                },
            }
        }
    };
}
