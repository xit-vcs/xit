const std = @import("std");
const hash = @import("./hash.zig");
const fs = @import("./fs.zig");
const rp = @import("./repo.zig");

pub const MAX_REF_CONTENT_SIZE = 512;
const REF_START_STR = "ref: ";

/// validates ref name with mostly the same rules as in:
/// git check-ref-format --help
pub fn validateName(name: []const u8) bool {
    if (name.len == 0 or
        name.len > 255 or // apparently git's max ref name size
        name[0] == '-' or
        name[name.len - 1] == '.' or
        std.mem.indexOf(u8, name, "..") != null or
        std.mem.indexOf(u8, name, "@{") != null)
    {
        return false;
    }

    // can't contain ASCII control chars or certain special chars
    for (name) |char| {
        switch (char) {
            0...0o37, 0o177, ' ', '~', '^', ':', '?', '*', '[', '\\' => return false,
            else => {},
        }
    }

    // restrictions on each path part
    var split_iter = std.mem.splitScalar(u8, name, '/');
    while (split_iter.next()) |path_part| {
        if (path_part.len == 0 or
            path_part[0] == '.' or
            std.mem.endsWith(u8, name, ".lock"))
        {
            return false;
        }
    }

    return true;
}

pub const RefKind = union(enum) {
    none,
    head,
    tag,
    remote: []const u8,
    other: []const u8,
};

pub const Ref = struct {
    kind: RefKind,
    name: []const u8,

    pub fn initFromPath(ref_path: []const u8, default_kind_maybe: ?RefKind) ?Ref {
        var split_iter = std.mem.splitScalar(u8, ref_path, '/');

        const first_part = split_iter.next() orelse return null;
        if (!std.mem.eql(u8, "refs", first_part)) {
            const unqualified_refs = std.StaticStringMap(void).initComptime(.{
                .{"HEAD"},
                .{"MERGE_HEAD"},
                .{"CHERRY_PICK_HEAD"},
            });

            // if this is an unqualified ref like HEAD, set the kind to none
            if (null == split_iter.peek() and unqualified_refs.has(first_part)) {
                return .{ .kind = .none, .name = ref_path };
            }
            // otherwise, give it the default kind
            else {
                return .{ .kind = default_kind_maybe orelse return null, .name = ref_path };
            }
        }

        const ref_kind = split_iter.next() orelse return null;
        const ref_name_offset = first_part.len + 1 + ref_kind.len + 1;
        const ref_name = if (ref_name_offset >= ref_path.len) return null else ref_path[ref_name_offset..];

        if (std.mem.eql(u8, "heads", ref_kind)) {
            return .{ .kind = .head, .name = ref_name };
        } else if (std.mem.eql(u8, "tags", ref_kind)) {
            return .{ .kind = .tag, .name = ref_name };
        } else if (std.mem.eql(u8, "remotes", ref_kind)) {
            const remote_name = split_iter.next() orelse return null;
            const remote_ref_name_offset = remote_name.len + 1;
            const remote_ref_name = if (remote_ref_name_offset >= ref_name.len) return null else ref_name[remote_ref_name_offset..];
            return .{ .kind = .{ .remote = remote_name }, .name = remote_ref_name };
        } else {
            return .{ .kind = .{ .other = ref_kind }, .name = ref_name };
        }
    }

    pub fn toPath(self: Ref, buffer: []u8) ![]const u8 {
        return switch (self.kind) {
            .none => try std.fmt.bufPrint(buffer, "{s}", .{self.name}),
            .head => try std.fmt.bufPrint(buffer, "refs/heads/{s}", .{self.name}),
            .tag => try std.fmt.bufPrint(buffer, "refs/tags/{s}", .{self.name}),
            .remote => |remote| try std.fmt.bufPrint(buffer, "refs/remotes/{s}/{s}", .{ remote, self.name }),
            .other => |other| try std.fmt.bufPrint(buffer, "refs/{s}/{s}", .{ other, self.name }),
        };
    }
};

test "parse ref paths" {
    try std.testing.expectEqualDeep(Ref{ .kind = .none, .name = "HEAD" }, Ref.initFromPath("HEAD", null));
    try std.testing.expectEqualDeep(Ref{ .kind = .head, .name = "master" }, Ref.initFromPath("refs/heads/master", null));
    try std.testing.expectEqualDeep(Ref{ .kind = .head, .name = "master" }, Ref.initFromPath("master", .head));
    try std.testing.expectEqualDeep(Ref{ .kind = .head, .name = "a/b/c" }, Ref.initFromPath("refs/heads/a/b/c", null));
    try std.testing.expectEqualDeep(Ref{ .kind = .tag, .name = "1.0.0" }, Ref.initFromPath("refs/tags/1.0.0", null));
    try std.testing.expectEqualDeep(Ref{ .kind = .{ .remote = "origin" }, .name = "master" }, Ref.initFromPath("refs/remotes/origin/master", null));
    try std.testing.expectEqualDeep(Ref{ .kind = .{ .other = "for" }, .name = "experimental" }, Ref.initFromPath("refs/for/experimental", null));
}

pub fn isOid(comptime hash_kind: hash.HashKind, content: []const u8) bool {
    if (content.len != hash.hexLen(hash_kind)) {
        return false;
    }
    for (content) |ch| {
        if (!std.ascii.isHex(ch)) {
            return false;
        }
    }
    return true;
}

pub fn RefOrOid(comptime hash_kind: hash.HashKind) type {
    return union(enum) {
        ref: Ref,
        oid: *const [hash.hexLen(hash_kind)]u8,

        pub fn initFromDb(content: []const u8) ?RefOrOid(hash_kind) {
            if (std.mem.startsWith(u8, content, REF_START_STR)) {
                if (Ref.initFromPath(content[REF_START_STR.len..], null)) |ref| {
                    return .{ .ref = ref };
                } else {
                    return null;
                }
            } else if (isOid(hash_kind, content)) {
                return .{ .oid = content[0..comptime hash.hexLen(hash_kind)] };
            } else {
                return null;
            }
        }

        pub fn initFromUser(content: []const u8) ?RefOrOid(hash_kind) {
            if (isOid(hash_kind, content)) {
                return .{ .oid = content[0..comptime hash.hexLen(hash_kind)] };
            } else if (Ref.initFromPath(content, .head)) |ref| {
                return .{ .ref = ref };
            } else {
                return null;
            }
        }

        pub fn name(self: *const RefOrOid(hash_kind)) []const u8 {
            return switch (self.*) {
                .ref => |ref| ref.name,
                .oid => |oid| oid,
            };
        }
    };
}

pub const RefList = struct {
    refs: std.StringArrayHashMap(Ref),
    arena: *std.heap.ArenaAllocator,
    allocator: std.mem.Allocator,

    pub fn init(
        comptime repo_kind: rp.RepoKind,
        comptime repo_opts: rp.RepoOpts(repo_kind),
        state: rp.Repo(repo_kind, repo_opts).State(.read_only),
        allocator: std.mem.Allocator,
        ref_kind: RefKind,
    ) !RefList {
        const arena = try allocator.create(std.heap.ArenaAllocator);
        arena.* = std.heap.ArenaAllocator.init(allocator);
        var ref_list = RefList{
            .refs = std.StringArrayHashMap(Ref).init(allocator),
            .arena = arena,
            .allocator = allocator,
        };
        errdefer ref_list.deinit();

        const dir_name = switch (ref_kind) {
            .none => return error.NotImplemented,
            .head => "heads",
            .tag => "tags",
            .remote => return error.NotImplemented,
            .other => |other_name| other_name,
        };

        switch (repo_kind) {
            .git => {
                var refs_dir = try state.core.repo_dir.openDir("refs", .{});
                defer refs_dir.close();
                var ref_kind_dir = refs_dir.openDir(dir_name, .{ .iterate = true }) catch |err| switch (err) {
                    error.FileNotFound => return ref_list,
                    else => |e| return e,
                };
                defer ref_kind_dir.close();

                var path = std.ArrayList([]const u8){};
                defer path.deinit(allocator);
                try ref_list.addRefs(repo_opts, state, ref_kind, ref_kind_dir, allocator, &path);
            },
            .xit => {
                if (try state.extra.moment.cursor.readPath(void, &.{
                    .{ .hash_map_get = .{ .value = hash.hashInt(repo_opts.hash, "refs") } },
                    .{ .hash_map_get = .{ .value = hash.hashInt(repo_opts.hash, dir_name) } },
                })) |heads_cursor| {
                    var iter = try heads_cursor.iterator();
                    while (try iter.next()) |*next_cursor| {
                        const kv_pair = try next_cursor.readKeyValuePair();
                        const name = try kv_pair.key_cursor.readBytesAlloc(ref_list.arena.allocator(), MAX_REF_CONTENT_SIZE);
                        try ref_list.refs.put(name, .{ .kind = ref_kind, .name = name });
                    }
                }
            },
        }

        return ref_list;
    }

    pub fn deinit(self: *RefList) void {
        self.refs.deinit();
        self.arena.deinit();
        self.allocator.destroy(self.arena);
    }

    fn addRefs(
        self: *RefList,
        comptime repo_opts: rp.RepoOpts(.git),
        state: rp.Repo(.git, repo_opts).State(.read_only),
        ref_kind: RefKind,
        dir: std.fs.Dir,
        allocator: std.mem.Allocator,
        path: *std.ArrayList([]const u8),
    ) !void {
        var iter = dir.iterate();
        while (try iter.next()) |entry| {
            var next_path = try path.clone(allocator);
            defer next_path.deinit(allocator);
            try next_path.append(allocator, entry.name);
            switch (entry.kind) {
                .file => {
                    const name = try fs.joinPath(self.arena.allocator(), next_path.items);
                    try self.refs.put(name, .{ .kind = ref_kind, .name = name });
                },
                .directory => {
                    var next_dir = try dir.openDir(entry.name, .{ .iterate = true });
                    defer next_dir.close();
                    try self.addRefs(repo_opts, state, ref_kind, next_dir, allocator, &next_path);
                },
                else => {},
            }
        }
    }
};

pub fn readRecur(
    comptime repo_kind: rp.RepoKind,
    comptime repo_opts: rp.RepoOpts(repo_kind),
    state: rp.Repo(repo_kind, repo_opts).State(.read_only),
    input: RefOrOid(repo_opts.hash),
) !?[hash.hexLen(repo_opts.hash)]u8 {
    switch (input) {
        .ref => |ref| {
            var ref_path_buffer = [_]u8{0} ** MAX_REF_CONTENT_SIZE;
            const ref_path = try ref.toPath(&ref_path_buffer);

            var read_buffer = [_]u8{0} ** MAX_REF_CONTENT_SIZE;
            const ref_or_oid_maybe = read(repo_kind, repo_opts, state, ref_path, &read_buffer) catch |err| switch (err) {
                error.RefNotFound => return null,
                else => |e| return e,
            };

            if (ref_or_oid_maybe) |next_input| {
                return try readRecur(repo_kind, repo_opts, state, next_input);
            } else {
                return null;
            }
        },
        .oid => |oid| return oid.*,
    }
}

pub fn read(
    comptime repo_kind: rp.RepoKind,
    comptime repo_opts: rp.RepoOpts(repo_kind),
    state: rp.Repo(repo_kind, repo_opts).State(.read_only),
    ref_path: []const u8,
    buffer: []u8,
) !?RefOrOid(repo_opts.hash) {
    switch (repo_kind) {
        .git => {
            // look for loose ref
            if (state.core.repo_dir.openFile(ref_path, .{ .mode = .read_only })) |ref_file| {
                defer ref_file.close();
                var reader = ref_file.reader(&.{});
                var writer = std.Io.Writer.fixed(buffer);
                const size = try reader.interface.streamRemaining(&writer);
                const ref_content = std.mem.sliceTo(buffer[0..size], '\n');
                return RefOrOid(repo_opts.hash).initFromDb(ref_content);
            } else |err| switch (err) {
                error.FileNotFound => {},
                else => |e| return e,
            }

            // look for packed ref
            if (state.core.repo_dir.openFile("packed-refs", .{ .mode = .read_only })) |packed_refs_file| {
                defer packed_refs_file.close();

                var reader_buffer = [_]u8{0} ** repo_opts.buffer_size;
                var reader = packed_refs_file.reader(&reader_buffer);

                // for each line...
                while (reader.interface.peekByte()) |_| {
                    var line_buffer = [_]u8{0} ** repo_opts.max_read_size;
                    var line_writer = std.Io.Writer.fixed(&line_buffer);
                    const size = try reader.interface.streamDelimiterEnding(&line_writer, '\n');
                    const line = line_buffer[0..size];

                    // skip delimiter
                    if (reader.interface.bufferedLen() > 0) {
                        reader.interface.toss(1);
                    }

                    const trimmed_line = std.mem.trim(u8, line, " ");
                    if (std.mem.startsWith(u8, trimmed_line, "#")) {
                        continue;
                    }

                    var split_iter = std.mem.splitScalar(u8, trimmed_line, ' ');
                    const oid_hex = split_iter.next() orelse continue;
                    const path = split_iter.next() orelse continue;

                    if (isOid(repo_opts.hash, oid_hex) and std.mem.eql(u8, ref_path, path)) {
                        @memcpy(buffer[0..comptime hash.hexLen(repo_opts.hash)], oid_hex);
                        return .{ .oid = buffer[0..comptime hash.hexLen(repo_opts.hash)] };
                    }
                } else |err| switch (err) {
                    error.EndOfStream => {},
                    else => |e| return e,
                }
            } else |err| switch (err) {
                error.FileNotFound => {},
                else => |e| return e,
            }

            return error.RefNotFound;
        },
        .xit => {
            var map = state.extra.moment.*;
            const ref = Ref.initFromPath(ref_path, null) orelse return error.InvalidRef;
            const refs_cursor = (try map.getCursor(hash.hashInt(repo_opts.hash, "refs"))) orelse return error.RefNotFound;
            const refs = try rp.Repo(repo_kind, repo_opts).DB.HashMap(.read_only).init(refs_cursor);

            switch (ref.kind) {
                .none => {},
                .head => {
                    const heads_cursor = (try refs.getCursor(hash.hashInt(repo_opts.hash, "heads"))) orelse return error.RefNotFound;
                    map = try rp.Repo(repo_kind, repo_opts).DB.HashMap(.read_only).init(heads_cursor);
                },
                .tag => {
                    const tags_cursor = (try refs.getCursor(hash.hashInt(repo_opts.hash, "tags"))) orelse return error.RefNotFound;
                    map = try rp.Repo(repo_kind, repo_opts).DB.HashMap(.read_only).init(tags_cursor);
                },
                .remote => |remote| {
                    const remotes_cursor = (try refs.getCursor(hash.hashInt(repo_opts.hash, "remotes"))) orelse return error.RefNotFound;
                    const remotes = try rp.Repo(repo_kind, repo_opts).DB.HashMap(.read_only).init(remotes_cursor);
                    const remote_cursor = (try remotes.getCursor(hash.hashInt(repo_opts.hash, remote))) orelse return error.RefNotFound;
                    map = try rp.Repo(repo_kind, repo_opts).DB.HashMap(.read_only).init(remote_cursor);
                },
                .other => |other_name| {
                    const other_cursor = (try refs.getCursor(hash.hashInt(repo_opts.hash, other_name))) orelse return error.RefNotFound;
                    map = try rp.Repo(repo_kind, repo_opts).DB.HashMap(.read_only).init(other_cursor);
                },
            }

            // if the ref's key hasn't been set, it doesn't exist
            _ = (try map.getKeyCursor(hash.hashInt(repo_opts.hash, ref.name))) orelse return error.RefNotFound;

            // if the ref's content hasn't been set, it's an empty ref so just return null
            const ref_cursor = (try map.getCursor(hash.hashInt(repo_opts.hash, ref.name))) orelse return null;
            const ref_content = try ref_cursor.readBytes(buffer);
            return RefOrOid(repo_opts.hash).initFromDb(ref_content);
        },
    }
}

pub fn readHeadRecurMaybe(
    comptime repo_kind: rp.RepoKind,
    comptime repo_opts: rp.RepoOpts(repo_kind),
    state: rp.Repo(repo_kind, repo_opts).State(.read_only),
) !?[hash.hexLen(repo_opts.hash)]u8 {
    var buffer = [_]u8{0} ** MAX_REF_CONTENT_SIZE;
    if (try read(repo_kind, repo_opts, state, "HEAD", &buffer)) |ref_or_oid| {
        return try readRecur(repo_kind, repo_opts, state, ref_or_oid);
    } else {
        return null;
    }
}

pub fn readHeadRecur(
    comptime repo_kind: rp.RepoKind,
    comptime repo_opts: rp.RepoOpts(repo_kind),
    state: rp.Repo(repo_kind, repo_opts).State(.read_only),
) ![hash.hexLen(repo_opts.hash)]u8 {
    if (try readHeadRecurMaybe(repo_kind, repo_opts, state)) |buffer| {
        return buffer;
    } else {
        return error.RefInvalidHash;
    }
}

pub fn readHead(
    comptime repo_kind: rp.RepoKind,
    comptime repo_opts: rp.RepoOpts(repo_kind),
    state: rp.Repo(repo_kind, repo_opts).State(.read_only),
    buffer: []u8,
) !?RefOrOid(repo_opts.hash) {
    return try read(repo_kind, repo_opts, state, "HEAD", buffer);
}

pub fn write(
    comptime repo_kind: rp.RepoKind,
    comptime repo_opts: rp.RepoOpts(repo_kind),
    state: rp.Repo(repo_kind, repo_opts).State(.read_write),
    ref_path: []const u8,
    ref_or_oid: RefOrOid(repo_opts.hash),
) !void {
    var buffer = [_]u8{0} ** MAX_REF_CONTENT_SIZE;
    const content = switch (ref_or_oid) {
        .oid => |oid| oid,
        .ref => |ref| blk: {
            @memcpy(buffer[0..REF_START_STR.len], REF_START_STR);
            const path = try ref.toPath(buffer[REF_START_STR.len..]);
            break :blk buffer[0 .. REF_START_STR.len + path.len];
        },
    };

    switch (repo_kind) {
        .git => {
            if (std.fs.path.dirname(ref_path)) |ref_parent_path| {
                try state.core.repo_dir.makePath(ref_parent_path);
            }
            var lock = try fs.LockFile.init(state.core.repo_dir, ref_path);
            defer lock.deinit();
            try lock.lock_file.writeAll(content);
            try lock.lock_file.writeAll("\n");
            lock.success = true;
        },
        .xit => {
            var map = state.extra.moment.*;
            const ref = Ref.initFromPath(ref_path, null) orelse return error.InvalidRef;
            const refs_cursor = try map.putCursor(hash.hashInt(repo_opts.hash, "refs"));
            const refs = try rp.Repo(repo_kind, repo_opts).DB.HashMap(.read_write).init(refs_cursor);

            switch (ref.kind) {
                .none => {},
                .head => {
                    const heads_cursor = try refs.putCursor(hash.hashInt(repo_opts.hash, "heads"));
                    map = try rp.Repo(repo_kind, repo_opts).DB.HashMap(.read_write).init(heads_cursor);
                },
                .tag => {
                    const tags_cursor = try refs.putCursor(hash.hashInt(repo_opts.hash, "tags"));
                    map = try rp.Repo(repo_kind, repo_opts).DB.HashMap(.read_write).init(tags_cursor);
                },
                .remote => |remote_name| {
                    const remotes_cursor = try refs.putCursor(hash.hashInt(repo_opts.hash, "remotes"));
                    const remotes = try rp.Repo(repo_kind, repo_opts).DB.HashMap(.read_write).init(remotes_cursor);
                    const remote_cursor = try remotes.putCursor(hash.hashInt(repo_opts.hash, remote_name));
                    map = try rp.Repo(repo_kind, repo_opts).DB.HashMap(.read_write).init(remote_cursor);
                },
                .other => |other_name| {
                    const other_cursor = try refs.putCursor(hash.hashInt(repo_opts.hash, other_name));
                    map = try rp.Repo(repo_kind, repo_opts).DB.HashMap(.read_write).init(other_cursor);
                },
            }

            const ref_name_hash = hash.hashInt(repo_opts.hash, ref.name);
            const ref_name_set_cursor = try state.extra.moment.putCursor(hash.hashInt(repo_opts.hash, "ref-name-set"));
            const ref_name_set = try rp.Repo(repo_kind, repo_opts).DB.HashSet(.read_write).init(ref_name_set_cursor);
            var ref_name_cursor = try ref_name_set.putCursor(ref_name_hash);
            try ref_name_cursor.writeIfEmpty(.{ .bytes = ref.name });
            try map.putKey(ref_name_hash, .{ .slot = ref_name_cursor.slot() });
            const ref_content_set_cursor = try state.extra.moment.putCursor(hash.hashInt(repo_opts.hash, "ref-content-set"));
            const ref_content_set = try rp.Repo(repo_kind, repo_opts).DB.HashSet(.read_write).init(ref_content_set_cursor);
            var ref_content_cursor = try ref_content_set.putCursor(hash.hashInt(repo_opts.hash, content));
            try ref_content_cursor.writeIfEmpty(.{ .bytes = content });
            try map.put(ref_name_hash, .{ .slot = ref_content_cursor.slot() });
        },
    }
}

pub fn writeRecur(
    comptime repo_kind: rp.RepoKind,
    comptime repo_opts: rp.RepoOpts(repo_kind),
    state: rp.Repo(repo_kind, repo_opts).State(.read_write),
    ref_path: []const u8,
    oid_hex: *const [hash.hexLen(repo_opts.hash)]u8,
) !void {
    var buffer = [_]u8{0} ** MAX_REF_CONTENT_SIZE;
    const ref_or_oid_maybe = read(repo_kind, repo_opts, state.readOnly(), ref_path, &buffer) catch |err| switch (err) {
        error.RefNotFound => {
            try write(repo_kind, repo_opts, state, ref_path, .{ .oid = oid_hex });
            return;
        },
        else => |e| return e,
    };
    if (ref_or_oid_maybe) |input| switch (input) {
        .ref => |ref| {
            var ref_path_buffer = [_]u8{0} ** MAX_REF_CONTENT_SIZE;
            const next_ref_path = try ref.toPath(&ref_path_buffer);
            try writeRecur(repo_kind, repo_opts, state, next_ref_path, oid_hex);
        },
        .oid => try write(repo_kind, repo_opts, state, ref_path, .{ .oid = oid_hex }),
    } else {
        try write(repo_kind, repo_opts, state, ref_path, .{ .oid = oid_hex });
    }
}

pub fn remove(
    comptime repo_kind: rp.RepoKind,
    comptime repo_opts: rp.RepoOpts(repo_kind),
    state: rp.Repo(repo_kind, repo_opts).State(.read_write),
    ref_path: []const u8,
) !void {
    switch (repo_kind) {
        .git => {
            state.core.repo_dir.deleteFile(ref_path) catch |err| switch (err) {
                error.FileNotFound => return error.RefNotFound,
                else => |e| return e,
            };
        },
        .xit => {
            var map = state.extra.moment.*;
            const ref = Ref.initFromPath(ref_path, null) orelse return error.InvalidRef;
            const refs_cursor = try map.putCursor(hash.hashInt(repo_opts.hash, "refs"));
            const refs = try rp.Repo(repo_kind, repo_opts).DB.HashMap(.read_write).init(refs_cursor);

            switch (ref.kind) {
                .none => {},
                .head => {
                    const heads_cursor = try refs.putCursor(hash.hashInt(repo_opts.hash, "heads"));
                    map = try rp.Repo(repo_kind, repo_opts).DB.HashMap(.read_write).init(heads_cursor);
                },
                .tag => {
                    const tags_cursor = try refs.putCursor(hash.hashInt(repo_opts.hash, "tags"));
                    map = try rp.Repo(repo_kind, repo_opts).DB.HashMap(.read_write).init(tags_cursor);
                },
                .remote => |remote_name| {
                    const remotes_cursor = try refs.putCursor(hash.hashInt(repo_opts.hash, "remotes"));
                    const remotes = try rp.Repo(repo_kind, repo_opts).DB.HashMap(.read_write).init(remotes_cursor);
                    const remote_cursor = try remotes.putCursor(hash.hashInt(repo_opts.hash, remote_name));
                    map = try rp.Repo(repo_kind, repo_opts).DB.HashMap(.read_write).init(remote_cursor);
                },
                .other => |other_name| {
                    const other_cursor = try refs.putCursor(hash.hashInt(repo_opts.hash, other_name));
                    map = try rp.Repo(repo_kind, repo_opts).DB.HashMap(.read_write).init(other_cursor);
                },
            }

            const ref_name_hash = hash.hashInt(repo_opts.hash, ref.name);
            if (!try map.remove(ref_name_hash)) {
                return error.RefNotFound;
            }
        },
    }
}

pub fn replaceHead(
    comptime repo_kind: rp.RepoKind,
    comptime repo_opts: rp.RepoOpts(repo_kind),
    state: rp.Repo(repo_kind, repo_opts).State(.read_write),
    ref_or_oid: RefOrOid(repo_opts.hash),
) !void {
    try write(repo_kind, repo_opts, state, "HEAD", ref_or_oid);
}

pub fn updateHead(
    comptime repo_kind: rp.RepoKind,
    comptime repo_opts: rp.RepoOpts(repo_kind),
    state: rp.Repo(repo_kind, repo_opts).State(.read_write),
    oid: *const [hash.hexLen(repo_opts.hash)]u8,
) !void {
    try writeRecur(repo_kind, repo_opts, state, "HEAD", oid);
}

pub fn exists(
    comptime repo_kind: rp.RepoKind,
    comptime repo_opts: rp.RepoOpts(repo_kind),
    state: rp.Repo(repo_kind, repo_opts).State(.read_only),
    ref: Ref,
) !bool {
    var ref_path_buffer = [_]u8{0} ** MAX_REF_CONTENT_SIZE;
    const ref_path = try ref.toPath(&ref_path_buffer);

    var read_buffer = [_]u8{0} ** MAX_REF_CONTENT_SIZE;
    _ = read(repo_kind, repo_opts, state, ref_path, &read_buffer) catch |err| switch (err) {
        error.RefNotFound => return false,
        else => |e| return e,
    };

    return true;
}
