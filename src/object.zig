const std = @import("std");
const builtin = @import("builtin");
const hash = @import("./hash.zig");
const idx = @import("./index.zig");
const rf = @import("./ref.zig");
const fs = @import("./fs.zig");
const rp = @import("./repo.zig");
const pack = @import("./pack.zig");
const chunk = @import("./chunk.zig");
const cfg = @import("./config.zig");
const tg = @import("./tag.zig");
const tr = @import("./tree.zig");
const mrg = @import("./merge.zig");
const zlib = @import("./std/zlib.zig");

fn compressZlib(comptime read_size: usize, in: std.fs.File, out: std.fs.File) !void {
    // init stream from input file
    var zlib_stream = try zlib.compressor(out.deprecatedWriter(), .{ .level = .default });

    // write the compressed data to the output file
    try in.seekTo(0);
    const reader = in.deprecatedReader();
    var buf = [_]u8{0} ** read_size;
    while (true) {
        // read from file
        const size = try reader.read(&buf);
        if (size == 0) break;
        // compress
        try zlib_stream.writer().writeAll(buf[0..size]);
    }
    try zlib_stream.finish();
}

pub fn writeObject(
    comptime repo_kind: rp.RepoKind,
    comptime repo_opts: rp.RepoOpts(repo_kind),
    state: rp.Repo(repo_kind, repo_opts).State(.read_write),
    stream: anytype,
    header: ObjectHeader,
    hash_bytes_buffer: *[hash.byteLen(repo_opts.hash)]u8,
) !void {
    // serialize object header
    var header_bytes = [_]u8{0} ** 32;
    const header_str = try header.write(&header_bytes);

    // calc the hash of its contents
    try hash.hashReader(repo_opts.hash, repo_opts.read_size, &stream.interface, header_str, hash_bytes_buffer);
    const hash_hex = std.fmt.bytesToHex(hash_bytes_buffer, .lower);

    // reset seek pos so we can reuse the reader for copying
    try stream.seekTo(0);

    switch (repo_kind) {
        .git => {
            var objects_dir = try state.core.repo_dir.openDir("objects", .{});
            defer objects_dir.close();

            // make the two char dir
            var hash_prefix_dir = try objects_dir.makeOpenPath(hash_hex[0..2], .{});
            defer hash_prefix_dir.close();
            const hash_suffix = hash_hex[2..];

            // exit early if the file already exists
            if (hash_prefix_dir.openFile(hash_suffix, .{})) |hash_suffix_file| {
                hash_suffix_file.close();
                return;
            } else |err| {
                if (err != error.FileNotFound) {
                    return err;
                }
            }

            // create lock file
            var lock = try fs.LockFile.init(hash_prefix_dir, hash_suffix ++ ".uncompressed");
            defer lock.deinit();
            try lock.lock_file.writeAll(header_str);

            // copy file into temp file
            var read_buffer = [_]u8{0} ** repo_opts.read_size;
            while (true) {
                const size = try stream.interface.readSliceShort(&read_buffer);
                if (size == 0) {
                    break;
                }
                try lock.lock_file.writeAll(read_buffer[0..size]);
            }

            // create compressed lock file
            var compressed_lock = try fs.LockFile.init(hash_prefix_dir, hash_suffix);
            defer compressed_lock.deinit();
            try compressZlib(repo_opts.read_size, lock.lock_file, compressed_lock.lock_file);
            compressed_lock.success = true;
        },
        .xit => {
            const object_hash = hash.bytesToInt(repo_opts.hash, hash_bytes_buffer);
            try chunk.writeChunks(repo_opts, state, &stream.interface, object_hash, header.size, header.kind.name());
        },
    }
}

const Tree = struct {
    entries: std.StringArrayHashMap([]const u8),
    arena: *std.heap.ArenaAllocator,
    allocator: std.mem.Allocator,

    fn init(allocator: std.mem.Allocator) !Tree {
        const arena = try allocator.create(std.heap.ArenaAllocator);
        errdefer allocator.destroy(arena);
        arena.* = std.heap.ArenaAllocator.init(allocator);
        return .{
            .entries = std.StringArrayHashMap([]const u8).init(arena.allocator()),
            .arena = arena,
            .allocator = allocator,
        };
    }

    fn deinit(self: *Tree) void {
        self.arena.deinit();
        self.allocator.destroy(self.arena);
    }

    fn addBlobEntry(self: *Tree, mode: fs.Mode, name: []const u8, oid: []const u8) !void {
        const entry = try std.fmt.allocPrint(self.arena.allocator(), "{s} {s}\x00{s}", .{ mode.toStr(), name, oid });
        try self.entries.put(name, entry);
    }

    fn addTreeEntry(self: *Tree, name: []const u8, oid: []const u8) !void {
        const entry = try std.fmt.allocPrint(self.arena.allocator(), "40000 {s}\x00{s}", .{ name, oid });
        // git sorts tree names as if they had a trailing slash
        const sort_name = try std.fmt.allocPrint(self.arena.allocator(), "{s}/", .{name});
        try self.entries.put(sort_name, entry);
    }

    fn addIndexEntries(
        self: *Tree,
        comptime repo_kind: rp.RepoKind,
        comptime repo_opts: rp.RepoOpts(repo_kind),
        state: rp.Repo(repo_kind, repo_opts).State(.read_write),
        allocator: std.mem.Allocator,
        index: *const idx.Index(repo_kind, repo_opts),
        prefix: []const u8,
        entries: [][]const u8,
    ) !void {
        for (entries) |name| {
            const path = try fs.joinPath(allocator, &.{ prefix, name });
            defer allocator.free(path);

            if (index.entries.get(path)) |*entries_for_path| {
                const entry = entries_for_path[0] orelse return error.NullEntry;
                try self.addBlobEntry(entry.mode, name, &entry.oid);
            } else if (index.dir_to_children.get(path)) |children| {
                var subtree = try Tree.init(allocator);
                defer subtree.deinit();

                var child_names = std.ArrayList([]const u8){};
                defer child_names.deinit(allocator);
                for (children.keys()) |child| {
                    try child_names.append(allocator, child);
                }

                try subtree.addIndexEntries(
                    repo_kind,
                    repo_opts,
                    state,
                    allocator,
                    index,
                    path,
                    child_names.items,
                );

                var tree_hash_bytes_buffer = [_]u8{0} ** hash.byteLen(repo_opts.hash);
                try writeTree(repo_kind, repo_opts, state, allocator, &subtree, &tree_hash_bytes_buffer);

                try self.addTreeEntry(name, &tree_hash_bytes_buffer);
            } else {
                return error.ObjectEntryNotFound;
            }
        }
    }
};

fn writeTree(
    comptime repo_kind: rp.RepoKind,
    comptime repo_opts: rp.RepoOpts(repo_kind),
    state: rp.Repo(repo_kind, repo_opts).State(.read_write),
    allocator: std.mem.Allocator,
    tree: *Tree,
    hash_bytes_buffer: *[hash.byteLen(repo_opts.hash)]u8,
) !void {
    // sort the entries so the tree hashes the same way it would from git
    const SortCtx = struct {
        keys: [][]const u8,
        pub fn lessThan(ctx: @This(), a_index: usize, b_index: usize) bool {
            return std.mem.lessThan(u8, ctx.keys[a_index], ctx.keys[b_index]);
        }
    };
    tree.entries.sort(SortCtx{ .keys = tree.entries.keys() });

    // create tree contents
    const tree_contents = try std.mem.join(allocator, "", tree.entries.values());
    defer allocator.free(tree_contents);

    // create tree header
    var header_buffer = [_]u8{0} ** 32;
    const header = try std.fmt.bufPrint(&header_buffer, "tree {}\x00", .{tree_contents.len});

    // create tree
    const tree_bytes = try std.fmt.allocPrint(allocator, "{s}{s}", .{ header, tree_contents });
    defer allocator.free(tree_bytes);

    // calc the hash of its contents
    try hash.hashBuffer(repo_opts.hash, tree_bytes, hash_bytes_buffer);
    const tree_hash_hex = std.fmt.bytesToHex(hash_bytes_buffer, .lower);

    switch (repo_kind) {
        .git => {
            var objects_dir = try state.core.repo_dir.openDir("objects", .{});
            defer objects_dir.close();

            // make the two char dir
            var tree_hash_prefix_dir = try objects_dir.makeOpenPath(tree_hash_hex[0..2], .{});
            defer tree_hash_prefix_dir.close();
            const tree_hash_suffix = tree_hash_hex[2..];

            // exit early if there is nothing to commit
            if (tree_hash_prefix_dir.openFile(tree_hash_suffix, .{})) |tree_hash_suffix_file| {
                tree_hash_suffix_file.close();
                return;
            } else |err| {
                if (err != error.FileNotFound) {
                    return err;
                }
            }

            // create lock file
            var lock = try fs.LockFile.init(tree_hash_prefix_dir, tree_hash_suffix ++ ".uncompressed");
            defer lock.deinit();
            try lock.lock_file.writeAll(tree_bytes);

            // create compressed lock file
            var compressed_lock = try fs.LockFile.init(tree_hash_prefix_dir, tree_hash_suffix);
            defer compressed_lock.deinit();
            try compressZlib(repo_opts.read_size, lock.lock_file, compressed_lock.lock_file);
            compressed_lock.success = true;
        },
        .xit => {
            const object_hash = hash.bytesToInt(repo_opts.hash, hash_bytes_buffer);
            var reader = std.Io.Reader.fixed(tree_contents);
            try chunk.writeChunks(repo_opts, state, &reader, object_hash, tree_contents.len, "tree");
        },
    }
}

fn sign(
    comptime repo_kind: rp.RepoKind,
    comptime repo_opts: rp.RepoOpts(repo_kind),
    state: rp.Repo(repo_kind, repo_opts).State(.read_only),
    allocator: std.mem.Allocator,
    arena: *std.heap.ArenaAllocator,
    lines: []const []const u8,
    signing_key: []const u8,
) ![]const []const u8 {
    const content = try std.mem.join(arena.allocator(), "\n", lines);

    // get the content file path
    const repo_dir_name = switch (repo_kind) {
        .git => ".git",
        .xit => ".xit",
    };
    const content_file_name = "xit_signing_buffer";
    const content_file_path = try std.fs.path.join(allocator, &.{ state.core.work_path, repo_dir_name, content_file_name });
    defer allocator.free(content_file_path);

    // write the commit content to a file
    const content_file = try std.fs.createFileAbsolute(content_file_path, .{ .truncate = true, .lock = .exclusive });
    defer {
        content_file.close();
        std.fs.deleteFileAbsolute(content_file_path) catch {};
    }
    try content_file.writeAll(content);

    // sign the file
    var process = std.process.Child.init(
        &.{ "ssh-keygen", "-Y", "sign", "-n", "git", "-f", signing_key, content_file_path },
        allocator,
    );
    process.stdin_behavior = .Inherit;
    process.stdout_behavior = .Inherit;
    process.stderr_behavior = .Inherit;
    const term = try process.spawnAndWait();
    if (0 != term.Exited) {
        return error.ObjectSigningFailed;
    }

    // read the sig
    {
        const sig_file_name = content_file_name ++ ".sig";
        const sig_file = try state.core.repo_dir.openFile(sig_file_name, .{ .mode = .read_only });
        defer {
            sig_file.close();
            state.core.repo_dir.deleteFile(sig_file_name) catch {};
        }

        var reader_buffer = [_]u8{0} ** repo_opts.buffer_size;
        var sig_file_reader = sig_file.reader(&reader_buffer);
        var sig_lines = std.ArrayList([]const u8){};

        // for each line...
        while (sig_file_reader.interface.peekByte()) |_| {
            var line_writer = std.Io.Writer.Allocating.init(arena.allocator());
            _ = try sig_file_reader.interface.streamDelimiterLimit(&line_writer.writer, '\n', .limited(repo_opts.max_read_size));

            // skip delimiter
            if (sig_file_reader.interface.bufferedLen() > 0) {
                sig_file_reader.interface.toss(1);
            }

            try sig_lines.append(arena.allocator(), line_writer.written());
        } else |err| switch (err) {
            error.EndOfStream => {},
            else => |e| return e,
        }

        return try sig_lines.toOwnedSlice(arena.allocator());
    }
}

pub fn CommitMetadata(comptime hash_kind: hash.HashKind) type {
    return struct {
        author: ?[]const u8 = null,
        committer: ?[]const u8 = null,
        message: ?[]const u8 = null,
        parent_oids: ?[]const [hash.hexLen(hash_kind)]u8 = null,
        allow_empty: bool = false,
        timestamp: u64 = 0,

        pub fn firstParent(self: CommitMetadata(hash_kind)) ?*const [hash.hexLen(hash_kind)]u8 {
            if (self.parent_oids) |parent_oids| {
                if (parent_oids.len > 0) {
                    return &parent_oids[0];
                }
            }
            return null;
        }
    };
}

pub fn writeCommit(
    comptime repo_kind: rp.RepoKind,
    comptime repo_opts: rp.RepoOpts(repo_kind),
    state: rp.Repo(repo_kind, repo_opts).State(.read_write),
    allocator: std.mem.Allocator,
    metadata: CommitMetadata(repo_opts.hash),
) ![hash.hexLen(repo_opts.hash)]u8 {
    const parent_oids = if (metadata.parent_oids) |oids| oids else blk: {
        const head_oid_maybe = try rf.readHeadRecurMaybe(repo_kind, repo_opts, state.readOnly());
        break :blk if (head_oid_maybe) |head_oid| &.{head_oid} else &.{};
    };

    // make sure there is no unfinished merge in progress
    try mrg.checkForUnfinishedMerge(repo_kind, repo_opts, state.readOnly());

    // read index
    var index = try idx.Index(repo_kind, repo_opts).init(allocator, state.readOnly());
    defer index.deinit();

    // create tree and add index entries
    var tree = try Tree.init(allocator);
    defer tree.deinit();
    try tree.addIndexEntries(repo_kind, repo_opts, state, allocator, &index, "", index.root_children.keys());

    // write and hash tree
    var tree_hash_bytes_buffer = [_]u8{0} ** hash.byteLen(repo_opts.hash);
    try writeTree(repo_kind, repo_opts, state, allocator, &tree, &tree_hash_bytes_buffer);
    const tree_hash_hex = std.fmt.bytesToHex(tree_hash_bytes_buffer, .lower);

    // don't allow commit if the tree hasn't changed
    if (!metadata.allow_empty) {
        if (parent_oids.len == 0) {
            if (tree.entries.count() == 0) {
                return error.EmptyCommit;
            }
        } else if (parent_oids.len == 1) {
            var first_parent = try Object(repo_kind, repo_opts, .full).init(allocator, state.readOnly(), &parent_oids[0]);
            defer first_parent.deinit();
            if (std.mem.eql(u8, &first_parent.content.commit.tree, &tree_hash_hex)) {
                return error.EmptyCommit;
            }
        }
    }

    // create commit contents
    const commit_contents = blk: {
        var arena = std.heap.ArenaAllocator.init(allocator);
        defer arena.deinit();

        var config = try cfg.Config(repo_kind, repo_opts).init(state.readOnly(), arena.allocator());
        defer config.deinit();

        var metadata_lines = std.ArrayList([]const u8){};

        try metadata_lines.append(arena.allocator(), try std.fmt.allocPrint(arena.allocator(), "tree {s}", .{tree_hash_hex}));
        for (parent_oids) |parent_oid| {
            try metadata_lines.append(arena.allocator(), try std.fmt.allocPrint(arena.allocator(), "parent {s}", .{parent_oid}));
        }

        const ts = if (repo_opts.is_test) 0 else std.time.timestamp();

        const author = metadata.author orelse auth_blk: {
            if (repo_opts.is_test) break :auth_blk "radar <radar@roark>";
            const user_section = config.sections.get("user") orelse return error.UserConfigNotFound;
            const name = user_section.get("name") orelse return error.UserConfigNotFound;
            const email = user_section.get("email") orelse return error.UserConfigNotFound;
            break :auth_blk try std.fmt.allocPrint(arena.allocator(), "{s} <{s}>", .{ name, email });
        };
        try metadata_lines.append(arena.allocator(), try std.fmt.allocPrint(arena.allocator(), "author {s} {} +0000", .{ author, ts }));

        const committer = metadata.committer orelse author;
        try metadata_lines.append(arena.allocator(), try std.fmt.allocPrint(arena.allocator(), "committer {s} {} +0000", .{ committer, ts }));

        try metadata_lines.append(arena.allocator(), try std.fmt.allocPrint(arena.allocator(), "\n{s}", .{metadata.message orelse ""}));

        // sign if key is in config
        if (config.sections.get("user")) |user_section| {
            if (user_section.get("signingkey")) |signing_key| {
                const sig_lines = try sign(repo_kind, repo_opts, state.readOnly(), allocator, &arena, metadata_lines.items, signing_key);

                var header_lines = std.ArrayList([]const u8){};
                defer header_lines.deinit(allocator);
                for (sig_lines, 0..) |line, i| {
                    const sig_line = if (i == 0)
                        try std.fmt.allocPrint(arena.allocator(), "gpgsig {s}", .{line})
                    else
                        try std.fmt.allocPrint(arena.allocator(), " {s}", .{line});
                    try header_lines.append(allocator, sig_line);
                }

                const message = metadata_lines.pop() orelse unreachable; // remove the message
                try metadata_lines.appendSlice(arena.allocator(), header_lines.items); // add the sig
                try metadata_lines.append(arena.allocator(), message); // add the message back
            }
        }

        break :blk try std.mem.join(allocator, "\n", metadata_lines.items);
    };
    defer allocator.free(commit_contents);

    // create commit header
    var header_buffer = [_]u8{0} ** 32;
    const header = try std.fmt.bufPrint(&header_buffer, "commit {}\x00", .{commit_contents.len});

    // create commit
    const obj_content = try std.fmt.allocPrint(allocator, "{s}{s}", .{ header, commit_contents });
    defer allocator.free(obj_content);

    // calc the hash of its contents
    var commit_hash_bytes_buffer = [_]u8{0} ** hash.byteLen(repo_opts.hash);
    try hash.hashBuffer(repo_opts.hash, obj_content, &commit_hash_bytes_buffer);
    const commit_hash_hex = std.fmt.bytesToHex(commit_hash_bytes_buffer, .lower);
    const commit_hash = hash.bytesToInt(repo_opts.hash, &commit_hash_bytes_buffer);

    switch (repo_kind) {
        .git => {
            // open the objects dir
            var objects_dir = try state.core.repo_dir.openDir("objects", .{});
            defer objects_dir.close();

            // make the two char dir
            var commit_hash_prefix_dir = try objects_dir.makeOpenPath(commit_hash_hex[0..2], .{});
            defer commit_hash_prefix_dir.close();
            const commit_hash_suffix = commit_hash_hex[2..];

            // create lock file
            var lock = try fs.LockFile.init(commit_hash_prefix_dir, commit_hash_suffix ++ ".uncompressed");
            defer lock.deinit();
            try lock.lock_file.writeAll(obj_content);

            // create compressed lock file
            var compressed_lock = try fs.LockFile.init(commit_hash_prefix_dir, commit_hash_suffix);
            defer compressed_lock.deinit();
            try compressZlib(repo_opts.read_size, lock.lock_file, compressed_lock.lock_file);
            compressed_lock.success = true;

            // write commit id to HEAD
            try rf.writeRecur(repo_kind, repo_opts, state, "HEAD", &commit_hash_hex);
        },
        .xit => {
            var reader = std.Io.Reader.fixed(commit_contents);
            try chunk.writeChunks(repo_opts, state, &reader, commit_hash, commit_contents.len, "commit");

            // write commit id to HEAD
            try rf.writeRecur(repo_kind, repo_opts, state, "HEAD", &commit_hash_hex);
        },
    }

    return std.fmt.bytesToHex(commit_hash_bytes_buffer, .lower);
}

pub fn writeTag(
    comptime repo_kind: rp.RepoKind,
    comptime repo_opts: rp.RepoOpts(repo_kind),
    state: rp.Repo(repo_kind, repo_opts).State(.read_write),
    allocator: std.mem.Allocator,
    input: tg.AddTagInput,
    target_oid: *const [hash.hexLen(repo_opts.hash)]u8,
) ![hash.hexLen(repo_opts.hash)]u8 {
    const tag_contents = blk: {
        var arena = std.heap.ArenaAllocator.init(allocator);
        defer arena.deinit();

        var config = try cfg.Config(repo_kind, repo_opts).init(state.readOnly(), arena.allocator());
        defer config.deinit();

        var metadata_lines = std.ArrayList([]const u8){};

        const kind = kind_blk: {
            var obj = try Object(repo_kind, repo_opts, .raw).init(allocator, state.readOnly(), target_oid);
            defer obj.deinit();
            break :kind_blk obj.content;
        };

        try metadata_lines.append(arena.allocator(), try std.fmt.allocPrint(arena.allocator(), "object {s}", .{target_oid}));
        try metadata_lines.append(arena.allocator(), try std.fmt.allocPrint(arena.allocator(), "type {s}", .{kind.name()}));
        try metadata_lines.append(arena.allocator(), try std.fmt.allocPrint(arena.allocator(), "tag {s}", .{input.name}));

        const ts = if (repo_opts.is_test) 0 else std.time.timestamp();

        const tagger = input.tagger orelse auth_blk: {
            if (repo_opts.is_test) break :auth_blk "radar <radar@roark>";
            const user_section = config.sections.get("user") orelse return error.UserConfigNotFound;
            const name = user_section.get("name") orelse return error.UserConfigNotFound;
            const email = user_section.get("email") orelse return error.UserConfigNotFound;
            break :auth_blk try std.fmt.allocPrint(arena.allocator(), "{s} <{s}>", .{ name, email });
        };
        try metadata_lines.append(arena.allocator(), try std.fmt.allocPrint(arena.allocator(), "tagger {s} {} +0000", .{ tagger, ts }));

        try metadata_lines.append(arena.allocator(), try std.fmt.allocPrint(arena.allocator(), "\n{s}", .{input.message orelse ""}));

        // sign if key is in config
        if (config.sections.get("user")) |user_section| {
            if (user_section.get("signingkey")) |signing_key| {
                const sig_lines = try sign(repo_kind, repo_opts, state.readOnly(), allocator, &arena, metadata_lines.items, signing_key);
                try metadata_lines.appendSlice(arena.allocator(), sig_lines);
            }
        }

        break :blk try std.mem.join(allocator, "\n", metadata_lines.items);
    };
    defer allocator.free(tag_contents);

    // create tag header
    var header_buffer = [_]u8{0} ** 32;
    const header = try std.fmt.bufPrint(&header_buffer, "tag {}\x00", .{tag_contents.len});

    // create tag
    const obj_content = try std.fmt.allocPrint(allocator, "{s}{s}", .{ header, tag_contents });
    defer allocator.free(obj_content);

    // calc the hash of its contents
    var tag_hash_bytes_buffer = [_]u8{0} ** hash.byteLen(repo_opts.hash);
    try hash.hashBuffer(repo_opts.hash, obj_content, &tag_hash_bytes_buffer);
    const tag_hash_hex = std.fmt.bytesToHex(tag_hash_bytes_buffer, .lower);
    const tag_hash = hash.bytesToInt(repo_opts.hash, &tag_hash_bytes_buffer);

    switch (repo_kind) {
        .git => {
            // open the objects dir
            var objects_dir = try state.core.repo_dir.openDir("objects", .{});
            defer objects_dir.close();

            // make the two char dir
            var tag_hash_prefix_dir = try objects_dir.makeOpenPath(tag_hash_hex[0..2], .{});
            defer tag_hash_prefix_dir.close();
            const tag_hash_suffix = tag_hash_hex[2..];

            // create lock file
            var lock = try fs.LockFile.init(tag_hash_prefix_dir, tag_hash_suffix ++ ".uncompressed");
            defer lock.deinit();
            try lock.lock_file.writeAll(obj_content);

            // create compressed lock file
            var compressed_lock = try fs.LockFile.init(tag_hash_prefix_dir, tag_hash_suffix);
            defer compressed_lock.deinit();
            try compressZlib(repo_opts.read_size, lock.lock_file, compressed_lock.lock_file);
            compressed_lock.success = true;
        },
        .xit => {
            var reader = std.Io.Reader.fixed(tag_contents);
            try chunk.writeChunks(repo_opts, state, &reader, tag_hash, tag_contents.len, "tag");
        },
    }

    return std.fmt.bytesToHex(tag_hash_bytes_buffer, .lower);
}

pub const ObjectKind = enum {
    blob,
    tree,
    commit,
    tag,

    pub fn init(kind_str: []const u8) !ObjectKind {
        return if (std.mem.eql(u8, "blob", kind_str))
            .blob
        else if (std.mem.eql(u8, "tree", kind_str))
            .tree
        else if (std.mem.eql(u8, "commit", kind_str))
            .commit
        else if (std.mem.eql(u8, "tag", kind_str))
            .tag
        else
            error.InvalidObjectKind;
    }

    pub fn name(self: ObjectKind) []const u8 {
        return switch (self) {
            .blob => "blob",
            .tree => "tree",
            .commit => "commit",
            .tag => "tag",
        };
    }
};

pub fn ObjectReader(comptime repo_kind: rp.RepoKind, comptime repo_opts: rp.RepoOpts(repo_kind)) type {
    return struct {
        allocator: std.mem.Allocator,
        reader: Reader,
        interface: std.Io.Reader,

        pub const Reader = switch (repo_kind) {
            .git => pack.LooseOrPackObjectReader(repo_opts),
            .xit => chunk.ChunkObjectReader(repo_opts),
        };

        pub fn init(
            allocator: std.mem.Allocator,
            state: rp.Repo(repo_kind, repo_opts).State(.read_only),
            oid: *const [hash.hexLen(repo_opts.hash)]u8,
        ) !ObjectReader(repo_kind, repo_opts) {
            const buffer = try allocator.alloc(u8, repo_opts.read_size);
            errdefer allocator.free(buffer);

            return .{
                .allocator = allocator,
                .reader = switch (repo_kind) {
                    .git => try pack.LooseOrPackObjectReader(repo_opts).init(allocator, state, oid),
                    .xit => try chunk.ChunkObjectReader(repo_opts).init(allocator, state, oid),
                },
                .interface = .{
                    .vtable = &.{ .stream = stream },
                    .buffer = buffer,
                    .seek = 0,
                    .end = 0,
                },
            };
        }

        pub fn deinit(self: *ObjectReader(repo_kind, repo_opts)) void {
            self.reader.deinit(self.allocator);
            self.allocator.free(self.interface.buffer);
        }

        pub fn reset(self: *ObjectReader(repo_kind, repo_opts)) !void {
            try self.reader.reset();
            self.interface.seek = 0;
            self.interface.end = 0;
        }

        pub fn seekTo(self: *ObjectReader(repo_kind, repo_opts), position: u64) !void {
            try self.reset();
            switch (repo_kind) {
                .git => try self.reader.skipBytes(position),
                .xit => try self.reader.seekTo(position),
            }
        }

        pub fn header(self: *const ObjectReader(repo_kind, repo_opts)) ObjectHeader {
            return switch (repo_kind) {
                .git => self.reader.header(),
                .xit => self.reader.header,
            };
        }

        fn stream(io_r: *std.Io.Reader, io_w: *std.Io.Writer, limit: std.Io.Limit) std.Io.Reader.StreamError!usize {
            const r: *ObjectReader(repo_kind, repo_opts) = @alignCast(@fieldParentPtr("interface", io_r));
            const dest = limit.slice(try io_w.writableSliceGreedy(1));
            const size = r.reader.read(dest) catch return error.ReadFailed;
            if (size == 0) return error.EndOfStream;
            io_w.advance(size);
            return size;
        }
    };
}

pub const ObjectHeader = struct {
    kind: ObjectKind,
    size: u64,

    pub fn read(reader: *std.Io.Reader) !ObjectHeader {
        const MAX_SIZE: usize = 16;

        // read the object kind
        var object_kind_buf = [_]u8{0} ** MAX_SIZE;
        var object_kind_writer = std.Io.Writer.fixed(&object_kind_buf);
        const object_kind_size = try reader.streamDelimiter(&object_kind_writer, ' ');
        const object_kind = object_kind_buf[0..object_kind_size];
        reader.toss(1); // skip delimiter

        // read the length
        var object_len_buf = [_]u8{0} ** MAX_SIZE;
        var object_len_writer = std.Io.Writer.fixed(&object_len_buf);
        const object_len_size = try reader.streamDelimiter(&object_len_writer, 0);
        const object_len = try std.fmt.parseInt(u64, object_len_buf[0..object_len_size], 10);
        reader.toss(1); // skip delimiter

        return .{
            .kind = try ObjectKind.init(object_kind),
            .size = object_len,
        };
    }

    pub fn write(self: ObjectHeader, buffer: []u8) ![]const u8 {
        const type_name = self.kind.name();
        const file_size = self.size;
        return try std.fmt.bufPrint(buffer, "{s} {}\x00", .{ type_name, file_size });
    }
};

pub fn ObjectContent(comptime hash_kind: hash.HashKind) type {
    return union(ObjectKind) {
        blob,
        tree: struct {
            entries: std.StringArrayHashMap(tr.TreeEntry(hash_kind)),
        },
        commit: struct {
            tree: [hash.hexLen(hash_kind)]u8,
            metadata: CommitMetadata(hash_kind),
            message_position: u64,
        },
        tag: struct {
            target: [hash.hexLen(hash_kind)]u8,
            kind: ObjectKind,
            name: []const u8,
            tagger: []const u8,
            message: ?[]const u8,
            message_position: u64,
        },
    };
}

pub const ObjectLoadKind = enum {
    // only load the header to determine the object kind,
    // but not any of the remaining content
    raw,
    // read the entire content of the object
    full,
};

pub fn Object(comptime repo_kind: rp.RepoKind, comptime repo_opts: rp.RepoOpts(repo_kind), comptime load_kind: ObjectLoadKind) type {
    return struct {
        allocator: std.mem.Allocator,
        arena: *std.heap.ArenaAllocator,
        content: switch (load_kind) {
            .raw => ObjectKind,
            .full => ObjectContent(repo_opts.hash),
        },
        oid: [hash.hexLen(repo_opts.hash)]u8,
        len: u64,
        object_reader: ObjectReader(repo_kind, repo_opts),

        pub fn init(
            allocator: std.mem.Allocator,
            state: rp.Repo(repo_kind, repo_opts).State(.read_only),
            oid: *const [hash.hexLen(repo_opts.hash)]u8,
        ) !Object(repo_kind, repo_opts, load_kind) {
            var obj_rdr = try ObjectReader(repo_kind, repo_opts).init(allocator, state, oid);
            errdefer obj_rdr.deinit();

            const arena = try allocator.create(std.heap.ArenaAllocator);
            arena.* = std.heap.ArenaAllocator.init(allocator);
            errdefer {
                arena.deinit();
                allocator.destroy(arena);
            }

            const header = obj_rdr.header();

            switch (header.kind) {
                .blob => return .{
                    .allocator = allocator,
                    .arena = arena,
                    .content = switch (load_kind) {
                        .raw => .blob,
                        .full => .{ .blob = {} },
                    },
                    .oid = oid.*,
                    .len = header.size,
                    .object_reader = obj_rdr,
                },
                .tree => switch (load_kind) {
                    .raw => return .{
                        .allocator = allocator,
                        .arena = arena,
                        .content = .tree,
                        .oid = oid.*,
                        .len = header.size,
                        .object_reader = obj_rdr,
                    },
                    .full => {
                        var entries = std.StringArrayHashMap(tr.TreeEntry(repo_opts.hash)).init(arena.allocator());

                        while (obj_rdr.interface.peekByte()) |_| {
                            var entry_mode_buffer = [_]u8{0} ** 6;
                            var entry_mode_writer = std.Io.Writer.fixed(&entry_mode_buffer);
                            const entry_mode_size = try obj_rdr.interface.streamDelimiter(&entry_mode_writer, ' ');
                            obj_rdr.interface.toss(1); // skip delimiter
                            const entry_mode_str = entry_mode_buffer[0..entry_mode_size];
                            const entry_mode: fs.Mode = @bitCast(try std.fmt.parseInt(u32, entry_mode_str, 8));

                            var entry_name_writer = std.Io.Writer.Allocating.init(arena.allocator());
                            _ = try obj_rdr.interface.streamDelimiterLimit(&entry_name_writer.writer, 0, .limited(repo_opts.max_read_size));
                            obj_rdr.interface.toss(1); // skip delimiter

                            const entry_name = entry_name_writer.written();
                            var entry_oid = [_]u8{0} ** hash.byteLen(repo_opts.hash);
                            try obj_rdr.interface.readSliceAll(&entry_oid);
                            try entries.put(entry_name, .{ .oid = entry_oid, .mode = entry_mode });
                        } else |err| switch (err) {
                            error.EndOfStream => {},
                            else => |e| return e,
                        }

                        return .{
                            .allocator = allocator,
                            .arena = arena,
                            .content = ObjectContent(repo_opts.hash){ .tree = .{ .entries = entries } },
                            .oid = oid.*,
                            .len = header.size,
                            .object_reader = obj_rdr,
                        };
                    },
                },
                .commit => switch (load_kind) {
                    .raw => return .{
                        .allocator = allocator,
                        .arena = arena,
                        .content = .commit,
                        .oid = oid.*,
                        .len = header.size,
                        .object_reader = obj_rdr,
                    },
                    .full => {
                        var position: u64 = 0;

                        // read the content kind
                        var content_kind_writer = std.Io.Writer.Allocating.init(allocator);
                        defer content_kind_writer.deinit();
                        _ = try obj_rdr.interface.streamDelimiterLimit(&content_kind_writer.writer, ' ', .limited(repo_opts.max_read_size));
                        obj_rdr.interface.toss(1); // skip delimiter
                        const content_kind = content_kind_writer.written();
                        if (!std.mem.eql(u8, "tree", content_kind)) {
                            return error.InvalidObject;
                        }
                        position += content_kind.len + 1;

                        // read the tree hash
                        var tree_hash = [_]u8{0} ** hash.hexLen(repo_opts.hash);
                        var tree_hash_writer = std.Io.Writer.fixed(&tree_hash);
                        const tree_hash_size = try obj_rdr.interface.streamDelimiter(&tree_hash_writer, '\n');
                        obj_rdr.interface.toss(1); // skip delimiter
                        if (tree_hash_size != tree_hash.len) {
                            return error.InvalidObject;
                        }
                        position += tree_hash.len + 1;

                        var parent_oids = std.ArrayList([hash.hexLen(repo_opts.hash)]u8){};
                        var metadata = CommitMetadata(repo_opts.hash){};

                        // read the metadata
                        while (true) {
                            var line_writer = std.Io.Writer.Allocating.init(arena.allocator());
                            _ = try obj_rdr.interface.streamDelimiterLimit(&line_writer.writer, '\n', .limited(repo_opts.max_read_size));
                            obj_rdr.interface.toss(1); // skip delimiter

                            const line = line_writer.written();
                            position += line.len + 1;
                            if (line.len == 0) {
                                break;
                            }
                            if (std.mem.indexOf(u8, line, " ")) |line_idx| {
                                if (line_idx == line.len) {
                                    break;
                                }
                                const key = line[0..line_idx];
                                const value = line[line_idx + 1 ..];

                                if (std.mem.eql(u8, "parent", key)) {
                                    if (value.len != hash.hexLen(repo_opts.hash)) {
                                        return error.InvalidObject;
                                    }
                                    try parent_oids.append(arena.allocator(), value[0..comptime hash.hexLen(repo_opts.hash)].*);
                                } else if (std.mem.eql(u8, "author", key)) {
                                    metadata.author = value;
                                } else if (std.mem.eql(u8, "committer", key)) {
                                    metadata.committer = value;
                                    var iter = std.mem.splitBackwardsScalar(u8, value, ' ');
                                    _ = iter.next(); // timezone
                                    if (iter.next()) |timestamp_str| {
                                        metadata.timestamp = try std.fmt.parseInt(u64, timestamp_str, 0);
                                    }
                                }
                            }
                        }

                        metadata.parent_oids = parent_oids.items;

                        // read only the first line
                        {
                            var line_writer = std.Io.Writer.Allocating.init(arena.allocator());
                            const line_size_maybe = obj_rdr.interface.streamDelimiterLimit(&line_writer.writer, '\n', .limited(repo_opts.max_line_size)) catch |err| switch (err) {
                                error.StreamTooLong => null,
                                else => |e| return e,
                            };

                            // skip delimiter
                            if (obj_rdr.interface.bufferedLen() > 0) {
                                obj_rdr.interface.toss(1);
                            }

                            metadata.message = if (line_size_maybe != null) line_writer.written() else null;
                        }

                        return .{
                            .allocator = allocator,
                            .arena = arena,
                            .content = .{
                                .commit = .{
                                    .tree = tree_hash,
                                    .metadata = metadata,
                                    .message_position = position,
                                },
                            },
                            .oid = oid.*,
                            .len = header.size,
                            .object_reader = obj_rdr,
                        };
                    },
                },
                .tag => switch (load_kind) {
                    .raw => return .{
                        .allocator = allocator,
                        .arena = arena,
                        .content = .tag,
                        .oid = oid.*,
                        .len = header.size,
                        .object_reader = obj_rdr,
                    },
                    .full => {
                        var position: u64 = 0;

                        // read the fields
                        var fields = std.StringArrayHashMap([]const u8).init(allocator);
                        defer fields.deinit();
                        while (true) {
                            var line_writer = std.Io.Writer.Allocating.init(arena.allocator());
                            _ = try obj_rdr.interface.streamDelimiterLimit(&line_writer.writer, '\n', .limited(repo_opts.max_read_size));
                            obj_rdr.interface.toss(1); // skip delimiter

                            const line = line_writer.written();
                            position += line.len + 1;
                            if (line.len == 0) {
                                break;
                            }
                            if (std.mem.indexOf(u8, line, " ")) |line_idx| {
                                if (line_idx == line.len) {
                                    break;
                                }
                                const key = line[0..line_idx];
                                const value = line[line_idx + 1 ..];
                                try fields.put(key, value);
                            }
                        }

                        // init the content
                        const target = fields.get("object") orelse return error.InvalidObject;
                        if (target.len != hash.hexLen(repo_opts.hash)) {
                            return error.InvalidObject;
                        }
                        var content = ObjectContent(repo_opts.hash){
                            .tag = .{
                                .target = target[0..comptime hash.hexLen(repo_opts.hash)].*,
                                .kind = try ObjectKind.init(fields.get("type") orelse return error.InvalidObject),
                                .name = fields.get("tag") orelse return error.InvalidObject,
                                .tagger = fields.get("tagger") orelse return error.InvalidObject,
                                .message = null,
                                .message_position = position,
                            },
                        };

                        // read only the first line
                        {
                            var line_writer = std.Io.Writer.Allocating.init(arena.allocator());
                            const line_size_maybe = obj_rdr.interface.streamDelimiterLimit(&line_writer.writer, '\n', .limited(repo_opts.max_line_size)) catch |err| switch (err) {
                                error.StreamTooLong => null,
                                else => |e| return e,
                            };

                            // skip delimiter
                            if (obj_rdr.interface.bufferedLen() > 0) {
                                obj_rdr.interface.toss(1);
                            }

                            content.tag.message = if (line_size_maybe != null) line_writer.written() else null;
                        }

                        return .{
                            .allocator = allocator,
                            .arena = arena,
                            .content = content,
                            .oid = oid.*,
                            .len = header.size,
                            .object_reader = obj_rdr,
                        };
                    },
                },
            }
        }

        pub fn initCommit(
            allocator: std.mem.Allocator,
            state: rp.Repo(repo_kind, repo_opts).State(.read_only),
            oid: *const [hash.hexLen(repo_opts.hash)]u8,
        ) !Object(repo_kind, repo_opts, load_kind) {
            var object = try Object(repo_kind, repo_opts, load_kind).init(allocator, state, oid);
            errdefer object.deinit();

            switch (object.content) {
                .blob, .tree => return error.CommitNotFound,
                .commit => return object,
                .tag => |tag| {
                    const commit_object = try initCommit(allocator, state, &tag.target);
                    object.deinit();
                    return commit_object;
                },
            }
        }

        pub fn deinit(self: *Object(repo_kind, repo_opts, load_kind)) void {
            self.arena.deinit();
            self.allocator.destroy(self.arena);
            self.object_reader.deinit();
        }
    };
}

pub const ObjectIteratorOptions = struct {
    kind: enum {
        all,
        commit,
    },
    max_depth: ?usize = null,
};

pub fn ObjectIterator(
    comptime repo_kind: rp.RepoKind,
    comptime repo_opts: rp.RepoOpts(repo_kind),
    comptime load_kind: ObjectLoadKind,
) type {
    return struct {
        allocator: std.mem.Allocator,
        core: *rp.Repo(repo_kind, repo_opts).Core,
        moment: rp.Repo(repo_kind, repo_opts).Moment(.read_only),
        oid_queue: std.DoublyLinkedList,
        oid_excludes: std.AutoHashMap([hash.hexLen(repo_opts.hash)]u8, void),
        object: Object(repo_kind, repo_opts, load_kind),
        depth: usize,
        options: ObjectIteratorOptions,

        const OidAndNode = struct {
            oid: [hash.hexLen(repo_opts.hash)]u8,
            depth: usize,
            node: std.DoublyLinkedList.Node,
        };

        pub fn init(
            allocator: std.mem.Allocator,
            state: rp.Repo(repo_kind, repo_opts).State(.read_only),
            options: ObjectIteratorOptions,
        ) !ObjectIterator(repo_kind, repo_opts, load_kind) {
            return .{
                .allocator = allocator,
                .core = state.core,
                .moment = state.extra.moment.*,
                .oid_queue = std.DoublyLinkedList{},
                .oid_excludes = std.AutoHashMap([hash.hexLen(repo_opts.hash)]u8, void).init(allocator),
                .object = undefined,
                .depth = 0,
                .options = options,
            };
        }

        pub fn deinit(self: *ObjectIterator(repo_kind, repo_opts, load_kind)) void {
            while (self.oid_queue.popFirst()) |node| {
                const oid_and_node: *OidAndNode = @fieldParentPtr("node", node);
                self.allocator.destroy(oid_and_node);
            }
            self.oid_excludes.deinit();
        }

        pub fn next(self: *ObjectIterator(repo_kind, repo_opts, load_kind)) !?*Object(repo_kind, repo_opts, load_kind) {
            const state = rp.Repo(repo_kind, repo_opts).State(.read_only){ .core = self.core, .extra = .{ .moment = &self.moment } };
            while (self.oid_queue.popFirst()) |node| {
                const oid_and_node: *OidAndNode = @fieldParentPtr("node", node);
                const next_oid = oid_and_node.oid;
                const node_depth = oid_and_node.depth;
                self.allocator.destroy(oid_and_node);

                if (!self.oid_excludes.contains(next_oid)) {
                    try self.oid_excludes.put(next_oid, {});
                    self.depth = node_depth;
                    switch (load_kind) {
                        .raw => {
                            var object = try Object(repo_kind, repo_opts, .full).init(self.allocator, state, &next_oid);
                            defer object.deinit();
                            try self.includeContent(object.content, node_depth + 1);

                            switch (self.options.kind) {
                                .all => {},
                                .commit => if (.commit != object.content) continue,
                            }

                            var raw_object = try Object(repo_kind, repo_opts, .raw).init(self.allocator, state, &next_oid);
                            errdefer raw_object.deinit();
                            self.object = raw_object;
                            return &self.object;
                        },
                        .full => {
                            var object = try Object(repo_kind, repo_opts, .full).init(self.allocator, state, &next_oid);
                            errdefer object.deinit();
                            try self.includeContent(object.content, node_depth + 1);

                            switch (self.options.kind) {
                                .all => {},
                                .commit => if (.commit != object.content) {
                                    object.deinit();
                                    continue;
                                },
                            }

                            self.object = object;
                            return &self.object;
                        },
                    }
                }
            }
            return null;
        }

        fn includeContent(self: *ObjectIterator(repo_kind, repo_opts, load_kind), content: ObjectContent(repo_opts.hash), child_depth: usize) !void {
            switch (content) {
                .blob => {},
                .tree => |tree_content| switch (self.options.kind) {
                    .all => for (tree_content.entries.values()) |entry| {
                        const entry_oid = std.fmt.bytesToHex(entry.oid, .lower);
                        try self.includeAtDepth(&entry_oid, child_depth);
                    },
                    .commit => {},
                },
                .commit => |commit_content| {
                    if (commit_content.metadata.parent_oids) |parent_oids| {
                        for (parent_oids) |*parent_oid| {
                            try self.includeAtDepth(parent_oid, child_depth);
                        }
                    }
                    switch (self.options.kind) {
                        .all => try self.includeAtDepth(&commit_content.tree, child_depth),
                        .commit => {},
                    }
                },
                .tag => |tag| try self.includeAtDepth(&tag.target, child_depth),
            }
        }

        pub fn include(self: *ObjectIterator(repo_kind, repo_opts, load_kind), oid: *const [hash.hexLen(repo_opts.hash)]u8) !void {
            try self.includeAtDepth(oid, 0);
        }

        pub fn includeAtDepth(self: *ObjectIterator(repo_kind, repo_opts, load_kind), oid: *const [hash.hexLen(repo_opts.hash)]u8, item_depth: usize) !void {
            if (self.options.max_depth) |max| if (item_depth > max) return;
            if (!self.oid_excludes.contains(oid.*)) {
                var oid_and_node = try self.allocator.create(OidAndNode);
                errdefer self.allocator.free(oid_and_node);
                oid_and_node.oid = oid.*;
                oid_and_node.depth = item_depth;
                oid_and_node.node = .{};
                self.oid_queue.append(&oid_and_node.node);
            }
        }

        pub fn exclude(self: *ObjectIterator(repo_kind, repo_opts, load_kind), oid: *const [hash.hexLen(repo_opts.hash)]u8) !void {
            try self.oid_excludes.put(oid.*, {});

            const state = rp.Repo(repo_kind, repo_opts).State(.read_only){ .core = self.core, .extra = .{ .moment = &self.moment } };
            var object = try Object(repo_kind, repo_opts, .full).init(self.allocator, state, oid);
            defer object.deinit();
            switch (object.content) {
                .blob, .tag => {},
                .tree => |tree| switch (self.options.kind) {
                    .all => for (tree.entries.values()) |entry| {
                        try self.exclude(&std.fmt.bytesToHex(entry.oid, .lower));
                    },
                    .commit => {},
                },
                .commit => |commit| {
                    if (commit.metadata.parent_oids) |parent_oids| {
                        for (parent_oids) |parent_oid| {
                            try self.oid_excludes.put(parent_oid, {});
                        }
                    }
                    switch (self.options.kind) {
                        .all => try self.exclude(&commit.tree),
                        .commit => {},
                    }
                },
            }
        }
    };
}

pub fn copyFromObjectIterator(
    comptime repo_kind: rp.RepoKind,
    comptime repo_opts: rp.RepoOpts(repo_kind),
    state: rp.Repo(repo_kind, repo_opts).State(.read_write),
    comptime source_repo_kind: rp.RepoKind,
    comptime source_repo_opts: rp.RepoOpts(source_repo_kind),
    obj_iter: *ObjectIterator(source_repo_kind, source_repo_opts, .raw),
    progress_ctx_maybe: ?repo_opts.ProgressCtx,
) !void {
    if (repo_opts.ProgressCtx != void) {
        if (progress_ctx_maybe) |progress_ctx| {
            try progress_ctx.run(.{ .start = .{
                .kind = .writing_object,
                .estimated_total_items = 0,
            } });
        }
    }

    while (try obj_iter.next()) |object| {
        defer object.deinit();

        var oid = [_]u8{0} ** hash.byteLen(repo_opts.hash);
        try writeObject(
            repo_kind,
            repo_opts,
            state,
            &object.object_reader,
            object.object_reader.header(),
            &oid,
        );

        if (repo_opts.ProgressCtx != void) {
            if (progress_ctx_maybe) |progress_ctx| {
                try progress_ctx.run(.{ .complete_one = .writing_object });
            }
        }
    }

    if (repo_opts.ProgressCtx != void) {
        if (progress_ctx_maybe) |progress_ctx| {
            try progress_ctx.run(.{ .end = .writing_object });
        }
    }
}

pub fn copyFromPackObjectIterator(
    comptime repo_kind: rp.RepoKind,
    comptime repo_opts: rp.RepoOpts(repo_kind),
    state: rp.Repo(repo_kind, repo_opts).State(.read_write),
    allocator: std.mem.Allocator,
    pack_iter: *pack.PackObjectIterator(repo_kind, repo_opts),
    progress_ctx_maybe: ?repo_opts.ProgressCtx,
) !void {
    if (repo_opts.ProgressCtx != void) {
        if (progress_ctx_maybe) |progress_ctx| {
            try progress_ctx.run(.{ .start = .{
                .kind = .writing_object_from_pack,
                .estimated_total_items = pack_iter.object_count,
            } });
        }
    }

    while (try pack_iter.next(state.readOnly())) |pack_reader| {
        defer pack_reader.deinit(allocator);

        const Stream = struct {
            reader: *pack.PackObjectReader(repo_kind, repo_opts),
            interface: std.Io.Reader,

            pub fn init(reader: *pack.PackObjectReader(repo_kind, repo_opts), buffer: []u8) @This() {
                return .{
                    .reader = reader,
                    .interface = .{
                        .vtable = &.{ .stream = stream },
                        .buffer = buffer,
                        .seek = 0,
                        .end = 0,
                    },
                };
            }

            pub fn seekTo(self: *@This(), offset: usize) !void {
                if (offset == 0) {
                    try self.reader.reset();
                    self.interface.seek = 0;
                    self.interface.end = 0;
                } else {
                    return error.InvalidOffset;
                }
            }

            fn stream(io_r: *std.Io.Reader, io_w: *std.Io.Writer, limit: std.Io.Limit) std.Io.Reader.StreamError!usize {
                const r: *@This() = @alignCast(@fieldParentPtr("interface", io_r));
                const dest = limit.slice(try io_w.writableSliceGreedy(1));
                const size = r.reader.read(dest) catch return error.ReadFailed;
                if (size == 0) return error.EndOfStream;
                io_w.advance(size);
                return size;
            }
        };

        var reader_buffer = [_]u8{0} ** repo_opts.buffer_size;
        var stream = Stream.init(pack_reader, &reader_buffer);

        var oid = [_]u8{0} ** hash.byteLen(repo_opts.hash);
        const header = pack_reader.header();
        try writeObject(repo_kind, repo_opts, state, &stream, header, &oid);

        if (repo_opts.ProgressCtx != void) {
            if (progress_ctx_maybe) |progress_ctx| {
                try progress_ctx.run(.{ .complete_one = .writing_object_from_pack });
            }
        }
    }

    if (repo_opts.ProgressCtx != void) {
        if (progress_ctx_maybe) |progress_ctx| {
            try progress_ctx.run(.{ .end = .writing_object_from_pack });
        }
    }
}
