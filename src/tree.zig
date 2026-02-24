const std = @import("std");
const hash = @import("./hash.zig");
const rf = @import("./ref.zig");
const fs = @import("./fs.zig");
const rp = @import("./repo.zig");
const obj = @import("./object.zig");

pub fn TreeEntry(comptime hash_kind: hash.HashKind) type {
    return struct {
        oid: [hash.byteLen(hash_kind)]u8,
        mode: fs.Mode,

        pub fn eql(self: TreeEntry(hash_kind), other: TreeEntry(hash_kind)) bool {
            return std.mem.eql(u8, &self.oid, &other.oid) and self.mode.eqlExact(other.mode);
        }

        pub fn isTree(self: TreeEntry(hash_kind)) bool {
            return self.mode.content.object_type == .tree;
        }
    };
}

pub fn Change(comptime hash_kind: hash.HashKind) type {
    return struct {
        old: ?TreeEntry(hash_kind),
        new: ?TreeEntry(hash_kind),
    };
}

pub fn TreeDiff(comptime repo_kind: rp.RepoKind, comptime repo_opts: rp.RepoOpts(repo_kind)) type {
    return struct {
        changes: std.StringArrayHashMap(Change(repo_opts.hash)),
        arena: std.heap.ArenaAllocator,

        pub fn init(allocator: std.mem.Allocator) TreeDiff(repo_kind, repo_opts) {
            return .{
                .changes = std.StringArrayHashMap(Change(repo_opts.hash)).init(allocator),
                .arena = std.heap.ArenaAllocator.init(allocator),
            };
        }

        pub fn deinit(self: *TreeDiff(repo_kind, repo_opts)) void {
            self.changes.deinit();
            self.arena.deinit();
        }

        pub fn compare(
            self: *TreeDiff(repo_kind, repo_opts),
            state: rp.Repo(repo_kind, repo_opts).State(.read_only),
            old_oid_maybe: ?*const [hash.hexLen(repo_opts.hash)]u8,
            new_oid_maybe: ?*const [hash.hexLen(repo_opts.hash)]u8,
            path_list_maybe: ?*std.ArrayList([]const u8),
        ) !void {
            if (old_oid_maybe == null and new_oid_maybe == null) {
                return;
            }
            const old_entries = try self.loadTree(state, old_oid_maybe);
            const new_entries = try self.loadTree(state, new_oid_maybe);
            // deletions and edits
            {
                var iter = old_entries.iterator();
                while (iter.next()) |old_entry| {
                    const old_key = old_entry.key_ptr.*;
                    const old_value = old_entry.value_ptr.*;
                    var path_list = if (path_list_maybe) |path_list| try path_list.clone(self.arena.allocator()) else std.ArrayList([]const u8){};
                    try path_list.append(self.arena.allocator(), old_key);
                    const path = try fs.joinPath(self.arena.allocator(), path_list.items);
                    if (new_entries.get(old_key)) |new_value| {
                        if (!old_value.eql(new_value)) {
                            const old_value_tree = old_value.isTree();
                            const new_value_tree = new_value.isTree();
                            try self.compare(state, if (old_value_tree) &std.fmt.bytesToHex(&old_value.oid, .lower) else null, if (new_value_tree) &std.fmt.bytesToHex(&new_value.oid, .lower) else null, &path_list);
                            if (!old_value_tree or !new_value_tree) {
                                try self.changes.put(path, Change(repo_opts.hash){ .old = if (old_value_tree) null else old_value, .new = if (new_value_tree) null else new_value });
                            }
                        }
                    } else {
                        if (old_value.isTree()) {
                            try self.compare(state, &std.fmt.bytesToHex(&old_value.oid, .lower), null, &path_list);
                        } else {
                            try self.changes.put(path, Change(repo_opts.hash){ .old = old_value, .new = null });
                        }
                    }
                }
            }
            // additions
            {
                var iter = new_entries.iterator();
                while (iter.next()) |new_entry| {
                    const new_key = new_entry.key_ptr.*;
                    const new_value = new_entry.value_ptr.*;
                    var path_list = if (path_list_maybe) |path_list| try path_list.clone(self.arena.allocator()) else std.ArrayList([]const u8){};
                    try path_list.append(self.arena.allocator(), new_key);
                    const path = try fs.joinPath(self.arena.allocator(), path_list.items);
                    if (old_entries.get(new_key)) |_| {
                        continue;
                    } else if (new_value.isTree()) {
                        try self.compare(state, null, &std.fmt.bytesToHex(&new_value.oid, .lower), &path_list);
                    } else {
                        try self.changes.put(path, Change(repo_opts.hash){ .old = null, .new = new_value });
                    }
                }
            }
        }

        fn loadTree(
            self: *TreeDiff(repo_kind, repo_opts),
            state: rp.Repo(repo_kind, repo_opts).State(.read_only),
            oid_maybe: ?*const [hash.hexLen(repo_opts.hash)]u8,
        ) !std.StringArrayHashMap(TreeEntry(repo_opts.hash)) {
            if (oid_maybe) |oid| {
                const object = try obj.Object(repo_kind, repo_opts, .full).init(self.arena.allocator(), state, oid);
                return switch (object.content) {
                    .blob, .tag => std.StringArrayHashMap(TreeEntry(repo_opts.hash)).init(self.arena.allocator()),
                    .tree => |tree| tree.entries,
                    .commit => |commit| self.loadTree(state, &commit.tree),
                };
            } else {
                return std.StringArrayHashMap(TreeEntry(repo_opts.hash)).init(self.arena.allocator());
            }
        }
    };
}

fn pathToTreeEntry(
    comptime repo_kind: rp.RepoKind,
    comptime repo_opts: rp.RepoOpts(repo_kind),
    state: rp.Repo(repo_kind, repo_opts).State(.read_only),
    allocator: std.mem.Allocator,
    parent: obj.Object(repo_kind, repo_opts, .full),
    path_parts: []const []const u8,
) !?TreeEntry(repo_opts.hash) {
    const path_part = path_parts[0];
    const tree_entry = parent.content.tree.entries.get(path_part) orelse return null;

    if (path_parts.len == 1) {
        return tree_entry;
    }

    const oid_hex = std.fmt.bytesToHex(tree_entry.oid, .lower);
    var tree_object = try obj.Object(repo_kind, repo_opts, .full).init(allocator, state, &oid_hex);
    defer tree_object.deinit();

    switch (tree_object.content) {
        .blob, .tag => return null,
        .tree => return pathToTreeEntry(repo_kind, repo_opts, state, allocator, tree_object, path_parts[1..]),
        .commit => return error.ObjectInvalid,
    }
}

pub fn headTreeEntry(
    comptime repo_kind: rp.RepoKind,
    comptime repo_opts: rp.RepoOpts(repo_kind),
    state: rp.Repo(repo_kind, repo_opts).State(.read_only),
    allocator: std.mem.Allocator,
    path_parts: []const []const u8,
) !?TreeEntry(repo_opts.hash) {
    // get the current commit
    const current_oid = try rf.readHeadRecur(repo_kind, repo_opts, state);
    var commit_object = try obj.Object(repo_kind, repo_opts, .full).init(allocator, state, &current_oid);
    defer commit_object.deinit();

    // get the tree of the current commit
    var tree_object = try obj.Object(repo_kind, repo_opts, .full).init(allocator, state, &commit_object.content.commit.tree);
    defer tree_object.deinit();

    // get the entry for the given path
    return try pathToTreeEntry(repo_kind, repo_opts, state, allocator, tree_object, path_parts);
}

pub fn Tree(comptime repo_kind: rp.RepoKind, comptime repo_opts: rp.RepoOpts(repo_kind)) type {
    return struct {
        entries: std.StringArrayHashMap(TreeEntry(repo_opts.hash)),
        arena: *std.heap.ArenaAllocator,
        allocator: std.mem.Allocator,

        pub fn init(
            allocator: std.mem.Allocator,
            state: rp.Repo(repo_kind, repo_opts).State(.read_only),
            oid_maybe: ?*const [hash.hexLen(repo_opts.hash)]u8,
        ) !Tree(repo_kind, repo_opts) {
            const arena = try allocator.create(std.heap.ArenaAllocator);
            arena.* = std.heap.ArenaAllocator.init(allocator);
            var tree = Tree(repo_kind, repo_opts){
                .entries = std.StringArrayHashMap(TreeEntry(repo_opts.hash)).init(allocator),
                .arena = arena,
                .allocator = allocator,
            };
            errdefer tree.deinit();

            const oid = oid_maybe orelse &(try rf.readHeadRecurMaybe(repo_kind, repo_opts, state) orelse return tree);

            var commit_object = try obj.Object(repo_kind, repo_opts, .full).initCommit(allocator, state, oid);
            defer commit_object.deinit();
            try tree.read(state, "", &commit_object.content.commit.tree);

            return tree;
        }

        pub fn deinit(self: *Tree(repo_kind, repo_opts)) void {
            self.entries.deinit();
            self.arena.deinit();
            self.allocator.destroy(self.arena);
        }

        fn read(self: *Tree(repo_kind, repo_opts), state: rp.Repo(repo_kind, repo_opts).State(.read_only), prefix: []const u8, oid: *const [hash.hexLen(repo_opts.hash)]u8) !void {
            var object = try obj.Object(repo_kind, repo_opts, .full).init(self.allocator, state, oid);
            defer object.deinit();

            switch (object.content) {
                .blob, .commit, .tag => {},
                .tree => |tree| {
                    for (tree.entries.keys(), tree.entries.values()) |name, tree_entry| {
                        const path = try fs.joinPath(self.arena.allocator(), &.{ prefix, name });
                        if (tree_entry.isTree()) {
                            const oid_hex = std.fmt.bytesToHex(tree_entry.oid, .lower);
                            try self.read(state, path, &oid_hex);
                        } else {
                            try self.entries.put(path, tree_entry);
                        }
                    }
                },
            }
        }
    };
}
