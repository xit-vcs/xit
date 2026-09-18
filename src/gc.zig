//! garbage collection for the xit backend. objects that can't be reached
//! from the supplied roots, HEAD, refs, the index, or in-progress merge heads
//! are removed, chunks that no live object references are removed, and the
//! database is compacted, discarding all transaction history.

const std = @import("std");
const rp = @import("./repo.zig");
const hash = @import("./hash.zig");
const obj = @import("./object.zig");
const rf = @import("./ref.zig");
const idx = @import("./index.zig");
const mrg = @import("./merge.zig");
const chunk = @import("./chunk.zig");
const fs = @import("./fs.zig");

pub fn GarbageCollectOptions(comptime hash_kind: hash.HashKind) type {
    return struct {
        extra_roots: []const [hash.hexLen(hash_kind)]u8 = &.{},
    };
}

pub const GcResult = struct {
    size_before: u64,
    size_after: u64,
};

// the sets of live things found while pruning grow with the repository, so
// they are kept in a scratch database rather than on the heap. a plain file
// is used because each write outside a transaction is flushed anyway.
fn SetsDb(comptime repo_opts: rp.RepoOpts(.xit)) type {
    return @import("xitdb").Database(.file, hash.HashInt(repo_opts.hash));
}

// store offsets as u64 keys in a separate, mutable top-level xitdb hash map
const DiskOffsets = struct {
    const DB = @import("xitdb").Database(.file, u64);

    io: std.Io,
    file: std.Io.File,
    db: DB = undefined, // initialized by compact's call to reset

    pub fn reset(self: *@This()) !void {
        try self.file.setLength(self.io, 0);
        self.db = try DB.init(.{ .io = self.io, .file = self.file, .fsync = false });
    }

    pub fn get(self: *@This(), source_offset: u64) !?u64 {
        const map = try DB.HashMap(.read_only).init(self.db.rootCursor().readOnly());
        const cursor = (try map.getCursor(source_offset)) orelse return null;
        return try cursor.readUint();
    }

    pub fn put(self: *@This(), source_offset: u64, target_offset: u64) !void {
        const map = try DB.HashMap(.read_write).init(self.db.rootCursor());
        try map.put(source_offset, .{ .uint = target_offset });
    }
};

// keeps only the entries of an oid-keyed map whose key is in `live_oids`
fn pruneOidMap(
    comptime repo_opts: rp.RepoOpts(.xit),
    state: rp.Repo(.xit, repo_opts).State(.read_write),
    live_oids: SetsDb(repo_opts).HashSet(.read_write),
    map_name: []const u8,
) !void {
    const DB = rp.Repo(.xit, repo_opts).DB;
    const map_key = hash.hashInt(repo_opts.hash, map_name);
    const old_cursor = (try state.extra.moment.getCursor(map_key)) orelse return;
    const old_map = try DB.HashMap(.read_only).init(old_cursor);
    const new_map = try DB.HashMap(.read_write).init(try state.extra.moment.putCursor(map_key));

    var iter = try old_map.iterator();
    while (try iter.next()) |*entry_cursor| {
        const kv_pair = try entry_cursor.readKeyValuePair();
        if (try live_oids.getSlot(kv_pair.hash) == null) {
            _ = try new_map.remove(kv_pair.hash);
        }
    }
}

fn prunePatchData(
    comptime repo_opts: rp.RepoOpts(.xit),
    state: rp.Repo(.xit, repo_opts).State(.read_write),
    allocator: std.mem.Allocator,
    sets: SetsDb(repo_opts).HashMap(.read_write),
) !void {
    const patch = @import("./patch.zig");
    const xitdb = @import("xitdb");
    const SlotInt = @typeInfo(xitdb.Slot).@"struct".backing_integer.?;
    const slot_size = @bitSizeOf(SlotInt) / 8;
    const DB = rp.Repo(.xit, repo_opts).DB;
    const visited = try SetsDb(repo_opts).HashSet(.read_write).init(try sets.putCursor(hash.hashInt(repo_opts.hash, "visited-positions")));
    const patches = try SetsDb(repo_opts).HashSet(.read_write).init(try sets.putCursor(hash.hashInt(repo_opts.hash, "live-patches")));
    const edits = try SetsDb(repo_opts).HashSet(.read_write).init(try sets.putCursor(hash.hashInt(repo_opts.hash, "live-edits")));
    // popped last-in first-out, so it holds at most one node's children per level of the trie
    var pending: std.ArrayList(struct { cursor: DB.Cursor(.read_only), kind: enum { files, edits } }) = .empty;
    defer pending.deinit(allocator);

    // walk file maps and applied-edit sets with one worklist. snapshots share
    // trie nodes, so skip nodes we've already visited instead of scanning
    // each file's entire edit history at every commit.
    if (try state.extra.moment.getCursor(hash.hashInt(repo_opts.hash, "commit-id->snapshot"))) |snapshots| {
        var snapshot_iter = try snapshots.iterator();
        while (try snapshot_iter.next()) |snapshot| {
            try pending.append(allocator, .{ .cursor = (try snapshot.readKeyValuePair()).value_cursor, .kind = .files });
            while (pending.pop()) |entry| {
                const cursor = entry.cursor;
                const slot = cursor.slot();
                if (slot.tag == .none) continue;
                if (try visited.getSlot(slot.value) != null) continue;
                try visited.put(slot.value, .{ .uint = 1 });
                switch (slot.tag) {
                    .kv_pair => {
                        const kv_pair = try cursor.readKeyValuePair();
                        if (entry.kind == .edits) {
                            try edits.put(kv_pair.hash, .{ .uint = 1 });
                            continue;
                        }
                        const fields = try DB.ArrayList(.read_only).init(kv_pair.value_cursor);
                        if (try fields.getCursor(@intFromEnum(patch.FileField.patch))) |patch_cursor| {
                            if (patch_cursor.slot().tag != .none) {
                                var id: [hash.byteLen(repo_opts.hash)]u8 = undefined;
                                _ = try patch_cursor.readBytes(&id);
                                try patches.put(hash.bytesToInt(repo_opts.hash, &id), .{ .uint = 1 });
                            }
                        }
                        if (try fields.getCursor(@intFromEnum(patch.FileField.edits))) |edit_cursor| {
                            try pending.append(allocator, .{ .cursor = edit_cursor, .kind = .edits });
                        }
                    },
                    .hash_map, .hash_set, .index => {
                        var reader = cursor.db.core.reader();
                        try reader.seekTo(slot.value);
                        var bytes: [xitdb.SLOT_COUNT * slot_size]u8 = undefined;
                        try reader.interface.readSliceAll(&bytes);
                        var slots = std.Io.Reader.fixed(&bytes);
                        for (0..xitdb.SLOT_COUNT) |i| {
                            const child: xitdb.Slot = @bitCast(try slots.takeInt(SlotInt, .big));
                            try child.tag.validate();
                            if (child.empty()) continue;
                            try pending.append(allocator, .{
                                .cursor = .{
                                    .db = cursor.db,
                                    .slot_ptr = .{ .position = slot.value + i * slot_size, .slot = child },
                                },
                                .kind = entry.kind,
                            });
                        }
                    },
                    else => return error.UnexpectedTag,
                }
            }
        }
    }

    try pruneOidMap(repo_opts, state, patches, "patch-id->edit-list");
    try pruneOidMap(repo_opts, state, edits, "edit-id->edit");
}

// the new repo db, ready to be renamed over "db"
const db_new_name = "db.gc";
const offsets_name = "db.gc.offsets";
const sets_name = "db.gc.sets";

// removes dead objects, snapshots, patch data, and chunks from the moment being written.
// their records still take up space until compactDatabase runs afterwards.
pub fn prune(
    comptime repo_opts: rp.RepoOpts(.xit),
    state: rp.Repo(.xit, repo_opts).State(.read_write),
    io: std.Io,
    allocator: std.mem.Allocator,
    extra_roots: []const [hash.hexLen(repo_opts.hash)]u8,
) !void {
    const patch = @import("./patch.zig");
    const DB = rp.Repo(.xit, repo_opts).DB;

    // the scratch database for the live sets. the transaction holds the
    // lock, so no other gc can be using the file.
    const sets_file = try state.core.repo_dir.createFile(io, sets_name, .{ .truncate = true, .read = true });
    defer {
        sets_file.close(io);
        state.core.repo_dir.deleteFile(io, sets_name) catch {};
    }
    var sets_db = try SetsDb(repo_opts).init(.{ .io = io, .file = sets_file, .fsync = false });
    const sets = try SetsDb(repo_opts).HashMap(.read_write).init(sets_db.rootCursor());

    // find every object reachable from the roots
    const live_oids = try SetsDb(repo_opts).HashSet(.read_write).init(try sets.putCursor(hash.hashInt(repo_opts.hash, "live-oids")));
    try findLiveOids(repo_opts, state.readOnly(), io, allocator, extra_roots, live_oids);

    // find every chunk record referenced by a live object
    const referenced_positions = try SetsDb(repo_opts).HashSet(.read_write).init(try sets.putCursor(hash.hashInt(repo_opts.hash, "referenced-positions")));
    try findReferencedPositions(repo_opts, state.readOnly(), live_oids, referenced_positions);

    // each map is iterated through a cursor taken before it is written to,
    // because entries can't be removed while the map is being iterated.
    // writing copies the map, so the cursor keeps seeing every entry.

    try pruneOidMap(repo_opts, state, live_oids, "object-id->content");

    // a dead commit's descendants are dead, and snapshots are only
    // loaded for live commits or seeded from a live commit's parent.
    try pruneOidMap(repo_opts, state, live_oids, "commit-id->snapshot");
    try pruneOidMap(repo_opts, state, live_oids, patch.COMMIT_ID_TO_STATS_KEY);
    try pruneOidMap(repo_opts, state, live_oids, obj.COMMIT_ID_TO_FIRST_PARENT_DEPTH_KEY);
    try prunePatchData(repo_opts, state, allocator, sets);

    if (try state.extra.moment.getCursor(hash.hashInt(repo_opts.hash, "chunk-hash->record"))) |old_chunk_map_cursor| {
        const old_chunk_map = try DB.HashMap(.read_only).init(old_chunk_map_cursor);
        const new_chunk_map_cursor = try state.extra.moment.putCursor(hash.hashInt(repo_opts.hash, "chunk-hash->record"));
        const new_chunk_map = try DB.HashMap(.read_write).init(new_chunk_map_cursor);

        var iter = try old_chunk_map.iterator();
        while (try iter.next()) |*entry_cursor| {
            const kv_pair = try entry_cursor.readKeyValuePair();
            const record_position = try chunk.chunkRecordPosition(kv_pair.value_cursor);
            if (try referenced_positions.getSlot(record_position) == null) {
                _ = try new_chunk_map.remove(kv_pair.hash);
            }
        }
    }
}

// replaces the repo's database with a copy of its latest moment, reclaiming
// everything the prune above removed along with all transaction history.
// the caller must still hold the exclusive lock the prune ran under.
pub fn compactDatabase(
    comptime repo_opts: rp.RepoOpts(.xit),
    repo: *rp.Repo(.xit, repo_opts),
    io: std.Io,
    allocator: std.mem.Allocator,
) !u64 {
    const repo_dir = repo.core.repo_dir;

    const offsets_file = try repo_dir.createFile(io, offsets_name, .{ .truncate = true, .read = true });
    defer {
        offsets_file.close(io);
        repo_dir.deleteFile(io, offsets_name) catch {};
    }
    var offset_map = DiskOffsets{ .io = io, .file = offsets_file };

    var adopted = false;
    const new_db_file = try repo_dir.createFile(io, db_new_name, .{ .truncate = true, .read = true });
    errdefer if (!adopted) new_db_file.close(io);

    // the new file is locked from birth, so the repo's db file is still
    // locked after it takes the place of the old one below.
    try new_db_file.lock(io, .exclusive);

    const new_db_buffer = try allocator.create(std.Io.Writer.Allocating);
    errdefer if (!adopted) allocator.destroy(new_db_buffer);
    new_db_buffer.* = std.Io.Writer.Allocating.init(allocator);
    errdefer if (!adopted) new_db_buffer.deinit();

    const new_db = try repo.core.db.compact(.buffered_file, .{
        .io = io,
        .file = new_db_file,
        .buffer = new_db_buffer,
        .fsync = false,
    }, &offset_map);

    // objects point at their chunk records through slots, so compaction has already moved them
    try new_db_file.sync(io);

    const size_after = try new_db_file.length(io);

    // replacing one file is atomic, so a crash leaves either the old valid
    // database or the new valid database. a stale db.gc is simply overwritten.
    try repo_dir.rename(db_new_name, repo_dir, "db", io);

    // adopt the new file and db. renaming doesn't invalidate the open file
    // handles, so the one compact wrote through becomes the repo's. the old
    // handle points at the now-unlinked old file; closing it also releases
    // the lock taken on it. nothing here can fail, so an error can never
    // leave the repo reading the old file after the new one went live.
    repo.core.db_file.close(io);
    repo.core.db.core.memory.buffer.deinit();
    allocator.destroy(repo.core.db.core.memory.buffer);
    repo.core.db_file = new_db_file;
    repo.core.db = new_db;
    adopted = true;

    try fs.syncDir(io, repo_dir);

    return size_after;
}

// finds every object reachable from the supplied roots, HEAD, all refs,
// in-progress merge heads, and blobs staged in the index. this doesn't use
// ObjectIterator, whose visited set is a heap map with every object in it.
fn findLiveOids(
    comptime repo_opts: rp.RepoOpts(.xit),
    state: rp.Repo(.xit, repo_opts).State(.read_only),
    io: std.Io,
    allocator: std.mem.Allocator,
    extra_roots: []const [hash.hexLen(repo_opts.hash)]u8,
    live_oids: SetsDb(repo_opts).HashSet(.read_write),
) !void {
    // objects whose content hasn't been read yet. an object is marked live
    // when it is queued, so nothing is queued twice, and the queue is popped
    // last-in first-out, so a commit's tree is finished before its parent is
    // read. that keeps the queue to the pending parents of merge commits
    // plus one tree's entries per level of the tree being read.
    var pending: std.ArrayList([hash.hexLen(repo_opts.hash)]u8) = .empty;
    defer pending.deinit(allocator);

    for (extra_roots) |*oid| try includeLiveOid(repo_opts, allocator, live_oids, &pending, oid);

    // HEAD. this covers a detached HEAD; a symbolic HEAD points at a
    // ref that is included below.
    if (try rf.readHeadRecurMaybe(.xit, repo_opts, state, io)) |head_oid| {
        try includeLiveOid(repo_opts, allocator, live_oids, &pending, &head_oid);
    }

    // all refs under the "refs" key: heads, tags, remotes and any other kind
    {
        var ref_iter = try rf.AllRefIterator(.xit, repo_opts).init(state, allocator);
        defer ref_iter.deinit();
        while (try ref_iter.next()) |ref| {
            if (try rf.readRecur(.xit, repo_opts, state, io, .{ .ref = ref })) |oid| {
                try includeLiveOid(repo_opts, allocator, live_oids, &pending, &oid);
            }
        }
    }

    // in-progress merge state (MERGE_HEAD, CHERRY_PICK_HEAD). any new
    // unqualified ref that contains an oid must be added here, because
    // unlike the refs above, they can't be enumerated.
    if (try mrg.readAnyMergeHead(.xit, repo_opts, state, io)) |merge_oid| {
        try includeLiveOid(repo_opts, allocator, live_oids, &pending, &merge_oid);
    }

    // blobs staged in the index
    {
        var index = try idx.Index(.xit, repo_opts).init(state, io, allocator);
        defer index.deinit();
        for (index.entries.values()) |*entries_for_path| {
            for (entries_for_path) |entry_maybe| {
                if (entry_maybe) |entry| {
                    const entry_oid = std.fmt.bytesToHex(entry.oid, .lower);
                    try includeLiveOid(repo_opts, allocator, live_oids, &pending, &entry_oid);
                }
            }
        }
    }

    // walk the object graph
    while (pending.pop()) |oid| {
        var object = try obj.Object(.xit, repo_opts).init(state, io, allocator, &oid);
        defer object.deinit();
        switch (object.content) {
            .blob => {},
            .tree => |tree| for (tree.entries.values()) |entry| {
                if (entry.mode.content.object_type == .gitlink) continue;
                const entry_oid = std.fmt.bytesToHex(entry.oid, .lower);
                try includeLiveOid(repo_opts, allocator, live_oids, &pending, &entry_oid);
            },
            .commit => |commit| {
                if (commit.metadata.parent_oids) |parent_oids| {
                    for (parent_oids) |*parent_oid| try includeLiveOid(repo_opts, allocator, live_oids, &pending, parent_oid);
                }
                try includeLiveOid(repo_opts, allocator, live_oids, &pending, &commit.tree);
            },
            .tag => |tag| try includeLiveOid(repo_opts, allocator, live_oids, &pending, &tag.target),
        }
    }
}

// marks an object live and queues it to be read, unless it already is
fn includeLiveOid(
    comptime repo_opts: rp.RepoOpts(.xit),
    allocator: std.mem.Allocator,
    live_oids: SetsDb(repo_opts).HashSet(.read_write),
    pending: *std.ArrayList([hash.hexLen(repo_opts.hash)]u8),
    oid: *const [hash.hexLen(repo_opts.hash)]u8,
) !void {
    const oid_int = try hash.hexToInt(repo_opts.hash, oid);
    if (try live_oids.getSlot(oid_int) != null) return;
    try live_oids.put(oid_int, .{ .uint = 1 });
    try pending.append(allocator, oid.*);
}

// collects the position of every chunk record a live object points at
fn findReferencedPositions(
    comptime repo_opts: rp.RepoOpts(.xit),
    state: rp.Repo(.xit, repo_opts).State(.read_only),
    live_oids: SetsDb(repo_opts).HashSet(.read_write),
    referenced_positions: SetsDb(repo_opts).HashSet(.read_write),
) !void {
    const DB = rp.Repo(.xit, repo_opts).DB;

    const map_cursor = (try state.extra.moment.getCursor(hash.hashInt(repo_opts.hash, "object-id->content"))) orelse return;
    const map = try DB.HashMap(.read_only).init(map_cursor);

    var iter = try map.iterator();
    while (try iter.next()) |*entry_cursor| {
        const kv_pair = try entry_cursor.readKeyValuePair();
        if (try live_oids.getSlot(kv_pair.hash) == null) continue;
        // only a chunked object points at records, through the slots after its first element
        if (kv_pair.value_cursor.slot().tag != .array_list) continue;
        const list = try DB.ArrayList(.read_only).init(kv_pair.value_cursor);
        var records = try list.iteratorFrom(1);
        while (try records.next()) |record_cursor| try referenced_positions.put(try chunk.chunkRecordPosition(record_cursor), .{ .uint = 1 });
    }
}
