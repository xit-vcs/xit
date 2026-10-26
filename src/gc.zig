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
    return @import("xitdb").Database(.buffered_file, hash.HashInt(repo_opts.hash));
}

// an error from the reporter, such as a cancellation, stops the collection
fn report(comptime repo_opts: rp.RepoOpts(.xit), io: std.Io, progress_ctx_maybe: ?repo_opts.ProgressCtx, event: rp.ProgressEvent) !void {
    if (repo_opts.ProgressCtx == void) return;
    const progress_ctx = progress_ctx_maybe orelse return;
    try progress_ctx.run(io, event);
}

// store offsets as u64 keys in a hash map in a separate xitdb database.
// compaction puts every record it copies at the end of the new database, so
// each record's offset there is how many bytes have been copied.
fn DiskOffsets(comptime repo_opts: rp.RepoOpts(.xit)) type {
    return struct {
        const DB = @import("xitdb").Database(.buffered_file, u64);

        io: std.Io,
        map: DB.HashMap(.read_write),
        progress_ctx_maybe: ?repo_opts.ProgressCtx,
        copied: u64 = 0,
        reported: u64 = 0,

        // bytes copied between reports
        const report_every = 1024 * 1024;

        pub fn reset(self: *@This()) !void {
            var cursor = self.map.cursor;
            try cursor.write(.{ .slot = null });
            self.map = try DB.HashMap(.read_write).init(cursor);
        }

        pub fn get(self: *@This(), source_offset: u64) !?u64 {
            const cursor = (try self.map.getCursor(source_offset)) orelse return null;
            return try cursor.readUint();
        }

        pub fn put(self: *@This(), source_offset: u64, target_offset: u64) !void {
            try self.map.put(source_offset, .{ .uint = target_offset });
            self.copied = @max(self.copied, target_offset);
            if (self.copied - self.reported < report_every) return;
            self.reported = self.copied;
            try report(repo_opts, self.io, self.progress_ctx_maybe, .{ .complete_total = .{ .kind = .compacting_database, .count = @intCast(self.copied) } });
        }
    };
}

// keeps only the entries of an oid-keyed map whose key is in `live_oids`
fn pruneOidMap(
    comptime repo_opts: rp.RepoOpts(.xit),
    state: rp.Repo(.xit, repo_opts).State(.read_write),
    io: std.Io,
    live_oids: SetsDb(repo_opts).HashSet(.read_write),
    map_name: []const u8,
    progress_ctx_maybe: ?repo_opts.ProgressCtx,
) !void {
    const DB = rp.Repo(.xit, repo_opts).DB;
    const map_key = hash.hashInt(repo_opts.hash, map_name);
    const old_cursor = (try state.extra.moment.getCursor(map_key)) orelse return;
    const old_map = try DB.CountedHashMap(.read_only).init(old_cursor);
    const new_map = try DB.CountedHashMap(.read_write).init(try state.extra.moment.putCursor(map_key));

    var iter = try old_map.iterator();
    while (try iter.next()) |*entry_cursor| {
        const kv_pair = try entry_cursor.readKeyValuePair();
        if (try live_oids.getSlot(kv_pair.hash) == null) {
            _ = try new_map.remove(kv_pair.hash);
        }
        try report(repo_opts, io, progress_ctx_maybe, .{ .complete_one = .pruning_database });
    }
}

// collects the patch each file of a live commit's snapshot names, returning
// how many there are. a snapshot only ever gains edits by applying the patch
// it then names, and a live commit's ancestors are live, so the live patches'
// edit lists hold every live edit and the edit sets needn't be walked.
fn findLivePatches(
    comptime repo_opts: rp.RepoOpts(.xit),
    state: rp.Repo(.xit, repo_opts).State(.read_only),
    io: std.Io,
    allocator: std.mem.Allocator,
    sets: SetsDb(repo_opts).HashMap(.read_write),
    live_oids: SetsDb(repo_opts).HashSet(.read_write),
    patches: SetsDb(repo_opts).HashSet(.read_write),
    progress_ctx_maybe: ?repo_opts.ProgressCtx,
) !u64 {
    const patch = @import("./patch.zig");
    const xitdb = @import("xitdb");
    const SlotInt = @typeInfo(xitdb.Slot).@"struct".backing_integer.?;
    const slot_size = @bitSizeOf(SlotInt) / 8;
    const DB = rp.Repo(.xit, repo_opts).DB;
    const visited = try SetsDb(repo_opts).HashSet(.read_write).init(try sets.putCursor(hash.hashInt(repo_opts.hash, "visited-positions")));
    // popped last-in first-out, so it holds at most one node's children per level of the trie
    var pending: std.ArrayList(DB.Cursor(.read_only)) = .empty;
    defer pending.deinit(allocator);
    var count: u64 = 0;

    // the first live snapshot reads its commit's whole file trie, and how big
    // that is isn't known up front, so it's counted by node in a phase of its
    // own. every later snapshot is one step of a percentage, and one step only
    // reads what earlier snapshots didn't share.
    const snapshots = try state.extra.moment.getCursor(hash.hashInt(repo_opts.hash, "commit-id->snapshot")) orelse return 0;
    const snapshot_count = try (try DB.CountedHashMap(.read_only).init(snapshots)).count();
    try report(repo_opts, io, progress_ctx_maybe, .{ .start = .{ .kind = .preparing_patch_walk, .estimated_total_items = 0 } });
    var walked_first = false;
    // the snapshots handled before the percentage starts, which it begins from
    var before_first: u64 = 0;

    // snapshots share trie nodes, so skip nodes we've already visited instead
    // of scanning every file at every commit. this runs before the snapshots
    // are pruned, so a dead commit's snapshot is skipped here.
    {
        var snapshot_iter = try snapshots.iterator();
        while (try snapshot_iter.next()) |snapshot| {
            // a dead commit's snapshot counts as one too, so the total is the map's count
            if (walked_first) {
                try report(repo_opts, io, progress_ctx_maybe, .{ .complete_one = .walking_patch });
            } else {
                before_first += 1;
            }
            const snapshot_pair = try snapshot.readKeyValuePair();
            if (try live_oids.getSlot(snapshot_pair.hash) == null) continue;
            try pending.append(allocator, snapshot_pair.value_cursor);
            while (pending.pop()) |cursor| {
                if (!walked_first) try report(repo_opts, io, progress_ctx_maybe, .{ .complete_one = .preparing_patch_walk });
                const slot = try cursor.slot();
                if (slot.tag == .none) continue;
                if (try visited.getSlot(slot.value) != null) continue;
                try visited.put(slot.value, .{ .uint = 1 });
                switch (slot.tag) {
                    .kv_pair => {
                        const kv_pair = try cursor.readKeyValuePair();
                        const fields = try DB.ArrayList(.read_only).init(kv_pair.value_cursor);
                        const patch_cursor = try fields.getCursor(@backingInt(patch.FileField.patch)) orelse continue;
                        if ((try patch_cursor.slot()).tag == .none) continue;
                        var id: [hash.byteLen(repo_opts.hash)]u8 = undefined;
                        _ = try patch_cursor.readBytes(&id);
                        const patch_id = hash.bytesToInt(repo_opts.hash, &id);
                        if (try patches.getSlot(patch_id) != null) continue;
                        try patches.put(patch_id, .{ .uint = 1 });
                        count += 1;
                    },
                    .hash_map, .index => {
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
                                .db = cursor.db,
                                .slot_ptr = .{ .position = slot.value + i * slot_size, .slot = child },
                            });
                        }
                    },
                    else => return error.UnexpectedTag,
                }
            }
            if (!walked_first) {
                walked_first = true;
                try report(repo_opts, io, progress_ctx_maybe, .{ .end = .preparing_patch_walk });
                try report(repo_opts, io, progress_ctx_maybe, .{ .start = .{ .kind = .walking_patch, .estimated_total_items = @intCast(snapshot_count) } });
                try report(repo_opts, io, progress_ctx_maybe, .{ .complete_total = .{ .kind = .walking_patch, .count = @intCast(before_first) } });
            }
        }
    }
    try report(repo_opts, io, progress_ctx_maybe, .{ .end = if (walked_first) .walking_patch else .preparing_patch_walk });
    return count;
}

// collects the edits the live patches list
fn findLiveEdits(
    comptime repo_opts: rp.RepoOpts(.xit),
    state: rp.Repo(.xit, repo_opts).State(.read_only),
    io: std.Io,
    patches: SetsDb(repo_opts).HashSet(.read_write),
    edits: SetsDb(repo_opts).HashSet(.read_write),
    progress_ctx_maybe: ?repo_opts.ProgressCtx,
) !void {
    const DB = rp.Repo(.xit, repo_opts).DB;
    const Id = hash.HashInt(repo_opts.hash);
    const lists_cursor = try state.extra.moment.getCursor(hash.hashInt(repo_opts.hash, "patch-id->edit-list"));
    const lists = if (lists_cursor) |cursor| try DB.CountedHashMap(.read_only).init(cursor) else null;

    var iter = try patches.iterator();
    while (try iter.next()) |*entry_cursor| {
        try report(repo_opts, io, progress_ctx_maybe, .{ .complete_one = .pruning_database });
        const patch_id = (try entry_cursor.readKeyValuePair()).hash;
        var list_cursor = (if (lists) |map| try map.getCursor(patch_id) else null) orelse continue;
        var buffer: [repo_opts.buffer_size]u8 = undefined;
        var reader = try list_cursor.reader(&buffer);
        while (reader.logicalPos() < reader.size) try edits.put(try reader.interface.takeInt(Id, .big), .{ .uint = 1 });
    }
}

// the new repo db, ready to be renamed over "db"
const db_new_name = "db.gc";
const offsets_name = "temp.gc-offsets";
const sets_name = "temp.gc-sets";

// removes dead objects, snapshots, patch data, and chunks from the moment being written.
// their records still take up space until compactDatabase runs afterwards.
pub fn prune(
    comptime repo_opts: rp.RepoOpts(.xit),
    state: rp.Repo(.xit, repo_opts).State(.read_write),
    io: std.Io,
    allocator: std.mem.Allocator,
    extra_roots: []const [hash.hexLen(repo_opts.hash)]u8,
    progress_ctx_maybe: ?repo_opts.ProgressCtx,
) !void {
    // the scratch database for the live sets. the transaction holds the
    // lock, so no other gc can be using the file.
    const sets_file = try state.core.repo_dir.createFile(io, sets_name, .{ .truncate = true, .read = true });
    defer {
        sets_file.close(io);
        state.core.repo_dir.deleteFile(io, sets_name) catch {};
    }
    var sets_buffer = std.Io.Writer.Allocating.init(allocator);
    defer sets_buffer.deinit();
    var sets_db = try SetsDb(repo_opts).init(io, .{ .file = sets_file, .buffer = &sets_buffer, .fsync = false });

    // the sets are written in one transaction, so their writes aren't each committed
    const Ctx = struct {
        state: rp.Repo(.xit, repo_opts).State(.read_write),
        io: std.Io,
        allocator: std.mem.Allocator,
        extra_roots: []const [hash.hexLen(repo_opts.hash)]u8,
        progress_ctx_maybe: ?repo_opts.ProgressCtx,

        pub fn run(ctx: @This(), cursor: *SetsDb(repo_opts).Cursor(.read_write)) !void {
            try pruneWithSets(repo_opts, ctx.state, ctx.io, ctx.allocator, ctx.extra_roots, cursor.*, ctx.progress_ctx_maybe);
        }
    };
    try sets_db.runContext(Ctx{
        .state = state,
        .io = io,
        .allocator = allocator,
        .extra_roots = extra_roots,
        .progress_ctx_maybe = progress_ctx_maybe,
    });
}

fn pruneWithSets(
    comptime repo_opts: rp.RepoOpts(.xit),
    state: rp.Repo(.xit, repo_opts).State(.read_write),
    io: std.Io,
    allocator: std.mem.Allocator,
    extra_roots: []const [hash.hexLen(repo_opts.hash)]u8,
    sets_cursor: SetsDb(repo_opts).Cursor(.read_write),
    progress_ctx_maybe: ?repo_opts.ProgressCtx,
) !void {
    const patch = @import("./patch.zig");
    const DB = rp.Repo(.xit, repo_opts).DB;

    const sets = try SetsDb(repo_opts).HashMap(.read_write).init(sets_cursor);

    // find every object reachable from the roots. like every gc phase, its
    // total isn't known until it is done.
    const live_oids = try SetsDb(repo_opts).HashSet(.read_write).init(try sets.putCursor(hash.hashInt(repo_opts.hash, "live-oids")));
    try report(repo_opts, io, progress_ctx_maybe, .{ .start = .{ .kind = .enumerating_object, .estimated_total_items = 0 } });
    try findLiveOids(repo_opts, state.readOnly(), io, allocator, extra_roots, live_oids, progress_ctx_maybe);
    try report(repo_opts, io, progress_ctx_maybe, .{ .end = .enumerating_object });

    // find every patch a live commit's snapshot names
    const patches = try SetsDb(repo_opts).HashSet(.read_write).init(try sets.putCursor(hash.hashInt(repo_opts.hash, "live-patches")));
    const live_patch_count = try findLivePatches(repo_opts, state.readOnly(), io, allocator, sets, live_oids, patches, progress_ctx_maybe);

    // each live patch's edit list is read once, and each map below is walked
    // once as it is pruned, so these counts make the phase's exact total
    var total: u64 = live_patch_count;
    for ([_]struct { []const u8, u64 }{
        .{ "object-id->content", 1 },
        .{ "commit-id->snapshot", 1 },
        .{ patch.COMMIT_ID_TO_STATS_KEY, 1 },
        .{ "patch-id->edit-list", 1 },
        .{ "edit-id->edit", 1 },
        .{ "chunk-hash->record", 1 },
    }) |map| {
        const cursor = try state.extra.moment.getCursor(hash.hashInt(repo_opts.hash, map[0])) orelse continue;
        const counted = try DB.CountedHashMap(.read_only).init(cursor);
        total += map[1] * try counted.count();
    }
    try report(repo_opts, io, progress_ctx_maybe, .{ .start = .{ .kind = .pruning_database, .estimated_total_items = @intCast(total) } });

    const edits = try SetsDb(repo_opts).HashSet(.read_write).init(try sets.putCursor(hash.hashInt(repo_opts.hash, "live-edits")));
    try findLiveEdits(repo_opts, state.readOnly(), io, patches, edits, progress_ctx_maybe);

    // each map is iterated through a cursor taken before it is written to,
    // because entries can't be removed while the map is being iterated.
    // writing copies the map, so the cursor keeps seeing every entry.

    const referenced_positions = try SetsDb(repo_opts).HashSet(.read_write).init(try sets.putCursor(hash.hashInt(repo_opts.hash, "referenced-positions")));
    try pruneObjects(repo_opts, state, io, live_oids, referenced_positions, progress_ctx_maybe);
    try pruneOidMap(repo_opts, state, io, patches, "patch-id->edit-list", progress_ctx_maybe);
    try pruneOidMap(repo_opts, state, io, edits, "edit-id->edit", progress_ctx_maybe);

    // a dead commit's descendants are dead, and snapshots are only
    // loaded for live commits or seeded from a live commit's parent.
    try pruneOidMap(repo_opts, state, io, live_oids, "commit-id->snapshot", progress_ctx_maybe);
    try pruneOidMap(repo_opts, state, io, live_oids, patch.COMMIT_ID_TO_STATS_KEY, progress_ctx_maybe);

    if (try state.extra.moment.getCursor(hash.hashInt(repo_opts.hash, "chunk-hash->record"))) |old_chunk_map_cursor| {
        const old_chunk_map = try DB.CountedHashMap(.read_only).init(old_chunk_map_cursor);
        const new_chunk_map_cursor = try state.extra.moment.putCursor(hash.hashInt(repo_opts.hash, "chunk-hash->record"));
        const new_chunk_map = try DB.CountedHashMap(.read_write).init(new_chunk_map_cursor);

        var iter = try old_chunk_map.iterator();
        while (try iter.next()) |*entry_cursor| {
            const kv_pair = try entry_cursor.readKeyValuePair();
            const record_position = try chunk.chunkRecordPosition(kv_pair.value_cursor);
            if (try referenced_positions.getSlot(record_position) == null) {
                _ = try new_chunk_map.remove(kv_pair.hash);
            }
            try report(repo_opts, io, progress_ctx_maybe, .{ .complete_one = .pruning_database });
        }
    }

    try report(repo_opts, io, progress_ctx_maybe, .{ .end = .pruning_database });
}

// replaces the repo's database with a copy of its latest moment, reclaiming
// everything the prune above removed along with all transaction history.
// the caller must still hold the exclusive lock the prune ran under.
pub fn compactDatabase(
    comptime repo_opts: rp.RepoOpts(.xit),
    repo: *rp.Repo(.xit, repo_opts),
    io: std.Io,
    allocator: std.mem.Allocator,
    progress_ctx_maybe: ?repo_opts.ProgressCtx,
) !u64 {
    const repo_dir = repo.core.repo_dir;

    const offsets_file = try repo_dir.createFile(io, offsets_name, .{ .truncate = true, .read = true });
    defer {
        offsets_file.close(io);
        repo_dir.deleteFile(io, offsets_name) catch {};
    }
    var offsets_buffer = std.Io.Writer.Allocating.init(allocator);
    defer offsets_buffer.deinit();
    var offsets_db = try DiskOffsets(repo_opts).DB.init(io, .{ .file = offsets_file, .buffer = &offsets_buffer, .fsync = false });

    var adopted = false;
    const new_db_file = try repo_dir.createFile(io, db_new_name, .{ .truncate = true, .read = true });
    // a cancelled or failed compaction leaves no partial copy behind
    errdefer if (!adopted) {
        new_db_file.close(io);
        repo_dir.deleteFile(io, db_new_name) catch {};
    };

    // the new file is locked from birth, so the repo's db file is still
    // locked after it takes the place of the old one below.
    try new_db_file.lock(io, .exclusive);

    const new_db_buffer = try allocator.create(std.Io.Writer.Allocating);
    errdefer if (!adopted) allocator.destroy(new_db_buffer);
    new_db_buffer.* = std.Io.Writer.Allocating.init(allocator);
    errdefer if (!adopted) new_db_buffer.deinit();

    // progress is bytes copied. only live records are copied, so the copy
    // can't outgrow the database it copies, which bounds it.
    try report(repo_opts, io, progress_ctx_maybe, .{ .start = .{ .kind = .compacting_database, .estimated_total_items = @intCast(try repo.core.db_file.length(io)) } });
    // compact inside one transaction on the offsets database, so the
    // offsets aren't each committed separately
    var new_db: rp.Repo(.xit, repo_opts).DB = undefined;
    const Ctx = struct {
        repo: *rp.Repo(.xit, repo_opts),
        io: std.Io,
        new_db_file: std.Io.File,
        new_db_buffer: *std.Io.Writer.Allocating,
        new_db: *rp.Repo(.xit, repo_opts).DB,
        progress_ctx_maybe: ?repo_opts.ProgressCtx,

        pub fn run(ctx: @This(), cursor: *DiskOffsets(repo_opts).DB.Cursor(.read_write)) !void {
            var offset_map = DiskOffsets(repo_opts){
                .io = ctx.io,
                .map = try DiskOffsets(repo_opts).DB.HashMap(.read_write).init(cursor.*),
                .progress_ctx_maybe = ctx.progress_ctx_maybe,
            };
            ctx.new_db.* = try ctx.repo.core.db.compact(.buffered_file, .{
                .file = ctx.new_db_file,
                .buffer = ctx.new_db_buffer,
                .fsync = false,
            }, &offset_map);
        }
    };
    try offsets_db.runContext(Ctx{
        .repo = repo,
        .io = io,
        .new_db_file = new_db_file,
        .new_db_buffer = new_db_buffer,
        .new_db = &new_db,
        .progress_ctx_maybe = progress_ctx_maybe,
    });

    // objects point at their chunk records through slots, so compaction has already moved them
    try new_db_file.sync(io);

    const size_after = try new_db_file.length(io);
    try report(repo_opts, io, progress_ctx_maybe, .{ .complete_total = .{ .kind = .compacting_database, .count = @intCast(size_after) } });
    try report(repo_opts, io, progress_ctx_maybe, .{ .end = .compacting_database });

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
    progress_ctx_maybe: ?repo_opts.ProgressCtx,
) !void {
    // objects whose content hasn't been read yet. an object is marked live
    // when it is queued, so nothing is queued twice, and the queue is popped
    // last-in first-out, so a commit's tree is finished before its parent is
    // read. that keeps the queue to the pending parents of merge commits
    // plus one tree's entries per level of the tree being read.
    var pending: std.ArrayList([hash.hexLen(repo_opts.hash)]u8) = .empty;
    defer pending.deinit(allocator);

    for (extra_roots) |*oid| try includeLiveOid(repo_opts, allocator, live_oids, &pending, oid, true);

    // HEAD. this covers a detached HEAD; a symbolic HEAD points at a
    // ref that is included below.
    if (try rf.readHeadRecurMaybe(.xit, repo_opts, state, io)) |head_oid| {
        try includeLiveOid(repo_opts, allocator, live_oids, &pending, &head_oid, true);
    }

    // all refs under the "refs" key: heads, tags, remotes and any other kind
    {
        var ref_iter = try rf.AllRefIterator(.xit, repo_opts).init(state, allocator);
        defer ref_iter.deinit();
        while (try ref_iter.next()) |ref| {
            if (try rf.readRecur(.xit, repo_opts, state, io, .{ .ref = ref })) |oid| {
                try includeLiveOid(repo_opts, allocator, live_oids, &pending, &oid, true);
            }
        }
    }

    // in-progress merge state (MERGE_HEAD, CHERRY_PICK_HEAD). any new
    // unqualified ref that contains an oid must be added here, because
    // unlike the refs above, they can't be enumerated.
    if (try mrg.readAnyMergeHead(.xit, repo_opts, state, io)) |merge_oid| {
        try includeLiveOid(repo_opts, allocator, live_oids, &pending, &merge_oid, true);
    }

    // blobs staged in the index
    {
        var index = try idx.Index(.xit, repo_opts).init(state, io, allocator);
        defer index.deinit();
        for (index.entries.values()) |*entries_for_path| {
            for (entries_for_path) |entry_maybe| {
                if (entry_maybe) |entry| {
                    const entry_oid = std.fmt.bytesToHex(entry.oid, .lower);
                    try includeLiveOid(repo_opts, allocator, live_oids, &pending, &entry_oid, false);
                }
            }
        }
    }

    // walk the object graph
    while (pending.pop()) |oid| {
        var object = try obj.Object(.xit, repo_opts).init(state, io, allocator, &oid);
        defer object.deinit();
        try report(repo_opts, io, progress_ctx_maybe, .{ .complete_one = .enumerating_object });
        switch (object.content) {
            .blob => {},
            .tree => |tree| for (tree.entries.values()) |entry| {
                const entry_oid = std.fmt.bytesToHex(entry.oid, .lower);
                switch (entry.mode.content.object_type) {
                    .tree => try includeLiveOid(repo_opts, allocator, live_oids, &pending, &entry_oid, true),
                    .regular_file, .symbolic_link => try includeLiveOid(repo_opts, allocator, live_oids, &pending, &entry_oid, false),
                    .gitlink => {},
                }
            },
            .commit => |commit| {
                if (commit.metadata.parent_oids) |parent_oids| {
                    for (parent_oids) |*parent_oid| try includeLiveOid(repo_opts, allocator, live_oids, &pending, parent_oid, true);
                }
                try includeLiveOid(repo_opts, allocator, live_oids, &pending, &commit.tree, true);
            },
            .tag => |tag| try includeLiveOid(repo_opts, allocator, live_oids, &pending, &tag.target, true),
        }
    }
}

// marks an object live, unless it already is, and queues it to be read when
// `walk` is set. a blob has nothing to walk, so it is only marked.
fn includeLiveOid(
    comptime repo_opts: rp.RepoOpts(.xit),
    allocator: std.mem.Allocator,
    live_oids: SetsDb(repo_opts).HashSet(.read_write),
    pending: *std.ArrayList([hash.hexLen(repo_opts.hash)]u8),
    oid: *const [hash.hexLen(repo_opts.hash)]u8,
    walk: bool,
) !void {
    const oid_int = try hash.hexToInt(repo_opts.hash, oid);
    if (try live_oids.getSlot(oid_int) != null) return;
    try live_oids.put(oid_int, .{ .uint = 1 });
    if (walk) try pending.append(allocator, oid.*);
}

// removes dead objects, and collects the position of every chunk record a
// live one points at, in one pass over the object map
fn pruneObjects(
    comptime repo_opts: rp.RepoOpts(.xit),
    state: rp.Repo(.xit, repo_opts).State(.read_write),
    io: std.Io,
    live_oids: SetsDb(repo_opts).HashSet(.read_write),
    referenced_positions: SetsDb(repo_opts).HashSet(.read_write),
    progress_ctx_maybe: ?repo_opts.ProgressCtx,
) !void {
    const DB = rp.Repo(.xit, repo_opts).DB;
    const map_key = hash.hashInt(repo_opts.hash, "object-id->content");
    const old_cursor = (try state.extra.moment.getCursor(map_key)) orelse return;
    const old_map = try DB.CountedHashMap(.read_only).init(old_cursor);
    const new_map = try DB.CountedHashMap(.read_write).init(try state.extra.moment.putCursor(map_key));

    var iter = try old_map.iterator();
    while (try iter.next()) |*entry_cursor| {
        const kv_pair = try entry_cursor.readKeyValuePair();
        try report(repo_opts, io, progress_ctx_maybe, .{ .complete_one = .pruning_database });
        if (try live_oids.getSlot(kv_pair.hash) == null) {
            _ = try new_map.remove(kv_pair.hash);
            continue;
        }
        // only a chunked object points at records, through the slots after its first element
        if ((try kv_pair.value_cursor.slot()).tag != .array_list) continue;
        const list = try DB.ArrayList(.read_only).init(kv_pair.value_cursor);
        var records = try list.iteratorFrom(1);
        while (try records.next()) |record_cursor| try referenced_positions.put(try chunk.chunkRecordPosition(record_cursor), .{ .uint = 1 });
    }
}
