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

pub const GcResult = struct {
    size_before: u64,
    size_after: u64,
};

// the new repo db, ready to be renamed over "db"
const db_new_name = "db.gc";

// removes dead objects, snapshots, and chunks from the moment being written.
// their records still take up space until compactDatabase runs afterwards.
pub fn prune(
    comptime repo_opts: rp.RepoOpts(.xit),
    state: rp.Repo(.xit, repo_opts).State(.read_write),
    io: std.Io,
    allocator: std.mem.Allocator,
    extra_roots: []const [hash.hexLen(repo_opts.hash)]u8,
) !void {
    const DB = rp.Repo(.xit, repo_opts).DB;

    // find every object reachable from the roots
    var live_oids = std.AutoHashMap(hash.HashInt(repo_opts.hash), void).init(allocator);
    defer live_oids.deinit();
    try findLiveOids(repo_opts, state.readOnly(), io, allocator, extra_roots, &live_oids);

    // find every chunk record referenced by a live object
    var referenced_positions = std.AutoHashMap(u64, void).init(allocator);
    defer referenced_positions.deinit();
    try findReferencedPositions(repo_opts, state.readOnly(), allocator, &live_oids, &referenced_positions);

    // each map is iterated through a cursor taken before it is written to,
    // because entries can't be removed while the map is being iterated.
    // writing copies the map, so the cursor keeps seeing every entry.

    if (try state.extra.moment.getCursor(hash.hashInt(repo_opts.hash, "object-id->chunk-info"))) |old_map_cursor| {
        const old_map = try DB.HashMap(.read_only).init(old_map_cursor);
        const new_map_cursor = try state.extra.moment.putCursor(hash.hashInt(repo_opts.hash, "object-id->chunk-info"));
        const new_map = try DB.HashMap(.read_write).init(new_map_cursor);

        var iter = try old_map.iterator();
        while (try iter.next()) |*entry_cursor| {
            const kv_pair = try entry_cursor.readKeyValuePair();
            if (!live_oids.contains(kv_pair.hash)) {
                _ = try new_map.remove(kv_pair.hash);
            }
        }
    }

    // a dead commit's descendants are dead, and snapshots are only
    // loaded for live commits or seeded from a live commit's parent.
    if (try state.extra.moment.getCursor(hash.hashInt(repo_opts.hash, "commit-id->snapshot"))) |old_snapshots_cursor| {
        const old_snapshots = try DB.HashMap(.read_only).init(old_snapshots_cursor);
        const new_snapshots_cursor = try state.extra.moment.putCursor(hash.hashInt(repo_opts.hash, "commit-id->snapshot"));
        const new_snapshots = try DB.HashMap(.read_write).init(new_snapshots_cursor);

        var iter = try old_snapshots.iterator();
        while (try iter.next()) |*entry_cursor| {
            const kv_pair = try entry_cursor.readKeyValuePair();
            if (!live_oids.contains(kv_pair.hash)) {
                _ = try new_snapshots.remove(kv_pair.hash);
            }
        }
    }

    if (try state.extra.moment.getCursor(hash.hashInt(repo_opts.hash, "chunk-hash->record"))) |old_chunk_map_cursor| {
        const old_chunk_map = try DB.HashMap(.read_only).init(old_chunk_map_cursor);
        const new_chunk_map_cursor = try state.extra.moment.putCursor(hash.hashInt(repo_opts.hash, "chunk-hash->record"));
        const new_chunk_map = try DB.HashMap(.read_write).init(new_chunk_map_cursor);

        var iter = try old_chunk_map.iterator();
        while (try iter.next()) |*entry_cursor| {
            const kv_pair = try entry_cursor.readKeyValuePair();
            const record_position = try chunk.chunkRecordPosition(kv_pair.value_cursor);
            if (!referenced_positions.contains(record_position)) {
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

    var offset_map = std.AutoHashMap(u64, u64).init(allocator);
    defer offset_map.deinit();

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

    // chunk info holds the position of each chunk record, which compaction
    // has just moved, so patch them in the unpublished database.
    const moment = try repo.core.latestMoment();
    try patchChunkInfoPositions(repo_opts, moment, io, allocator, new_db_file, &offset_map);
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
// in-progress merge heads, and blobs staged in the index
fn findLiveOids(
    comptime repo_opts: rp.RepoOpts(.xit),
    state: rp.Repo(.xit, repo_opts).State(.read_only),
    io: std.Io,
    allocator: std.mem.Allocator,
    extra_roots: []const [hash.hexLen(repo_opts.hash)]u8,
    live_oids: *std.AutoHashMap(hash.HashInt(repo_opts.hash), void),
) !void {
    var obj_iter = try obj.ObjectIterator(.xit, repo_opts).init(state, io, allocator, .{ .kind = .all });
    defer obj_iter.deinit();

    for (extra_roots) |*oid| try obj_iter.include(oid);

    // HEAD. this covers a detached HEAD; a symbolic HEAD points at a
    // ref that is included below.
    if (try rf.readHeadRecurMaybe(.xit, repo_opts, state, io)) |head_oid| {
        try obj_iter.include(&head_oid);
    }

    // all refs under the "refs" key: heads, tags, remotes and any other kind
    {
        var ref_iter = try rf.AllRefIterator(.xit, repo_opts).init(state, allocator);
        defer ref_iter.deinit();
        while (try ref_iter.next()) |ref| {
            if (try rf.readRecur(.xit, repo_opts, state, io, .{ .ref = ref })) |oid| {
                try obj_iter.include(&oid);
            }
        }
    }

    // in-progress merge state (MERGE_HEAD, CHERRY_PICK_HEAD). any new
    // unqualified ref that contains an oid must be added here, because
    // unlike the refs above, they can't be enumerated.
    if (try mrg.readAnyMergeHead(.xit, repo_opts, state, io)) |merge_oid| {
        try obj_iter.include(&merge_oid);
    }

    // blobs staged in the index
    {
        var index = try idx.Index(.xit, repo_opts).init(state, io, allocator);
        defer index.deinit();
        for (index.entries.values()) |*entries_for_path| {
            for (entries_for_path) |entry_maybe| {
                if (entry_maybe) |entry| {
                    const entry_oid = std.fmt.bytesToHex(entry.oid, .lower);
                    try obj_iter.include(&entry_oid);
                }
            }
        }
    }

    // walk the object graph
    while (try obj_iter.next(allocator)) |object| {
        defer object.deinit();
        try live_oids.put(try hash.hexToInt(repo_opts.hash, &object.oid), {});
    }
}

// collects every chunk record position referenced by a live object's chunk info
fn findReferencedPositions(
    comptime repo_opts: rp.RepoOpts(.xit),
    state: rp.Repo(.xit, repo_opts).State(.read_only),
    allocator: std.mem.Allocator,
    live_oids: *const std.AutoHashMap(hash.HashInt(repo_opts.hash), void),
    referenced_positions: *std.AutoHashMap(u64, void),
) !void {
    const DB = rp.Repo(.xit, repo_opts).DB;

    const map_cursor = (try state.extra.moment.getCursor(hash.hashInt(repo_opts.hash, "object-id->chunk-info"))) orelse return;
    const map = try DB.HashMap(.read_only).init(map_cursor);

    var iter = try map.iterator();
    while (try iter.next()) |*entry_cursor| {
        var kv_pair = try entry_cursor.readKeyValuePair();
        if (!live_oids.contains(kv_pair.hash)) continue;

        const chunk_info = try readChunkInfoAlloc(repo_opts, &kv_pair.value_cursor, allocator);
        defer allocator.free(chunk_info);
        try chunk.collectRecordPositions(chunk_info, referenced_positions);
    }
}

// patch opaque chunk-record positions in the unpublished database. the
// compaction map both locates each chunk-info byte array in the target and
// relocates the record positions stored inside it.
fn patchChunkInfoPositions(
    comptime repo_opts: rp.RepoOpts(.xit),
    source_moment: rp.Repo(.xit, repo_opts).DB.HashMap(.read_only),
    io: std.Io,
    allocator: std.mem.Allocator,
    target_file: std.Io.File,
    compaction_map: *const std.AutoHashMap(u64, u64),
) !void {
    const DB = rp.Repo(.xit, repo_opts).DB;
    const map_cursor = (try source_moment.getCursor(hash.hashInt(repo_opts.hash, "object-id->chunk-info"))) orelse return;
    const object_map = try DB.HashMap(.read_only).init(map_cursor);

    var write_buffer: [repo_opts.buffer_size]u8 = undefined;
    var writer = target_file.writer(io, &write_buffer);

    var iter = try object_map.iterator();
    while (try iter.next()) |*entry_cursor| {
        var kv_pair = try entry_cursor.readKeyValuePair();
        const source_position = kv_pair.value_cursor.slot().value;
        const target_position = compaction_map.get(source_position) orelse return error.ChunkInfoNotFound;

        const chunk_info = try readChunkInfoAlloc(repo_opts, &kv_pair.value_cursor, allocator);
        defer allocator.free(chunk_info);
        try chunk.rewriteRecordPositions(chunk_info, compaction_map);

        try writer.seekTo(target_position + @sizeOf(u64));
        try writer.interface.writeAll(chunk_info);
    }
    try writer.interface.flush();
}

// reads an object's chunk info into memory
fn readChunkInfoAlloc(
    comptime repo_opts: rp.RepoOpts(.xit),
    cursor: *rp.Repo(.xit, repo_opts).DB.Cursor(.read_only),
    allocator: std.mem.Allocator,
) ![]u8 {
    var read_buffer: [repo_opts.buffer_size]u8 = undefined;
    var reader = try cursor.reader(&read_buffer);
    const chunk_info = try allocator.alloc(u8, @intCast(reader.size));
    errdefer allocator.free(chunk_info);
    try reader.interface.readSliceAll(chunk_info);
    return chunk_info;
}
