//! garbage collection for the xit backend. objects that can't be reached
//! from the roots (HEAD, refs, the index, and in-progress merge heads) are
//! removed, chunks that no live object references are removed, and both
//! database files are compacted, discarding all transaction history.

const std = @import("std");
const rp = @import("./repo.zig");
const hash = @import("./hash.zig");
const obj = @import("./object.zig");
const rf = @import("./ref.zig");
const idx = @import("./index.zig");
const mrg = @import("./merge.zig");
const chunk = @import("./chunk.zig");
const fs = @import("./fs.zig");
const un = @import("./undo.zig");

pub const GcResult = struct {
    db_size_before: u64,
    db_size_after: u64,
    chunk_store_size_before: u64,
    chunk_store_size_after: u64,
};

// while this file exists, a gc swap is in progress (or crashed midway)
const gc_pending_name = "gc-pending";
// the compacted repo db before its chunk store offsets are rewritten
const db_temp_name = "db.gc.temp";
// the new repo db, ready to be renamed over "db"
const db_new_name = "db.gc";
// the new chunk store, ready to be renamed over "chunks"
const chunk_store_new_name = "chunks.gc";

/// completes a gc whose process crashed during the swap. the marker file
/// is created durably only after the new files are fully written and
/// synced, so if it exists, rolling forward is always safe.
pub fn recover(io: std.Io, repo_dir: std.Io.Dir) !void {
    repo_dir.access(io, gc_pending_name, .{}) catch |err| switch (err) {
        error.FileNotFound => return,
        else => |e| return e,
    };

    repo_dir.rename(chunk_store_new_name, repo_dir, "chunks", io) catch |err| switch (err) {
        error.FileNotFound => {},
        else => |e| return e,
    };
    repo_dir.rename(db_new_name, repo_dir, "db", io) catch |err| switch (err) {
        error.FileNotFound => {},
        else => |e| return e,
    };
    try fs.syncDir(io, repo_dir);

    repo_dir.deleteFile(io, gc_pending_name) catch |err| switch (err) {
        error.FileNotFound => {},
        else => |e| return e,
    };
    try fs.syncDir(io, repo_dir);
}

pub fn run(
    comptime repo_opts: rp.RepoOpts(.xit),
    repo: *rp.Repo(.xit, repo_opts),
    io: std.Io,
    allocator: std.mem.Allocator,
) !GcResult {
    const DB = rp.Repo(.xit, repo_opts).DB;
    const repo_dir = repo.core.repo_dir;

    // a shared chunk store contains chunks referenced by other repos,
    // so it must not be gc'd based on this repo's roots alone
    {
        var target_buffer = [_]u8{0} ** std.fs.max_path_bytes;
        if (repo_dir.readLink(io, "chunks", &target_buffer)) |_| {
            return error.SharedChunkStoreNotSupported;
        } else |err| switch (err) {
            error.NotLink => {},
            else => |e| return e,
        }
    }
    // a store shared via hardlink can't be detected with readLink,
    // so also check the link count
    {
        const chunk_store_stat = try repo.core.chunk_store_file.stat(io);
        if (chunk_store_stat.nlink > 1) return error.SharedChunkStoreNotSupported;
    }

    const db_size_before = try repo.core.db_file.length(io);
    const chunk_store_size_before = try repo.core.chunk_store_file.length(io);

    // an empty db has nothing to collect
    _ = repo.core.latestMoment() catch |err| switch (err) {
        error.DatabaseIsEmpty => return .{
            .db_size_before = db_size_before,
            .db_size_after = db_size_before,
            .chunk_store_size_before = chunk_store_size_before,
            .chunk_store_size_after = chunk_store_size_before,
        },
        else => |e| return e,
    };

    // hold both locks for the entire gc, so no other process can write
    // while the new files are being built from the current state.
    var old_files_closed = false;
    try repo.core.db_file.lock(io, .exclusive);
    errdefer if (!old_files_closed) repo.core.db_file.unlock(io);
    try repo.core.chunk_store_file.lock(io, .exclusive);
    errdefer if (!old_files_closed) repo.core.chunk_store_file.unlock(io);

    var moment = try repo.core.latestMoment();
    const state = rp.Repo(.xit, repo_opts).State(.read_only){ .core = &repo.core, .extra = .{ .moment = &moment } };

    // find every object reachable from the roots
    var live_oids = std.AutoHashMap(hash.HashInt(repo_opts.hash), void).init(allocator);
    defer live_oids.deinit();
    try findLiveOids(repo_opts, state, io, allocator, &live_oids);

    // find every chunk record referenced by a live object
    var referenced_offsets = std.AutoHashMap(u64, void).init(allocator);
    defer referenced_offsets.deinit();
    try findReferencedOffsets(repo_opts, state, allocator, &live_oids, &referenced_offsets);

    // remove unreferenced chunks from the store's map. the records stay
    // where they are (the store is append-only); compacting the store
    // below is what actually drops them.
    try pruneChunkStore(repo_opts, &repo.core, allocator, &referenced_offsets);

    // compact the chunk store into a new file, recording where each
    // record moved so the chunk info offsets can be rewritten
    var offset_map = std.AutoHashMap(u64, u64).init(allocator);
    defer offset_map.deinit();

    var adopted = false;

    const new_chunk_store_file = try repo_dir.createFile(io, chunk_store_new_name, .{ .truncate = true, .read = true });
    errdefer if (!adopted) new_chunk_store_file.close(io);

    const new_chunk_store_buffer_ptr = try allocator.create(std.Io.Writer.Allocating);
    errdefer if (!adopted) allocator.destroy(new_chunk_store_buffer_ptr);
    new_chunk_store_buffer_ptr.* = std.Io.Writer.Allocating.init(allocator);
    errdefer if (!adopted) new_chunk_store_buffer_ptr.deinit();

    const new_chunk_store_db = try repo.core.chunk_store_db.compact(.buffered_file, .{
        .io = io,
        .file = new_chunk_store_file,
        .buffer = new_chunk_store_buffer_ptr,
        // same setting as in `Repo.init`. because of it, compact's own
        // sync doesn't fsync, so that is done explicitly below
        .fsync = false,
    }, &offset_map);

    // make the new store durable before anything can reference it
    try new_chunk_store_file.sync(io);

    // compact the repo db to a temp file, dropping its history. its one
    // moment still references the old chunk store offsets and still
    // contains the dead objects, both fixed by the transaction below.
    const db_temp_file = try repo_dir.createFile(io, db_temp_name, .{ .truncate = true, .read = true });
    defer repo_dir.deleteFile(io, db_temp_name) catch {};
    defer db_temp_file.close(io);

    var db_temp_buffer = std.Io.Writer.Allocating.init(allocator);
    defer db_temp_buffer.deinit();

    var db_temp_db = blk: {
        // each compact needs its own empty offset map
        var db_temp_offset_map = std.AutoHashMap(u64, u64).init(allocator);
        defer db_temp_offset_map.deinit();
        break :blk try repo.core.db.compact(.buffered_file, .{
            .io = io,
            .file = db_temp_file,
            .buffer = &db_temp_buffer,
            // no need to fsync the temp db; only the final one matters
            .fsync = false,
        }, &db_temp_offset_map);
    };

    // in a new transaction on the temp db: remove the dead objects,
    // rewrite the chunk store offsets of the live ones, and remove the
    // patch snapshots of dead commits. the stale moment this leaves
    // behind is dropped by the second compact below.
    {
        const old_history = try DB.ArrayList(.read_only).init(db_temp_db.rootCursor().readOnly());
        const old_moment_cursor = (try old_history.getCursor(-1)) orelse return error.DatabaseIsEmpty;
        const old_moment = try DB.HashMap(.read_only).init(old_moment_cursor);

        const Ctx = struct {
            core: *rp.Repo(.xit, repo_opts).Core,
            old_moment: DB.HashMap(.read_only),
            live_oids: *const std.AutoHashMap(hash.HashInt(repo_opts.hash), void),
            offset_map: *const std.AutoHashMap(u64, u64),
            allocator: std.mem.Allocator,

            pub fn run(ctx: @This(), cursor: *DB.Cursor(.read_write)) !void {
                var ctx_moment = try DB.HashMap(.read_write).init(cursor.*);

                // object-id->chunk-info
                if (try ctx.old_moment.getCursor(hash.hashInt(repo_opts.hash, "object-id->chunk-info"))) |old_map_cursor| {
                    const old_map = try DB.HashMap(.read_only).init(old_map_cursor);
                    const new_map_cursor = try ctx_moment.putCursor(hash.hashInt(repo_opts.hash, "object-id->chunk-info"));
                    const new_map = try DB.HashMap(.read_write).init(new_map_cursor);

                    var iter = try old_map.iterator();
                    while (try iter.next()) |*entry_cursor| {
                        var kv_pair = try entry_cursor.readKeyValuePair();
                        if (!ctx.live_oids.contains(kv_pair.hash)) {
                            _ = try new_map.remove(kv_pair.hash);
                            continue;
                        }

                        const chunk_info = try readChunkInfoAlloc(repo_opts, &kv_pair.value_cursor, ctx.allocator);
                        defer ctx.allocator.free(chunk_info);
                        try chunk.rewriteRecordOffsets(chunk_info, ctx.offset_map);
                        try new_map.put(kv_pair.hash, .{ .bytes = chunk_info });
                    }
                }

                // commit-id->snapshot: drop the patch snapshots of dead
                // commits. this is safe because a dead commit's descendants
                // are all dead, and snapshots are only ever looked up for
                // live commits (or seeded from a live commit's parent).
                if (try ctx.old_moment.getCursor(hash.hashInt(repo_opts.hash, "commit-id->snapshot"))) |old_snapshots_cursor| {
                    const old_snapshots = try DB.HashMap(.read_only).init(old_snapshots_cursor);
                    const new_snapshots_cursor = try ctx_moment.putCursor(hash.hashInt(repo_opts.hash, "commit-id->snapshot"));
                    const new_snapshots = try DB.HashMap(.read_write).init(new_snapshots_cursor);

                    var iter = try old_snapshots.iterator();
                    while (try iter.next()) |*entry_cursor| {
                        const kv_pair = try entry_cursor.readKeyValuePair();
                        if (!ctx.live_oids.contains(kv_pair.hash)) {
                            _ = try new_snapshots.remove(kv_pair.hash);
                        }
                    }
                }

                const ctx_state = rp.Repo(.xit, repo_opts).State(.read_write){ .core = ctx.core, .extra = .{ .moment = &ctx_moment } };
                try un.writeMessage(repo_opts, ctx_state, .gc);
            }
        };

        const history = try DB.ArrayList(.read_write).init(db_temp_db.rootCursor());
        try history.appendContext(
            .{ .slot = try history.getSlot(-1) },
            Ctx{
                .core = &repo.core,
                .old_moment = old_moment,
                .live_oids = &live_oids,
                .offset_map = &offset_map,
                .allocator = allocator,
            },
        );
    }

    // compact the temp db into the final new db, dropping the moment
    // with the stale offsets. fsync stays enabled (like the repo db in
    // `Repo.open`), which also makes compact leave the new db durable.
    const new_db_file = try repo_dir.createFile(io, db_new_name, .{ .truncate = true, .read = true });
    errdefer if (!adopted) new_db_file.close(io);

    const new_db_buffer_ptr = try allocator.create(std.Io.Writer.Allocating);
    errdefer if (!adopted) allocator.destroy(new_db_buffer_ptr);
    new_db_buffer_ptr.* = std.Io.Writer.Allocating.init(allocator);
    errdefer if (!adopted) new_db_buffer_ptr.deinit();

    const new_db = blk: {
        var db_offset_map = std.AutoHashMap(u64, u64).init(allocator);
        defer db_offset_map.deinit();
        break :blk try db_temp_db.compact(.buffered_file, .{
            .io = io,
            .file = new_db_file,
            .buffer = new_db_buffer_ptr,
        }, &db_offset_map);
    };

    // make the new files' directory entries durable before creating the
    // marker, so recovery can always complete the swap
    try fs.syncDir(io, repo_dir);

    // the swap. once the marker exists, a crash at any point is rolled
    // forward by `recover`, so error paths from here on complete the
    // swap rather than cleaning up. (stale temp files from failures
    // *before* this point are harmless: the next gc truncates them.)
    errdefer recover(io, repo_dir) catch {};

    {
        const marker_file = try repo_dir.createFile(io, gc_pending_name, .{ .truncate = true });
        marker_file.close(io);
    }
    try fs.syncDir(io, repo_dir);

    try repo_dir.rename(chunk_store_new_name, repo_dir, "chunks", io);
    try repo_dir.rename(db_new_name, repo_dir, "db", io);
    try fs.syncDir(io, repo_dir);

    try repo_dir.deleteFile(io, gc_pending_name);
    try fs.syncDir(io, repo_dir);

    const db_size_after = try new_db_file.length(io);
    const chunk_store_size_after = try new_chunk_store_file.length(io);

    // adopt the new files and dbs. renaming doesn't invalidate the open
    // file handles, so the ones compact wrote through become the repo's.
    // the old handles point at the now-unlinked old files; closing them
    // also releases the locks taken above.
    repo.core.db_file.close(io);
    repo.core.db.core.memory.buffer.deinit();
    allocator.destroy(repo.core.db.core.memory.buffer);
    repo.core.db_file = new_db_file;
    repo.core.db = new_db;

    repo.core.chunk_store_file.close(io);
    repo.core.chunk_store_db.core.memory.buffer.deinit();
    allocator.destroy(repo.core.chunk_store_db.core.memory.buffer);
    repo.core.chunk_store_file = new_chunk_store_file;
    repo.core.chunk_store_db = new_chunk_store_db;

    old_files_closed = true;
    adopted = true;

    // compacting an empty store produces a db with no top-level array
    // list, so eagerly create it like `Repo.init` does (no-op otherwise)
    {
        try repo.core.chunk_store_file.lock(io, .exclusive);
        defer repo.core.chunk_store_file.unlock(io);
        _ = try DB.ArrayList(.read_write).init(repo.core.chunk_store_db.rootCursor());
    }

    return .{
        .db_size_before = db_size_before,
        .db_size_after = db_size_after,
        .chunk_store_size_before = chunk_store_size_before,
        .chunk_store_size_after = chunk_store_size_after,
    };
}

// finds every object reachable from the roots: HEAD, all refs (including
// remote-tracking refs), in-progress merge heads, and blobs staged in the
// index. anything else is garbage.
fn findLiveOids(
    comptime repo_opts: rp.RepoOpts(.xit),
    state: rp.Repo(.xit, repo_opts).State(.read_only),
    io: std.Io,
    allocator: std.mem.Allocator,
    live_oids: *std.AutoHashMap(hash.HashInt(repo_opts.hash), void),
) !void {
    var obj_iter = try obj.ObjectIterator(.xit, repo_opts).init(state, io, allocator, .{ .kind = .all });
    defer obj_iter.deinit();

    // HEAD. this covers a detached HEAD; a symbolic HEAD points at a
    // ref that is included below.
    if (try rf.readHeadRecurMaybe(.xit, repo_opts, state, io)) |head_oid| {
        try obj_iter.include(&head_oid);
    }

    // all refs under the "refs" key: heads, tags, remotes and any other kind
    {
        var ref_iter = try rf.AllRefIterator(.xit, repo_opts).init(state, io, allocator);
        defer ref_iter.deinit(io);
        while (try ref_iter.next(io)) |ref| {
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

// collects the chunk store offset of every record referenced by a live
// object's chunk info
fn findReferencedOffsets(
    comptime repo_opts: rp.RepoOpts(.xit),
    state: rp.Repo(.xit, repo_opts).State(.read_only),
    allocator: std.mem.Allocator,
    live_oids: *const std.AutoHashMap(hash.HashInt(repo_opts.hash), void),
    referenced_offsets: *std.AutoHashMap(u64, void),
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
        try chunk.collectRecordOffsets(chunk_info, referenced_offsets);
    }
}

// removes every chunk that no live object references from the store's
// map, in a single store transaction
fn pruneChunkStore(
    comptime repo_opts: rp.RepoOpts(.xit),
    core: *rp.Repo(.xit, repo_opts).Core,
    allocator: std.mem.Allocator,
    referenced_offsets: *const std.AutoHashMap(u64, void),
) !void {
    const DB = rp.Repo(.xit, repo_opts).DB;

    // find the chunks to remove
    var dead_chunks: std.ArrayList(hash.HashInt(repo_opts.hash)) = .empty;
    defer dead_chunks.deinit(allocator);
    {
        const history = try DB.ArrayList(.read_only).init(core.chunk_store_db.rootCursor().readOnly());
        // a store with no moments has no chunks to prune
        const moment_cursor = (try history.getCursor(-1)) orelse return;
        const chunk_map = try DB.HashMap(.read_only).init(moment_cursor);

        var iter = try chunk_map.iterator();
        while (try iter.next()) |*entry_cursor| {
            const kv_pair = try entry_cursor.readKeyValuePair();
            const record_offset = try chunk.chunkRecordOffset(kv_pair.value_cursor);
            if (!referenced_offsets.contains(record_offset)) {
                try dead_chunks.append(allocator, kv_pair.hash);
            }
        }
    }

    if (dead_chunks.items.len == 0) return;

    const Ctx = struct {
        dead_chunks: []const hash.HashInt(repo_opts.hash),

        pub fn run(ctx: @This(), cursor: *DB.Cursor(.read_write)) !void {
            const chunk_map = try DB.HashMap(.read_write).init(cursor.*);
            for (ctx.dead_chunks) |chunk_hash| {
                _ = try chunk_map.remove(chunk_hash);
            }
        }
    };

    // note: no lock is taken here, because `run` holds it for the
    // entire gc
    const store_history = try DB.ArrayList(.read_write).init(core.chunk_store_db.rootCursor());
    try store_history.appendContext(
        .{ .slot = try store_history.getSlot(-1) },
        Ctx{ .dead_chunks = dead_chunks.items },
    );
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
