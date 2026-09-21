//! the implementation of patch-based version control, inspired by pijul.
//! patch data lives in .xit/db, in maps within each database moment.
//!
//! commit-id->snapshot maps each commit to a path map, initially shared with
//! its first parent and copied on write. path strings are stored as readable
//! keys. each file's value is an array of four database slots (FileField):
//! - patch: the last patch created for the file, inherited if unchanged;
//! - edits: the set of all applied edit ids;
//! - lines: a persistent sequence of blobs holding the file's lines in order.
//!   each entry is a gap, as a u32 count and the ids of the deletions that made
//!   its neighbors adjacent, then the id of the line after it. a line id is an
//!   edit id followed by the u32 index of a line inserted by that edit, starting
//!   at zero. the last entry is the gap at the end of the file, with no line.
//!   stable positions choose blob boundaries (about 16 entries per blob, at
//!   most 64), so a commit rewrites only the blobs it touches and snapshots
//!   share the rest, along with unchanged tree nodes.
//! - oid: the blob the lines describe. a binary commit keeps the last text
//!   state, so its oid differs from the commit's blob.
//! commit-id->stats stores nine u64s: first-parent depth, lines added/changed/removed,
//! bytes added/removed, then files added/changed/removed. paired removals and
//! insertions within each edit count only as changed lines. bytes sum per-file
//! growth/shrinkage and exclude submodules. file counts include binary and
//! mode-only changes; line counts exclude binary changes and the final empty entry.
//!
//! patch-id->edit-list stores ordered edit ids, without a count. the patch id
//! hashes those ids. edit-id->edit stores each edit once, in this order:
//! - a u32 removal count and the removed line ids in order;
//! - only for pure insertions, the gap: the length-prefixed positions of the
//!   surviving neighbors (an empty start is the file start; an end length of
//!   0xffffffff is the file end), then a counted list of dependency ids: the
//!   neighbors' edits and the deletions that made them adjacent;
//! - a u32 inserted-line count;
//! - a hash of the inserted lines, each as a u32 byte length and its text
//!   without '\n';
//! - only for replacements, the placement: a length-prefixed prefix, then the
//!   u64 bounds its ordinals lie strictly between.
//! integers are big endian. the edit id hashes the record excluding placement.
//! paths, commits, and unrelated edits aren't part of it. the text itself isn't
//! stored: line i of a snapshot is line i of the blob named by its oid field.
//!
//! positions are sequences of (u64 ordinal, edit id) pairs, compared as bytes.
//! lines under the same prefix are siblings ordered by ordinal, then by id. an
//! edit's lines get ordinals strictly between its neighbors' ordinals at the
//! shallowest level with room, padding with zero pairs when the left neighbor
//! is shorter. appends and prepends step by a fixed stride so room lasts;
//! other insertions divide the interval. only an exhausted interval nests.
//! a one-line replacement keeps the removed line's position; several lines
//! replacing one nest under it; otherwise replacements span the interval
//! between the first and last removed lines, so an edit's lines always lie
//! within its conflict range and rewriting a block barely narrows it.
//! positions are derived from stored bounds alone, so concurrent insertions
//! into the same gap collide and are detected.
//!
//! how patches are created: compare changed files with their first parent using
//! myers, recording edits, statistics, and gap dependencies. apply the edits and save
//! the snapshot, sharing unchanged gap chunks.
//!
//! how patches are applied: load the snapshot and collect edits from the chosen
//! patches, skipping those already applied. verify their dependencies and removed
//! line ids, apply removals and insertions, then sort the remaining lines by
//! position. when merging, compare the new edits with those the base lacks to
//! find conflict regions. return the updated file and newly applied edit ids
//! for saving or writing the merged text.

const std = @import("std");
const rp = @import("./repo.zig");
const hash = @import("./hash.zig");
const df = @import("./diff.zig");
const obj = @import("./object.zig");
const tr = @import("./tree.zig");

pub fn writeAndApplyPatches(
    comptime repo_opts: rp.RepoOpts(.xit),
    state: rp.Repo(.xit, repo_opts).State(.read_write),
    io: std.Io,
    allocator: std.mem.Allocator,
    commit_oid: *const [hash.hexLen(repo_opts.hash)]u8,
) !void {
    const DB = rp.Repo(.xit, repo_opts).DB;
    const Id = hash.HashInt(repo_opts.hash);
    const parent_commit_oid_maybe = blk: {
        var commit_object = try obj.Object(.xit, repo_opts).init(state.readOnly(), io, allocator, commit_oid);
        defer commit_object.deinit();

        if (commit_object.content.commit.metadata.firstParent()) |oid| {
            break :blk oid.*;
        } else {
            break :blk null;
        }
    };

    // init snapshot
    const commit_id_to_snapshot_cursor = try state.extra.moment.putCursor(hash.hashInt(repo_opts.hash, "commit-id->snapshot"));
    const commit_id_to_snapshot = try DB.HashMap(.read_write).init(commit_id_to_snapshot_cursor);
    const commit_id_int = try hash.hexToInt(repo_opts.hash, commit_oid);
    if (try commit_id_to_snapshot.getCursor(commit_id_int)) |_| {
        return; // exit early if patches have already been created for this commit
    }
    var snapshot_cursor = try commit_id_to_snapshot.putCursor(commit_id_int);

    var stats: CommitStats = .{ .first_parent_depth = 1 };
    // if there is a parent commit, inherit its snapshot and increment its depth
    if (parent_commit_oid_maybe) |*parent_commit_oid| {
        if (try commit_id_to_snapshot.getCursor(try hash.hexToInt(repo_opts.hash, parent_commit_oid))) |parent_snapshot_cursor| {
            try snapshot_cursor.write(.{ .slot = parent_snapshot_cursor.slot() });
        } else {
            return error.ParentCommitSnapshotNotFound;
        }
        const parent_stats = (try readCommitStats(repo_opts, state.readOnly().extra.moment, parent_commit_oid)) orelse return error.CommitStatsNotFound;
        stats.first_parent_depth = std.math.add(u64, parent_stats.first_parent_depth, 1) catch return error.CommitDepthOverflow;
    }

    const snapshot = try DB.HashMap(.read_write).init(snapshot_cursor);

    // init file iterator
    var tree_diff = tr.TreeDiff(.xit, repo_opts).init(allocator);
    defer tree_diff.deinit();
    try tree_diff.compare(
        state.readOnly(),
        io,
        if (parent_commit_oid_maybe) |parent_commit_oid| &parent_commit_oid else null,
        commit_oid,
        null,
    );
    var file_iter = try df.FileIterator(.xit, repo_opts).init(
        state.readOnly(),
        io,
        allocator,
        .{ .tree = .{ .tree_diff = &tree_diff } },
    );

    // iterate over each modified file and create/apply the patch
    while (try file_iter.next()) |*line_iter_pair_ptr| {
        var line_iter_pair = line_iter_pair_ptr.*;
        defer line_iter_pair.deinit();

        // count files and bytes before skipping binary or mode-only changes.
        stats.bytes_added +|= line_iter_pair.b.size -| line_iter_pair.a.size;
        stats.bytes_removed +|= line_iter_pair.a.size -| line_iter_pair.b.size;
        if (line_iter_pair.a.source == .nothing) {
            stats.files_added += 1;
        } else if (line_iter_pair.b.source == .nothing) {
            stats.files_removed += 1;
        } else {
            stats.files_changed += 1;
        }

        // keep the last text state while the file is binary
        if (line_iter_pair.b.source == .binary) continue;
        if (std.mem.eql(u8, &line_iter_pair.a.oid, &line_iter_pair.b.oid)) continue;

        // zero counts exclude binary transitions from statistics. for text files,
        // omit the empty entry that represents end of file.
        var line_counts: [2]usize = .{ 0, 0 };
        if (line_iter_pair.a.source != .binary) {
            for ([_]*df.LineIterator(.xit, repo_opts){ &line_iter_pair.a, &line_iter_pair.b }, &line_counts) |iter, *count| {
                count.* = iter.count();
                if (count.* == 0) continue;
                if ((try iter.get(count.* - 1)).len == 0) count.* -= 1;
            }
        }

        const path_hash = hash.hashInt(repo_opts.hash, line_iter_pair.path);
        var application = PatchApplication(repo_opts){
            .file = try File(repo_opts).load(state.readOnly().extra.moment, snapshot.cursor.readOnly(), allocator, path_hash),
            .edits = .empty,
        };
        defer application.deinit(allocator);
        const file = &application.file;
        // the gaps of the new file, starting with the one before its first line
        var next_gaps: std.ArrayList([]const Id) = .empty;
        defer next_gaps.deinit(allocator);
        try next_gaps.append(allocator, file.gaps[0]);
        // the line ids the new file must have, in order
        var expected: std.ArrayList(LineId(repo_opts.hash).Int) = .empty;
        defer expected.deinit(allocator);

        // create and store the patch. each run of insertions/deletions
        // becomes an edit with its own id and text.
        const patch_hash = blk: {
            var recorded = [_]u8{0} ** hash.byteLen(repo_opts.hash);
            if (try snapshot.cursor.readOnly().readPath(void, &.{
                .{ .hash_map_get = .{ .value = path_hash } },
                .{ .array_list_get = @intFromEnum(FileField.oid) },
            })) |cursor| {
                if (cursor.slot().tag != .none and (try cursor.readBytes(&recorded)).len != recorded.len) return error.InvalidFileOid;
            }
            if (line_iter_pair.a.source == .binary) {
                // compare to the retained text state, which its recorded blob holds
                const text_iter = if (file.lines.items.len == 0)
                    try df.LineIterator(.xit, repo_opts).initFromNothing(allocator, line_iter_pair.path)
                else
                    try df.LineIterator(.xit, repo_opts).initFromTextOid(state.readOnly(), io, allocator, line_iter_pair.path, &recorded);
                line_iter_pair.a.deinit();
                line_iter_pair.a = text_iter;
            } else if (!std.mem.eql(u8, &recorded, &line_iter_pair.a.oid)) {
                // the snapshot must describe the parent's blob
                return error.SnapshotBlobMismatch;
            }
            if (file.lines.items.len != line_iter_pair.a.count()) return error.InvalidLineList;
            var diff = try df.MyersDiffIterator(.xit, repo_opts).init(allocator, &line_iter_pair.a, &line_iter_pair.b);
            defer diff.deinit();
            var patch_buffer = std.Io.Writer.Allocating.init(allocator);
            defer patch_buffer.deinit();
            const records = try DB.HashMap(.read_write).init(try state.extra.moment.putCursor(hash.hashInt(repo_opts.hash, "edit-id->edit")));
            var next_edit = try diff.next();
            var old_index: usize = 0;
            while (next_edit) |edit| {
                if (edit == .eql) {
                    // equal text with a changed line terminator is still a change.
                    // an empty end entry matched to a real blank line counts once.
                    const old_has_newline = edit.eql.old_line.num + 1 < line_iter_pair.a.count();
                    const new_has_newline = edit.eql.new_line.num + 1 < line_iter_pair.b.count();
                    if (old_has_newline != new_has_newline) {
                        if (edit.eql.old_line.num < line_counts[0] and edit.eql.new_line.num < line_counts[1]) {
                            stats.lines_changed += 1;
                        } else if (edit.eql.old_line.num < line_counts[0]) {
                            stats.lines_removed += 1;
                        } else if (edit.eql.new_line.num < line_counts[1]) {
                            stats.lines_added += 1;
                        }
                    }
                    try expected.append(allocator, file.lines.items[old_index].id);
                    old_index += 1;
                    try next_gaps.append(allocator, file.gaps[old_index]);
                    next_edit = try diff.next();
                    continue;
                }
                // include records created by earlier edits in this transaction
                file.moment = state.readOnly().extra.moment.*;
                const start = old_index;
                var text_hasher = hash.Hasher(repo_opts.hash).init(.{});
                var text_count: usize = 0;
                var lines_added: u64 = 0;
                var lines_removed: u64 = 0;
                // hash inserted text as the diff yields it
                while (next_edit) |change| : (next_edit = try diff.next()) {
                    switch (change) {
                        .del => |del| {
                            old_index += 1;
                            if (del.old_line.num < line_counts[0]) lines_removed += 1;
                        },
                        .ins => |ins| {
                            const line = try line_iter_pair.b.get(ins.new_line.num);
                            var line_size: [4]u8 = undefined;
                            std.mem.writeInt(u32, &line_size, @intCast(line.len), .big);
                            text_hasher.update(&line_size);
                            text_hasher.update(line);
                            text_count += 1;
                            if (ins.new_line.num < line_counts[1]) lines_added += 1;
                        },
                        .eql => break,
                    }
                }
                // pair removals and insertions within this edit; count only the excess separately.
                const lines_changed = @min(lines_added, lines_removed);
                stats.lines_added += lines_added - lines_changed;
                stats.lines_changed += lines_changed;
                stats.lines_removed += lines_removed - lines_changed;
                // deletions in this edit are a contiguous slice of the old lines
                const removed = file.lines.items[start..old_index];
                var buffer = std.Io.Writer.Allocating.init(allocator);
                defer buffer.deinit();
                try buffer.writer.writeInt(u32, @intCast(removed.len), .big);
                for (removed) |line| try buffer.writer.writeInt(LineId(repo_opts.hash).Int, line.id, .big);
                if (removed.len == 0) {
                    // the gap between the surviving neighbors
                    try File(repo_opts).writeGap(&buffer.writer, .{
                        .start = if (start > 0) file.lines.items[start - 1].position else "",
                        .end = if (start < file.lines.items.len) file.lines.items[start].position else null,
                        .deps = try file.gapDeps(allocator, start, file.gaps[start]),
                    });
                }
                try buffer.writer.writeInt(u32, @intCast(text_count), .big);
                var text_hash: [hash.byteLen(repo_opts.hash)]u8 = undefined;
                text_hasher.final(&text_hash);
                try buffer.writer.writeAll(&text_hash);
                const id = hash.hashInt(repo_opts.hash, buffer.written());
                for (0..text_count) |index| try expected.append(allocator, @bitCast(LineId(repo_opts.hash){ .edit_id = id, .line = @intCast(index) }));
                // placement isn't part of the edit's identity
                if (removed.len > 0 and text_count > 0) {
                    const placement = try File(repo_opts).replacementPlacement(removed, @intCast(text_count), file.arena.allocator());
                    try writeLengthPrefixedBytes(&buffer.writer, placement.prefix);
                    try buffer.writer.writeInt(u64, placement.lo, .big);
                    try buffer.writer.writeInt(u64, placement.hi, .big);
                }
                var record = try records.putCursor(id);
                if (record.slot().empty()) {
                    try record.write(.{ .bytes = buffer.written() });
                } else {
                    // reused records still need checking; a fresh one was just hashed
                    var scratch = std.heap.ArenaAllocator.init(allocator);
                    defer scratch.deinit();
                    try File(repo_opts).verify(try file.readEdit(id, scratch.allocator()));
                }
                try patch_buffer.writer.writeInt(Id, id, .big);

                // a one-line replacement keeps both exterior gaps
                if (removed.len == 1 and text_count == 1) {
                    try next_gaps.append(allocator, file.gaps[old_index]);
                    continue;
                }

                // update the gap dependencies alongside the diff
                if (text_count == 0) {
                    // a deletion joins the surrounding gaps, keeping every dependency
                    // so independent deletions can be combined in either order
                    var joined: std.AutoArrayHashMapUnmanaged(Id, void) = .empty;
                    defer joined.deinit(allocator);
                    for (file.gaps[start .. old_index + 1]) |old| {
                        for (old) |dep| try joined.put(allocator, dep, {});
                    }
                    try joined.put(allocator, id, {});
                    std.mem.sort(Id, joined.keys(), {}, std.sort.asc(Id));
                    next_gaps.items[next_gaps.items.len - 1] = try file.arena.allocator().dupe(Id, joined.keys());
                } else {
                    // new lines start without dependencies between them. an insertion
                    // splits its gap; a replacement keeps its exterior gaps.
                    if (removed.len == 0) _ = next_gaps.pop();
                    const interior = if (removed.len == 0) text_count + 1 else text_count - 1;
                    for (0..interior) |_| try next_gaps.append(allocator, &.{});
                    if (removed.len > 0) try next_gaps.append(allocator, file.gaps[old_index]);
                }
            }
            if (patch_buffer.written().len == 0) continue;
            const patch_id = hash.hashInt(repo_opts.hash, patch_buffer.written());
            const patches = try DB.HashMap(.read_write).init(try state.extra.moment.putCursor(hash.hashInt(repo_opts.hash, "patch-id->edit-list")));
            var patch_cursor = try patches.putCursor(patch_id);
            try patch_cursor.writeIfEmpty(.{ .bytes = patch_buffer.written() });
            break :blk patch_id;
        };

        // apply the patch to the snapshot it was created from
        // refresh the moment so the new patch record is visible
        file.moment = state.readOnly().extra.moment.*;
        try applyPatchesToFile(repo_opts, &application, allocator, &.{patch_hash}, .create, null);
        // the text isn't stored, so the lines must be exactly those of the new blob, in order
        if (file.lines.items.len != expected.items.len) return error.InvalidLineList;
        for (file.lines.items, expected.items) |line, id| {
            if (line.id != id) return error.InvalidLineList;
        }
        try application.save(&snapshot, allocator, line_iter_pair.path, next_gaps.items);

        // associate the patch hash and blob with path/commit
        const fields = try DB.ArrayList(.read_write).init(try snapshot.putCursor(path_hash));
        try fields.put(@intFromEnum(FileField.patch), .{ .bytes = &hash.intToBytes(Id, patch_hash) });
        try fields.put(@intFromEnum(FileField.oid), .{ .bytes = &line_iter_pair.b.oid });
    }

    // save even zero totals, so an indexed commit differs from a missing summary.
    var stats_bytes: [CommitStats.byte_len]u8 = undefined;
    inline for (std.meta.fields(CommitStats), 0..) |field, i| {
        std.mem.writeInt(u64, stats_bytes[i * 8 ..][0..8], @field(stats, field.name), .big);
    }
    const summaries = try DB.HashMap(.read_write).init(try state.extra.moment.putCursor(hash.hashInt(repo_opts.hash, COMMIT_ID_TO_STATS_KEY)));
    try summaries.put(commit_id_int, .{ .bytes = &stats_bytes });

    // this will force xitdb consider the start of the transaction
    // to be at the very end of the file. this is necessary in case
    // this function is called again in this transaction, which can
    // happen during a clone or fetch. this could be bad because,
    // as you can see above, we are getting the snapshot from the
    // parent commit and copying it. we don't want that snapshot to
    // be mutable, so we have to make xitdb think the transaction
    // just started.
    try state.core.db.freeze();
}

pub const COMMIT_ID_TO_STATS_KEY = "commit-id->stats";

// fields are stored in declaration order as big-endian u64s.
pub const CommitStats = struct {
    first_parent_depth: u64 = 0,
    lines_added: u64 = 0,
    lines_changed: u64 = 0,
    lines_removed: u64 = 0,
    bytes_added: u64 = 0,
    bytes_removed: u64 = 0,
    files_added: u64 = 0,
    files_changed: u64 = 0,
    files_removed: u64 = 0,

    const byte_len = std.meta.fields(@This()).len * @sizeOf(u64);
};

pub fn readCommitStats(
    comptime repo_opts: rp.RepoOpts(.xit),
    moment: *const rp.Repo(.xit, repo_opts).DB.HashMap(.read_only),
    oid: *const [hash.hexLen(repo_opts.hash)]u8,
) !?CommitStats {
    const DB = rp.Repo(.xit, repo_opts).DB;
    const summaries_cursor = (try moment.getCursor(hash.hashInt(repo_opts.hash, COMMIT_ID_TO_STATS_KEY))) orelse return null;
    const summaries = try DB.HashMap(.read_only).init(summaries_cursor);
    const cursor = (try summaries.getCursor(try hash.hexToInt(repo_opts.hash, oid))) orelse return null;
    var bytes: [CommitStats.byte_len]u8 = undefined;
    if ((try cursor.readBytes(&bytes)).len != bytes.len) return error.InvalidCommitStats;
    var stats: CommitStats = undefined;
    inline for (std.meta.fields(CommitStats), 0..) |field, i| {
        @field(stats, field.name) = std.mem.readInt(u64, bytes[i * 8 ..][0..8], .big);
    }
    return stats;
}

// the base snapshot, when given, must be an ancestor of the target snapshot
// and of every commit the patches came from. edits it already applied are
// skipped during conflict detection, since every new edit was made on a
// lineage that included them. the patches themselves must come from one
// first-parent chain; they aren't checked for conflicts with each other.
pub fn applyPatches(
    comptime opts: rp.RepoOpts(.xit),
    moment: *const rp.Repo(.xit, opts).DB.HashMap(.read_only),
    snapshot: rp.Repo(.xit, opts).DB.Cursor(.read_only),
    base_snapshot: ?rp.Repo(.xit, opts).DB.Cursor(.read_only),
    allocator: std.mem.Allocator,
    path: []const u8,
    patch_hashes: []const hash.HashInt(opts.hash),
) !PatchApplication(opts) {
    const DB = rp.Repo(.xit, opts).DB;
    const path_hash = hash.hashInt(opts.hash, path);
    var application = PatchApplication(opts){
        .file = try File(opts).load(moment, snapshot, allocator, path_hash),
        .edits = .empty,
    };
    errdefer application.deinit(allocator);
    const base_edits: ?DB.HashSet(.read_only) = if (base_snapshot) |base| blk: {
        const cursor = (try base.readPath(void, &.{
            .{ .hash_map_get = .{ .value = path_hash } },
            .{ .array_list_get = @intFromEnum(FileField.edits) },
        })) orelse break :blk null;
        break :blk try DB.HashSet(.read_only).init(cursor);
    } else null;
    try applyPatchesToFile(opts, &application, allocator, patch_hashes, .merge, base_edits);
    return application;
}

// creation skips verification: its new records were just hashed and reused ones checked.
fn applyPatchesToFile(
    comptime opts: rp.RepoOpts(.xit),
    application: *PatchApplication(opts),
    allocator: std.mem.Allocator,
    patch_hashes: []const hash.HashInt(opts.hash),
    kind: PatchApplicationKind,
    base_edits: ?rp.Repo(.xit, opts).DB.HashSet(.read_only),
) !void {
    const Id = hash.HashInt(opts.hash);
    const file = &application.file;
    const pending = &application.edits;
    for (patch_hashes) |patch_hash| {
        var cursor = (try file.moment.cursor.readPath(void, &.{
            .{ .hash_map_get = .{ .value = hash.hashInt(opts.hash, "patch-id->edit-list") } },
            .{ .hash_map_get = .{ .value = patch_hash } },
        })) orelse return error.PatchNotFound;
        var buffer: [opts.buffer_size]u8 = undefined;
        var reader = try cursor.reader(&buffer);
        while (reader.logicalPos() < reader.size) {
            const id = try reader.interface.takeInt(Id, .big);
            if (!try file.contains(id)) try pending.put(allocator, id, {});
        }
    }
    var removed: std.AutoHashMapUnmanaged(LineId(opts.hash).Int, void) = .empty;
    defer removed.deinit(allocator);
    var scratch = std.heap.ArenaAllocator.init(allocator);
    defer scratch.deinit();

    // validate dependencies and removals before changing the lines
    for (pending.keys()) |id| {
        _ = scratch.reset(.retain_capacity);
        const edit = try file.readEdit(id, scratch.allocator());
        if (kind == .merge) try File(opts).verify(edit);
        for (edit.gap.deps) |dep| {
            if (!pending.contains(dep) and !try file.contains(dep)) return error.MissingPatchDependency;
        }
        var previous: ?[]const u8 = null;
        for (0..edit.removed_count) |i| {
            const line_id = try File(opts).removedAt(edit, @intCast(i));
            const line: LineId(opts.hash) = @bitCast(line_id);
            if (!pending.contains(line.edit_id) and !try file.contains(line.edit_id)) return error.MissingPatchDependency;
            const node = try file.node(line_id, scratch.allocator());
            if (previous) |pos| if (!File(opts).less(pos, node.position)) return error.InvalidEdit;
            previous = node.position;
            try removed.put(allocator, line_id, {});
        }
    }

    // apply removals and insertions, then sort by position
    var count: usize = 0;
    for (file.lines.items) |line| {
        if (removed.contains(line.id)) continue;
        file.lines.items[count] = line;
        count += 1;
    }
    file.lines.shrinkRetainingCapacity(count);
    for (pending.keys()) |id| {
        const edit = try file.readEdit(id, file.arena.allocator());
        if (edit.text_count == 0) continue;
        const where = try File(opts).placement(edit, file.arena.allocator());
        for (0..edit.text_count) |ordinal| {
            const line: LineId(opts.hash).Int = @bitCast(LineId(opts.hash){ .edit_id = id, .line = @intCast(ordinal) });
            if (!removed.contains(line)) try file.lines.append(file.arena.allocator(), try File(opts).nodeFromEdit(edit, where, ordinal, file.arena.allocator()));
        }
    }
    std.mem.sort(File(opts).Node, file.lines.items, {}, struct {
        fn lt(_: void, a: File(opts).Node, b: File(opts).Node) bool {
            return if (std.mem.eql(u8, a.position, b.position)) a.id < b.id else File(opts).less(a.position, b.position);
        }
    }.lt);

    // a diff of this exact snapshot describes its chosen next state.
    // conflict checks are only needed when combining changes from other states.
    if (kind == .create) return;

    var other_arena = std.heap.ArenaAllocator.init(allocator);
    defer other_arena.deinit();

    // only edits concurrent with the new ones can conflict. collect them once,
    // without reading the file's entire history for each new edit.
    var concurrent: std.ArrayList(Id) = .empty;
    defer concurrent.deinit(allocator);
    if (file.edits) |old_edits| {
        var iter = try old_edits.iterator();
        while (try iter.next()) |entry| {
            const other_id = (try entry.readKeyValuePair()).hash;
            if (base_edits) |base| {
                if (try base.getSlot(other_id) != null) continue;
            }
            try concurrent.append(allocator, other_id);
        }
    }

    // compare new edits with concurrent applied edits. new edits come from one
    // lineage, so each was made with knowledge of the earlier ones.
    for (pending.keys()) |id| {
        _ = scratch.reset(.retain_capacity);
        const edit = try file.readEdit(id, scratch.allocator());
        const edit_range = try file.range(edit, scratch.allocator());
        for (concurrent.items) |other_id| {
            _ = other_arena.reset(.retain_capacity);
            const other = try file.readEdit(other_id, other_arena.allocator());
            if (try file.conflict(edit, edit_range, other, other_arena.allocator())) |region| try file.addRegion(region);
        }
    }

    std.mem.sort(File(opts).Region, file.regions.items, {}, struct {
        fn lt(_: void, a: File(opts).Region, b: File(opts).Region) bool {
            return File(opts).less(a.start, b.start);
        }
    }.lt);
}

const PatchApplicationKind = enum { create, merge };

// the result of applying patches to a single file: its updated state and
// newly applied edit ids. saves both to a snapshot when needed.
pub fn PatchApplication(comptime opts: rp.RepoOpts(.xit)) type {
    return struct {
        file: File(opts),
        edits: std.AutoArrayHashMapUnmanaged(hash.HashInt(opts.hash), void),

        pub fn deinit(self: *@This(), allocator: std.mem.Allocator) void {
            self.file.deinit();
            self.edits.deinit(allocator);
        }

        // writes the lines with the gaps between them. the file's chunks are
        // those it was loaded with, so unchanged ones stay shared.
        pub fn save(self: *const @This(), snapshot: *const rp.Repo(.xit, opts).DB.HashMap(.read_write), allocator: std.mem.Allocator, path: []const u8, gaps: []const []const hash.HashInt(opts.hash)) !void {
            // snapshots hold chosen text, never conflict alternatives
            if (self.file.regions.items.len > 0) return error.ConflictedPatchApplication;
            // applied ids are scoped to this file: a nonempty patch on a new path
            // always reaches initialization below. repeats preserve the snapshot.
            if (self.edits.count() == 0) return;
            try self.file.validateGaps(gaps);
            const DB = rp.Repo(.xit, opts).DB;
            const path_hash = hash.hashInt(opts.hash, path);
            try snapshot.putKey(path_hash, .{ .bytes = path });
            const fields = try DB.ArrayList(.read_write).init(try snapshot.putCursor(path_hash));
            while (try fields.count() < @typeInfo(FileField).@"enum".fields.len) try fields.append(.{ .slot = null });
            const set = try DB.HashSet(.read_write).init(try fields.putCursor(@intFromEnum(FileField.edits)));
            for (self.edits.keys()) |id| try set.put(id, .{ .uint = 1 });

            // update the chunk list in position order, keeping unchanged blobs
            const before = self.file.chunks;
            const lines = self.file.lines.items;
            const list = try DB.LinkedArrayList(.read_write).init(try fields.putCursor(@intFromEnum(FileField.lines)));
            if (try list.count() != before.len) return error.InvalidLineList;
            var buffer = std.Io.Writer.Allocating.init(allocator);
            defer buffer.deinit();
            var old_index: usize = 0;
            var new_index: usize = 0;
            var start: usize = 0;
            for (gaps, 0..) |deps, i| {
                try buffer.writer.writeInt(u32, @intCast(deps.len), .big);
                for (deps) |dep| try buffer.writer.writeInt(hash.HashInt(opts.hash), dep, .big);
                if (i < lines.len) try buffer.writer.writeInt(LineId(opts.hash).Int, lines[i].id, .big);
                // stable positions let later chunks remain shared after an
                // insertion or deletion. cap long runs at 64 entries.
                const left = if (i == 0) "" else lines[i - 1].position;
                if (i + 1 < gaps.len and i + 1 - start < 64 and std.hash.Wyhash.hash(0, left) & 15 != 0) continue;
                const chunk_start = if (start == 0) "" else lines[start - 1].position;
                while (old_index < before.len and std.mem.lessThan(u8, before[old_index].start, chunk_start)) {
                    try list.remove(@intCast(new_index));
                    old_index += 1;
                }
                if (old_index < before.len and std.mem.eql(u8, before[old_index].start, chunk_start)) {
                    const bytes = try before[old_index].cursor.readBytesAlloc(allocator, null);
                    defer allocator.free(bytes);
                    if (!std.mem.eql(u8, bytes, buffer.written())) try list.put(@intCast(new_index), .{ .bytes = buffer.written() });
                    old_index += 1;
                } else if (old_index == before.len) {
                    try list.append(.{ .bytes = buffer.written() });
                } else {
                    try list.insert(@intCast(new_index), .{ .bytes = buffer.written() });
                }
                new_index += 1;
                start = i + 1;
                buffer.clearRetainingCapacity();
            }
            while (old_index < before.len) : (old_index += 1) try list.remove(@intCast(new_index));
        }
    };
}

// a file's state within the patch system. provides the lines and edit
// records needed to create and apply patches, find conflicts, and read text.
pub fn File(comptime opts: rp.RepoOpts(.xit)) type {
    return struct {
        const Self = @This();
        const DB = rp.Repo(.xit, opts).DB;
        const Id = hash.HashInt(opts.hash);
        const Line = LineId(opts.hash).Int;
        const line_size = @bitSizeOf(Line) / 8;
        const pair_size = hash.byteLen(opts.hash) + 8;
        const max_ordinal = std.math.maxInt(u64);
        const stride: u64 = 1 << 32;
        pub const Gap = struct { start: []const u8 = "", end: ?[]const u8 = null, deps: []const Id = &.{} };
        // a stored blob of entries: the index of its first entry, and once the
        // lines are known, the position to its left, which identifies it
        const Chunk = struct { first: usize, start: []const u8 = "", cursor: DB.Cursor(.read_only) };
        const Entries = struct { ids: []const Line, gaps: []const []const Id, chunks: []Chunk };
        // where an edit's lines go: under prefix, with ordinals strictly between lo and hi
        const Placement = struct { prefix: []const u8, lo: u64, hi: u64 };
        const Lineage = struct { edit: Id, deletion: Id };
        const Edit = struct {
            id: Id,
            cursor: DB.Cursor(.read_only),
            removed_count: u32,
            gap: Gap,
            text_count: u32,
            header_end: u64,
        };
        pub const Node = struct {
            id: Line,
            position: []const u8,
        };
        pub const Region = struct {
            start: []const u8,
            end: []const u8,

            pub fn contains(self: Region, pos: []const u8) bool {
                return !less(pos, self.start) and (less(pos, self.end) or std.mem.startsWith(u8, pos, self.end));
            }
        };

        arena: std.heap.ArenaAllocator,
        moment: DB.HashMap(.read_only),
        edits: ?DB.HashSet(.read_only),
        lines: std.ArrayList(Node) = .empty,
        // the deletions behind each gap, and the chunks they were loaded from. applying
        // patches changes the lines but not these, so a save can tell what changed.
        gaps: []const []const Id = &.{},
        chunks: []const Chunk = &.{},
        regions: std.ArrayList(Region) = .empty,
        // whether an edit descends from a deletion, memoized for one application
        lineage: std.AutoHashMapUnmanaged(Lineage, bool) = .empty,

        pub fn load(moment: *const DB.HashMap(.read_only), snapshot: DB.Cursor(.read_only), allocator: std.mem.Allocator, path_hash: Id) !Self {
            const edit_cursor = try snapshot.readPath(void, &.{
                .{ .hash_map_get = .{ .value = path_hash } },
                .{ .array_list_get = @intFromEnum(FileField.edits) },
            });
            var self = Self{
                .arena = std.heap.ArenaAllocator.init(allocator),
                .moment = moment.*,
                .edits = if (edit_cursor) |cursor| try DB.HashSet(.read_only).init(cursor) else null,
            };
            errdefer self.deinit();
            const entries = try readEntries(snapshot, path_hash, allocator, self.arena.allocator());
            defer allocator.free(entries.ids);
            // lines from the same edit share its header and placement,
            // so only edits with live lines are read
            var edits: std.AutoHashMapUnmanaged(Id, struct { edit: Edit, where: Placement }) = .empty;
            defer edits.deinit(allocator);
            for (entries.ids) |id| {
                const line: LineId(opts.hash) = @bitCast(id);
                const entry = try edits.getOrPut(allocator, line.edit_id);
                if (!entry.found_existing) {
                    const edit = try self.readEdit(line.edit_id, self.arena.allocator());
                    entry.value_ptr.* = .{ .edit = edit, .where = try placement(edit, self.arena.allocator()) };
                }
                try self.lines.append(self.arena.allocator(), try nodeFromEdit(entry.value_ptr.edit, entry.value_ptr.where, line.line, self.arena.allocator()));
            }
            for (entries.chunks) |*chunk| {
                if (chunk.first > 0) chunk.start = self.lines.items[chunk.first - 1].position;
            }
            self.gaps = entries.gaps;
            self.chunks = entries.chunks;
            try self.validateGaps(self.gaps);
            return self;
        }

        pub fn deinit(self: *Self) void {
            self.arena.deinit();
        }

        pub fn contains(self: *const Self, id: Id) !bool {
            const edits = self.edits orelse return false;
            return try edits.getSlot(id) != null;
        }

        // the ids alone, for finding a line's index in the blob the snapshot describes
        pub fn lineIds(snapshot: DB.Cursor(.read_only), allocator: std.mem.Allocator, path_hash: Id) ![]const Line {
            const entries = try readEntries(snapshot, path_hash, allocator, allocator);
            for (entries.gaps) |deps| allocator.free(deps);
            allocator.free(entries.gaps);
            allocator.free(entries.chunks);
            return entries.ids;
        }

        // a file that was never patched has no lines and one gap
        fn readEntries(snapshot: DB.Cursor(.read_only), path_hash: Id, ids_allocator: std.mem.Allocator, allocator: std.mem.Allocator) !Entries {
            var ids: std.ArrayList(Line) = .empty;
            errdefer ids.deinit(ids_allocator);
            var gaps: std.ArrayList([]const Id) = .empty;
            errdefer {
                for (gaps.items) |deps| allocator.free(deps);
                gaps.deinit(allocator);
            }
            const cursor = (try snapshot.readPath(void, &.{
                .{ .hash_map_get = .{ .value = path_hash } },
                .{ .array_list_get = @intFromEnum(FileField.lines) },
            })) orelse {
                try gaps.append(allocator, &.{});
                return .{ .ids = &.{}, .gaps = try gaps.toOwnedSlice(allocator), .chunks = &.{} };
            };
            const list = try DB.LinkedArrayList(.read_only).init(cursor);
            const chunks = try allocator.alloc(Chunk, @intCast(try list.count()));
            errdefer allocator.free(chunks);
            var iter = try list.iterator();
            // only the last entry of the last chunk has no line: the gap at the end
            var ended = false;
            for (chunks) |*chunk| {
                var entry = (try iter.next()) orelse return error.InvalidLineList;
                var buffer: [opts.buffer_size]u8 = undefined;
                var reader = try entry.reader(&buffer);
                if (ended or reader.size == 0) return error.InvalidLineList;
                chunk.* = .{ .first = gaps.items.len, .cursor = entry };
                while (reader.logicalPos() < reader.size) {
                    const dep_count = try reader.interface.takeInt(u32, .big);
                    if (dep_count > (reader.size -| reader.logicalPos()) / hash.byteLen(opts.hash)) return error.InvalidLineList;
                    const deps = try allocator.alloc(Id, dep_count);
                    {
                        errdefer allocator.free(deps);
                        for (deps) |*dep| dep.* = try reader.interface.takeInt(Id, .big);
                        try gaps.append(allocator, deps);
                    }
                    if (reader.logicalPos() == reader.size) {
                        ended = true;
                        break;
                    }
                    if (line_size > reader.size - reader.logicalPos()) return error.InvalidLineList;
                    try ids.append(ids_allocator, try reader.interface.takeInt(Line, .big));
                }
            }
            if (!ended) return error.InvalidLineList;
            // once detached, the list's cleanup no longer covers the ids
            const owned_ids = try ids.toOwnedSlice(ids_allocator);
            errdefer ids_allocator.free(owned_ids);
            return .{ .ids = owned_ids, .gaps = try gaps.toOwnedSlice(allocator), .chunks = chunks };
        }

        fn validateGaps(self: *const Self, gaps: []const []const Id) !void {
            if (gaps.len != self.lines.items.len + 1) return error.InvalidLineList;
            for (gaps) |deps| {
                for (deps, 0..) |dep, j| {
                    if (j > 0 and deps[j - 1] >= dep) return error.InvalidLineList;
                }
            }
        }

        // an insertion depends on the edits that placed its neighbors and on the
        // deletions that made them adjacent, so the same text in the same gap
        // shares an id. a one-line replacement keeps its position, so the gap
        // identity survives it.
        fn gapDeps(self: *Self, allocator: std.mem.Allocator, index: usize, deletions: []const Id) ![]const Id {
            var deps: std.AutoArrayHashMapUnmanaged(Id, void) = .empty;
            defer deps.deinit(allocator);
            if (index > 0) try deps.put(allocator, positionId(self.lines.items[index - 1].position), {});
            if (index < self.lines.items.len) try deps.put(allocator, positionId(self.lines.items[index].position), {});
            for (deletions) |dep| try deps.put(allocator, dep, {});
            std.mem.sort(Id, deps.keys(), {}, std.sort.asc(Id));
            return self.arena.allocator().dupe(Id, deps.keys());
        }

        fn conflict(self: *Self, a: Edit, ar: Region, b: Edit, allocator: std.mem.Allocator) !?Region {
            if (a.id == b.id) return null;
            if (a.text_count == 0 and b.text_count == 0) return null;
            const br = try self.range(b, allocator);
            var overlaps = false;
            if (a.removed_count == 0 and b.removed_count == 0) {
                // the same gap, whatever room each insertion found for its lines
                overlaps = std.mem.eql(u8, a.gap.start, b.gap.start) and std.mem.eql(u8, a.gap.end orelse "", b.gap.end orelse "");
            } else {
                if (!ar.contains(br.start) and !br.contains(ar.start)) return null;
                if (a.removed_count > 0 and b.removed_count > 0) {
                    var i: u32 = 0;
                    var j: u32 = 0;
                    var scratch = std.heap.ArenaAllocator.init(allocator);
                    defer scratch.deinit();
                    while (i < a.removed_count and j < b.removed_count) {
                        _ = scratch.reset(.retain_capacity);
                        const ai = try removedAt(a, i);
                        const bi = try removedAt(b, j);
                        if (ai == bi) {
                            overlaps = true;
                            break;
                        }
                        const ap = (try self.node(ai, scratch.allocator())).position;
                        const bp = (try self.node(bi, scratch.allocator())).position;
                        switch (std.mem.order(u8, ap, bp)) {
                            .lt => i += 1,
                            .gt => j += 1,
                            .eq => {
                                i += 1;
                                j += 1;
                            },
                        }
                    }
                }
                if (!overlaps and a.text_count > 0 and b.removed_count > 0) overlaps = try self.placedInside(a, br, b, allocator);
                if (!overlaps and b.text_count > 0 and a.removed_count > 0) overlaps = try self.placedInside(b, ar, a, allocator);
            }
            if (!overlaps) return null;
            return .{ .start = if (less(ar.start, br.start)) ar.start else br.start, .end = if (endsBefore(ar.end, br.end)) br.end else ar.end };
        }

        // whether the edit put a surviving line strictly inside the deleted
        // range without descending from the deletion
        fn placedInside(self: *Self, edit: Edit, region: Region, deletion: Edit, allocator: std.mem.Allocator) !bool {
            const where = try placement(edit, allocator);
            const first = try nodeFromEdit(edit, where, 0, allocator);
            if (!less(region.start, first.position) or !less(first.position, region.end)) return false;
            if (try self.inLineage(edit, deletion.id, allocator)) return false;
            for (0..edit.text_count) |index| {
                const line = try nodeFromEdit(edit, where, index, allocator);
                if (region.contains(line.position) and self.survives(line)) return true;
            }
            return false;
        }

        // an edit descends from a deletion when any edit it depends on does:
        // the creators of the lines it replaced, or for an insertion the gap's
        // dependencies and the lines it nests under. memoized, so a chain of
        // rewrites is walked once rather than once per rewrite.
        fn inLineage(self: *Self, edit: Edit, id: Id, allocator: std.mem.Allocator) !bool {
            const key = Lineage{ .edit = edit.id, .deletion = id };
            if (self.lineage.get(key)) |found| return found;
            var deps: std.AutoArrayHashMapUnmanaged(Id, void) = .empty;
            defer deps.deinit(allocator);
            if (edit.removed_count > 0) {
                for (try removedIds(edit, allocator)) |line| try deps.put(allocator, @as(LineId(opts.hash), @bitCast(line)).edit_id, {});
            } else {
                for (edit.gap.deps) |dep| try deps.put(allocator, dep, {});
                const where = try placeBetween(edit.gap.start, edit.gap.end, edit.text_count, allocator);
                var pairs = std.Io.Reader.fixed(where.prefix);
                while (pairs.bufferedLen() >= pair_size) {
                    _ = try pairs.takeInt(u64, .big);
                    const owner = try pairs.takeInt(Id, .big);
                    if (owner != 0) try deps.put(allocator, owner, {}); // zero pairs are padding
                }
            }
            var found = false;
            for (deps.keys()) |dep| {
                if (dep == id or try self.inLineage(try self.readEdit(dep, allocator), id, allocator)) {
                    found = true;
                    break;
                }
            }
            try self.lineage.put(self.arena.allocator(), key, found);
            return found;
        }

        // lines sharing a position, like competing one-line replacements, differ by id
        fn survives(self: *const Self, line: Node) bool {
            var begin: usize = 0;
            var end = self.lines.items.len;
            while (begin < end) {
                const middle = begin + (end - begin) / 2;
                switch (std.mem.order(u8, self.lines.items[middle].position, line.position)) {
                    .lt => begin = middle + 1,
                    .gt => end = middle,
                    .eq => {
                        var index = middle;
                        while (index > 0 and std.mem.eql(u8, self.lines.items[index - 1].position, line.position)) index -= 1;
                        while (index < self.lines.items.len and std.mem.eql(u8, self.lines.items[index].position, line.position)) : (index += 1) {
                            if (self.lines.items[index].id == line.id) return true;
                        }
                        return false;
                    },
                }
            }
            return false;
        }

        fn addRegion(self: *Self, value: Region) !void {
            for (self.regions.items) |region| {
                if (!less(value.start, region.start) and !endsBefore(region.end, value.end)) return;
            }
            const allocator = self.arena.allocator();
            var start: []const u8 = try allocator.dupe(u8, value.start);
            var end: []const u8 = try allocator.dupe(u8, value.end);
            var i: usize = 0;
            while (i < self.regions.items.len) {
                const region = Region{ .start = start, .end = end };
                const other = self.regions.items[i];
                if (region.contains(other.start) or other.contains(region.start)) {
                    if (less(other.start, start)) start = other.start;
                    if (endsBefore(end, other.end)) end = other.end;
                    _ = self.regions.swapRemove(i);
                    i = 0;
                } else i += 1;
            }
            try self.regions.append(allocator, .{ .start = start, .end = end });
        }

        fn range(self: *const Self, edit: Edit, allocator: std.mem.Allocator) !Region {
            if (edit.removed_count == 0) {
                // the whole interval, so concurrent insertions into one gap share a range
                const where = try placeBetween(edit.gap.start, edit.gap.end, edit.text_count, allocator);
                return .{ .start = try bound(allocator, where.prefix, where.lo + 1), .end = try bound(allocator, where.prefix, where.hi - 1) };
            }
            return .{
                .start = (try self.node(try removedAt(edit, 0), allocator)).position,
                .end = (try self.node(try removedAt(edit, edit.removed_count - 1), allocator)).position,
            };
        }

        fn node(self: *const Self, id: Line, allocator: std.mem.Allocator) !Node {
            const line: LineId(opts.hash) = @bitCast(id);
            const edit = try self.readEdit(line.edit_id, allocator);
            return nodeFromEdit(edit, try placement(edit, allocator), line.line, allocator);
        }

        fn nodeFromEdit(edit: Edit, where: Placement, ordinal: u64, allocator: std.mem.Allocator) !Node {
            if (ordinal >= edit.text_count) return error.InvalidLineId;
            return .{
                .id = @bitCast(LineId(opts.hash){ .edit_id = edit.id, .line = @intCast(ordinal) }),
                .position = if (edit.removed_count == 1 and edit.text_count == 1) where.prefix else try position(allocator, where.prefix, ordinalAt(where, edit.text_count, ordinal, edit.removed_count > 0), edit.id),
            };
        }

        fn placement(edit: Edit, allocator: std.mem.Allocator) !Placement {
            if (edit.text_count == 0) return error.InvalidLineId;
            if (edit.removed_count == 0) return placeBetween(edit.gap.start, edit.gap.end, edit.text_count, allocator);
            // replacement placement is shared by all its lines. reading
            // it doesn't require following the edits it replaced.
            var cursor = edit.cursor;
            var buffer: [opts.buffer_size]u8 = undefined;
            var reader = try cursor.reader(&buffer);
            try reader.seekTo(edit.header_end);
            const prefix = try readBytes(&reader, allocator);
            const lo = try reader.interface.takeInt(u64, .big);
            const hi = try reader.interface.takeInt(u64, .big);
            if (hi <= lo or hi - lo - 1 < edit.text_count) return error.InvalidEdit;
            return .{ .prefix = prefix, .lo = lo, .hi = hi };
        }

        // a one-line replacement keeps the removed line's position. several
        // lines replacing one nest under it; otherwise they go strictly between
        // the first and last removed lines, inside the edit's conflict range.
        fn replacementPlacement(removed: []const Node, text_count: u32, allocator: std.mem.Allocator) !Placement {
            if (removed.len == 1) return .{ .prefix = removed[0].position, .lo = 0, .hi = max_ordinal };
            return placeBetween(removed[0].position, removed[removed.len - 1].position, text_count, allocator);
        }

        // finds the shallowest level with room for the ordinals strictly between
        // positions a and b, else goes deeper under a, padding past its end with
        // zero pairs. b is only a bound while it still shares the prefix.
        fn placeBetween(a: []const u8, b_maybe: ?[]const u8, text_count: u32, allocator: std.mem.Allocator) !Placement {
            var prefix: std.ArrayList(u8) = .empty;
            defer prefix.deinit(allocator);
            var level: usize = 0;
            const b = b_maybe orelse "";
            var b_active = b_maybe != null;
            while (true) : (level += 1) {
                const a_pair: ?[]const u8 = if ((level + 1) * pair_size <= a.len) a[level * pair_size ..][0..pair_size] else null;
                const b_pair: ?[]const u8 = if (b_active and (level + 1) * pair_size <= b.len) b[level * pair_size ..][0..pair_size] else null;
                const lo: u64 = if (a_pair) |pair| std.mem.readInt(u64, pair[0..8], .big) else 0;
                const hi: u64 = if (b_pair) |pair| std.mem.readInt(u64, pair[0..8], .big) else max_ordinal;
                if (hi > lo and hi - lo - 1 >= text_count) {
                    return .{ .prefix = try allocator.dupe(u8, prefix.items), .lo = lo, .hi = hi };
                }
                const pair = a_pair orelse &([_]u8{0} ** pair_size);
                try prefix.appendSlice(allocator, pair);
                b_active = if (b_pair) |other| std.mem.eql(u8, pair, other) else false;
            }
        }

        // spreads the ordinals strictly between lo and hi. appends and prepends
        // step by a stride so room lasts; other insertions divide the interval.
        // replacements use both ends, so rewriting a block over and over only
        // narrows its interval by two each time.
        fn ordinalAt(where: Placement, text_count: u32, index: u64, replacement: bool) u64 {
            const count: u64 = text_count;
            if (where.lo == 0 and where.hi == max_ordinal) return (1 << 63) + index * stride;
            if (replacement) {
                if (index == 0) return where.lo + 1;
                if (index + 1 == count) return where.hi - 1;
                return where.lo + 1 + index * ((where.hi - where.lo - 2) / (count - 1));
            }
            if (where.hi == max_ordinal and (count + 1) * stride < max_ordinal - where.lo) return where.lo + (index + 1) * stride;
            if (where.lo == 0 and (count + 1) * stride < where.hi) return where.hi - (count - index) * stride;
            return where.lo + (index + 1) * ((where.hi - where.lo) / (count + 1));
        }

        fn verify(edit_value: Edit) !void {
            var edit = edit_value;
            var buffer: [opts.buffer_size]u8 = undefined;
            var reader = try edit.cursor.reader(&buffer);
            var hasher = hash.Hasher(opts.hash).init(.{});
            var remaining = edit.header_end;
            while (remaining > 0) {
                const size: usize = @intCast(@min(remaining, buffer.len));
                hasher.update(try reader.interface.take(size));
                remaining -= size;
            }
            var result: [hash.byteLen(opts.hash)]u8 = undefined;
            hasher.final(&result);
            if (hash.bytesToInt(opts.hash, &result) != edit.id) return error.InvalidEdit;
        }

        fn readEdit(self: *const Self, id: Id, allocator: std.mem.Allocator) !Edit {
            var cursor = (try self.moment.cursor.readPath(void, &.{
                .{ .hash_map_get = .{ .value = hash.hashInt(opts.hash, "edit-id->edit") } },
                .{ .hash_map_get = .{ .value = id } },
            })) orelse return error.EditNotFound;
            var buffer: [opts.buffer_size]u8 = undefined;
            var reader = try cursor.reader(&buffer);
            const removed_count = try reader.interface.takeInt(u32, .big);
            if (removed_count > (reader.size -| reader.logicalPos()) / line_size) return error.InvalidEdit;
            try reader.seekTo(reader.logicalPos() + @as(u64, removed_count) * line_size);
            const gap = if (removed_count == 0) try readGap(&reader, allocator) else Gap{};
            const text_count = try reader.interface.takeInt(u32, .big);
            // the hash of the inserted text ends the part the id covers
            if (hash.byteLen(opts.hash) > reader.size -| reader.logicalPos()) return error.InvalidEdit;
            try reader.seekTo(reader.logicalPos() + hash.byteLen(opts.hash));
            const header_end = reader.logicalPos();
            if (removed_count > 0 and text_count > 0) {
                const size = try reader.interface.takeInt(u32, .big);
                if (size % pair_size != 0 or size + 16 > reader.size -| reader.logicalPos()) return error.InvalidEdit;
                try reader.seekTo(reader.logicalPos() + size + 16);
            }
            if (reader.logicalPos() != reader.size) return error.InvalidEdit;
            if (removed_count == 0 and text_count == 0) return error.InvalidEdit;
            return .{ .id = id, .cursor = cursor, .removed_count = removed_count, .gap = gap, .text_count = text_count, .header_end = header_end };
        }

        fn removedIds(edit: Edit, allocator: std.mem.Allocator) ![]const Line {
            var cursor = edit.cursor;
            var buffer: [opts.buffer_size]u8 = undefined;
            var reader = try cursor.reader(&buffer);
            try reader.seekTo(4);
            const lines = try allocator.alloc(Line, edit.removed_count);
            for (lines) |*line| line.* = try reader.interface.takeInt(Line, .big);
            return lines;
        }

        fn removedAt(edit: Edit, index: u32) !Line {
            if (index >= edit.removed_count) return error.InvalidEdit;
            var cursor = edit.cursor;
            var buffer: [line_size]u8 = undefined;
            var reader = try cursor.reader(&buffer);
            try reader.seekTo(4 + @as(u64, index) * line_size);
            return reader.interface.takeInt(Line, .big);
        }

        fn readGap(reader: *DB.Cursor(.read_only).Reader, allocator: std.mem.Allocator) !Gap {
            const start = try readBytes(reader, allocator);
            const end: ?[]const u8 = if (try reader.interface.peekInt(u32, .big) == std.math.maxInt(u32)) blk: {
                try reader.interface.discardAll(4);
                break :blk null;
            } else try readBytes(reader, allocator);
            if (start.len % pair_size != 0) return error.InvalidGapList;
            if (end) |value| {
                if (value.len % pair_size != 0 or !less(start, value)) return error.InvalidGapList;
            }
            const count = try reader.interface.takeInt(u32, .big);
            if (count > (reader.size -| reader.logicalPos()) / hash.byteLen(opts.hash)) return error.InvalidGapList;
            const deps = try allocator.alloc(Id, count);
            for (deps) |*dep| dep.* = try reader.interface.takeInt(Id, .big);
            return .{ .start = start, .end = end, .deps = deps };
        }

        fn writeGap(writer: *std.Io.Writer, gap: Gap) !void {
            try writeLengthPrefixedBytes(writer, gap.start);
            if (gap.end) |end| try writeLengthPrefixedBytes(writer, end) else try writer.writeInt(u32, std.math.maxInt(u32), .big);
            try writer.writeInt(u32, @intCast(gap.deps.len), .big);
            for (gap.deps) |dep| try writer.writeInt(Id, dep, .big);
        }

        fn positionId(pos: []const u8) Id {
            return std.mem.readInt(Id, pos[pos.len - hash.byteLen(opts.hash) ..][0..comptime hash.byteLen(opts.hash)], .big);
        }

        fn position(allocator: std.mem.Allocator, prefix: []const u8, ordinal: u64, id: Id) ![]const u8 {
            const result = try allocator.alloc(u8, prefix.len + pair_size);
            @memcpy(result[0..prefix.len], prefix);
            std.mem.writeInt(u64, result[prefix.len..][0..8], ordinal, .big);
            std.mem.writeInt(Id, result[prefix.len + 8 ..][0..comptime hash.byteLen(opts.hash)], id, .big);
            return result;
        }

        // an ordinal without an id, before every line with that ordinal
        fn bound(allocator: std.mem.Allocator, prefix: []const u8, ordinal: u64) ![]const u8 {
            const result = try allocator.alloc(u8, prefix.len + 8);
            @memcpy(result[0..prefix.len], prefix);
            std.mem.writeInt(u64, result[prefix.len..][0..8], ordinal, .big);
            return result;
        }

        fn endsBefore(a: []const u8, b: []const u8) bool {
            // an end position includes everything nested inside it
            if (std.mem.startsWith(u8, b, a)) return false;
            if (std.mem.startsWith(u8, a, b)) return true;
            return less(a, b);
        }

        fn less(a: []const u8, b: []const u8) bool {
            return std.mem.order(u8, a, b) == .lt;
        }

        fn readBytes(reader: *DB.Cursor(.read_only).Reader, allocator: std.mem.Allocator) ![]const u8 {
            const count = try reader.interface.takeInt(u32, .big);
            if (count > reader.size -| reader.logicalPos()) return error.InvalidEdit;
            const bytes = try allocator.alloc(u8, count);
            try reader.interface.readSliceAll(bytes);
            return bytes;
        }
    };
}

// a line is identified by its edit and its position within that edit.
pub fn LineId(comptime hash_kind: hash.HashKind) type {
    return packed struct {
        line: u32,
        edit_id: hash.HashInt(hash_kind),

        pub const Int = @typeInfo(LineId(hash_kind)).@"struct".backing_integer orelse unreachable;
    };
}

pub const FileField = enum(u8) { patch, edits, lines, oid };

fn writeLengthPrefixedBytes(writer: *std.Io.Writer, bytes: []const u8) !void {
    try writer.writeInt(u32, @intCast(bytes.len), .big);
    try writer.writeAll(bytes);
}

pub fn writePatches(
    comptime repo_opts: rp.RepoOpts(.xit),
    state: rp.Repo(.xit, repo_opts).State(.read_write),
    io: std.Io,
    allocator: std.mem.Allocator,
    iter: *obj.ObjectIterator(.xit, repo_opts),
    progress_ctx_maybe: ?repo_opts.ProgressCtx,
) !void {
    var patch_writer = try PatchWriter(repo_opts).init(state.readOnly(), io, allocator);
    defer patch_writer.deinit(io, allocator);

    while (try iter.next(allocator)) |commit_object| {
        defer commit_object.deinit();
        const oid = try hash.hexToBytes(repo_opts.hash, commit_object.oid);
        try patch_writer.add(state.readOnly(), io, allocator, &oid);
    }

    try patch_writer.write(state, io, allocator, progress_ctx_maybe);
}

pub fn PatchWriter(comptime repo_opts: rp.RepoOpts(.xit)) type {
    return struct {
        const DB = rp.Repo(.xit, repo_opts).DB;
        // the map of commits waiting on their parent grows with the history,
        // so it lives in a temporary database rather than on the heap. a plain
        // file is used because each write outside a transaction is synced anyway.
        const TempDB = @import("xitdb").Database(.file, hash.HashInt(repo_opts.hash));
        const db_name = "temp.patches";

        repo_dir: std.Io.Dir,
        db_file: std.Io.File,
        db: *TempDB,
        parent_to_children: TempDB.HashMap(.read_write),
        oid_queue: std.AutoArrayHashMapUnmanaged([hash.byteLen(repo_opts.hash)]u8, void),
        commit_count: usize,

        pub fn init(state: rp.Repo(.xit, repo_opts).State(.read_only), io: std.Io, allocator: std.mem.Allocator) !PatchWriter(repo_opts) {
            const db_file = try state.core.repo_dir.createFile(io, db_name, .{ .truncate = true, .lock = .exclusive, .read = true });
            errdefer {
                db_file.close(io);
                state.core.repo_dir.deleteFile(io, db_name) catch {};
            }

            // cursors point at the database, so it needs a stable address
            const db_ptr = try allocator.create(TempDB);
            errdefer allocator.destroy(db_ptr);
            db_ptr.* = try TempDB.init(.{ .io = io, .file = db_file, .fsync = false });

            const map = try TempDB.HashMap(.read_write).init(db_ptr.rootCursor());

            const parent_to_children_cursor = try map.putCursor(hash.hashInt(repo_opts.hash, "parent->children"));
            const parent_to_children = try TempDB.HashMap(.read_write).init(parent_to_children_cursor);

            return .{
                .repo_dir = state.core.repo_dir,
                .db_file = db_file,
                .db = db_ptr,
                .parent_to_children = parent_to_children,
                .oid_queue = std.AutoArrayHashMapUnmanaged([hash.byteLen(repo_opts.hash)]u8, void){},
                .commit_count = 0,
            };
        }

        pub fn deinit(self: *PatchWriter(repo_opts), io: std.Io, allocator: std.mem.Allocator) void {
            self.db_file.close(io);
            self.repo_dir.deleteFile(io, db_name) catch {};
            allocator.destroy(self.db);
            self.oid_queue.deinit(allocator);
        }

        pub fn add(
            self: *PatchWriter(repo_opts),
            state: rp.Repo(.xit, repo_opts).State(.read_only),
            io: std.Io,
            allocator: std.mem.Allocator,
            oid: *const [hash.byteLen(repo_opts.hash)]u8,
        ) !void {
            if (self.oid_queue.contains(oid.*)) {
                return;
            }

            const oid_hex = std.fmt.bytesToHex(oid, .lower);
            const commit_id_int = try hash.hexToInt(repo_opts.hash, &oid_hex);

            var object = try obj.Object(.xit, repo_opts).init(state, io, allocator, &oid_hex);
            defer object.deinit();

            var is_base_oid = false;
            if (object.content.commit.metadata.firstParent()) |parent_oid| {
                const parent_commit_id_int = try hash.hexToInt(repo_opts.hash, parent_oid);

                if (try state.extra.moment.getCursor(hash.hashInt(repo_opts.hash, "commit-id->snapshot"))) |commit_id_to_snapshot_cursor| {
                    const commit_id_to_snapshot = try DB.HashMap(.read_only).init(commit_id_to_snapshot_cursor);

                    // if the commit already has patches, there is nothing to do so exit early
                    if (try commit_id_to_snapshot.getCursor(commit_id_int)) |_| {
                        return;
                    }
                    // if the commit's parent already has patches, consider this a "base" commit
                    // (i.e., a commit that is ready to have a patch generated right away)
                    else if (try commit_id_to_snapshot.getCursor(parent_commit_id_int)) |_| {
                        is_base_oid = true;
                    }
                }

                if (!is_base_oid) {
                    const children_cursor = try self.parent_to_children.putCursor(parent_commit_id_int);
                    const children = try TempDB.HashMap(.read_write).init(children_cursor);
                    _ = try children.putCursor(commit_id_int);
                }
            } else {
                is_base_oid = true;
            }

            if (is_base_oid) {
                try self.oid_queue.put(allocator, oid.*, {});
            }

            self.commit_count += 1;
        }

        pub fn write(
            self: *PatchWriter(repo_opts),
            state: rp.Repo(.xit, repo_opts).State(.read_write),
            io: std.Io,
            allocator: std.mem.Allocator,
            progress_ctx_maybe: ?repo_opts.ProgressCtx,
        ) !void {
            if (repo_opts.ProgressCtx != void) {
                if (progress_ctx_maybe) |progress_ctx| {
                    try progress_ctx.run(io, .{ .start = .{
                        .kind = .writing_patch,
                        .estimated_total_items = self.commit_count,
                    } });
                }
            }

            var showed_perf_warning = false;
            const start_time = std.Io.Timestamp.now(io, .real).toSeconds();

            while (self.oid_queue.count() > 0) {
                const oid = self.oid_queue.keys()[0];
                const oid_hex = std.fmt.bytesToHex(&oid, .lower);

                try writeAndApplyPatches(repo_opts, state, io, allocator, &oid_hex);
                self.oid_queue.swapRemoveAt(0);

                if (repo_opts.ProgressCtx != void) {
                    if (progress_ctx_maybe) |progress_ctx| {
                        try progress_ctx.run(io, .{ .complete_one = .writing_patch });
                    }
                }

                const commit_id_int = try hash.hexToInt(repo_opts.hash, &oid_hex);
                if (try self.parent_to_children.getCursor(commit_id_int)) |children_cursor| {
                    const children = try TempDB.HashMap(.read_only).init(children_cursor);
                    var children_iter = try children.iterator();

                    while (try children_iter.next()) |*next_cursor| {
                        const kv_pair = try next_cursor.readKeyValuePair();
                        const child_oid = hash.intToBytes(hash.HashInt(repo_opts.hash), kv_pair.hash);
                        try self.oid_queue.put(allocator, child_oid, {});
                    }
                }

                if (repo_opts.ProgressCtx != void) {
                    if (progress_ctx_maybe) |progress_ctx| {
                        if (!showed_perf_warning) {
                            const current_time = std.Io.Timestamp.now(io, .real).toSeconds();
                            if (current_time - start_time >= 5) {
                                showed_perf_warning = true;
                                try progress_ctx.run(io, .{ .child_text = "making patches can take a while." });
                                try progress_ctx.run(io, .{ .child_text = "run `xit patch off` to disable it." });
                            }
                        }
                    }
                }
            }

            if (repo_opts.ProgressCtx != void) {
                if (progress_ctx_maybe) |progress_ctx| {
                    try progress_ctx.run(io, .{ .end = .writing_patch });
                }
            }
        }
    };
}
