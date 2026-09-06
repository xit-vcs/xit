//! the implementation of patch-based version control, inspired by pijul.
//! patch data lives in .xit/db, in maps within each database moment.
//!
//! commit-id->snapshot maps each commit to a path map, initially shared with
//! its first parent and copied on write. path strings are stored as readable
//! keys. each file's value is an array of four database slots (FileField):
//! - patch: the last patch created for the file, inherited if unchanged;
//! - edits: the set of all applied edit ids, including conflicted edits;
//! - lines: a conflict byte (0 or 1), then ordered surviving line ids, including
//!   conflict alternatives. a line id is an edit id followed by the u32 index
//!   of a line inserted by that edit, starting at zero.
//! - gaps: a persistent sequence of blobs containing live boundaries, including
//!   both file ends. stable positions choose boundaries (about 16 gaps per blob,
//!   at most 64). unchanged blobs and tree nodes are shared between snapshots.
//!
//! patch-id->edit-list stores ordered edit ids, without a count. the patch id
//! hashes those ids. edit-id->edit stores each edit once, in this order:
//! - a u32 removal count and the removed line ids in order;
//! - only for pure insertions, the original gap: length-prefixed start/end
//!   positions, then a counted list of dependency ids (u32 lengths/counts).
//!   an end length of 0xffffffff denotes a point; otherwise the gap is a span;
//! - a u32 inserted-line count;
//! - only for replacements, the first removed line's position (u32 length/bytes);
//! - u64 text offsets for inserted lines 64, 128, etc. line 0's offset is zero;
//! - each inserted line as a u32 byte length and its text, without '\n'.
//! integers are big endian. offsets are relative to the start of the text data.
//! the edit id hashes the record excluding placement (including its length)
//! and the offset table. paths, commits, and unrelated edits aren't part of it.
//!
//! positions are sequences of (edit id, ordinal) pairs: even ordinals name
//! gaps, odd ordinals name lines. insertions extend their gap's position;
//! replacements extend the first removed line's position, except 1:1 keeps it.
//! insertions split gaps; replacements preserve their exterior gaps. deletions
//! join gaps, keeping outer bounds and the sorted union of dependencies plus
//! the deletion id. joining an insertion's exterior gaps restores its original
//! bounds; a reopened point becomes a span with equal bounds. points use their
//! start directly; a span's insertion position extends its start with a hash
//! of its bounds and dependencies, so reinserting text after deletion has a
//! new identity.
//!
//! how patches are created: compare each changed file with its first-parent
//! state using myers, turning changed runs into edits and updating gaps as needed.
//! store the edits and their ordered ids as a patch, apply it to the parent
//! snapshot, then save the new snapshot, sharing unchanged gap chunks.
//!
//! how patches are applied: load the snapshot and collect edits from the chosen
//! patches, skipping those already applied. verify their dependencies and removed
//! line ids, apply removals and insertions, then sort the remaining lines by
//! position. when merging, compare edits to find conflict regions. return the
//! updated file and newly applied edit ids for saving or writing the merged text.

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

    // if there is a parent commit, set the initial value of the snapshot to the one from that commit
    if (parent_commit_oid_maybe) |*parent_commit_oid| {
        if (try commit_id_to_snapshot.getCursor(try hash.hexToInt(repo_opts.hash, parent_commit_oid))) |parent_snapshot_cursor| {
            try snapshot_cursor.write(.{ .slot = parent_snapshot_cursor.slot() });
        } else {
            return error.ParentCommitSnapshotNotFound;
        }
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

        // keep the last text state while the file is binary
        if (line_iter_pair.b.source == .binary) continue;
        if (std.mem.eql(u8, &line_iter_pair.a.oid, &line_iter_pair.b.oid)) continue;

        const path_hash = hash.hashInt(repo_opts.hash, line_iter_pair.path);
        var application = PatchApplication(repo_opts){
            .file = try File(repo_opts).load(state.readOnly().extra.moment, snapshot.cursor.readOnly(), allocator, path_hash),
            .edits = .empty,
        };
        defer application.deinit(allocator);
        const file = &application.file;
        // commit snapshots describe chosen text, without conflict alternatives.
        // retained text states have creation gaps; foreign applications may not.
        if (file.has_conflict) return error.ConflictedPatchSnapshot;
        var gap_list: ?File(repo_opts).GapList = null;
        var next_gaps: std.ArrayList(File(repo_opts).Gap) = .empty;
        defer next_gaps.deinit(allocator);

        // create and store the patch. each run of insertions/deletions
        // becomes an edit with its own id and text.
        const patch_hash = blk: {
            if (line_iter_pair.a.source == .binary) {
                // compare to the retained text, even if its blob is no longer stored
                const text = try file.readText(allocator);
                defer allocator.free(text);
                const text_iter = if (file.lines.items.len == 0)
                    try df.LineIterator(.xit, repo_opts).initFromNothing(io, allocator, line_iter_pair.path)
                else
                    try df.LineIterator(.xit, repo_opts).initFromBuffer(io, allocator, line_iter_pair.path, &([_]u8{0} ** hash.byteLen(repo_opts.hash)), null, text);
                line_iter_pair.a.deinit();
                line_iter_pair.a = text_iter;
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
                    old_index += 1;
                    if (gap_list) |list| try next_gaps.append(allocator, list.values[old_index]);
                    next_edit = try diff.next();
                    continue;
                }
                // include records created by earlier edits in this transaction
                file.moment = state.readOnly().extra.moment.*;
                const start = old_index;
                var text_buffer = std.Io.Writer.Allocating.init(allocator);
                defer text_buffer.deinit();
                var offsets: std.ArrayList(u64) = .empty;
                defer offsets.deinit(allocator);
                var text_count: usize = 0;
                // write inserted text as the diff yields it
                while (next_edit) |change| : (next_edit = try diff.next()) {
                    switch (change) {
                        .del => old_index += 1,
                        .ins => |ins| {
                            const line = try line_iter_pair.b.get(ins.new_line.num);
                            defer line_iter_pair.b.free(line);
                            if (text_count > 0 and text_count % File(repo_opts).text_block_size == 0) try offsets.append(allocator, text_buffer.written().len);
                            try writeLengthPrefixedBytes(&text_buffer.writer, line);
                            text_count += 1;
                        },
                        .eql => break,
                    }
                }
                // deletions in this edit are a contiguous slice of the old lines
                const removed = file.lines.items[start..old_index];
                // one-line replacements preserve every gap. load them only when
                // a change needs to split or join boundaries, keeping the old prefix.
                if (gap_list == null and !(removed.len == 1 and text_count == 1)) {
                    const list = try file.readGaps(snapshot.cursor.readOnly(), path_hash);
                    gap_list = list;
                    try next_gaps.appendSlice(allocator, list.values[0 .. start + 1]);
                }
                const gap = if (removed.len == 0) (gap_list orelse unreachable).values[start] else File(repo_opts).Gap{};
                var buffer = std.Io.Writer.Allocating.init(allocator);
                defer buffer.deinit();
                try buffer.writer.writeInt(u32, @intCast(removed.len), .big);
                for (removed) |line| try buffer.writer.writeInt(LineId(repo_opts.hash).Int, line.id, .big);
                if (removed.len == 0) try File(repo_opts).writeGap(&buffer.writer, gap);
                try buffer.writer.writeInt(u32, @intCast(text_count), .big);
                var edit_hasher = hash.Hasher(repo_opts.hash).init(.{});
                edit_hasher.update(buffer.written());
                edit_hasher.update(text_buffer.written());
                var edit_bytes: [hash.byteLen(repo_opts.hash)]u8 = undefined;
                edit_hasher.final(&edit_bytes);
                const id = hash.bytesToInt(repo_opts.hash, &edit_bytes);
                // placement and the seek table aren't part of the edit's identity
                if (removed.len > 0 and text_count > 0) {
                    try writeLengthPrefixedBytes(&buffer.writer, removed[0].position);
                }
                for (offsets.items) |offset| try buffer.writer.writeInt(u64, offset, .big);
                try buffer.writer.writeAll(text_buffer.written());
                var record = try records.putCursor(id);
                if (record.slot().empty()) {
                    try record.write(.{ .bytes = buffer.written() });
                } else {
                    // reused records still need checking; freshly written text was
                    // already hashed above and uses the offsets we just constructed.
                    var scratch = std.heap.ArenaAllocator.init(allocator);
                    defer scratch.deinit();
                    try File(repo_opts).verify(try file.readEdit(id, scratch.allocator()));
                }
                try patch_buffer.writer.writeInt(Id, id, .big);

                // a one-line replacement keeps both exterior gaps
                if (removed.len == 1 and text_count == 1) {
                    if (gap_list) |list| try next_gaps.append(allocator, list.values[old_index]);
                    continue;
                }

                // update the gaps alongside the diff. keep span bounds intact
                // so independent deletions can be combined in either order.
                const gaps = (gap_list orelse unreachable).values;
                if (text_count == 0) {
                    var deps: std.AutoArrayHashMapUnmanaged(Id, void) = .empty;
                    defer deps.deinit(allocator);
                    for (gaps[start .. old_index + 1]) |old_gap| {
                        for (old_gap.deps) |dep| try deps.put(allocator, dep, {});
                    }
                    try deps.put(allocator, id, {});
                    std.mem.sort(Id, deps.keys(), {}, std.sort.asc(Id));
                    const end = gaps[old_index].end orelse gaps[old_index].start;
                    var joined: File(repo_opts).Gap = .{
                        .start = gaps[start].start,
                        .end = end,
                        .deps = try file.arena.allocator().dupe(Id, deps.keys()),
                    };
                    // joining an insertion's exterior gaps reopens its original gap.
                    // matching prefixes and ordinals 0 and 2 * line count identify
                    // both ends of the same insertion. keep deletion dependencies,
                    // but don't nest positions on each cycle.
                    const position_size = hash.byteLen(repo_opts.hash) + 8;
                    if (joined.start.len >= position_size and joined.start.len == end.len and
                        std.mem.eql(u8, joined.start[0 .. end.len - 8], end[0 .. end.len - 8]) and
                        std.mem.readInt(u64, joined.start[end.len - 8 ..][0..8], .big) == 0)
                    {
                        const owner = std.mem.readInt(Id, joined.start[end.len - position_size ..][0..comptime hash.byteLen(repo_opts.hash)], .big);
                        const inserted = try file.readEdit(owner, file.arena.allocator());
                        if (inserted.removed_count == 0 and std.mem.readInt(u64, end[end.len - 8 ..][0..8], .big) == @as(u64, inserted.text_count) * 2) {
                            joined.start = inserted.gap.start;
                            joined.end = inserted.gap.end orelse inserted.gap.start;
                        }
                    }
                    next_gaps.items[next_gaps.items.len - 1] = joined;
                } else {
                    // insertions split a gap; replacements keep the exterior gaps
                    const insertion = removed.len == 0;
                    const parent = if (insertion) try File(repo_opts).resolveGap(gap, file.arena.allocator()) else removed[0].position;
                    const deps = try file.arena.allocator().dupe(Id, &.{id});
                    if (insertion) _ = next_gaps.pop();
                    const first: usize = if (insertion) 0 else 1;
                    const end = if (insertion) text_count + 1 else text_count;
                    for (first..end) |i| try next_gaps.append(allocator, .{
                        .start = try File(repo_opts).position(file.arena.allocator(), parent, id, @as(u64, i) * 2),
                        .deps = deps,
                    });
                    if (!insertion) try next_gaps.append(allocator, gaps[old_index]);
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
        try applyPatchesToFile(repo_opts, &application, allocator, &.{patch_hash}, .create, false);
        try application.save(&snapshot, allocator, line_iter_pair.path, if (gap_list) |list| .{ .write = .{ .before = list.chunks, .after = next_gaps.items } } else .keep);

        // associate patch hash with path/commit
        const fields = try DB.ArrayList(.read_write).init(try snapshot.putCursor(path_hash));
        try fields.put(@intFromEnum(FileField.patch), .{ .bytes = &hash.intToBytes(Id, patch_hash) });
    }

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

pub fn applyPatches(
    comptime opts: rp.RepoOpts(.xit),
    moment: *const rp.Repo(.xit, opts).DB.HashMap(.read_only),
    snapshot: rp.Repo(.xit, opts).DB.Cursor(.read_only),
    allocator: std.mem.Allocator,
    path: []const u8,
    patch_hashes: []const hash.HashInt(opts.hash),
    kind: PatchApplicationKind,
) !PatchApplication(opts) {
    var application = PatchApplication(opts){
        .file = try File(opts).load(moment, snapshot, allocator, hash.hashInt(opts.hash, path)),
        .edits = .empty,
    };
    errdefer application.deinit(allocator);
    if (kind == .create and application.file.has_conflict) return error.ConflictedPatchSnapshot;
    try applyPatchesToFile(opts, &application, allocator, patch_hashes, kind, true);
    return application;
}

// only creation can skip verification, after hashing new records and checking reused ones.
fn applyPatchesToFile(
    comptime opts: rp.RepoOpts(.xit),
    application: *PatchApplication(opts),
    allocator: std.mem.Allocator,
    patch_hashes: []const hash.HashInt(opts.hash),
    kind: PatchApplicationKind,
    verify_edits: bool,
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
        if (verify_edits) try File(opts).verify(edit);
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
        const parent = try File(opts).editParent(edit, file.arena.allocator());
        for (0..edit.text_count) |ordinal| {
            const line: LineId(opts.hash).Int = @bitCast(LineId(opts.hash){ .edit_id = id, .line = @intCast(ordinal) });
            if (!removed.contains(line)) try file.lines.append(file.arena.allocator(), try File(opts).nodeFromEdit(edit, parent, ordinal, file.arena.allocator()));
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

    // reconstruct existing conflict regions against the surviving lines
    if (file.has_conflict) {
        if (file.edits) |edits| {
            var outer = try edits.iterator();
            while (try outer.next()) |entry| {
                const id = (try entry.readKeyValuePair()).hash;
                _ = scratch.reset(.retain_capacity);
                const a = try file.readEdit(id, scratch.allocator());
                const ar = try file.range(a, scratch.allocator());
                var inner = try edits.iterator();
                while (try inner.next()) |other| {
                    const other_id = (try other.readKeyValuePair()).hash;
                    if (other_id <= id) continue;
                    _ = other_arena.reset(.retain_capacity);
                    const b = try file.readEdit(other_id, other_arena.allocator());
                    if (try file.conflict(a, ar, b, other_arena.allocator())) |region| try file.addRegion(region);
                }
            }
        }
    }

    // compare new edits with earlier applied edits and with each other
    for (pending.keys(), 0..) |id, edit_index| {
        _ = scratch.reset(.retain_capacity);
        const edit = try file.readEdit(id, scratch.allocator());
        const edit_range = try file.range(edit, scratch.allocator());
        if (file.edits) |old_edits| {
            var iter = try old_edits.iterator();
            while (try iter.next()) |entry| {
                _ = other_arena.reset(.retain_capacity);
                const other = try file.readEdit((try entry.readKeyValuePair()).hash, other_arena.allocator());
                if (try file.conflict(edit, edit_range, other, other_arena.allocator())) |region| try file.addRegion(region);
            }
        }
        for (pending.keys()[0..edit_index]) |other_id| {
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
    file.has_conflict = file.regions.items.len > 0;
}

pub const PatchApplicationKind = enum { create, merge };

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

        pub fn save(self: *const @This(), snapshot: *const rp.Repo(.xit, opts).DB.HashMap(.read_write), allocator: std.mem.Allocator, path: []const u8, gaps: union(enum) { keep, clear, write: struct { before: []const File(opts).GapChunk, after: []const File(opts).Gap } }) !void {
            // applied ids are scoped to this file: a nonempty patch on a new path
            // always reaches initialization below. repeats preserve the snapshot and gaps.
            if (self.edits.count() == 0) return;
            if (gaps == .write) try self.file.validateGaps(gaps.write.after);
            const DB = rp.Repo(.xit, opts).DB;
            const path_hash = hash.hashInt(opts.hash, path);
            try snapshot.putKey(path_hash, .{ .bytes = path });
            const fields = try DB.ArrayList(.read_write).init(try snapshot.putCursor(path_hash));
            while (try fields.count() < @typeInfo(FileField).@"enum".fields.len) try fields.append(.{ .slot = null });
            const set = try DB.HashSet(.read_write).init(try fields.putCursor(@intFromEnum(FileField.edits)));
            for (self.edits.keys()) |id| try set.put(id, .{ .uint = 1 });
            var buffer = std.Io.Writer.Allocating.init(allocator);
            defer buffer.deinit();
            // keep the alternatives too, so another application can use this snapshot
            try buffer.writer.writeByte(@intFromBool(self.file.has_conflict));
            for (self.file.lines.items) |line| try buffer.writer.writeInt(LineId(opts.hash).Int, line.id, .big);
            try fields.put(@intFromEnum(FileField.lines), .{ .bytes = buffer.written() });
            switch (gaps) {
                .keep => {},
                .clear => {
                    // foreign applications can't inherit the old creation gaps
                    try fields.put(@intFromEnum(FileField.gaps), .{ .slot = null });
                },
                .write => |values| {
                    // update the chunk list in position order, keeping unchanged blobs
                    const list = try DB.LinkedArrayList(.read_write).init(try fields.putCursor(@intFromEnum(FileField.gaps)));
                    if (try list.count() != values.before.len) return error.InvalidGapList;
                    var old_index: usize = 0;
                    var new_index: usize = 0;
                    var start: usize = 0;
                    buffer.clearRetainingCapacity();
                    for (values.after, 0..) |gap, i| {
                        try File(opts).writeGap(&buffer.writer, gap);
                        // stable positions let later chunks remain shared after an
                        // insertion or deletion. cap long runs at 64 gaps.
                        if (i + 1 < values.after.len and i + 1 - start < 64 and std.hash.Wyhash.hash(0, gap.start) & 15 != 0) continue;
                        const chunk_start = values.after[start].start;
                        while (old_index < values.before.len and std.mem.lessThan(u8, values.before[old_index].start, chunk_start)) {
                            try list.remove(@intCast(new_index));
                            old_index += 1;
                        }
                        if (old_index < values.before.len and std.mem.eql(u8, values.before[old_index].start, chunk_start)) {
                            const bytes = try values.before[old_index].cursor.readBytesAlloc(allocator, null);
                            defer allocator.free(bytes);
                            if (!std.mem.eql(u8, bytes, buffer.written())) try list.put(@intCast(new_index), .{ .bytes = buffer.written() });
                            old_index += 1;
                        } else if (old_index == values.before.len) {
                            try list.append(.{ .bytes = buffer.written() });
                        } else {
                            try list.insert(@intCast(new_index), .{ .bytes = buffer.written() });
                        }
                        new_index += 1;
                        start = i + 1;
                        buffer.clearRetainingCapacity();
                    }
                    while (old_index < values.before.len) : (old_index += 1) try list.remove(@intCast(new_index));
                },
            }
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
        const text_block_size = 64;
        pub const Gap = struct { start: []const u8 = "", end: ?[]const u8 = null, deps: []const Id = &.{} };
        pub const GapChunk = struct { start: []const u8, cursor: DB.Cursor(.read_only) };
        const GapList = struct { values: []const Gap, chunks: []const GapChunk };
        const Edit = struct {
            id: Id,
            cursor: DB.Cursor(.read_only),
            removed_count: u32,
            gap: Gap,
            text_count: u32,
            header_end: u64,
            index_start: u64,
            text_start: u64,
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
        regions: std.ArrayList(Region) = .empty,
        has_conflict: bool = false,

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
            if (try snapshot.readPath(void, &.{
                .{ .hash_map_get = .{ .value = path_hash } },
                .{ .array_list_get = @intFromEnum(FileField.lines) },
            })) |cursor| {
                var line_cursor = cursor;
                var buffer: [opts.buffer_size]u8 = undefined;
                var reader = try line_cursor.reader(&buffer);
                const flag = try reader.interface.takeByte();
                if (flag > 1 or (reader.size - 1) % line_size != 0) return error.InvalidLineList;
                self.has_conflict = flag == 1;
                // lines from the same edit share its header and placement. cache
                // only edits with live lines, without reading their historical text.
                var edits: std.AutoHashMapUnmanaged(Id, struct { edit: Edit, parent: []const u8 }) = .empty;
                defer edits.deinit(allocator);
                while (reader.logicalPos() < reader.size) {
                    const id = try reader.interface.takeInt(Line, .big);
                    const line: LineId(opts.hash) = @bitCast(id);
                    const entry = try edits.getOrPut(allocator, line.edit_id);
                    if (!entry.found_existing) {
                        const edit = try self.readEdit(line.edit_id, self.arena.allocator());
                        entry.value_ptr.* = .{ .edit = edit, .parent = try editParent(edit, self.arena.allocator()) };
                    }
                    try self.lines.append(self.arena.allocator(), try nodeFromEdit(entry.value_ptr.edit, entry.value_ptr.parent, line.line, self.arena.allocator()));
                }
            }
            return self;
        }

        pub fn deinit(self: *Self) void {
            const allocator = self.arena.child_allocator;
            for (self.regions.items) |region| {
                allocator.free(region.start);
                allocator.free(region.end);
            }
            self.regions.deinit(allocator);
            self.arena.deinit();
        }

        pub fn contains(self: *const Self, id: Id) !bool {
            const edits = self.edits orelse return false;
            return try edits.getSlot(id) != null;
        }

        pub fn readText(self: *const Self, allocator: std.mem.Allocator) ![]u8 {
            var buffer = std.Io.Writer.Allocating.init(allocator);
            errdefer buffer.deinit();
            var reader = TextReader.init(self, allocator);
            defer reader.deinit();
            for (self.lines.items, 0..) |node_value, i| {
                const text = try reader.readLine(node_value.id, allocator);
                defer allocator.free(text);
                if (i > 0) try buffer.writer.writeByte('\n');
                try buffer.writer.writeAll(text);
            }
            return buffer.toOwnedSlice();
        }

        /// sequential reads share one edit header and buffered cursor. jumps use
        /// the sparse text index, without retaining text from unrequested lines.
        /// must not be copied or moved after the first readLine call.
        pub const TextReader = struct {
            file: *const Self,
            arena: std.heap.ArenaAllocator,
            edit: ?Edit = null,
            reader: DB.Cursor(.read_only).Reader = undefined,
            buffer: [opts.buffer_size]u8 = undefined,
            next_line: u64 = 0,

            pub fn init(file: *const Self, allocator: std.mem.Allocator) @This() {
                return .{ .file = file, .arena = std.heap.ArenaAllocator.init(allocator) };
            }

            pub fn deinit(self: *@This()) void {
                self.arena.deinit();
            }

            pub fn readLine(self: *@This(), id: Line, allocator: std.mem.Allocator) ![]const u8 {
                errdefer self.edit = null;
                const line: LineId(opts.hash) = @bitCast(id);
                const edit_changed = if (self.edit) |edit| edit.id != line.edit_id else true;
                if (edit_changed) {
                    _ = self.arena.reset(.retain_capacity);
                    self.edit = try self.file.readEdit(line.edit_id, self.arena.allocator());
                    // initialize after the reader has its final address: the cursor
                    // reader borrows both our edit cursor and our buffer.
                    const edit = if (self.edit) |*edit| edit else unreachable;
                    self.reader = try edit.cursor.reader(&self.buffer);
                    try self.reader.seekTo(edit.text_start);
                    self.next_line = 0;
                }
                const edit = self.edit orelse unreachable;
                if (line.line >= edit.text_count) return error.InvalidLineId;
                const reader = &self.reader;
                if (line.line != self.next_line) {
                    const block = line.line / text_block_size;
                    const offset = if (block == 0) 0 else blk: {
                        try reader.seekTo(edit.index_start + (block - 1) * 8);
                        break :blk try reader.interface.takeInt(u64, .big);
                    };
                    if (offset > reader.size - edit.text_start) return error.InvalidEdit;
                    try reader.seekTo(edit.text_start + offset);
                    for (0..line.line % text_block_size) |_| {
                        const size = try reader.interface.takeInt(u32, .big);
                        if (size > reader.size -| reader.logicalPos()) return error.InvalidEdit;
                        try reader.seekTo(reader.logicalPos() + size);
                    }
                }
                const size = try reader.interface.takeInt(u32, .big);
                if (size > opts.max_line_size or size > reader.size -| reader.logicalPos()) return error.InvalidEdit;
                const text = try allocator.alloc(u8, size);
                errdefer allocator.free(text);
                try reader.interface.readSliceAll(text);
                self.next_line = @as(u64, line.line) + 1;
                return text;
            }
        };

        // gaps are only needed when creating a patch from a commit snapshot.
        // foreign application results may have lines but no creation gaps.
        fn readGaps(self: *Self, snapshot: DB.Cursor(.read_only), path_hash: Id) !GapList {
            const cursor = (try snapshot.readPath(void, &.{
                .{ .hash_map_get = .{ .value = path_hash } },
                .{ .array_list_get = @intFromEnum(FileField.gaps) },
            })) orelse {
                if (self.edits != null or self.lines.items.len != 0) return error.GapListNotFound;
                return .{ .values = &.{.{}}, .chunks = &.{} };
            };
            const allocator = self.arena.allocator();
            const list = try DB.LinkedArrayList(.read_only).init(cursor);
            const count = try list.count();
            if (count == 0 or count > self.lines.items.len + 1) return error.InvalidGapList;
            const chunks = try allocator.alloc(GapChunk, @intCast(count));
            const gaps = try allocator.alloc(Gap, self.lines.items.len + 1);
            var iter = try list.iterator();
            var index: usize = 0;
            for (chunks) |*chunk| {
                var entry = (try iter.next()) orelse return error.InvalidGapList;
                var buffer: [opts.buffer_size]u8 = undefined;
                var reader = try entry.reader(&buffer);
                const start = index;
                while (reader.logicalPos() < reader.size) {
                    if (index == gaps.len) return error.InvalidGapList;
                    gaps[index] = try readGap(&reader, allocator);
                    index += 1;
                }
                if (index == start or reader.logicalPos() != reader.size) return error.InvalidGapList;
                chunk.* = .{ .start = gaps[start].start, .cursor = entry };
            }
            if (index != gaps.len) return error.InvalidGapList;
            try self.validateGaps(gaps);
            return .{ .values = gaps, .chunks = chunks };
        }

        fn validateGaps(self: *const Self, gaps: []const Gap) !void {
            if (gaps.len != self.lines.items.len + 1) return error.InvalidGapList;
            const position_size = hash.byteLen(opts.hash) + 8;
            for (gaps, 0..) |gap, i| {
                if (gap.start.len % position_size != 0) return error.InvalidGapList;
                if (gap.end) |end| {
                    if (end.len % position_size != 0 or less(end, gap.start)) return error.InvalidGapList;
                    if (end.len > gap.start.len and std.mem.startsWith(u8, end, gap.start)) return error.InvalidGapList;
                }
                if (i > 0 and !less(self.lines.items[i - 1].position, gap.start)) return error.InvalidGapList;
                if (i < self.lines.items.len and !less(gap.end orelse gap.start, self.lines.items[i].position)) return error.InvalidGapList;
                for (gap.deps, 0..) |dep, j| {
                    if (j > 0 and gap.deps[j - 1] >= dep) return error.InvalidGapList;
                }
            }
        }

        fn conflict(self: *const Self, a: Edit, ar: Region, b: Edit, allocator: std.mem.Allocator) !?Region {
            if (a.id == b.id) return null;
            if (a.text_count == 0 and b.text_count == 0) return null;
            const br = try self.range(b, allocator);
            if (!ar.contains(br.start) and !br.contains(ar.start)) return null;
            var overlaps = false;
            if (a.removed_count == 0 and b.removed_count == 0) {
                overlaps = std.mem.eql(u8, ar.start, br.start);
            } else if (a.removed_count > 0 and b.removed_count > 0) {
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
            } else {
                const insertion = if (a.removed_count == 0) a else b;
                const deletion = if (a.removed_count == 0) b else a;
                const region = if (a.removed_count == 0) br else ar;
                const insertion_position = if (a.removed_count == 0) ar.start else br.start;
                if (!less(region.start, insertion_position) or !less(insertion_position, region.end)) return null;
                if (std.mem.indexOfScalar(Id, insertion.gap.deps, deletion.id) != null) return null;

                // nested positions retain earlier replacements, even when
                // the gap only depends directly on a later edit.
                var ancestors = std.Io.Reader.fixed(insertion_position);
                while (ancestors.bufferedLen() > 0) {
                    const id = try ancestors.takeInt(Id, .big);
                    _ = try ancestors.takeInt(u64, .big);
                    if (id == deletion.id) return null;
                }

                // only surviving lines inside the deleted range can compete,
                // including later lines nested inside this insertion.
                const id_bytes = hash.intToBytes(Id, insertion.id);
                const prefix = try std.mem.concat(allocator, u8, &.{ insertion_position, &id_bytes });
                var begin: usize = 0;
                var end = self.lines.items.len;
                while (begin < end) {
                    const middle = begin + (end - begin) / 2;
                    if (less(self.lines.items[middle].position, prefix)) {
                        begin = middle + 1;
                    } else {
                        end = middle;
                    }
                }
                if (begin == self.lines.items.len) return null;
                const pos = self.lines.items[begin].position;
                overlaps = std.mem.startsWith(u8, pos, prefix) and region.contains(pos);
            }
            if (!overlaps) return null;
            return .{ .start = if (less(ar.start, br.start)) ar.start else br.start, .end = if (endsBefore(ar.end, br.end)) br.end else ar.end };
        }

        fn addRegion(self: *Self, value: Region) !void {
            const allocator = self.arena.child_allocator;
            var start: []const u8 = try allocator.dupe(u8, value.start);
            errdefer allocator.free(start);
            var end: []const u8 = try allocator.dupe(u8, value.end);
            errdefer allocator.free(end);
            var i: usize = 0;
            while (i < self.regions.items.len) {
                const region = Region{ .start = start, .end = end };
                const other = self.regions.items[i];
                if (region.contains(other.start) or other.contains(region.start)) {
                    if (less(other.start, start)) {
                        allocator.free(start);
                        start = other.start;
                    } else allocator.free(other.start);
                    if (endsBefore(end, other.end)) {
                        allocator.free(end);
                        end = other.end;
                    } else allocator.free(other.end);
                    _ = self.regions.swapRemove(i);
                    i = 0;
                } else i += 1;
            }
            try self.regions.append(allocator, .{ .start = start, .end = end });
        }

        fn range(self: *const Self, edit: Edit, allocator: std.mem.Allocator) !Region {
            if (edit.removed_count == 0) {
                const pos = try resolveGap(edit.gap, allocator);
                return .{ .start = pos, .end = pos };
            }
            return .{
                .start = (try self.node(try removedAt(edit, 0), allocator)).position,
                .end = (try self.node(try removedAt(edit, edit.removed_count - 1), allocator)).position,
            };
        }

        fn node(self: *const Self, id: Line, allocator: std.mem.Allocator) !Node {
            const line: LineId(opts.hash) = @bitCast(id);
            const edit = try self.readEdit(line.edit_id, allocator);
            return nodeFromEdit(edit, try editParent(edit, allocator), line.line, allocator);
        }

        fn nodeFromEdit(edit: Edit, parent: []const u8, ordinal: u64, allocator: std.mem.Allocator) !Node {
            if (ordinal >= edit.text_count) return error.InvalidLineId;
            return .{
                .id = @bitCast(LineId(opts.hash){ .edit_id = edit.id, .line = @intCast(ordinal) }),
                .position = if (edit.removed_count == 1 and edit.text_count == 1) parent else try position(allocator, parent, edit.id, ordinal * 2 + 1),
            };
        }

        fn editParent(edit: Edit, allocator: std.mem.Allocator) ![]const u8 {
            if (edit.text_count == 0) return error.InvalidLineId;
            if (edit.removed_count == 0) return resolveGap(edit.gap, allocator);
            // replacement placement is shared by all its lines. reading
            // it doesn't require following the edits it replaced.
            var cursor = edit.cursor;
            var buffer: [opts.buffer_size]u8 = undefined;
            var reader = try cursor.reader(&buffer);
            try reader.seekTo(edit.header_end);
            return readBytes(&reader, allocator);
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
            try reader.seekTo(edit.text_start);
            for (0..edit.text_count) |i| {
                if (i > 0 and i % text_block_size == 0) {
                    var index_buffer: [8]u8 = undefined;
                    // cursor readers have independent positions; this seek leaves text alone.
                    var index_reader = try edit.cursor.reader(&index_buffer);
                    try index_reader.seekTo(edit.index_start + (i / text_block_size - 1) * 8);
                    if (try index_reader.interface.takeInt(u64, .big) != reader.logicalPos() - edit.text_start) return error.InvalidEdit;
                }
                const size_bytes = (try reader.interface.takeArray(4)).*;
                hasher.update(&size_bytes);
                remaining = std.mem.readInt(u32, &size_bytes, .big);
                if (remaining > opts.max_line_size) return error.InvalidEdit;
                while (remaining > 0) {
                    const size: usize = @intCast(@min(remaining, buffer.len));
                    hasher.update(try reader.interface.take(size));
                    remaining -= size;
                }
            }
            var result: [hash.byteLen(opts.hash)]u8 = undefined;
            hasher.final(&result);
            if (reader.logicalPos() != reader.size or hash.bytesToInt(opts.hash, &result) != edit.id) return error.InvalidEdit;
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
            const header_end = reader.logicalPos();
            if (removed_count > 0 and text_count > 0) {
                const size = try reader.interface.takeInt(u32, .big);
                if (size % (hash.byteLen(opts.hash) + 8) != 0 or size > reader.size -| reader.logicalPos()) return error.InvalidEdit;
                try reader.seekTo(reader.logicalPos() + size);
            }
            const index_start = reader.logicalPos();
            const text_start = index_start + ((@as(u64, text_count) -| 1) / text_block_size) * 8;
            if (text_start > reader.size or text_count > (reader.size - text_start) / 4) return error.InvalidEdit;
            if (removed_count == 0 and text_count == 0) return error.InvalidEdit;
            return .{ .id = id, .cursor = cursor, .removed_count = removed_count, .gap = gap, .text_count = text_count, .header_end = header_end, .index_start = index_start, .text_start = text_start };
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
            const position_size = hash.byteLen(opts.hash) + 8;
            if (start.len % position_size != 0) return error.InvalidGapList;
            if (end) |value| {
                if (value.len % position_size != 0 or less(value, start)) return error.InvalidGapList;
                if (value.len > start.len and std.mem.startsWith(u8, value, start)) return error.InvalidGapList;
            }
            const count = try reader.interface.takeInt(u32, .big);
            if (count > (reader.size -| reader.logicalPos()) / hash.byteLen(opts.hash)) return error.InvalidEdit;
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

        fn resolveGap(gap: Gap, allocator: std.mem.Allocator) ![]const u8 {
            const end = gap.end orelse return gap.start;
            var hasher = std.Io.Writer.Hashing(hash.Hasher(opts.hash)).init(&.{});
            try hasher.writer.writeAll("gap");
            try writeLengthPrefixedBytes(&hasher.writer, gap.start);
            try writeLengthPrefixedBytes(&hasher.writer, end);
            for (gap.deps) |dep| try hasher.writer.writeInt(Id, dep, .big);
            var bytes: [hash.byteLen(opts.hash)]u8 = undefined;
            hasher.hasher.final(&bytes);
            return position(allocator, gap.start, hash.bytesToInt(opts.hash, &bytes), 0);
        }

        // positions contain (edit id, ordinal) pairs, with even ordinals
        // for gaps and odd ordinals for lines. a nested position sorts
        // after its parent.
        fn position(allocator: std.mem.Allocator, parent: []const u8, id: Id, ordinal: u64) ![]const u8 {
            const result = try allocator.alloc(u8, parent.len + hash.byteLen(opts.hash) + 8);
            @memcpy(result[0..parent.len], parent);
            std.mem.writeInt(Id, result[parent.len..][0..comptime hash.byteLen(opts.hash)], id, .big);
            std.mem.writeInt(u64, result[result.len - 8 ..][0..8], ordinal, .big);
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

        pub const Int = @typeInfo(LineId(hash_kind)).@"struct".backing_integer.?;
    };
}

pub const FileField = enum(u8) { patch, edits, lines, gaps };

fn writeLengthPrefixedBytes(writer: *std.Io.Writer, bytes: []const u8) !void {
    try writer.writeInt(u32, @intCast(bytes.len), .big);
    try writer.writeAll(bytes);
}

pub fn PatchWriter(comptime repo_opts: rp.RepoOpts(.xit)) type {
    return struct {
        const DB = rp.Repo(.xit, repo_opts).DB;
        const db_name = "temp.db";

        repo_dir: std.Io.Dir,
        db_file: std.Io.File,
        db: *DB,
        parent_to_children: DB.HashMap(.read_write),
        oid_queue: std.AutoArrayHashMapUnmanaged([hash.byteLen(repo_opts.hash)]u8, void),
        commit_count: usize,

        pub fn init(state: rp.Repo(.xit, repo_opts).State(.read_only), io: std.Io, allocator: std.mem.Allocator) !PatchWriter(repo_opts) {
            const db_file = try state.core.repo_dir.createFile(io, db_name, .{ .truncate = true, .lock = .exclusive, .read = true });
            errdefer {
                db_file.close(io);
                state.core.repo_dir.deleteFile(io, db_name) catch {};
            }

            const buffer_ptr = try allocator.create(std.Io.Writer.Allocating);
            errdefer allocator.destroy(buffer_ptr);

            buffer_ptr.* = std.Io.Writer.Allocating.init(allocator);
            errdefer buffer_ptr.deinit();

            const db_ptr = try allocator.create(DB);
            errdefer allocator.destroy(db_ptr);
            db_ptr.* = try DB.init(.{ .io = io, .file = db_file, .buffer = buffer_ptr });

            const map = try DB.HashMap(.read_write).init(db_ptr.rootCursor());

            const parent_to_children_cursor = try map.putCursor(hash.hashInt(repo_opts.hash, "parent->children"));
            const parent_to_children = try DB.HashMap(.read_write).init(parent_to_children_cursor);

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
            self.db.core.memory.buffer.deinit();
            allocator.destroy(self.db.core.memory.buffer);
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
                    const children = try DB.HashMap(.read_write).init(children_cursor);
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
                    const children = try DB.HashMap(.read_only).init(children_cursor);
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
