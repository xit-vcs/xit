const std = @import("std");
const hash = @import("./hash.zig");
const rp = @import("./repo.zig");
const obj = @import("./object.zig");

// reordering is a breaking change
const CompressKind = enum(u8) {
    none,
    zlib,
};

pub const FastCdcOpts = struct {
    min_size: usize,
    avg_size: usize,
    max_size: usize,
    normalization: Normalization,

    const Normalization = enum {
        level0,
        level1,
        level2,
        level3,
    };
};

fn FastCdc(comptime opts: FastCdcOpts) type {
    std.debug.assert(opts.min_size > 0);
    std.debug.assert(opts.min_size <= opts.avg_size);
    std.debug.assert(opts.avg_size <= opts.max_size);
    return struct {
        remaining: usize,

        const gear_hash = computeGearHash();
        // in some tests, avg_size will be very low, so we use @max
        // here so that a valid mask is still used
        const bits = std.math.log2(@max(opts.avg_size, 256));
        const normalization = @intFromEnum(opts.normalization);
        // thanks to https://github.com/nlfiedler/fastcdc-rs
        const masks: [26]u64 = .{
            0, // padding
            0, // padding
            0, // padding
            0, // padding
            0, // padding
            0x0000000001804110, // unused except for NC 3
            0x0000000001803110, // 64B
            0x0000000018035100, // 128B
            0x0000001800035300, // 256B
            0x0000019000353000, // 512B
            0x0000590003530000, // 1KB
            0x0000d90003530000, // 2KB
            0x0000d90103530000, // 4KB
            0x0000d90303530000, // 8KB
            0x0000d90313530000, // 16KB
            0x0000d90f03530000, // 32KB
            0x0000d90303537000, // 64KB
            0x0000d90703537000, // 128KB
            0x0000d90707537000, // 256KB
            0x0000d91707537000, // 512KB
            0x0000d91747537000, // 1MB
            0x0000d91767537000, // 2MB
            0x0000d93767537000, // 4MB
            0x0000d93777537000, // 8MB
            0x0000d93777577000, // 16MB
            0x0000db3777577000, // unused except for NC 3
        };
        comptime {
            // each mask's index is its number of one-bits
            for (masks, 0..) |mask, i| if (mask != 0) std.debug.assert(@popCount(mask) == i);
        }
        const mask_s = masks[bits + normalization];
        const mask_l = masks[bits - normalization];

        pub fn init(total_size: usize) FastCdc(opts) {
            return .{
                .remaining = total_size,
            };
        }

        pub fn next(self: *FastCdc(opts), reader: *std.Io.Reader, buffer: *[opts.max_size]u8) !?[]const u8 {
            if (self.remaining == 0) {
                return null;
            } else {
                const chunk = try self.read(reader, buffer);
                self.remaining -= chunk.len;
                return chunk;
            }
        }

        fn read(self: FastCdc(opts), reader: *std.Io.Reader, buffer: *[opts.max_size]u8) ![]const u8 {
            var remaining = self.remaining;
            if (remaining <= opts.min_size) {
                try reader.readSliceAll(buffer[0..remaining]);
                return buffer[0..remaining];
            }

            var center = opts.avg_size;
            if (remaining > opts.max_size) {
                remaining = opts.max_size;
            } else if (remaining < center) {
                center = remaining;
            }

            var index = opts.min_size - 1;
            try reader.readSliceAll(buffer[0..index]);

            // scan the reader's buffered bytes a slice at a time. the small
            // mask is used up to `center` and the large mask after, so the
            // slice is capped at `center` to switch masks at the right byte.
            var h: u64 = 0;
            while (index < remaining) {
                const in_small_zone = index < center;
                const end = if (in_small_zone) center else remaining;
                const mask = if (in_small_zone) mask_s else mask_l;
                const available = try reader.peekGreedy(1);
                const limit = @min(available.len, end - index);
                for (available[0..limit], 1..) |byte, tossed| {
                    buffer[index] = byte;
                    h = (h << 1) +% gear_hash[byte];
                    index += 1;
                    if (h & mask == 0) {
                        reader.toss(tossed);
                        return buffer[0..index];
                    }
                }
                reader.toss(limit);
            }

            return buffer[0..index];
        }

        fn computeGearHash() [256]u64 {
            @setEvalBranchQuota(1_000_000);
            var nums: [256]u64 = undefined;
            for (&nums, 0..) |*num, i| {
                var seed = [_]u8{0} ** 64;
                @memset(&seed, i);

                var buffer = [_]u8{0} ** std.crypto.hash.Md5.digest_length;
                std.crypto.hash.Md5.hash(&seed, &buffer, .{});

                num.* = std.mem.readInt(u64, buffer[0..8], .big);
            }
            return nums;
        }
    };
}

test "fastcdc all zeros" {
    const opts = FastCdcOpts{
        .min_size = 1024,
        .avg_size = 2048,
        .max_size = 4096,
        .normalization = .level1,
    };
    const zero_buffer = [_]u8{0} ** (opts.max_size * 3);
    var reader = std.Io.Reader.fixed(&zero_buffer);
    var iter = FastCdc(opts).init(zero_buffer.len);
    var chunk_buffer = [_]u8{0} ** opts.max_size;
    while (try iter.next(&reader, &chunk_buffer)) |chunk| {
        try std.testing.expectEqual(opts.max_size, chunk.len);
    }
}

test "fastcdc sekien 16k chunks" {
    const opts = FastCdcOpts{
        .min_size = 4096,
        .avg_size = 16384,
        .max_size = 65535,
        .normalization = .level1,
    };
    const buffer = @embedFile("test/data/SekienAkashita.jpg");
    var reader = std.Io.Reader.fixed(buffer);
    var iter = FastCdc(opts).init(buffer.len);
    var chunk_buffer = [_]u8{0} ** opts.max_size;
    const expected_lengths = [_]usize{
        21326,
        17140,
        28084,
        18217,
        24699,
    };
    for (expected_lengths) |expected_length| {
        const actual_chunk = (try iter.next(&reader, &chunk_buffer)).?;
        try std.testing.expectEqual(expected_length, actual_chunk.len);
    }
    try std.testing.expectEqual(0, iter.remaining);
}

test "fastcdc sekien 32k chunks" {
    const opts = FastCdcOpts{
        .min_size = 8192,
        .avg_size = 32768,
        .max_size = 131072,
        .normalization = .level1,
    };
    const buffer = @embedFile("test/data/SekienAkashita.jpg");
    var reader = std.Io.Reader.fixed(buffer);
    var iter = FastCdc(opts).init(buffer.len);
    var chunk_buffer = [_]u8{0} ** opts.max_size;
    const expected_lengths = [_]usize{
        66550,
        42916,
    };
    for (expected_lengths) |expected_length| {
        const actual_chunk = (try iter.next(&reader, &chunk_buffer)).?;
        try std.testing.expectEqual(expected_length, actual_chunk.len);
    }
    try std.testing.expectEqual(0, iter.remaining);
}

test "fastcdc sekien 64k chunks" {
    const opts = FastCdcOpts{
        .min_size = 16384,
        .avg_size = 65536,
        .max_size = 262144,
        .normalization = .level1,
    };
    const buffer = @embedFile("test/data/SekienAkashita.jpg");
    var reader = std.Io.Reader.fixed(buffer);
    var iter = FastCdc(opts).init(buffer.len);
    var chunk_buffer = [_]u8{0} ** opts.max_size;
    const expected_lengths = [_]usize{
        109466,
    };
    for (expected_lengths) |expected_length| {
        const actual_chunk = (try iter.next(&reader, &chunk_buffer)).?;
        try std.testing.expectEqual(expected_length, actual_chunk.len);
    }
    try std.testing.expectEqual(0, iter.remaining);
}

// the fixed-size header at the start of every chunk record:
// the compress kind and the adler32 checksum of the uncompressed chunk
const chunk_record_header_size = @sizeOf(CompressKind) + @sizeOf(u32);

// a chunked object is stored as a list. its first element is a blob with one
// (record size, end offset) entry per chunk, and the rest are slots pointing at
// the chunk records. positions change when the database is compacted, and as
// slots xitdb relocates them itself; sizes and offsets never change. an empty
// object is a chunked object with no chunks.
const stored_entry_size = @sizeOf(u32) + @sizeOf(u64);

// once loaded, chunk info entries contain (record position, record size, end
// offset): the location of the chunk record and its end position within the object.
const chunk_entry_size = @sizeOf(u64) + @sizeOf(u32) + @sizeOf(u64);

// an object that fits in one chunk is stored as its own value: its size, then
// the chunk record. the value carries a format tag, which xitdb records in the
// slot, so it can be told apart from chunk info without reading anything.
// such a chunk is never shared: an object with the same content is the same
// object, and a chunk ending at the end of a file rarely matches another's.
const inline_format_tag = "in".*;
const inline_size_len = @sizeOf(u32);

const ChunkLocation = struct {
    position: u64,
    size: u32,
};

// Return the position of a chunk record's xitdb byte-array header, which
// identifies the record. a record must be written with a byte writer rather
// than `put`, because a short value is kept in its slot and has no position.
pub fn chunkRecordPosition(cursor: anytype) !u64 {
    const slot = cursor.slot();
    if (slot.tag != .bytes) return error.UnexpectedTag;
    return slot.value;
}

// build a chunk record in `buffer`: the record header followed by the
// chunk itself, compressed only if that makes the record smaller
fn makeChunkRecord(
    comptime repo_opts: rp.RepoOpts(.xit),
    chunk: []const u8,
    buffer: *[chunk_record_header_size + repo_opts.extra.chunk_opts.max_size]u8,
) []const u8 {
    var kind = CompressKind.none;
    var payload_len = chunk.len;
    const payload_buffer = buffer[chunk_record_header_size..];

    const len_maybe = compress: {
        // tiny chunks are skipped, both because they can't shrink and because
        // the compressor requires an output buffer larger than 8 bytes.
        if (!repo_opts.extra.compress_chunks or chunk.len <= 8) break :compress null;

        var payload_writer = std.Io.Writer.fixed(payload_buffer[0..chunk.len]);
        var dbuf: [std.compress.flate.max_window_len]u8 = undefined;
        var zlib_stream = std.compress.flate.Compress.init(&payload_writer, &dbuf, .zlib, .default) catch break :compress null;
        zlib_stream.writer.writeAll(chunk) catch break :compress null;
        zlib_stream.finish() catch break :compress null;
        if (payload_writer.end >= chunk.len) break :compress null;

        break :compress payload_writer.end;
    };

    if (len_maybe) |len| {
        kind = .zlib;
        payload_len = len;
    } else {
        @memcpy(payload_buffer[0..chunk.len], chunk);
    }

    buffer[0] = @intFromEnum(kind);
    std.mem.writeInt(u32, buffer[1..chunk_record_header_size], std.hash.Adler32.hash(chunk), .big);
    return buffer[0 .. chunk_record_header_size + payload_len];
}

pub fn writeChunks(
    comptime repo_opts: rp.RepoOpts(.xit),
    state: rp.Repo(.xit, repo_opts).State(.read_write),
    allocator: std.mem.Allocator,
    hashed: anytype,
    object_len: usize,
    object_kind_name: []const u8,
    object_hash_bytes: *[hash.byteLen(repo_opts.hash)]u8,
) !void {
    const DB = rp.Repo(.xit, repo_opts).DB;

    // the oid isn't known until the end, so a chunked object's entries and record slots are kept until then
    var entries = std.Io.Writer.Allocating.init(allocator);
    defer entries.deinit();
    var record_slots: std.ArrayList(@import("xitdb").Slot) = .empty;
    defer record_slots.deinit(allocator);

    // scratch space, left uninitialized because zeroing it costs more than small objects do.
    // the record buffer leaves room for the size that precedes an inline record.
    var chunk_buffer: [repo_opts.extra.chunk_opts.max_size]u8 = undefined;
    var value_buffer: [inline_size_len + chunk_record_header_size + repo_opts.extra.chunk_opts.max_size]u8 = undefined;
    const record_buffer = value_buffer[inline_size_len..];
    var iter = FastCdc(repo_opts.extra.chunk_opts).init(object_len);
    var chunk_maybe = try iter.next(&hashed.reader, &chunk_buffer);

    // when the first chunk is also the last, the object is stored inline. its record
    // is built after the existence check below, since building it compresses the chunk.
    const inline_chunk_maybe: ?[]const u8 = if (chunk_maybe) |chunk|
        (if (iter.remaining == 0) chunk else null)
    else
        null;

    // otherwise its chunks and their locations are written as part of the repo transaction
    if (inline_chunk_maybe == null) {
        const chunk_map_cursor = try state.extra.moment.putCursor(hash.hashInt(repo_opts.hash, "chunk-hash->record"));
        const chunk_map = try DB.HashMap(.read_write).init(chunk_map_cursor);
        var end_offset: u64 = 0;
        while (chunk_maybe) |chunk| : (chunk_maybe = try iter.next(&hashed.reader, &chunk_buffer)) {
            // hash the chunk
            var chunk_hash_bytes = [_]u8{0} ** hash.byteLen(repo_opts.hash);
            try hash.hashBuffer(repo_opts.hash, chunk, &chunk_hash_bytes);
            const chunk_hash_int = hash.bytesToInt(repo_opts.hash, &chunk_hash_bytes);

            // write the chunk record unless it already exists
            const record_slot, const record_size: u64 = if (try chunk_map.getCursor(chunk_hash_int)) |chunk_cursor|
                .{ chunk_cursor.slot(), try chunk_cursor.count() }
            else blk: {
                const record = makeChunkRecord(repo_opts, chunk, record_buffer);
                var chunk_cursor = try chunk_map.putCursor(chunk_hash_int);
                var record_writer = try chunk_cursor.writer(&.{});
                try record_writer.interface.writeAll(record);
                try record_writer.finish();
                break :blk .{ chunk_cursor.slot(), record.len };
            };
            try record_slots.append(allocator, record_slot);

            // write the record's size and the chunk's end offset.
            // note: we are storing the offset at the *end* of this chunk.
            // this is useful so we can find the total size of the object
            // by looking at the last offset.
            end_offset += chunk.len;
            try entries.writer.writeInt(u32, @intCast(record_size), .big);
            try entries.writer.writeInt(u64, end_offset, .big);
        }
    }

    hashed.hasher.final(object_hash_bytes);
    const object_hash = hash.bytesToInt(repo_opts.hash, object_hash_bytes);

    // an object that already exists has its content stored. every commit
    // writes all of its trees, so rewriting them would grow the database each time.
    if (try state.extra.moment.getCursor(hash.hashInt(repo_opts.hash, "object-id->content"))) |existing_cursor| {
        const existing = try DB.HashMap(.read_only).init(existing_cursor);
        if (try existing.getCursor(object_hash) != null) return;
    }

    // the content is written after every chunk record is finished, because
    // xitdb byte writers must be contiguous and cannot be interleaved.
    const object_map_cursor = try state.extra.moment.putCursor(hash.hashInt(repo_opts.hash, "object-id->content"));
    const object_map = try DB.HashMap(.read_write).init(object_map_cursor);
    try object_map.putKey(object_hash, .{ .bytes = object_kind_name });

    if (inline_chunk_maybe) |chunk| {
        const record = makeChunkRecord(repo_opts, chunk, record_buffer);
        std.mem.writeInt(u32, value_buffer[0..inline_size_len], @intCast(object_len), .big);
        try object_map.put(object_hash, .{ .bytes_object = .{ .value = value_buffer[0 .. inline_size_len + record.len], .format_tag = inline_format_tag } });
        return;
    }

    // an empty object has no chunks, so its entries are empty and there are no slots
    const list = try DB.ArrayList(.read_write).init(try object_map.putCursor(object_hash));
    try list.append(.{ .bytes = entries.written() });
    for (record_slots.items) |slot| try list.append(.{ .slot = slot });
}

// find the index of the chunk covering `position` in the object, or null if
// the position is past the last chunk. `chunk_info` holds fixed-size entries
// whose last field is the chunk's end offset, so this is a binary search for
// the first chunk whose end offset is greater than the position.
fn findChunkIndex(
    chunk_info: []const u8,
    position: u64,
) ?usize {
    const end_offset_position = chunk_entry_size - @sizeOf(u64);
    const chunk_count = chunk_info.len / chunk_entry_size;

    var left: usize = 0;
    var right: usize = chunk_count;
    while (left < right) {
        const mid = left + ((right - left) / 2);
        const end_offset = std.mem.readInt(u64, chunk_info[mid * chunk_entry_size + end_offset_position ..][0..@sizeOf(u64)], .big);
        if (position < end_offset) {
            right = mid;
        } else {
            left = mid + 1;
        }
    }

    return if (left < chunk_count) left else null;
}

// where a chunk lives in the object: it starts at `object_offset` and is `len`
// uncompressed bytes long.
pub const ChunkSpan = struct {
    object_offset: u64,
    len: usize,
};

// Read the chunk record at `chunk_index` directly from its database position,
// decompress it into `buf`, and return its span. Callers cache the result so a
// chunk is only read and decompressed once.
pub fn loadChunk(
    comptime repo_opts: rp.RepoOpts(.xit),
    chunk_info: []const u8,
    db: *rp.Repo(.xit, repo_opts).DB,
    chunk_index: usize,
    buf: []u8,
) !ChunkSpan {
    const entry = chunk_info[chunk_index * chunk_entry_size ..][0..chunk_entry_size];
    const record_position = std.mem.readInt(u64, entry[0..@sizeOf(u64)], .big);
    const record_size = std.mem.readInt(u32, entry[@sizeOf(u64)..][0..@sizeOf(u32)], .big);
    const end_offset = std.mem.readInt(u64, entry[chunk_entry_size - @sizeOf(u64) ..], .big);
    const object_offset = if (chunk_index == 0)
        0
    else
        std.mem.readInt(u64, chunk_info[chunk_index * chunk_entry_size - @sizeOf(u64) ..][0..@sizeOf(u64)], .big);
    // offsets come from the database, so a damaged entry must be an error, not a panic
    const chunk_size = std.math.cast(usize, std.math.sub(u64, end_offset, object_offset) catch return error.WrongChunkSize) orelse return error.WrongChunkSize;

    try readRecord(repo_opts, db, record_position + @sizeOf(u64), record_size, chunk_size, buf);
    return .{ .object_offset = object_offset, .len = chunk_size };
}

// read the chunk record that starts at `position`, decompress it into `buf` if
// necessary, and check it against the expected size and the checksum
fn readRecord(
    comptime repo_opts: rp.RepoOpts(.xit),
    db: *rp.Repo(.xit, repo_opts).DB,
    position: u64,
    record_size: u32,
    chunk_size: usize,
    buf: []u8,
) !void {
    var record_buffer: [chunk_record_header_size + repo_opts.extra.chunk_opts.max_size]u8 = undefined;
    if (record_size < chunk_record_header_size or record_size > record_buffer.len or chunk_size > buf.len) return error.WrongChunkSize;
    var reader = db.core.reader();
    try reader.seekTo(position);
    try reader.interface.readSliceAll(record_buffer[0..record_size]);
    const record = record_buffer[0..record_size];

    const compress_kind = std.enums.fromInt(CompressKind, record[0]) orelse return error.InvalidEnumTag;
    const expected_checksum = std.mem.readInt(u32, record[@sizeOf(CompressKind)..chunk_record_header_size], .big);
    const payload = record[chunk_record_header_size..];

    const chunk = switch (compress_kind) {
        .none => payload,
        .zlib => zlib: {
            var payload_reader = std.Io.Reader.fixed(payload);
            var zlib_stream_buffer: [std.compress.flate.max_window_len]u8 = undefined;
            var zlib_stream: std.compress.flate.Decompress = .init(&payload_reader, .zlib, &zlib_stream_buffer);
            var chunk_writer = std.Io.Writer.fixed(buf);
            const size = try zlib_stream.reader.streamRemaining(&chunk_writer);
            break :zlib buf[0..size];
        },
    };

    if (chunk.len != chunk_size) return error.WrongChunkSize;
    if (std.hash.Adler32.hash(chunk) != expected_checksum) return error.WrongChunkChecksum;

    // an uncompressed payload still points into the record, so copy it
    if (compress_kind == .none) @memcpy(buf[0..chunk.len], chunk);
}

pub fn ChunkObjectReader(comptime repo_opts: rp.RepoOpts(.xit)) type {
    return struct {
        db: *rp.Repo(.xit, repo_opts).DB,
        allocator: std.mem.Allocator,
        content_cursor: rp.Repo(.xit, repo_opts).DB.Cursor(.read_only),
        // the object's chunk info entries (chunk location + end offset), built
        // in memory on the first read. It's tiny compared to the object
        // (one entry per chunk, and chunks are thousands of bytes).
        chunk_info: ?[]u8,
        // where the record of an inline object is, instead of chunk info
        inline_record: ?ChunkLocation,
        position: u64,
        header: obj.ObjectHeader,
        // the most recently decompressed chunk and the object range it covers,
        // so reads within one chunk (the common case) are plain memcpys instead
        // of re-reading and re-decompressing it each time. allocated on the
        // first read, because many objects are only opened for their header.
        chunk_cache: []u8,
        cache_start: u64,
        cache_end: u64,

        pub fn init(
            state: rp.Repo(.xit, repo_opts).State(.read_only),
            _: std.Io,
            allocator: std.mem.Allocator,
            oid: *const [hash.hexLen(repo_opts.hash)]u8,
        ) !ChunkObjectReader(repo_opts) {
            // object map
            const object_map_cursor = (try state.extra.moment.getCursor(hash.hashInt(repo_opts.hash, "object-id->content"))) orelse return error.ObjectNotFound;
            const object_map = try rp.Repo(.xit, repo_opts).DB.HashMap(.read_only).init(object_map_cursor);
            var kv_pair = (try object_map.getKeyValuePair(try hash.hexToInt(repo_opts.hash, oid))) orelse return error.ObjectNotFound;

            // object kind name
            var object_kind_name_buffer = [_]u8{0} ** 8;
            const object_kind_name = try kv_pair.key_cursor.readBytes(&object_kind_name_buffer);

            // object size
            var inline_record: ?ChunkLocation = null;
            const value_slot = kv_pair.value_cursor.slot();
            const object_size = if (value_slot.full) blk: {
                // a tagged value is an inline object. one read gets the byte
                // array's length and the object size in front of the record.
                if (value_slot.tag != .bytes) return error.UnexpectedTag;
                var head: [@sizeOf(u64) + inline_size_len]u8 = undefined;
                var reader = state.core.db.core.reader();
                try reader.seekTo(value_slot.value);
                try reader.interface.readSliceAll(&head);
                const value_size = std.mem.readInt(u64, head[0..@sizeOf(u64)], .big);
                const record_size = std.math.cast(u32, std.math.sub(u64, value_size, inline_size_len) catch return error.WrongChunkSize) orelse return error.WrongChunkSize;
                inline_record = .{ .position = value_slot.value + head.len, .size = record_size };
                break :blk std.mem.readInt(u32, head[@sizeOf(u64)..], .big);
            } else blk: {
                // a chunked object. the last end offset in its entries is the object size.
                const list = try rp.Repo(.xit, repo_opts).DB.ArrayList(.read_only).init(kv_pair.value_cursor);
                var entries_cursor = (try list.getCursor(0)) orelse return error.WrongChunkInfoSize;
                var read_buffer: [@sizeOf(u64)]u8 = undefined;
                var reader = try entries_cursor.reader(&read_buffer);
                if (reader.size == 0) break :blk 0;
                if (reader.size < stored_entry_size) return error.WrongChunkInfoSize;
                try reader.seekTo(reader.size - @sizeOf(u64));
                break :blk try reader.interface.takeInt(u64, .big);
            };

            return .{
                .db = &state.core.db,
                .allocator = allocator,
                .content_cursor = kv_pair.value_cursor,
                .chunk_info = null,
                .inline_record = inline_record,
                .position = 0,
                .header = .{
                    .kind = try obj.ObjectKind.init(object_kind_name),
                    .size = object_size,
                },
                .chunk_cache = &.{},
                .cache_start = 0,
                .cache_end = 0,
            };
        }

        pub fn deinit(self: *ChunkObjectReader(repo_opts), _: std.Io, allocator: std.mem.Allocator) void {
            if (self.chunk_info) |chunk_info| allocator.free(chunk_info);
            allocator.free(self.chunk_cache);
        }

        pub fn read(self: *ChunkObjectReader(repo_opts), buf: []u8) !usize {
            var size: usize = 0;
            while (size < buf.len) {
                const read_size = try self.readStep(buf[size..]);
                if (read_size == 0) {
                    break;
                }
                size += read_size;
                self.position += read_size;
            }
            return size;
        }

        fn readStep(self: *ChunkObjectReader(repo_opts), buf: []u8) !usize {
            if (buf.len == 0) return 0;

            // load the chunk that covers the current position when it falls
            // outside the cached range
            if (self.position < self.cache_start or self.position >= self.cache_end) {
                if (self.position >= self.header.size) return 0;

                // no chunk can be larger than the object itself, so small objects
                // (the common case for trees and commits) get a small cache.
                // add 1 so streamRemaining can drain a full-sized chunk
                if (self.chunk_cache.len == 0) {
                    const max_chunk_size: usize = @intCast(@min(self.header.size, repo_opts.extra.chunk_opts.max_size));
                    self.chunk_cache = try self.allocator.alloc(u8, max_chunk_size + 1);
                }

                // an inline object is a single record covering the whole object
                if (self.inline_record) |location| {
                    const object_size = std.math.cast(usize, self.header.size) orelse return error.WrongChunkSize;
                    try readRecord(repo_opts, self.db, location.position, location.size, object_size, self.chunk_cache);
                    self.cache_start = 0;
                    self.cache_end = self.header.size;
                } else {
                    // build the chunk info in memory the first time it's needed, pairing
                    // each stored entry with the position of the record its slot points at
                    const chunk_info = self.chunk_info orelse blk: {
                        const list = try rp.Repo(.xit, repo_opts).DB.ArrayList(.read_only).init(self.content_cursor);
                        var entries_cursor = (try list.getCursor(0)) orelse return error.WrongChunkInfoSize;
                        // read the entries in one call. small reads aren't served from a buffer.
                        var reader = try entries_cursor.reader(&.{});
                        const entries = try self.allocator.alloc(u8, std.math.cast(usize, reader.size) orelse return error.WrongChunkInfoSize);
                        defer self.allocator.free(entries);
                        try reader.interface.readSliceAll(entries);
                        const chunk_count = entries.len / stored_entry_size;
                        if (entries.len % stored_entry_size != 0 or chunk_count + 1 != try list.count()) return error.WrongChunkInfoSize;
                        const chunk_info = try self.allocator.alloc(u8, chunk_count * chunk_entry_size);
                        errdefer self.allocator.free(chunk_info);
                        var records = try list.iteratorFrom(1);
                        for (0..chunk_count) |index| {
                            const record_cursor = (try records.next()) orelse return error.WrongChunkInfoSize;
                            const entry = chunk_info[index * chunk_entry_size ..][0..chunk_entry_size];
                            std.mem.writeInt(u64, entry[0..@sizeOf(u64)], try chunkRecordPosition(record_cursor), .big);
                            @memcpy(entry[@sizeOf(u64)..], entries[index * stored_entry_size ..][0..stored_entry_size]);
                        }
                        self.chunk_info = chunk_info;
                        break :blk chunk_info;
                    };

                    const chunk_index = findChunkIndex(chunk_info, self.position) orelse return 0;
                    const span = try loadChunk(repo_opts, chunk_info, self.db, chunk_index, self.chunk_cache);
                    self.cache_start = span.object_offset;
                    self.cache_end = span.object_offset + span.len;
                }
                if (self.position < self.cache_start or self.position >= self.cache_end) return 0;
            }

            // serve straight from the cache
            const off: usize = @intCast(self.position - self.cache_start);
            const avail: usize = @intCast(self.cache_end - self.position);
            const read_size = @min(buf.len, avail);
            @memcpy(buf[0..read_size], self.chunk_cache[off .. off + read_size]);
            return read_size;
        }

        pub fn reset(self: *ChunkObjectReader(repo_opts)) !void {
            try self.seekTo(0);
        }

        pub fn seekTo(self: *ChunkObjectReader(repo_opts), offset: u64) !void {
            self.position = offset;
        }

        pub fn skipBytes(self: *ChunkObjectReader(repo_opts), num_bytes: u64) void {
            self.position += num_bytes;
        }
    };
}
