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

            var h: u64 = 0;
            while (index < center) {
                const byte = try reader.takeByte();
                buffer[index] = byte;
                h = (h << 1) +% gear_hash[byte];
                index += 1;
                if (h & mask_s == 0) {
                    return buffer[0..index];
                }
            }

            const last_pos = remaining;
            while (index < last_pos) {
                const byte = try reader.takeByte();
                buffer[index] = byte;
                h = (h << 1) +% gear_hash[byte];
                index += 1;
                if (h & mask_l == 0) {
                    return buffer[0..index];
                }
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

// chunk info entries contain (record offset, record size, end offset):
// the location of the chunk record in the chunk store file, and the end
// position of the chunk within the object
const chunk_entry_size = @sizeOf(u64) + @sizeOf(u32) + @sizeOf(u64);

// where a chunk record lives in the chunk store file
const ChunkLocation = struct {
    offset: u64,
    size: u32,
};

// a chunk record is stored in the chunk store as a xitdb byte array:
// a u64 length header followed by the bytes themselves, laid out
// contiguously. the record's location can therefore be derived from the
// cursor's slot, allowing readers to find it with a single positional read.
pub fn chunkRecordOffset(cursor: anytype) !u64 {
    const slot = cursor.slot();
    // byte arrays small enough to be inlined into the slot (short_bytes)
    // have no file location, so they must never be used for chunk records
    if (slot.tag != .bytes) return error.UnexpectedTag;
    return slot.value + @sizeOf(u64);
}

fn chunkLocation(cursor: anytype, size: u64) !ChunkLocation {
    return .{
        .offset = try chunkRecordOffset(cursor),
        .size = @intCast(size),
    };
}

// collect the chunk store offset of every record referenced by a chunk
// info buffer. used by gc to find the records that must be kept.
pub fn collectRecordOffsets(chunk_info: []const u8, offsets: *std.AutoHashMap(u64, void)) !void {
    if (chunk_info.len % chunk_entry_size != 0) return error.WrongChunkInfoSize;
    var position: usize = 0;
    while (position < chunk_info.len) : (position += chunk_entry_size) {
        const record_offset = std.mem.readInt(u64, chunk_info[position..][0..@sizeOf(u64)], .big);
        try offsets.put(record_offset, {});
    }
}

// rewrite every record offset in a chunk info buffer using the offset map
// produced by compacting the chunk store
pub fn rewriteRecordOffsets(chunk_info: []u8, offset_map: *const std.AutoHashMap(u64, u64)) !void {
    if (chunk_info.len % chunk_entry_size != 0) return error.WrongChunkInfoSize;
    var position: usize = 0;
    while (position < chunk_info.len) : (position += chunk_entry_size) {
        const record_offset = std.mem.readInt(u64, chunk_info[position..][0..@sizeOf(u64)], .big);
        const new_position = offset_map.get(record_offset - @sizeOf(u64)) orelse return error.ChunkNotFound;
        std.mem.writeInt(u64, chunk_info[position..][0..@sizeOf(u64)], new_position + @sizeOf(u64), .big);
    }
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
        var dbuf = [_]u8{0} ** std.compress.flate.max_window_len;
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
    io: std.Io,
    hashed: anytype,
    object_len: usize,
    object_kind_name: []const u8,
    object_hash_bytes: *[hash.byteLen(repo_opts.hash)]u8,
) !void {
    const DB = rp.Repo(.xit, repo_opts).DB;

    // get a writer to the value slot
    var temp_chunk_info_cursor = try state.extra.moment.putCursor(hash.hashInt(repo_opts.hash, "object.temp"));
    var write_buffer: [repo_opts.buffer_size]u8 = undefined;
    var writer = try temp_chunk_info_cursor.writer(&write_buffer);

    // write the chunks to the chunk store and their locations to the chunk info
    {
        const Ctx = struct {
            hashed: @TypeOf(hashed),
            object_len: usize,
            chunk_info_writer: *DB.Cursor(.read_write).Writer,

            pub fn run(ctx: @This(), cursor: *DB.Cursor(.read_write)) !void {
                const chunk_map = try DB.HashMap(.read_write).init(cursor.*);

                var chunk_buffer = [_]u8{0} ** repo_opts.extra.chunk_opts.max_size;
                var record_buffer = [_]u8{0} ** (chunk_record_header_size + repo_opts.extra.chunk_opts.max_size);
                var iter = FastCdc(repo_opts.extra.chunk_opts).init(ctx.object_len);
                var end_offset: u64 = 0;
                var wrote_chunk = false;
                while (try iter.next(&ctx.hashed.reader, &chunk_buffer)) |chunk| {
                    // hash the chunk
                    var chunk_hash_bytes = [_]u8{0} ** hash.byteLen(repo_opts.hash);
                    try hash.hashBuffer(repo_opts.hash, chunk, &chunk_hash_bytes);
                    const chunk_hash_int = hash.bytesToInt(repo_opts.hash, &chunk_hash_bytes);

                    // write the chunk record unless it already exists
                    const location = if (try chunk_map.getCursor(chunk_hash_int)) |chunk_cursor|
                        try chunkLocation(chunk_cursor, try chunk_cursor.count())
                    else blk: {
                        const record = makeChunkRecord(repo_opts, chunk, &record_buffer);
                        var chunk_cursor = try chunk_map.putCursor(chunk_hash_int);
                        var record_writer = try chunk_cursor.writer(&.{});
                        try record_writer.interface.writeAll(record);
                        try record_writer.finish();
                        wrote_chunk = true;
                        break :blk try chunkLocation(chunk_cursor, record.len);
                    };

                    // write the chunk's location and end offset.
                    // note: we are storing the offset at the *end* of this chunk.
                    // this is useful so we can find the total size of the object
                    // by looking at the last offset.
                    end_offset += chunk.len;
                    try ctx.chunk_info_writer.interface.writeInt(u64, location.offset, .big);
                    try ctx.chunk_info_writer.interface.writeInt(u32, location.size, .big);
                    try ctx.chunk_info_writer.interface.writeInt(u64, end_offset, .big);
                }

                if (!wrote_chunk) return error.CancelTransaction;
            }
        };

        try state.core.chunk_store_file.lock(io, .exclusive);
        defer state.core.chunk_store_file.unlock(io);

        const store_history = try DB.ArrayList(.read_write).init(state.core.chunk_store_db.rootCursor());
        store_history.appendContext(
            .{ .slot = try store_history.getSlot(-1) },
            Ctx{ .hashed = hashed, .object_len = object_len, .chunk_info_writer = &writer },
        ) catch |err| switch (err) {
            error.CancelTransaction => {},
            else => |e| return e,
        };
    }

    // finish writing to db
    try writer.finish();

    hashed.hasher.final(object_hash_bytes);

    // write slot to the map
    const blob_id_to_chunk_info_cursor = try state.extra.moment.putCursor(hash.hashInt(repo_opts.hash, "object-id->chunk-info"));
    const blob_id_to_chunk_info = try rp.Repo(.xit, repo_opts).DB.HashMap(.read_write).init(blob_id_to_chunk_info_cursor);

    const object_hash = hash.bytesToInt(repo_opts.hash, object_hash_bytes);
    try blob_id_to_chunk_info.putKey(object_hash, .{ .bytes = object_kind_name });
    try blob_id_to_chunk_info.put(object_hash, .{ .slot = temp_chunk_info_cursor.slot() });

    // remove temp object
    _ = try state.extra.moment.remove(hash.hashInt(repo_opts.hash, "object.temp"));
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

// read the chunk record at `chunk_index` from the chunk store file with a
// single positional read, decompress it into `buf` (which must be at least
// one byte larger than the object's largest chunk, so at most
// chunk_opts.max_size + 1 bytes) and return its span. callers cache the
// result so a chunk is only read and decompressed once even when the
// object is scanned line by line.
pub fn loadChunk(
    comptime repo_opts: rp.RepoOpts(.xit),
    chunk_info: []const u8,
    io: std.Io,
    chunk_store_file: std.Io.File,
    chunk_index: usize,
    buf: []u8,
) !ChunkSpan {
    // find the chunk's location in the chunk store and its span in the object.
    // since entries store *end* offsets, the offset of this chunk is the
    // end offset of the previous one.
    const entry = chunk_info[chunk_index * chunk_entry_size ..][0..chunk_entry_size];
    const record_offset = std.mem.readInt(u64, entry[0..@sizeOf(u64)], .big);
    const record_size = std.mem.readInt(u32, entry[@sizeOf(u64)..][0..@sizeOf(u32)], .big);
    const end_offset = std.mem.readInt(u64, entry[chunk_entry_size - @sizeOf(u64) ..], .big);
    const object_offset = if (chunk_index == 0)
        0
    else
        std.mem.readInt(u64, chunk_info[chunk_index * chunk_entry_size - @sizeOf(u64) ..][0..@sizeOf(u64)], .big);
    const chunk_size: usize = @intCast(end_offset - object_offset);

    // read the whole chunk record with a single positional read
    var reader_buffer = [_]u8{0} ** (chunk_record_header_size + repo_opts.extra.chunk_opts.max_size);
    if (record_size < chunk_record_header_size or record_size > reader_buffer.len or chunk_size > buf.len) {
        return error.WrongChunkSize;
    }
    var reader = chunk_store_file.reader(io, &reader_buffer);
    try reader.seekTo(record_offset);
    const record = try reader.interface.take(record_size);

    // parse the record header
    const compress_kind = std.enums.fromInt(CompressKind, record[0]) orelse return error.InvalidEnumTag;
    const expected_checksum = std.mem.readInt(u32, record[@sizeOf(CompressKind)..chunk_record_header_size], .big);
    const payload = record[chunk_record_header_size..];

    // get the chunk, decompressing if necessary
    const chunk = switch (compress_kind) {
        .none => payload,
        .zlib => zlib: {
            var payload_reader = std.Io.Reader.fixed(payload);
            var zlib_stream_buffer = [_]u8{0} ** std.compress.flate.max_window_len;
            var zlib_stream: std.compress.flate.Decompress = .init(&payload_reader, .zlib, &zlib_stream_buffer);
            var chunk_writer = std.Io.Writer.fixed(buf);
            const size = try zlib_stream.reader.streamRemaining(&chunk_writer);
            break :zlib buf[0..size];
        },
    };

    if (chunk.len != chunk_size) {
        return error.WrongChunkSize;
    }
    if (std.hash.Adler32.hash(chunk) != expected_checksum) {
        return error.WrongChunkChecksum;
    }

    // uncompressed payloads still point into the reader buffer,
    // so they must be copied into `buf`
    if (compress_kind == .none) {
        @memcpy(buf[0..chunk.len], chunk);
    }

    return .{ .object_offset = object_offset, .len = chunk.len };
}

pub fn ChunkObjectReader(comptime repo_opts: rp.RepoOpts(.xit)) type {
    return struct {
        io: std.Io,
        chunk_store_file: std.Io.File,
        allocator: std.mem.Allocator,
        chunk_info_cursor: rp.Repo(.xit, repo_opts).DB.Cursor(.read_only),
        // the object's chunk info entries (chunk location + end offset),
        // read into memory on the first read so that finding chunks never
        // has to touch the db again. it's tiny compared to the object
        // (one entry per chunk, and chunks are thousands of bytes).
        chunk_info: ?[]u8,
        position: u64,
        header: obj.ObjectHeader,
        // the most recently decompressed chunk and the object range it covers,
        // so reads within one chunk (the common case) are plain memcpys instead
        // of re-opening the chunk file and re-decompressing it each time
        chunk_cache: []u8,
        cache_start: u64,
        cache_end: u64,

        pub fn init(
            state: rp.Repo(.xit, repo_opts).State(.read_only),
            io: std.Io,
            allocator: std.mem.Allocator,
            oid: *const [hash.hexLen(repo_opts.hash)]u8,
        ) !ChunkObjectReader(repo_opts) {
            // chunk info map
            const object_id_to_chunk_info_cursor = (try state.extra.moment.getCursor(hash.hashInt(repo_opts.hash, "object-id->chunk-info"))) orelse return error.ObjectNotFound;
            const object_id_to_chunk_info = try rp.Repo(.xit, repo_opts).DB.HashMap(.read_only).init(object_id_to_chunk_info_cursor);
            var chunk_info_kv_pair = (try object_id_to_chunk_info.getKeyValuePair(try hash.hexToInt(repo_opts.hash, oid))) orelse return error.ObjectNotFound;

            // object kind name
            var object_kind_name_buffer = [_]u8{0} ** 8;
            const object_kind_name = try chunk_info_kv_pair.key_cursor.readBytes(&object_kind_name_buffer);

            // object size
            const object_size = blk: {
                var read_buffer: [repo_opts.buffer_size]u8 = undefined;
                var reader = try chunk_info_kv_pair.value_cursor.reader(&read_buffer);
                if (reader.size == 0) {
                    break :blk 0;
                } else {
                    // the last 8 bytes in the chunk info contain the object size
                    try reader.seekTo(reader.size - @sizeOf(u64));
                    break :blk try reader.interface.takeInt(u64, .big);
                }
            };

            // no chunk can be larger than the object itself, so small objects
            // (the common case for trees and commits) get a small cache.
            // add 1 so streamRemaining can drain a full-sized chunk
            const max_chunk_size: usize = @intCast(@min(object_size, repo_opts.extra.chunk_opts.max_size));
            const chunk_cache = try allocator.alloc(u8, max_chunk_size + 1);
            errdefer allocator.free(chunk_cache);

            return .{
                .io = io,
                .chunk_store_file = state.core.chunk_store_file,
                .allocator = allocator,
                .chunk_info_cursor = chunk_info_kv_pair.value_cursor,
                .chunk_info = null,
                .position = 0,
                .header = .{
                    .kind = try obj.ObjectKind.init(object_kind_name),
                    .size = object_size,
                },
                .chunk_cache = chunk_cache,
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
                // read the chunk info into memory the first time it's needed
                const chunk_info = self.chunk_info orelse blk: {
                    var read_buffer: [repo_opts.buffer_size]u8 = undefined;
                    var reader = try self.chunk_info_cursor.reader(&read_buffer);
                    const chunk_info = try self.allocator.alloc(u8, @intCast(reader.size));
                    errdefer self.allocator.free(chunk_info);
                    try reader.interface.readSliceAll(chunk_info);
                    self.chunk_info = chunk_info;
                    break :blk chunk_info;
                };

                const chunk_index = findChunkIndex(chunk_info, self.position) orelse return 0;
                const span = try loadChunk(repo_opts, chunk_info, self.io, self.chunk_store_file, chunk_index, self.chunk_cache);
                self.cache_start = span.object_offset;
                self.cache_end = span.object_offset + span.len;
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
