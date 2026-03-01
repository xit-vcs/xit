const std = @import("std");
const hash = @import("./hash.zig");
const rp = @import("./repo.zig");
const obj = @import("./object.zig");

pub const PackReader = union(enum) {
    file: struct {
        io: std.Io,
        allocator: std.mem.Allocator,
        dir: std.Io.Dir,
        file_name: []const u8,
        buffer_size: usize,
        file: std.Io.File,
        file_reader: *std.Io.File.Reader,
        file_reader_buffer: []u8,
    },
    stream: struct {
        file_reader: *std.Io.File.Reader,
    },

    const buffer_size = 4 * 1024;

    pub fn initFile(io: std.Io, allocator: std.mem.Allocator, dir: std.Io.Dir, file_name: []const u8) !PackReader {
        const file = try dir.openFile(io, file_name, .{ .mode = .read_only });
        errdefer file.close(io);

        const buffer = try allocator.alloc(u8, buffer_size);
        errdefer allocator.free(buffer);

        const file_reader = try allocator.create(std.Io.File.Reader);
        errdefer allocator.destroy(file_reader);
        file_reader.* = file.reader(io, buffer);

        var dir_copy = try dir.openDir(io, ".", .{});
        errdefer dir_copy.close(io);

        const file_name_copy = try allocator.dupe(u8, file_name);
        errdefer allocator.free(file_name_copy);

        return .{
            .file = .{
                .io = io,
                .allocator = allocator,
                .dir = dir_copy,
                .file_name = file_name_copy,
                .buffer_size = buffer_size,
                .file = file,
                .file_reader = file_reader,
                .file_reader_buffer = buffer,
            },
        };
    }

    pub fn initStream(rdr: *std.Io.File.Reader) PackReader {
        return .{
            .stream = .{
                .file_reader = rdr,
            },
        };
    }

    pub fn deinit(self: *PackReader) void {
        switch (self.*) {
            .file => |*file| {
                file.dir.close(file.io);
                file.allocator.free(file.file_name);
                file.file.close(file.io);
                file.allocator.free(file.file_reader_buffer);
                file.allocator.destroy(file.file_reader);
            },
            .stream => {},
        }
    }

    pub fn dupe(self: *const PackReader) !PackReader {
        switch (self.*) {
            .file => |*file| return try .initFile(file.io, file.allocator, file.dir, file.file_name),
            .stream => |*stream| return .initStream(stream.file_reader),
        }
    }

    pub fn seekTo(self: *PackReader, position: u64) !void {
        switch (self.*) {
            .file => |*file| try file.file_reader.seekTo(position),
            // stream-based PackReaders can't seek, so unless we are trying to seek
            // to the position that we are already at, we have to return an error
            .stream => |*stream| if (position != stream.file_reader.logicalPos()) {
                return error.Unseekable;
            },
        }
    }

    pub fn logicalPos(self: *const PackReader) u64 {
        switch (self.*) {
            .file => |*file| return file.file_reader.logicalPos(),
            .stream => |*stream| return stream.file_reader.logicalPos(),
        }
    }

    pub fn reader(self: *PackReader) *std.Io.Reader {
        switch (self.*) {
            .file => |*file| return &file.file_reader.interface,
            .stream => |*stream| return &stream.file_reader.interface,
        }
    }
};

pub fn PackIterator(comptime repo_kind: rp.RepoKind, comptime repo_opts: rp.RepoOpts(repo_kind)) type {
    return struct {
        io: std.Io,
        allocator: std.mem.Allocator,
        pack_reader: *PackReader,
        start_position: u64,
        object_count: u32,
        object_index: u32,
        pack_obj_rdr: ?PackObjectReader(repo_kind, repo_opts),

        pub fn init(io: std.Io, allocator: std.mem.Allocator, pack_reader: *PackReader) !PackIterator(repo_kind, repo_opts) {
            // parse header
            const sig = try pack_reader.reader().takeArray(4);
            if (!std.mem.eql(u8, "PACK", sig)) {
                return error.InvalidPackFileSig;
            }
            const version = try pack_reader.reader().takeInt(u32, .big);
            if (version != 2) {
                return error.InvalidPackFileVersion;
            }
            const obj_count = try pack_reader.reader().takeInt(u32, .big);

            return .{
                .io = io,
                .allocator = allocator,
                .pack_reader = pack_reader,
                .start_position = pack_reader.logicalPos(),
                .object_count = obj_count,
                .object_index = 0,
                .pack_obj_rdr = null,
            };
        }

        pub fn next(
            self: *PackIterator(repo_kind, repo_opts),
            state: rp.Repo(repo_kind, repo_opts).State(.read_only),
            offset_to_oid_maybe: ?*std.AutoArrayHashMap(u64, [hash.byteLen(repo_opts.hash)]u8),
        ) !?*PackObjectReader(repo_kind, repo_opts) {
            if (self.object_index == self.object_count) {
                return null;
            }

            if (self.pack_obj_rdr) |*pack_obj_rdr| {
                if (pack_obj_rdr.stream.end_position) |end_pos| {
                    self.start_position = end_pos;
                } else {
                    return error.PackObjectReaderNotDeinited;
                }
            }

            const start_position = self.start_position;

            var pack_obj_rdr = try PackObjectReader(repo_kind, repo_opts).initAtPosition(self.io, self.allocator, self.pack_reader, start_position);
            errdefer pack_obj_rdr.deinit(self.io, self.allocator);

            switch (pack_obj_rdr.internal) {
                .basic => {},
                .delta => |*delta| switch (delta.init) {
                    .ofs => |*ofs| {
                        // `offset_to_oid` lets you look up the oid of  the object at
                        // the given offset. this is possible if we are writing each
                        // object in the pack file as loose objects. it allows us to
                        // turn ofs_delta objects into ref_delta objects (i.e., they
                        // read their base object as a loose object rather than trying
                        // to read it from this pack file). this is especially important
                        // for stream-based PackReaders, because they can't seek, so
                        // reading it from a loose object is the easiest thing to do.
                        if (offset_to_oid_maybe) |offset_to_oid| {
                            if (offset_to_oid.get(ofs.position)) |*oid| {
                                delta.init = .{
                                    .ref = .{
                                        .oid_hex = std.fmt.bytesToHex(oid.*, .lower),
                                    },
                                };
                            }
                        }
                        try pack_obj_rdr.initDeltaAndCache(self.io, self.allocator, state);
                    },
                    .ref => try pack_obj_rdr.initDeltaAndCache(self.io, self.allocator, state),
                },
            }

            self.object_index += 1;

            self.pack_obj_rdr = pack_obj_rdr;
            return &(self.pack_obj_rdr orelse unreachable);
        }
    };
}

/// used as the type for base objects within delta objects. this is necessary
/// because ref delta objects just contain an oid and must be looked up in
/// the backend's object store. for the xit backend, that means it needs to
/// look it up in the chunk object store. the git backend will never do that,
/// which is why you see all those `unreachable`s.
fn GitOrXitObjectReader(comptime repo_kind: rp.RepoKind, comptime repo_opts: rp.RepoOpts(repo_kind)) type {
    return union(enum) {
        git: LooseOrPackObjectReader(repo_kind, repo_opts),
        xit: ChunkObjectReader,

        const ChunkObjectReader = switch (repo_kind) {
            .git => void,
            .xit => @import("./chunk.zig").ChunkObjectReader(repo_opts),
        };

        pub fn deinit(self: *GitOrXitObjectReader(repo_kind, repo_opts), io: std.Io, allocator: std.mem.Allocator) void {
            switch (self.*) {
                .git => |*loose_or_pack| loose_or_pack.deinit(io, allocator),
                .xit => |*chunk_reader| switch (repo_kind) {
                    .git => unreachable,
                    .xit => chunk_reader.deinit(io, allocator),
                },
            }
        }

        pub fn header(self: *const GitOrXitObjectReader(repo_kind, repo_opts)) obj.ObjectHeader {
            return switch (self.*) {
                .git => |*loose_or_pack| loose_or_pack.header(),
                .xit => |*chunk_reader| switch (repo_kind) {
                    .git => unreachable,
                    .xit => chunk_reader.header,
                },
            };
        }

        pub fn reset(self: *GitOrXitObjectReader(repo_kind, repo_opts)) anyerror!void {
            switch (self.*) {
                .git => |*loose_or_pack| try loose_or_pack.reset(),
                .xit => |*chunk_reader| switch (repo_kind) {
                    .git => unreachable,
                    .xit => try chunk_reader.reset(),
                },
            }
        }

        pub fn position(self: *const GitOrXitObjectReader(repo_kind, repo_opts)) u64 {
            return switch (self.*) {
                .git => |*loose_or_pack| switch (loose_or_pack.*) {
                    .loose => 0,
                    .pack => |*pack| switch (pack.internal) {
                        .basic => pack.relative_position,
                        .delta => |delta| if (delta.state) |base_delta_state|
                            base_delta_state.real_position
                        else
                            unreachable,
                    },
                },
                .xit => |*chunk_reader| switch (repo_kind) {
                    .git => unreachable,
                    .xit => chunk_reader.position,
                },
            };
        }

        pub fn skipBytes(self: *GitOrXitObjectReader(repo_kind, repo_opts), num_bytes: u64) !void {
            switch (self.*) {
                .git => |*loose_or_pack| try loose_or_pack.skipBytes(num_bytes),
                .xit => |*chunk_reader| switch (repo_kind) {
                    .git => unreachable,
                    .xit => chunk_reader.skipBytes(num_bytes),
                },
            }
        }

        pub fn read(self: *GitOrXitObjectReader(repo_kind, repo_opts), buf: []u8) !usize {
            return switch (self.*) {
                .git => |*loose_or_pack| try loose_or_pack.read(buf),
                .xit => |*chunk_reader| switch (repo_kind) {
                    .git => unreachable,
                    .xit => try chunk_reader.read(buf),
                },
            };
        }
    };
}

const PackObjectKind = enum(u3) {
    commit = 1,
    tree = 2,
    blob = 3,
    tag = 4,
    ofs_delta = 6,
    ref_delta = 7,
};

const PackObjectHeader = packed struct {
    size: u4,
    kind: PackObjectKind,
    extra: bool,
};

const PackObjectStream = struct {
    io: std.Io,
    allocator: std.mem.Allocator,
    pack_reader: *PackReader,
    object_stream: union(enum) {
        zlib: struct {
            stream: *std.compress.flate.Decompress,
            stream_buffer: []u8,

            fn deinit(self: *@This(), allocator: std.mem.Allocator) void {
                allocator.destroy(self.stream);
                allocator.free(self.stream_buffer);
            }
        },
        memory: struct {
            buffer: []u8,
            interface: std.Io.Reader,
            end_position: u64,

            fn deinit(self: *@This(), allocator: std.mem.Allocator) void {
                allocator.free(self.buffer);
            }
        },
    },
    start_position: u64,
    // this is set during deinit for the sake of the PackIterator.
    // it reads this field after deinit to see where the zlib data ended.
    end_position: ?u64 = null,

    fn init(
        io: std.Io,
        allocator: std.mem.Allocator,
        pack_reader_orig: *PackReader,
        start_position: u64,
    ) !PackObjectStream {
        const pack_reader = try allocator.create(PackReader);
        errdefer allocator.destroy(pack_reader);

        pack_reader.* = try pack_reader_orig.dupe();
        errdefer pack_reader.deinit();

        try pack_reader.seekTo(start_position);

        const zlib_stream_buffer = try allocator.alloc(u8, std.compress.flate.max_window_len);
        errdefer allocator.free(zlib_stream_buffer);

        const zlib_stream = try allocator.create(std.compress.flate.Decompress);
        errdefer allocator.destroy(zlib_stream);
        zlib_stream.* = .init(pack_reader.reader(), .zlib, zlib_stream_buffer);

        return .{
            .io = io,
            .allocator = allocator,
            .pack_reader = pack_reader,
            .object_stream = .{
                .zlib = .{
                    .stream = zlib_stream,
                    .stream_buffer = zlib_stream_buffer,
                },
            },
            .start_position = start_position,
        };
    }

    fn deinit(self: *PackObjectStream) void {
        if (self.getEndPos()) |end_pos| {
            self.end_position = end_pos;
        } else |_| {}
        self.pack_reader.deinit();
        self.allocator.destroy(self.pack_reader);
        switch (self.object_stream) {
            .zlib => |*zlib| zlib.deinit(self.allocator),
            .memory => |*memory| memory.deinit(self.allocator),
        }
    }

    pub fn readIntoMemoryMaybe(self: *PackObjectStream, allocator: std.mem.Allocator, object_size: u64) !void {
        switch (self.pack_reader.*) {
            .file => {
                switch (self.object_stream) {
                    .zlib => |*zlib| {
                        // objects larger than this (in bytes) will not be read entirely into memory
                        const max_buffer_size = 50_000_000;

                        if (object_size <= max_buffer_size) {
                            try self.reset();

                            const buffer = try allocator.alloc(u8, object_size);
                            errdefer allocator.free(buffer);

                            var bytes_read: usize = 0;
                            while (bytes_read < object_size) {
                                const size = try self.read(buffer[bytes_read..]);
                                if (size == 0) {
                                    break;
                                }
                                bytes_read += size;
                            }

                            if (bytes_read != object_size) {
                                return error.EndOfStream;
                            }

                            const end_position = try self.getEndPos();

                            zlib.deinit(allocator);
                            self.object_stream = .{
                                .memory = .{
                                    .buffer = buffer,
                                    .interface = std.Io.Reader.fixed(buffer),
                                    .end_position = end_position,
                                },
                            };
                        }
                    },
                    .memory => {},
                }
            },
            .stream => {},
        }
    }

    fn reset(self: *PackObjectStream) !void {
        try self.pack_reader.seekTo(self.start_position);
        switch (self.object_stream) {
            .zlib => |*zlib| zlib.stream.* = .init(self.pack_reader.reader(), .zlib, zlib.stream_buffer),
            .memory => |*memory| memory.interface.seek = 0,
        }
    }

    fn getEndPos(self: *PackObjectStream) !u64 {
        switch (self.object_stream) {
            .zlib => |*zlib| {
                _ = try zlib.stream.reader.discardRemaining();
                return self.pack_reader.logicalPos();
            },
            .memory => |*memory| return memory.end_position,
        }
    }

    fn read(self: *PackObjectStream, dest: []u8) !usize {
        switch (self.object_stream) {
            .zlib => |*zlib| return try zlib.stream.reader.readSliceShort(dest),
            .memory => |*memory| return try memory.interface.readSliceShort(dest),
        }
    }

    fn skipBytes(self: *PackObjectStream, num_bytes: u64) !void {
        switch (self.object_stream) {
            .zlib => |*zlib| try zlib.stream.reader.discardAll64(num_bytes),
            .memory => |*memory| try memory.interface.discardAll64(num_bytes),
        }
    }
};

pub fn PackObjectReader(comptime repo_kind: rp.RepoKind, comptime repo_opts: rp.RepoOpts(repo_kind)) type {
    return struct {
        stream: PackObjectStream,
        relative_position: u64,
        size: u64,
        internal: union(enum) {
            basic: struct {
                header: obj.ObjectHeader,
            },
            delta: struct {
                init: union(enum) {
                    ofs: struct {
                        position: u64,
                    },
                    ref: struct {
                        oid_hex: [hash.hexLen(repo_opts.hash)]u8,
                    },
                },
                state: ?struct {
                    base_reader: *GitOrXitObjectReader(repo_kind, repo_opts),
                    chunk_index: usize,
                    chunk_position: u64,
                    real_position: u64,
                    chunks: std.ArrayList(DeltaChunk),
                    cache: std.AutoArrayHashMap(DeltaChunk, []const u8),
                    cache_arena: *std.heap.ArenaAllocator,
                    recon_size: u64,
                },
            },
        },

        const DeltaChunk = struct {
            kind: enum {
                add_new,
                copy_from_base,
            },
            offset: usize,
            size: usize,
        };

        pub fn init(
            io: std.Io,
            allocator: std.mem.Allocator,
            state: rp.Repo(repo_kind, repo_opts).State(.read_only),
            oid_hex: *const [hash.hexLen(repo_opts.hash)]u8,
        ) anyerror!PackObjectReader(repo_kind, repo_opts) {
            var pack_obj_rdr = try PackObjectReader(repo_kind, repo_opts).initWithIndex(state.core, io, allocator, oid_hex);
            errdefer pack_obj_rdr.deinit(io, allocator);
            try pack_obj_rdr.initDeltaAndCache(io, allocator, state);
            return pack_obj_rdr;
        }

        pub fn initWithoutIndex(
            io: std.Io,
            allocator: std.mem.Allocator,
            state: rp.Repo(repo_kind, repo_opts).State(.read_only),
            pack_reader: *PackReader,
            oid_hex: *const [hash.hexLen(repo_opts.hash)]u8,
        ) !PackObjectReader(repo_kind, repo_opts) {
            var iter = try PackIterator(repo_kind, repo_opts).init(io, allocator, pack_reader);

            while (try iter.next(state, null)) |pack_obj_rdr| {
                {
                    errdefer pack_obj_rdr.deinit(io, allocator);

                    // serialize object header
                    var header_bytes = [_]u8{0} ** 32;
                    const header_str = try pack_obj_rdr.header().write(&header_bytes);

                    // expose pack_obj_rdr as new interface so we can hash it
                    const Stream = struct {
                        reader: *PackObjectReader(repo_kind, repo_opts),
                        interface: std.Io.Reader,

                        fn stream(r: *std.Io.Reader, w: *std.Io.Writer, limit: std.Io.Limit) std.Io.Reader.StreamError!usize {
                            const a: *@This() = @alignCast(@fieldParentPtr("interface", r));
                            const buf = limit.slice(try w.writableSliceGreedy(1));
                            const n = a.reader.read(buf) catch return error.ReadFailed;
                            if (n == 0) return error.EndOfStream;
                            w.advance(n);
                            return n;
                        }
                    };
                    var reader_buffer = [_]u8{0} ** repo_opts.buffer_size;
                    var stream = Stream{
                        .reader = pack_obj_rdr,
                        .interface = .{
                            .buffer = &reader_buffer,
                            .vtable = &.{ .stream = Stream.stream },
                            .seek = 0,
                            .end = 0,
                        },
                    };

                    var oid = [_]u8{0} ** hash.byteLen(repo_opts.hash);
                    try hash.hashReader(repo_opts.hash, repo_opts.read_size, &stream.interface, header_str, &oid);

                    if (std.mem.eql(u8, oid_hex, &std.fmt.bytesToHex(oid, .lower))) {
                        try pack_obj_rdr.reset();
                        return pack_obj_rdr.*;
                    }
                }

                pack_obj_rdr.deinit(io, allocator);
            }

            return error.ObjectNotFound;
        }

        fn initWithIndex(
            core: *rp.Repo(repo_kind, repo_opts).Core,
            io: std.Io,
            allocator: std.mem.Allocator,
            oid_hex: *const [hash.hexLen(repo_opts.hash)]u8,
        ) !PackObjectReader(repo_kind, repo_opts) {
            var pack_dir = try core.repo_dir.openDir(io, "objects/pack", .{ .iterate = true });
            defer pack_dir.close(io);

            const pack_offset = try searchPackIndexes(repo_opts.hash, io, pack_dir, oid_hex);

            const pack_prefix = "pack-";
            const pack_suffix = ".pack";
            const pack_file_name_len = pack_prefix.len + comptime hash.hexLen(repo_opts.hash) + pack_suffix.len;

            var file_name_buf = [_]u8{0} ** pack_file_name_len;
            const file_name = try std.fmt.bufPrint(&file_name_buf, "{s}{s}{s}", .{ pack_prefix, pack_offset.pack_id, pack_suffix });

            var pack_reader = try PackReader.initFile(io, allocator, pack_dir, file_name);
            defer pack_reader.deinit();

            // parse header
            const sig = try pack_reader.reader().takeArray(4);
            if (!std.mem.eql(u8, "PACK", sig)) {
                return error.InvalidPackFileSig;
            }
            const version = try pack_reader.reader().takeInt(u32, .big);
            if (version != 2) {
                return error.InvalidPackFileVersion;
            }
            _ = try pack_reader.reader().takeInt(u32, .big); // number of objects

            return try PackObjectReader(repo_kind, repo_opts).initAtPosition(io, allocator, &pack_reader, pack_offset.value);
        }

        fn initAtPosition(
            io: std.Io,
            allocator: std.mem.Allocator,
            pack_reader: *PackReader,
            position: u64,
        ) !PackObjectReader(repo_kind, repo_opts) {
            try pack_reader.seekTo(position);
            const reader = pack_reader.reader();

            // parse object header
            const obj_header: PackObjectHeader = @bitCast(try reader.takeByte());

            // get size of object (little endian variable length format)
            var size: u64 = obj_header.size;
            {
                var shift: u6 = @bitSizeOf(@TypeOf(obj_header.size));
                var cont = obj_header.extra;
                while (cont) {
                    const next_byte: packed struct {
                        value: u7,
                        extra: bool,
                    } = @bitCast(try reader.takeByte());
                    cont = next_byte.extra;
                    const value: u64 = next_byte.value;
                    size |= (value << shift);
                    shift += 7;
                }
            }

            switch (obj_header.kind) {
                inline .commit, .tree, .blob, .tag => |pack_obj_kind| {
                    const start_position = pack_reader.logicalPos();

                    var stream = try PackObjectStream.init(io, allocator, pack_reader, start_position);
                    errdefer stream.deinit();

                    try stream.readIntoMemoryMaybe(allocator, size);

                    return .{
                        .stream = stream,
                        .relative_position = 0,
                        .size = size,
                        .internal = .{
                            .basic = .{
                                .header = .{
                                    .kind = switch (pack_obj_kind) {
                                        .commit => .commit,
                                        .tree => .tree,
                                        .blob => .blob,
                                        .tag => .tag,
                                        else => comptime unreachable,
                                    },
                                    .size = size,
                                },
                            },
                        },
                    };
                },
                .ofs_delta => {
                    // get offset (big endian variable length format)
                    var offset: u64 = 0;
                    {
                        while (true) {
                            const next_byte: packed struct {
                                value: u7,
                                extra: bool,
                            } = @bitCast(try reader.takeByte());
                            offset = (offset << 7) | next_byte.value;
                            if (!next_byte.extra) {
                                break;
                            }
                            offset += 1; // "offset encoding" https://git-scm.com/docs/pack-format
                        }
                    }

                    const start_position = pack_reader.logicalPos();

                    var stream = try PackObjectStream.init(io, allocator, pack_reader, start_position);
                    errdefer stream.deinit();

                    return .{
                        .stream = stream,
                        .relative_position = 0,
                        .size = size,
                        .internal = .{
                            .delta = .{
                                .init = .{
                                    .ofs = .{
                                        .position = position - offset,
                                    },
                                },
                                .state = null,
                            },
                        },
                    };
                },
                .ref_delta => {
                    const base_oid = try reader.takeArray(hash.byteLen(repo_opts.hash));

                    const start_position = pack_reader.logicalPos();

                    var stream = try PackObjectStream.init(io, allocator, pack_reader, start_position);
                    errdefer stream.deinit();

                    return .{
                        .stream = stream,
                        .relative_position = 0,
                        .size = size,
                        .internal = .{
                            .delta = .{
                                .init = .{
                                    .ref = .{
                                        .oid_hex = std.fmt.bytesToHex(base_oid, .lower),
                                    },
                                },
                                .state = null,
                            },
                        },
                    };
                },
            }
        }

        fn initDeltaAndCache(
            self: *PackObjectReader(repo_kind, repo_opts),
            io: std.Io,
            allocator: std.mem.Allocator,
            state: rp.Repo(repo_kind, repo_opts).State(.read_only),
        ) !void {
            // make a list of the chain of deltified objects,
            // and initialize each one. we can't do this during the initial
            // creation of the PackObjectReader because it would cause them
            // to be initialized recursively. since delta chains can get
            // really long, that can lead to a stack overflow.
            var delta_objects = std.ArrayList(*PackObjectReader(repo_kind, repo_opts)){};
            defer delta_objects.deinit(allocator);
            var last_object = self;
            while (last_object.internal == .delta) {
                try last_object.initDelta(io, allocator, state);
                try delta_objects.append(allocator, last_object);
                last_object = if (last_object.internal.delta.state) |delta_state|
                    switch (delta_state.base_reader.*) {
                        .git => |*loose_or_pack| switch (loose_or_pack.*) {
                            .loose => break,
                            .pack => |*pack| pack,
                        },
                        .xit => break,
                    }
                else
                    // delta object wasn't initialized
                    unreachable;
            }

            // initialize the cache for each deltified object, starting
            // with the one at the end of the chain. we need to cache
            // "copy_from_base" delta transformations for performance.
            // the base object could itself be a deltified object, so
            // trying to read the data on the fly could lead to a very
            // slow recursive descent into madness.
            for (0..delta_objects.items.len) |i| {
                const delta_object = delta_objects.items[delta_objects.items.len - i - 1];
                try delta_object.initCache();
            }
        }

        fn initDelta(
            self: *PackObjectReader(repo_kind, repo_opts),
            io: std.Io,
            allocator: std.mem.Allocator,
            state: rp.Repo(repo_kind, repo_opts).State(.read_only),
        ) !void {
            const base_reader = try allocator.create(GitOrXitObjectReader(repo_kind, repo_opts));
            errdefer allocator.destroy(base_reader);

            base_reader.* = switch (self.internal.delta.init) {
                .ofs => |ofs| blk: {
                    var pack_reader = try self.stream.pack_reader.dupe();
                    defer pack_reader.deinit();
                    break :blk .{ .git = .{ .pack = try PackObjectReader(repo_kind, repo_opts).initAtPosition(io, allocator, &pack_reader, ofs.position) } };
                },
                .ref => |ref| switch (repo_kind) {
                    .git => .{ .git = try LooseOrPackObjectReader(repo_kind, repo_opts).init(state, io, allocator, &ref.oid_hex) },
                    .xit => .{ .xit = try GitOrXitObjectReader(repo_kind, repo_opts).ChunkObjectReader.init(state, io, allocator, &ref.oid_hex) },
                },
            };
            errdefer base_reader.deinit(io, allocator);

            var bytes_read: u64 = 0;

            const zlib_stream = self.stream.object_stream.zlib.stream;

            // get size of base object (little endian variable length format)
            var base_size: u64 = 0;
            {
                var shift: u6 = 0;
                var cont = true;
                while (cont) {
                    const next_byte: packed struct {
                        value: u7,
                        extra: bool,
                    } = @bitCast(try zlib_stream.reader.takeByte());
                    bytes_read += 1;
                    cont = next_byte.extra;
                    const value: u64 = next_byte.value;
                    base_size |= (value << shift);
                    shift += 7;
                }
            }

            // get size of reconstructed object (little endian variable length format)
            var recon_size: u64 = 0;
            {
                var shift: u6 = 0;
                var cont = true;
                while (cont) {
                    const next_byte: packed struct {
                        value: u7,
                        extra: bool,
                    } = @bitCast(try zlib_stream.reader.takeByte());
                    bytes_read += 1;
                    cont = next_byte.extra;
                    const value: u64 = next_byte.value;
                    recon_size |= (value << shift);
                    shift += 7;
                }
            }

            var chunks = std.ArrayList(DeltaChunk){};
            errdefer chunks.deinit(allocator);

            var cache = std.AutoArrayHashMap(DeltaChunk, []const u8).init(allocator);
            errdefer cache.deinit();

            const cache_arena = try allocator.create(std.heap.ArenaAllocator);
            cache_arena.* = std.heap.ArenaAllocator.init(allocator);
            errdefer {
                cache_arena.deinit();
                allocator.destroy(cache_arena);
            }

            while (bytes_read < self.size) {
                const next_byte: packed struct {
                    value: u7,
                    high_bit: u1,
                } = @bitCast(try zlib_stream.reader.takeByte());
                bytes_read += 1;

                switch (next_byte.high_bit) {
                    // add new data
                    0 => {
                        if (next_byte.value == 0) { // reserved instruction
                            continue;
                        }
                        const chunk = DeltaChunk{
                            .kind = .add_new,
                            .offset = bytes_read,
                            .size = next_byte.value,
                        };
                        try chunks.append(allocator, chunk);
                        // stream-based pack readers can't seek, so we need to cache the add_new
                        // instructions in memory to enable us to read delta objects. file-based
                        // pack readers can seek, so we choose not to cache this instruction in
                        // order to reduce memory use.
                        switch (self.stream.pack_reader.*) {
                            .file => try zlib_stream.reader.discardAll64(next_byte.value),
                            .stream => {
                                var writer = std.Io.Writer.Allocating.init(cache_arena.allocator());
                                try zlib_stream.reader.streamExact(&writer.writer, next_byte.value);
                                try cache.put(chunk, writer.written());
                            },
                        }
                        bytes_read += next_byte.value;
                    },
                    // copy data
                    1 => {
                        var vals = [_]u8{0} ** 7;
                        var i: u3 = 0;
                        for (&vals) |*val| {
                            const mask: u7 = @as(u7, 1) << i;
                            i += 1;
                            if (next_byte.value & mask != 0) {
                                val.* = try zlib_stream.reader.takeByte();
                                bytes_read += 1;
                            }
                        }
                        const copy_offset = std.mem.readInt(u32, vals[0..4], .little);
                        const copy_size = std.mem.readInt(u24, vals[4..], .little);
                        const chunk = DeltaChunk{
                            .kind = .copy_from_base,
                            .offset = copy_offset,
                            .size = if (copy_size == 0) 0x10000 else copy_size,
                        };
                        try chunks.append(allocator, chunk);
                        // copy_from_base instructions must always be cached in memory
                        // for performance. however, we won't read the data yet. if
                        // the base object is also a delta object, we will delay reading
                        // until we call `initCache` so we can read the chain of delta
                        // objects in the correct order.
                        try cache.put(chunk, "");
                    },
                }
            }

            const SortCtx = struct {
                keys: []DeltaChunk,
                pub fn lessThan(ctx: @This(), a_index: usize, b_index: usize) bool {
                    const a_loc = ctx.keys[a_index];
                    const b_loc = ctx.keys[b_index];
                    if (a_loc.offset == b_loc.offset) {
                        return a_loc.size > b_loc.size;
                    }
                    return a_loc.offset < b_loc.offset;
                }
            };
            cache.sort(SortCtx{ .keys = cache.keys() });

            try self.stream.readIntoMemoryMaybe(allocator, self.size);

            self.* = .{
                .stream = self.stream,
                .relative_position = bytes_read,
                .size = self.size,
                .internal = .{
                    .delta = .{
                        .init = self.internal.delta.init,
                        .state = .{
                            .base_reader = base_reader,
                            .chunk_index = 0,
                            .chunk_position = 0,
                            .real_position = bytes_read,
                            .chunks = chunks,
                            .cache = cache,
                            .cache_arena = cache_arena,
                            .recon_size = recon_size,
                        },
                    },
                },
            };
        }

        fn initCache(self: *PackObjectReader(repo_kind, repo_opts)) !void {
            const delta_state = if (self.internal.delta.state) |*state| state else unreachable;
            const keys = delta_state.cache.keys();
            const values = delta_state.cache.values();
            for (keys, values, 0..) |location, *value, i| {
                // the value has already been set
                if (value.len > 0) continue;

                // if the value is a subset of the previous value, just get a slice of it
                if (i > 0 and location.offset == keys[i - 1].offset and location.size < keys[i - 1].size) {
                    const last_buffer = values[i - 1];
                    value.* = last_buffer[0..location.size];
                    continue;
                }

                // seek the base reader to the correct position
                // TODO: can we avoid calling reset if position <= location.offset?
                // i tried that already but the cache was
                // getting messed up in rare cases for some reason.
                // currently, position is always 0 because we're always resetting,
                // but maybe in the future i can make it reset only when necessary.
                try delta_state.base_reader.reset();
                const position = delta_state.base_reader.position();
                const bytes_to_skip = location.offset - position;
                try delta_state.base_reader.skipBytes(bytes_to_skip);

                // read into the buffer and put it in the cache
                const buffer = try delta_state.cache_arena.allocator().alloc(u8, location.size);
                var read_so_far: usize = 0;
                while (read_so_far < buffer.len) {
                    const amt = @min(buffer.len - read_so_far, 2048);
                    const read_size = try delta_state.base_reader.read(buffer[read_so_far .. read_so_far + amt]);
                    if (read_size == 0) break;
                    read_so_far += read_size;
                }
                if (read_so_far != buffer.len) {
                    return error.UnexpectedEndOfStream;
                }
                value.* = buffer;
            }

            // now that the cache has been initialized, clear the cache in
            // the base object if necessary, because it won't be used anymore.
            switch (delta_state.base_reader.*) {
                .git => |*loose_or_pack| switch (loose_or_pack.*) {
                    .loose => {},
                    .pack => |*pack| switch (pack.internal) {
                        .basic => {},
                        .delta => |*delta| {
                            const base_delta_state = if (delta.state) |*state| state else unreachable;
                            _ = base_delta_state.cache_arena.reset(.free_all);
                            base_delta_state.cache.clearAndFree();
                        },
                    },
                },
                .xit => {},
            }
        }

        pub fn deinit(self: *PackObjectReader(repo_kind, repo_opts), io: std.Io, allocator: std.mem.Allocator) void {
            self.stream.deinit();
            switch (self.internal) {
                .basic => {},
                .delta => |*delta| {
                    if (delta.state) |*state| {
                        state.base_reader.deinit(io, allocator);
                        allocator.destroy(state.base_reader);
                        state.chunks.deinit(allocator);
                        state.cache.deinit();
                        state.cache_arena.deinit();
                        allocator.destroy(state.cache_arena);
                    }
                },
            }
        }

        pub fn header(self: PackObjectReader(repo_kind, repo_opts)) obj.ObjectHeader {
            return switch (self.internal) {
                .basic => self.internal.basic.header,
                .delta => |delta| if (delta.state) |delta_state| .{
                    .kind = delta_state.base_reader.header().kind,
                    .size = delta_state.recon_size,
                } else unreachable,
            };
        }

        pub fn reset(self: *PackObjectReader(repo_kind, repo_opts)) !void {
            try self.stream.reset();
            self.relative_position = 0;

            switch (self.internal) {
                .basic => {},
                .delta => |*delta| if (delta.state) |*state| {
                    state.chunk_index = 0;
                    state.chunk_position = 0;
                    state.real_position = 0;
                    try state.base_reader.reset();
                },
            }
        }

        pub fn read(self: *PackObjectReader(repo_kind, repo_opts), dest: []u8) !usize {
            switch (self.internal) {
                .basic => {
                    if (self.size < self.relative_position) return error.EndOfStream;
                    const size = try self.stream.read(dest[0..@min(dest.len, self.size - self.relative_position)]);
                    self.relative_position += size;
                    return size;
                },
                .delta => |*delta| {
                    const delta_state = if (delta.state) |*state| state else unreachable;
                    var bytes_read: usize = 0;
                    while (bytes_read < dest.len) {
                        if (delta_state.chunk_index == delta_state.chunks.items.len) {
                            break;
                        }
                        const delta_chunk = delta_state.chunks.items[delta_state.chunk_index];
                        var dest_slice = dest[bytes_read..];
                        const bytes_to_read = @min(delta_chunk.size - delta_state.chunk_position, dest_slice.len);
                        switch (delta_chunk.kind) {
                            .add_new => {
                                const offset = delta_chunk.offset + delta_state.chunk_position;
                                if (delta_state.cache.get(delta_chunk)) |buffer| {
                                    @memcpy(dest_slice[0..bytes_to_read], buffer[delta_state.chunk_position .. delta_state.chunk_position + bytes_to_read]);
                                    bytes_read += bytes_to_read;
                                    delta_state.chunk_position += bytes_to_read;
                                    delta_state.real_position += bytes_to_read;
                                } else {
                                    if (self.relative_position > offset) {
                                        try self.stream.reset();
                                        self.relative_position = 0;
                                    }
                                    if (self.relative_position < offset) {
                                        const bytes_to_skip = offset - self.relative_position;
                                        try self.stream.skipBytes(bytes_to_skip);
                                        self.relative_position += bytes_to_skip;
                                    }
                                    const size = try self.stream.read(dest_slice[0..bytes_to_read]);
                                    // TODO: in rare cases this is not true....why?
                                    //if (size != bytes_to_read) return error.UnexpectedEndOfStream;
                                    self.relative_position += size;
                                    bytes_read += size;
                                    delta_state.chunk_position += size;
                                    delta_state.real_position += size;
                                }
                            },
                            .copy_from_base => {
                                const buffer = delta_state.cache.get(delta_chunk) orelse return error.InvalidDeltaCache;
                                @memcpy(dest_slice[0..bytes_to_read], buffer[delta_state.chunk_position .. delta_state.chunk_position + bytes_to_read]);
                                bytes_read += bytes_to_read;
                                delta_state.chunk_position += bytes_to_read;
                                delta_state.real_position += bytes_to_read;
                            },
                        }
                        if (delta_state.chunk_position == delta_chunk.size) {
                            delta_state.chunk_index += 1;
                            delta_state.chunk_position = 0;
                        }
                    }
                    return bytes_read;
                },
            }
        }

        pub fn skipBytes(self: *PackObjectReader(repo_kind, repo_opts), num_bytes: u64) !void {
            var buf = [_]u8{0} ** 512;
            var remaining = num_bytes;
            while (remaining > 0) {
                const max_size = @min(remaining, buf.len);
                const size = try self.read(buf[0..max_size]);
                remaining -= size;
            }
        }
    };
}

pub fn LooseOrPackObjectReader(comptime repo_kind: rp.RepoKind, comptime repo_opts: rp.RepoOpts(repo_kind)) type {
    return union(enum) {
        loose: struct {
            io: std.Io,
            file: std.Io.File,
            file_reader: *std.Io.File.Reader,
            file_reader_buffer: []u8,
            zlib_stream: *std.compress.flate.Decompress,
            zlib_stream_buffer: []u8,
            header: obj.ObjectHeader,
        },
        pack: PackObjectReader(repo_kind, repo_opts),

        pub fn init(
            state: rp.Repo(repo_kind, repo_opts).State(.read_only),
            io: std.Io,
            allocator: std.mem.Allocator,
            oid_hex: *const [hash.hexLen(repo_opts.hash)]u8,
        ) !LooseOrPackObjectReader(repo_kind, repo_opts) {
            // open the objects dir
            var objects_dir = try state.core.repo_dir.openDir(io, "objects", .{});
            defer objects_dir.close(io);

            // open the object file
            var path_buf = [_]u8{0} ** (hash.hexLen(repo_opts.hash) + 1);
            const path = try std.fmt.bufPrint(&path_buf, "{s}/{s}", .{ oid_hex[0..2], oid_hex[2..] });
            var object_file = objects_dir.openFile(io, path, .{ .mode = .read_only }) catch |err| switch (err) {
                error.FileNotFound => return .{
                    .pack = try PackObjectReader(repo_kind, repo_opts).init(io, allocator, state, oid_hex),
                },
                else => |e| return e,
            };
            errdefer object_file.close(io);

            const reader_buffer = try allocator.alloc(u8, repo_opts.buffer_size);
            errdefer allocator.free(reader_buffer);

            const reader = try allocator.create(std.Io.File.Reader);
            errdefer allocator.destroy(reader);
            reader.* = object_file.reader(io, reader_buffer);

            const zlib_stream_buffer = try allocator.alloc(u8, std.compress.flate.max_window_len);
            errdefer allocator.free(zlib_stream_buffer);

            const zlib_stream = try allocator.create(std.compress.flate.Decompress);
            errdefer allocator.destroy(zlib_stream);
            zlib_stream.* = .init(&reader.interface, .zlib, zlib_stream_buffer);

            return .{
                .loose = .{
                    .io = io,
                    .file = object_file,
                    .file_reader = reader,
                    .file_reader_buffer = reader_buffer,
                    .zlib_stream = zlib_stream,
                    .zlib_stream_buffer = zlib_stream_buffer,
                    .header = try obj.ObjectHeader.read(&zlib_stream.reader),
                },
            };
        }

        pub fn deinit(self: *LooseOrPackObjectReader(repo_kind, repo_opts), io: std.Io, allocator: std.mem.Allocator) void {
            switch (self.*) {
                .loose => |*loose| {
                    loose.file.close(io);
                    allocator.destroy(loose.file_reader);
                    allocator.destroy(loose.zlib_stream);
                    allocator.free(loose.file_reader_buffer);
                    allocator.free(loose.zlib_stream_buffer);
                },
                .pack => |*pack| pack.deinit(io, allocator),
            }
        }

        pub fn header(self: LooseOrPackObjectReader(repo_kind, repo_opts)) obj.ObjectHeader {
            return switch (self) {
                .loose => |loose| loose.header,
                .pack => |pack| pack.header(),
            };
        }

        pub fn reset(self: *LooseOrPackObjectReader(repo_kind, repo_opts)) !void {
            switch (self.*) {
                .loose => |*loose| {
                    loose.file_reader.* = loose.file.reader(loose.io, loose.file_reader_buffer);
                    try loose.file_reader.seekTo(0);
                    loose.zlib_stream.* = .init(&loose.file_reader.interface, .zlib, loose.zlib_stream_buffer);
                    _ = try loose.zlib_stream.reader.discardDelimiterInclusive(0);
                },
                .pack => |*pack| try pack.reset(),
            }
        }

        pub fn read(self: *LooseOrPackObjectReader(repo_kind, repo_opts), dest: []u8) !usize {
            switch (self.*) {
                .loose => |*loose| return try loose.zlib_stream.reader.readSliceShort(dest),
                .pack => |*pack| return try pack.read(dest),
            }
        }

        pub fn skipBytes(self: *LooseOrPackObjectReader(repo_kind, repo_opts), num_bytes: u64) !void {
            switch (self.*) {
                .loose => |*loose| try loose.zlib_stream.reader.discardAll64(num_bytes),
                .pack => |*pack| try pack.skipBytes(num_bytes),
            }
        }
    };
}

pub fn PackWriter(comptime repo_kind: rp.RepoKind, comptime repo_opts: rp.RepoOpts(repo_kind)) type {
    return struct {
        allocator: std.mem.Allocator,
        objects: std.ArrayList(obj.Object(repo_kind, repo_opts, .raw)),
        object_index: usize,
        out_bytes: std.Io.Writer.Allocating,
        out_index: usize,
        stream_buffer: [std.compress.flate.max_window_len]u8,
        hasher: hash.Hasher(repo_opts.hash),
        mode: union(enum) {
            header,
            object: struct {
                stream: ?std.compress.flate.Compress,
            },
            footer,
            finished,
        },

        pub fn init(allocator: std.mem.Allocator, obj_iter: *obj.ObjectIterator(repo_kind, repo_opts, .raw)) !?PackWriter(repo_kind, repo_opts) {
            var self = PackWriter(repo_kind, repo_opts){
                .allocator = allocator,
                .objects = std.ArrayList(obj.Object(repo_kind, repo_opts, .raw)){},
                .object_index = 0,
                .out_bytes = try .initCapacity(allocator, repo_opts.buffer_size),
                .out_index = 0,
                .stream_buffer = [_]u8{0} ** std.compress.flate.max_window_len,
                .hasher = hash.Hasher(repo_opts.hash).init(),
                .mode = .header,
            };
            errdefer self.deinit();

            while (try obj_iter.next()) |object| {
                errdefer object.deinit();
                try self.objects.append(allocator, object.*);
            }

            if (self.objects.items.len == 0) {
                return null;
            }

            _ = try self.out_bytes.writer.write("PACK");
            try self.out_bytes.writer.writeInt(u32, 2, .big); // version
            try self.out_bytes.writer.writeInt(u32, @intCast(self.objects.items.len), .big);

            try self.writeObjectHeader();

            return self;
        }

        pub fn deinit(self: *PackWriter(repo_kind, repo_opts)) void {
            for (self.objects.items) |*object| {
                object.deinit();
            }
            self.objects.deinit(self.allocator);
            self.out_bytes.deinit();
        }

        pub fn read(self: *PackWriter(repo_kind, repo_opts), buffer: []u8) !usize {
            var size: usize = 0;
            while (size < buffer.len and .finished != self.mode) {
                size += try self.readStep(buffer[size..]);
            }
            return size;
        }

        fn readStep(self: *PackWriter(repo_kind, repo_opts), buffer: []u8) !usize {
            switch (self.mode) {
                .header => {
                    const size = @min(self.out_bytes.written().len - self.out_index, buffer.len);
                    @memcpy(buffer[0..size], self.out_bytes.written()[self.out_index .. self.out_index + size]);
                    self.hasher.update(buffer[0..size]);
                    if (size < buffer.len) {
                        self.out_bytes.deinit();
                        self.out_bytes = try .initCapacity(self.allocator, repo_opts.buffer_size);
                        self.out_index = 0;
                        self.mode = .{
                            .object = .{
                                .stream = try .init(&self.out_bytes.writer, &self.stream_buffer, .zlib, .default),
                            },
                        };
                    } else {
                        self.out_index += size;
                    }
                    return size;
                },
                .object => |*o| {
                    if (self.out_index < self.out_bytes.written().len) {
                        const size = @min(self.out_bytes.written().len - self.out_index, buffer.len);
                        @memcpy(buffer[0..size], self.out_bytes.written()[self.out_index .. self.out_index + size]);
                        self.hasher.update(buffer[0..size]);
                        self.out_index += size;
                        return size;
                    } else {
                        // everything in out_bytes has been written, so we can clear it
                        self.out_bytes.deinit();
                        self.out_bytes = try .initCapacity(self.allocator, repo_opts.buffer_size);
                        self.out_index = 0;

                        if (o.stream) |*stream| {
                            const object = &self.objects.items[self.object_index];
                            const size = object.object_reader.interface.stream(&stream.writer, @enumFromInt(buffer.len)) catch |err| switch (err) {
                                error.EndOfStream => 0,
                                else => |e| return e,
                            };

                            if (size > 0) {
                                // return so we can read out_bytes the next time this fn is called
                                return 0;
                            } else {
                                try stream.writer.flush();
                                o.stream = null;
                                // if flush() added more data to out_bytes,
                                // return so we can read it next time this fn is called
                                if (self.out_index < self.out_bytes.written().len) {
                                    return 0;
                                }
                            }
                        }

                        // there is nothing more to write, so move on to the next object
                        self.object_index += 1;
                        if (self.object_index < self.objects.items.len) {
                            self.mode = .header;
                            try self.writeObjectHeader();
                        } else {
                            self.mode = .footer;
                            var hash_buffer = [_]u8{0} ** hash.byteLen(repo_opts.hash);
                            self.hasher.final(&hash_buffer);
                            try self.out_bytes.writer.writeAll(&hash_buffer);
                        }
                        return 0;
                    }
                },
                .footer => {
                    const size = @min(self.out_bytes.written().len - self.out_index, buffer.len);
                    @memcpy(buffer[0..size], self.out_bytes.written()[self.out_index .. self.out_index + size]);
                    if (size < buffer.len) {
                        self.out_bytes.deinit();
                        self.out_bytes = try .initCapacity(self.allocator, repo_opts.buffer_size);
                        self.out_index = 0;
                        self.mode = .finished;
                    } else {
                        self.out_index += size;
                    }
                    return size;
                },
                .finished => return 0,
            }
        }

        fn writeObjectHeader(self: *PackWriter(repo_kind, repo_opts)) !void {
            const object = self.objects.items[self.object_index];
            const size = object.len;

            const first_size_parts: packed struct {
                low_bits: u4,
                high_bits: u60,
            } = @bitCast(size);

            const obj_header = PackObjectHeader{
                .size = first_size_parts.low_bits,
                .kind = switch (object.content) {
                    .blob => .blob,
                    .tree => .tree,
                    .commit => .commit,
                    .tag => .tag,
                },
                .extra = first_size_parts.high_bits > 0,
            };

            try self.out_bytes.writer.writeByte(@bitCast(obj_header));

            // set size of object (little endian variable length format)
            var next_size = first_size_parts.high_bits;
            while (next_size > 0) {
                const size_parts: packed struct {
                    low_bits: u7,
                    high_bits: u53,
                } = @bitCast(next_size);
                const next_byte: packed struct {
                    value: u7,
                    extra: bool,
                } = .{
                    .value = size_parts.low_bits,
                    .extra = size_parts.high_bits > 0,
                };
                try self.out_bytes.writer.writeByte(@bitCast(next_byte));
                next_size = size_parts.high_bits;
            }
        }
    };
}

// search pack index files

fn findOid(
    comptime hash_kind: hash.HashKind,
    io: std.Io,
    idx_file: std.Io.File,
    oid_list_pos: u64,
    index: usize,
) ![hash.byteLen(hash_kind)]u8 {
    var reader_buffer = [_]u8{0} ** hash.byteLen(hash_kind);
    var reader = idx_file.reader(io, &reader_buffer);
    const oid_pos = oid_list_pos + (index * hash.byteLen(hash_kind));
    try reader.seekTo(oid_pos);
    return (try reader.interface.takeArray(hash.byteLen(hash_kind))).*;
}

fn findObjectIndex(
    comptime hash_kind: hash.HashKind,
    io: std.Io,
    idx_file: std.Io.File,
    fanout_table: [256]u32,
    oid_list_pos: u64,
    oid_bytes: *const [hash.byteLen(hash_kind)]u8,
) !?usize {
    var left: u32 = 0;
    var right = fanout_table[oid_bytes[0]];

    // binary search for the oid
    while (left < right) {
        const mid = left + ((right - left) / 2);
        const mid_oid_bytes = try findOid(hash_kind, io, idx_file, oid_list_pos, mid);
        if (std.mem.eql(u8, oid_bytes, &mid_oid_bytes)) {
            return mid;
        } else if (std.mem.lessThan(u8, oid_bytes, &mid_oid_bytes)) {
            if (mid == 0) {
                break;
            } else {
                right = mid - 1;
            }
        } else {
            if (left == fanout_table[oid_bytes[0]]) {
                break;
            } else {
                left = mid + 1;
            }
        }
    }

    const right_oid_bytes = try findOid(hash_kind, io, idx_file, oid_list_pos, right);
    if (std.mem.eql(u8, oid_bytes, &right_oid_bytes)) {
        return right;
    }

    return null;
}

fn findOffset(
    comptime hash_kind: hash.HashKind,
    io: std.Io,
    idx_file: std.Io.File,
    fanout_table: [256]u32,
    oid_list_pos: u64,
    index: usize,
) !u64 {
    var reader_buffer = [_]u8{0} ** 256;
    var reader = idx_file.reader(io, &reader_buffer);

    const entry_count = fanout_table[fanout_table.len - 1];
    const crc_size: u64 = 4;
    const offset_size: u64 = 4;
    const crc_list_pos = oid_list_pos + (entry_count * hash.byteLen(hash_kind));
    const offset_list_pos = crc_list_pos + (entry_count * crc_size);
    const offset_pos = offset_list_pos + (index * offset_size);

    try reader.seekTo(offset_pos);
    const offset: packed struct {
        value: u31,
        extra: bool,
    } = @bitCast(try reader.interface.takeInt(u32, .big));
    if (!offset.extra) {
        return offset.value;
    }

    const offset64_size: u64 = 8;
    const offset64_list_pos = offset_list_pos + (entry_count * offset_size);
    const offset64_pos = offset64_list_pos + (offset.value * offset64_size);

    try reader.seekTo(offset64_pos);
    return try reader.interface.takeInt(u64, .big);
}

fn searchPackIndex(
    comptime hash_kind: hash.HashKind,
    io: std.Io,
    idx_file: std.Io.File,
    oid_bytes: *const [hash.byteLen(hash_kind)]u8,
) !?u64 {
    var reader_buffer = [_]u8{0} ** 256;
    var reader = idx_file.reader(io, &reader_buffer);

    const header = try reader.interface.takeArray(4);
    const version = if (!std.mem.eql(u8, &.{ 255, 116, 79, 99 }, header)) 1 else try reader.interface.takeInt(u32, .big);
    if (version != 2) {
        return error.NotImplemented;
    }

    var fanout_table = [_]u32{0} ** 256;
    for (&fanout_table) |*entry| {
        entry.* = try reader.interface.takeInt(u32, .big);
    }
    const oid_list_pos = reader.logicalPos();

    if (try findObjectIndex(hash_kind, io, idx_file, fanout_table, oid_list_pos, oid_bytes)) |index| {
        return try findOffset(hash_kind, io, idx_file, fanout_table, oid_list_pos, index);
    }

    return null;
}

fn PackOffset(comptime hash_kind: hash.HashKind) type {
    return struct {
        pack_id: [hash.hexLen(hash_kind)]u8,
        value: u64,
    };
}

fn searchPackIndexes(
    comptime hash_kind: hash.HashKind,
    io: std.Io,
    pack_dir: std.Io.Dir,
    oid_hex: *const [hash.hexLen(hash_kind)]u8,
) !PackOffset(hash_kind) {
    const oid_bytes = try hash.hexToBytes(hash_kind, oid_hex.*);

    const prefix = "pack-";
    const suffix = ".idx";

    var iter = pack_dir.iterate();
    while (try iter.next(io)) |entry| {
        switch (entry.kind) {
            .file => {
                if (std.mem.startsWith(u8, entry.name, prefix) and std.mem.endsWith(u8, entry.name, suffix)) {
                    const pack_id = entry.name[prefix.len .. entry.name.len - suffix.len];

                    if (pack_id.len == hash.hexLen(hash_kind)) {
                        var idx_file = try pack_dir.openFile(io, entry.name, .{ .mode = .read_only });
                        defer idx_file.close(io);

                        if (try searchPackIndex(hash_kind, io, idx_file, &oid_bytes)) |offset| {
                            return .{
                                .pack_id = pack_id[0..comptime hash.hexLen(hash_kind)].*,
                                .value = offset,
                            };
                        }
                    }
                }
            },
            else => {},
        }
    }

    return error.ObjectNotFound;
}
