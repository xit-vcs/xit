const std = @import("std");

pub const HashKind = enum {
    sha1,
    sha256,
};

pub fn HashInt(comptime hash_kind: ?HashKind) type {
    return switch (hash_kind orelse return u0) {
        .sha1 => u160,
        .sha256 => u256,
    };
}

pub fn hashId(comptime hash_kind: ?HashKind) u32 {
    const xitdb = @import("xitdb");
    return switch (hash_kind orelse return 0) {
        .sha1 => xitdb.HashId.fromBytes("sha1").id,
        .sha256 => xitdb.HashId.fromBytes("sha2").id,
    };
}

pub fn hashKind(hash_id: u32, hash_size: u16) ?HashKind {
    return switch (hash_id) {
        hashId(.sha1) => switch (hash_size) {
            byteLen(.sha1) => .sha1,
            else => null,
        },
        hashId(.sha256) => switch (hash_size) {
            byteLen(.sha256) => .sha256,
            else => null,
        },
        else => null,
    };
}

pub fn byteLen(comptime hash_kind: ?HashKind) usize {
    return switch (hash_kind orelse return 0) {
        .sha1 => std.crypto.hash.Sha1.digest_length,
        .sha256 => std.crypto.hash.sha2.Sha256.digest_length,
    };
}

pub fn hexLen(comptime hash_kind: ?HashKind) usize {
    return byteLen(hash_kind) * 2;
}

pub fn Hasher(comptime hash_kind: ?HashKind) type {
    return struct {
        hasher: if (hash_kind) |hk| switch (hk) {
            .sha1 => std.crypto.hash.Sha1,
            .sha256 => std.crypto.hash.sha2.Sha256,
        } else void,

        pub fn init() Hasher(hash_kind) {
            return .{
                .hasher = switch (hash_kind orelse @compileError("no hash algorithm")) {
                    .sha1 => std.crypto.hash.Sha1.init(.{}),
                    .sha256 => std.crypto.hash.sha2.Sha256.init(.{}),
                },
            };
        }

        pub fn update(self: *Hasher(hash_kind), buffer: []const u8) void {
            self.hasher.update(buffer);
        }

        pub fn final(self: *Hasher(hash_kind), out: *[byteLen(hash_kind)]u8) void {
            self.hasher.final(out);
        }
    };
}

pub fn hashReader(
    comptime hash_kind: ?HashKind,
    comptime read_size: usize,
    reader: *std.Io.Reader,
    header_maybe: ?[]const u8,
    out: *[byteLen(hash_kind)]u8,
) !void {
    var hasher = Hasher(hash_kind).init();
    var buffer = [_]u8{0} ** read_size;
    if (header_maybe) |header| {
        hasher.update(header);
    }
    while (true) {
        const size = try reader.readSliceShort(&buffer);
        if (size == 0) {
            break;
        }
        hasher.update(buffer[0..size]);
    }
    hasher.final(out);
}

pub fn hashBuffer(comptime hash_kind: ?HashKind, buffer: []const u8, out: *[byteLen(hash_kind)]u8) !void {
    var hasher = Hasher(hash_kind).init();
    hasher.update(buffer);
    hasher.final(out);
}

pub fn hashInt(comptime hash_kind: ?HashKind, buffer: []const u8) HashInt(hash_kind) {
    var hash_buffer = [_]u8{0} ** byteLen(hash_kind);
    var hasher = Hasher(hash_kind).init();
    hasher.update(buffer);
    hasher.final(&hash_buffer);
    return bytesToInt(hash_kind, &hash_buffer);
}

pub fn hexToInt(comptime hash_kind: ?HashKind, hex_buffer: *const [hexLen(hash_kind)]u8) !HashInt(hash_kind) {
    var hash_buffer = [_]u8{0} ** byteLen(hash_kind);
    _ = try std.fmt.hexToBytes(&hash_buffer, hex_buffer);
    return bytesToInt(hash_kind, &hash_buffer);
}

pub fn bytesToInt(comptime hash_kind: ?HashKind, bytes_buffer: *const [byteLen(hash_kind)]u8) HashInt(hash_kind) {
    return std.mem.readInt(HashInt(hash_kind), bytes_buffer, .big);
}

pub fn hexToBytes(comptime hash_kind: ?HashKind, hex_buffer: [hexLen(hash_kind)]u8) ![byteLen(hash_kind)]u8 {
    var bytes = [_]u8{0} ** byteLen(hash_kind);
    _ = try std.fmt.hexToBytes(&bytes, &hex_buffer);
    return bytes;
}

pub fn intToBytes(comptime T: type, num: T) [@bitSizeOf(T) / 8]u8 {
    var bytes = [_]u8{0} ** (@bitSizeOf(T) / 8);
    std.mem.writeInt(T, &bytes, num, .big);
    return bytes;
}
