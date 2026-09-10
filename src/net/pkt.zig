const std = @import("std");
const builtin = @import("builtin");
const net = @import("../net.zig");
const net_fetch = @import("./fetch.zig");
const net_wire = @import("./wire.zig");
const rp = @import("../repo.zig");
const hash = @import("../hash.zig");

pub fn Ref(comptime repo_kind: rp.RepoKind, comptime repo_opts: rp.RepoOpts(repo_kind)) type {
    return struct {
        head: net.RemoteHead(repo_kind, repo_opts),
        capabilities: ?[]const u8,

        pub fn deinit(self: *Ref(repo_kind, repo_opts), allocator: std.mem.Allocator) void {
            self.head.deinit(allocator);
            if (self.capabilities) |caps| allocator.free(caps);
        }
    };
}

pub fn Pkt(comptime repo_kind: rp.RepoKind, comptime repo_opts: rp.RepoOpts(repo_kind)) type {
    return union(enum) {
        flush: void,
        ref: Ref(repo_kind, repo_opts),
        ack: struct {
            oid: [hash.hexLen(repo_opts.hash)]u8,
            status: ?enum {
                cont,
                common,
                ready,
            },
        },
        nak: void,
        comment: []u8,
        data: []u8,
        progress: []u8,
        err: []u8,
        ok: []u8,
        ng: []u8,
        unpack: struct {
            unpack_ok: bool,
        },
        unshallow: struct {
            oid: [hash.hexLen(repo_opts.hash)]u8,
        },
        shallow: struct {
            oid: [hash.hexLen(repo_opts.hash)]u8,
        },

        /// parses the next packet from `buffer`, or returns null if the buffer
        /// doesn't contain a complete packet yet. `consumed` is set to the
        /// number of bytes the packet took up whenever a packet is returned.
        pub fn initMaybe(
            allocator: std.mem.Allocator,
            buffer: []const u8,
            found_capabilities: *bool,
            consumed: *usize,
        ) !?Pkt(repo_kind, repo_opts) {
            var line = buffer;

            if (line.len < PKT_LEN_SIZE) {
                return null;
            }

            var len = try std.fmt.parseInt(u16, line[0..PKT_LEN_SIZE], 16);

            if (line.len < len or (len != 0 and len < PKT_LEN_SIZE)) {
                return null;
            }

            line = line[PKT_LEN_SIZE..];

            if (len == PKT_LEN_SIZE) {
                return error.InvalidEmptyPacket;
            }

            if (len == 0) {
                consumed.* = PKT_LEN_SIZE;
                return .{ .flush = {} };
            }

            len -= PKT_LEN_SIZE;
            consumed.* = PKT_LEN_SIZE + len;

            const content = line[0..len];

            return switch (line[0]) {
                1 => .{ .data = try allocator.dupe(u8, content[1..]) },
                2 => .{ .progress = try allocator.dupe(u8, content[1..]) },
                3 => .{ .err = try allocator.dupe(u8, content[1..]) },
                else => if (std.mem.startsWith(u8, content, "ACK"))
                    try ackPkt(content)
                else if (std.mem.startsWith(u8, content, "NAK"))
                    .{ .nak = {} }
                else if (line[0] == '#')
                    .{ .comment = try allocator.dupe(u8, content) }
                else if (std.mem.startsWith(u8, content, "ERR"))
                    try errPkt(allocator, content)
                else if (std.mem.startsWith(u8, content, "ok"))
                    try okPkt(allocator, content)
                else if (std.mem.startsWith(u8, content, "ng"))
                    try ngPkt(allocator, content)
                else if (std.mem.startsWith(u8, content, "unpack"))
                    .{ .unpack = .{ .unpack_ok = std.mem.startsWith(u8, content, "unpack ok") } }
                else if (std.mem.startsWith(u8, content, "unshallow"))
                    try unshallowPkt(content)
                else if (std.mem.startsWith(u8, content, "shallow"))
                    try shallowPkt(content)
                else
                    try refPkt(allocator, content, found_capabilities),
            };
        }

        pub fn deinit(self: *Pkt(repo_kind, repo_opts), allocator: std.mem.Allocator) void {
            switch (self.*) {
                .flush => {},
                .ref => |*p| p.deinit(allocator),
                .ack => {},
                .nak => {},
                .comment => |p| allocator.free(p),
                .data => |p| allocator.free(p),
                .progress => |p| allocator.free(p),
                .err => |p| allocator.free(p),
                .ok => |p| allocator.free(p),
                .ng => |p| allocator.free(p),
                .unpack => {},
                .unshallow => {},
                .shallow => {},
            }
        }

        fn ackPkt(content: []const u8) !Pkt(repo_kind, repo_opts) {
            // the content looks like "ACK <oid>[ <status>]"
            const oid_len = comptime hash.hexLen(repo_opts.hash);
            if (content.len < "ACK ".len + oid_len) {
                return error.InvalidPacket;
            }

            var pkt = Pkt(repo_kind, repo_opts){ .ack = .{ .oid = content["ACK ".len..][0..oid_len].*, .status = null } };

            const rest = content["ACK ".len + oid_len ..];
            if (rest.len > 0 and rest[0] == ' ') {
                const status = rest[1..];
                pkt.ack.status =
                    if (std.mem.startsWith(u8, status, "continue"))
                        .cont
                    else if (std.mem.startsWith(u8, status, "common"))
                        .common
                    else if (std.mem.startsWith(u8, status, "ready"))
                        .ready
                    else
                        return error.InvalidPacket;
            }

            return pkt;
        }

        fn errPkt(allocator: std.mem.Allocator, content: []const u8) !Pkt(repo_kind, repo_opts) {
            if (content.len < "ERR ".len) {
                return error.InvalidPacket;
            }
            return .{ .err = try allocator.dupe(u8, content["ERR ".len..]) };
        }

        fn okPkt(allocator: std.mem.Allocator, content: []const u8) !Pkt(repo_kind, repo_opts) {
            if (content.len < "ok ".len) {
                return error.InvalidPacket;
            }
            return .{ .ok = try dupeChomped(allocator, content["ok ".len..]) };
        }

        fn ngPkt(allocator: std.mem.Allocator, content: []const u8) !Pkt(repo_kind, repo_opts) {
            if (content.len < "ng ".len) {
                return error.InvalidPacket;
            }
            return .{ .ng = try dupeChomped(allocator, content["ng ".len..]) };
        }

        fn shallowPkt(content: []const u8) !Pkt(repo_kind, repo_opts) {
            const oid_len = comptime hash.hexLen(repo_opts.hash);
            if (content.len < "shallow ".len + oid_len) {
                return error.InvalidPacket;
            }
            return .{ .shallow = .{ .oid = content["shallow ".len..][0..oid_len].* } };
        }

        fn unshallowPkt(content: []const u8) !Pkt(repo_kind, repo_opts) {
            const oid_len = comptime hash.hexLen(repo_opts.hash);
            if (content.len < "unshallow ".len + oid_len) {
                return error.InvalidPacket;
            }
            return .{ .unshallow = .{ .oid = content["unshallow ".len..][0..oid_len].* } };
        }

        fn refPkt(allocator: std.mem.Allocator, content: []const u8, found_capabilities: *bool) !Pkt(repo_kind, repo_opts) {
            // the content looks like "<oid> <name>[\x00<capabilities>]"
            if (!found_capabilities.*) {
                const caps = if (std.mem.indexOfScalar(u8, content, 0)) |pos| content[pos + 1 ..] else null;
                const remote_hash = try parseObjectFormat(caps);
                if (remote_hash != repo_opts.hash) return error.ObjectFormatMismatch;
            }
            const oid_len = comptime hash.hexLen(repo_opts.hash);
            if (content.len < oid_len) {
                return error.InvalidPacket;
            }
            const oid_hex = content[0..oid_len];

            var line = content[oid_len..];
            if (!std.mem.startsWith(u8, line, " ")) {
                return error.InvalidPacket;
            }
            line = line[1..];

            if (line.len == 0) {
                return error.InvalidPacket;
            }
            if (line[line.len - 1] == '\n') {
                line = line[0 .. line.len - 1];
            }

            const head_name = try allocator.dupe(u8, std.mem.sliceTo(line, 0));
            errdefer allocator.free(head_name);

            var head = net.RemoteHead(repo_kind, repo_opts).init(head_name);
            head.oid = oid_hex.*;

            var caps_maybe: ?[]const u8 = null;
            errdefer if (caps_maybe) |caps| allocator.free(caps);

            if (head_name.len < line.len) {
                if (!found_capabilities.*) {
                    caps_maybe = try allocator.dupe(u8, line[head_name.len + 1 ..]);
                } else {
                    return error.InvalidPacket;
                }
            }

            found_capabilities.* = true;

            return .{ .ref = .{
                .head = head,
                .capabilities = caps_maybe,
            } };
        }
    };
}

fn parseObjectFormat(caps: ?[]const u8) !hash.HashKind {
    var iter = std.mem.tokenizeAny(u8, caps orelse return .sha1, " \t\r\n");
    var result: ?hash.HashKind = null;
    while (iter.next()) |cap| {
        if (std.mem.startsWith(u8, cap, "object-format=")) {
            const kind = std.meta.stringToEnum(hash.HashKind, cap["object-format=".len..]) orelse return error.UnsupportedObjectFormat;
            if (result) |previous| {
                if (previous != kind) return error.UnsupportedObjectFormat;
            }
            result = kind;
        }
    }
    return result orelse .sha1;
}

/// dupe the line with its trailing newline (if any) removed
fn dupeChomped(allocator: std.mem.Allocator, line: []const u8) ![]u8 {
    const end = if (std.mem.endsWith(u8, line, "\n")) line.len - 1 else line.len;
    return allocator.dupe(u8, line[0..end]);
}

const PKT_HAVE_PREFIX = "have ";
const PKT_WANT_PREFIX = "want ";

const PKT_LEN_SIZE = 4;
const PKT_MAX_SIZE = 0xffff;

/// append a pkt-line to `buf`: a 4-digit hex length header followed by the
/// formatted content
pub fn appendPktLine(allocator: std.mem.Allocator, buf: *std.ArrayList(u8), comptime fmt: []const u8, args: anytype) !void {
    var content = std.Io.Writer.Allocating.init(allocator);
    defer content.deinit();
    try content.writer.print(fmt, args);

    const pkt_len = content.written().len + PKT_LEN_SIZE;
    if (pkt_len > PKT_MAX_SIZE) {
        return error.InvalidPacket;
    }
    var header: [PKT_LEN_SIZE]u8 = undefined;
    var header_writer: std.Io.Writer = .fixed(&header);
    header_writer.print("{x:0>4}", .{pkt_len}) catch unreachable;

    try buf.appendSlice(allocator, &header);
    try buf.appendSlice(allocator, content.written());
}

pub fn bufferHave(
    comptime repo_kind: rp.RepoKind,
    comptime repo_opts: rp.RepoOpts(repo_kind),
    allocator: std.mem.Allocator,
    oid_hex: *const [hash.hexLen(repo_opts.hash)]u8,
    buf: *std.ArrayList(u8),
) !void {
    try appendPktLine(allocator, buf, "{s}{s}\n", .{ PKT_HAVE_PREFIX, oid_hex });
}

fn bufferWantWithCaps(
    comptime repo_kind: rp.RepoKind,
    comptime repo_opts: rp.RepoOpts(repo_kind),
    allocator: std.mem.Allocator,
    head: *const net.RemoteHead(repo_kind, repo_opts),
    caps: *const net_wire.Capabilities,
    buf: *std.ArrayList(u8),
) !void {
    var caps_str = std.Io.Writer.Allocating.init(allocator);
    defer caps_str.deinit();

    if (caps.object_format) {
        try caps_str.writer.writeAll("object-format=" ++ @tagName(repo_opts.hash) ++ " ");
    }

    if (caps.multi_ack_detailed) {
        try caps_str.writer.writeAll("multi_ack_detailed ");
    } else if (caps.multi_ack) {
        try caps_str.writer.writeAll("multi_ack ");
    }

    if (caps.side_band_64k) {
        try caps_str.writer.writeAll("side-band-64k ");
    } else if (caps.side_band) {
        try caps_str.writer.writeAll("side-band ");
    }

    if (caps.include_tag) {
        try caps_str.writer.writeAll("include-tag ");
    }

    if (caps.thin_pack) {
        try caps_str.writer.writeAll("thin-pack ");
    }

    if (caps.ofs_delta) {
        try caps_str.writer.writeAll("ofs-delta ");
    }

    if (caps.shallow) {
        try caps_str.writer.writeAll("shallow ");
    }

    try appendPktLine(allocator, buf, "{s}{s} {s}\n", .{ PKT_WANT_PREFIX, &head.oid, caps_str.written() });
}

pub fn bufferWants(
    comptime repo_kind: rp.RepoKind,
    comptime repo_opts: rp.RepoOpts(repo_kind),
    allocator: std.mem.Allocator,
    wants: *const net_fetch.FetchNegotiation(repo_kind, repo_opts),
    caps: *const net_wire.Capabilities,
    buf: *std.ArrayList(u8),
) !void {
    var idx: usize = 0;
    if (caps.common) {
        for (wants.refs, 0..) |*head, i| {
            if (!head.is_local) {
                idx = i;
                break;
            }
        }

        try bufferWantWithCaps(repo_kind, repo_opts, allocator, &wants.refs[idx], caps, buf);

        idx += 1;
    }

    for (idx..wants.refs.len) |i| {
        const head = &wants.refs[i];

        if (head.is_local) {
            continue;
        }

        try appendPktLine(allocator, buf, "{s}{s}\n", .{ PKT_WANT_PREFIX, &head.oid });
    }

    try buf.appendSlice(allocator, "0000");
}

test "xit advertised object formats" {
    const allocator = std.testing.allocator;
    const Case = struct {
        local_hash: hash.HashKind,
        remote_hash: hash.HashKind,
        format: ?[]const u8,
        expected_error: ?anyerror,
    };
    const cases = [_]Case{
        .{ .local_hash = .sha1, .remote_hash = .sha1, .format = null, .expected_error = null },
        .{ .local_hash = .sha1, .remote_hash = .sha1, .format = "sha1", .expected_error = null },
        .{ .local_hash = .sha1, .remote_hash = .sha1, .format = "sha256", .expected_error = error.ObjectFormatMismatch },
        .{ .local_hash = .sha1, .remote_hash = .sha1, .format = "sha512", .expected_error = error.UnsupportedObjectFormat },
        .{ .local_hash = .sha1, .remote_hash = .sha256, .format = null, .expected_error = error.InvalidPacket },
        .{ .local_hash = .sha1, .remote_hash = .sha256, .format = "sha1", .expected_error = error.InvalidPacket },
        .{ .local_hash = .sha1, .remote_hash = .sha256, .format = "sha256", .expected_error = error.ObjectFormatMismatch },
        .{ .local_hash = .sha1, .remote_hash = .sha256, .format = "sha512", .expected_error = error.UnsupportedObjectFormat },
        .{ .local_hash = .sha256, .remote_hash = .sha1, .format = null, .expected_error = error.ObjectFormatMismatch },
        .{ .local_hash = .sha256, .remote_hash = .sha1, .format = "sha1", .expected_error = error.ObjectFormatMismatch },
        .{ .local_hash = .sha256, .remote_hash = .sha1, .format = "sha256", .expected_error = error.InvalidPacket },
        .{ .local_hash = .sha256, .remote_hash = .sha1, .format = "sha512", .expected_error = error.UnsupportedObjectFormat },
        .{ .local_hash = .sha256, .remote_hash = .sha256, .format = null, .expected_error = error.ObjectFormatMismatch },
        .{ .local_hash = .sha256, .remote_hash = .sha256, .format = "sha1", .expected_error = error.ObjectFormatMismatch },
        .{ .local_hash = .sha256, .remote_hash = .sha256, .format = "sha256", .expected_error = null },
        .{ .local_hash = .sha256, .remote_hash = .sha256, .format = "sha512", .expected_error = error.UnsupportedObjectFormat },
    };
    inline for (cases) |case| {
        var buffer: std.ArrayList(u8) = .empty;
        defer buffer.deinit(allocator);
        const oid = [_]u8{'1'} ** hash.hexLen(case.remote_hash);
        const caps = if (case.format) |name| "\x00object-format=" ++ name ++ "\n" else "\n";
        try appendPktLine(allocator, &buffer, "{s} refs/heads/main{s}", .{ &oid, caps });
        var found = false;
        var consumed: usize = 0;
        const parsed = Pkt(.xit, .{ .hash = case.local_hash }).initMaybe(allocator, buffer.items, &found, &consumed);
        if (case.expected_error) |expected| {
            try std.testing.expectError(expected, parsed);
        } else {
            var result = (try parsed).?;
            defer result.deinit(allocator);
            try std.testing.expectEqualStrings(&oid, &result.ref.head.oid);
            try std.testing.expectEqual(buffer.items.len, consumed);
        }
    }
}
