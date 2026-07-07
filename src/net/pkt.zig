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

        pub fn initMaybe(
            allocator: std.mem.Allocator,
            buffer: []const u8,
            found_capabilities: *bool,
            bufptr: *?[*]const u8,
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
                bufptr.* = line.ptr;
                return .{ .flush = {} };
            }

            len -= PKT_LEN_SIZE;
            bufptr.* = line[len..].ptr;

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

/// dupe the line with its trailing newline (if any) removed
fn dupeChomped(allocator: std.mem.Allocator, line: []const u8) ![]u8 {
    const end = if (std.mem.endsWith(u8, line, "\n")) line.len - 1 else line.len;
    return allocator.dupe(u8, line[0..end]);
}

const PKT_HAVE_PREFIX = "have ";
const PKT_WANT_PREFIX = "want ";

const PKT_LEN_SIZE = 4;
const PKT_MAX_SIZE = 0xffff;

pub fn commandSize(command: []u8, len: usize) !void {
    var command_size_buf = [_]u8{'0'} ** 4;
    const command_size = try std.fmt.bufPrint(&command_size_buf, "{x}", .{len});
    @memcpy(command[command_size_buf.len - command_size.len .. command_size_buf.len], command_size);
}

pub fn bufferHave(
    comptime repo_kind: rp.RepoKind,
    comptime repo_opts: rp.RepoOpts(repo_kind),
    allocator: std.mem.Allocator,
    oid_hex: *const [hash.hexLen(repo_opts.hash)]u8,
    buf: *std.ArrayList(u8),
) !void {
    var command_size_buf = [_]u8{'0'} ** 4;

    const line = try std.fmt.allocPrint(allocator, "{s}{s}{s}\n", .{ &command_size_buf, PKT_HAVE_PREFIX, oid_hex });
    defer allocator.free(line);

    try commandSize(&command_size_buf, line.len);
    @memcpy(line[0..4], &command_size_buf);

    try buf.appendSlice(allocator, line);
}

fn bufferWantWithCaps(
    comptime repo_kind: rp.RepoKind,
    comptime repo_opts: rp.RepoOpts(repo_kind),
    allocator: std.mem.Allocator,
    head: *const net.RemoteHead(repo_kind, repo_opts),
    caps: *const net_wire.Capabilities,
    buf: *std.ArrayList(u8),
) !void {
    var line = std.Io.Writer.Allocating.init(allocator);
    defer line.deinit();

    var command_size_buf = [_]u8{'0'} ** 4;

    try line.writer.print("{s}{s}{s} ", .{ &command_size_buf, PKT_WANT_PREFIX, &head.oid });

    if (caps.multi_ack_detailed) {
        try line.writer.writeAll("multi_ack_detailed ");
    } else if (caps.multi_ack) {
        try line.writer.writeAll("multi_ack ");
    }

    if (caps.side_band_64k) {
        try line.writer.writeAll("side-band-64k ");
    } else if (caps.side_band) {
        try line.writer.writeAll("side-band ");
    }

    if (caps.include_tag) {
        try line.writer.writeAll("include-tag ");
    }

    if (caps.thin_pack) {
        try line.writer.writeAll("thin-pack ");
    }

    if (caps.ofs_delta) {
        try line.writer.writeAll("ofs-delta ");
    }

    if (caps.shallow) {
        try line.writer.writeAll("shallow ");
    }

    try line.writer.writeByte('\n');

    const PKT_MAX_WANTLEN = (PKT_LEN_SIZE + PKT_WANT_PREFIX.len + hash.hexLen(repo_opts.hash) + 1);

    var written = line.written();

    if (written.len > (PKT_MAX_SIZE - (PKT_MAX_WANTLEN + 1))) {
        return error.InvalidPacket;
    }

    try commandSize(&command_size_buf, written.len);
    @memcpy(written[0..4], &command_size_buf);

    try buf.appendSlice(allocator, written);
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

        var command_size_buf = [_]u8{'0'} ** 4;

        const line = try std.fmt.allocPrint(allocator, "{s}{s}{s}\n", .{ &command_size_buf, PKT_WANT_PREFIX, &head.oid });
        defer allocator.free(line);

        try commandSize(&command_size_buf, line.len);
        @memcpy(line[0..4], &command_size_buf);

        try buf.appendSlice(allocator, line);
    }

    try buf.appendSlice(allocator, "0000");
}
