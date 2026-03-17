const std = @import("std");
const net = @import("../net.zig");
const net_wire = @import("./wire.zig");
const net_file = @import("./file.zig");
const net_push = @import("./push.zig");
const net_fetch = @import("./fetch.zig");
const net_ssh = @import("./ssh.zig");
const rp = @import("../repo.zig");
const hash = @import("../hash.zig");

pub fn Opts(comptime ProgressCtx: type) type {
    return struct {
        refspecs: ?[]const []const u8 = null,
        progress_ctx: ?ProgressCtx = null,
        wire: net_wire.Opts = .{},
    };
}

pub const TransportKind = enum {
    file,
    wire,
};

pub const Capabilities = struct {
    fetch_by_oid: bool = false,
    fetch_reachable: bool = false,
    push_options: bool = false,
};

pub fn Transport(comptime repo_kind: rp.RepoKind, comptime repo_opts: rp.RepoOpts(repo_kind)) type {
    return union(TransportKind) {
        file: net_file.FileTransport(repo_kind, repo_opts),
        wire: net_wire.WireTransport(repo_kind, repo_opts),

        pub fn init(
            state: rp.Repo(repo_kind, repo_opts).State(.read_only),
            io: std.Io,
            allocator: std.mem.Allocator,
            url: []const u8,
            opts: Opts(repo_opts.ProgressCtx),
        ) !Transport(repo_kind, repo_opts) {
            const transport_def_kind = TransportDefinition.init(io, state.core.cwd, url) orelse return error.UnsupportedUrl;
            return switch (transport_def_kind) {
                .file => .{ .file = try net_file.FileTransport(repo_kind, repo_opts).init(opts) },
                .wire => |wire_kind| .{ .wire = try net_wire.WireTransport(repo_kind, repo_opts).init(state, io, allocator, wire_kind, opts) },
            };
        }

        pub fn deinit(self: *Transport(repo_kind, repo_opts), io: std.Io, allocator: std.mem.Allocator) void {
            switch (self.*) {
                .file => |*file| file.deinit(io, allocator),
                .wire => |*wire| wire.deinit(io, allocator),
            }
        }

        pub fn connect(
            self: *Transport(repo_kind, repo_opts),
            state: rp.Repo(repo_kind, repo_opts).State(.read_only),
            io: std.Io,
            allocator: std.mem.Allocator,
            url: []const u8,
            direction: net.Direction,
        ) !void {
            switch (self.*) {
                .file => |*file| try file.connect(state, io, allocator, url, direction),
                .wire => |*wire| try wire.connect(io, allocator, url, direction),
            }
        }

        pub fn capabilities(self: *const Transport(repo_kind, repo_opts)) Capabilities {
            return switch (self.*) {
                .file => |*file| file.capabilities(),
                .wire => |*wire| wire.capabilities(),
            };
        }

        pub fn getHeads(self: *const Transport(repo_kind, repo_opts)) ![]net.RemoteHead(repo_kind, repo_opts) {
            return switch (self.*) {
                .file => |*file| try file.getHeads(),
                .wire => |*wire| try wire.getHeads(),
            };
        }

        pub fn push(
            self: *Transport(repo_kind, repo_opts),
            state: rp.Repo(repo_kind, repo_opts).State(.read_only),
            io: std.Io,
            allocator: std.mem.Allocator,
            git_push: *net_push.Push(repo_kind, repo_opts),
        ) !void {
            switch (self.*) {
                .file => |*file| try file.push(state, io, allocator, git_push),
                .wire => |*wire| try wire.push(io, allocator, git_push),
            }
        }

        pub fn negotiateFetch(
            self: *Transport(repo_kind, repo_opts),
            state: rp.Repo(repo_kind, repo_opts).State(.read_only),
            io: std.Io,
            allocator: std.mem.Allocator,
            fetch_data: *const net_fetch.FetchNegotiation(repo_kind, repo_opts),
        ) !void {
            switch (self.*) {
                .file => |*file| try file.negotiateFetch(state, io, allocator),
                .wire => |*wire| try wire.negotiateFetch(state, io, allocator, fetch_data),
            }
        }

        pub fn downloadPack(
            self: *Transport(repo_kind, repo_opts),
            state: rp.Repo(repo_kind, repo_opts).State(.read_write),
            io: std.Io,
            allocator: std.mem.Allocator,
        ) !void {
            switch (self.*) {
                .file => |*file| try file.downloadPack(state, io, allocator),
                .wire => |*wire| try wire.downloadPack(state, io, allocator),
            }
        }

        pub fn isConnected(self: *const Transport(repo_kind, repo_opts)) bool {
            switch (self.*) {
                .file => |*file| return file.isConnected(),
                .wire => |*wire| return wire.isConnected(),
            }
        }

        pub fn close(self: *Transport(repo_kind, repo_opts), io: std.Io, allocator: std.mem.Allocator) void {
            switch (self.*) {
                .file => |*file| file.close(io, allocator),
                .wire => |*wire| wire.close(io, allocator),
            }
        }
    };
}

const transports = std.StaticStringMap(TransportDefinition).initComptime(.{
    .{ "git://", TransportDefinition{ .wire = .raw } },
    .{ "http://", TransportDefinition{ .wire = .http } },
    .{ "https://", TransportDefinition{ .wire = .http } },
    .{ "file://", TransportDefinition.file },
    .{ "ssh://", TransportDefinition{ .wire = .ssh } },
});

pub const TransportDefinition = union(TransportKind) {
    file,
    wire: net_wire.WireKind,

    pub fn init(io: std.Io, cwd: std.Io.Dir, url: []const u8) ?TransportDefinition {
        if (initWithUrl(url)) |def| {
            return def;
        }

        if (net_ssh.parseUri(url)) |_| {
            return .{ .wire = .ssh };
        } else |_| {}

        var dir_or_err = cwd.openDir(io, url, .{});
        if (dir_or_err) |*dir| {
            defer dir.close(io);
            return .file;
        } else |_| {}

        return null;
    }

    fn initWithUrl(url: []const u8) ?TransportDefinition {
        const scheme_suffix = "://";
        if (std.mem.indexOf(u8, url, scheme_suffix)) |idx| {
            if (transports.get(url[0 .. idx + scheme_suffix.len])) |def| {
                return def;
            }
        }

        return null;
    }
};
