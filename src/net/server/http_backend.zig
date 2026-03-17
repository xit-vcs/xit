const std = @import("std");
const common = @import("./common.zig");
const receive_pack = @import("./receive_pack.zig");
const upload_pack = @import("./upload_pack.zig");
const pkt = @import("./pkt.zig");

const rp = @import("../../repo.zig");
const cfg = @import("../../config.zig");

pub const HandlerKind = enum {
    get_info_refs,
    run_service,
};

pub const Options = struct {
    request_method: std.http.Method,
    handler: HandlerKind,
    suffix: []const u8,
    query_string: []const u8,
    content_type: []const u8,
    has_remote_user: bool,
    protocol_version: common.ProtocolVersion,
};

const Route = struct {
    method: std.http.Method,
    suffix: []const u8,
    handler: HandlerKind,
};

pub const routes = [_]Route{
    .{ .method = .GET, .suffix = "/info/refs", .handler = .get_info_refs },
    .{ .method = .POST, .suffix = "/git-upload-pack", .handler = .run_service },
    .{ .method = .POST, .suffix = "/git-receive-pack", .handler = .run_service },
};

const Config = struct {
    uploadpack: bool = true,
    receivepack: bool = false,
};

pub fn resolveDir(
    allocator: std.mem.Allocator,
    cwd_path: []const u8,
    environ_map: *std.process.Environ.Map,
) ![]const u8 {
    var path_buf: [4096]u8 = undefined;
    const path = try resolveRepoPath(environ_map, &path_buf);

    const dir = for (&routes) |*svc| {
        if (std.mem.endsWith(u8, path, svc.suffix)) {
            break path[0 .. path.len - svc.suffix.len];
        }
    } else return error.NotFound;

    return try std.fs.path.resolve(allocator, &.{ cwd_path, dir });
}

pub fn run(
    comptime repo_kind: rp.RepoKind,
    comptime repo_opts: rp.RepoOpts(repo_kind),
    state: rp.Repo(repo_kind, repo_opts).State(.read_write),
    io: std.Io,
    allocator: std.mem.Allocator,
    reader: *std.Io.Reader,
    writer: *std.Io.Writer,
    options: Options,
) !void {
    // method validation
    for (&routes) |*svc| {
        if (svc.handler == options.handler) {
            if (options.request_method != svc.method) {
                try sendBadRequest(writer, svc.method, options);
                return error.CancelTransaction;
            }
            break;
        }
    }

    runRoute(repo_kind, repo_opts, state, io, allocator, reader, writer, options) catch |err| switch (err) {
        error.Forbidden, error.ServiceNotEnabled => {
            try sendForbidden(writer);
            return error.CancelTransaction;
        },
        error.BadRequest, error.UnsupportedMediaType => return error.CancelTransaction,
        else => return err,
    };
}

fn runRoute(
    comptime repo_kind: rp.RepoKind,
    comptime repo_opts: rp.RepoOpts(repo_kind),
    state: rp.Repo(repo_kind, repo_opts).State(.read_write),
    io: std.Io,
    allocator: std.mem.Allocator,
    reader: *std.Io.Reader,
    writer: *std.Io.Writer,
    options: Options,
) !void {
    // read http config
    var http_config = Config{};
    {
        var config = try cfg.Config(repo_kind, repo_opts).init(state.readOnly(), io, allocator);
        defer config.deinit();

        if (config.sections.get("http")) |vars| {
            if (vars.get("uploadpack")) |v| http_config.uploadpack = common.parseBool(v);
            if (vars.get("receivepack")) |v| http_config.receivepack = common.parseBool(v);
        }
    }

    // auto-enable receivepack for authenticated users
    if (options.has_remote_user) {
        http_config.receivepack = true;
    }

    switch (options.handler) {
        .get_info_refs => try getInfoRefs(repo_kind, repo_opts, state, io, allocator, reader, writer, options, &http_config),
        .run_service => try runService(repo_kind, repo_opts, state, io, allocator, reader, writer, options, &http_config),
    }
}

fn httpStatus(writer: *std.Io.Writer, code: u16, msg: []const u8) std.Io.Writer.Error!void {
    try writer.print("Status: {d} {s}\r\n", .{ code, msg });
}

fn writeHeader(writer: *std.Io.Writer, name: []const u8, value: []const u8) std.Io.Writer.Error!void {
    try writer.print("{s}: {s}\r\n", .{ name, value });
}

fn writeNocacheHeaders(writer: *std.Io.Writer) std.Io.Writer.Error!void {
    try writeHeader(writer, "Expires", "Fri, 01 Jan 1980 00:00:00 GMT");
    try writeHeader(writer, "Pragma", "no-cache");
    try writeHeader(writer, "Cache-Control", "no-cache, max-age=0, must-revalidate");
}

fn finishHeaders(writer: *std.Io.Writer) std.Io.Writer.Error!void {
    try writer.writeAll("\r\n");
    try writer.flush();
}

pub fn sendNotFound(writer: *std.Io.Writer) std.Io.Writer.Error!void {
    try httpStatus(writer, 404, "Not Found");
    try writeNocacheHeaders(writer);
    try finishHeaders(writer);
}

fn sendForbidden(writer: *std.Io.Writer) std.Io.Writer.Error!void {
    try httpStatus(writer, 403, "Forbidden");
    try writeNocacheHeaders(writer);
    try finishHeaders(writer);
}

fn sendBadRequest(writer: *std.Io.Writer, allowed_method: std.http.Method, options: Options) std.Io.Writer.Error!void {
    if (options.request_method != allowed_method) {
        try httpStatus(writer, 405, "Method Not Allowed");
        try writeHeader(writer, "Allow", @tagName(allowed_method));
    } else {
        try httpStatus(writer, 400, "Bad Request");
    }
    try writeNocacheHeaders(writer);
    try finishHeaders(writer);
}

pub fn resolveRepoPath(environ_map: *std.process.Environ.Map, buf: []u8) ![]const u8 {
    if (environ_map.get("GIT_PROJECT_ROOT")) |root| {
        const path_info = environ_map.get("PATH_INFO") orelse return error.NotFound;
        // reject .. segments for path traversal safety
        var iter = std.mem.splitScalar(u8, path_info, '/');
        while (iter.next()) |segment| {
            if (std.mem.eql(u8, segment, "..")) return error.Forbidden;
        }
        if (root.len + path_info.len > buf.len) return error.NotFound;
        @memcpy(buf[0..root.len], root);
        @memcpy(buf[root.len..][0..path_info.len], path_info);
        return buf[0 .. root.len + path_info.len];
    }
    const path = environ_map.get("PATH_TRANSLATED") orelse return error.NotFound;
    var iter = std.mem.splitScalar(u8, path, '/');
    while (iter.next()) |segment| {
        if (std.mem.eql(u8, segment, "..")) return error.Forbidden;
    }
    return path;
}

fn getInfoRefs(
    comptime repo_kind: rp.RepoKind,
    comptime repo_opts: rp.RepoOpts(repo_kind),
    state: rp.Repo(repo_kind, repo_opts).State(.read_write),
    io: std.Io,
    allocator: std.mem.Allocator,
    reader: *std.Io.Reader,
    writer: *std.Io.Writer,
    options: Options,
    http_config: *const Config,
) !void {
    // smart protocol: ?service=git-upload-pack or ?service=git-receive-pack
    if (std.mem.startsWith(u8, options.query_string, "service=git-upload-pack")) {
        if (!http_config.uploadpack) return error.ServiceNotEnabled;
        try httpStatus(writer, 200, "OK");
        try writeHeader(writer, "Content-Type", "application/x-git-upload-pack-advertisement");
        try writeNocacheHeaders(writer);
        try finishHeaders(writer);

        if (options.protocol_version != .v2) {
            try pkt.writePktLineFmt(writer, "# service=git-upload-pack\n", .{});
            try pkt.writePktFlush(writer);
        }

        try upload_pack.run(repo_kind, repo_opts, state.readOnly(), io, allocator, reader, writer, .{
            .protocol_version = options.protocol_version,
            .advertise_refs = true,
            .is_stateless = true,
        });
        // no need to make a new transaction
        return error.CancelTransaction;
    }

    if (std.mem.startsWith(u8, options.query_string, "service=git-receive-pack")) {
        if (!http_config.receivepack) return error.ServiceNotEnabled;
        try httpStatus(writer, 200, "OK");
        try writeHeader(writer, "Content-Type", "application/x-git-receive-pack-advertisement");
        try writeNocacheHeaders(writer);
        try finishHeaders(writer);

        if (options.protocol_version != .v2) {
            try pkt.writePktLineFmt(writer, "# service=git-receive-pack\n", .{});
            try pkt.writePktFlush(writer);
        }

        try receive_pack.run(repo_kind, repo_opts, state, io, allocator, reader, writer, .{
            .protocol_version = options.protocol_version,
            .advertise_refs = true,
            .is_stateless = true,
        });
        // no need to make a new transaction
        return error.CancelTransaction;
    }

    return error.BadRequest;
}

fn runService(
    comptime repo_kind: rp.RepoKind,
    comptime repo_opts: rp.RepoOpts(repo_kind),
    state: rp.Repo(repo_kind, repo_opts).State(.read_write),
    io: std.Io,
    allocator: std.mem.Allocator,
    reader: *std.Io.Reader,
    writer: *std.Io.Writer,
    options: Options,
    http_config: *const Config,
) !void {
    // strip "/git-" prefix from suffix (e.g. "/git-upload-pack" -> "upload-pack")
    const service = if (std.mem.startsWith(u8, options.suffix, "/git-"))
        options.suffix["/git-".len..]
    else
        return error.BadRequest;

    const is_upload = std.mem.eql(u8, service, "upload-pack");
    const is_receive = std.mem.eql(u8, service, "receive-pack");

    if (!is_upload and !is_receive) return error.BadRequest;

    if (is_upload and !http_config.uploadpack) return error.ServiceNotEnabled;
    if (is_receive and !http_config.receivepack) return error.ServiceNotEnabled;

    // validate content-type
    var expected_ct_buf: [64]u8 = undefined;
    const expected_ct = std.fmt.bufPrint(&expected_ct_buf, "application/x-git-{s}-request", .{service}) catch return error.BadRequest;
    if (!std.mem.eql(u8, options.content_type, expected_ct)) {
        try httpStatus(writer, 415, "Unsupported Media Type");
        try writeNocacheHeaders(writer);
        try finishHeaders(writer);
        return error.UnsupportedMediaType;
    }

    // response headers
    var result_ct_buf: [64]u8 = undefined;
    const result_ct = std.fmt.bufPrint(&result_ct_buf, "application/x-git-{s}-result", .{service}) catch return error.BadRequest;
    try httpStatus(writer, 200, "OK");
    try writeHeader(writer, "Content-Type", result_ct);
    try writeNocacheHeaders(writer);
    try finishHeaders(writer);

    // dispatch
    if (is_upload) {
        try upload_pack.run(repo_kind, repo_opts, state.readOnly(), io, allocator, reader, writer, .{
            .protocol_version = options.protocol_version,
            .is_stateless = true,
        });
        // no need to make a new transaction
        return error.CancelTransaction;
    } else {
        try receive_pack.run(repo_kind, repo_opts, state, io, allocator, reader, writer, .{
            .protocol_version = options.protocol_version,
            .is_stateless = true,
        });
    }
}
