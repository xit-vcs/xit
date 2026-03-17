const std = @import("std");
const net_wire = @import("./wire.zig");

pub const HttpState = struct {
    http_client: std.http.Client,
    read_request: ?std.http.Client.Request,
    write_request: ?std.http.Client.Request,
    body_writer: ?std.http.BodyWriter,
    sent_write_request: bool,
    arena: *std.heap.ArenaAllocator,
    allocator: std.mem.Allocator,

    pub fn init(io: std.Io, allocator: std.mem.Allocator) !HttpState {
        var arena = try allocator.create(std.heap.ArenaAllocator);
        arena.* = .init(allocator);
        errdefer {
            arena.deinit();
            allocator.destroy(arena);
        }

        const client: std.http.Client = .{ .io = io, .allocator = arena.allocator() };
        // TODO: call `initDefaultProxies` here. the call was removed
        // because it requires an env map, which needs to be passed here
        // all the way from the main fn.

        return .{
            .http_client = client,
            .read_request = null,
            .write_request = null,
            .body_writer = null,
            .sent_write_request = false,
            .arena = arena,
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *HttpState) void {
        self.http_client.deinit();
        close(self);
        self.arena.deinit();
        self.allocator.destroy(self.arena);
        self.* = undefined;
    }

    pub fn close(self: *HttpState) void {
        if (self.read_request) |*req| {
            req.deinit();
            self.read_request = null;
        }
        if (self.write_request) |*req| {
            req.deinit();
            self.write_request = null;
        }
        self.body_writer = null;
        self.sent_write_request = false;
    }
};

pub const HttpStream = struct {
    wire_state: *HttpState,
    service: *const HttpInfo,
    url: []const u8,

    pub fn init(
        wire_state: *HttpState,
        url: []const u8,
        wire_action: net_wire.WireAction,
    ) !HttpStream {
        const service = switch (wire_action) {
            .list_upload_pack => &upload_pack_ls_info,
            .list_receive_pack => &receive_pack_ls_info,
            .upload_pack => &upload_pack_info,
            .receive_pack => &receive_pack_info,
        };

        return .{
            .service = service,
            .wire_state = wire_state,
            .url = url,
        };
    }

    pub fn deinit(_: *HttpStream) void {}

    pub fn write(
        self: *HttpStream,
        allocator: std.mem.Allocator,
        buffer: [*]const u8,
        len: usize,
    ) !void {
        if (self.wire_state.body_writer) |*body_writer| {
            try body_writer.writer.writeAll(buffer[0..len]);
            try body_writer.flush();
        } else {
            var request = try HttpRequest.init(allocator, self, len);
            defer request.deinit(allocator);
            try self.initWriteRequest(&request, buffer[0..len]);
        }
    }

    pub fn read(
        self: *HttpStream,
        allocator: std.mem.Allocator,
        buffer: [*]u8,
        len: usize,
    ) !usize {
        switch (self.service.method) {
            .GET => return if (self.wire_state.read_request) |*req|
                try readAny(&req.reader.interface, buffer[0..len]) orelse {
                    req.deinit();
                    self.wire_state.read_request = null;
                    return 0;
                }
            else
                try self.initReadRequest(allocator, buffer[0..len]),
            .POST => return if (self.wire_state.write_request) |*req|
                try self.readPost(req, buffer[0..len]) orelse {
                    req.deinit();
                    self.wire_state.write_request = null;
                    self.wire_state.body_writer = null;
                    self.wire_state.sent_write_request = false;
                    return 0;
                }
            else
                0,
            else => return error.UnexpectedHttpMethod,
        }
    }

    fn readAny(reader: *std.Io.Reader, buffer: []u8) !?usize {
        const size = try reader.readSliceShort(buffer);
        if (size == 0) return null;
        return size;
    }

    fn initReadRequest(
        self: *HttpStream,
        allocator: std.mem.Allocator,
        buffer: []u8,
    ) !usize {
        var request = try HttpRequest.init(allocator, self, 0);
        defer request.deinit(allocator);

        const uri = try std.Uri.parse(request.url);

        var req = try self.wire_state.http_client.request(request.method, uri, .{
            .keep_alive = false,
        });
        errdefer req.deinit();

        try req.sendBodiless();

        var response = try req.receiveHead(&.{});
        try self.handleResponse(response.head, true);
        const out_len = try readAny(response.reader(&.{}), buffer) orelse return error.UnexpectedEndOfStream;

        self.wire_state.read_request = req;

        return out_len;
    }

    fn initWriteRequest(
        self: *HttpStream,
        request: *const HttpRequest,
        buffer: []const u8,
    ) !void {
        const uri = try std.Uri.parse(request.url);

        var req = try self.wire_state.http_client.request(request.method, uri, .{
            .keep_alive = false,
        });
        errdefer req.deinit();

        req.transfer_encoding = if (request.chunked)
            .chunked
        else
            .{ .content_length = buffer.len };
        if (request.content_type) |content_type| {
            req.headers.content_type = .{ .override = content_type };
        }
        req.handle_continue = request.expect_continue;
        req.extra_headers = &.{
            .{ .name = "accept", .value = request.accept },
        };

        var body_writer = try req.sendBody(&.{});
        try body_writer.writer.writeAll(buffer);
        try body_writer.flush();

        self.wire_state.write_request = req;
        self.wire_state.body_writer = body_writer;
    }

    fn readPost(
        self: *HttpStream,
        req: *std.http.Client.Request,
        buffer: []u8,
    ) !?usize {
        var reader = &req.reader.interface;

        if (!self.wire_state.sent_write_request) {
            var body_writer = self.wire_state.body_writer orelse return error.BodyWriterNotFound;
            try body_writer.end();

            var response = try req.receiveHead(&.{});
            try self.handleResponse(response.head, false);
            reader = response.reader(&.{});

            self.wire_state.sent_write_request = true;
        }

        return try readAny(reader, buffer);
    }

    fn handleResponse(
        self: *HttpStream,
        head: std.http.Client.Response.Head,
        allow_replay: bool,
    ) !void {
        const is_redirect = head.status == .moved_permanently or
            head.status == .found or
            head.status == .see_other or
            head.status == .temporary_redirect or
            head.status == .permanent_redirect;

        if (allow_replay and is_redirect) {
            if (head.location) |_| {
                return error.HttpRedirectNotImplemented;
            } else {
                return error.HttpRedirectWithoutLocation;
            }
            return;
        } else if (is_redirect) {
            return error.HttpRedirectUnexpected;
        }

        if (head.status == .unauthorized or head.status == .proxy_auth_required) {
            return error.HttpUnauthorized;
        }

        if (head.status != .ok) {
            const status_code: c_int = @intFromEnum(head.status);
            _ = status_code;
            return error.HttpStatusCodeUnexpected;
        }

        if (head.content_type) |content_type| {
            if (!std.mem.eql(u8, content_type, self.service.response_type)) {
                return error.HttpContentTypeInvalid;
            }
        } else {
            return error.HttpContentTypeMissing;
        }
    }
};

const HttpInfo = struct {
    method: std.http.Method,
    url: []const u8,
    request_type: ?[]const u8,
    response_type: []const u8,
    chunked: bool,
};

const upload_pack_ls_info = HttpInfo{
    .method = .GET,
    .url = "/info/refs?service=git-upload-pack",
    .request_type = null,
    .response_type = "application/x-git-upload-pack-advertisement",
    .chunked = false,
};

const upload_pack_info = HttpInfo{
    .method = .POST,
    .url = "/git-upload-pack",
    .request_type = "application/x-git-upload-pack-request",
    .response_type = "application/x-git-upload-pack-result",
    .chunked = false,
};

const receive_pack_ls_info = HttpInfo{
    .method = .GET,
    .url = "/info/refs?service=git-receive-pack",
    .request_type = null,
    .response_type = "application/x-git-receive-pack-advertisement",
    .chunked = false,
};

const receive_pack_info = HttpInfo{
    .method = .POST,
    .url = "/git-receive-pack",
    .request_type = "application/x-git-receive-pack-request",
    .response_type = "application/x-git-receive-pack-result",
    .chunked = true,
};

const HttpRequest = struct {
    method: std.http.Method,
    url: []const u8,
    accept: []const u8,
    content_type: ?[]const u8,
    content_length: usize,
    chunked: bool,
    expect_continue: bool,

    fn init(
        allocator: std.mem.Allocator,
        stream: *HttpStream,
        len: usize,
    ) !HttpRequest {
        var uri = try std.Uri.parse(stream.url);
        const base_path = switch (uri.path) {
            .raw => |s| s,
            .percent_encoded => |s| s,
        };

        const path = try std.fmt.allocPrint(allocator, "{s}{s}", .{ base_path, stream.service.url });
        defer allocator.free(path);

        var uri_writer = std.Io.Writer.Allocating.init(allocator);
        defer uri_writer.deinit();

        uri.path = .{ .percent_encoded = path };
        try uri.writeToStream(&uri_writer.writer, .{ .scheme = true, .authority = true, .path = true, .port = true });

        const url = try allocator.dupe(u8, uri_writer.written());
        errdefer allocator.free(url);

        return .{
            .method = stream.service.method,
            .url = url,
            .accept = stream.service.response_type,
            .content_type = stream.service.request_type,
            .content_length = if (stream.service.chunked) 0 else len,
            .chunked = stream.service.chunked,
            .expect_continue = false,
        };
    }

    fn deinit(self: *HttpRequest, allocator: std.mem.Allocator) void {
        allocator.free(self.url);
    }
};
