const std = @import("std");
const builtin = @import("builtin");
const xit = @import("xit");
const rp = xit.repo;
const rf = xit.ref;
const net = xit.net;
const hash = xit.hash;
const pkt = xit.net_pkt;

test "git fetch small" {
    const io = std.testing.io;
    const allocator = std.testing.allocator;
    try testFetch(.git, .git, .{ .wire = .http }, 3001, .sha1, io, allocator);
    if (.windows != builtin.os.tag) {
        try testFetch(.git, .git, .{ .wire = .raw }, 3002, .sha1, io, allocator);
        try testFetch(.git, .git, .{ .wire = .ssh }, 3003, .sha1, io, allocator);
    }
    try testFetch(.git, .git, .file, 0, .sha1, io, allocator);
}

test "xit fetch small" {
    const io = std.testing.io;
    const allocator = std.testing.allocator;
    try testFetch(.xit, .xit, .{ .wire = .http }, 3101, .sha1, io, allocator);
    try testFetch(.xit, .xit, .{ .wire = .http }, 3102, .sha256, io, allocator);
    if (.windows != builtin.os.tag) {
        try testFetch(.xit, .git, .{ .wire = .raw }, 3103, .sha1, io, allocator);
        try testFetch(.xit, .git, .{ .wire = .raw }, 3104, .sha256, io, allocator);
        try testFetch(.xit, .xit, .{ .wire = .ssh }, 3105, .sha1, io, allocator);
        try testFetch(.xit, .xit, .{ .wire = .ssh }, 3106, .sha256, io, allocator);
    }
    try testFetch(.xit, .xit, .file, 0, .sha1, io, allocator);
    try testFetch(.xit, .xit, .file, 0, .sha256, io, allocator);
}

test "git push small" {
    const io = std.testing.io;
    const allocator = std.testing.allocator;
    try testPush(.git, .git, .{ .wire = .http }, 3201, .sha1, io, allocator);
    if (.windows != builtin.os.tag) {
        try testPush(.git, .git, .{ .wire = .raw }, 3202, .sha1, io, allocator);
        try testPush(.git, .git, .{ .wire = .ssh }, 3203, .sha1, io, allocator);
    }
    try testPush(.git, .git, .file, 0, .sha1, io, allocator);
    try testPush(.git, .git, .file, 0, .sha256, io, allocator);
    try testPush(.git, .xit, .file, 0, .sha1, io, allocator);
    try testPush(.git, .xit, .file, 0, .sha256, io, allocator);
}

test "xit push small" {
    const io = std.testing.io;
    const allocator = std.testing.allocator;
    try testPush(.xit, .xit, .{ .wire = .http }, 3301, .sha1, io, allocator);
    try testPush(.xit, .xit, .{ .wire = .http }, 3302, .sha256, io, allocator);
    if (.windows != builtin.os.tag) {
        try testPush(.xit, .git, .{ .wire = .raw }, 3303, .sha1, io, allocator);
        try testPush(.xit, .git, .{ .wire = .raw }, 3304, .sha256, io, allocator);
        try testPush(.xit, .xit, .{ .wire = .ssh }, 3305, .sha1, io, allocator);
        try testPush(.xit, .xit, .{ .wire = .ssh }, 3306, .sha256, io, allocator);
    }
    try testPush(.xit, .git, .file, 0, .sha1, io, allocator);
    try testPush(.xit, .git, .file, 0, .sha256, io, allocator);
    try testPush(.xit, .xit, .file, 0, .sha1, io, allocator);
    try testPush(.xit, .xit, .file, 0, .sha256, io, allocator);
}

test "git clone small" {
    const io = std.testing.io;
    const allocator = std.testing.allocator;
    try testClone(.git, .git, .{ .wire = .http }, 3401, false, .sha1, io, allocator);
    if (.windows != builtin.os.tag) {
        try testClone(.git, .git, .{ .wire = .raw }, 3402, false, .sha1, io, allocator);
        try testClone(.git, .git, .{ .wire = .ssh }, 3403, false, .sha1, io, allocator);
    }
    try testClone(.git, .git, .file, 0, false, .sha1, io, allocator);
    try testClone(.git, .git, .file, 0, false, .sha256, io, allocator);
    try testClone(.git, .xit, .file, 0, false, .sha1, io, allocator);
    try testClone(.git, .xit, .file, 0, false, .sha256, io, allocator);
}

test "xit clone small" {
    const io = std.testing.io;
    const allocator = std.testing.allocator;
    try testClone(.xit, .xit, .{ .wire = .http }, 3501, false, .sha1, io, allocator);
    try testClone(.xit, .xit, .{ .wire = .http }, 3502, false, .sha256, io, allocator);
    if (.windows != builtin.os.tag) {
        try testClone(.xit, .git, .{ .wire = .raw }, 3503, false, .sha1, io, allocator);
        try testClone(.xit, .git, .{ .wire = .raw }, 3504, false, .sha256, io, allocator);
        try testClone(.xit, .xit, .{ .wire = .ssh }, 3505, false, .sha1, io, allocator);
        try testClone(.xit, .xit, .{ .wire = .ssh }, 3506, false, .sha256, io, allocator);
    }
    try testClone(.xit, .git, .file, 0, false, .sha1, io, allocator);
    try testClone(.xit, .git, .file, 0, false, .sha256, io, allocator);
    try testClone(.xit, .xit, .file, 0, false, .sha1, io, allocator);
    try testClone(.xit, .xit, .file, 0, false, .sha256, io, allocator);
}

test "git clone small subprocess" {
    const io = std.testing.io;
    const allocator = std.testing.allocator;
    try testClone(.git, .xit, .{ .wire = .http }, 3601, true, .sha1, io, allocator);
    try testClone(.git, .xit, .{ .wire = .http }, 3602, true, .sha256, io, allocator);
    if (.windows != builtin.os.tag) {
        try testClone(.git, .git, .{ .wire = .raw }, 3603, true, .sha1, io, allocator);
        try testClone(.git, .git, .{ .wire = .raw }, 3604, true, .sha256, io, allocator);
        try testClone(.git, .xit, .{ .wire = .ssh }, 3605, true, .sha1, io, allocator);
        try testClone(.git, .xit, .{ .wire = .ssh }, 3606, true, .sha256, io, allocator);
    }
}

test "git fetch large" {
    const io = std.testing.io;
    const allocator = std.testing.allocator;
    try testFetchLarge(.git, .git, .{ .wire = .http }, 3701, false, .sha1, io, allocator);
    if (.windows != builtin.os.tag) {
        try testFetchLarge(.git, .git, .{ .wire = .raw }, 3702, false, .sha1, io, allocator);
        try testFetchLarge(.git, .git, .{ .wire = .ssh }, 3703, false, .sha1, io, allocator);
    }
    try testFetchLarge(.git, .git, .file, 0, false, .sha1, io, allocator);
}

test "git fetch large subprocess" {
    const io = std.testing.io;
    const allocator = std.testing.allocator;
    try testFetchLarge(.git, .xit, .{ .wire = .http }, 3801, true, .sha1, io, allocator);
    try testFetchLarge(.git, .xit, .{ .wire = .http }, 3802, true, .sha256, io, allocator);
    if (.windows != builtin.os.tag) {
        try testFetchLarge(.git, .git, .{ .wire = .raw }, 3803, true, .sha1, io, allocator);
        try testFetchLarge(.git, .git, .{ .wire = .raw }, 3804, true, .sha256, io, allocator);
        try testFetchLarge(.git, .xit, .{ .wire = .ssh }, 3805, true, .sha1, io, allocator);
        try testFetchLarge(.git, .xit, .{ .wire = .ssh }, 3806, true, .sha256, io, allocator);
    }
}

test "git push large" {
    const io = std.testing.io;
    const allocator = std.testing.allocator;
    try testPushLarge(.git, .git, .{ .wire = .http }, 3901, false, .sha1, io, allocator);
    if (.windows != builtin.os.tag) {
        try testPushLarge(.git, .git, .{ .wire = .raw }, 3902, false, .sha1, io, allocator);
        try testPushLarge(.git, .git, .{ .wire = .ssh }, 3903, false, .sha1, io, allocator);
    }
    try testPushLarge(.git, .git, .file, 0, false, .sha1, io, allocator);
}

test "git push large subprocess" {
    const io = std.testing.io;
    const allocator = std.testing.allocator;
    try testPushLarge(.git, .xit, .{ .wire = .http }, 4001, true, .sha1, io, allocator);
    try testPushLarge(.git, .xit, .{ .wire = .http }, 4002, true, .sha256, io, allocator);
    if (.windows != builtin.os.tag) {
        try testPushLarge(.git, .git, .{ .wire = .raw }, 4003, true, .sha1, io, allocator);
        try testPushLarge(.git, .git, .{ .wire = .raw }, 4004, true, .sha256, io, allocator);
        try testPushLarge(.git, .xit, .{ .wire = .ssh }, 4005, true, .sha1, io, allocator);
        try testPushLarge(.git, .xit, .{ .wire = .ssh }, 4006, true, .sha256, io, allocator);
    }
}

test "xit server rejects incompatible object formats" {
    const io = std.testing.io;
    const allocator = std.testing.allocator;
    inline for (.{ .sha1, .sha256 }) |hash_kind| {
        var temp = std.testing.tmpDir(.{});
        defer temp.cleanup();
        const path = try temp.dir.realPathFileAlloc(io, ".", allocator);
        defer allocator.free(path);
        var repo = try rp.Repo(.xit, .{ .hash = hash_kind, .is_test = true }).init(io, allocator, .{ .path = path, .bare = true });
        defer repo.deinit(io, allocator);
        const zero = [_]u8{'0'} ** hash.hexLen(hash_kind);
        inline for ([_]?[]const u8{ null, "sha1", "sha256", "sha512" }) |format| {
            const selected: ?hash.HashKind = if (format) |name| std.meta.stringToEnum(hash.HashKind, name) else .sha1;
            if (selected != hash_kind) {
                var request: std.ArrayList(u8) = .empty;
                defer request.deinit(allocator);
                const caps = if (format) |name| "\x00side-band-64k object-format=" ++ name else "";
                try pkt.appendPktLine(allocator, &request, "{s} {s} refs/heads/master{s}\n", .{ &zero, &zero, caps });
                try request.appendSlice(allocator, "0000");
                var reader = std.Io.Reader.fixed(request.items);
                var output = std.Io.Writer.Discarding.init(&.{});
                try std.testing.expectError(error.ObjectFormatMismatch, repo.receivePack(io, allocator, &reader, &output.writer, .{ .is_stateless = true }));
                try std.testing.expectEqual(null, try repo.readRef(io, .{ .kind = .head, .name = "master" }));

                // legacy fetch may omit the format, but explicit conflicts are rejected.
                if (format) |name| {
                    request.clearRetainingCapacity();
                    try pkt.appendPktLine(allocator, &request, "want {s} object-format={s}\n", .{ &zero, name });
                    try request.appendSlice(allocator, "0000");
                    reader = .fixed(request.items);
                    try std.testing.expectError(error.ObjectFormatMismatch, repo.uploadPack(io, allocator, &reader, &output.writer, .{ .is_stateless = true }));
                }
            }
        }
    }
}

fn Server(
    comptime server_repo_kind: rp.RepoKind,
    comptime transport_def: net.TransportDefinition,
    comptime port: u16,
) type {
    if (server_repo_kind == .xit and transport_def == .wire and transport_def.wire == .raw) {
        @compileError("git daemon cannot serve .xit repos");
    }

    return struct {
        core: Core,

        const Core = switch (transport_def) {
            .file => void,
            .wire => |wire_kind| switch (wire_kind) {
                .http => struct {
                    io: std.Io,
                    allocator: std.mem.Allocator,
                    temp_path: []const u8,
                    stop_server_endpoint: []const u8,
                    net_server: std.Io.net.Server,
                    server_thread: std.Thread,
                },
                .raw => struct {
                    io: std.Io,
                    process: ?std.process.Child,
                    temp_path: []const u8,
                },
                .ssh => struct {
                    io: std.Io,
                    process: ?std.process.Child,
                    temp_path: []const u8,
                },
            },
        };

        fn init(
            io: std.Io,
            allocator: std.mem.Allocator,
            temp_dir: std.Io.Dir,
            temp_path: []const u8,
        ) !Server(server_repo_kind, transport_def, port) {
            switch (transport_def) {
                .file => return .{ .core = {} },
                .wire => |wire_kind| switch (wire_kind) {
                    .http => {
                        const address = try std.Io.net.IpAddress.parseIp4("127.0.0.1", port);
                        const net_server = try address.listen(io, .{ .reuse_address = true });
                        errdefer net_server.deinit();
                        return .{
                            .core = .{
                                .io = io,
                                .allocator = allocator,
                                .temp_path = temp_path,
                                .stop_server_endpoint = std.fmt.comptimePrint("http://127.0.0.1:{}/stop-server", .{port}),
                                .net_server = net_server,
                                .server_thread = undefined,
                            },
                        };
                    },
                    .raw => return .{
                        .core = .{ .io = io, .process = null, .temp_path = temp_path },
                    },
                    .ssh => {
                        // create priv host key
                        const host_key_file = try temp_dir.createFile(io, "host_key", .{});
                        defer host_key_file.close(io);
                        try host_key_file.writeStreamingAll(io,
                            \\-----BEGIN OPENSSH PRIVATE KEY-----
                            \\b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAaAAAABNlY2RzYS
                            \\1zaGEyLW5pc3RwMjU2AAAACG5pc3RwMjU2AAAAQQS1ppUfk8n7yvVKEgz3tXjt4q76VGuj
                            \\LcQlRwmogzovV40LLcX0aTObZlQaLWfzJMNpCa/ztMpQlr86nsarE4lEAAAAqLe43zK3uN
                            \\8yAAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBLWmlR+TyfvK9UoS
                            \\DPe1eO3irvpUa6MtxCVHCaiDOi9XjQstxfRpM5tmVBotZ/Mkw2kJr/O0ylCWvzqexqsTiU
                            \\QAAAAgQ+LCk30ZNJxb2Da5JL+QOFWCMf7bgXCWcEzhEGGvFWYAAAALcmFkYXJAcm9hcmsB
                            \\AgMEBQ==
                            \\-----END OPENSSH PRIVATE KEY-----
                            \\
                        );
                        if (.windows != builtin.os.tag) {
                            try host_key_file.setPermissions(io, @enumFromInt(0o600));
                        }

                        // create priv client key
                        const priv_key_file = try temp_dir.createFile(io, "key", .{});
                        defer priv_key_file.close(io);
                        try priv_key_file.writeStreamingAll(io,
                            \\-----BEGIN OPENSSH PRIVATE KEY-----
                            \\b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
                            \\QyNTUxOQAAACCniLPJiaooAWecvOCeAjoJwCSeWxzysvpTNkpYjF22JgAAAJA+7hikPu4Y
                            \\pAAAAAtzc2gtZWQyNTUxOQAAACCniLPJiaooAWecvOCeAjoJwCSeWxzysvpTNkpYjF22Jg
                            \\AAAEDVlopOMnKt/7by/IA8VZvQXUS/O6VLkixOqnnahUdPCKeIs8mJqigBZ5y84J4COgnA
                            \\JJ5bHPKy+lM2SliMXbYmAAAAC3JhZGFyQHJvYXJrAQI=
                            \\-----END OPENSSH PRIVATE KEY-----
                            \\
                        );
                        if (.windows != builtin.os.tag) {
                            try priv_key_file.setPermissions(io, @enumFromInt(0o600));
                        }

                        // create pub key
                        const pub_key_file = try temp_dir.createFile(io, "key.pub", .{});
                        defer pub_key_file.close(io);
                        try pub_key_file.writeStreamingAll(io,
                            \\ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKeIs8mJqigBZ5y84J4COgnAJJ5bHPKy+lM2SliMXbYm radar@roark
                            \\
                        );
                        if (.windows != builtin.os.tag) {
                            try pub_key_file.setPermissions(io, @enumFromInt(0o600));
                        }

                        // create authorized_keys file
                        const auth_keys_file = try temp_dir.createFile(io, "authorized_keys", .{});
                        defer auth_keys_file.close(io);
                        try auth_keys_file.writeStreamingAll(io,
                            \\ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKeIs8mJqigBZ5y84J4COgnAJJ5bHPKy+lM2SliMXbYm radar@roark
                            \\
                        );
                        if (.windows != builtin.os.tag) {
                            try auth_keys_file.setPermissions(io, @enumFromInt(0o600));
                        }

                        // create known_hosts file
                        const known_hosts_file = try temp_dir.createFile(io, "known_hosts", .{});
                        defer known_hosts_file.close(io);
                        const port_str = std.fmt.comptimePrint("{}", .{port});
                        try known_hosts_file.writeStreamingAll(io, "[localhost]:" ++ port_str ++ " ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBLWmlR+TyfvK9UoSDPe1eO3irvpUa6MtxCVHCaiDOi9XjQstxfRpM5tmVBotZ/Mkw2kJr/O0ylCWvzqexqsTiUQ=");
                        if (.windows != builtin.os.tag) {
                            try known_hosts_file.setPermissions(io, @enumFromInt(0o600));
                        }

                        // create sshd_config file
                        const sshd_config_str = blk: {
                            // SetEnv PATH=... allows us to propagate the test process's PATH
                            // to the spawned login shell (in sshd).
                            //
                            // without it, shells that don't auto-resource PATH on startup (e.g. nushell
                            // on NixOS) through /etc/set-environment will fail to find
                            // git-upload-pack / git-receive-pack.
                            const base_config =
                                \\AuthenticationMethods publickey
                                \\PubkeyAuthentication yes
                                \\PasswordAuthentication no
                                \\StrictModes no
                                //SetEnv PATH={s} -- if we find $PATH defined.
                            ;
                            var env_map = try std.process.Environ.createMap(std.testing.io_instance.environ.process_environ, allocator);
                            defer env_map.deinit();

                            const config_str = if (env_map.get("PATH")) |path_str|
                                try std.fmt.allocPrint(allocator, "{s}\n" ++ "SetEnv PATH={s}\n", .{ base_config, path_str })
                            else
                                try std.fmt.allocPrint(allocator, "{s}", .{base_config});

                            break :blk config_str;
                        };
                        defer allocator.free(sshd_config_str);

                        const sshd_config_file = try temp_dir.createFile(io, "sshd_config", .{});
                        defer sshd_config_file.close(io);
                        try sshd_config_file.writeStreamingAll(io, sshd_config_str);
                        if (.windows != builtin.os.tag) {
                            try sshd_config_file.setPermissions(io, @enumFromInt(0o600));
                        }

                        // create sshd.sh contents
                        const host_key_path = try std.fs.path.join(allocator, &.{ temp_path, "host_key" });
                        defer allocator.free(host_key_path);
                        const auth_keys_path = try std.fs.path.join(allocator, &.{ temp_path, "authorized_keys" });
                        defer allocator.free(auth_keys_path);
                        const sshd_contents = try std.fmt.allocPrint(
                            allocator,
                            "#!/bin/sh\nexec $(which sshd) -p {} -f sshd_config -h \"{s}\" -D -e -o AuthorizedKeysFile=\"{s}\"",
                            .{ port, host_key_path, auth_keys_path },
                        );
                        defer allocator.free(sshd_contents);

                        // if path has a space char, it fucks up sshd
                        try std.testing.expect(null == std.mem.indexOfScalar(u8, auth_keys_path, ' '));

                        // create sshd.sh
                        {
                            const sshd_file = try temp_dir.createFile(io, "sshd.sh", .{});
                            defer sshd_file.close(io);
                            try sshd_file.writeStreamingAll(io, sshd_contents);
                            if (.windows != builtin.os.tag) {
                                try sshd_file.setPermissions(io, .executable_file);
                            }
                        }

                        return .{
                            .core = .{ .io = io, .process = null, .temp_path = temp_path },
                        };
                    },
                },
            }
        }

        fn start(self: *Server(server_repo_kind, transport_def, port)) !void {
            switch (transport_def) {
                .file => {},
                .wire => |wire_kind| switch (wire_kind) {
                    .http => {
                        const ServerHandler = struct {
                            fn run(core: *Core) !void {
                                var send_buffer = [_]u8{0} ** 1024;
                                var recv_buffer = [_]u8{0} ** 1024;

                                accept: while (true) {
                                    const stream = try core.net_server.accept(core.io);
                                    defer stream.close(core.io);

                                    var conn_br = stream.reader(core.io, &recv_buffer);
                                    var conn_bw = stream.writer(core.io, &send_buffer);
                                    var http_server = std.http.Server.init(&conn_br.interface, &conn_bw.interface);

                                    while (http_server.reader.state == .ready) {
                                        var request = http_server.receiveHead() catch |err| switch (err) {
                                            error.HttpConnectionClosing => continue :accept,
                                            else => |e| return e,
                                        };
                                        if (std.mem.eql(u8, request.head.target, "/stop-server")) {
                                            break :accept;
                                        }

                                        const uri = try std.Uri.parseAfterScheme("", request.head.target);
                                        if (uri.path.percent_encoded[0] != '/') return error.PathMustStartWithSlash;
                                        const path = if (std.mem.indexOfScalar(u8, uri.path.percent_encoded[1..], '/')) |idx|
                                            uri.path.percent_encoded[idx + 1 ..]
                                        else
                                            return error.SlashNotFound;

                                        const path_translated = try std.fmt.allocPrint(core.allocator, "{s}{s}", .{
                                            core.temp_path,
                                            uri.path.percent_encoded,
                                        });
                                        defer core.allocator.free(path_translated);

                                        // init env map
                                        var env_map = std.process.Environ.Map.init(core.allocator);
                                        defer env_map.deinit();
                                        try env_map.put("GATEWAY_INTERFACE", "CGI/1.1");
                                        try env_map.put("REQUEST_METHOD", @tagName(request.head.method));
                                        try env_map.put("PATH_INFO", path);
                                        try env_map.put("PATH_TRANSLATED", path_translated);
                                        if (uri.query) |query| {
                                            try env_map.put("QUERY_STRING", query.percent_encoded);
                                        }

                                        var accept: std.ArrayList([]const u8) = .empty;
                                        defer accept.deinit(core.allocator);

                                        var keep_alive = true; // HTTP 1.1 defaults to keep-alive

                                        // iterate over headers to fill env map
                                        var req_header_it = request.iterateHeaders();
                                        while (req_header_it.next()) |header| {
                                            const header_name = header.name;
                                            const header_value = header.value;

                                            if (std.ascii.eqlIgnoreCase(header_name, "content-type")) {
                                                try env_map.put("CONTENT_TYPE", header_value);
                                            } else if (std.ascii.eqlIgnoreCase(header_name, "content-length")) {
                                                try env_map.put("CONTENT_LENGTH", header_value);
                                            } else if (std.ascii.eqlIgnoreCase(header_name, "referer")) {
                                                try env_map.put("HTTP_REFERER", header_value);
                                            } else if (std.ascii.eqlIgnoreCase(header_name, "accept")) {
                                                try accept.append(core.allocator, header_value);
                                            } else if (std.ascii.eqlIgnoreCase(header_name, "user-agent")) {
                                                try env_map.put("HTTP_USER_AGENT", header_value);
                                            } else if (std.ascii.eqlIgnoreCase(header_name, "connection")) {
                                                if (std.ascii.eqlIgnoreCase(header_value, "close")) {
                                                    keep_alive = false;
                                                }
                                            } else if (std.ascii.eqlIgnoreCase(header_name, "git-protocol")) {
                                                try env_map.put("GIT_PROTOCOL", header_value);
                                            }
                                        }

                                        const accept_str = try std.mem.join(core.allocator, ",", accept.items);
                                        defer core.allocator.free(accept_str);
                                        if (accept_str.len > 0) {
                                            try env_map.put("HTTP_ACCEPT", accept_str);
                                        }

                                        const cwd_path = try std.process.currentPathAlloc(core.io, core.allocator);
                                        defer core.allocator.free(cwd_path);
                                        const xit_path = try std.fs.path.join(core.allocator, &.{ cwd_path, "zig-out", "bin", "xit" });
                                        defer core.allocator.free(xit_path);

                                        var process = try std.process.spawn(core.io, .{
                                            .argv = switch (server_repo_kind) {
                                                .git => &.{ "git", "http-backend" },
                                                .xit => &.{ xit_path, "http-backend" },
                                            },
                                            .cwd = switch (server_repo_kind) {
                                                .git => .inherit,
                                                .xit => .{ .path = core.temp_path },
                                            },
                                            .environ_map = &env_map,
                                            .stdin = .pipe,
                                            .stdout = .pipe,
                                            .stderr = .pipe,
                                        });
                                        defer process.kill(core.io);

                                        if (request.head.method == .POST) {
                                            const reader = try request.readerExpectContinue(&.{});
                                            const request_body = try reader.allocRemaining(core.allocator, .unlimited);
                                            defer core.allocator.free(request_body);
                                            try process.stdin.?.writeStreamingAll(core.io, request_body);
                                        }
                                        process.stdin.?.close(core.io);
                                        process.stdin = null;

                                        var multi_reader_buffer: std.Io.File.MultiReader.Buffer(2) = undefined;
                                        var multi_reader: std.Io.File.MultiReader = undefined;
                                        multi_reader.init(core.allocator, core.io, multi_reader_buffer.toStreams(), &.{ process.stdout.?, process.stderr.? });
                                        defer multi_reader.deinit();

                                        while (multi_reader.fill(64, .none)) |_| {} else |err| switch (err) {
                                            error.EndOfStream => {},
                                            else => |e| return e,
                                        }

                                        try multi_reader.checkAnyError();

                                        _ = try process.wait(core.io);

                                        const stdout_slice = try multi_reader.toOwnedSlice(0);
                                        defer core.allocator.free(stdout_slice);
                                        const stderr_slice = try multi_reader.toOwnedSlice(1);
                                        defer core.allocator.free(stderr_slice);

                                        // transition the http state machine so it can
                                        // read the next request on this connection
                                        if (http_server.reader.state == .received_head) {
                                            http_server.reader.state = .ready;
                                        }

                                        if (stderr_slice.len > 0) {
                                            std.debug.print("Error from git-http-backend:\n{s}\n", .{stderr_slice});
                                            try http_server.out.writeAll("HTTP/1.1 500 Internal Server Error\r\n\r\n");
                                        } else {
                                            try http_server.out.writeAll("HTTP/1.1 200 OK\r\n");
                                            const double_newline = "\r\n\r\n";
                                            const double_newline_idx = std.mem.indexOf(u8, stdout_slice, double_newline) orelse unreachable;
                                            try http_server.out.writeAll(stdout_slice[0..double_newline_idx]);
                                            try http_server.out.print("\r\nContent-Length: {}", .{stdout_slice.len - (double_newline_idx + double_newline.len)});
                                            try http_server.out.writeAll(stdout_slice[double_newline_idx..]);
                                        }
                                        try http_server.out.flush();

                                        if (!keep_alive) {
                                            continue :accept;
                                        }
                                    }
                                }
                            }
                        };
                        self.core.server_thread = try std.Thread.spawn(.{}, ServerHandler.run, .{&self.core});
                    },
                    .raw => {
                        std.debug.assert(self.core.process == null);
                        const port_str = std.fmt.comptimePrint("{}", .{port});
                        self.core.process = try std.process.spawn(self.core.io, .{
                            .argv = &.{ "git", "daemon", "--reuseaddr", "--base-path=.", "--export-all", "--enable=receive-pack", "--log-destination=stderr", "--port=" ++ port_str },
                            .cwd = .{ .path = self.core.temp_path },
                            .stdin = .ignore,
                            .stdout = .ignore,
                            .stderr = .ignore,
                        });
                    },
                    .ssh => {
                        std.debug.assert(self.core.process == null);
                        self.core.process = try std.process.spawn(self.core.io, .{
                            .argv = &.{"./sshd.sh"},
                            .cwd = .{ .path = self.core.temp_path },
                            .stdin = .pipe,
                            .stdout = .ignore,
                            .stderr = .ignore,
                        });
                    },
                },
            }

            // wait for server to be ready by polling the port
            if (transport_def == .wire) {
                const address = try std.Io.net.IpAddress.parseIp4("127.0.0.1", port);
                for (0..50) |_| {
                    const stream = address.connect(self.core.io, .{ .mode = .stream }) catch {
                        try std.Io.sleep(self.core.io, .fromMilliseconds(100), .real);
                        continue;
                    };
                    stream.close(self.core.io);
                    break;
                }
            }
        }

        fn stop(self: *Server(server_repo_kind, transport_def, port)) void {
            switch (transport_def) {
                .file => {},
                .wire => |wire_kind| switch (wire_kind) {
                    .http => {
                        var client = std.http.Client{ .io = self.core.io, .allocator = self.core.allocator };
                        defer client.deinit();
                        _ = client.fetch(.{ .location = .{ .url = self.core.stop_server_endpoint } }) catch return;
                        self.core.server_thread.join();
                    },
                    .raw => {
                        _ = self.core.process.?.kill(self.core.io);
                        self.core.process = null;
                    },
                    .ssh => {
                        _ = self.core.process.?.kill(self.core.io);
                        self.core.process = null;
                    },
                },
            }
        }
    };
}

fn testFetch(
    comptime repo_kind: rp.RepoKind,
    comptime server_repo_kind: rp.RepoKind,
    comptime transport_def: net.TransportDefinition,
    comptime port: u16,
    comptime hash_kind: xit.hash.HashKind,
    io: std.Io,
    allocator: std.mem.Allocator,
) !void {
    // create the temp dir
    var temp = std.testing.tmpDir(.{});
    defer temp.cleanup();
    const temp_path = try temp.dir.realPathFileAlloc(io, ".", allocator);
    defer allocator.free(temp_path);

    // init server
    var server = try Server(server_repo_kind, transport_def, port).init(io, allocator, temp.dir, temp_path);
    try server.start();
    defer server.stop();

    const cwd_path = try std.process.currentPathAlloc(io, allocator);
    defer allocator.free(cwd_path);

    const server_path = try std.fs.path.join(allocator, &.{ temp_path, "server" });
    defer allocator.free(server_path);

    var server_repo = try rp.Repo(server_repo_kind, .{ .hash = hash_kind, .is_test = true }).init(io, allocator, .{ .path = server_path, .bare = true });
    defer server_repo.deinit(io, allocator);

    // make a commit
    const commit1 = blk: {
        break :blk try commitServer(&server_repo, io, allocator, .{ .files = &.{.{ .path = "hello.txt", .content = "hello, world!" }} }, .{ .message = "let there be light" });
    };

    // export server repo
    {
        const export_file = try server_repo.core.repo_dir.createFile(io, "git-daemon-export-ok", .{});
        defer export_file.close(io);

        try server_repo.addConfig(io, allocator, .{ .name = "uploadpack.allowAnySHA1InWant", .value = "true" });
    }

    // add a tag
    _ = try server_repo.addTag(io, allocator, .{ .name = "1.0.0", .message = "hi" });

    const client_path = try std.fs.path.join(allocator, &.{ temp_path, "client" });
    defer allocator.free(client_path);

    var client_repo = try rp.Repo(repo_kind, .{ .hash = hash_kind, .is_test = true }).init(io, allocator, .{ .path = client_path });
    defer client_repo.deinit(io, allocator);

    // add remote
    if (.windows == builtin.os.tag) {
        std.mem.replaceScalar(u8, server_path, '\\', '/');
    }
    const separator = if (server_path[0] == '/') "" else "/";

    const remote_url = switch (transport_def) {
        //.file => try std.fmt.allocPrint(allocator, "file://{s}{s}", .{ separator, server_path }),
        .file => try std.fmt.allocPrint(allocator, "../server", .{}), // relative file paths work too
        .wire => |wire_kind| switch (wire_kind) {
            .http => try std.fmt.allocPrint(allocator, "http://localhost:{}/server", .{port}),
            .raw => try std.fmt.allocPrint(allocator, "git://localhost:{}/server", .{port}),
            .ssh => try std.fmt.allocPrint(allocator, "ssh://localhost:{}{s}{s}", .{ port, separator, server_path }),
        },
    };
    defer allocator.free(remote_url);

    try client_repo.addRemote(io, allocator, .{ .name = "origin", .value = remote_url });
    try client_repo.addConfig(io, allocator, .{ .name = "branch.master.remote", .value = "origin" });

    // create refspec with oid as a test
    const oid_refspec = try std.fmt.allocPrint(allocator, "+{s}:refs/heads/foo", .{&commit1});
    defer allocator.free(oid_refspec);

    const refspecs = &.{
        "+refs/heads/master:refs/heads/master",
        oid_refspec,
    };

    const is_ssh = switch (transport_def) {
        .file => false,
        .wire => |wire_kind| .ssh == wire_kind,
    };
    const ssh_cmd_maybe: ?[]const u8 = if (is_ssh) blk: {
        const known_hosts_path = try std.fs.path.join(allocator, &.{ temp_path, "known_hosts" });
        defer allocator.free(known_hosts_path);

        const priv_key_path = try std.fs.path.join(allocator, &.{ temp_path, "key" });
        defer allocator.free(priv_key_path);

        break :blk try std.fmt.allocPrint(allocator, "ssh -o UserKnownHostsFile=\"{s}\" -o LogLevel=ERROR -o IdentityFile=\"{s}\"", .{ known_hosts_path, priv_key_path });
    } else null;
    defer if (ssh_cmd_maybe) |ssh_cmd| allocator.free(ssh_cmd);

    const upload_pack_command = try switch (server_repo_kind) {
        .xit => std.fmt.allocPrint(allocator, "{s}/zig-out/bin/xit upload-pack", .{cwd_path}),
        .git => allocator.dupe(u8, "git-upload-pack"),
    };
    defer allocator.free(upload_pack_command);

    try client_repo.fetch(
        io,
        allocator,
        "origin",
        .{ .refspecs = refspecs, .wire = .{ .ssh = .{
            .command = ssh_cmd_maybe,
            .upload_pack_command = upload_pack_command,
        } } },
    );

    // update the working dir
    try client_repo.restore(io, allocator, ".");

    // make sure fetch was successful
    {
        const hello_txt = try temp.dir.openFile(io, "client/hello.txt", .{});
        defer hello_txt.close(io);

        try std.testing.expect(null != try client_repo.readRef(io, .{ .kind = .tag, .name = "1.0.0" }));
        try std.testing.expect(null != try client_repo.readRef(io, .{ .kind = .head, .name = "foo" }));

        const oid_master = (try client_repo.readRef(io, .{ .kind = .head, .name = "master" })).?;
        try std.testing.expectEqualStrings(&commit1, &oid_master);
    }

    // make another commit
    const commit2 = blk: {
        break :blk try commitServer(&server_repo, io, allocator, .{ .files = &.{.{ .path = "goodbye.txt", .content = "goodbye, world!" }} }, .{ .message = "goodbye" });
    };

    try client_repo.fetch(
        io,
        allocator,
        "origin",
        .{ .refspecs = refspecs, .wire = .{ .ssh = .{
            .command = ssh_cmd_maybe,
            .upload_pack_command = upload_pack_command,
        } } },
    );

    // update the working dir
    try client_repo.restore(io, allocator, ".");

    // make sure fetch was successful
    {
        const goodbye_txt = try temp.dir.openFile(io, "client/goodbye.txt", .{});
        defer goodbye_txt.close(io);

        const oid_master = (try client_repo.readRef(io, .{ .kind = .head, .name = "master" })).?;
        try std.testing.expectEqualStrings(&commit2, &oid_master);
    }

    // hash-mismatch checks currently cover only the xit backend.
    if (repo_kind == .xit) {
        try server_repo.addConfig(io, allocator, .{ .name = "http.receivepack", .value = "true" });
        const other_hash: xit.hash.HashKind = if (hash_kind == .sha1) .sha256 else .sha1;
        const Other = rp.Repo(.xit, .{ .hash = other_hash, .is_test = true });
        const other_path = try std.fs.path.join(allocator, &.{ temp_path, "mismatched" });
        defer allocator.free(other_path);
        var other = try Other.init(io, allocator, .{ .path = other_path });
        defer other.deinit(io, allocator);
        try other.addRemote(io, allocator, .{ .name = "origin", .value = remote_url });
        const receive_pack_command = try std.fmt.allocPrint(allocator, "{s}/zig-out/bin/xit receive-pack", .{cwd_path});
        defer allocator.free(receive_pack_command);
        const opts: net.Opts(void) = .{ .wire = .{ .ssh = .{
            .command = ssh_cmd_maybe,
            .upload_pack_command = upload_pack_command,
            .receive_pack_command = receive_pack_command,
        } } };
        const mismatch_error = if (transport_def == .file) error.UnexpectedHashKind else error.ObjectFormatMismatch;
        try std.testing.expectError(mismatch_error, other.fetch(io, allocator, "origin", opts));
        const local_oid = try commitServer(&other, io, allocator, .{ .files = &.{.{ .path = "other.txt", .content = "different hash" }} }, .{ .message = "local" });
        try std.testing.expectError(mismatch_error, other.push(io, allocator, "origin", "refs/heads/master:refs/heads/master", false, opts));
        try std.testing.expectEqualStrings(&local_oid, &(try other.readRef(io, .{ .kind = .head, .name = "master" })).?);
        try std.testing.expectEqualStrings(&commit2, &(try server_repo.readRef(io, .{ .kind = .head, .name = "master" })).?);
        const clone_path = try std.fs.path.join(allocator, &.{ temp_path, "mismatched-clone" });
        defer allocator.free(clone_path);
        // file urls here are relative to the parent of client/, not client/ itself.
        const clone_url = if (transport_def == .file) server_path else remote_url;
        try std.testing.expectError(mismatch_error, Other.clone(io, allocator, clone_url, temp_path, clone_path, null, .{ .transport = opts }));
    }
}

fn testPush(
    comptime repo_kind: rp.RepoKind,
    comptime server_repo_kind: rp.RepoKind,
    comptime transport_def: net.TransportDefinition,
    comptime port: u16,
    comptime hash_kind: xit.hash.HashKind,
    io: std.Io,
    allocator: std.mem.Allocator,
) !void {
    // create the temp dir
    var temp = std.testing.tmpDir(.{});
    defer temp.cleanup();
    const temp_path = try temp.dir.realPathFileAlloc(io, ".", allocator);
    defer allocator.free(temp_path);

    // init server
    var server = try Server(server_repo_kind, transport_def, port).init(io, allocator, temp.dir, temp_path);
    try server.start();
    defer server.stop();

    const cwd_path = try std.process.currentPathAlloc(io, allocator);
    defer allocator.free(cwd_path);

    const server_path = try std.fs.path.join(allocator, &.{ temp_path, "server" });
    defer allocator.free(server_path);

    var server_repo = try rp.Repo(server_repo_kind, .{ .hash = hash_kind, .is_test = true }).init(io, allocator, .{ .path = server_path, .bare = true });
    defer server_repo.deinit(io, allocator);

    try server_repo.addConfig(io, allocator, .{ .name = "http.receivepack", .value = "true" });
    try server_repo.addConfig(io, allocator, .{ .name = "receive.denycurrentbranch", .value = "updateInstead" });
    try server_repo.addConfig(io, allocator, .{ .name = "receive.denydeletecurrent", .value = "true" });

    // export server repo
    {
        const export_file = try server_repo.core.repo_dir.createFile(io, "git-daemon-export-ok", .{});
        defer export_file.close(io);
    }

    const client_path = try std.fs.path.join(allocator, &.{ temp_path, "client" });
    defer allocator.free(client_path);

    var client_repo = try rp.Repo(repo_kind, .{ .hash = hash_kind, .is_test = true }).init(io, allocator, .{ .path = client_path });
    defer client_repo.deinit(io, allocator);

    // make a commit
    const commit1 = blk: {
        const hello_txt = try client_repo.core.work_dir.createFile(io, "hello.txt", .{ .truncate = true });
        defer hello_txt.close(io);
        try hello_txt.writeStreamingAll(io, "hello, world!");
        try client_repo.add(io, allocator, &.{"hello.txt"});
        break :blk try client_repo.commit(io, allocator, .{ .message = "let there be light" });
    };

    // add a tag
    _ = try client_repo.addTag(io, allocator, .{ .name = "1.0.0", .message = "hi" });

    // add remote
    {
        if (.windows == builtin.os.tag) {
            std.mem.replaceScalar(u8, server_path, '\\', '/');
        }
        const separator = if (server_path[0] == '/') "" else "/";

        const remote_url = switch (transport_def) {
            //.file => try std.fmt.allocPrint(allocator, "file://{s}{s}", .{ separator, server_path }),
            .file => try std.fmt.allocPrint(allocator, "../server", .{}), // relative file paths work too
            .wire => |wire_kind| switch (wire_kind) {
                .http => try std.fmt.allocPrint(allocator, "http://localhost:{}/server", .{port}),
                .raw => try std.fmt.allocPrint(allocator, "git://localhost:{}/server", .{port}),
                .ssh => try std.fmt.allocPrint(allocator, "ssh://localhost:{}{s}{s}", .{ port, separator, server_path }),
            },
        };
        defer allocator.free(remote_url);

        try client_repo.addRemote(io, allocator, .{ .name = "origin", .value = remote_url });
        try client_repo.addConfig(io, allocator, .{ .name = "branch.master.remote", .value = "origin" });
    }

    const refspecs = &.{
        "refs/tags/1.0.0:refs/tags/1.0.0",
    };

    const is_ssh = switch (transport_def) {
        .file => false,
        .wire => |wire_kind| .ssh == wire_kind,
    };
    const ssh_cmd_maybe: ?[]const u8 = if (is_ssh) blk: {
        const known_hosts_path = try std.fs.path.join(allocator, &.{ temp_path, "known_hosts" });
        defer allocator.free(known_hosts_path);

        const priv_key_path = try std.fs.path.join(allocator, &.{ temp_path, "key" });
        defer allocator.free(priv_key_path);

        break :blk try std.fmt.allocPrint(allocator, "ssh -o UserKnownHostsFile=\"{s}\" -o LogLevel=ERROR -o IdentityFile=\"{s}\"", .{ known_hosts_path, priv_key_path });
    } else null;
    defer if (ssh_cmd_maybe) |ssh_cmd| allocator.free(ssh_cmd);

    const upload_pack_command = try switch (server_repo_kind) {
        .xit => std.fmt.allocPrint(allocator, "{s}/zig-out/bin/xit upload-pack", .{cwd_path}),
        .git => allocator.dupe(u8, "git-upload-pack"),
    };
    defer allocator.free(upload_pack_command);
    const receive_pack_command = try switch (server_repo_kind) {
        .xit => std.fmt.allocPrint(allocator, "{s}/zig-out/bin/xit receive-pack", .{cwd_path}),
        .git => allocator.dupe(u8, "git-receive-pack"),
    };
    defer allocator.free(receive_pack_command);

    try client_repo.push(
        io,
        allocator,
        "origin",
        "master",
        false,
        .{ .refspecs = refspecs, .wire = .{ .ssh = .{
            .command = ssh_cmd_maybe,
            .receive_pack_command = receive_pack_command,
        } } },
    );

    // make sure push was successful
    {
        try std.testing.expect(null != try server_repo.readRef(io, .{ .kind = .tag, .name = "1.0.0" }));

        const oid_master = (try server_repo.readRef(io, .{ .kind = .head, .name = "master" })).?;
        try std.testing.expectEqualStrings(&commit1, &oid_master);
        if (server_repo_kind == .xit) {
            try std.testing.expectEqual(1, try server_repo.commitCount(io, allocator, .{ .oid = &oid_master }));
        }
    }

    // creating a branch at an existing remote object still requires an empty pack.
    try client_repo.push(io, allocator, "origin", "master:refs/heads/alias", false, .{ .wire = .{ .ssh = .{
        .command = ssh_cmd_maybe,
        .receive_pack_command = receive_pack_command,
    } } });
    try std.testing.expectEqualStrings(&commit1, &(try server_repo.readRef(io, .{ .kind = .head, .name = "alias" })).?);
    try client_repo.push(io, allocator, "origin", ":refs/heads/alias", false, .{ .wire = .{ .ssh = .{
        .command = ssh_cmd_maybe,
        .receive_pack_command = receive_pack_command,
    } } });

    // make a commit on the server
    {
        _ = try commitServer(&server_repo, io, allocator, .{ .files = &.{.{ .path = "hello.txt", .content = "hello, world from the server!" }} }, .{ .message = "new commit from the server" });
    }

    // make another commit
    const commit2 = blk: {
        const goodbye_txt = try client_repo.core.work_dir.createFile(io, "goodbye.txt", .{ .truncate = true });
        defer goodbye_txt.close(io);
        try goodbye_txt.writeStreamingAll(io, "goodbye, world!");
        try client_repo.add(io, allocator, &.{"goodbye.txt"});
        break :blk try client_repo.commit(io, allocator, .{ .message = "goodbye" });
    };

    // can't push because server has commit not found locally
    try std.testing.expectError(error.RemoteRefContainsCommitsNotFoundLocally, client_repo.push(
        io,
        allocator,
        "origin",
        "master",
        false,
        .{ .wire = .{ .ssh = .{
            .command = ssh_cmd_maybe,
            .receive_pack_command = receive_pack_command,
        } } },
    ));

    // make a commit on the server with no parents, thus creating an incompatible git history
    {
        _ = try commitServer(&server_repo, io, allocator, .{ .files = &.{.{ .path = "hello.txt", .content = "hello, world from the server again!" }} }, .{ .message = "new git history on the server", .parent_oids = &.{} });
    }

    // can't push because commit doesn't exist locally
    try std.testing.expectError(error.RemoteRefContainsCommitsNotFoundLocally, client_repo.push(
        io,
        allocator,
        "origin",
        "master",
        false,
        .{ .wire = .{ .ssh = .{
            .command = ssh_cmd_maybe,
            .receive_pack_command = receive_pack_command,
        } } },
    ));

    // retrieve the commit object
    try client_repo.fetch(
        io,
        allocator,
        "origin",
        .{ .wire = .{ .ssh = .{
            .command = ssh_cmd_maybe,
            .upload_pack_command = upload_pack_command,
        } } },
    );

    // can't push because server's history is incompatible
    try std.testing.expectError(error.RemoteRefContainsIncompatibleHistory, client_repo.push(
        io,
        allocator,
        "origin",
        "master",
        false,
        .{ .wire = .{ .ssh = .{
            .command = ssh_cmd_maybe,
            .receive_pack_command = receive_pack_command,
        } } },
    ));

    // every transport enforces receive policies.
    {
        // set denyNonFastForwards on server
        try server_repo.addConfig(io, allocator, .{ .name = "receive.denynonfastforwards", .value = "true" });

        // save the server's current master ref
        const oid_before_denied_push = (try server_repo.readRef(io, .{ .kind = .head, .name = "master" })).?;

        // force push should be rejected by server due to denyNonFastForwards
        try std.testing.expectError(error.RemoteRejectedRef, client_repo.push(
            io,
            allocator,
            "origin",
            "master",
            true,
            .{ .wire = .{ .ssh = .{
                .command = ssh_cmd_maybe,
                .receive_pack_command = receive_pack_command,
            } } },
        ));

        // verify the server ref was not updated (push was denied)
        {
            const oid_master = (try server_repo.readRef(io, .{ .kind = .head, .name = "master" })).?;
            try std.testing.expectEqualStrings(&oid_before_denied_push, &oid_master);
        }

        // remove denyNonFastForwards from server
        try server_repo.removeConfig(io, allocator, .{ .name = "receive.denynonfastforwards" });
    }

    // force push
    try client_repo.push(
        io,
        allocator,
        "origin",
        "master",
        true,
        .{ .wire = .{ .ssh = .{
            .command = ssh_cmd_maybe,
            .receive_pack_command = receive_pack_command,
        } } },
    );

    // make sure push was successful
    {
        const oid_master = (try server_repo.readRef(io, .{ .kind = .head, .name = "master" })).?;
        try std.testing.expectEqualStrings(&commit2, &oid_master);
    }

    // remove the remote tag
    try client_repo.push(
        io,
        allocator,
        "origin",
        ":refs/tags/1.0.0",
        false,
        .{ .wire = .{ .ssh = .{
            .command = ssh_cmd_maybe,
            .receive_pack_command = receive_pack_command,
        } } },
    );

    // make sure push was successful
    try std.testing.expect(null == try server_repo.readRef(io, .{ .kind = .tag, .name = "1.0.0" }));

    // a bare server ignores updateInstead and leaves stray files untouched
    if (server_repo_kind == .xit) switch (transport_def) {
        .file => {},
        .wire => |wire_kind| if (.http == wire_kind) {
            try server_repo.addConfig(io, allocator, .{ .name = "receive.denycurrentbranch", .value = "updateInstead" });
            {
                const hello_txt = try server_repo.core.work_dir.createFile(io, "hello.txt", .{ .truncate = true });
                defer hello_txt.close(io);
                try hello_txt.writeStreamingAll(io, "local server change");
            }
            {
                const hello_txt = try client_repo.core.work_dir.createFile(io, "hello.txt", .{ .truncate = true });
                defer hello_txt.close(io);
                try hello_txt.writeStreamingAll(io, "new client change");
            }
            try client_repo.add(io, allocator, &.{"hello.txt"});
            const commit3 = try client_repo.commit(io, allocator, .{ .message = "change hello" });

            try client_repo.push(
                io,
                allocator,
                "origin",
                "master",
                false,
                .{ .wire = .{ .ssh = .{
                    .command = ssh_cmd_maybe,
                    .receive_pack_command = receive_pack_command,
                } } },
            );

            const oid_master = (try server_repo.readRef(io, .{ .kind = .head, .name = "master" })).?;
            try std.testing.expectEqualStrings(&commit3, &oid_master);

            const hello = try server_repo.core.work_dir.readFileAlloc(io, "hello.txt", allocator, .limited(1024));
            defer allocator.free(hello);
            try std.testing.expectEqualStrings("local server change", hello);
        },
    };

    if (transport_def == .file) {
        // deletion policy still applies to bare HEAD, and failed atomic pushes
        // must not create any of their other refs.
        try server_repo.addConfig(io, allocator, .{ .name = "receive.denydeletes", .value = "true" });
        const before_rejected = if (server_repo_kind == .xit) try server_repo.core.db_file.length(io) else 0;
        try std.testing.expectError(error.RemoteRejectedRef, client_repo.push(io, allocator, "origin", ":master", false, .{ .refspecs = &.{"refs/heads/master:refs/heads/fresh"} }));
        if (server_repo_kind == .xit) {
            try std.testing.expectEqual(before_rejected, try server_repo.core.db_file.length(io));
            try std.testing.expectEqual(null, try server_repo.readRef(io, .{ .kind = .head, .name = "fresh" }));
        }
        try server_repo.removeConfig(io, allocator, .{ .name = "receive.denydeletes" });
        try client_repo.push(io, allocator, "origin", ":master", false, .{});
        try client_repo.push(io, allocator, "origin", "master", false, .{});

        // also exercise conversion to an empty non-bare local destination.
        const checkout_path = try std.fs.path.join(allocator, &.{ temp_path, "checkout" });
        defer allocator.free(checkout_path);
        const Checkout = rp.Repo(server_repo_kind, .{ .hash = hash_kind, .is_test = true });
        var checkout = try Checkout.init(io, allocator, .{ .path = checkout_path });
        defer checkout.deinit(io, allocator);
        try client_repo.addRemote(io, allocator, .{ .name = "checkedout", .value = checkout_path });
        const third = try commitServer(&client_repo, io, allocator, .{ .files = &.{.{ .path = "file", .content = "pushed" }} }, .{ .message = "pushed" });
        // the default updates the checked-out branch, index, and files together.
        try client_repo.push(io, allocator, "checkedout", "master:master", false, .{});
        checkout.deinit(io, allocator);
        checkout = try Checkout.open(io, allocator, .{ .path = checkout_path });
        try std.testing.expectEqualStrings(&third, &(try checkout.readRef(io, .{ .kind = .head, .name = "master" })).?);
        {
            const content = try checkout.core.work_dir.readFileAlloc(io, "file", allocator, .limited(64));
            defer allocator.free(content);
            try std.testing.expectEqualStrings("pushed", content);
            var status = try checkout.status(io, allocator);
            defer status.deinit(allocator);
            try std.testing.expectEqual(0, status.index_added.count() + status.index_modified.count() + status.index_deleted.count());
            try std.testing.expectEqual(0, status.work_dir_modified.count() + status.work_dir_deleted.count() + status.untracked.count());
        }
        const fourth = try commitServer(&client_repo, io, allocator, .{ .files = &.{.{ .path = "file", .content = "next" }} }, .{ .message = "next" });
        // explicit refusal still overrides the default.
        try checkout.addConfig(io, allocator, .{ .name = "receive.denycurrentbranch", .value = "refuse" });
        try std.testing.expectError(error.RemoteRejectedRef, client_repo.push(io, allocator, "checkedout", "master:master", false, .{}));
        try checkout.removeConfig(io, allocator, .{ .name = "receive.denycurrentbranch" });
        // protect unstaged, staged, and untracked content at the incoming path.
        const file = try checkout.core.work_dir.createFile(io, "file", .{});
        try file.writeStreamingAll(io, "local");
        file.close(io);
        try std.testing.expectError(error.RemoteRejectedRef, client_repo.push(io, allocator, "checkedout", "master:master", false, .{}));
        try checkout.add(io, allocator, &.{"file"});
        try std.testing.expectError(error.RemoteRejectedRef, client_repo.push(io, allocator, "checkedout", "master:master", false, .{}));
        try checkout.untrack(io, allocator, &.{"file"}, .{});
        try std.testing.expectError(error.RemoteRejectedRef, client_repo.push(io, allocator, "checkedout", "master:master", false, .{}));
        checkout.deinit(io, allocator);
        checkout = try Checkout.open(io, allocator, .{ .path = checkout_path });
        try std.testing.expectEqualStrings(&third, &(try checkout.readRef(io, .{ .kind = .head, .name = "master" })).?);
        {
            const content = try checkout.core.work_dir.readFileAlloc(io, "file", allocator, .limited(64));
            defer allocator.free(content);
            try std.testing.expectEqualStrings("local", content);
            var status = try checkout.status(io, allocator);
            defer status.deinit(allocator);
            try std.testing.expect(status.index_deleted.contains("file"));
            try std.testing.expect(status.untracked.contains("file"));
        }
        try checkout.restore(io, allocator, "file");
        try checkout.add(io, allocator, &.{"file"});
        try client_repo.push(io, allocator, "checkedout", "master:master", false, .{});
        checkout.deinit(io, allocator);
        checkout = try Checkout.open(io, allocator, .{ .path = checkout_path });
        try std.testing.expectEqualStrings(&fourth, &(try checkout.readRef(io, .{ .kind = .head, .name = "master" })).?);
    }
}

fn testClone(
    comptime repo_kind: rp.RepoKind,
    comptime server_repo_kind: rp.RepoKind,
    comptime transport_def: net.TransportDefinition,
    comptime port: u16,
    comptime shell_out_to_git: bool,
    comptime hash_kind: xit.hash.HashKind,
    io: std.Io,
    allocator: std.mem.Allocator,
) !void {
    // create the temp dir
    const cwd = std.Io.Dir.cwd();
    var temp = std.testing.tmpDir(.{});
    defer temp.cleanup();
    const temp_path = try temp.dir.realPathFileAlloc(io, ".", allocator);
    defer allocator.free(temp_path);

    // init server
    var server = try Server(server_repo_kind, transport_def, port).init(io, allocator, temp.dir, temp_path);
    try server.start();
    defer server.stop();

    const cwd_path = try std.process.currentPathAlloc(io, allocator);
    defer allocator.free(cwd_path);

    const server_path = try std.fs.path.join(allocator, &.{ temp_path, "server" });
    defer allocator.free(server_path);

    // init server repo with default branch name as main
    // is_test must be false when shell_out_to_git so commits get real timestamps (needed for --shallow-since)
    var server_repo = try rp.Repo(server_repo_kind, .{ .hash = hash_kind, .is_test = !shell_out_to_git }).init(io, allocator, .{ .path = server_path, .bare = true, .create_default_branch = "main" });
    defer server_repo.deinit(io, allocator);

    if (shell_out_to_git) {
        try server_repo.addConfig(io, allocator, .{ .name = "user.name", .value = "test" });
        try server_repo.addConfig(io, allocator, .{ .name = "user.email", .value = "test@test" });
        try server_repo.addConfig(io, allocator, .{ .name = "uploadpack.allowfilter", .value = "true" });
    }

    // export server repo
    {
        const export_file = try server_repo.core.repo_dir.createFile(io, "git-daemon-export-ok", .{});
        defer export_file.close(io);
    }

    const client_path = try std.fs.path.join(allocator, &.{ temp_path, "client" });
    defer allocator.free(client_path);

    // get remote url
    const remote_url = blk: {
        if (.windows == builtin.os.tag) {
            std.mem.replaceScalar(u8, server_path, '\\', '/');
        }
        const separator = if (server_path[0] == '/') "" else "/";

        break :blk switch (transport_def) {
            //.file => try std.fmt.allocPrint(allocator, "file://{s}{s}", .{ separator, server_path }),
            .file => try std.fmt.allocPrint(allocator, "server", .{}), // relative file paths work too
            .wire => |wire_kind| switch (wire_kind) {
                .http => try std.fmt.allocPrint(allocator, "http://localhost:{}/server", .{port}),
                .raw => try std.fmt.allocPrint(allocator, "git://localhost:{}/server", .{port}),
                .ssh => try std.fmt.allocPrint(allocator, "ssh://localhost:{}{s}{s}", .{ port, separator, server_path }),
            },
        };
    };
    defer allocator.free(remote_url);

    const is_ssh = switch (transport_def) {
        .file => false,
        .wire => |wire_kind| .ssh == wire_kind,
    };

    const upload_pack_command = try switch (server_repo_kind) {
        .xit => std.fmt.allocPrint(allocator, "{s}/zig-out/bin/xit upload-pack", .{cwd_path}),
        .git => allocator.dupe(u8, "git-upload-pack"),
    };
    defer allocator.free(upload_pack_command);

    const ssh_cmd_maybe: ?[]const u8 = if (is_ssh) blk: {
        const known_hosts_path = try std.fs.path.join(allocator, &.{ temp_path, "known_hosts" });
        defer allocator.free(known_hosts_path);

        const priv_key_path = try std.fs.path.join(allocator, &.{ temp_path, "key" });
        defer allocator.free(priv_key_path);

        break :blk try std.fmt.allocPrint(allocator, "ssh -o UserKnownHostsFile=\"{s}\" -o LogLevel=ERROR -o IdentityFile=\"{s}\"", .{ known_hosts_path, priv_key_path });
    } else null;
    defer if (ssh_cmd_maybe) |ssh_cmd| allocator.free(ssh_cmd);

    const Client = rp.Repo(repo_kind, .{ .hash = hash_kind, .is_test = true });
    const clone_opts: net.CloneOpts(void) = .{ .transport = .{ .wire = .{ .ssh = .{
        .command = ssh_cmd_maybe,
        .upload_pack_command = upload_pack_command,
    } } } };
    if (!shell_out_to_git and (transport_def == .file or server_repo_kind == .xit)) {
        const empty_path = try std.fs.path.join(allocator, &.{ temp_path, "empty" });
        defer allocator.free(empty_path);
        var empty_opts = clone_opts;
        empty_opts.bare = true;
        var empty = try Client.clone(io, allocator, remote_url, temp_path, empty_path, null, empty_opts);
        defer empty.deinit(io, allocator);
        var head_buffer: [rf.MAX_REF_CONTENT_SIZE]u8 = undefined;
        try std.testing.expectEqualStrings("main", (try empty.head(io, &head_buffer)).ref.name);
        try std.testing.expectEqual(null, try empty.readRef(io, .{ .kind = .head, .name = "main" }));
        try std.testing.expectError(error.FileNotFound, empty.core.repo_dir.access(io, "index", .{}));
    }

    const first = try commitServer(&server_repo, io, allocator, .{ .files = &.{.{ .path = "hello.txt", .content = "hello, world!" }} }, .{ .message = "let there be light" });
    if (!shell_out_to_git) try server_repo.addBranch(io, .{ .name = "other" });

    // tag first commit
    _ = try server_repo.addTag(io, allocator, .{ .name = "v1", .message = "first" });

    // make a commit
    {
        _ = try commitServer(&server_repo, io, allocator, .{ .files = &.{.{ .path = "goodbye.txt", .content = "goodbye, world!" }} }, .{ .message = "add goodbye file" });
    }

    if (shell_out_to_git) {
        const ssh_config_arg = try std.fmt.allocPrint(allocator, "core.sshCommand={s}", .{ssh_cmd_maybe orelse "ssh"});
        defer allocator.free(ssh_config_arg);

        {
            var process = try std.process.spawn(io, .{
                .argv = if (is_ssh)
                    &.{ "git", "-c", ssh_config_arg, "clone", "--upload-pack", upload_pack_command, "--depth", "1", remote_url, "client" }
                else
                    &.{ "git", "clone", "--depth", "1", remote_url, "client" },
                .cwd = .{ .path = temp_path },
                .stdin = .ignore,
                .stdout = .ignore,
                .stderr = .ignore,
            });
            const term = try process.wait(io);
            if (term != .exited or term.exited != 0) {
                return error.GitCommandFailed;
            }
        }

        // make sure shallow clone was successful
        {
            const hello_txt = try temp.dir.openFile(io, "client/hello.txt", .{});
            hello_txt.close(io);
        }

        // make a third commit on the server
        {
            _ = try commitServer(&server_repo, io, allocator, .{ .files = &.{.{ .path = "extra.txt", .content = "extra content" }} }, .{ .message = "add extra file" });
        }

        // pull --unshallow to deepen the clone and get the new commit
        {
            var process = try std.process.spawn(io, .{
                .argv = if (is_ssh)
                    &.{ "git", "-c", ssh_config_arg, "pull", "--upload-pack", upload_pack_command, "--unshallow" }
                else
                    &.{ "git", "pull", "--unshallow" },
                .cwd = .{ .path = client_path },
                .stdin = .ignore,
                .stdout = .ignore,
                .stderr = .ignore,
            });
            const term = try process.wait(io);
            if (term != .exited or term.exited != 0) {
                return error.GitCommandFailed;
            }
        }

        // make sure unshallow pull was successful
        {
            const extra_txt = try temp.dir.openFile(io, "client/extra.txt", .{});
            extra_txt.close(io);
        }

        // delete client and clone again with --shallow-since
        try temp.dir.deleteTree(io, "client");

        {
            var process = try std.process.spawn(io, .{
                .argv = if (is_ssh)
                    &.{ "git", "-c", ssh_config_arg, "clone", "--upload-pack", upload_pack_command, "--shallow-since=2000-01-01", remote_url, "client" }
                else
                    &.{ "git", "clone", "--shallow-since=2000-01-01", remote_url, "client" },
                .cwd = .{ .path = temp_path },
                .stdin = .ignore,
                .stdout = .ignore,
                .stderr = .ignore,
            });
            const term = try process.wait(io);
            if (term != .exited or term.exited != 0) {
                return error.GitCommandFailed;
            }
        }

        // make sure shallow clone was successful
        {
            const hello_txt = try temp.dir.openFile(io, "client/hello.txt", .{});
            hello_txt.close(io);
        }

        // delete client and clone again with --shallow-exclude
        try temp.dir.deleteTree(io, "client");

        {
            var process = try std.process.spawn(io, .{
                .argv = if (is_ssh)
                    &.{ "git", "-c", ssh_config_arg, "clone", "--upload-pack", upload_pack_command, "--shallow-exclude=v1", remote_url, "client" }
                else
                    &.{ "git", "clone", "--shallow-exclude=v1", remote_url, "client" },
                .cwd = .{ .path = temp_path },
                .stdin = .ignore,
                .stdout = .ignore,
                .stderr = .ignore,
            });
            const term = try process.wait(io);
            if (term != .exited or term.exited != 0) {
                return error.GitCommandFailed;
            }
        }

        // make sure shallow clone was successful
        {
            const hello_txt = try temp.dir.openFile(io, "client/hello.txt", .{});
            hello_txt.close(io);
        }

        // delete client and clone again with --filter=blob:none
        try temp.dir.deleteTree(io, "client");

        {
            var process = try std.process.spawn(io, .{
                .argv = if (is_ssh)
                    &.{ "git", "-c", ssh_config_arg, "clone", "--upload-pack", upload_pack_command, "--filter=blob:none", remote_url, "client" }
                else
                    &.{ "git", "clone", "--filter=blob:none", remote_url, "client" },
                .cwd = .{ .path = temp_path },
                .stdin = .ignore,
                .stdout = .ignore,
                .stderr = .ignore,
            });
            const term = try process.wait(io);
            if (term != .exited or term.exited != 0) {
                return error.GitCommandFailed;
            }
        }

        // make sure partial clone was successful
        {
            const hello_txt = try temp.dir.openFile(io, "client/hello.txt", .{});
            hello_txt.close(io);
        }

        // delete client and clone again with --filter=tree:0
        try temp.dir.deleteTree(io, "client");

        {
            var process = try std.process.spawn(io, .{
                .argv = if (is_ssh)
                    &.{ "git", "-c", ssh_config_arg, "clone", "--upload-pack", upload_pack_command, "--filter=tree:0", remote_url, "client" }
                else
                    &.{ "git", "clone", "--filter=tree:0", remote_url, "client" },
                .cwd = .{ .path = temp_path },
                .stdin = .ignore,
                .stdout = .ignore,
                .stderr = .ignore,
            });
            const term = try process.wait(io);
            if (term != .exited or term.exited != 0) {
                return error.GitCommandFailed;
            }
        }

        // make sure treeless clone was successful
        {
            const goodbye_txt = try temp.dir.openFile(io, "client/goodbye.txt", .{});
            goodbye_txt.close(io);
        }
    } else {
        inline for (.{ false, true }) |bare| {
            var opts = clone_opts;
            opts.bare = bare;
            var client_repo = try Client.clone(io, allocator, remote_url, temp_path, client_path, null, opts);
            defer cwd.deleteTree(io, client_path) catch {};
            defer client_repo.deinit(io, allocator);

            var current_branch_buffer: [rf.MAX_REF_CONTENT_SIZE]u8 = undefined;
            try std.testing.expectEqualStrings("main", (try client_repo.head(io, &current_branch_buffer)).ref.name);
            try std.testing.expectEqual(bare, try client_repo.isBare(io, allocator));
            if (bare) {
                try std.testing.expectEqualStrings(&(try server_repo.readRef(io, .{ .kind = .head, .name = "main" })).?, &(try client_repo.readRef(io, .{ .kind = .head, .name = "main" })).?);
                try std.testing.expectEqualStrings(&first, &(try client_repo.readRef(io, .{ .kind = .head, .name = "other" })).?);
                try std.testing.expectError(error.FileNotFound, client_repo.core.repo_dir.access(io, "index", .{}));
                try std.testing.expectError(error.FileNotFound, client_repo.core.work_dir.access(io, "hello.txt", .{}));
            } else {
                try client_repo.core.work_dir.access(io, "hello.txt", .{});
            }
        }

        if (transport_def == .file) {
            // leave HEAD pointing to a commit that no branch or tag reaches.
            const detached = (try server_repo.readRef(io, .{ .kind = .head, .name = "main" })).?;
            try server_repo.resetAdd(io, .{ .oid = &first });
            const R = @TypeOf(server_repo);
            const Ctx = struct {
                core: *R.Core,
                io: std.Io,
                oid: *const [xit.hash.hexLen(hash_kind)]u8,

                fn write(ctx: @This(), state: R.State(.read_write)) !void {
                    try rf.replaceHead(server_repo_kind, .{ .hash = hash_kind, .is_test = true }, state, ctx.io, .{ .oid = ctx.oid });
                }

                pub fn run(ctx: @This(), cursor: *R.DB.Cursor(.read_write)) !void {
                    var moment = try R.DB.HashMap(.read_write).init(cursor.*);
                    try ctx.write(.{ .core = ctx.core, .extra = .{ .moment = &moment } });
                }
            };
            const ctx = Ctx{ .core = &server_repo.core, .io = io, .oid = &detached };
            switch (server_repo_kind) {
                .git => try ctx.write(.{ .core = &server_repo.core, .extra = .{} }),
                .xit => {
                    try server_repo.core.db_file.lock(io, .exclusive);
                    defer server_repo.core.db_file.unlock(io);
                    const history = try R.DB.ArrayList(.read_write).init(server_repo.core.db.rootCursor());
                    try history.appendContext(.{ .slot = try history.getSlot(-1) }, ctx);
                },
            }
            var client_repo = try Client.clone(io, allocator, remote_url, temp_path, client_path, null, .{ .bare = true });
            defer client_repo.deinit(io, allocator);
            var head_buffer: [rf.MAX_REF_CONTENT_SIZE]u8 = undefined;
            try std.testing.expectEqualStrings(&detached, (try client_repo.head(io, &head_buffer)).oid);
            var log = try client_repo.log(io, allocator, .{});
            defer log.deinit();
            var commit = (try log.next(allocator)).?;
            defer commit.deinit();
            try std.testing.expectEqualStrings(&detached, &commit.oid);
        }
    }
}

fn testFetchLarge(
    comptime repo_kind: rp.RepoKind,
    comptime server_repo_kind: rp.RepoKind,
    comptime transport_def: net.TransportDefinition,
    comptime port: u16,
    comptime shell_out_to_git: bool,
    comptime hash_kind: xit.hash.HashKind,
    io: std.Io,
    allocator: std.mem.Allocator,
) !void {
    // create the temp dir
    var temp = std.testing.tmpDir(.{});
    defer temp.cleanup();
    const temp_path = try temp.dir.realPathFileAlloc(io, ".", allocator);
    defer allocator.free(temp_path);

    // init server
    var server = try Server(server_repo_kind, transport_def, port).init(io, allocator, temp.dir, temp_path);
    try server.start();
    defer server.stop();

    const cwd_path = try std.process.currentPathAlloc(io, allocator);
    defer allocator.free(cwd_path);

    const server_path = try std.fs.path.join(allocator, &.{ temp_path, "server" });
    defer allocator.free(server_path);

    var server_repo = try rp.Repo(server_repo_kind, .{ .hash = hash_kind, .is_test = true }).init(io, allocator, .{ .path = server_path, .bare = true });
    defer server_repo.deinit(io, allocator);

    // build the server tree directly from this project's source files.
    const commit1 = try commitServer(&server_repo, io, allocator, .{ .dirs = &.{ "src", "docs" } }, .{ .message = "let there be light" });

    // export server repo
    {
        const export_file = try server_repo.core.repo_dir.createFile(io, "git-daemon-export-ok", .{});
        defer export_file.close(io);
    }

    if (shell_out_to_git) {
        try server_repo.addConfig(io, allocator, .{ .name = "uploadpack.allowrefinwant", .value = "true" });
    }

    const client_path = try std.fs.path.join(allocator, &.{ temp_path, "client" });
    defer allocator.free(client_path);

    var client_repo = try rp.Repo(repo_kind, .{ .hash = hash_kind, .is_test = true }).init(io, allocator, .{ .path = client_path });
    defer client_repo.deinit(io, allocator);

    // add remote
    {
        if (.windows == builtin.os.tag) {
            std.mem.replaceScalar(u8, server_path, '\\', '/');
        }
        const separator = if (server_path[0] == '/') "" else "/";

        const remote_url = switch (transport_def) {
            //.file => try std.fmt.allocPrint(allocator, "file://{s}{s}", .{ separator, server_path }),
            .file => try std.fmt.allocPrint(allocator, "../server", .{}), // relative file paths work too
            .wire => |wire_kind| switch (wire_kind) {
                .http => try std.fmt.allocPrint(allocator, "http://localhost:{}/server", .{port}),
                .raw => try std.fmt.allocPrint(allocator, "git://localhost:{}/server", .{port}),
                .ssh => try std.fmt.allocPrint(allocator, "ssh://localhost:{}{s}{s}", .{ port, separator, server_path }),
            },
        };
        defer allocator.free(remote_url);

        try client_repo.addRemote(io, allocator, .{ .name = "origin", .value = remote_url });
        try client_repo.addConfig(io, allocator, .{ .name = "branch.master.remote", .value = "origin" });
    }

    const is_ssh = switch (transport_def) {
        .file => false,
        .wire => |wire_kind| .ssh == wire_kind,
    };

    const upload_pack_command = try switch (server_repo_kind) {
        .xit => std.fmt.allocPrint(allocator, "{s}/zig-out/bin/xit upload-pack", .{cwd_path}),
        .git => allocator.dupe(u8, "git-upload-pack"),
    };
    defer allocator.free(upload_pack_command);

    if (shell_out_to_git) {
        const priv_key_path = try std.fs.path.join(allocator, &.{ temp_path, "key" });
        defer allocator.free(priv_key_path);
        const ssh_config_arg = try std.fmt.allocPrint(allocator, "core.sshCommand=ssh -o StrictHostKeyChecking=no -o LogLevel=ERROR -o IdentityFile={s}", .{priv_key_path});
        defer allocator.free(ssh_config_arg);

        {
            var process = try std.process.spawn(io, .{
                .argv = if (is_ssh)
                    &.{ "git", "-c", ssh_config_arg, "pull", "--upload-pack", upload_pack_command, "origin", "master" }
                else
                    &.{ "git", "pull", "origin", "master" },
                .cwd = .{ .path = client_path },
                .stdin = .ignore,
                .stdout = .ignore,
                .stderr = .ignore,
            });
            const term = try process.wait(io);
            if (term != .exited or term.exited != 0) {
                return error.GitCommandFailed;
            }
        }

        // make sure pull was successful
        {
            const oid_master = (try client_repo.readRef(io, .{ .kind = .head, .name = "master" })).?;
            try std.testing.expectEqualStrings(&commit1, &oid_master);
        }

        // make another commit on the server
        const commit2 = blk: {
            break :blk try commitServer(&server_repo, io, allocator, .{ .files = &.{.{ .path = "extra.txt", .content = "extra content" }} }, .{ .message = "add extra file" });
        };

        // fetch with ref-in-want (git uses want-ref in protocol v2 when fetching named refs)
        {
            var process = try std.process.spawn(io, .{
                .argv = if (is_ssh)
                    &.{ "git", "-c", ssh_config_arg, "fetch", "--upload-pack", upload_pack_command, "origin", "master" }
                else
                    &.{ "git", "fetch", "origin", "master" },
                .cwd = .{ .path = client_path },
                .stdin = .ignore,
                .stdout = .ignore,
                .stderr = .ignore,
            });
            const term = try process.wait(io);
            if (term != .exited or term.exited != 0) {
                return error.GitCommandFailed;
            }
        }

        // make sure fetch with want-ref was successful
        {
            const oid_remote_master = (try client_repo.readRef(io, .{ .kind = .{ .remote = "origin" }, .name = "master" })).?;
            try std.testing.expectEqualStrings(&commit2, &oid_remote_master);
        }
    } else {
        const refspecs = &.{
            "+refs/heads/master:refs/heads/master",
        };

        const ssh_cmd_maybe: ?[]const u8 = if (is_ssh) blk: {
            const known_hosts_path = try std.fs.path.join(allocator, &.{ temp_path, "known_hosts" });
            defer allocator.free(known_hosts_path);

            const priv_key_path = try std.fs.path.join(allocator, &.{ temp_path, "key" });
            defer allocator.free(priv_key_path);

            break :blk try std.fmt.allocPrint(allocator, "ssh -o UserKnownHostsFile=\"{s}\" -o LogLevel=ERROR -o IdentityFile=\"{s}\"", .{ known_hosts_path, priv_key_path });
        } else null;
        defer if (ssh_cmd_maybe) |ssh_cmd| allocator.free(ssh_cmd);

        try client_repo.fetch(
            io,
            allocator,
            "origin",
            .{ .refspecs = refspecs, .wire = .{ .ssh = .{
                .command = ssh_cmd_maybe,
                .upload_pack_command = upload_pack_command,
            } } },
        );

        // update the working dir
        try client_repo.restore(io, allocator, ".");
    }

    // make sure fetch was successful
    {
        const oid_master = (try client_repo.readRef(io, .{ .kind = .head, .name = "master" })).?;
        try std.testing.expectEqualStrings(&commit1, &oid_master);
    }
}

fn testPushLarge(
    comptime repo_kind: rp.RepoKind,
    comptime server_repo_kind: rp.RepoKind,
    comptime transport_def: net.TransportDefinition,
    comptime port: u16,
    comptime shell_out_to_git: bool,
    comptime hash_kind: xit.hash.HashKind,
    io: std.Io,
    allocator: std.mem.Allocator,
) !void {
    // create the temp dir
    const cwd = std.Io.Dir.cwd();
    var temp = std.testing.tmpDir(.{});
    defer temp.cleanup();
    const temp_path = try temp.dir.realPathFileAlloc(io, ".", allocator);
    defer allocator.free(temp_path);

    // init server
    var server = try Server(server_repo_kind, transport_def, port).init(io, allocator, temp.dir, temp_path);
    try server.start();
    defer server.stop();

    const cwd_path = try std.process.currentPathAlloc(io, allocator);
    defer allocator.free(cwd_path);

    const server_path = try std.fs.path.join(allocator, &.{ temp_path, "server" });
    defer allocator.free(server_path);

    var server_repo = try rp.Repo(server_repo_kind, .{ .hash = hash_kind, .is_test = true }).init(io, allocator, .{ .path = server_path, .bare = true });
    defer server_repo.deinit(io, allocator);

    try server_repo.addConfig(io, allocator, .{ .name = "http.receivepack", .value = "true" });

    // export server repo
    {
        const export_file = try server_repo.core.repo_dir.createFile(io, "git-daemon-export-ok", .{});
        defer export_file.close(io);
    }

    const client_path = try std.fs.path.join(allocator, &.{ temp_path, "client" });
    defer allocator.free(client_path);

    var client_repo = try rp.Repo(repo_kind, .{ .hash = hash_kind, .is_test = true }).init(io, allocator, .{ .path = client_path });
    defer client_repo.deinit(io, allocator);

    var client_dir = try cwd.openDir(io, client_path, .{});
    defer client_dir.close(io);

    {
        const hello_txt = try client_repo.core.work_dir.createFile(io, "hello.txt", .{ .truncate = true });
        defer hello_txt.close(io);
        try hello_txt.writeStreamingAll(io, "hello, world!");
        try client_repo.add(io, allocator, &.{"hello.txt"});
    }

    // copy files from current repo into client dir
    for (&[_][]const u8{ "src", "docs" }) |dir_name| {
        var src_repo_dir = try cwd.openDir(io, dir_name, .{ .iterate = true });
        defer src_repo_dir.close(io);

        var dest_repo_dir = try client_dir.createDirPathOpen(io, dir_name, .{});
        defer dest_repo_dir.close(io);

        try copyDir(io, src_repo_dir, dest_repo_dir);

        try client_repo.add(io, allocator, &.{dir_name});
    }

    _ = try client_repo.commit(io, allocator, .{ .message = "let there be light" });

    // change the files so git will send them as delta objects
    for (&[_][]const u8{ "src", "docs" }) |dir_name| {
        var dest_repo_dir = try client_dir.createDirPathOpen(io, dir_name, .{ .open_options = .{ .iterate = true } });
        defer dest_repo_dir.close(io);

        {
            var iter = dest_repo_dir.iterate();
            while (try iter.next(io)) |entry| {
                switch (entry.kind) {
                    .file => {
                        const file = try dest_repo_dir.openFile(io, entry.name, .{ .mode = .read_write });
                        defer file.close(io);
                        var writer = file.writer(io, &.{});
                        try writer.interface.writeAll("EDIT");
                    },
                    else => {},
                }
            }
        }

        try client_repo.add(io, allocator, &.{dir_name});
    }

    const commit2 = try client_repo.commit(io, allocator, .{ .message = "more stuff" });

    // add remote
    {
        if (.windows == builtin.os.tag) {
            std.mem.replaceScalar(u8, server_path, '\\', '/');
        }
        const separator = if (server_path[0] == '/') "" else "/";

        const remote_url = switch (transport_def) {
            //.file => try std.fmt.allocPrint(allocator, "file://{s}{s}", .{ separator, server_path }),
            .file => try std.fmt.allocPrint(allocator, "../server", .{}), // relative file paths work too
            .wire => |wire_kind| switch (wire_kind) {
                .http => try std.fmt.allocPrint(allocator, "http://localhost:{}/server", .{port}),
                .raw => try std.fmt.allocPrint(allocator, "git://localhost:{}/server", .{port}),
                .ssh => try std.fmt.allocPrint(allocator, "ssh://localhost:{}{s}{s}", .{ port, separator, server_path }),
            },
        };
        defer allocator.free(remote_url);

        try client_repo.addRemote(io, allocator, .{ .name = "origin", .value = remote_url });
        try client_repo.addConfig(io, allocator, .{ .name = "branch.master.remote", .value = "origin" });
    }

    const is_ssh = switch (transport_def) {
        .file => false,
        .wire => |wire_kind| .ssh == wire_kind,
    };

    const receive_pack_command = try switch (server_repo_kind) {
        .xit => std.fmt.allocPrint(allocator, "{s}/zig-out/bin/xit receive-pack", .{cwd_path}),
        .git => allocator.dupe(u8, "git-receive-pack"),
    };
    defer allocator.free(receive_pack_command);

    if (shell_out_to_git) {
        const priv_key_path = try std.fs.path.join(allocator, &.{ temp_path, "key" });
        defer allocator.free(priv_key_path);
        const ssh_config_arg = try std.fmt.allocPrint(allocator, "core.sshCommand=ssh -o StrictHostKeyChecking=no -o LogLevel=ERROR -o IdentityFile={s}", .{priv_key_path});
        defer allocator.free(ssh_config_arg);

        // shell out to git so it will send delta objects
        var process = try std.process.spawn(io, .{
            .argv = if (is_ssh)
                &.{ "git", "-c", ssh_config_arg, "push", "--receive-pack", receive_pack_command, "origin", "master" }
            else
                &.{ "git", "push", "origin", "master" },
            .cwd = .{ .path = client_path },
            .stdin = .ignore,
            .stdout = .ignore,
            .stderr = .ignore,
        });
        const term = try process.wait(io);
        if (term != .exited or term.exited != 0) {
            return error.GitCommandFailed;
        }
    } else {
        const ssh_cmd_maybe: ?[]const u8 = if (is_ssh) blk: {
            const known_hosts_path = try std.fs.path.join(allocator, &.{ temp_path, "known_hosts" });
            defer allocator.free(known_hosts_path);

            const priv_key_path = try std.fs.path.join(allocator, &.{ temp_path, "key" });
            defer allocator.free(priv_key_path);

            break :blk try std.fmt.allocPrint(allocator, "ssh -o UserKnownHostsFile=\"{s}\" -o LogLevel=ERROR -o IdentityFile=\"{s}\"", .{ known_hosts_path, priv_key_path });
        } else null;
        defer if (ssh_cmd_maybe) |ssh_cmd| allocator.free(ssh_cmd);

        try client_repo.push(
            io,
            allocator,
            "origin",
            "master",
            false,
            .{ .wire = .{ .ssh = .{
                .command = ssh_cmd_maybe,
                .receive_pack_command = receive_pack_command,
            } } },
        );
    }

    // make sure push was successful
    {
        const oid_master = (try server_repo.readRef(io, .{ .kind = .head, .name = "master" })).?;
        try std.testing.expectEqualStrings(&commit2, &oid_master);

        var moment = try server_repo.core.latestMoment();
        var tree = try xit.tree.Tree(server_repo_kind, server_repo.self_repo_opts).init(.{ .core = &server_repo.core, .extra = .{ .moment = &moment } }, io, allocator, &oid_master);
        defer tree.deinit();
        try std.testing.expect(tree.entries.contains("hello.txt"));
        try std.testing.expectError(error.FileNotFound, server_repo.core.work_dir.access(io, "hello.txt", .{}));
        try std.testing.expectError(error.FileNotFound, server_repo.core.repo_dir.access(io, "index", .{}));
    }
}

fn copyDir(io: std.Io, src_dir: std.Io.Dir, dest_dir: std.Io.Dir) !void {
    var iter = src_dir.iterate();
    while (try iter.next(io)) |entry| {
        switch (entry.kind) {
            .file => try src_dir.copyFile(entry.name, dest_dir, entry.name, io, .{}),
            .directory => {
                try dest_dir.createDirPath(io, entry.name);
                var dest_entry_dir = try dest_dir.openDir(io, entry.name, .{ .access_sub_paths = true, .iterate = true, .follow_symlinks = false });
                defer dest_entry_dir.close(io);
                var src_entry_dir = try src_dir.openDir(io, entry.name, .{ .access_sub_paths = true, .iterate = true, .follow_symlinks = false });
                defer src_entry_dir.close(io);
                try copyDir(io, src_entry_dir, dest_entry_dir);
            },
            else => {},
        }
    }
}

const ServerFiles = union(enum) {
    files: []const struct { path: []const u8, content: []const u8 },
    dirs: []const []const u8,
};

/// prepare blobs and a tree without ever writing the server's index or worktree.
fn commitServer(repo: anytype, io: std.Io, allocator: std.mem.Allocator, files: ServerFiles, metadata: xit.object.CommitMetadata(repo.self_repo_opts.hash)) ![xit.hash.hexLen(repo.self_repo_opts.hash)]u8 {
    const R = @TypeOf(repo.*);
    const kind = repo.self_repo_kind;
    const opts = repo.self_repo_opts;
    const Index = xit.index.Index(kind, opts);
    var tree: ?xit.object.Tree = null;
    defer if (tree) |*t| t.deinit();
    const Ctx = struct {
        core: *R.Core,
        io: std.Io,
        allocator: std.mem.Allocator,
        files: ServerFiles,
        tree: *?xit.object.Tree,

        fn addFile(ctx: @This(), state: R.State(.read_write), index: *Index, path: []const u8, content: []const u8) !void {
            var reader = std.Io.Reader.fixed(content);
            var oid: [xit.hash.byteLen(opts.hash)]u8 = undefined;
            try xit.object.writeObject(kind, opts, state, ctx.io, ctx.allocator, &reader, .{ .kind = .blob, .size = content.len }, &oid);
            const path_parts = try xit.fs.splitPath(ctx.allocator, path);
            defer ctx.allocator.free(path_parts);
            try index.addTreeEntryFile(&.{ .oid = oid, .mode = @bitCast(@as(u32, 0o100644)) }, path_parts, content.len, 0);
        }

        fn addDir(ctx: @This(), state: R.State(.read_write), index: *Index, path: []const u8) anyerror!void {
            var dir = try std.Io.Dir.cwd().openDir(ctx.io, path, .{ .iterate = true });
            defer dir.close(ctx.io);
            var entries = dir.iterate();
            while (try entries.next(ctx.io)) |entry| {
                const child = try std.fs.path.join(ctx.allocator, &.{ path, entry.name });
                defer ctx.allocator.free(child);
                switch (entry.kind) {
                    .directory => try ctx.addDir(state, index, child),
                    .file => {
                        const content = try dir.readFileAlloc(ctx.io, entry.name, ctx.allocator, .unlimited);
                        defer ctx.allocator.free(content);
                        try ctx.addFile(state, index, child, content);
                    },
                    else => {},
                }
            }
        }

        fn build(ctx: @This(), state: R.State(.read_write)) !void {
            const head = try rf.readHeadRecurMaybe(kind, opts, state.readOnly(), ctx.io);
            var index = if (head) |oid| try Index.initFromCommit(state.readOnly(), ctx.io, ctx.allocator, &oid) else try Index.init(state.readOnly(), ctx.io, ctx.allocator);
            defer index.deinit();
            switch (ctx.files) {
                .files => |updates| for (updates) |file| try ctx.addFile(state, &index, file.path, file.content),
                .dirs => |dirs| for (dirs) |dir| try ctx.addDir(state, &index, dir),
            }
            ctx.tree.* = try xit.object.Tree.initFromIndex(kind, opts, state, ctx.io, ctx.allocator, &index);
        }

        pub fn run(ctx: @This(), cursor: *R.DB.Cursor(.read_write)) !void {
            var moment = try R.DB.HashMap(.read_write).init(cursor.*);
            try ctx.build(.{ .core = ctx.core, .extra = .{ .moment = &moment } });
        }
    };
    const ctx = Ctx{ .core = &repo.core, .io = io, .allocator = allocator, .files = files, .tree = &tree };
    switch (kind) {
        .git => try ctx.build(.{ .core = &repo.core, .extra = .{} }),
        .xit => {
            try repo.core.db_file.lock(io, .exclusive);
            defer repo.core.db_file.unlock(io);
            const history = try R.DB.ArrayList(.read_write).init(repo.core.db.rootCursor());
            try history.appendContext(.{ .slot = try history.getSlot(-1) }, ctx);
        },
    }
    var head_buffer: [rf.MAX_REF_CONTENT_SIZE]u8 = undefined;
    const head = try repo.head(io, &head_buffer);
    return repo.commitAtRef(io, allocator, metadata, &tree.?, head.ref);
}
