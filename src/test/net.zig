const std = @import("std");
const builtin = @import("builtin");
const xit = @import("xit");
const rp = xit.repo;
const rf = xit.ref;
const work = xit.workdir;
const hash = xit.hash;
const net = xit.net;

test "git fetch" {
    const allocator = std.testing.allocator;
    try testFetch(.git, .{ .is_test = true }, .{ .wire = .http }, 3001, allocator);
    if (.windows != builtin.os.tag) {
        try testFetch(.git, .{ .is_test = true }, .{ .wire = .raw }, 3002, allocator);
        try testFetch(.git, .{ .is_test = true }, .{ .wire = .ssh }, 3003, allocator);
    }
    try testFetch(.git, .{ .is_test = true }, .file, 0, allocator);
}

test "xit fetch" {
    const allocator = std.testing.allocator;
    try testFetch(.xit, .{ .is_test = true }, .{ .wire = .http }, 3004, allocator);
    if (.windows != builtin.os.tag) {
        try testFetch(.xit, .{ .is_test = true }, .{ .wire = .raw }, 3005, allocator);
        try testFetch(.xit, .{ .is_test = true }, .{ .wire = .ssh }, 3006, allocator);
    }
    try testFetch(.xit, .{ .is_test = true }, .file, 0, allocator);
}

test "git push" {
    const allocator = std.testing.allocator;
    try testPush(.git, .{ .is_test = true }, .{ .wire = .http }, 3007, allocator);
    if (.windows != builtin.os.tag) {
        try testPush(.git, .{ .is_test = true }, .{ .wire = .raw }, 3008, allocator);
        try testPush(.git, .{ .is_test = true }, .{ .wire = .ssh }, 3009, allocator);
    }
    try testPush(.git, .{ .is_test = true }, .file, 0, allocator);
}

test "xit push" {
    const allocator = std.testing.allocator;
    try testPush(.xit, .{ .is_test = true }, .{ .wire = .http }, 3010, allocator);
    if (.windows != builtin.os.tag) {
        try testPush(.xit, .{ .is_test = true }, .{ .wire = .raw }, 3011, allocator);
        try testPush(.xit, .{ .is_test = true }, .{ .wire = .ssh }, 3012, allocator);
    }
    try testPush(.xit, .{ .is_test = true }, .file, 0, allocator);
}

test "git clone" {
    const allocator = std.testing.allocator;
    try testClone(.git, .{ .is_test = true }, .{ .wire = .http }, 3013, allocator);
    if (.windows != builtin.os.tag) {
        try testClone(.git, .{ .is_test = true }, .{ .wire = .raw }, 3014, allocator);
        try testClone(.git, .{ .is_test = true }, .{ .wire = .ssh }, 3015, allocator);
    }
    try testClone(.git, .{ .is_test = true }, .file, 0, allocator);
}

test "xit clone" {
    const allocator = std.testing.allocator;
    try testClone(.xit, .{ .is_test = true }, .{ .wire = .http }, 3016, allocator);
    if (.windows != builtin.os.tag) {
        try testClone(.xit, .{ .is_test = true }, .{ .wire = .raw }, 3017, allocator);
        try testClone(.xit, .{ .is_test = true }, .{ .wire = .ssh }, 3018, allocator);
    }
    try testClone(.xit, .{ .is_test = true }, .file, 0, allocator);
}

test "git fetch large" {
    const allocator = std.testing.allocator;
    try testFetchLarge(.git, .{ .is_test = true }, .{ .wire = .http }, 3019, allocator);
    if (true) return; // skip the rest for now because they're slow
    if (.windows != builtin.os.tag) {
        try testFetchLarge(.git, .{ .is_test = true }, .{ .wire = .raw }, 3020, allocator);
        try testFetchLarge(.git, .{ .is_test = true }, .{ .wire = .ssh }, 3021, allocator);
    }
    try testFetchLarge(.git, .{ .is_test = true }, .file, 0, allocator);
}

test "git push large" {
    const allocator = std.testing.allocator;
    try testPushLarge(.git, .{ .is_test = true }, .{ .wire = .http }, 3022, allocator);
    if (true) return; // skip the rest for now because they're slow
    if (.windows != builtin.os.tag) {
        try testPushLarge(.git, .{ .is_test = true }, .{ .wire = .raw }, 3023, allocator);
        try testPushLarge(.git, .{ .is_test = true }, .{ .wire = .ssh }, 3024, allocator);
    }
    try testPushLarge(.git, .{ .is_test = true }, .file, 0, allocator);
}

fn Server(comptime transport_def: net.TransportDefinition) type {
    return struct {
        core: Core,

        const Core = switch (transport_def) {
            .file => void,
            .wire => |wire_kind| switch (wire_kind) {
                .http => struct {
                    allocator: std.mem.Allocator,
                    temp_dir_name: []const u8,
                    stop_server_endpoint: []const u8,
                    net_server: std.net.Server,
                    server_thread: std.Thread,
                },
                .raw => struct {
                    process: std.process.Child,
                },
                .ssh => struct {
                    process: std.process.Child,
                },
            },
        };

        fn init(allocator: std.mem.Allocator, comptime temp_dir_name: []const u8, comptime port: u16) !Server(transport_def) {
            switch (transport_def) {
                .file => return .{ .core = {} },
                .wire => |wire_kind| switch (wire_kind) {
                    .http => {
                        const address = try std.net.Address.parseIp("127.0.0.1", port);
                        const net_server = try address.listen(.{ .reuse_address = true });
                        errdefer net_server.deinit();
                        return .{
                            .core = .{
                                .allocator = allocator,
                                .temp_dir_name = temp_dir_name,
                                .stop_server_endpoint = std.fmt.comptimePrint("http://127.0.0.1:{}/stop-server", .{port}),
                                .net_server = net_server,
                                .server_thread = undefined,
                            },
                        };
                    },
                    .raw => {
                        const port_str = std.fmt.comptimePrint("{}", .{port});
                        var process = std.process.Child.init(
                            &.{ "git", "daemon", "--reuseaddr", "--base-path=.", "--export-all", "--enable=receive-pack", "--log-destination=stderr", "--port=" ++ port_str },
                            allocator,
                        );
                        process.cwd = temp_dir_name;
                        process.stdin_behavior = .Pipe;
                        process.stdout_behavior = .Pipe;
                        process.stderr_behavior = .Pipe;
                        return .{
                            .core = .{ .process = process },
                        };
                    },
                    .ssh => {
                        // create priv host key
                        const host_key_file = try std.fs.cwd().createFile(temp_dir_name ++ "/host_key", .{});
                        defer host_key_file.close();
                        try host_key_file.writeAll(
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
                            try host_key_file.setPermissions(.{ .inner = .{ .mode = 0o600 } });
                        }

                        // create priv client key
                        const priv_key_file = try std.fs.cwd().createFile(temp_dir_name ++ "/key", .{});
                        defer priv_key_file.close();
                        try priv_key_file.writeAll(
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
                            try priv_key_file.setPermissions(.{ .inner = .{ .mode = 0o600 } });
                        }

                        // create pub key
                        const pub_key_file = try std.fs.cwd().createFile(temp_dir_name ++ "/key.pub", .{});
                        defer pub_key_file.close();
                        try pub_key_file.writeAll(
                            \\ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKeIs8mJqigBZ5y84J4COgnAJJ5bHPKy+lM2SliMXbYm radar@roark
                            \\
                        );
                        if (.windows != builtin.os.tag) {
                            try pub_key_file.setPermissions(.{ .inner = .{ .mode = 0o600 } });
                        }

                        // create authorized_keys file
                        const auth_keys_file = try std.fs.cwd().createFile(temp_dir_name ++ "/authorized_keys", .{});
                        defer auth_keys_file.close();
                        try auth_keys_file.writeAll(
                            \\ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKeIs8mJqigBZ5y84J4COgnAJJ5bHPKy+lM2SliMXbYm radar@roark
                            \\
                        );
                        if (.windows != builtin.os.tag) {
                            try auth_keys_file.setPermissions(.{ .inner = .{ .mode = 0o600 } });
                        }

                        // create known_hosts file
                        const known_hosts_file = try std.fs.cwd().createFile(temp_dir_name ++ "/known_hosts", .{});
                        defer known_hosts_file.close();
                        const port_str = std.fmt.comptimePrint("{}", .{port});
                        try known_hosts_file.writeAll("[localhost]:" ++ port_str ++ " ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBLWmlR+TyfvK9UoSDPe1eO3irvpUa6MtxCVHCaiDOi9XjQstxfRpM5tmVBotZ/Mkw2kJr/O0ylCWvzqexqsTiUQ=");
                        if (.windows != builtin.os.tag) {
                            try known_hosts_file.setPermissions(.{ .inner = .{ .mode = 0o600 } });
                        }

                        // create sshd_config file
                        const sshd_config_file = try std.fs.cwd().createFile(temp_dir_name ++ "/sshd_config", .{});
                        defer sshd_config_file.close();
                        try sshd_config_file.writeAll(
                            \\AuthenticationMethods publickey
                            \\PubkeyAuthentication yes
                            \\PasswordAuthentication no
                            \\StrictModes no
                            \\
                        );
                        if (.windows != builtin.os.tag) {
                            try sshd_config_file.setPermissions(.{ .inner = .{ .mode = 0o600 } });
                        }

                        // create sshd.sh contents
                        const cwd_path = try std.process.getCwdAlloc(allocator);
                        defer allocator.free(cwd_path);
                        const host_key_path = try std.fs.path.join(allocator, &.{ cwd_path, temp_dir_name, "host_key" });
                        defer allocator.free(host_key_path);
                        const auth_keys_path = try std.fs.path.join(allocator, &.{ cwd_path, temp_dir_name, "authorized_keys" });
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
                        const sshd_file = try std.fs.cwd().createFile(temp_dir_name ++ "/sshd.sh", .{});
                        defer sshd_file.close();
                        try sshd_file.writeAll(sshd_contents);
                        if (.windows != builtin.os.tag) {
                            try sshd_file.setPermissions(.{ .inner = .{ .mode = 0o755 } });
                        }

                        var process = std.process.Child.init(&.{"./sshd.sh"}, allocator);
                        process.cwd = temp_dir_name;
                        process.stdin_behavior = .Pipe;
                        process.stdout_behavior = .Pipe;
                        process.stderr_behavior = .Pipe;
                        return .{
                            .core = .{ .process = process },
                        };
                    },
                },
            }
        }

        fn start(self: *Server(transport_def)) !void {
            switch (transport_def) {
                .file => {},
                .wire => |wire_kind| switch (wire_kind) {
                    .http => {
                        const ServerHandler = struct {
                            fn run(core: *Core) !void {
                                var send_buffer = [_]u8{0} ** 1024;
                                var recv_buffer = [_]u8{0} ** 1024;

                                accept: while (true) {
                                    const conn = try core.net_server.accept();
                                    defer conn.stream.close();

                                    var conn_br = conn.stream.reader(&recv_buffer);
                                    var conn_bw = conn.stream.writer(&send_buffer);
                                    var http_server = std.http.Server.init(conn_br.interface(), &conn_bw.interface);

                                    while (http_server.reader.state == .ready) {
                                        // give server some time to receive the request.
                                        // without it, POST requests sometimes don't have all the
                                        // expected data in their bodies because they use chunked encoding.
                                        std.Thread.sleep(std.time.ns_per_s * 0.5);

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

                                        const cwd_path = try std.process.getCwdAlloc(core.allocator);
                                        defer core.allocator.free(cwd_path);
                                        const temp_dir_path = try std.fs.path.join(core.allocator, &.{ cwd_path, core.temp_dir_name });
                                        defer core.allocator.free(temp_dir_path);
                                        const path_translated = try std.fmt.allocPrint(core.allocator, "{s}{s}", .{
                                            temp_dir_path,
                                            uri.path.percent_encoded,
                                        });
                                        defer core.allocator.free(path_translated);

                                        // init env map
                                        var env_map = std.process.EnvMap.init(core.allocator);
                                        defer env_map.deinit();
                                        try env_map.put("GATEWAY_INTERFACE", "CGI/1.1");
                                        try env_map.put("REQUEST_METHOD", @tagName(request.head.method));
                                        try env_map.put("PATH_INFO", path);
                                        try env_map.put("PATH_TRANSLATED", path_translated);
                                        if (uri.query) |query| {
                                            try env_map.put("QUERY_STRING", query.percent_encoded);
                                        }

                                        var accept = std.ArrayList([]const u8){};
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
                                            }
                                        }

                                        const accept_str = try std.mem.join(core.allocator, ",", accept.items);
                                        defer core.allocator.free(accept_str);
                                        if (accept_str.len > 0) {
                                            try env_map.put("HTTP_ACCEPT", accept_str);
                                        }

                                        var process = std.process.Child.init(&.{ "git", "http-backend" }, core.allocator);
                                        process.cwd = core.temp_dir_name;
                                        process.stdin_behavior = .Pipe;
                                        process.stdout_behavior = .Pipe;
                                        process.stderr_behavior = .Pipe;
                                        process.env_map = &env_map;
                                        try process.spawn();

                                        if (request.head.method == .POST) {
                                            const reader = try request.readerExpectContinue(&.{});
                                            const request_body = try reader.allocRemaining(core.allocator, .unlimited);
                                            defer core.allocator.free(request_body);
                                            try process.stdin.?.writeAll(request_body);
                                        }
                                        process.stdin.?.close();
                                        process.stdin = null;

                                        var stdout = std.ArrayList(u8){};
                                        defer stdout.deinit(core.allocator);
                                        var stderr = std.ArrayList(u8){};
                                        defer stderr.deinit(core.allocator);
                                        try process.collectOutput(core.allocator, &stdout, &stderr, 20 * 1024 * 1024);

                                        _ = try process.wait();

                                        // transition the http state machine so it can
                                        // read the next request on this connection
                                        if (http_server.reader.state == .received_head) {
                                            http_server.reader.state = .ready;
                                        }

                                        if (stderr.items.len > 0) {
                                            std.debug.print("Error from git-http-backend:\n{s}\n", .{stderr.items});
                                            try http_server.out.writeAll("HTTP/1.1 500 Internal Server Error\r\n\r\n");
                                        } else {
                                            try http_server.out.writeAll("HTTP/1.1 200 OK\r\n");
                                            const double_newline = "\r\n\r\n";
                                            const double_newline_idx = std.mem.indexOf(u8, stdout.items, double_newline) orelse unreachable;
                                            try http_server.out.writeAll(stdout.items[0..double_newline_idx]);
                                            try http_server.out.print("\r\nContent-Length: {}", .{stdout.items.len - (double_newline_idx + double_newline.len)});
                                            try http_server.out.writeAll(stdout.items[double_newline_idx..]);
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
                    .raw => try self.core.process.spawn(),
                    .ssh => try self.core.process.spawn(),
                },
            }

            // give server some time to start
            std.Thread.sleep(std.time.ns_per_s * 0.5);
        }

        fn stop(self: *Server(transport_def)) void {
            switch (transport_def) {
                .file => {},
                .wire => |wire_kind| switch (wire_kind) {
                    .http => {
                        var client = std.http.Client{ .allocator = self.core.allocator };
                        defer client.deinit();
                        _ = client.fetch(.{ .location = .{ .url = self.core.stop_server_endpoint } }) catch return;
                        self.core.server_thread.join();
                    },
                    .raw => _ = self.core.process.kill() catch {},
                    .ssh => _ = self.core.process.kill() catch {},
                },
            }
        }
    };
}

fn testFetch(
    comptime repo_kind: rp.RepoKind,
    comptime repo_opts: rp.RepoOpts(repo_kind),
    comptime transport_def: net.TransportDefinition,
    comptime port: u16,
    allocator: std.mem.Allocator,
) !void {
    const temp_dir_name = "temp-testnet-fetch";

    // create the temp dir
    const cwd = std.fs.cwd();
    var temp_dir_or_err = cwd.openDir(temp_dir_name, .{});
    if (temp_dir_or_err) |*temp_dir| {
        temp_dir.close();
        try cwd.deleteTree(temp_dir_name);
    } else |_| {}
    var temp_dir = try cwd.makeOpenPath(temp_dir_name, .{});
    defer cwd.deleteTree(temp_dir_name) catch {};
    defer temp_dir.close();

    // init server
    var server = try Server(transport_def).init(allocator, temp_dir_name, port);
    try server.start();
    defer server.stop();

    const cwd_path = try std.process.getCwdAlloc(allocator);
    defer allocator.free(cwd_path);

    const server_path = try std.fs.path.join(allocator, &.{ cwd_path, temp_dir_name, "server" });
    defer allocator.free(server_path);

    var server_repo = try rp.Repo(.git, .{ .is_test = true }).init(allocator, .{ .path = server_path });
    defer server_repo.deinit(allocator);

    // make a commit
    const commit1 = blk: {
        const hello_txt = try server_repo.core.work_dir.createFile("hello.txt", .{ .truncate = true });
        defer hello_txt.close();
        try hello_txt.writeAll("hello, world!");
        try server_repo.add(allocator, &.{"hello.txt"});
        break :blk try server_repo.commit(allocator, .{ .message = "let there be light" });
    };

    // export server repo
    {
        const export_file = try server_repo.core.repo_dir.createFile("git-daemon-export-ok", .{});
        defer export_file.close();

        try server_repo.addConfig(allocator, .{ .name = "uploadpack.allowAnySHA1InWant", .value = "true" });
    }

    // add a tag
    _ = try server_repo.addTag(allocator, .{ .name = "1.0.0", .message = "hi" });

    const client_path = try std.fs.path.join(allocator, &.{ cwd_path, temp_dir_name, "client" });
    defer allocator.free(client_path);

    var client_repo = try rp.Repo(repo_kind, repo_opts).init(allocator, .{ .path = client_path });
    defer client_repo.deinit(allocator);

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

        try client_repo.addRemote(allocator, .{ .name = "origin", .value = remote_url });
        try client_repo.addConfig(allocator, .{ .name = "branch.master.remote", .value = "origin" });
    }

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
        const known_hosts_path = try std.fs.path.join(allocator, &.{ cwd_path, temp_dir_name, "known_hosts" });
        defer allocator.free(known_hosts_path);

        const priv_key_path = try std.fs.path.join(allocator, &.{ cwd_path, temp_dir_name, "key" });
        defer allocator.free(priv_key_path);

        break :blk try std.fmt.allocPrint(allocator, "ssh -o UserKnownHostsFile=\"{s}\" -o IdentityFile=\"{s}\"", .{ known_hosts_path, priv_key_path });
    } else null;
    defer if (ssh_cmd_maybe) |ssh_cmd| allocator.free(ssh_cmd);

    client_repo.fetch(
        allocator,
        "origin",
        .{ .refspecs = refspecs, .wire = .{ .ssh = .{ .command = ssh_cmd_maybe } } },
    ) catch |err| {
        if (false) {
            var stdout = std.ArrayList(u8){};
            defer stdout.deinit(allocator);
            var stderr = std.ArrayList(u8){};
            defer stderr.deinit(allocator);
            try server.core.process.collectOutput(allocator, &stdout, &stderr, 1024 * 1024);
            if (stdout.items.len > 0) std.debug.print("server output:\n{s}\n", .{stdout.items});
            if (stderr.items.len > 0) std.debug.print("server error:\n{s}\n", .{stderr.items});
        }
        return err;
    };

    // update the working dir
    try client_repo.restore(allocator, ".");

    // make sure fetch was successful
    {
        const hello_txt = try temp_dir.openFile("client/hello.txt", .{});
        defer hello_txt.close();

        try std.testing.expect(null != try client_repo.readRef(.{ .kind = .tag, .name = "1.0.0" }));
        try std.testing.expect(null != try client_repo.readRef(.{ .kind = .head, .name = "foo" }));

        const oid_master = (try client_repo.readRef(.{ .kind = .head, .name = "master" })).?;
        try std.testing.expectEqualStrings(&commit1, &oid_master);
    }

    // make another commit
    const commit2 = blk: {
        const goodbye_txt = try server_repo.core.work_dir.createFile("goodbye.txt", .{ .truncate = true });
        defer goodbye_txt.close();
        try goodbye_txt.writeAll("goodbye, world!");
        try server_repo.add(allocator, &.{"goodbye.txt"});
        break :blk try server_repo.commit(allocator, .{ .message = "goodbye" });
    };

    client_repo.fetch(
        allocator,
        "origin",
        .{ .refspecs = refspecs, .wire = .{ .ssh = .{ .command = ssh_cmd_maybe } } },
    ) catch |err| {
        if (false) {
            var stdout = std.ArrayList(u8){};
            defer stdout.deinit(allocator);
            var stderr = std.ArrayList(u8){};
            defer stderr.deinit(allocator);
            try server.core.process.collectOutput(allocator, &stdout, &stderr, 1024 * 1024);
            if (stdout.items.len > 0) std.debug.print("server output:\n{s}\n", .{stdout.items});
            if (stderr.items.len > 0) std.debug.print("server error:\n{s}\n", .{stderr.items});
        }
        return err;
    };

    // update the working dir
    try client_repo.restore(allocator, ".");

    // make sure fetch was successful
    {
        const goodbye_txt = try temp_dir.openFile("client/goodbye.txt", .{});
        defer goodbye_txt.close();

        const oid_master = (try client_repo.readRef(.{ .kind = .head, .name = "master" })).?;
        try std.testing.expectEqualStrings(&commit2, &oid_master);
    }
}

fn testPush(
    comptime repo_kind: rp.RepoKind,
    comptime repo_opts: rp.RepoOpts(repo_kind),
    comptime transport_def: net.TransportDefinition,
    comptime port: u16,
    allocator: std.mem.Allocator,
) !void {
    const temp_dir_name = "temp-testnet-push";

    // create the temp dir
    const cwd = std.fs.cwd();
    var temp_dir_or_err = cwd.openDir(temp_dir_name, .{});
    if (temp_dir_or_err) |*temp_dir| {
        temp_dir.close();
        try cwd.deleteTree(temp_dir_name);
    } else |_| {}
    var temp_dir = try cwd.makeOpenPath(temp_dir_name, .{});
    defer cwd.deleteTree(temp_dir_name) catch {};
    defer temp_dir.close();

    // init server
    var server = try Server(transport_def).init(allocator, temp_dir_name, port);
    try server.start();
    defer server.stop();

    const cwd_path = try std.process.getCwdAlloc(allocator);
    defer allocator.free(cwd_path);

    const server_path = try std.fs.path.join(allocator, &.{ cwd_path, temp_dir_name, "server" });
    defer allocator.free(server_path);

    var server_repo = try rp.Repo(.git, .{ .is_test = true }).init(allocator, .{ .path = server_path });
    defer server_repo.deinit(allocator);

    // add config
    switch (transport_def) {
        .file => try server_repo.addConfig(allocator, .{ .name = "core.bare", .value = "true" }),
        .wire => {
            try server_repo.addConfig(allocator, .{ .name = "core.bare", .value = "false" });
            try server_repo.addConfig(allocator, .{ .name = "receive.denycurrentbranch", .value = "updateinstead" });
        },
    }
    try server_repo.addConfig(allocator, .{ .name = "http.receivepack", .value = "true" });

    // export server repo
    {
        const export_file = try server_repo.core.repo_dir.createFile("git-daemon-export-ok", .{});
        defer export_file.close();
    }

    const client_path = try std.fs.path.join(allocator, &.{ cwd_path, temp_dir_name, "client" });
    defer allocator.free(client_path);

    var client_repo = try rp.Repo(repo_kind, repo_opts).init(allocator, .{ .path = client_path });
    defer client_repo.deinit(allocator);

    // make a commit
    const commit1 = blk: {
        const hello_txt = try client_repo.core.work_dir.createFile("hello.txt", .{ .truncate = true });
        defer hello_txt.close();
        try hello_txt.writeAll("hello, world!");
        try client_repo.add(allocator, &.{"hello.txt"});
        break :blk try client_repo.commit(allocator, .{ .message = "let there be light" });
    };

    // add a tag
    _ = try client_repo.addTag(allocator, .{ .name = "1.0.0", .message = "hi" });

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

        try client_repo.addRemote(allocator, .{ .name = "origin", .value = remote_url });
        try client_repo.addConfig(allocator, .{ .name = "branch.master.remote", .value = "origin" });
    }

    const refspecs = &.{
        "refs/tags/1.0.0:refs/tags/1.0.0",
    };

    const is_ssh = switch (transport_def) {
        .file => false,
        .wire => |wire_kind| .ssh == wire_kind,
    };
    const ssh_cmd_maybe: ?[]const u8 = if (is_ssh) blk: {
        const known_hosts_path = try std.fs.path.join(allocator, &.{ cwd_path, temp_dir_name, "known_hosts" });
        defer allocator.free(known_hosts_path);

        const priv_key_path = try std.fs.path.join(allocator, &.{ cwd_path, temp_dir_name, "key" });
        defer allocator.free(priv_key_path);

        break :blk try std.fmt.allocPrint(allocator, "ssh -o UserKnownHostsFile=\"{s}\" -o IdentityFile=\"{s}\"", .{ known_hosts_path, priv_key_path });
    } else null;
    defer if (ssh_cmd_maybe) |ssh_cmd| allocator.free(ssh_cmd);

    client_repo.push(
        allocator,
        "origin",
        "master",
        false,
        .{ .refspecs = refspecs, .wire = .{ .ssh = .{ .command = ssh_cmd_maybe } } },
    ) catch |err| {
        if (false) {
            var stdout = std.ArrayList(u8){};
            defer stdout.deinit(allocator);
            var stderr = std.ArrayList(u8){};
            defer stderr.deinit(allocator);
            try server.core.process.collectOutput(allocator, &stdout, &stderr, 1024 * 1024);
            if (stdout.items.len > 0) std.debug.print("server output:\n{s}\n", .{stdout.items});
            if (stderr.items.len > 0) std.debug.print("server error:\n{s}\n", .{stderr.items});
        }
        return err;
    };

    // make sure push was successful
    {
        try std.testing.expect(null != try server_repo.readRef(.{ .kind = .tag, .name = "1.0.0" }));

        const oid_master = (try server_repo.readRef(.{ .kind = .head, .name = "master" })).?;
        try std.testing.expectEqualStrings(&commit1, &oid_master);
    }

    // make a commit on the server
    {
        const hello_txt = try server_repo.core.work_dir.createFile("hello.txt", .{ .truncate = true });
        defer hello_txt.close();
        try hello_txt.writeAll("hello, world from the server!");
        try server_repo.add(allocator, &.{"hello.txt"});
        _ = try server_repo.commit(allocator, .{ .message = "new commit from the server" });
    }

    // make another commit
    const commit2 = blk: {
        const goodbye_txt = try client_repo.core.work_dir.createFile("goodbye.txt", .{ .truncate = true });
        defer goodbye_txt.close();
        try goodbye_txt.writeAll("goodbye, world!");
        try client_repo.add(allocator, &.{"goodbye.txt"});
        break :blk try client_repo.commit(allocator, .{ .message = "goodbye" });
    };

    // can't push because server has commit not found locally
    try std.testing.expectError(error.RemoteRefContainsCommitsNotFoundLocally, client_repo.push(
        allocator,
        "origin",
        "master",
        false,
        .{ .wire = .{ .ssh = .{ .command = ssh_cmd_maybe } } },
    ));

    // make a commit on the server with no parents, thus creating an incompatible git history
    {
        const hello_txt = try server_repo.core.work_dir.createFile("hello.txt", .{ .truncate = true });
        defer hello_txt.close();
        try hello_txt.writeAll("hello, world from the server again!");
        try server_repo.add(allocator, &.{"hello.txt"});
        _ = try server_repo.commit(allocator, .{ .message = "new git history on the server", .parent_oids = &.{} });
    }

    // can't push because commit doesn't exist locally
    try std.testing.expectError(error.RemoteRefContainsCommitsNotFoundLocally, client_repo.push(
        allocator,
        "origin",
        "master",
        false,
        .{ .wire = .{ .ssh = .{ .command = ssh_cmd_maybe } } },
    ));

    // retrieve the commit object
    try client_repo.fetch(
        allocator,
        "origin",
        .{ .wire = .{ .ssh = .{ .command = ssh_cmd_maybe } } },
    );

    // can't push because server's history is incompatible
    try std.testing.expectError(error.RemoteRefContainsIncompatibleHistory, client_repo.push(
        allocator,
        "origin",
        "master",
        false,
        .{ .wire = .{ .ssh = .{ .command = ssh_cmd_maybe } } },
    ));

    // force push
    try client_repo.push(
        allocator,
        "origin",
        "master",
        true,
        .{ .wire = .{ .ssh = .{ .command = ssh_cmd_maybe } } },
    );

    // make sure push was successful
    {
        const oid_master = (try server_repo.readRef(.{ .kind = .head, .name = "master" })).?;
        try std.testing.expectEqualStrings(&commit2, &oid_master);
    }

    // remove the remote tag
    try client_repo.push(
        allocator,
        "origin",
        ":refs/tags/1.0.0",
        false,
        .{ .wire = .{ .ssh = .{ .command = ssh_cmd_maybe } } },
    );

    // make sure push was successful
    try std.testing.expect(null == try server_repo.readRef(.{ .kind = .tag, .name = "1.0.0" }));
}

fn testClone(
    comptime repo_kind: rp.RepoKind,
    comptime repo_opts: rp.RepoOpts(repo_kind),
    comptime transport_def: net.TransportDefinition,
    comptime port: u16,
    allocator: std.mem.Allocator,
) !void {
    const temp_dir_name = "temp-testnet-clone";

    // create the temp dir
    const cwd = std.fs.cwd();
    var temp_dir_or_err = cwd.openDir(temp_dir_name, .{});
    if (temp_dir_or_err) |*temp_dir| {
        temp_dir.close();
        try cwd.deleteTree(temp_dir_name);
    } else |_| {}
    var temp_dir = try cwd.makeOpenPath(temp_dir_name, .{});
    defer cwd.deleteTree(temp_dir_name) catch {};
    defer temp_dir.close();

    // init server
    var server = try Server(transport_def).init(allocator, temp_dir_name, port);
    try server.start();
    defer server.stop();

    const cwd_path = try std.process.getCwdAlloc(allocator);
    defer allocator.free(cwd_path);

    const temp_path = try std.fs.path.join(allocator, &.{ cwd_path, temp_dir_name });
    defer allocator.free(temp_path);

    const server_path = try std.fs.path.join(allocator, &.{ cwd_path, temp_dir_name, "server" });
    defer allocator.free(server_path);

    // init server repo with default branch name as main
    var server_repo = try rp.Repo(.git, .{ .is_test = true }).init(allocator, .{ .path = server_path, .create_default_branch = "main" });
    defer server_repo.deinit(allocator);

    // make a commit
    {
        const hello_txt = try server_repo.core.work_dir.createFile("hello.txt", .{ .truncate = true });
        defer hello_txt.close();
        try hello_txt.writeAll("hello, world!");
        try server_repo.add(allocator, &.{"hello.txt"});
        _ = try server_repo.commit(allocator, .{ .message = "let there be light" });
    }

    // export server repo
    {
        const export_file = try server_repo.core.repo_dir.createFile("git-daemon-export-ok", .{});
        defer export_file.close();
    }

    const client_path = try std.fs.path.join(allocator, &.{ cwd_path, temp_dir_name, "client" });
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
    const ssh_cmd_maybe: ?[]const u8 = if (is_ssh) blk: {
        const known_hosts_path = try std.fs.path.join(allocator, &.{ cwd_path, temp_dir_name, "known_hosts" });
        defer allocator.free(known_hosts_path);

        const priv_key_path = try std.fs.path.join(allocator, &.{ cwd_path, temp_dir_name, "key" });
        defer allocator.free(priv_key_path);

        break :blk try std.fmt.allocPrint(allocator, "ssh -o UserKnownHostsFile=\"{s}\" -o IdentityFile=\"{s}\"", .{ known_hosts_path, priv_key_path });
    } else null;
    defer if (ssh_cmd_maybe) |ssh_cmd| allocator.free(ssh_cmd);

    // clone repo
    var client_repo = rp.Repo(repo_kind, repo_opts).clone(
        allocator,
        remote_url,
        temp_path,
        client_path,
        .{ .wire = .{ .ssh = .{ .command = ssh_cmd_maybe } } },
    ) catch |err| {
        if (false) {
            var stdout = std.ArrayList(u8){};
            defer stdout.deinit(allocator);
            var stderr = std.ArrayList(u8){};
            defer stderr.deinit(allocator);
            try server.core.process.collectOutput(allocator, &stdout, &stderr, 1024 * 1024);
            if (stdout.items.len > 0) std.debug.print("server output:\n{s}\n", .{stdout.items});
            if (stderr.items.len > 0) std.debug.print("server error:\n{s}\n", .{stderr.items});
        }
        return err;
    };
    defer client_repo.deinit(allocator);

    // make sure clone was successful
    const hello_txt = try temp_dir.openFile("client/hello.txt", .{});
    defer hello_txt.close();

    // make sure HEAD points to the right default branch
    var current_branch_buffer = [_]u8{0} ** rf.MAX_REF_CONTENT_SIZE;
    const head = try client_repo.head(&current_branch_buffer);
    try std.testing.expectEqualStrings("main", head.ref.name);
}

fn testFetchLarge(
    comptime repo_kind: rp.RepoKind,
    comptime repo_opts: rp.RepoOpts(repo_kind),
    comptime transport_def: net.TransportDefinition,
    comptime port: u16,
    allocator: std.mem.Allocator,
) !void {
    const temp_dir_name = "temp-testnet-fetch-large";

    // create the temp dir
    const cwd = std.fs.cwd();
    var temp_dir_or_err = cwd.openDir(temp_dir_name, .{});
    if (temp_dir_or_err) |*temp_dir| {
        temp_dir.close();
        try cwd.deleteTree(temp_dir_name);
    } else |_| {}
    var temp_dir = try cwd.makeOpenPath(temp_dir_name, .{});
    defer cwd.deleteTree(temp_dir_name) catch {};
    defer temp_dir.close();

    // init server
    var server = try Server(transport_def).init(allocator, temp_dir_name, port);
    try server.start();
    defer server.stop();

    const cwd_path = try std.process.getCwdAlloc(allocator);
    defer allocator.free(cwd_path);

    const server_path = try std.fs.path.join(allocator, &.{ cwd_path, temp_dir_name, "server" });
    defer allocator.free(server_path);

    var server_repo = try rp.Repo(.git, .{ .is_test = true }).init(allocator, .{ .path = server_path });
    defer server_repo.deinit(allocator);

    var server_dir = try cwd.openDir(server_path, .{});
    defer server_dir.close();

    // copy files from current repo into server dir
    for (&[_][]const u8{ "src", "docs" }) |dir_name| {
        var src_repo_dir = try cwd.openDir(dir_name, .{ .iterate = true });
        defer src_repo_dir.close();

        var dest_repo_dir = try server_dir.makeOpenPath(dir_name, .{});
        defer dest_repo_dir.close();

        try copyDir(src_repo_dir, dest_repo_dir);

        try server_repo.add(allocator, &.{dir_name});
    }

    // make a commit
    const commit1 = try server_repo.commit(allocator, .{ .message = "let there be light" });

    // export server repo
    {
        const export_file = try server_repo.core.repo_dir.createFile("git-daemon-export-ok", .{});
        defer export_file.close();
    }

    const client_path = try std.fs.path.join(allocator, &.{ cwd_path, temp_dir_name, "client" });
    defer allocator.free(client_path);

    var client_repo = try rp.Repo(repo_kind, repo_opts).init(allocator, .{ .path = client_path });
    defer client_repo.deinit(allocator);

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

        try client_repo.addRemote(allocator, .{ .name = "origin", .value = remote_url });
        try client_repo.addConfig(allocator, .{ .name = "branch.master.remote", .value = "origin" });
    }

    const refspecs = &.{
        "+refs/heads/master:refs/heads/master",
    };

    const is_ssh = switch (transport_def) {
        .file => false,
        .wire => |wire_kind| .ssh == wire_kind,
    };
    const ssh_cmd_maybe: ?[]const u8 = if (is_ssh) blk: {
        const known_hosts_path = try std.fs.path.join(allocator, &.{ cwd_path, temp_dir_name, "known_hosts" });
        defer allocator.free(known_hosts_path);

        const priv_key_path = try std.fs.path.join(allocator, &.{ cwd_path, temp_dir_name, "key" });
        defer allocator.free(priv_key_path);

        break :blk try std.fmt.allocPrint(allocator, "ssh -o UserKnownHostsFile=\"{s}\" -o IdentityFile=\"{s}\"", .{ known_hosts_path, priv_key_path });
    } else null;
    defer if (ssh_cmd_maybe) |ssh_cmd| allocator.free(ssh_cmd);

    client_repo.fetch(
        allocator,
        "origin",
        .{ .refspecs = refspecs, .wire = .{ .ssh = .{ .command = ssh_cmd_maybe } } },
    ) catch |err| {
        if (false) {
            var stdout = std.ArrayList(u8){};
            defer stdout.deinit(allocator);
            var stderr = std.ArrayList(u8){};
            defer stderr.deinit(allocator);
            try server.core.process.collectOutput(allocator, &stdout, &stderr, 1024 * 1024);
            if (stdout.items.len > 0) std.debug.print("server output:\n{s}\n", .{stdout.items});
            if (stderr.items.len > 0) std.debug.print("server error:\n{s}\n", .{stderr.items});
        }
        return err;
    };

    // update the working dir
    try client_repo.restore(allocator, ".");

    // make sure fetch was successful
    {
        const oid_master = (try client_repo.readRef(.{ .kind = .head, .name = "master" })).?;
        try std.testing.expectEqualStrings(&commit1, &oid_master);
    }
}

fn testPushLarge(
    comptime repo_kind: rp.RepoKind,
    comptime repo_opts: rp.RepoOpts(repo_kind),
    comptime transport_def: net.TransportDefinition,
    comptime port: u16,
    allocator: std.mem.Allocator,
) !void {
    const temp_dir_name = "temp-testnet-push-large";

    // create the temp dir
    const cwd = std.fs.cwd();
    var temp_dir_or_err = cwd.openDir(temp_dir_name, .{});
    if (temp_dir_or_err) |*temp_dir| {
        temp_dir.close();
        try cwd.deleteTree(temp_dir_name);
    } else |_| {}
    var temp_dir = try cwd.makeOpenPath(temp_dir_name, .{});
    defer cwd.deleteTree(temp_dir_name) catch {};
    defer temp_dir.close();

    // init server
    var server = try Server(transport_def).init(allocator, temp_dir_name, port);
    try server.start();
    defer server.stop();

    const cwd_path = try std.process.getCwdAlloc(allocator);
    defer allocator.free(cwd_path);

    const server_path = try std.fs.path.join(allocator, &.{ cwd_path, temp_dir_name, "server" });
    defer allocator.free(server_path);

    var server_repo = try rp.Repo(.git, .{ .is_test = true }).init(allocator, .{ .path = server_path });
    defer server_repo.deinit(allocator);

    // add config
    switch (transport_def) {
        .file => try server_repo.addConfig(allocator, .{ .name = "core.bare", .value = "true" }),
        .wire => {
            try server_repo.addConfig(allocator, .{ .name = "core.bare", .value = "false" });
            try server_repo.addConfig(allocator, .{ .name = "receive.denycurrentbranch", .value = "updateinstead" });
        },
    }
    try server_repo.addConfig(allocator, .{ .name = "http.receivepack", .value = "true" });

    // export server repo
    {
        const export_file = try server_repo.core.repo_dir.createFile("git-daemon-export-ok", .{});
        defer export_file.close();
    }

    const client_path = try std.fs.path.join(allocator, &.{ cwd_path, temp_dir_name, "client" });
    defer allocator.free(client_path);

    var client_repo = try rp.Repo(repo_kind, repo_opts).init(allocator, .{ .path = client_path });
    defer client_repo.deinit(allocator);

    var client_dir = try cwd.openDir(client_path, .{});
    defer client_dir.close();

    // copy files from current repo into client dir
    for (&[_][]const u8{ "src", "docs" }) |dir_name| {
        var src_repo_dir = try cwd.openDir(dir_name, .{ .iterate = true });
        defer src_repo_dir.close();

        var dest_repo_dir = try client_dir.makeOpenPath(dir_name, .{});
        defer dest_repo_dir.close();

        try copyDir(src_repo_dir, dest_repo_dir);

        try client_repo.add(allocator, &.{dir_name});
    }

    // make a commit
    const commit1 = try client_repo.commit(allocator, .{ .message = "let there be light" });

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

        try client_repo.addRemote(allocator, .{ .name = "origin", .value = remote_url });
        try client_repo.addConfig(allocator, .{ .name = "branch.master.remote", .value = "origin" });
    }

    const is_ssh = switch (transport_def) {
        .file => false,
        .wire => |wire_kind| .ssh == wire_kind,
    };
    const ssh_cmd_maybe: ?[]const u8 = if (is_ssh) blk: {
        const known_hosts_path = try std.fs.path.join(allocator, &.{ cwd_path, temp_dir_name, "known_hosts" });
        defer allocator.free(known_hosts_path);

        const priv_key_path = try std.fs.path.join(allocator, &.{ cwd_path, temp_dir_name, "key" });
        defer allocator.free(priv_key_path);

        break :blk try std.fmt.allocPrint(allocator, "ssh -o UserKnownHostsFile=\"{s}\" -o IdentityFile=\"{s}\"", .{ known_hosts_path, priv_key_path });
    } else null;
    defer if (ssh_cmd_maybe) |ssh_cmd| allocator.free(ssh_cmd);

    client_repo.push(
        allocator,
        "origin",
        "master",
        false,
        .{ .refspecs = &.{}, .wire = .{ .ssh = .{ .command = ssh_cmd_maybe } } },
    ) catch |err| {
        if (false) {
            var stdout = std.ArrayList(u8){};
            defer stdout.deinit(allocator);
            var stderr = std.ArrayList(u8){};
            defer stderr.deinit(allocator);
            try server.core.process.collectOutput(allocator, &stdout, &stderr, 1024 * 1024);
            if (stdout.items.len > 0) std.debug.print("server output:\n{s}\n", .{stdout.items});
            if (stderr.items.len > 0) std.debug.print("server error:\n{s}\n", .{stderr.items});
        }
        return err;
    };

    // make sure push was successful
    {
        const oid_master = (try server_repo.readRef(.{ .kind = .head, .name = "master" })).?;
        try std.testing.expectEqualStrings(&commit1, &oid_master);
    }
}

fn copyDir(src_dir: std.fs.Dir, dest_dir: std.fs.Dir) !void {
    var iter = src_dir.iterate();
    while (try iter.next()) |entry| {
        switch (entry.kind) {
            .file => try src_dir.copyFile(entry.name, dest_dir, entry.name, .{}),
            .directory => {
                try dest_dir.makeDir(entry.name);
                var dest_entry_dir = try dest_dir.openDir(entry.name, .{ .access_sub_paths = true, .iterate = true, .no_follow = true });
                defer dest_entry_dir.close();
                var src_entry_dir = try src_dir.openDir(entry.name, .{ .access_sub_paths = true, .iterate = true, .no_follow = true });
                defer src_entry_dir.close();
                try copyDir(src_entry_dir, dest_entry_dir);
            },
            else => {},
        }
    }
}
