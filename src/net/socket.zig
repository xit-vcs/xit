const std = @import("std");
const builtin = @import("builtin");

const CONNECT_TIMEOUT = 5000;

const INVALID_SOCKET = if (.windows == builtin.os.tag)
    std.os.windows.ws2_32.INVALID_SOCKET
else
    -1;

pub const SocketStream = struct {
    io: std.Io,
    host: []const u8,
    port: u16,
    socket: std.posix.socket_t,

    pub fn init(
        io: std.Io,
        allocator: std.mem.Allocator,
        host: []const u8,
        port: u16,
    ) !SocketStream {
        const host_dupe = try allocator.dupe(u8, host);
        errdefer allocator.free(host_dupe);

        return .{
            .io = io,
            .host = host_dupe,
            .port = port,
            .socket = INVALID_SOCKET,
        };
    }

    pub fn deinit(self: *SocketStream, allocator: std.mem.Allocator) void {
        allocator.free(self.host);
    }

    pub fn close(self: *SocketStream) !void {
        if (self.socket != INVALID_SOCKET) {
            std.posix.close(self.socket);
            self.socket = INVALID_SOCKET;
        }
    }

    pub fn read(
        self: *SocketStream,
        data: [*c]u8,
        len: usize,
    ) !usize {
        return try recv(self.socket, data[0..len], 0);
    }

    pub fn write(
        self: *SocketStream,
        data: [*c]const u8,
        len: usize,
    ) !usize {
        return try send(self.socket, data[0..len], 0);
    }

    pub fn writeAll(
        self: *SocketStream,
        data: [*c]const u8,
        len: usize,
    ) !void {
        var total_written: usize = 0;
        while (total_written < len) {
            const written = try self.write(data + total_written, len - total_written);
            total_written += written;
        }
    }

    pub fn connect(self: *SocketStream) !void {
        var canonical_name_buffer: [std.Io.net.HostName.max_len]u8 = undefined;
        var results_buffer: [32]std.Io.net.HostName.LookupResult = undefined;
        var results: std.Io.Queue(std.Io.net.HostName.LookupResult) = .init(&results_buffer);

        try std.Io.net.HostName.lookup(try .init(self.host), self.io, &results, .{
            .port = self.port,
            .canonical_name_buffer = &canonical_name_buffer,
        });

        var addr_v4: ?std.Io.net.IpAddress = null;
        var addr_v6: ?std.Io.net.IpAddress = null;
        while (results.getOne(self.io)) |result| switch (result) {
            .address => |address| switch (address) {
                .ip4 => addr_v4 = address,
                .ip6 => addr_v6 = address,
            },
            .canonical_name => continue,
        } else |_| {}

        const address = addr_v4 orelse addr_v6 orelse return error.AddressNotFound;
        const family: u32 = switch (address) {
            .ip4 => std.c.AF.INET,
            .ip6 => std.c.AF.INET6,
        };

        const s = try initSocket(family, std.posix.SOCK.STREAM, std.posix.IPPROTO.TCP);

        if (INVALID_SOCKET != s) {
            try connectWithTimeout(s, &address, CONNECT_TIMEOUT);
        } else {
            return error.ConnectFailed;
        }

        self.socket = s;
    }
};

fn initSocket(domain: u32, socket_type: u32, protocol: u32) !std.posix.socket_t {
    const rc = std.posix.system.socket(domain, socket_type, protocol);
    switch (std.posix.errno(rc)) {
        .SUCCESS => return @intCast(rc),
        else => return error.SocketCreationFailure,
    }
}

fn send(sockfd: std.posix.socket_t, buf: []const u8, flags: u32) !usize {
    const rc = std.posix.system.sendto(sockfd, buf.ptr, buf.len, flags, null, 0);
    switch (std.posix.errno(rc)) {
        .SUCCESS => return @intCast(rc),
        else => return error.SendFailed,
    }
}

pub const RecvFromError = error{
    /// The socket is marked nonblocking and the requested operation would block, and
    /// there is no global event loop configured.
    WouldBlock,

    /// A remote host refused to allow the network connection, typically because it is not
    /// running the requested service.
    ConnectionRefused,

    /// Could not allocate kernel memory.
    SystemResources,

    ConnectionResetByPeer,
    Timeout,

    /// The socket has not been bound.
    SocketNotBound,

    /// The UDP message was too big for the buffer and part of it has been discarded
    MessageOversize,

    /// The network subsystem has failed.
    NetworkDown,

    /// The socket is not connected (connection-oriented sockets only).
    SocketUnconnected,

    /// The other end closed the socket unexpectedly or a read is executed on a shut down socket
    BrokenPipe,
} || std.Io.UnexpectedError;

pub fn recv(sock: std.posix.socket_t, buf: []u8, flags: u32) RecvFromError!usize {
    return recvfrom(sock, buf, flags, null, null);
}

pub fn recvfrom(
    sockfd: std.posix.socket_t,
    buf: []u8,
    flags: u32,
    src_addr: ?*std.posix.sockaddr,
    addrlen: ?*std.posix.socklen_t,
) RecvFromError!usize {
    while (true) {
        const rc = std.posix.system.recvfrom(sockfd, buf.ptr, buf.len, flags, src_addr, addrlen);
        if (builtin.os.tag == .windows) {
            if (rc == std.os.windows.ws2_32.SOCKET_ERROR) {
                switch (std.os.windows.ws2_32.WSAGetLastError()) {
                    .NOTINITIALISED => unreachable,
                    .ECONNRESET => return error.ConnectionResetByPeer,
                    .EINVAL => return error.SocketNotBound,
                    .EMSGSIZE => return error.MessageOversize,
                    .ENETDOWN => return error.NetworkDown,
                    .ENOTCONN => return error.SocketUnconnected,
                    .EWOULDBLOCK => return error.WouldBlock,
                    .ETIMEDOUT => return error.Timeout,
                    // TODO: handle more errors
                    else => |err| return std.os.windows.unexpectedWSAError(err),
                }
            } else {
                return @intCast(rc);
            }
        } else {
            switch (std.posix.errno(rc)) {
                .SUCCESS => return @intCast(rc),
                .BADF => unreachable, // always a race condition
                .FAULT => unreachable,
                .INVAL => unreachable,
                .NOTCONN => return error.SocketUnconnected,
                .NOTSOCK => unreachable,
                .INTR => continue,
                .AGAIN => return error.WouldBlock,
                .NOMEM => return error.SystemResources,
                .CONNREFUSED => return error.ConnectionRefused,
                .CONNRESET => return error.ConnectionResetByPeer,
                .TIMEDOUT => return error.Timeout,
                .PIPE => return error.BrokenPipe,
                else => |err| return std.posix.unexpectedErrno(err),
            }
        }
    }
}

fn setBlocking(s: std.posix.socket_t, blocking: bool) !void {
    if (.windows == builtin.os.tag) {
        var nonblocking: u32 = if (blocking) 0 else 1;
        if (std.os.windows.ws2_32.ioctlsocket(s, std.os.windows.ws2_32.FIONBIO, &nonblocking) != 0) {
            return error.SocketError;
        }
    } else {
        var flags = try fcntl(s, std.posix.F.GETFL, 0);

        if (flags == -1) {
            return error.SocketError;
        }

        if (blocking) {
            flags &= ~@as(usize, std.os.linux.SOCK.NONBLOCK);
        } else {
            flags |= std.os.linux.SOCK.NONBLOCK;
        }

        _ = try fcntl(s, std.posix.F.SETFL, flags);
    }
}

const FcntlError = error{
    PermissionDenied,
    FileBusy,
    ProcessFdQuotaExceeded,
    Locked,
    DeadLock,
    LockedRegionLimitExceeded,
} || std.Io.UnexpectedError;

fn fcntl(fd: std.posix.fd_t, cmd: i32, arg: usize) FcntlError!usize {
    while (true) {
        const rc = std.posix.system.fcntl(fd, cmd, arg);
        switch (std.posix.errno(rc)) {
            .SUCCESS => return @intCast(rc),
            .INTR => continue,
            .AGAIN, .ACCES => return error.Locked,
            .BADF => unreachable,
            .BUSY => return error.FileBusy,
            .INVAL => unreachable, // invalid parameters
            .PERM => return error.PermissionDenied,
            .MFILE => return error.ProcessFdQuotaExceeded,
            .NOTDIR => unreachable, // invalid parameter
            .DEADLK => return error.DeadLock,
            .NOLCK => return error.LockedRegionLimitExceeded,
            else => |err| return std.posix.unexpectedErrno(err),
        }
    }
}

fn waitWithTimeout(
    socket: std.posix.socket_t,
    timeout: c_int,
    comptime event_kind: enum { in, out },
) !void {
    if (.windows == builtin.os.tag) {
        const POLL = std.os.windows.ws2_32.POLL;
        const event = switch (event_kind) {
            .in => POLL.IN,
            .out => POLL.OUT,
        };

        var fds = [_]std.os.windows.ws2_32.pollfd{.{
            .fd = socket,
            .events = event,
            .revents = 0,
        }};

        const ret = std.os.windows.ws2_32.WSAPoll(&fds, fds.len, timeout);

        if (ret <= 0) {
            return error.SocketError;
        } else if ((fds[0].revents & (POLL.PRI | POLL.HUP | POLL.ERR)) != 0) {
            return error.SocketError;
        } else if ((fds[0].revents & event) != event) {
            return error.SocketError;
        }
    } else {
        const POLL = std.os.linux.POLL;
        const event = switch (event_kind) {
            .in => POLL.IN,
            .out => POLL.OUT,
        };

        var fds = [_]std.posix.pollfd{.{
            .fd = socket,
            .events = event,
            .revents = 0,
        }};

        const ret = try std.posix.poll(&fds, timeout);

        if (ret == 0) {
            return error.SocketError;
        } else if ((fds[0].revents & (POLL.PRI | POLL.HUP | POLL.ERR)) != 0) {
            return error.SocketError;
        } else if ((fds[0].revents & event) != event) {
            return error.SocketError;
        }
    }
}

fn connectWithTimeout(
    socket: std.posix.socket_t,
    address: *const std.Io.net.IpAddress,
    timeout: c_int,
) !void {
    if (0 != timeout) {
        try setBlocking(socket, false);
    }

    var storage: PosixAddress = undefined;
    const addr_len = addressToPosix(address, &storage);

    connect(socket, &storage.any, addr_len) catch |err| switch (err) {
        error.WouldBlock => {},
        else => |e| return e,
    };

    if (0 != timeout) {
        try waitWithTimeout(socket, timeout, .out);

        try setBlocking(socket, true);
    }
}

fn connect(sock: std.posix.socket_t, sock_addr: *const std.posix.sockaddr, len: std.posix.socklen_t) !void {
    while (true) {
        switch (std.posix.errno(std.posix.system.connect(sock, sock_addr, len))) {
            .SUCCESS => return,
            .ACCES => return error.AccessDenied,
            .PERM => return error.PermissionDenied,
            .ADDRNOTAVAIL => return error.AddressUnavailable,
            .AFNOSUPPORT => return error.AddressFamilyUnsupported,
            .AGAIN, .INPROGRESS => return error.WouldBlock,
            .ALREADY => return error.ConnectionPending,
            .BADF => unreachable, // sockfd is not a valid open file descriptor.
            .CONNREFUSED => return error.ConnectionRefused,
            .CONNRESET => return error.ConnectionResetByPeer,
            .FAULT => unreachable, // The socket structure address is outside the user's address space.
            .INTR => continue,
            .ISCONN => @panic("AlreadyConnected"), // The socket is already connected.
            .HOSTUNREACH => return error.NetworkUnreachable,
            .NETUNREACH => return error.NetworkUnreachable,
            .NOTSOCK => unreachable, // The file descriptor sockfd does not refer to a socket.
            .PROTOTYPE => unreachable, // The socket type does not support the requested communications protocol.
            .TIMEDOUT => return error.Timeout,
            .NOENT => return error.FileNotFound, // Returned when socket is AF.UNIX and the given path does not exist.
            .CONNABORTED => unreachable, // Tried to reuse socket that previously received error.ConnectionRefused.
            else => |err| return std.posix.unexpectedErrno(err),
        }
    }
}

pub const PosixAddress = extern union {
    any: std.posix.sockaddr,
    in: std.posix.sockaddr.in,
    in6: std.posix.sockaddr.in6,
};

fn addressToPosix(a: *const std.Io.net.IpAddress, storage: *PosixAddress) std.posix.socklen_t {
    return switch (a.*) {
        .ip4 => |ip4| {
            storage.in = address4ToPosix(ip4);
            return @sizeOf(std.posix.sockaddr.in);
        },
        .ip6 => |*ip6| {
            storage.in6 = address6ToPosix(ip6);
            return @sizeOf(std.posix.sockaddr.in6);
        },
    };
}

fn address4ToPosix(a: std.Io.net.Ip4Address) std.posix.sockaddr.in {
    return .{
        .port = std.mem.nativeToBig(u16, a.port),
        .addr = @bitCast(a.bytes),
    };
}

fn address6ToPosix(a: *const std.Io.net.Ip6Address) std.posix.sockaddr.in6 {
    return .{
        .port = std.mem.nativeToBig(u16, a.port),
        .flowinfo = a.flow,
        .addr = a.bytes,
        .scope_id = a.interface.index,
    };
}
