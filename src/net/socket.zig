const std = @import("std");

pub const SocketStream = struct {
    io: std.Io,
    host: []const u8,
    port: u16,
    net_stream: ?std.Io.net.Stream,

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
            .net_stream = null,
        };
    }

    pub fn deinit(self: *SocketStream, allocator: std.mem.Allocator) void {
        allocator.free(self.host);
    }

    pub fn close(self: *SocketStream) !void {
        if (self.net_stream) |*s| {
            s.close(self.io);
            self.net_stream = null;
        }
    }

    pub fn read(
        self: *SocketStream,
        data: [*c]u8,
        len: usize,
    ) !usize {
        const stream = self.net_stream orelse return error.SocketUnconnected;
        var bufs: [1][]u8 = .{data[0..len]};
        return try self.io.vtable.netRead(self.io.userdata, stream.socket.handle, &bufs);
    }

    pub fn write(
        self: *SocketStream,
        data: [*c]const u8,
        len: usize,
    ) !usize {
        const stream = self.net_stream orelse return error.SocketUnconnected;
        const dummy: [1][]const u8 = .{""};
        return try self.io.vtable.netWrite(self.io.userdata, stream.socket.handle, data[0..len], &dummy, 0);
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
        self.net_stream = try address.connect(self.io, .{ .mode = .stream });
    }
};
