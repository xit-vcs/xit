const std = @import("std");

pub const PKT_LEN_SIZE = 4;
pub const LARGE_PACKET_MAX = 65520;
pub const LARGE_PACKET_DATA_MAX = LARGE_PACKET_MAX - PKT_LEN_SIZE;

pub fn pktLineHeader(len: usize) [4]u8 {
    var header: [4]u8 = undefined;
    var w: std.Io.Writer = .fixed(&header);
    w.print("{x:0>4}", .{len}) catch unreachable;
    return header;
}

pub fn writePktLine(writer: *std.Io.Writer, data: []const u8) std.Io.Writer.Error!void {
    const len = data.len + PKT_LEN_SIZE;
    try writer.writeAll(&pktLineHeader(len));
    try writer.writeAll(data);
    try writer.flush();
}

pub fn writePktLineFmt(writer: *std.Io.Writer, comptime fmt: []const u8, args: anytype) std.Io.Writer.Error!void {
    var buf: [LARGE_PACKET_MAX]u8 = undefined;
    var fixed: std.Io.Writer = .fixed(&buf);
    try fixed.print(fmt, args);
    try writePktLine(writer, fixed.buffered());
}

pub fn writePktFlush(writer: *std.Io.Writer) std.Io.Writer.Error!void {
    try writer.writeAll("0000");
    try writer.flush();
}

pub fn writePktDelim(writer: *std.Io.Writer) std.Io.Writer.Error!void {
    try writer.writeAll("0001");
    try writer.flush();
}

pub fn writePktLineSB(writer: *std.Io.Writer, band: u8, data: []const u8) std.Io.Writer.Error!void {
    const len = data.len + PKT_LEN_SIZE + 1;
    try writer.writeAll(&pktLineHeader(len));
    try writer.writeByte(band);
    try writer.writeAll(data);
    try writer.flush();
}

pub fn writePktLineSBFmt(writer: *std.Io.Writer, band: u8, comptime fmt: []const u8, args: anytype) std.Io.Writer.Error!void {
    var buf: [LARGE_PACKET_MAX]u8 = undefined;
    var fixed: std.Io.Writer = .fixed(&buf);
    try fixed.print(fmt, args);
    try writePktLineSB(writer, band, fixed.buffered());
}

pub fn sendSideband(writer: *std.Io.Writer, band: u8, data: []const u8) std.Io.Writer.Error!void {
    if (data.len == 0) return;

    const max_chunk = LARGE_PACKET_MAX - 5;
    var remaining = data;
    while (remaining.len > 0) {
        const n = @min(remaining.len, max_chunk);
        try writer.writeAll(&pktLineHeader(n + 5));
        try writer.writeByte(band);
        try writer.writeAll(remaining[0..n]);
        try writer.flush();
        remaining = remaining[n..];
    }
}

pub fn bufPktLineFmt(buf: *std.ArrayList(u8), allocator: std.mem.Allocator, comptime fmt: []const u8, args: anytype) !void {
    var tmp: [LARGE_PACKET_DATA_MAX]u8 = undefined;
    var fixed: std.Io.Writer = .fixed(&tmp);
    try fixed.print(fmt, args);
    const content = fixed.buffered();
    const len = content.len + PKT_LEN_SIZE;
    try buf.appendSlice(allocator, &pktLineHeader(len));
    try buf.appendSlice(allocator, content);
}

pub fn bufPktFlush(buf: *std.ArrayList(u8), allocator: std.mem.Allocator) !void {
    try buf.appendSlice(allocator, "0000");
}

pub fn readPktLine(reader: *std.Io.Reader, buf: []u8) !?[]const u8 {
    const header = try reader.takeArray(PKT_LEN_SIZE);
    const len = std.fmt.parseInt(usize, header, 16) catch return error.InvalidPktLineHeader;
    if (len == 0) return null; // flush
    if (len < PKT_LEN_SIZE) return error.InvalidPktLineLength;
    const data_len = len - PKT_LEN_SIZE;
    if (data_len > buf.len) return error.PktLineTooLong;
    try reader.readSliceAll(buf[0..data_len]);
    // chomp newline
    if (data_len > 0 and buf[data_len - 1] == '\n') return buf[0 .. data_len - 1];
    return buf[0..data_len];
}

pub const PktLineResult = union(enum) {
    data: []const u8,
    flush,
    delim,
    response_end,
    eof,
};

pub fn readPktLineEx(reader: *std.Io.Reader, buf: []u8) !PktLineResult {
    const header = reader.takeArray(PKT_LEN_SIZE) catch |err| switch (err) {
        error.EndOfStream => return .eof,
        else => |e| return e,
    };
    const len = std.fmt.parseInt(usize, header, 16) catch return error.InvalidPktLineHeader;
    if (len == 0) return .flush;
    if (len == 1) return .delim;
    if (len == 2) return .response_end;
    if (len < PKT_LEN_SIZE) return error.InvalidPktLineLength;
    const data_len = len - PKT_LEN_SIZE;
    if (data_len > buf.len) return error.PktLineTooLong;
    try reader.readSliceAll(buf[0..data_len]);
    // chomp newline
    if (data_len > 0 and buf[data_len - 1] == '\n') return .{ .data = buf[0 .. data_len - 1] };
    return .{ .data = buf[0..data_len] };
}
