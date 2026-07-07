const std = @import("std");
const rf = @import("../ref.zig");
const net = @import("../net.zig");

pub const git_refspec_tags = "refs/tags/*:refs/tags/*";

pub fn validateName(ref_path: []const u8, is_glob: bool) bool {
    const ref = rf.Ref.initFromPath(ref_path, .head) orelse return false;
    if (is_glob) {
        var split_iter = std.mem.splitScalar(u8, ref.name, '/');
        while (split_iter.next()) |path_part| {
            if (!std.mem.eql(u8, "*", ref.name) and !rf.validateName(path_part)) {
                return false;
            }
        }
        return true;
    } else {
        return rf.validateName(ref.name);
    }
}

pub fn matches(target_ref_path: []const u8, source_ref_path: []const u8) bool {
    var target_iter = std.mem.splitScalar(u8, target_ref_path, '/');
    var source_iter = std.mem.splitScalar(u8, source_ref_path, '/');

    while (true) {
        const target_part_maybe = target_iter.next();
        const source_part_maybe = source_iter.next();

        if (target_part_maybe) |target_part| {
            if (source_part_maybe) |source_part| {
                if (std.mem.eql(u8, "*", target_part) or std.mem.eql(u8, target_part, source_part)) {
                    continue;
                } else {
                    return false;
                }
            } else {
                return false;
            }
        } else {
            if (source_part_maybe) |_| {
                return false;
            } else {
                return true;
            }
        }
    }
}

pub const RefSpec = struct {
    full: []u8,
    src: []u8,
    dst: []u8,
    direction: net.Direction,
    is_force: bool,
    is_glob: bool,

    pub fn init(allocator: std.mem.Allocator, input: []const u8, direction: net.Direction) !RefSpec {
        var self = RefSpec{
            .full = undefined,
            .src = undefined,
            .dst = undefined,
            .direction = direction,
            .is_force = false,
            .is_glob = false,
        };

        self.full = try allocator.dupe(u8, input);
        errdefer allocator.free(self.full);

        if (.push == direction and (std.mem.eql(u8, ":", input) or std.mem.eql(u8, "+:", input))) {
            self.src = try allocator.dupe(u8, "");
            errdefer allocator.free(self.src);
            self.dst = try allocator.dupe(u8, "");
            errdefer allocator.free(self.dst);
            return self;
        }

        var lhs = input;
        if (std.mem.startsWith(u8, lhs, "+")) {
            self.is_force = true;
            lhs = input[1..];
        }

        const rhs_maybe = if (std.mem.lastIndexOfScalar(u8, lhs, ':')) |idx| lhs[idx + 1 ..] else null;
        var is_glob = false;

        {
            var dst_set = false;

            if (rhs_maybe) |rhs| {
                if (rhs.len > 0 or .push == direction) {
                    is_glob = (rhs.len > 0 and null != std.mem.indexOfScalar(u8, rhs, '*'));
                    self.dst = try allocator.dupe(u8, rhs);
                    dst_set = true;
                }
            }

            if (!dst_set) {
                self.dst = try allocator.dupe(u8, "");
            }
        }
        errdefer allocator.free(self.dst);

        const llen = if (rhs_maybe) |rhs| lhs.len - rhs.len - 1 else lhs.len;
        if (llen > 0 and null != std.mem.indexOfScalar(u8, lhs[0..llen], '*')) {
            if ((null != rhs_maybe and !is_glob) or (null == rhs_maybe and .fetch == direction)) {
                return error.InvalidRefSpec;
            }
            is_glob = true;
        } else if (null != rhs_maybe and is_glob) {
            return error.InvalidRefSpec;
        }

        self.is_glob = is_glob;
        self.src = try allocator.dupe(u8, lhs[0..llen]);
        errdefer allocator.free(self.src);

        switch (direction) {
            .fetch => {
                if (self.src.len > 0 and !validateName(self.src, is_glob)) {
                    return error.InvalidRefSpec;
                }

                if (self.dst.len > 0 and !validateName(self.dst, is_glob)) {
                    return error.InvalidRefSpec;
                }
            },
            .push => {
                if (is_glob) {
                    if (self.src.len > 0 and !validateName(self.src, is_glob)) {
                        return error.InvalidRefSpec;
                    }
                }

                if (self.dst.len > 0) {
                    if (!validateName(self.dst, is_glob)) {
                        return error.InvalidRefSpec;
                    }
                } else {
                    if (!validateName(self.src, is_glob)) {
                        return error.InvalidRefSpec;
                    }

                    const src_dupe = try allocator.dupe(u8, self.src);
                    allocator.free(self.dst);
                    self.dst = src_dupe;
                }
            },
        }

        return self;
    }

    pub fn deinit(self: *RefSpec, allocator: std.mem.Allocator) void {
        allocator.free(self.full);
        allocator.free(self.src);
        allocator.free(self.dst);
    }

    pub fn dupe(self: *const RefSpec, allocator: std.mem.Allocator) !RefSpec {
        const full = try allocator.dupe(u8, self.full);
        errdefer allocator.free(full);
        const src = try allocator.dupe(u8, self.src);
        errdefer allocator.free(src);
        const dst = try allocator.dupe(u8, self.dst);
        errdefer allocator.free(dst);
        return .{
            .full = full,
            .src = src,
            .dst = dst,
            .direction = self.direction,
            .is_force = self.is_force,
            .is_glob = self.is_glob,
        };
    }

    pub fn normalize(self: *RefSpec, allocator: std.mem.Allocator) ![]const u8 {
        const src_ref_maybe = if (rf.Ref.initFromPath(self.src, .head)) |ref| blk: {
            if (ref.name.len == 0) {
                break :blk null;
            } else {
                break :blk ref;
            }
        } else {
            return error.InvalidRef;
        };

        var src_ref_path_buffer = [_]u8{0} ** rf.MAX_REF_CONTENT_SIZE;
        const src_ref_path = if (src_ref_maybe) |src_ref| try src_ref.toPath(&src_ref_path_buffer) else "";

        const dst_ref_maybe = if (rf.Ref.initFromPath(self.dst, .head)) |ref| blk: {
            if (ref.name.len == 0) {
                break :blk null;
            } else {
                break :blk ref;
            }
        } else {
            return error.InvalidRef;
        };

        var dst_ref_path_buffer = [_]u8{0} ** rf.MAX_REF_CONTENT_SIZE;
        const dst_ref_path = if (dst_ref_maybe) |dst_ref| try dst_ref.toPath(&dst_ref_path_buffer) else "";

        return try std.fmt.allocPrint(allocator, "{s}{s}:{s}", .{ if (self.is_force) "+" else "", src_ref_path, dst_ref_path });
    }
};

pub fn transform(allocator: std.mem.Allocator, out: *std.ArrayList(u8), spec: *const RefSpec, name: []const u8) !void {
    if (!matches(spec.src, name)) {
        return error.RefSpecDoesNotMatch;
    }

    if (spec.is_glob) {
        const from = spec.src;
        const to = spec.dst;

        const from_star_offset = std.mem.indexOfScalar(u8, from, '*') orelse return error.FromStarNotFound;
        const to_star_offset = std.mem.indexOfScalar(u8, to, '*') orelse return error.ToStarNotFound;

        const to_start = to[0..to_star_offset];
        const to_end = to[to_star_offset + 1 ..];

        const from_part_len = name[from_star_offset..].len - from[from_star_offset + 1 ..].len;
        const from_part = name[from_star_offset .. from_star_offset + from_part_len];

        out.clearAndFree(allocator);
        try out.appendSlice(allocator, to_start);
        try out.appendSlice(allocator, from_part);
        try out.appendSlice(allocator, to_end);
    } else {
        try out.appendSlice(allocator, spec.dst);
    }
}
