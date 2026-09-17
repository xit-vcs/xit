const std = @import("std");
const hash = @import("../../hash.zig");

pub fn hashName(comptime hash_kind: hash.HashKind) []const u8 {
    return switch (hash_kind) {
        .sha1 => "sha1",
        .sha256 => "sha256",
    };
}

pub const ProtocolVersion = enum { v0, v1, v2 };

pub fn hasFeature(features: []const u8, name: []const u8) bool {
    var iter = std.mem.splitScalar(u8, features, ' ');
    while (iter.next()) |feature| {
        if (std.mem.startsWith(u8, feature, name) and
            (feature.len == name.len or feature[name.len] == '='))
            return true;
    }
    return false;
}

pub fn getFeatureValue(features: []const u8, name: []const u8) ?[]const u8 {
    var iter = std.mem.splitScalar(u8, features, ' ');
    while (iter.next()) |feature| {
        if (std.mem.startsWith(u8, feature, name) and
            feature.len > name.len and feature[name.len] == '=')
            return feature[name.len + 1 ..];
    }
    return null;
}

/// the version a client asked for in its GIT_PROTOCOL env value or
/// Git-Protocol header
pub fn parseProtocolVersion(value: ?[]const u8) ProtocolVersion {
    const git_protocol = value orelse return .v0;
    var version: ProtocolVersion = .v0;
    var iter = std.mem.splitScalar(u8, git_protocol, ':');
    while (iter.next()) |entry| {
        const pair = std.mem.trimStart(u8, entry, " ");
        if (std.mem.startsWith(u8, pair, "version=")) {
            const v = pair["version=".len..];
            if (std.mem.eql(u8, v, "2"))
                version = .v2
            else if (std.mem.eql(u8, v, "1") and version != .v2)
                version = .v1;
        }
    }
    return version;
}
