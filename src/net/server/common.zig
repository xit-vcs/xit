const std = @import("std");
const hash = @import("../../hash.zig");

pub fn hashName(comptime hash_kind: hash.HashKind) []const u8 {
    return switch (hash_kind) {
        .sha1 => "sha1",
        .sha256 => "sha256",
    };
}

pub const ProtocolVersion = enum { v0, v1, v2 };

pub fn parseBool(value: []const u8) bool {
    if (std.ascii.eqlIgnoreCase(value, "true") or
        std.ascii.eqlIgnoreCase(value, "yes") or
        std.ascii.eqlIgnoreCase(value, "on") or
        std.mem.eql(u8, value, "1"))
        return true;
    return false;
}

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

pub fn detectProtocolVersion(environ_map: *std.process.Environ.Map) ProtocolVersion {
    const git_protocol = environ_map.get("GIT_PROTOCOL") orelse return .v0;
    var version: ProtocolVersion = .v0;
    var iter = std.mem.splitScalar(u8, git_protocol, ':');
    while (iter.next()) |entry| {
        const value = std.mem.trimStart(u8, entry, " ");
        if (std.mem.startsWith(u8, value, "version=")) {
            const v = value["version=".len..];
            if (std.mem.eql(u8, v, "2"))
                version = .v2
            else if (std.mem.eql(u8, v, "1") and version != .v2)
                version = .v1;
        }
    }
    return version;
}
