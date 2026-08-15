const std = @import("std");
const rp = @import("./repo.zig");
const hash = @import("./hash.zig");

pub const AddConfigInput = struct {
    name: []const u8,
    value: []const u8,
};

pub const RemoveConfigInput = struct {
    name: []const u8,
};

pub const ConfigCommand = union(enum) {
    list,
    add: AddConfigInput,
    remove: RemoveConfigInput,
};

pub fn Config(comptime repo_kind: rp.RepoKind, comptime repo_opts: rp.RepoOpts(repo_kind)) type {
    return struct {
        allocator: std.mem.Allocator,
        arena: *std.heap.ArenaAllocator,
        /// the global config with the repo's own config layered on top
        sections: Sections,
        /// just the repo's own config. this is what is written back to disk,
        /// so the global config is never copied into the repo.
        local_sections: Sections,

        pub fn init(
            state: rp.Repo(repo_kind, repo_opts).State(.read_only),
            io: std.Io,
            allocator: std.mem.Allocator,
        ) !Config(repo_kind, repo_opts) {
            var arena = try allocator.create(std.heap.ArenaAllocator);
            arena.* = std.heap.ArenaAllocator.init(allocator);
            errdefer {
                arena.deinit();
                allocator.destroy(arena);
            }

            var global_sections: Sections = .empty;

            // the global config is written by other tools, so unparsable lines
            // are skipped rather than making the repo unusable
            if (state.core.global_config_path) |global_config_path| open: {
                var global_file = std.Io.Dir.cwd().openFile(io, global_config_path, .{}) catch |err| switch (err) {
                    error.FileNotFound => break :open,
                    else => |e| return e,
                };
                defer global_file.close(io);

                try parseFile(repo_kind, repo_opts, true, global_file, io, allocator, arena.allocator(), &global_sections);
            }

            var local_sections: Sections = .empty;

            switch (repo_kind) {
                .git => {
                    var config_file = try state.core.repo_dir.createFile(io, "config", .{ .read = true, .truncate = false });
                    defer config_file.close(io);

                    try parseFile(repo_kind, repo_opts, false, config_file, io, allocator, arena.allocator(), &local_sections);
                },
                .xit => {
                    if (try state.extra.moment.getCursor(hash.hashInt(repo_opts.hash, "config"))) |config_cursor| {
                        var config_iter = try config_cursor.iterator();
                        while (try config_iter.next()) |*section_cursor| {
                            const section_kv_pair = try section_cursor.readKeyValuePair();
                            const section_name = try section_kv_pair.key_cursor.readBytesAlloc(arena.allocator(), repo_opts.max_read_size);

                            var variables = Variables.empty;

                            var var_iter = try section_kv_pair.value_cursor.iterator();
                            while (try var_iter.next()) |*var_cursor| {
                                const var_kv_pair = try var_cursor.readKeyValuePair();
                                const var_name = try var_kv_pair.key_cursor.readBytesAlloc(arena.allocator(), repo_opts.max_read_size);
                                const var_value = try var_kv_pair.value_cursor.readBytesAlloc(arena.allocator(), repo_opts.max_read_size);
                                try variables.put(arena.allocator(), var_name, var_value);
                            }

                            try local_sections.put(arena.allocator(), section_name, variables);
                        }
                    }
                },
            }

            var sections: Sections = .empty;
            try overlay(&sections, global_sections, arena.allocator());
            try overlay(&sections, local_sections, arena.allocator());

            return .{
                .allocator = allocator,
                .arena = arena,
                .sections = sections,
                .local_sections = local_sections,
            };
        }

        pub fn deinit(self: *Config(repo_kind, repo_opts)) void {
            self.arena.deinit();
            self.allocator.destroy(self.arena);
        }

        pub fn add(
            self: *Config(repo_kind, repo_opts),
            state: rp.Repo(repo_kind, repo_opts).State(.read_write),
            io: std.Io,
            input: AddConfigInput,
        ) !void {
            const last_dot_index = std.mem.lastIndexOfScalar(u8, input.name, '.') orelse return error.KeyDoesNotContainASection;

            // extract the parts of the config name
            var section_name_orig = input.name[0..last_dot_index];
            var subsection_name_orig_maybe: ?[]const u8 = null;
            if (std.mem.indexOfScalar(u8, section_name_orig, '.')) |dot_index| {
                subsection_name_orig_maybe = section_name_orig[dot_index + 1 ..];
                section_name_orig = section_name_orig[0..dot_index];
            }
            const var_name_orig = input.name[last_dot_index + 1 ..];

            // validate the section and var names
            for (&[_][]const u8{ section_name_orig, var_name_orig }) |name| {
                if (name.len == 0) return error.InvalidConfigName;
                for (name) |char| {
                    switch (char) {
                        'a'...'z', 'A'...'Z', '0'...'9', '-' => {},
                        else => return error.InvalidConfigName,
                    }
                }
            }

            const section_name_lower = try lowerAlloc(self.arena.allocator(), section_name_orig);
            const section_name = if (subsection_name_orig_maybe) |subsection_name|
                try std.fmt.allocPrint(self.arena.allocator(), "{s}.{s}", .{ section_name_lower, subsection_name })
            else
                section_name_lower;
            const var_name = try lowerAlloc(self.arena.allocator(), var_name_orig);
            const var_value = try self.arena.allocator().dupe(u8, input.value);

            for ([_]*Sections{ &self.local_sections, &self.sections }) |sections| {
                const variables = try sections.getOrPut(self.arena.allocator(), section_name);
                if (!variables.found_existing) {
                    variables.value_ptr.* = Variables.empty;
                }
                try variables.value_ptr.put(self.arena.allocator(), var_name, var_value);
            }

            switch (repo_kind) {
                .git => try self.write(state, io),
                .xit => {
                    const DB = rp.Repo(repo_kind, repo_opts).DB;

                    // add section name to config
                    const config_cursor = try state.extra.moment.putCursor(hash.hashInt(repo_opts.hash, "config"));
                    const config = try DB.SortedMap(.read_write).init(config_cursor);

                    // save the variable in the section
                    const section_cursor = try config.putCursor(section_name);
                    const section = try DB.SortedMap(.read_write).init(section_cursor);
                    try section.put(var_name, .{ .bytes = var_value });
                },
            }
        }

        pub fn remove(
            self: *Config(repo_kind, repo_opts),
            state: rp.Repo(repo_kind, repo_opts).State(.read_write),
            io: std.Io,
            input: RemoveConfigInput,
        ) !void {
            const last_dot_index = std.mem.lastIndexOfScalar(u8, input.name, '.') orelse return error.KeyDoesNotContainASection;

            const section_name = try self.arena.allocator().dupe(u8, input.name[0..last_dot_index]);
            const var_name = try self.arena.allocator().dupe(u8, input.name[last_dot_index + 1 ..]);

            // only the repo's own config can be removed. a variable that is
            // only in the global config is not considered to exist here.
            if (self.local_sections.getPtr(section_name)) |variables| {
                _ = variables.orderedRemove(var_name);
                if (variables.count() == 0) {
                    _ = self.local_sections.orderedRemove(section_name);
                }
            } else {
                return error.SectionDoesNotExist;
            }

            if (self.sections.getPtr(section_name)) |variables| {
                _ = variables.orderedRemove(var_name);
                if (variables.count() == 0) {
                    _ = self.sections.orderedRemove(section_name);
                }
            }

            switch (repo_kind) {
                .git => try self.write(state, io),
                .xit => {
                    const DB = rp.Repo(repo_kind, repo_opts).DB;
                    const config_cursor = try state.extra.moment.putCursor(hash.hashInt(repo_opts.hash, "config"));
                    const config = try DB.SortedMap(.read_write).init(config_cursor);
                    if (!self.local_sections.contains(section_name)) {
                        _ = try config.remove(section_name);
                    } else {
                        const section_cursor = try config.putCursor(section_name);
                        const section = try DB.SortedMap(.read_write).init(section_cursor);
                        _ = try section.remove(var_name);
                    }
                },
            }
        }

        fn write(self: *Config(.git, repo_opts), state: rp.Repo(.git, repo_opts).State(.read_write), io: std.Io) !void {
            const lock_file = state.extra.lock_file_maybe orelse return error.NoLockFile;
            try io.vtable.fileSeekTo(io.userdata, lock_file, 0);
            try lock_file.setLength(io, 0); // truncate file in case this method is called multiple times

            for (self.local_sections.keys(), self.local_sections.values()) |section_name, variables| {
                // if the section name has periods, put everything after the first period in quotes
                const section_line = if (std.mem.indexOfScalar(u8, section_name, '.')) |index| blk: {
                    const subsection_name = try escapeStr(self.allocator, section_name[index + 1 ..]);
                    defer self.allocator.free(subsection_name);
                    break :blk try std.fmt.allocPrint(self.allocator, "[{s} \"{s}\"]\n", .{ section_name[0..index], subsection_name });
                } else try std.fmt.allocPrint(self.allocator, "[{s}]\n", .{section_name});
                defer self.allocator.free(section_line);
                try lock_file.writeStreamingAll(io, section_line);

                for (variables.keys(), variables.values()) |name, value| {
                    const var_line = try std.fmt.allocPrint(self.allocator, "\t{s} = {s}\n", .{ name, value });
                    defer self.allocator.free(var_line);
                    try lock_file.writeStreamingAll(io, var_line);
                }
            }
        }
    };
}

/// returns the path of the global config file, or null if there isn't one
pub fn globalConfigPath(io: std.Io, allocator: std.mem.Allocator, environ_map: *std.process.Environ.Map) !?[]const u8 {
    if (environ_map.get("GIT_CONFIG_GLOBAL")) |path| {
        // git uses this value to mean the global config should be skipped
        if (std.mem.eql(u8, path, "/dev/null")) return null;
        return try allocator.dupe(u8, path);
    }

    const home_path_maybe = environ_map.get("HOME");

    // the home config takes precedence over the xdg one
    if (home_path_maybe) |home_path| {
        const path = try std.fs.path.join(allocator, &.{ home_path, ".gitconfig" });
        if (try fileExists(io, path)) return path;
        allocator.free(path);
    }

    const xdg_path = if (environ_map.get("XDG_CONFIG_HOME")) |xdg_path|
        try allocator.dupe(u8, xdg_path)
    else if (home_path_maybe) |home_path|
        try std.fs.path.join(allocator, &.{ home_path, ".config" })
    else
        return null;
    defer allocator.free(xdg_path);

    const path = try std.fs.path.join(allocator, &.{ xdg_path, "git", "config" });
    if (try fileExists(io, path)) return path;
    allocator.free(path);

    return null;
}

fn fileExists(io: std.Io, path: []const u8) !bool {
    std.Io.Dir.cwd().access(io, path, .{}) catch |err| switch (err) {
        error.FileNotFound => return false,
        else => |e| return e,
    };
    return true;
}

pub const Variables = std.StringArrayHashMapUnmanaged([]const u8);
pub const Sections = std.StringArrayHashMapUnmanaged(Variables);

pub fn parseBool(value: []const u8) bool {
    if (std.ascii.eqlIgnoreCase(value, "true") or
        std.ascii.eqlIgnoreCase(value, "yes") or
        std.ascii.eqlIgnoreCase(value, "on") or
        std.mem.eql(u8, value, "1"))
        return true;
    return false;
}

/// categories of characters parsed in the config file
const CharKind = enum {
    whitespace,
    comment,
    open_bracket,
    close_bracket,
    equals,
    quote,
    symbol,

    fn init(rune: []const u8) CharKind {
        return if (rune.len == 1)
            switch (rune[0]) {
                ' ', '\t' => .whitespace,
                '#' => .comment,
                '[' => .open_bracket,
                ']' => .close_bracket,
                '=' => .equals,
                '"' => .quote,
                else => .symbol,
            }
        else
            .symbol;
    }
};

/// represents a line fully parsed from the config file
const ParsedLine = union(enum) {
    empty,
    section_header: []const u8,
    variable: struct {
        name: []const u8,
        value: []const u8,
    },
    invalid,

    const section_header_pattern = [_]CharKind{
        .open_bracket,
        .symbol,
        .close_bracket,
    };

    const extended_section_header_pattern = [_]CharKind{
        .open_bracket,
        .symbol,
        .quote,
        .close_bracket,
    };

    const variable_pattern = [_]CharKind{
        .symbol,
        .equals,
        .symbol,
    };

    fn init(allocator: std.mem.Allocator, arena_allocator: std.mem.Allocator, char_kinds: []CharKind, tokens: []const []const u8) !ParsedLine {
        if (char_kinds.len == 0) {
            return .empty;
        } else if (std.mem.eql(CharKind, &section_header_pattern, char_kinds)) {
            return .{ .section_header = try lowerAlloc(arena_allocator, tokens[1]) };
        } else if (std.mem.eql(CharKind, &extended_section_header_pattern, char_kinds)) {
            // extended section headers look like this:
            // [branch "master"]
            // ...and they must be represented in memory like this:
            // branch.master
            const subsection_name = try unescapeStr(allocator, tokens[2][1 .. tokens[2].len - 1]);
            defer allocator.free(subsection_name);
            const section_name = try lowerAlloc(allocator, tokens[1]);
            defer allocator.free(section_name);
            return .{ .section_header = try std.fmt.allocPrint(arena_allocator, "{s}.{s}", .{ section_name, subsection_name }) };
        } else if (std.mem.startsWith(CharKind, char_kinds, &variable_pattern)) {
            const name = try lowerAlloc(arena_allocator, tokens[0]);
            // variables can have multiple symbols after the equals,
            // so we check with startsWith and join the tokens
            if (tokens[2..].len > 1) {
                return .{ .variable = .{ .name = name, .value = try std.mem.join(arena_allocator, " ", tokens[2..]) } };
            } else {
                return .{ .variable = .{ .name = name, .value = tokens[2] } };
            }
        } else {
            return .invalid;
        }
    }
};

/// reads a config file in git's format into `sections`. section and variable
/// names are lower-cased, because that is how they are looked up. subsection
/// names keep their case. if `skip_invalid_lines` is true, lines that fail to
/// parse are ignored rather than causing an error.
fn parseFile(
    comptime repo_kind: rp.RepoKind,
    comptime repo_opts: rp.RepoOpts(repo_kind),
    comptime skip_invalid_lines: bool,
    config_file: std.Io.File,
    io: std.Io,
    allocator: std.mem.Allocator,
    arena_allocator: std.mem.Allocator,
    sections: *Sections,
) !void {
    var current_section_name_maybe: ?[]const u8 = null;
    var current_variables = Variables.empty;

    var reader_buffer = [_]u8{0} ** repo_opts.buffer_size;
    var reader = config_file.reader(io, &reader_buffer);

    // for each line...
    while (reader.interface.peekByte()) |_| {
        var line_buffer = [_]u8{0} ** repo_opts.max_read_size;
        var line_writer = std.Io.Writer.fixed(&line_buffer);
        const size = try reader.interface.streamDelimiterEnding(&line_writer, '\n');
        const line = line_buffer[0..size];

        // skip delimiter
        if (reader.interface.bufferedLen() > 0) {
            reader.interface.toss(1);
        }

        const text = try std.unicode.Utf8View.init(line);
        var iter = text.iterator();
        var next_cursor: usize = 0;

        var token_kinds: std.ArrayList(CharKind) = .empty;
        defer token_kinds.deinit(allocator);

        var token_ranges: std.ArrayList(struct { start: usize, end: usize }) = .empty;
        defer token_ranges.deinit(allocator);

        var current_token_maybe: ?struct { kind: CharKind, start: usize } = null;

        // for each codepoint...
        while (iter.nextCodepointSlice()) |rune| {
            const char_kind = CharKind.init(rune);

            const cursor = next_cursor;
            next_cursor += rune.len;

            if (current_token_maybe) |*current_token| {
                if (current_token.kind == .quote and std.mem.eql(u8, "\\", rune)) {
                    // the next character is escaped, so skip it
                    if (iter.nextCodepointSlice()) |next_rune| {
                        next_cursor += next_rune.len;
                    } else {
                        return error.InvalidEscapeInString;
                    }
                    continue;
                } else if (current_token.kind == .quote and char_kind == .quote) {
                    // the quote terminated, so save the current token
                    try token_kinds.append(allocator, current_token.kind);
                    try token_ranges.append(allocator, .{ .start = current_token.start, .end = next_cursor });
                    current_token_maybe = null;
                    continue;
                } else if (current_token.kind == char_kind or current_token.kind == .comment or current_token.kind == .quote) {
                    // this rune goes in the current token because either
                    // its char kind is the same, or it's a comment/quote
                    // (comments/quotes consume subsequent chars)
                    continue;
                } else {
                    switch (current_token.kind) {
                        .whitespace, .comment => {},
                        else => {
                            // the char kind changed, so save the current token
                            try token_kinds.append(allocator, current_token.kind);
                            try token_ranges.append(allocator, .{ .start = current_token.start, .end = cursor });
                        },
                    }
                }
            }

            // change the current token. this happens if the char kind changed,
            // or if current token is null (the very beginning of the line)
            current_token_maybe = .{ .kind = char_kind, .start = cursor };
        }

        // add the last token if necessary
        if (current_token_maybe) |current_token| {
            switch (current_token.kind) {
                .whitespace, .comment => {},
                else => {
                    try token_kinds.append(allocator, current_token.kind);
                    try token_ranges.append(allocator, .{ .start = current_token.start, .end = next_cursor });
                },
            }
        }

        // get all the tokens from the line using the ranges
        var tokens: std.ArrayList([]const u8) = .empty;
        for (token_ranges.items) |range| {
            try tokens.append(arena_allocator, try arena_allocator.dupe(u8, line[range.start..range.end]));
        }

        // parse the lines and update the sections/variables
        const parsed_line = try ParsedLine.init(allocator, arena_allocator, token_kinds.items, tokens.items);
        switch (parsed_line) {
            .empty => {},
            .section_header => |section_header| {
                if (current_section_name_maybe) |current_section_name| {
                    try sections.put(arena_allocator, current_section_name, current_variables);
                    current_variables = Variables.empty;
                }
                current_section_name_maybe = section_header;
            },
            .variable => |variable| {
                try current_variables.put(arena_allocator, variable.name, variable.value);
            },
            .invalid => if (!skip_invalid_lines) return error.InvalidLine,
        }
    } else |err| switch (err) {
        error.EndOfStream => {},
        else => |e| return e,
    }

    // add the last section if necessary
    if (current_section_name_maybe) |current_section_name| {
        try sections.put(arena_allocator, current_section_name, current_variables);
    }
}

/// copies everything in `src` over `dest`, so variables in `src` win.
fn overlay(dest: *Sections, src: Sections, arena_allocator: std.mem.Allocator) !void {
    for (src.keys(), src.values()) |section_name, variables| {
        const entry = try dest.getOrPut(arena_allocator, section_name);
        if (!entry.found_existing) {
            entry.value_ptr.* = Variables.empty;
        }
        for (variables.keys(), variables.values()) |var_name, var_value| {
            try entry.value_ptr.put(arena_allocator, var_name, var_value);
        }
    }
}

fn lowerAlloc(allocator: std.mem.Allocator, str: []const u8) ![]u8 {
    const buffer = try allocator.alloc(u8, str.len);
    return std.ascii.lowerString(buffer, str);
}

fn escapeChar(char: u8) ?u8 {
    return switch (char) {
        '"', '\'' => char,
        '\n' => 'n',
        '\r' => 'r',
        '\t' => 't',
        else => null,
    };
}

fn unescapeChar(char: u8) ?u8 {
    return switch (char) {
        '"', '\'' => char,
        'n' => '\n',
        'r' => '\r',
        't' => '\t',
        else => null,
    };
}

fn escapeStr(allocator: std.mem.Allocator, str: []const u8) ![]u8 {
    var arr: std.ArrayList(u8) = .empty;
    errdefer arr.deinit(allocator);
    for (str) |ch| {
        if (escapeChar(ch)) |esc_ch| {
            try arr.append(allocator, '\\');
            try arr.append(allocator, esc_ch);
        } else {
            try arr.append(allocator, ch);
        }
    }
    return try arr.toOwnedSlice(allocator);
}

fn unescapeStr(allocator: std.mem.Allocator, str: []const u8) ![]u8 {
    var arr: std.ArrayList(u8) = .empty;
    errdefer arr.deinit(allocator);
    var i: usize = 0;
    while (i < str.len) {
        const char = str[i];
        if (char == '\\') {
            const next_char = if (i + 1 < str.len) str[i + 1] else return error.InvalidEscapeInString;
            try arr.append(allocator, unescapeChar(next_char) orelse return error.InvalidEscapeInString);
            i += 1;
        } else {
            try arr.append(allocator, char);
        }
        i += 1;
    }
    return try arr.toOwnedSlice(allocator);
}

pub const RemoteConfig = struct {
    allocator: std.mem.Allocator,
    arena: *std.heap.ArenaAllocator,
    sections: Sections,

    pub fn init(
        comptime repo_kind: rp.RepoKind,
        comptime repo_opts: rp.RepoOpts(repo_kind),
        config: *Config(repo_kind, repo_opts),
        allocator: std.mem.Allocator,
    ) !RemoteConfig {
        var arena = try allocator.create(std.heap.ArenaAllocator);
        arena.* = std.heap.ArenaAllocator.init(allocator);
        errdefer {
            arena.deinit();
            allocator.destroy(arena);
        }

        var sections: Sections = .empty;

        const prefix = "remote.";

        for (config.sections.keys(), config.sections.values()) |section_name, variables| {
            if (std.mem.startsWith(u8, section_name, prefix)) {
                const remote_name = try arena.allocator().dupe(u8, section_name[prefix.len..]);

                var remote_variables = Variables.empty;
                for (variables.keys(), variables.values()) |key, val| {
                    const remote_key = try arena.allocator().dupe(u8, key);
                    const remote_val = try arena.allocator().dupe(u8, val);
                    try remote_variables.put(arena.allocator(), remote_key, remote_val);
                }

                try sections.put(arena.allocator(), remote_name, remote_variables);
            }
        }

        return .{
            .allocator = allocator,
            .arena = arena,
            .sections = sections,
        };
    }

    pub fn deinit(self: *RemoteConfig) void {
        self.arena.deinit();
        self.allocator.destroy(self.arena);
    }
};
