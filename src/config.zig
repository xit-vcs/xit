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
        sections: std.StringArrayHashMap(Variables),

        const Variables = std.StringArrayHashMap([]const u8);

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

            var sections = std.StringArrayHashMap(Variables).init(arena.allocator());

            var current_section_name_maybe: ?[]const u8 = null;
            var current_variables = Variables.init(arena.allocator());

            switch (repo_kind) {
                .git => {
                    // categories of characters parsed in the config file
                    const CharKind = enum {
                        whitespace,
                        comment,
                        open_bracket,
                        close_bracket,
                        equals,
                        quote,
                        symbol,

                        fn init(rune: []const u8) @This() {
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

                    // represents a line fully parsed from the config file
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

                        fn init(inner_allocator: std.mem.Allocator, arena_ptr: *std.heap.ArenaAllocator, char_kinds: []CharKind, tokens: []const []const u8) !@This() {
                            if (char_kinds.len == 0) {
                                return .empty;
                            } else if (std.mem.eql(CharKind, &section_header_pattern, char_kinds)) {
                                return .{ .section_header = tokens[1] };
                            } else if (std.mem.eql(CharKind, &extended_section_header_pattern, char_kinds)) {
                                // extended section headers look like this:
                                // [branch "master"]
                                // ...and they must be represented in memory like this:
                                // branch.master
                                const subsection_name = try unescapeStr(inner_allocator, tokens[2][1 .. tokens[2].len - 1]);
                                defer inner_allocator.free(subsection_name);
                                return .{ .section_header = try std.fmt.allocPrint(arena_ptr.allocator(), "{s}.{s}", .{ tokens[1], subsection_name }) };
                            } else if (std.mem.startsWith(CharKind, char_kinds, &variable_pattern)) {
                                // variables can have multiple symbols after the equals,
                                // so we check with startsWith and join the tokens
                                if (tokens[2..].len > 1) {
                                    return .{ .variable = .{ .name = tokens[0], .value = try std.mem.join(arena_ptr.allocator(), " ", tokens[2..]) } };
                                } else {
                                    return .{ .variable = .{ .name = tokens[0], .value = tokens[2] } };
                                }
                            } else {
                                return .invalid;
                            }
                        }
                    };

                    var config_file = try state.core.repo_dir.createFile(io, "config", .{ .read = true, .truncate = false });
                    defer config_file.close(io);

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

                        var token_kinds = std.ArrayList(CharKind){};
                        defer token_kinds.deinit(allocator);

                        var token_ranges = std.ArrayList(struct { start: usize, end: usize }){};
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
                        var tokens = std.ArrayList([]const u8){};
                        for (token_ranges.items) |range| {
                            try tokens.append(arena.allocator(), try arena.allocator().dupe(u8, line[range.start..range.end]));
                        }

                        // parse the lines and update the sections/variables
                        const parsed_line = try ParsedLine.init(allocator, arena, token_kinds.items, tokens.items);
                        switch (parsed_line) {
                            .empty => {},
                            .section_header => |section_header| {
                                if (current_section_name_maybe) |current_section_name| {
                                    try sections.put(current_section_name, current_variables);
                                    current_variables = Variables.init(arena.allocator());
                                }
                                current_section_name_maybe = section_header;
                            },
                            .variable => |variable| {
                                try current_variables.put(variable.name, variable.value);
                            },
                            .invalid => return error.InvalidLine,
                        }
                    } else |err| switch (err) {
                        error.EndOfStream => {},
                        else => |e| return e,
                    }

                    // add the last section if necessary
                    if (current_section_name_maybe) |current_section_name| {
                        try sections.put(current_section_name, current_variables);
                    }
                },
                .xit => {
                    if (try state.extra.moment.getCursor(hash.hashInt(repo_opts.hash, "config"))) |config_cursor| {
                        var config_iter = try config_cursor.iterator();
                        while (try config_iter.next()) |*section_cursor| {
                            const section_kv_pair = try section_cursor.readKeyValuePair();
                            const section_name = try section_kv_pair.key_cursor.readBytesAlloc(arena.allocator(), repo_opts.max_read_size);

                            var variables = Variables.init(arena.allocator());

                            var var_iter = try section_kv_pair.value_cursor.iterator();
                            while (try var_iter.next()) |*var_cursor| {
                                const var_kv_pair = try var_cursor.readKeyValuePair();
                                const var_name = try var_kv_pair.key_cursor.readBytesAlloc(arena.allocator(), repo_opts.max_read_size);
                                const var_value = try var_kv_pair.value_cursor.readBytesAlloc(arena.allocator(), repo_opts.max_read_size);
                                try variables.put(var_name, var_value);
                            }

                            try sections.put(section_name, variables);
                        }
                    }
                },
            }

            return .{
                .allocator = allocator,
                .arena = arena,
                .sections = sections,
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

            const section_name_lower = try self.arena.allocator().alloc(u8, section_name_orig.len);
            _ = std.ascii.lowerString(section_name_lower, section_name_orig);
            const section_name = if (subsection_name_orig_maybe) |subsection_name|
                try std.fmt.allocPrint(self.arena.allocator(), "{s}.{s}", .{ section_name_lower, subsection_name })
            else
                section_name_lower;
            const var_name = try self.arena.allocator().alloc(u8, var_name_orig.len);
            _ = std.ascii.lowerString(var_name, var_name_orig);
            const var_value = try self.arena.allocator().dupe(u8, input.value);

            if (self.sections.getPtr(section_name)) |variables| {
                try variables.put(var_name, var_value);
            } else {
                var variables = Variables.init(self.arena.allocator());
                try variables.put(var_name, var_value);
                try self.sections.put(section_name, variables);
            }

            switch (repo_kind) {
                .git => try self.write(state, io),
                .xit => {
                    const config_name_set_cursor = try state.extra.moment.putCursor(hash.hashInt(repo_opts.hash, "config-name-set"));
                    const config_name_set = try rp.Repo(repo_kind, repo_opts).DB.HashSet(.read_write).init(config_name_set_cursor);

                    // store section name
                    const section_name_hash = hash.hashInt(repo_opts.hash, section_name);
                    var section_name_cursor = try config_name_set.putCursor(section_name_hash);
                    try section_name_cursor.writeIfEmpty(.{ .bytes = section_name });

                    // add section name to config
                    const config_cursor = try state.extra.moment.putCursor(hash.hashInt(repo_opts.hash, "config"));
                    const config = try rp.Repo(repo_kind, repo_opts).DB.HashMap(.read_write).init(config_cursor);
                    try config.putKey(section_name_hash, .{ .slot = section_name_cursor.slot() });

                    // store variable name
                    const var_name_hash = hash.hashInt(repo_opts.hash, var_name);
                    var var_name_cursor = try config_name_set.putCursor(var_name_hash);
                    try var_name_cursor.writeIfEmpty(.{ .bytes = var_name });

                    // add var name to config
                    const section_cursor = try config.putCursor(section_name_hash);
                    const section = try rp.Repo(repo_kind, repo_opts).DB.HashMap(.read_write).init(section_cursor);
                    try section.putKey(var_name_hash, .{ .slot = var_name_cursor.slot() });

                    // save the variable
                    try section.put(var_name_hash, .{ .bytes = var_value });
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
            if (self.sections.getPtr(section_name)) |variables| {
                _ = variables.orderedRemove(var_name);
                if (variables.count() == 0) {
                    _ = self.sections.orderedRemove(section_name);
                }
            } else {
                return error.SectionDoesNotExist;
            }

            switch (repo_kind) {
                .git => try self.write(state, io),
                .xit => {
                    const config_cursor = try state.extra.moment.putCursor(hash.hashInt(repo_opts.hash, "config"));
                    const config = try rp.Repo(repo_kind, repo_opts).DB.HashMap(.read_write).init(config_cursor);
                    if (!self.sections.contains(section_name)) {
                        _ = try config.remove(hash.hashInt(repo_opts.hash, section_name));
                    } else {
                        const section_cursor = try config.putCursor(hash.hashInt(repo_opts.hash, section_name));
                        const section = try rp.Repo(repo_kind, repo_opts).DB.HashMap(.read_write).init(section_cursor);
                        _ = try section.remove(hash.hashInt(repo_opts.hash, var_name));
                    }
                },
            }
        }

        fn write(self: *Config(.git, repo_opts), state: rp.Repo(.git, repo_opts).State(.read_write), io: std.Io) !void {
            const lock_file = state.extra.lock_file_maybe orelse return error.NoLockFile;
            try io.vtable.fileSeekTo(io.userdata, lock_file, 0);
            try lock_file.setLength(io, 0); // truncate file in case this method is called multiple times

            for (self.sections.keys(), self.sections.values()) |section_name, variables| {
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
            var arr = std.ArrayList(u8){};
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
            var arr = std.ArrayList(u8){};
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
    };
}

pub const RemoteConfig = struct {
    allocator: std.mem.Allocator,
    arena: *std.heap.ArenaAllocator,
    sections: std.StringArrayHashMap(Variables),

    const Variables = std.StringArrayHashMap([]const u8);

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

        var sections = std.StringArrayHashMap(Variables).init(arena.allocator());

        const prefix = "remote.";

        for (config.sections.keys(), config.sections.values()) |section_name, variables| {
            if (std.mem.startsWith(u8, section_name, prefix)) {
                const remote_name = try arena.allocator().dupe(u8, section_name[prefix.len..]);

                var remote_variables = Variables.init(arena.allocator());
                for (variables.keys(), variables.values()) |key, val| {
                    const remote_key = try arena.allocator().dupe(u8, key);
                    const remote_val = try arena.allocator().dupe(u8, val);
                    try remote_variables.put(remote_key, remote_val);
                }

                try sections.put(remote_name, remote_variables);
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
