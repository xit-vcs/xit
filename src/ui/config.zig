const std = @import("std");
const xitui = @import("xitui");
const wgt = xitui.widget;
const layout = xitui.layout;
const inp = xitui.input;
const Grid = xitui.grid.Grid;
const Focus = xitui.focus.Focus;
const rp = @import("../repo.zig");
const hash = @import("../hash.zig");
const cfg = @import("../config.zig");

pub fn ConfigListItem(comptime Widget: type) type {
    return struct {
        box: wgt.Box(Widget),
        // only the focusable cells are tracked here
        nav_ids: [2]usize,
        // ids of the two action buttons hosted in the action Stack.
        remove_id: usize,
        update_id: usize,
        // bytes are owned by ConfigList's arena (same lifetime as this row)
        original_value: []const u8,

        pub const value_index: usize = 0;
        pub const action_index: usize = 1;

        // positions inside self.box.children
        const name_child_index: usize = 0;
        const value_child_index: usize = 1;
        const action_child_index: usize = 2;

        pub fn init(allocator: std.mem.Allocator, full_name: []const u8, value: []const u8) !ConfigListItem(Widget) {
            var box = try wgt.Box(Widget).init(allocator, .{ .border_style = null, .direction = .horiz });
            errdefer box.deinit(allocator);

            var nav_ids: [2]usize = undefined;

            {
                var name_text = try wgt.TextBox(Widget).init(allocator, full_name, .{ .border_style = .hidden, .wrap_kind = .none });
                errdefer name_text.deinit(allocator);
                // match the value TextInput's rendered width (visible_width 28 + 1-cell border on each side)
                try box.children.put(allocator, name_text.getFocus().id, .{ .widget = .{ .text_box = name_text }, .rect = null, .min_size = .{ .width = 30, .height = null } });
            }

            {
                var value_input = try wgt.TextInput(Widget).init(allocator, .{ .visible_width = 28 });
                errdefer value_input.deinit(allocator);
                value_input.getFocus().focusable = true;
                try value_input.setContent(allocator, value);
                value_input.cursor = 0;
                nav_ids[value_index] = value_input.getFocus().id;
                try box.children.put(allocator, value_input.getFocus().id, .{ .widget = .{ .text_input = value_input }, .rect = null, .min_size = null });
            }

            var remove_id: usize = undefined;
            var update_id: usize = undefined;
            {
                var stack = try wgt.Stack(Widget).init(allocator);
                errdefer stack.deinit(allocator);

                {
                    var remove_button = try wgt.TextBox(Widget).init(allocator, "remove", .{ .border_style = .single, .wrap_kind = .none });
                    errdefer remove_button.deinit(allocator);
                    remove_button.getFocus().focusable = true;
                    remove_id = remove_button.getFocus().id;
                    try stack.children.put(allocator, remove_id, .{ .text_box = remove_button });
                }

                {
                    var update_button = try wgt.TextBox(Widget).init(allocator, "update", .{ .border_style = .single, .wrap_kind = .none });
                    errdefer update_button.deinit(allocator);
                    update_button.getFocus().focusable = true;
                    update_id = update_button.getFocus().id;
                    try stack.children.put(allocator, update_id, .{ .text_box = update_button });
                }

                // start out showing "remove" — the value matches the original
                stack.getFocus().child_id = remove_id;

                nav_ids[action_index] = stack.getFocus().id;
                try box.children.put(allocator, stack.getFocus().id, .{ .widget = .{ .stack = stack }, .rect = null, .min_size = null });
            }

            var self = ConfigListItem(Widget){
                .box = box,
                .nav_ids = nav_ids,
                .remove_id = remove_id,
                .update_id = update_id,
                .original_value = value,
            };
            self.getFocus().child_id = nav_ids[value_index];
            return self;
        }

        pub fn deinit(self: *ConfigListItem(Widget), allocator: std.mem.Allocator) void {
            self.box.deinit(allocator);
        }

        pub fn build(self: *ConfigListItem(Widget), allocator: std.mem.Allocator, constraint: layout.Constraint, root_focus: *Focus) !void {
            self.clearGrid();
            // flip the action Stack between "remove" and "update" based on
            // whether the user has edited the value cell.
            const stack = &self.box.children.values()[action_child_index].widget.stack;
            stack.focus.child_id = if (self.isValueModified()) self.update_id else self.remove_id;
            try self.box.build(allocator, constraint, root_focus);
        }

        pub fn input(self: *ConfigListItem(Widget), allocator: std.mem.Allocator, key: inp.Key, root_focus: *Focus) !void {
            if (self.getFocus().child_id) |child_id| {
                const children = &self.box.children;
                if (children.getIndex(child_id)) |index| {
                    try children.values()[index].widget.input(allocator, key, root_focus);
                }
            }
        }

        pub fn indexOf(self: ConfigListItem(Widget), child_id: usize) ?usize {
            for (self.nav_ids, 0..) |id, i| {
                if (id == child_id) return i;
            }
            return null;
        }

        pub fn name(self: *const ConfigListItem(Widget)) []const u8 {
            return self.box.children.values()[name_child_index].widget.text_box.content;
        }

        pub fn valueInput(self: *ConfigListItem(Widget)) *wgt.TextInput(Widget) {
            return &self.box.children.values()[value_child_index].widget.text_input;
        }

        // compares the TextInput's current codepoints to original_value without
        // allocating a contiguous copy.
        pub fn isValueModified(self: *const ConfigListItem(Widget)) bool {
            const value_input = &self.box.children.values()[value_child_index].widget.text_input;
            var i: usize = 0;
            for (value_input.content.items) |cp| {
                if (i + cp.len > self.original_value.len) return true;
                if (!std.mem.eql(u8, cp, self.original_value[i..][0..cp.len])) return true;
                i += cp.len;
            }
            return i != self.original_value.len;
        }

        pub fn clearGrid(self: *ConfigListItem(Widget)) void {
            self.box.clearGrid();
        }

        pub fn getGrid(self: ConfigListItem(Widget)) ?Grid {
            return self.box.getGrid();
        }

        pub fn getFocus(self: *ConfigListItem(Widget)) *Focus {
            return self.box.getFocus();
        }
    };
}

pub fn ConfigAddListItem(comptime Widget: type) type {
    return struct {
        box: wgt.Box(Widget),
        nav_ids: [3]usize,

        pub const name_index: usize = 0;
        pub const value_index: usize = 1;
        pub const action_index: usize = 2;

        pub fn init(allocator: std.mem.Allocator) !ConfigAddListItem(Widget) {
            var box = try wgt.Box(Widget).init(allocator, .{ .border_style = null, .direction = .horiz });
            errdefer box.deinit(allocator);

            var nav_ids: [3]usize = undefined;

            {
                var name_input = try wgt.TextInput(Widget).init(allocator, .{ .visible_width = 28, .label = " name " });
                errdefer name_input.deinit(allocator);
                name_input.getFocus().focusable = true;
                nav_ids[name_index] = name_input.getFocus().id;
                try box.children.put(allocator, name_input.getFocus().id, .{ .widget = .{ .text_input = name_input }, .rect = null, .min_size = null });
            }

            {
                var value_input = try wgt.TextInput(Widget).init(allocator, .{ .visible_width = 28, .label = " value " });
                errdefer value_input.deinit(allocator);
                value_input.getFocus().focusable = true;
                nav_ids[value_index] = value_input.getFocus().id;
                try box.children.put(allocator, value_input.getFocus().id, .{ .widget = .{ .text_input = value_input }, .rect = null, .min_size = null });
            }

            {
                var add_button = try wgt.TextBox(Widget).init(allocator, "add", .{ .border_style = .single, .wrap_kind = .none });
                errdefer add_button.deinit(allocator);
                add_button.getFocus().focusable = true;
                nav_ids[action_index] = add_button.getFocus().id;
                try box.children.put(allocator, add_button.getFocus().id, .{ .widget = .{ .text_box = add_button }, .rect = null, .min_size = null });
            }

            var self = ConfigAddListItem(Widget){
                .box = box,
                .nav_ids = nav_ids,
            };
            self.getFocus().child_id = nav_ids[name_index];
            return self;
        }

        pub fn deinit(self: *ConfigAddListItem(Widget), allocator: std.mem.Allocator) void {
            self.box.deinit(allocator);
        }

        pub fn build(self: *ConfigAddListItem(Widget), allocator: std.mem.Allocator, constraint: layout.Constraint, root_focus: *Focus) !void {
            self.clearGrid();
            try self.box.build(allocator, constraint, root_focus);
        }

        pub fn input(self: *ConfigAddListItem(Widget), allocator: std.mem.Allocator, key: inp.Key, root_focus: *Focus) !void {
            if (self.getFocus().child_id) |child_id| {
                const children = &self.box.children;
                if (children.getIndex(child_id)) |index| {
                    try children.values()[index].widget.input(allocator, key, root_focus);
                }
            }
        }

        pub fn indexOf(self: ConfigAddListItem(Widget), child_id: usize) ?usize {
            for (self.nav_ids, 0..) |id, i| {
                if (id == child_id) return i;
            }
            return null;
        }

        pub fn nameInput(self: *ConfigAddListItem(Widget)) *wgt.TextInput(Widget) {
            return &self.box.children.values()[name_index].widget.text_input;
        }

        pub fn valueInput(self: *ConfigAddListItem(Widget)) *wgt.TextInput(Widget) {
            return &self.box.children.values()[value_index].widget.text_input;
        }

        pub fn clearInputs(self: *ConfigAddListItem(Widget), allocator: std.mem.Allocator) void {
            self.nameInput().clear(allocator);
            self.valueInput().clear(allocator);
        }

        pub fn clearGrid(self: *ConfigAddListItem(Widget)) void {
            self.box.clearGrid();
        }

        pub fn getGrid(self: ConfigAddListItem(Widget)) ?Grid {
            return self.box.getGrid();
        }

        pub fn getFocus(self: *ConfigAddListItem(Widget)) *Focus {
            return self.box.getFocus();
        }
    };
}

pub fn ConfigList(comptime Widget: type, comptime repo_kind: rp.RepoKind, comptime repo_opts: rp.RepoOpts(repo_kind)) type {
    return struct {
        box: wgt.Box(Widget),
        config: cfg.Config(repo_kind, repo_opts),
        arena: *std.heap.ArenaAllocator,
        repo: *rp.Repo(repo_kind, repo_opts),
        io: std.Io,
        // set by input() after a successful addConfig/removeConfig. build()
        // runs the actual UI refresh — destroying the old ConfigListItems
        // during build means root_focus.children is rebuilt in the same
        // pass, so no in-flight event can observe dangling Focus pointers.
        refresh_pending: bool,

        const add_idx: usize = 0;
        const scroll_idx: usize = 1;

        pub fn init(io: std.Io, allocator: std.mem.Allocator, repo: *rp.Repo(repo_kind, repo_opts)) !ConfigList(Widget, repo_kind, repo_opts) {
            var config = try repo.listConfig(io, allocator);
            errdefer config.deinit();

            const arena = try allocator.create(std.heap.ArenaAllocator);
            arena.* = std.heap.ArenaAllocator.init(allocator);
            errdefer {
                arena.deinit();
                allocator.destroy(arena);
            }

            var box = try wgt.Box(Widget).init(allocator, .{ .border_style = null, .direction = .vert });
            errdefer box.deinit(allocator);

            // add row at index 0 — always visible
            {
                var add_item = try ConfigAddListItem(Widget).init(allocator);
                errdefer add_item.deinit(allocator);
                try box.children.put(allocator, add_item.getFocus().id, .{ .widget = .{ .ui_config_add_list_item = add_item }, .rect = null, .min_size = null });
            }

            // scroll with the config items below
            {
                var inner_box = try wgt.Box(Widget).init(allocator, .{ .border_style = null, .direction = .vert });
                errdefer inner_box.deinit(allocator);

                try appendConfigItems(&inner_box, allocator, arena.allocator(), &config);

                var scroll = try wgt.Scroll(Widget).init(allocator, .{ .box = inner_box }, .{ .direction = .vert });
                errdefer scroll.deinit(allocator);
                if (inner_box.children.count() > 0) {
                    scroll.getFocus().child_id = inner_box.children.keys()[0];
                }

                try box.children.put(allocator, scroll.getFocus().id, .{ .widget = .{ .scroll = scroll }, .rect = null, .min_size = null });
            }

            // start focus on the add row
            box.focus.child_id = box.children.keys()[add_idx];

            return ConfigList(Widget, repo_kind, repo_opts){
                .box = box,
                .config = config,
                .arena = arena,
                .repo = repo,
                .io = io,
                .refresh_pending = false,
            };
        }

        pub fn deinit(self: *ConfigList(Widget, repo_kind, repo_opts), allocator: std.mem.Allocator) void {
            self.box.deinit(allocator);
            self.config.deinit();
            self.arena.deinit();
            allocator.destroy(self.arena);
        }

        pub fn build(self: *ConfigList(Widget, repo_kind, repo_opts), allocator: std.mem.Allocator, constraint: layout.Constraint, root_focus: *Focus) !void {
            if (self.refresh_pending) {
                self.refresh_pending = false;

                var new_config = try self.repo.listConfig(self.io, allocator);
                errdefer new_config.deinit();

                const inner_box = &self.box.children.values()[scroll_idx].widget.scroll.child.box;

                for (inner_box.children.values()) |*child| {
                    child.widget.deinit(allocator);
                }
                inner_box.children.clearAndFree(allocator);

                // the arena only held the previous "section.name" strings
                _ = self.arena.reset(.retain_capacity);

                try appendConfigItems(inner_box, allocator, self.arena.allocator(), &new_config);

                self.config.deinit();
                self.config = new_config;

                // focus on the add row
                const add_item = self.addItemPtr();
                try root_focus.setFocus(add_item.nav_ids[ConfigAddListItem(Widget).name_index]);

                const scroll = &self.box.children.values()[scroll_idx].widget.scroll;
                scroll.x = 0;
                scroll.y = 0;
                if (inner_box.children.count() > 0) {
                    inner_box.focus.child_id = inner_box.children.keys()[0];
                } else {
                    inner_box.focus.child_id = null;
                }
            }
            self.clearGrid();
            try self.box.build(allocator, constraint, root_focus);
        }

        pub fn input(self: *ConfigList(Widget, repo_kind, repo_opts), allocator: std.mem.Allocator, key: inp.Key, root_focus: *Focus) !void {
            const current_row = self.currentRowIndex() orelse return;
            const row_count = self.rowCount();

            // figure out which cell of the focused row is selected
            const cell = self.currentCell(current_row) orelse return;

            if (cell.col == cell.action_index) {
                const triggered = switch (key) {
                    .enter => true,
                    .mouse => |mouse| blk: {
                        if (mouse.action == .press and mouse.action.press == .left) {
                            if (root_focus.children.get(cell.child_id)) |entry| {
                                const r = entry.rect;
                                if (mouse.x >= r.x and mouse.y >= r.y and
                                    mouse.x < r.x + r.size.width and mouse.y < r.y + r.size.height)
                                {
                                    break :blk true;
                                }
                            }
                        }
                        break :blk false;
                    },
                    else => false,
                };
                if (triggered) {
                    // skip re-triggering until the pending refresh applies, so
                    // a queued double-click can't try to remove the same row
                    // twice (the widget tree still shows it until build runs).
                    if (self.refresh_pending) return;

                    if (current_row == 0) {
                        const add_item = self.addItemPtr();
                        const name = try add_item.nameInput().text(allocator);
                        defer allocator.free(name);
                        const value = try add_item.valueInput().text(allocator);
                        defer allocator.free(value);

                        // ignore empty names — addConfig wants a "section.name" key
                        if (name.len == 0) return;

                        try self.repo.addConfig(self.io, allocator, .{ .name = name, .value = value });
                        add_item.clearInputs(allocator);
                    } else {
                        const item = self.configItemPtr(current_row - 1) orelse return;
                        if (item.isValueModified()) {
                            // "update" path: addConfig acts as an upsert, so
                            // sending the same name with the new value writes
                            // it back to the repo's config.
                            const value = try item.valueInput().text(allocator);
                            defer allocator.free(value);
                            try self.repo.addConfig(self.io, allocator, .{ .name = item.name(), .value = value });
                        } else {
                            try self.repo.removeConfig(self.io, allocator, .{ .name = item.name() });
                        }
                    }
                    self.refresh_pending = true;
                    return;
                }
            }

            // text-editing keys go to the focused cell
            switch (key) {
                .codepoint, .arrow_left, .arrow_right, .home, .end, .delete, .backspace => {
                    if (current_row == 0) {
                        try self.addItemPtr().input(allocator, key, root_focus);
                    } else if (self.configItemPtr(current_row - 1)) |row| {
                        try row.input(allocator, key, root_focus);
                    }
                    return;
                },
                else => {},
            }

            var new_row = current_row;
            var new_col = cell.col;

            switch (key) {
                .arrow_up, .back_tab => {
                    if (new_col > 0) {
                        new_col -= 1;
                    } else if (new_row > 0) {
                        new_row -= 1;
                        new_col = self.rowColCount(new_row) -| 1;
                    }
                },
                .arrow_down, .tab => {
                    if (new_col + 1 < cell.col_count) {
                        new_col += 1;
                    } else if (new_row + 1 < row_count) {
                        new_row += 1;
                        new_col = 0;
                    }
                },
                .page_up => {
                    if (self.getGrid()) |grid| {
                        const half_count = (grid.size.height / 3) / 2;
                        new_row -|= half_count;
                    }
                },
                .page_down => {
                    if (self.getGrid()) |grid| {
                        if (row_count > 0) {
                            const half_count = (grid.size.height / 3) / 2;
                            new_row = @min(current_row + half_count, row_count - 1);
                        }
                    }
                },
                .mouse => |mouse| switch (mouse.action) {
                    .scroll => |dir| switch (dir) {
                        .up => new_row -|= 1,
                        .down => if (new_row + 1 < row_count) {
                            new_row += 1;
                        },
                    },
                    else => {},
                },
                else => {},
            }

            if (new_row != current_row or new_col != cell.col) {
                if (self.rowChildIdAt(new_row, new_col)) |target_id| {
                    try root_focus.setFocus(target_id);
                    // only scroll items need updateScroll; the add row is fixed
                    if (new_row != current_row and new_row > 0) self.updateScroll(new_row - 1);
                }
            }
        }

        // describes the focused cell within a row, without caring about
        // which row type it lives in.
        const Cell = struct {
            child_id: usize,
            col: usize,
            col_count: usize,
            action_index: usize,
        };

        fn currentCell(self: *ConfigList(Widget, repo_kind, repo_opts), current_row: usize) ?Cell {
            if (current_row == 0) {
                const row = self.addItemPtr();
                const id = row.box.focus.child_id orelse return null;
                const col = row.indexOf(id) orelse return null;
                return .{
                    .child_id = id,
                    .col = col,
                    .col_count = row.nav_ids.len,
                    .action_index = ConfigAddListItem(Widget).action_index,
                };
            }
            const row = self.configItemPtr(current_row - 1) orelse return null;
            const id = row.box.focus.child_id orelse return null;
            const col = row.indexOf(id) orelse return null;
            return .{
                .child_id = id,
                .col = col,
                .col_count = row.nav_ids.len,
                .action_index = ConfigListItem(Widget).action_index,
            };
        }

        pub fn clearGrid(self: *ConfigList(Widget, repo_kind, repo_opts)) void {
            self.box.clearGrid();
        }

        pub fn getGrid(self: ConfigList(Widget, repo_kind, repo_opts)) ?Grid {
            return self.box.getGrid();
        }

        pub fn getFocus(self: *ConfigList(Widget, repo_kind, repo_opts)) *Focus {
            return self.box.getFocus();
        }

        // returns the focused cell's index in row-major order
        pub fn getSelectedIndex(self: ConfigList(Widget, repo_kind, repo_opts)) ?usize {
            const current_row = self.currentRowIndex() orelse return null;
            if (current_row == 0) {
                const row = &self.box.children.values()[add_idx].widget.ui_config_add_list_item;
                const col_id = row.box.focus.child_id orelse return current_row * row.nav_ids.len;
                const col_idx = row.indexOf(col_id) orelse 0;
                return current_row * row.nav_ids.len + col_idx;
            }
            const inner_box = &self.box.children.values()[scroll_idx].widget.scroll.child.box;
            if ((current_row - 1) >= inner_box.children.count()) return null;
            const row = &inner_box.children.values()[current_row - 1].widget.ui_config_list_item;
            const col_id = row.box.focus.child_id orelse return current_row * row.nav_ids.len;
            const col_idx = row.indexOf(col_id) orelse 0;
            return current_row * row.nav_ids.len + col_idx;
        }

        // total number of rows: 1 (add) + the scroll's items.
        fn rowCount(self: *const ConfigList(Widget, repo_kind, repo_opts)) usize {
            const inner_box = &self.box.children.values()[scroll_idx].widget.scroll.child.box;
            return 1 + inner_box.children.count();
        }

        fn addItemPtr(self: *const ConfigList(Widget, repo_kind, repo_opts)) *ConfigAddListItem(Widget) {
            return &self.box.children.values()[add_idx].widget.ui_config_add_list_item;
        }

        fn configItemPtr(self: *const ConfigList(Widget, repo_kind, repo_opts), idx: usize) ?*ConfigListItem(Widget) {
            const inner_box = &self.box.children.values()[scroll_idx].widget.scroll.child.box;
            if (idx >= inner_box.children.count()) return null;
            return &inner_box.children.values()[idx].widget.ui_config_list_item;
        }

        fn rowColCount(self: *const ConfigList(Widget, repo_kind, repo_opts), row: usize) usize {
            if (row == 0) return self.addItemPtr().nav_ids.len;
            const item = self.configItemPtr(row - 1) orelse return 0;
            return item.nav_ids.len;
        }

        fn rowChildIdAt(self: *const ConfigList(Widget, repo_kind, repo_opts), row: usize, col: usize) ?usize {
            if (row == 0) {
                const r = self.addItemPtr();
                if (col >= r.nav_ids.len) return null;
                return r.nav_ids[col];
            }
            const r = self.configItemPtr(row - 1) orelse return null;
            if (col >= r.nav_ids.len) return null;
            return r.nav_ids[col];
        }

        // which row is currently focused
        fn currentRowIndex(self: *const ConfigList(Widget, repo_kind, repo_opts)) ?usize {
            const top_id = self.box.focus.child_id orelse return null;
            const add_id = self.box.children.keys()[add_idx];
            if (top_id == add_id) return 0;
            const inner_box = &self.box.children.values()[scroll_idx].widget.scroll.child.box;
            const item_id = inner_box.focus.child_id orelse return null;
            const item_idx = inner_box.children.getIndex(item_id) orelse return null;
            return 1 + item_idx;
        }

        fn updateScroll(self: *ConfigList(Widget, repo_kind, repo_opts), scroll_item_idx: usize) void {
            const scroll = &self.box.children.values()[scroll_idx].widget.scroll;
            const inner_box = &scroll.child.box;
            if (scroll_item_idx >= inner_box.children.count()) return;
            if (inner_box.children.values()[scroll_item_idx].rect) |rect| {
                scroll.scrollToRect(rect);
            }
        }

        fn appendConfigItems(
            inner_box: *wgt.Box(Widget),
            allocator: std.mem.Allocator,
            arena_allocator: std.mem.Allocator,
            config: *const cfg.Config(repo_kind, repo_opts),
        ) !void {
            for (config.sections.keys(), config.sections.values()) |section_name, variables| {
                for (variables.keys(), variables.values()) |name, value| {
                    const full_name = try std.fmt.allocPrint(arena_allocator, "{s}.{s}", .{ section_name, name });
                    var config_item = try ConfigListItem(Widget).init(allocator, full_name, value);
                    errdefer config_item.deinit(allocator);
                    try inner_box.children.put(allocator, config_item.getFocus().id, .{ .widget = .{ .ui_config_list_item = config_item }, .rect = null, .min_size = null });
                }
            }
        }
    };
}
