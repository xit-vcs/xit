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

        pub fn init(allocator: std.mem.Allocator, full_name: []const u8, value: []const u8) !ConfigListItem(Widget) {
            var box = try wgt.Box(Widget).init(allocator, .{ .border_style = null, .direction = .horiz });
            errdefer box.deinit(allocator);

            var name_input = wgt.TextInput(Widget).init(allocator, .{ .visible_width = 28 });
            errdefer name_input.deinit(allocator);
            name_input.getFocus().focusable = true;
            try name_input.setContent(allocator, full_name);
            name_input.cursor = 0;
            try box.children.put(allocator, name_input.getFocus().id, .{ .widget = .{ .text_input = name_input }, .rect = null, .min_size = null });

            var value_input = wgt.TextInput(Widget).init(allocator, .{ .visible_width = 28 });
            errdefer value_input.deinit(allocator);
            value_input.getFocus().focusable = true;
            try value_input.setContent(allocator, value);
            value_input.cursor = 0;
            try box.children.put(allocator, value_input.getFocus().id, .{ .widget = .{ .text_input = value_input }, .rect = null, .min_size = null });

            var remove_button = try wgt.TextBox(Widget).init(allocator, "remove", .{ .border_style = .single, .wrap_kind = .none });
            errdefer remove_button.deinit(allocator);
            remove_button.getFocus().focusable = true;
            try box.children.put(allocator, remove_button.getFocus().id, .{ .widget = .{ .text_box = remove_button }, .rect = null, .min_size = null });

            var self = ConfigListItem(Widget){
                .box = box,
            };
            self.getFocus().child_id = box.children.keys()[0];
            return self;
        }

        pub fn deinit(self: *ConfigListItem(Widget), allocator: std.mem.Allocator) void {
            self.box.deinit(allocator);
        }

        pub fn build(self: *ConfigListItem(Widget), allocator: std.mem.Allocator, constraint: layout.Constraint, root_focus: *Focus) !void {
            self.clearGrid();
            try self.box.build(allocator, constraint, root_focus);
        }

        // forward keys to the currently focused cell; the surrounding
        // ConfigList owns up/down navigation between cells.
        pub fn input(self: *ConfigListItem(Widget), allocator: std.mem.Allocator, key: inp.Key, root_focus: *Focus) !void {
            if (self.getFocus().child_id) |child_id| {
                const children = &self.box.children;
                if (children.getIndex(child_id)) |index| {
                    try children.values()[index].widget.input(allocator, key, root_focus);
                }
            }
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

        pub fn init(allocator: std.mem.Allocator) !ConfigAddListItem(Widget) {
            var box = try wgt.Box(Widget).init(allocator, .{ .border_style = null, .direction = .horiz });
            errdefer box.deinit(allocator);

            var name_input = wgt.TextInput(Widget).init(allocator, .{ .visible_width = 28 });
            errdefer name_input.deinit(allocator);
            name_input.getFocus().focusable = true;
            try box.children.put(allocator, name_input.getFocus().id, .{ .widget = .{ .text_input = name_input }, .rect = null, .min_size = null });

            var value_input = wgt.TextInput(Widget).init(allocator, .{ .visible_width = 28 });
            errdefer value_input.deinit(allocator);
            value_input.getFocus().focusable = true;
            try box.children.put(allocator, value_input.getFocus().id, .{ .widget = .{ .text_input = value_input }, .rect = null, .min_size = null });

            var add_button = try wgt.TextBox(Widget).init(allocator, "add", .{ .border_style = .single, .wrap_kind = .none });
            errdefer add_button.deinit(allocator);
            add_button.getFocus().focusable = true;
            try box.children.put(allocator, add_button.getFocus().id, .{ .widget = .{ .text_box = add_button }, .rect = null, .min_size = null });

            var self = ConfigAddListItem(Widget){
                .box = box,
            };
            self.getFocus().child_id = box.children.keys()[0];
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

        // resets both TextInputs so the row is ready for the next entry.
        pub fn clearInputs(self: *ConfigAddListItem(Widget), allocator: std.mem.Allocator) void {
            self.box.children.values()[0].widget.text_input.clear(allocator);
            self.box.children.values()[1].widget.text_input.clear(allocator);
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

                var scroll = try wgt.Scroll(Widget).init(allocator, .{ .box = inner_box }, .vert);
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
                const add_item = &self.box.children.values()[add_idx].widget.ui_config_add_list_item;
                const name_input_id = add_item.box.children.values()[0].widget.text_input.getFocus().id;
                try root_focus.setFocus(name_input_id);

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
            const row_box = self.rowAtIndex(current_row) orelse return;
            const cols = &row_box.children;
            const col_count = cols.count();
            const col_id = row_box.focus.child_id orelse cols.keys()[0];
            const current_col = cols.getIndex(col_id) orelse 0;

            const action_col = col_count - 1;
            const triggered = current_col == action_col and switch (key) {
                .enter => true,
                .mouse => |mouse| mouse.action == .press and mouse.action.press == .left,
                else => false,
            };
            if (triggered) {
                // skip re-triggering until the pending refresh applies, so a
                // queued double-click can't try to remove the same row twice
                // (the widget tree still shows it until build runs).
                if (self.refresh_pending) return;

                if (current_row == 0) {
                    const add_item = &self.box.children.values()[add_idx].widget.ui_config_add_list_item;
                    const name_input = &add_item.box.children.values()[0].widget.text_input;
                    const value_input = &add_item.box.children.values()[1].widget.text_input;

                    const name = try name_input.text(allocator);
                    defer allocator.free(name);
                    const value = try value_input.text(allocator);
                    defer allocator.free(value);

                    // ignore empty names — addConfig wants a "section.name" key
                    if (name.len == 0) return;

                    try self.repo.addConfig(self.io, allocator, .{ .name = name, .value = value });
                    add_item.clearInputs(allocator);
                } else {
                    const inner_box = &self.box.children.values()[scroll_idx].widget.scroll.child.box;
                    const item = &inner_box.children.values()[current_row - 1].widget.ui_config_list_item;
                    const name_input = &item.box.children.values()[0].widget.text_input;
                    const name = try name_input.text(allocator);
                    defer allocator.free(name);

                    try self.repo.removeConfig(self.io, allocator, .{ .name = name });
                }
                self.refresh_pending = true;
                return;
            }

            // text-editing keys go to the focused cell
            switch (key) {
                .codepoint, .arrow_left, .arrow_right, .home, .end, .delete, .backspace => {
                    try cols.values()[current_col].widget.input(allocator, key, root_focus);
                    return;
                },
                else => {},
            }

            var new_row = current_row;
            var new_col = current_col;

            switch (key) {
                .arrow_up => {
                    if (new_col > 0) {
                        new_col -= 1;
                    } else if (new_row > 0) {
                        new_row -= 1;
                        if (self.rowAtIndex(new_row)) |prev_box| {
                            new_col = prev_box.children.count() -| 1;
                        }
                    }
                },
                .arrow_down => {
                    if (new_col + 1 < col_count) {
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

            if (new_row != current_row or new_col != current_col) {
                const target_box = self.rowAtIndex(new_row) orelse return;
                if (new_col >= target_box.children.count()) return;
                try root_focus.setFocus(target_box.children.keys()[new_col]);
                // only scroll items need updateScroll; the add row is fixed
                if (new_row != current_row and new_row > 0) self.updateScroll(new_row - 1);
            }
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
            const row_box = self.rowAtIndex(current_row) orelse return null;
            const cols = &row_box.children;
            const col_id = row_box.focus.child_id orelse return current_row * cols.count();
            const col_idx = cols.getIndex(col_id) orelse 0;
            return current_row * cols.count() + col_idx;
        }

        // total number of rows: 1 (add) + the scroll's items.
        fn rowCount(self: *const ConfigList(Widget, repo_kind, repo_opts)) usize {
            const inner_box = &self.box.children.values()[scroll_idx].widget.scroll.child.box;
            return 1 + inner_box.children.count();
        }

        // pointer to the Box that owns the cells of row `i`
        fn rowAtIndex(self: *const ConfigList(Widget, repo_kind, repo_opts), i: usize) ?*wgt.Box(Widget) {
            if (i == 0) {
                return &self.box.children.values()[add_idx].widget.ui_config_add_list_item.box;
            }
            const inner_box = &self.box.children.values()[scroll_idx].widget.scroll.child.box;
            const scroll_idx_local = i - 1;
            if (scroll_idx_local >= inner_box.children.count()) return null;
            return &inner_box.children.values()[scroll_idx_local].widget.ui_config_list_item.box;
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
