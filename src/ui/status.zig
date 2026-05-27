const std = @import("std");
const xitui = @import("xitui");
const wgt = xitui.widget;
const layout = xitui.layout;
const inp = xitui.input;
const Grid = xitui.grid.Grid;
const Focus = xitui.focus.Focus;
const ui_diff = @import("./diff.zig");
const ui_root = @import("./root.zig");
const rp = @import("../repo.zig");
const hash = @import("../hash.zig");
const work = @import("../workdir.zig");
const df = @import("../diff.zig");

pub const StatusItem = struct {
    kind: work.StatusKind,
    path: []const u8,
};

pub fn StatusListItem(comptime Widget: type) type {
    return struct {
        box: wgt.Box(Widget),

        pub fn init(allocator: std.mem.Allocator, status: StatusItem) !StatusListItem(Widget) {
            const status_kind_sym = switch (status.kind) {
                .added => |added| switch (added) {
                    .created => "+",
                    .modified => "±",
                    .deleted => "-",
                    .conflict => "≠",
                },
                .not_added => |not_added| switch (not_added) {
                    .modified => "±",
                    .deleted => "-",
                    .conflict => "≠",
                },
                .not_tracked => "?",
            };
            var status_text = try wgt.TextBox(Widget).init(allocator, status_kind_sym, .{ .border_style = .hidden, .wrap_kind = .none });
            errdefer status_text.deinit(allocator);

            var path_text = try wgt.TextBox(Widget).init(allocator, status.path, .{ .border_style = .hidden, .wrap_kind = .none });
            errdefer path_text.deinit(allocator);

            var box = try wgt.Box(Widget).init(allocator, .{ .border_style = null, .direction = .horiz });
            errdefer box.deinit(allocator);
            try box.children.put(allocator, status_text.getFocus().id, .{ .widget = .{ .text_box = status_text }, .rect = null, .min_size = null });
            try box.children.put(allocator, path_text.getFocus().id, .{ .widget = .{ .text_box = path_text }, .rect = null, .min_size = null });

            return .{
                .box = box,
            };
        }

        pub fn deinit(self: *StatusListItem(Widget), allocator: std.mem.Allocator) void {
            self.box.deinit(allocator);
        }

        pub fn build(self: *StatusListItem(Widget), allocator: std.mem.Allocator, constraint: layout.Constraint, root_focus: *Focus) !void {
            self.clearGrid();
            try self.box.build(allocator, constraint, root_focus);
        }

        pub fn input(self: *StatusListItem(Widget), allocator: std.mem.Allocator, key: inp.Key, root_focus: *Focus) !void {
            _ = self;
            _ = allocator;
            _ = key;
            _ = root_focus;
        }

        pub fn clearGrid(self: *StatusListItem(Widget)) void {
            self.box.clearGrid();
        }

        pub fn getGrid(self: StatusListItem(Widget)) ?Grid {
            return self.box.getGrid();
        }

        pub fn getFocus(self: *StatusListItem(Widget)) *Focus {
            return self.box.getFocus();
        }

        pub fn setBorder(self: *StatusListItem(Widget), border_style: ?wgt.BorderStyle) void {
            self.box.children.values()[1].widget.text_box.options.border_style = border_style;
        }
    };
}

pub fn StatusList(comptime Widget: type) type {
    return struct {
        scroll: wgt.Scroll(Widget),
        statuses: []StatusItem,

        pub fn init(allocator: std.mem.Allocator, statuses: []StatusItem) !StatusList(Widget) {
            // init inner_box
            var inner_box = try wgt.Box(Widget).init(allocator, .{ .border_style = null, .direction = .vert });
            errdefer inner_box.deinit(allocator);
            for (statuses) |item| {
                var list_item = try StatusListItem(Widget).init(allocator, item);
                errdefer list_item.deinit(allocator);
                list_item.getFocus().focusable = true;
                try inner_box.children.put(allocator, list_item.getFocus().id, .{ .widget = .{ .ui_status_list_item = list_item }, .rect = null, .min_size = null });
            }

            // init scroll
            var scroll = try wgt.Scroll(Widget).init(allocator, .{ .box = inner_box }, .vert);
            errdefer scroll.deinit(allocator);
            if (inner_box.children.count() > 0) {
                scroll.getFocus().child_id = inner_box.children.keys()[0];
            }

            return .{
                .scroll = scroll,
                .statuses = statuses,
            };
        }

        pub fn deinit(self: *StatusList(Widget), allocator: std.mem.Allocator) void {
            self.scroll.deinit(allocator);
        }

        pub fn build(self: *StatusList(Widget), allocator: std.mem.Allocator, constraint: layout.Constraint, root_focus: *Focus) !void {
            self.clearGrid();
            const children = &self.scroll.child.box.children;
            for (children.keys(), children.values()) |id, *item| {
                item.widget.ui_status_list_item.setBorder(if (self.getFocus().child_id == id)
                    (if (root_focus.grandchild_id == id) .double else .single)
                else
                    .hidden);
            }
            try self.scroll.build(allocator, constraint, root_focus);
        }

        pub fn input(self: *StatusList(Widget), allocator: std.mem.Allocator, key: inp.Key, root_focus: *Focus) !void {
            _ = allocator;
            if (self.getFocus().child_id) |child_id| {
                const children = &self.scroll.child.box.children;
                if (children.getIndex(child_id)) |current_index| {
                    const index = blk: {
                        switch (key) {
                            .arrow_up => {
                                break :blk current_index - 1;
                            },
                            .arrow_down => {
                                if (current_index + 1 < children.count()) {
                                    break :blk current_index + 1;
                                }
                            },
                            .home => {
                                break :blk 0;
                            },
                            .end => {
                                if (children.count() > 0) {
                                    break :blk children.count() - 1;
                                }
                            },
                            .page_up => {
                                if (self.getGrid()) |grid| {
                                    const half_count = (grid.size.height / 3) / 2;
                                    break :blk current_index -| half_count;
                                }
                            },
                            .page_down => {
                                if (self.getGrid()) |grid| {
                                    if (children.count() > 0) {
                                        const half_count = (grid.size.height / 3) / 2;
                                        break :blk @min(current_index + half_count, children.count() - 1);
                                    }
                                }
                            },
                            .mouse => |mouse| switch (mouse.action) {
                                .scroll => |dir| switch (dir) {
                                    .up => break :blk current_index -| 1,
                                    .down => if (current_index + 1 < children.count()) {
                                        break :blk current_index + 1;
                                    },
                                },
                                else => {},
                            },
                            else => {},
                        }
                        break :blk current_index;
                    };

                    if (index != current_index) {
                        try root_focus.setFocus(children.keys()[index]);
                        self.updateScroll(index);
                    }
                }
            }
        }

        pub fn clearGrid(self: *StatusList(Widget)) void {
            self.scroll.clearGrid();
        }

        pub fn getGrid(self: StatusList(Widget)) ?Grid {
            return self.scroll.getGrid();
        }

        pub fn getFocus(self: *StatusList(Widget)) *Focus {
            return self.scroll.getFocus();
        }

        pub fn getSelectedIndex(self: StatusList(Widget)) ?usize {
            if (self.scroll.child.box.focus.child_id) |child_id| {
                const children = &self.scroll.child.box.children;
                return children.getIndex(child_id);
            } else {
                return null;
            }
        }

        fn updateScroll(self: *StatusList(Widget), index: usize) void {
            const left_box = &self.scroll.child.box;
            if (left_box.children.values()[index].rect) |rect| {
                self.scroll.scrollToRect(rect);
            }
        }
    };
}

pub fn StatusTabs(comptime Widget: type, comptime repo_kind: rp.RepoKind, comptime repo_opts: rp.RepoOpts(repo_kind)) type {
    return struct {
        box: wgt.Box(Widget),
        arena: *std.heap.ArenaAllocator,

        const tab_count = @typeInfo(work.IndexStatusKind).@"enum".fields.len;

        pub fn init(allocator: std.mem.Allocator, status: *work.Status(repo_kind, repo_opts)) !StatusTabs(Widget, repo_kind, repo_opts) {
            var box = try wgt.Box(Widget).init(allocator, .{ .border_style = null, .direction = .horiz });
            errdefer box.deinit(allocator);

            const arena = try allocator.create(std.heap.ArenaAllocator);
            arena.* = std.heap.ArenaAllocator.init(allocator);
            errdefer {
                arena.deinit();
                allocator.destroy(arena);
            }

            const counts = [_]usize{
                status.index_added.count() + status.index_modified.count() + status.index_deleted.count() + status.resolved_conflicts.count(),
                status.work_dir_modified.count() + status.work_dir_deleted.count() + status.unresolved_conflicts.count(),
                status.untracked.count(),
            };

            var selected_maybe: ?work.IndexStatusKind = null;

            inline for (@typeInfo(work.IndexStatusKind).@"enum".fields, 0..) |field, i| {
                const index_kind: work.IndexStatusKind = @enumFromInt(field.value);
                if (selected_maybe == null and counts[i] > 0) {
                    selected_maybe = index_kind;
                }
                const name = switch (index_kind) {
                    .added => "added",
                    .not_added => "not added",
                    .not_tracked => "not tracked",
                };
                const label = try std.fmt.allocPrint(arena.allocator(), "{s} ({})", .{ name, counts[i] });
                var text_box = try wgt.TextBox(Widget).init(allocator, label, .{ .border_style = .single, .wrap_kind = .none });
                errdefer text_box.deinit(allocator);
                text_box.getFocus().focusable = true;
                try box.children.put(allocator, text_box.getFocus().id, .{ .widget = .{ .text_box = text_box }, .rect = null, .min_size = null });
            }

            var ui_status_tabs = StatusTabs(Widget, repo_kind, repo_opts){
                .box = box,
                .arena = arena,
            };
            ui_status_tabs.getFocus().child_id = box.children.keys()[@intFromEnum(selected_maybe orelse .added)];
            return ui_status_tabs;
        }

        pub fn deinit(self: *StatusTabs(Widget, repo_kind, repo_opts), allocator: std.mem.Allocator) void {
            self.box.deinit(allocator);
            self.arena.deinit();
            allocator.destroy(self.arena);
        }

        pub fn build(self: *StatusTabs(Widget, repo_kind, repo_opts), allocator: std.mem.Allocator, constraint: layout.Constraint, root_focus: *Focus) !void {
            self.clearGrid();
            for (self.box.children.keys(), self.box.children.values()) |id, *tab| {
                tab.widget.text_box.options.border_style = if (self.getFocus().child_id == id) .single else .hidden;
            }
            try self.box.build(allocator, constraint, root_focus);
        }

        pub fn input(self: *StatusTabs(Widget, repo_kind, repo_opts), allocator: std.mem.Allocator, key: inp.Key, root_focus: *Focus) !void {
            _ = allocator;
            if (self.getFocus().child_id) |child_id| {
                const children = &self.box.children;
                if (children.getIndex(child_id)) |current_index| {
                    const index = blk: {
                        switch (key) {
                            .arrow_left => {
                                break :blk current_index -| 1;
                            },
                            .arrow_right => {
                                if (current_index + 1 < children.count()) {
                                    break :blk current_index + 1;
                                }
                            },
                            else => {},
                        }
                        break :blk current_index;
                    };

                    if (index != current_index) {
                        try root_focus.setFocus(children.keys()[index]);
                    }
                }
            }
        }

        pub fn clearGrid(self: *StatusTabs(Widget, repo_kind, repo_opts)) void {
            self.box.clearGrid();
        }

        pub fn getGrid(self: StatusTabs(Widget, repo_kind, repo_opts)) ?Grid {
            return self.box.getGrid();
        }

        pub fn getFocus(self: *StatusTabs(Widget, repo_kind, repo_opts)) *Focus {
            return self.box.getFocus();
        }

        pub fn getSelectedIndex(self: StatusTabs(Widget, repo_kind, repo_opts)) ?usize {
            if (self.box.focus.child_id) |child_id| {
                const children = &self.box.children;
                return children.getIndex(child_id);
            } else {
                return null;
            }
        }
    };
}

pub fn StatusContent(comptime Widget: type, comptime repo_kind: rp.RepoKind, comptime repo_opts: rp.RepoOpts(repo_kind)) type {
    return struct {
        box: wgt.Box(Widget),
        filtered_statuses: std.ArrayList(StatusItem),
        repo: *rp.Repo(repo_kind, repo_opts),
        status: *work.Status(repo_kind, repo_opts),
        io: std.Io,
        diffed_status_index: ?usize,

        const FocusKind = enum { status_list, diff };

        pub fn init(io: std.Io, allocator: std.mem.Allocator, repo: *rp.Repo(repo_kind, repo_opts), status: *work.Status(repo_kind, repo_opts), selected: work.IndexStatusKind) !StatusContent(Widget, repo_kind, repo_opts) {
            var filtered_statuses: std.ArrayList(StatusItem) = .empty;
            errdefer filtered_statuses.deinit(allocator);

            switch (selected) {
                .added => {
                    for (status.index_added.keys()) |path| {
                        try filtered_statuses.append(allocator, .{ .kind = .{ .added = .created }, .path = path });
                    }
                    for (status.index_modified.keys()) |path| {
                        try filtered_statuses.append(allocator, .{ .kind = .{ .added = .modified }, .path = path });
                    }
                    for (status.index_deleted.keys()) |path| {
                        try filtered_statuses.append(allocator, .{ .kind = .{ .added = .deleted }, .path = path });
                    }
                    for (status.resolved_conflicts.keys()) |path| {
                        try filtered_statuses.append(allocator, .{ .kind = .{ .added = .conflict }, .path = path });
                    }
                },
                .not_added => {
                    for (status.work_dir_modified.values()) |entry| {
                        try filtered_statuses.append(allocator, .{ .kind = .{ .not_added = .modified }, .path = entry.path });
                    }
                    for (status.work_dir_deleted.keys()) |path| {
                        try filtered_statuses.append(allocator, .{ .kind = .{ .not_added = .deleted }, .path = path });
                    }
                    for (status.unresolved_conflicts.keys()) |path| {
                        try filtered_statuses.append(allocator, .{ .kind = .{ .not_added = .conflict }, .path = path });
                    }
                },
                .not_tracked => {
                    for (status.untracked.values()) |entry| {
                        try filtered_statuses.append(allocator, .{ .kind = .not_tracked, .path = entry.path });
                    }
                },
            }

            var box = try wgt.Box(Widget).init(allocator, .{ .border_style = null, .direction = .horiz });
            errdefer box.deinit(allocator);

            inline for (@typeInfo(FocusKind).@"enum".fields) |focus_kind_field| {
                const focus_kind: FocusKind = @enumFromInt(focus_kind_field.value);
                switch (focus_kind) {
                    .status_list => {
                        var status_list = try StatusList(Widget).init(allocator, filtered_statuses.items);
                        errdefer status_list.deinit(allocator);
                        try box.children.put(allocator, status_list.getFocus().id, .{ .widget = .{ .ui_status_list = status_list }, .rect = null, .min_size = .{ .width = 20, .height = null } });
                    },
                    .diff => {
                        var diff = try ui_diff.Diff(Widget, repo_kind, repo_opts).init(allocator, repo);
                        errdefer diff.deinit(allocator);
                        diff.getFocus().focusable = true;
                        try box.children.put(allocator, diff.getFocus().id, .{ .widget = .{ .ui_diff = diff }, .rect = null, .min_size = .{ .width = 60, .height = null } });
                    },
                }
            }

            var status_content = StatusContent(Widget, repo_kind, repo_opts){
                .box = box,
                .filtered_statuses = filtered_statuses,
                .repo = repo,
                .status = status,
                .io = io,
                .diffed_status_index = null,
            };
            status_content.getFocus().child_id = box.children.keys()[0];
            try status_content.refreshDiffIfNeeded(allocator);
            return status_content;
        }

        pub fn deinit(self: *StatusContent(Widget, repo_kind, repo_opts), allocator: std.mem.Allocator) void {
            self.box.deinit(allocator);
            self.filtered_statuses.deinit(allocator);
        }

        pub fn build(self: *StatusContent(Widget, repo_kind, repo_opts), allocator: std.mem.Allocator, constraint: layout.Constraint, root_focus: *Focus) !void {
            self.clearGrid();
            if (self.filtered_statuses.items.len > 0) {
                // regenerate the diff only when the selected status actually
                // changed — keeps scroll-burst handling cheap.
                try self.refreshDiffIfNeeded(allocator);
                try self.box.build(allocator, constraint, root_focus);
            }
        }

        pub fn input(self: *StatusContent(Widget, repo_kind, repo_opts), allocator: std.mem.Allocator, key: inp.Key, root_focus: *Focus) !void {
            const diff_scroll_x = self.box.children.values()[1].widget.ui_diff.getScrollX();

            if (self.getFocus().child_id) |child_id| {
                if (self.box.children.getIndex(child_id)) |current_index| {
                    const child = &self.box.children.values()[current_index].widget;

                    var index = blk: {
                        switch (key) {
                            .arrow_left => {
                                if (child.* == .ui_diff and diff_scroll_x == 0) {
                                    break :blk @intFromEnum(FocusKind.status_list);
                                }
                            },
                            .arrow_right => {
                                if (child.* == .ui_status_list) {
                                    break :blk @intFromEnum(FocusKind.diff);
                                }
                            },
                            .codepoint => |codepoint| {
                                switch (codepoint) {
                                    13 => {
                                        if (child.* == .ui_status_list) {
                                            break :blk @intFromEnum(FocusKind.status_list);
                                        }
                                    },
                                    127, '\x1B' => {
                                        if (child.* == .ui_diff) {
                                            break :blk @intFromEnum(FocusKind.diff);
                                        }
                                    },
                                    else => {},
                                }
                            },
                            else => {},
                        }
                        try child.input(allocator, key, root_focus);
                        break :blk current_index;
                    };

                    if (index == @intFromEnum(FocusKind.diff) and self.box.children.values()[@intFromEnum(FocusKind.diff)].widget.ui_diff.isEmpty()) {
                        index = @intFromEnum(FocusKind.status_list);
                    }

                    if (index != current_index) {
                        try root_focus.setFocus(self.box.children.keys()[index]);
                    }
                }
            }
        }

        pub fn clearGrid(self: *StatusContent(Widget, repo_kind, repo_opts)) void {
            self.box.clearGrid();
        }

        pub fn getGrid(self: StatusContent(Widget, repo_kind, repo_opts)) ?Grid {
            return self.box.getGrid();
        }

        pub fn getFocus(self: *StatusContent(Widget, repo_kind, repo_opts)) *Focus {
            return self.box.getFocus();
        }

        pub fn scrolledToTop(self: StatusContent(Widget, repo_kind, repo_opts)) bool {
            if (self.box.focus.child_id) |child_id| {
                if (self.box.children.getIndex(child_id)) |current_index| {
                    const child = &self.box.children.values()[current_index].widget;
                    switch (child.*) {
                        .ui_status_list => |child_ui_status_list| {
                            if (child_ui_status_list.getSelectedIndex()) |status_index| {
                                return status_index == 0;
                            }
                        },
                        .ui_diff => |child_ui_diff| {
                            return child_ui_diff.getScrollY() == 0;
                        },
                        else => {},
                    }
                }
            }
            return true;
        }

        fn refreshDiffIfNeeded(self: *StatusContent(Widget, repo_kind, repo_opts), allocator: std.mem.Allocator) !void {
            const status_list = &self.box.children.values()[0].widget.ui_status_list;
            const current = status_list.getSelectedIndex();
            if (current == self.diffed_status_index) return;
            try self.updateDiff(allocator);
            self.diffed_status_index = current;
        }

        fn updateDiff(self: *StatusContent(Widget, repo_kind, repo_opts), allocator: std.mem.Allocator) !void {
            const status_list = &self.box.children.values()[0].widget.ui_status_list;
            if (status_list.getSelectedIndex()) |status_index| {
                const status_item = status_list.statuses[status_index];

                // get widget
                var diff = &self.box.children.values()[1].widget.ui_diff;
                try diff.clearDiffs(allocator);

                const line_iter_pair = self.repo.filePair(self.io, diff.iter_arena.allocator(), status_item.path, status_item.kind, self.status) catch |err| switch (err) {
                    error.IsDir => return,
                    else => |e| return e,
                };

                const line_iter_a = try diff.iter_arena.allocator().create(df.LineIterator(repo_kind, repo_opts));
                line_iter_a.* = line_iter_pair.a;

                const line_iter_b = try diff.iter_arena.allocator().create(df.LineIterator(repo_kind, repo_opts));
                line_iter_b.* = line_iter_pair.b;

                diff.hunk_iter = try df.HunkIterator(repo_kind, repo_opts).init(diff.iter_arena.allocator(), line_iter_a, line_iter_b);
            }
        }
    };
}

pub fn Status(comptime Widget: type, comptime repo_kind: rp.RepoKind, comptime repo_opts: rp.RepoOpts(repo_kind)) type {
    return struct {
        box: wgt.Box(Widget),
        status: *work.Status(repo_kind, repo_opts),

        const FocusKind = enum { status_tabs, status_content };

        pub fn init(io: std.Io, allocator: std.mem.Allocator, repo: *rp.Repo(repo_kind, repo_opts)) !Status(Widget, repo_kind, repo_opts) {
            var status = try repo.status(io, allocator);
            errdefer status.deinit(allocator);

            // put Status object on the heap so the pointer is stable
            const status_ptr = try allocator.create(work.Status(repo_kind, repo_opts));
            errdefer allocator.destroy(status_ptr);
            status_ptr.* = status;

            // init box
            var box = try wgt.Box(Widget).init(allocator, .{ .border_style = null, .direction = .vert });
            errdefer box.deinit(allocator);

            inline for (@typeInfo(FocusKind).@"enum".fields) |focus_kind_field| {
                const focus_kind: FocusKind = @enumFromInt(focus_kind_field.value);
                switch (focus_kind) {
                    .status_tabs => {
                        var status_tabs = try StatusTabs(Widget, repo_kind, repo_opts).init(allocator, status_ptr);
                        errdefer status_tabs.deinit(allocator);
                        try box.children.put(allocator, status_tabs.getFocus().id, .{ .widget = .{ .ui_status_tabs = status_tabs }, .rect = null, .min_size = null });
                    },
                    .status_content => {
                        var stack = wgt.Stack(Widget).init(allocator);
                        errdefer stack.deinit(allocator);

                        inline for (@typeInfo(work.IndexStatusKind).@"enum".fields) |index_kind_field| {
                            const index_kind: work.IndexStatusKind = @enumFromInt(index_kind_field.value);
                            var status_content = try StatusContent(Widget, repo_kind, repo_opts).init(io, allocator, repo, status_ptr, index_kind);
                            errdefer status_content.deinit(allocator);
                            try stack.children.put(allocator, status_content.getFocus().id, .{ .ui_status_content = status_content });
                        }

                        try box.children.put(allocator, stack.getFocus().id, .{ .widget = .{ .stack = stack }, .rect = null, .min_size = null });
                    },
                }
            }

            var ui_status = Status(Widget, repo_kind, repo_opts){
                .box = box,
                .status = status_ptr,
            };
            ui_status.getFocus().child_id = box.children.keys()[0];
            return ui_status;
        }

        pub fn deinit(self: *Status(Widget, repo_kind, repo_opts), allocator: std.mem.Allocator) void {
            self.box.deinit(allocator);
            self.status.deinit(allocator);
            allocator.destroy(self.status);
        }

        pub fn build(self: *Status(Widget, repo_kind, repo_opts), allocator: std.mem.Allocator, constraint: layout.Constraint, root_focus: *Focus) !void {
            self.clearGrid();
            const status_tabs = &self.box.children.values()[@intFromEnum(FocusKind.status_tabs)].widget.ui_status_tabs;
            const stack = &self.box.children.values()[@intFromEnum(FocusKind.status_content)].widget.stack;
            if (status_tabs.getSelectedIndex()) |index| {
                stack.getFocus().child_id = stack.children.keys()[index];
            }
            try self.box.build(allocator, constraint, root_focus);
        }

        pub fn input(self: *Status(Widget, repo_kind, repo_opts), allocator: std.mem.Allocator, key: inp.Key, root_focus: *Focus) !void {
            if (self.getFocus().child_id) |child_id| {
                if (self.box.children.getIndex(child_id)) |current_index| {
                    const child = &self.box.children.values()[current_index].widget;

                    // scroll wheel moves the selection across tabs/content just
                    // like arrow up/down does
                    const Direction = enum { up, down, none };
                    const direction: Direction = switch (key) {
                        .arrow_up => .up,
                        .arrow_down => .down,
                        .mouse => |mouse| if (mouse.action == .scroll)
                            (if (mouse.action.scroll == .up) .up else .down)
                        else
                            .none,
                        else => .none,
                    };

                    var index = blk: {
                        switch (child.*) {
                            .ui_status_tabs => |*child_ui_status_tabs| {
                                if (direction == .down) {
                                    break :blk @intFromEnum(FocusKind.status_content);
                                } else {
                                    try child_ui_status_tabs.input(allocator, key, root_focus);
                                }
                            },
                            .stack => |*child_stack| {
                                if (child_stack.getSelected()) |selected_widget| {
                                    if (direction == .up and selected_widget.ui_status_content.scrolledToTop()) {
                                        break :blk @intFromEnum(FocusKind.status_tabs);
                                    } else {
                                        try child_stack.input(allocator, key, root_focus);
                                    }
                                }
                            },
                            else => {},
                        }
                        break :blk current_index;
                    };

                    if (index == @intFromEnum(FocusKind.status_content)) {
                        if (self.box.children.values()[@intFromEnum(FocusKind.status_content)].widget.stack.getSelected()) |selected_widget| {
                            if (selected_widget.ui_status_content.getGrid() == null) {
                                index = @intFromEnum(FocusKind.status_tabs);
                            }
                        }
                    }

                    if (index != current_index) {
                        try root_focus.setFocus(self.box.children.keys()[index]);
                    }
                }
            }
        }

        pub fn clearGrid(self: *Status(Widget, repo_kind, repo_opts)) void {
            self.box.clearGrid();
        }

        pub fn getGrid(self: Status(Widget, repo_kind, repo_opts)) ?Grid {
            return self.box.getGrid();
        }

        pub fn getFocus(self: *Status(Widget, repo_kind, repo_opts)) *Focus {
            return self.box.getFocus();
        }

        pub fn getSelectedIndex(self: Status(Widget, repo_kind, repo_opts)) ?usize {
            if (self.box.focus.child_id) |child_id| {
                const children = &self.box.children;
                return children.getIndex(child_id);
            } else {
                return null;
            }
        }
    };
}
