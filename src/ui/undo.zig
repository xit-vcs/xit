const std = @import("std");
const xitui = @import("xitui");
const wgt = xitui.widget;
const layout = xitui.layout;
const inp = xitui.input;
const Grid = xitui.grid.Grid;
const Focus = xitui.focus.Focus;
const rp = @import("../repo.zig");
const hash = @import("../hash.zig");
const df = @import("../diff.zig");
const obj = @import("../object.zig");
const tr = @import("../tree.zig");

pub fn UndoList(comptime Widget: type, comptime repo_kind: rp.RepoKind, comptime repo_opts: rp.RepoOpts(repo_kind)) type {
    return struct {
        allocator: std.mem.Allocator,
        scroll: wgt.Scroll(Widget),
        repo: *rp.Repo(repo_kind, repo_opts),
        txes: std.ArrayList(?[]const u8),
        tx_count: usize,
        arena: *std.heap.ArenaAllocator,

        pub fn init(allocator: std.mem.Allocator, repo: *rp.Repo(repo_kind, repo_opts)) !UndoList(Widget, repo_kind, repo_opts) {
            var self = blk: {
                const arena = try allocator.create(std.heap.ArenaAllocator);
                errdefer allocator.destroy(arena);
                arena.* = std.heap.ArenaAllocator.init(allocator);

                // init txes
                const txes: std.ArrayList(?[]const u8) = .empty;

                var inner_box = try wgt.Box(Widget).init(allocator, null, .vert);
                errdefer inner_box.deinit();

                // init scroll
                var scroll = try wgt.Scroll(Widget).init(allocator, .{ .box = inner_box }, .vert);
                errdefer scroll.deinit();

                const history = try rp.Repo(repo_kind, repo_opts).DB.ArrayList(.read_only).init(repo.core.db.rootCursor().readOnly());
                const tx_count = try history.count();

                break :blk UndoList(Widget, repo_kind, repo_opts){
                    .allocator = allocator,
                    .scroll = scroll,
                    .repo = repo,
                    .txes = txes,
                    .tx_count = tx_count,
                    .arena = arena,
                };
            };
            errdefer self.deinit();

            try self.addTransactions(20);
            if (self.scroll.child.box.children.count() > 0) {
                self.scroll.getFocus().child_id = self.scroll.child.box.children.keys()[0];
            }

            return self;
        }

        pub fn deinit(self: *UndoList(Widget, repo_kind, repo_opts)) void {
            self.arena.deinit();
            self.allocator.destroy(self.arena);
            self.scroll.deinit();
        }

        pub fn build(self: *UndoList(Widget, repo_kind, repo_opts), constraint: layout.Constraint, root_focus: *Focus) !void {
            self.clearGrid();
            const children = &self.scroll.child.box.children;
            for (children.keys(), children.values()) |id, *commit| {
                commit.widget.text_box.border_style = if (self.getFocus().child_id == id)
                    (if (root_focus.grandchild_id == id) .double else .single)
                else
                    .hidden;
            }
            try self.scroll.build(constraint, root_focus);

            // add more commits if necessary
            if (self.scroll.grid) |scroll_grid| {
                const scroll_y = self.scroll.y;
                const u_scroll_y: usize = if (scroll_y >= 0) @intCast(scroll_y) else 0;
                if (self.scroll.child.box.grid) |inner_box_grid| {
                    const inner_box_height = inner_box_grid.size.height;
                    const min_scroll_remaining = 5;
                    if (inner_box_height -| (scroll_grid.size.height + u_scroll_y) <= min_scroll_remaining) {
                        try self.addTransactions(20);
                    }
                }
            }
        }

        pub fn input(self: *UndoList(Widget, repo_kind, repo_opts), key: inp.Key, root_focus: *Focus) !void {
            if (self.getFocus().child_id) |child_id| {
                const children = &self.scroll.child.box.children;
                if (children.getIndex(child_id)) |current_index| {
                    var index = current_index;

                    switch (key) {
                        .arrow_up => {
                            index -|= 1;
                        },
                        .arrow_down => {
                            if (index + 1 < children.count()) {
                                index += 1;
                            }
                        },
                        .home => {
                            index = 0;
                        },
                        .end => {
                            if (children.count() > 0) {
                                index = children.count() - 1;
                            }
                        },
                        .page_up => {
                            if (self.getGrid()) |grid| {
                                const half_count = (grid.size.height / 3) / 2;
                                index -|= half_count;
                            }
                        },
                        .page_down => {
                            if (self.getGrid()) |grid| {
                                if (children.count() > 0) {
                                    const half_count = (grid.size.height / 3) / 2;
                                    index = @min(index + half_count, children.count() - 1);
                                }
                            }
                        },
                        else => {},
                    }

                    if (index != current_index) {
                        try root_focus.setFocus(children.keys()[index]);
                        self.updateScroll(index);
                    }
                }
            }
        }

        pub fn clearGrid(self: *UndoList(Widget, repo_kind, repo_opts)) void {
            self.scroll.clearGrid();
        }

        pub fn getGrid(self: UndoList(Widget, repo_kind, repo_opts)) ?Grid {
            return self.scroll.getGrid();
        }

        pub fn getFocus(self: *UndoList(Widget, repo_kind, repo_opts)) *Focus {
            return self.scroll.getFocus();
        }

        pub fn getSelectedIndex(self: UndoList(Widget, repo_kind, repo_opts)) ?usize {
            if (self.scroll.child.box.focus.child_id) |child_id| {
                const children = &self.scroll.child.box.children;
                return children.getIndex(child_id);
            } else {
                return null;
            }
        }

        fn updateScroll(self: *UndoList(Widget, repo_kind, repo_opts), index: usize) void {
            const left_box = &self.scroll.child.box;
            if (left_box.children.values()[index].rect) |rect| {
                self.scroll.scrollToRect(rect);
            }
        }

        fn addTransactions(self: *UndoList(Widget, repo_kind, repo_opts), max_txes: usize) !void {
            if (repo_kind != .xit) return;

            const history = try rp.Repo(repo_kind, repo_opts).DB.ArrayList(.read_only).init(self.repo.core.db.rootCursor().readOnly());

            const tx_remain_count = self.tx_count - self.txes.items.len;
            const tx_add_count = @min(tx_remain_count, max_txes);

            for (0..tx_add_count) |i| {
                const ii = tx_remain_count - i - 1;

                const moment_cursor = try history.getCursor(ii) orelse return error.TransactionNotFound;
                const moment = try rp.Repo(repo_kind, repo_opts).DB.HashMap(.read_only).init(moment_cursor);

                const msg_value = if (try moment.getCursor(hash.hashInt(repo_opts.hash, "undo-message"))) |msg_cursor|
                    try msg_cursor.readBytesAlloc(self.allocator, repo_opts.max_read_size)
                else
                    try self.allocator.dupe(u8, "(empty message)");
                defer self.allocator.free(msg_value);

                const msg = try std.fmt.allocPrint(self.arena.allocator(), "{} - {s}", .{ ii, msg_value });
                try self.txes.append(self.arena.allocator(), msg);

                const inner_box = &self.scroll.child.box;
                var text_box = try wgt.TextBox(Widget).init(self.allocator, msg, .hidden, .none);
                errdefer text_box.deinit();
                text_box.getFocus().focusable = true;
                try inner_box.children.put(self.allocator, text_box.getFocus().id, .{ .widget = .{ .text_box = text_box }, .rect = null, .min_size = null });
            }
        }
    };
}

pub fn Undo(comptime Widget: type, comptime repo_kind: rp.RepoKind, comptime repo_opts: rp.RepoOpts(repo_kind)) type {
    return struct {
        box: wgt.Box(Widget),
        repo: *rp.Repo(repo_kind, repo_opts),
        allocator: std.mem.Allocator,

        pub fn init(allocator: std.mem.Allocator, repo: *rp.Repo(repo_kind, repo_opts)) !Undo(Widget, repo_kind, repo_opts) {
            var box = try wgt.Box(Widget).init(allocator, null, .horiz);
            errdefer box.deinit();

            // add undo list
            {
                var undo_list = try UndoList(Widget, repo_kind, repo_opts).init(allocator, repo);
                errdefer undo_list.deinit();
                try box.children.put(allocator, undo_list.getFocus().id, .{ .widget = .{ .ui_undo_list = undo_list }, .rect = null, .min_size = .{ .width = 30, .height = null } });
            }

            // add empty box
            {
                var empty_box = try wgt.Box(Widget).init(allocator, null, .horiz);
                errdefer empty_box.deinit();
                try box.children.put(allocator, empty_box.getFocus().id, .{ .widget = .{ .box = empty_box }, .rect = null, .min_size = .{ .width = 60, .height = null } });
            }

            var undo = Undo(Widget, repo_kind, repo_opts){
                .box = box,
                .repo = repo,
                .allocator = allocator,
            };
            undo.getFocus().child_id = box.children.keys()[0];
            try undo.updateUndoContent();

            return undo;
        }

        pub fn deinit(self: *Undo(Widget, repo_kind, repo_opts)) void {
            self.box.deinit();
        }

        pub fn build(self: *Undo(Widget, repo_kind, repo_opts), constraint: layout.Constraint, root_focus: *Focus) !void {
            self.clearGrid();
            try self.box.build(constraint, root_focus);
        }

        pub fn input(self: *Undo(Widget, repo_kind, repo_opts), key: inp.Key, root_focus: *Focus) !void {
            const diff_scroll_x = 0;

            if (self.getFocus().child_id) |child_id| {
                if (self.box.children.getIndex(child_id)) |current_index| {
                    const child = &self.box.children.values()[current_index].widget;

                    const index = blk: {
                        switch (key) {
                            .arrow_left => {
                                if (child.* != .ui_undo_list and diff_scroll_x == 0) {
                                    break :blk 0;
                                }
                            },
                            .arrow_right => {
                                if (child.* == .ui_undo_list) {
                                    break :blk 1;
                                }
                            },
                            .codepoint => |codepoint| {
                                switch (codepoint) {
                                    13 => {
                                        if (child.* == .ui_undo_list) {
                                            break :blk 1;
                                        }
                                    },
                                    127, '\x1B' => {
                                        if (child.* != .ui_undo_list) {
                                            break :blk 0;
                                        }
                                    },
                                    else => {},
                                }
                            },
                            else => {},
                        }
                        try child.input(key, root_focus);
                        if (child.* == .ui_undo_list) {
                            try self.updateUndoContent();
                        }
                        break :blk current_index;
                    };

                    if (index != current_index) {
                        try root_focus.setFocus(self.box.children.keys()[index]);
                    }
                }
            }
        }

        pub fn clearGrid(self: *Undo(Widget, repo_kind, repo_opts)) void {
            self.box.clearGrid();
        }

        pub fn getGrid(self: Undo(Widget, repo_kind, repo_opts)) ?Grid {
            return self.box.getGrid();
        }

        pub fn getFocus(self: *Undo(Widget, repo_kind, repo_opts)) *Focus {
            return self.box.getFocus();
        }

        pub fn scrolledToTop(self: Undo(Widget, repo_kind, repo_opts)) bool {
            if (self.box.focus.child_id) |child_id| {
                if (self.box.children.getIndex(child_id)) |current_index| {
                    const child = &self.box.children.values()[current_index].widget;
                    switch (child.*) {
                        .ui_undo_list => |child_ui_undo_list| {
                            const undo_list = &child_ui_undo_list;
                            if (undo_list.getSelectedIndex()) |commit_index| {
                                return commit_index == 0;
                            }
                        },
                        // TODO: add branch for undo content
                        else => {},
                    }
                }
            }
            return true;
        }

        fn updateUndoContent(self: *Undo(Widget, repo_kind, repo_opts)) !void {
            _ = self;
        }
    };
}
