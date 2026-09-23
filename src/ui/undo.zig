const std = @import("std");
const xitui = @import("xitui");
const wgt = xitui.widget;
const layout = xitui.layout;
const Key = xitui.input.Key;
const Grid = xitui.grid.Grid;
const Focus = xitui.focus.Focus;
const ui = @import("../ui.zig");
const inp = @import("./input.zig");
const rp = @import("../repo.zig");
const un = @import("../undo.zig");

const undo_label = " press enter to undo this ";
const undo_all_label = " press enter to undo this and all above ";

pub fn UndoList(comptime Widget: type, comptime repo_kind: rp.RepoKind, comptime repo_opts: rp.RepoOpts(repo_kind)) type {
    return struct {
        scroll: wgt.Scroll(Widget),
        repo: *rp.Repo(repo_kind, repo_opts),
        session: *ui.Session,
        tx_count: usize,

        pub fn init(allocator: std.mem.Allocator, repo: *rp.Repo(repo_kind, repo_opts), session: *ui.Session) !UndoList(Widget, repo_kind, repo_opts) {
            const history = try rp.Repo(repo_kind, repo_opts).DB.ArrayList(.read_only).init(repo.core.db.rootCursor().readOnly());
            const tx_count = try history.count();

            var self = blk: {
                var inner_box = try wgt.Box(Widget).init(allocator, .{ .border_style = null, .direction = .vert });
                errdefer inner_box.deinit(allocator);

                // init scroll
                const scroll = try wgt.Scroll(Widget).init(allocator, .{ .box = inner_box }, .{ .direction = .vert });

                break :blk UndoList(Widget, repo_kind, repo_opts){
                    .scroll = scroll,
                    .repo = repo,
                    .session = session,
                    .tx_count = tx_count,
                };
            };
            errdefer self.deinit(allocator);

            try self.addTransactions(allocator, 20);
            if (self.scroll.child.box.children.count() > 0) {
                self.scroll.getFocus().child_id = self.scroll.child.box.children.keys()[0];
            }

            return self;
        }

        pub fn deinit(self: *UndoList(Widget, repo_kind, repo_opts), allocator: std.mem.Allocator) void {
            self.scroll.deinit(allocator);
        }

        pub fn build(self: *UndoList(Widget, repo_kind, repo_opts), allocator: std.mem.Allocator, constraint: layout.Constraint, root_focus: *Focus) !void {
            self.clearGrid();
            const children = &self.scroll.child.box.children;
            for (children.keys(), children.values(), 0..) |id, *item, index| {
                const selected = self.getFocus().child_id == id;
                item.widget.text_box.options.border_style = if (selected) .single else .hidden;
                item.widget.text_box.options.inverted = selected;
                item.widget.text_box.options.bottom_label = if (root_focus.grandchild_id != id or index + 1 == self.tx_count)
                    ""
                else if (index == 0)
                    undo_label
                else
                    undo_all_label;
            }
            try self.scroll.build(allocator, constraint, root_focus);

            // add more commits if necessary
            if (self.scroll.grid) |scroll_grid| {
                const scroll_y = self.scroll.y;
                const u_scroll_y: usize = if (scroll_y >= 0) @intCast(scroll_y) else 0;
                if (self.scroll.child.box.grid) |inner_box_grid| {
                    const inner_box_height = inner_box_grid.size.height;
                    const min_scroll_remaining = 5;
                    if (inner_box_height -| (scroll_grid.size.height + u_scroll_y) <= min_scroll_remaining) {
                        try self.addTransactions(allocator, 20);
                    }
                }
            }
        }

        pub fn input(self: *UndoList(Widget, repo_kind, repo_opts), allocator: std.mem.Allocator, key: Key, root_focus: *Focus) !void {
            _ = allocator;
            if (self.session.pending != null) return;
            if (self.getFocus().child_id) |child_id| {
                const children = &self.scroll.child.box.children;
                if (children.getIndex(child_id)) |current_index| {
                    if (key == .enter) {
                        const history_index = self.tx_count - current_index - 1;
                        if (history_index > 0) self.session.pending = .{ .undo = history_index };
                        return;
                    }
                    const index = inp.vertIndex(key, current_index, children.count(), self.getGrid());

                    if (index != current_index) {
                        root_focus.setFocus(children.keys()[index]);
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

        fn addTransactions(self: *UndoList(Widget, repo_kind, repo_opts), allocator: std.mem.Allocator, max_txes: usize) !void {
            if (repo_kind != .xit) return;

            const tx_remain_count = self.tx_count - self.scroll.child.box.children.count();
            const tx_add_count = @min(tx_remain_count, max_txes);

            var record_buffer: [repo_opts.max_read_size]u8 = undefined;
            var label = std.Io.Writer.Allocating.init(allocator);
            defer label.deinit();
            for (0..tx_add_count) |i| {
                const ii = tx_remain_count - i - 1;

                const moment = try self.repo.core.momentAt(ii);

                label.clearRetainingCapacity();
                try label.writer.print("{} - ", .{ii});
                if (try un.read(repo_opts, moment, &record_buffer)) |record| {
                    try un.format(repo_opts, &self.repo.core, allocator, record, &label.writer);
                } else {
                    try label.writer.writeAll("(empty description)");
                }

                const inner_box = &self.scroll.child.box;
                var text_box = try wgt.TextBox.init(allocator, label.written(), .{ .border_style = .hidden, .wrap_kind = .none });
                errdefer text_box.deinit(allocator);
                text_box.getFocus().mode = .all;
                try inner_box.children.put(allocator, text_box.getFocus().id, .{ .widget = .{ .text_box = text_box }, .rect = null, .min_size = null });
            }
        }
    };
}

pub fn Undo(comptime Widget: type, comptime repo_kind: rp.RepoKind, comptime repo_opts: rp.RepoOpts(repo_kind)) type {
    return struct {
        box: wgt.Box(Widget),
        session: *ui.Session,

        const buttons_index = 0;
        const list_index = 1;

        pub fn init(allocator: std.mem.Allocator, repo: *rp.Repo(repo_kind, repo_opts), session: *ui.Session) !Undo(Widget, repo_kind, repo_opts) {
            var box = try wgt.Box(Widget).init(allocator, .{ .border_style = null, .direction = .vert });
            errdefer box.deinit(allocator);

            // keep the action row above the scrollable content.
            {
                var buttons = try wgt.Box(Widget).init(allocator, .{ .border_style = null, .direction = .horiz });
                errdefer buttons.deinit(allocator);

                {
                    var button = try wgt.TextBox.init(allocator, "clear undo history", .{ .border_style = .single, .wrap_kind = .none });
                    errdefer button.deinit(allocator);
                    button.getFocus().mode = .all;
                    try buttons.children.put(allocator, button.getFocus().id, .{ .widget = .{ .text_box = button }, .rect = null, .min_size = null });
                    buttons.focus.child_id = button.getFocus().id;
                }
                try box.children.put(allocator, buttons.getFocus().id, .{ .widget = .{ .box = buttons }, .rect = null, .min_size = null });
            }

            {
                var undo_list = try UndoList(Widget, repo_kind, repo_opts).init(allocator, repo, session);
                errdefer undo_list.deinit(allocator);
                try box.children.put(allocator, undo_list.getFocus().id, .{ .widget = .{ .ui_undo_list = undo_list }, .rect = null, .min_size = null });
            }

            var undo = Undo(Widget, repo_kind, repo_opts){
                .box = box,
                .session = session,
            };
            undo.getFocus().child_id = box.children.keys()[0];

            return undo;
        }

        pub fn deinit(self: *Undo(Widget, repo_kind, repo_opts), allocator: std.mem.Allocator) void {
            self.box.deinit(allocator);
        }

        pub fn build(self: *Undo(Widget, repo_kind, repo_opts), allocator: std.mem.Allocator, constraint: layout.Constraint, root_focus: *Focus) !void {
            self.clearGrid();
            const button = &self.box.children.values()[buttons_index].widget.box.children.values()[0].widget.text_box;
            button.options.bottom_label = if (self.session.pending != null and self.session.pending.? == .gc)
                " running gc... "
            else if (root_focus.grandchild_id == button.getFocus().id)
                " run gc "
            else
                "";
            try self.box.build(allocator, constraint, root_focus);
        }

        pub fn input(self: *Undo(Widget, repo_kind, repo_opts), allocator: std.mem.Allocator, key: Key, root_focus: *Focus) !void {
            if (self.session.pending != null) return;

            const buttons = &self.box.children.values()[buttons_index].widget.box;
            const list = &self.box.children.values()[list_index].widget.ui_undo_list;
            const direction = inp.vertDirection(key);

            if (self.scrolledToTop()) {
                if (inp.activates(key, buttons.children.keys()[0], root_focus)) {
                    // the terminal runs this action after rendering the busy label.
                    self.session.pending = .gc;
                } else if (direction == .down) {
                    self.focusList(root_focus);
                }
                return;
            }

            if (direction == .up and (list.getSelectedIndex() orelse 0) == 0) {
                root_focus.setFocus(buttons.getFocus().id);
            } else {
                try list.input(allocator, key, root_focus);
            }
        }

        pub fn focusList(self: *Undo(Widget, repo_kind, repo_opts), root_focus: *Focus) void {
            const list = &self.box.children.values()[list_index].widget.ui_undo_list;
            if (list.scroll.child.box.children.count() > 0) {
                list.getFocus().child_id = list.scroll.child.box.children.keys()[0];
                self.getFocus().child_id = list.getFocus().id;
                root_focus.setFocus(self.getFocus().id);
                list.updateScroll(0);
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
            return self.box.focus.child_id == self.box.children.keys()[buttons_index];
        }
    };
}
