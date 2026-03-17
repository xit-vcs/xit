const std = @import("std");
const xitui = @import("xitui");
const term = xitui.terminal;
const wgt = xitui.widget;
const layout = xitui.layout;
const inp = xitui.input;
const Grid = xitui.grid.Grid;
const Focus = xitui.focus.Focus;
const rp = @import("../repo.zig");
const hash = @import("../hash.zig");
const df = @import("../diff.zig");

pub fn Diff(comptime Widget: type, comptime repo_kind: rp.RepoKind, comptime repo_opts: rp.RepoOpts(repo_kind)) type {
    return struct {
        box: wgt.Box(Widget),
        allocator: std.mem.Allocator,
        repo: *rp.Repo(repo_kind, repo_opts),
        iter_arena: std.heap.ArenaAllocator,
        file_iter: ?df.FileIterator(repo_kind, repo_opts),
        hunk_iter: ?df.HunkIterator(repo_kind, repo_opts),
        bufs: std.ArrayList([]const u8),

        pub fn init(allocator: std.mem.Allocator, repo: *rp.Repo(repo_kind, repo_opts)) !Diff(Widget, repo_kind, repo_opts) {
            var inner_box = try wgt.Box(Widget).init(allocator, null, .vert);
            errdefer inner_box.deinit();

            var scroll = try wgt.Scroll(Widget).init(allocator, .{ .box = inner_box }, .both);
            errdefer scroll.deinit();

            var outer_box = try wgt.Box(Widget).init(allocator, .single, .vert);
            errdefer outer_box.deinit();
            try outer_box.children.put(allocator, scroll.getFocus().id, .{ .widget = .{ .scroll = scroll }, .rect = null, .min_size = null });

            return .{
                .box = outer_box,
                .allocator = allocator,
                .repo = repo,
                .iter_arena = std.heap.ArenaAllocator.init(allocator),
                .file_iter = null,
                .hunk_iter = null,
                .bufs = .empty,
            };
        }

        pub fn deinit(self: *Diff(Widget, repo_kind, repo_opts)) void {
            for (self.bufs.items) |buf| {
                self.allocator.free(buf);
            }
            self.iter_arena.deinit();
            self.bufs.deinit(self.allocator);
            self.box.deinit();
        }

        pub fn build(self: *Diff(Widget, repo_kind, repo_opts), constraint: layout.Constraint, root_focus: *Focus) !void {
            self.clearGrid();
            self.box.border_style = if (root_focus.grandchild_id == self.getFocus().id) .double else .single;
            try self.box.build(constraint, root_focus);

            // add another diff if necessary
            if (self.box.grid) |outer_box_grid| {
                const outer_box_height = outer_box_grid.size.height - 2;
                const scroll_y = self.box.children.values()[0].widget.scroll.y;
                const u_scroll_y: usize = if (scroll_y >= 0) @intCast(scroll_y) else 0;
                if (self.box.children.values()[0].widget.scroll.child.box.grid) |inner_box_grid| {
                    const inner_box_height = inner_box_grid.size.height;
                    const min_scroll_remaining = 5;
                    if (inner_box_height -| (outer_box_height + u_scroll_y) <= min_scroll_remaining) {
                        // add the next hunk
                        if (self.hunk_iter) |*hunk_iter| {
                            if (hunk_iter.header_lines.items.len > 0) {
                                try self.addLines(hunk_iter.header_lines.items);
                                hunk_iter.header_lines.clearAndFree(hunk_iter.arena.allocator());
                            }
                            if (try hunk_iter.next(self.iter_arena.allocator())) |*hunk_ptr| {
                                try self.addHunk(hunk_iter, hunk_ptr);
                            } else {
                                self.hunk_iter = null;
                            }
                        }

                        // get the next hunk iter
                        if (self.hunk_iter == null) {
                            if (self.file_iter) |*file_iter| {
                                if (try file_iter.next()) |line_iter_pair| {
                                    const line_iter_a = try self.iter_arena.allocator().create(df.LineIterator(repo_kind, repo_opts));
                                    line_iter_a.* = line_iter_pair.a;

                                    const line_iter_b = try self.iter_arena.allocator().create(df.LineIterator(repo_kind, repo_opts));
                                    line_iter_b.* = line_iter_pair.b;

                                    self.hunk_iter = try df.HunkIterator(repo_kind, repo_opts).init(self.iter_arena.allocator(), line_iter_a, line_iter_b);
                                } else {
                                    self.file_iter = null;
                                }
                            }
                        }
                    }
                }
            }
        }

        pub fn input(self: *Diff(Widget, repo_kind, repo_opts), key: inp.Key, root_focus: *Focus) !void {
            _ = root_focus;
            switch (key) {
                .arrow_up => {
                    if (self.box.children.values()[0].widget.scroll.y > 0) {
                        self.box.children.values()[0].widget.scroll.y -= 1;
                    }
                },
                .arrow_down => {
                    if (self.box.grid) |outer_box_grid| {
                        const outer_box_height = outer_box_grid.size.height - 2;
                        const scroll_y = self.box.children.values()[0].widget.scroll.y;
                        const u_scroll_y: usize = if (scroll_y >= 0) @intCast(scroll_y) else 0;
                        if (self.box.children.values()[0].widget.scroll.child.box.grid) |inner_box_grid| {
                            const inner_box_height = inner_box_grid.size.height;
                            if (outer_box_height + u_scroll_y < inner_box_height) {
                                self.box.children.values()[0].widget.scroll.y += 1;
                            }
                        }
                    }
                },
                .arrow_left => {
                    if (self.box.children.values()[0].widget.scroll.x > 0) {
                        self.box.children.values()[0].widget.scroll.x -= 1;
                    }
                },
                .arrow_right => {
                    if (self.box.grid) |outer_box_grid| {
                        const outer_box_width = outer_box_grid.size.width - 2;
                        const scroll_x = self.box.children.values()[0].widget.scroll.x;
                        const u_scroll_x: usize = if (scroll_x >= 0) @intCast(scroll_x) else 0;
                        if (self.box.children.values()[0].widget.scroll.child.box.grid) |inner_box_grid| {
                            const inner_box_width = inner_box_grid.size.width;
                            if (outer_box_width + u_scroll_x < inner_box_width) {
                                self.box.children.values()[0].widget.scroll.x += 1;
                            }
                        }
                    }
                },
                .home => {
                    self.box.children.values()[0].widget.scroll.y = 0;
                },
                .end => {
                    if (self.box.grid) |outer_box_grid| {
                        if (self.box.children.values()[0].widget.scroll.child.box.grid) |inner_box_grid| {
                            const outer_box_height = outer_box_grid.size.height - 2;
                            const inner_box_height = inner_box_grid.size.height;
                            const max_scroll: isize = if (inner_box_height > outer_box_height) @intCast(inner_box_height - outer_box_height) else 0;
                            self.box.children.values()[0].widget.scroll.y = max_scroll;
                        }
                    }
                },
                .page_up => {
                    if (self.box.grid) |outer_box_grid| {
                        const outer_box_height = outer_box_grid.size.height - 2;
                        const scroll_y = self.box.children.values()[0].widget.scroll.y;
                        const scroll_change: isize = @intCast(outer_box_height / 2);
                        self.box.children.values()[0].widget.scroll.y = @max(0, scroll_y - scroll_change);
                    }
                },
                .page_down => {
                    if (self.box.grid) |outer_box_grid| {
                        if (self.box.children.values()[0].widget.scroll.child.box.grid) |inner_box_grid| {
                            const outer_box_height = outer_box_grid.size.height - 2;
                            const inner_box_height = inner_box_grid.size.height;
                            const max_scroll: isize = if (inner_box_height > outer_box_height) @intCast(inner_box_height - outer_box_height) else 0;
                            const scroll_y = self.box.children.values()[0].widget.scroll.y;
                            const scroll_change: isize = @intCast(outer_box_height / 2);
                            self.box.children.values()[0].widget.scroll.y = @min(scroll_y + scroll_change, max_scroll);
                        }
                    }
                },
                else => {},
            }
        }

        pub fn clearGrid(self: *Diff(Widget, repo_kind, repo_opts)) void {
            self.box.clearGrid();
        }

        pub fn getGrid(self: Diff(Widget, repo_kind, repo_opts)) ?Grid {
            return self.box.getGrid();
        }

        pub fn getFocus(self: *Diff(Widget, repo_kind, repo_opts)) *Focus {
            return self.box.getFocus();
        }

        pub fn clearDiffs(self: *Diff(Widget, repo_kind, repo_opts)) !void {
            // clear buffers
            for (self.bufs.items) |buf| {
                self.allocator.free(buf);
            }
            self.bufs.clearAndFree(self.allocator);

            // reset the arena
            self.file_iter = null;
            self.hunk_iter = null;
            _ = self.iter_arena.reset(.free_all);

            // remove old diff widgets
            for (self.box.children.values()[0].widget.scroll.child.box.children.values()) |*child| {
                child.widget.deinit();
            }
            self.box.children.values()[0].widget.scroll.child.box.children.clearAndFree(self.allocator);

            // reset scroll position
            const widget = &self.box.children.values()[0].widget;
            widget.scroll.x = 0;
            widget.scroll.y = 0;
        }

        pub fn addLines(self: *Diff(Widget, repo_kind, repo_opts), lines: []const []const u8) !void {
            const buf = blk: {
                var writer = std.Io.Writer.Allocating.init(self.allocator);
                errdefer writer.deinit();

                // add header
                for (lines) |line| {
                    try writer.writer.print("{s}\n", .{line});
                }

                break :blk try writer.toOwnedSlice();
            };

            // add buffer
            {
                errdefer self.allocator.free(buf);
                try self.bufs.append(self.allocator, buf);
            }

            // add new diff widget
            var text_box = try wgt.TextBox(Widget).init(self.allocator, buf, .hidden, .none);
            errdefer text_box.deinit();
            try self.box.children.values()[0].widget.scroll.child.box.children.put(self.allocator, text_box.getFocus().id, .{ .widget = .{ .text_box = text_box }, .rect = null, .min_size = null });
        }

        pub fn addHunk(
            self: *Diff(Widget, repo_kind, repo_opts),
            hunk_iter: *const df.HunkIterator(repo_kind, repo_opts),
            hunk: *const df.Hunk(repo_kind, repo_opts),
        ) !void {
            const buf = blk: {
                var writer = std.Io.Writer.Allocating.init(self.allocator);
                errdefer writer.deinit();

                // create buffer from hunk
                const offsets = hunk.offsets();
                try writer.writer.print("@@ -{},{} +{},{} @@\n", .{
                    offsets.del_start,
                    offsets.del_count,
                    offsets.ins_start,
                    offsets.ins_count,
                });
                for (hunk.edits.items) |edit| {
                    const line = switch (edit) {
                        .eql => |eql| try hunk_iter.line_iter_b.get(eql.new_line.num),
                        .ins => |ins| try hunk_iter.line_iter_b.get(ins.new_line.num),
                        .del => |del| try hunk_iter.line_iter_a.get(del.old_line.num),
                    };
                    defer switch (edit) {
                        .eql => hunk_iter.line_iter_b.free(line),
                        .ins => hunk_iter.line_iter_b.free(line),
                        .del => hunk_iter.line_iter_a.free(line),
                    };
                    try writer.writer.print("{s} {s}\n", .{
                        switch (edit) {
                            .eql => " ",
                            .ins => "+",
                            .del => "-",
                        },
                        line,
                    });
                }

                break :blk try writer.toOwnedSlice();
            };

            // add buffer
            {
                errdefer self.allocator.free(buf);
                try self.bufs.append(self.allocator, buf);
            }

            // add new diff widget
            var text_box = try wgt.TextBox(Widget).init(self.allocator, buf, .hidden, .none);
            errdefer text_box.deinit();
            try self.box.children.values()[0].widget.scroll.child.box.children.put(self.allocator, text_box.getFocus().id, .{ .widget = .{ .text_box = text_box }, .rect = null, .min_size = null });
        }

        pub fn getScrollX(self: Diff(Widget, repo_kind, repo_opts)) isize {
            return self.box.children.values()[0].widget.scroll.x;
        }

        pub fn getScrollY(self: Diff(Widget, repo_kind, repo_opts)) isize {
            return self.box.children.values()[0].widget.scroll.y;
        }

        pub fn isEmpty(self: Diff(Widget, repo_kind, repo_opts)) bool {
            return self.bufs.items.len == 0;
        }
    };
}
