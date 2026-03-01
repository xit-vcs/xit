const std = @import("std");
const xitui = @import("xitui");
const wgt = xitui.widget;
const layout = xitui.layout;
const inp = xitui.input;
const Grid = xitui.grid.Grid;
const Focus = xitui.focus.Focus;
const ui_diff = @import("./diff.zig");
const rp = @import("../repo.zig");
const hash = @import("../hash.zig");
const df = @import("../diff.zig");
const obj = @import("../object.zig");
const tr = @import("../tree.zig");

pub fn LogCommitList(comptime Widget: type, comptime repo_kind: rp.RepoKind, comptime repo_opts: rp.RepoOpts(repo_kind)) type {
    return struct {
        allocator: std.mem.Allocator,
        scroll: wgt.Scroll(Widget),
        repo: *rp.Repo(repo_kind, repo_opts),
        commit_iter: obj.ObjectIterator(repo_kind, repo_opts, .full),
        commits: std.ArrayList(obj.Object(repo_kind, repo_opts, .full)),

        pub fn init(io: std.Io, allocator: std.mem.Allocator, repo: *rp.Repo(repo_kind, repo_opts)) !LogCommitList(Widget, repo_kind, repo_opts) {
            var self = blk: {
                // init commits
                var commits = std.ArrayList(obj.Object(repo_kind, repo_opts, .full)){};
                errdefer {
                    for (commits.items) |*commit| {
                        commit.deinit();
                    }
                    commits.deinit(allocator);
                }

                // walk the commits
                var commit_iter = try repo.log(io, allocator, null);
                errdefer commit_iter.deinit();

                var inner_box = try wgt.Box(Widget).init(allocator, null, .vert);
                errdefer inner_box.deinit();

                // init scroll
                var scroll = try wgt.Scroll(Widget).init(allocator, .{ .box = inner_box }, .vert);
                errdefer scroll.deinit();

                break :blk LogCommitList(Widget, repo_kind, repo_opts){
                    .allocator = allocator,
                    .scroll = scroll,
                    .repo = repo,
                    .commit_iter = commit_iter,
                    .commits = commits,
                };
            };
            errdefer self.deinit();

            try self.addCommits(20);
            if (self.scroll.child.box.children.count() > 0) {
                self.scroll.getFocus().child_id = self.scroll.child.box.children.keys()[0];
            }

            return self;
        }

        pub fn deinit(self: *LogCommitList(Widget, repo_kind, repo_opts)) void {
            for (self.commits.items) |*commit_object| {
                commit_object.deinit();
            }
            self.commit_iter.deinit();
            self.commits.deinit(self.allocator);
            self.scroll.deinit();
        }

        pub fn build(self: *LogCommitList(Widget, repo_kind, repo_opts), constraint: layout.Constraint, root_focus: *Focus) !void {
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
                        try self.addCommits(20);
                    }
                }
            }
        }

        pub fn input(self: *LogCommitList(Widget, repo_kind, repo_opts), key: inp.Key, root_focus: *Focus) !void {
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

        pub fn clearGrid(self: *LogCommitList(Widget, repo_kind, repo_opts)) void {
            self.scroll.clearGrid();
        }

        pub fn getGrid(self: LogCommitList(Widget, repo_kind, repo_opts)) ?Grid {
            return self.scroll.getGrid();
        }

        pub fn getFocus(self: *LogCommitList(Widget, repo_kind, repo_opts)) *Focus {
            return self.scroll.getFocus();
        }

        pub fn getSelectedIndex(self: LogCommitList(Widget, repo_kind, repo_opts)) ?usize {
            if (self.scroll.child.box.focus.child_id) |child_id| {
                const children = &self.scroll.child.box.children;
                return children.getIndex(child_id);
            } else {
                return null;
            }
        }

        fn updateScroll(self: *LogCommitList(Widget, repo_kind, repo_opts), index: usize) void {
            const left_box = &self.scroll.child.box;
            if (left_box.children.values()[index].rect) |rect| {
                self.scroll.scrollToRect(rect);
            }
        }

        fn addCommits(self: *LogCommitList(Widget, repo_kind, repo_opts), max_commits: usize) !void {
            for (0..max_commits) |_| {
                if (try self.commit_iter.next()) |commit_object| {
                    {
                        errdefer commit_object.deinit();
                        try self.commits.append(self.allocator, commit_object.*);
                    }

                    const inner_box = &self.scroll.child.box;
                    const line = commit_object.content.commit.metadata.message orelse "(empty message)";
                    var text_box = try wgt.TextBox(Widget).init(self.allocator, line, .hidden, .none);
                    errdefer text_box.deinit();
                    text_box.getFocus().focusable = true;
                    try inner_box.children.put(text_box.getFocus().id, .{ .widget = .{ .text_box = text_box }, .rect = null, .min_size = null });
                } else {
                    break;
                }
            }
        }
    };
}

pub fn Log(comptime Widget: type, comptime repo_kind: rp.RepoKind, comptime repo_opts: rp.RepoOpts(repo_kind)) type {
    return struct {
        box: wgt.Box(Widget),
        repo: *rp.Repo(repo_kind, repo_opts),
        io: std.Io,
        allocator: std.mem.Allocator,

        pub fn init(io: std.Io, allocator: std.mem.Allocator, repo: *rp.Repo(repo_kind, repo_opts)) !Log(Widget, repo_kind, repo_opts) {
            var box = try wgt.Box(Widget).init(allocator, null, .horiz);
            errdefer box.deinit();

            // add commit list
            {
                var commit_list = try LogCommitList(Widget, repo_kind, repo_opts).init(io, allocator, repo);
                errdefer commit_list.deinit();
                try box.children.put(commit_list.getFocus().id, .{ .widget = .{ .ui_log_commit_list = commit_list }, .rect = null, .min_size = .{ .width = 30, .height = null } });
            }

            // add diff
            {
                var diff = Widget{ .ui_diff = try ui_diff.Diff(Widget, repo_kind, repo_opts).init(allocator, repo) };
                errdefer diff.deinit();
                diff.getFocus().focusable = true;
                try box.children.put(diff.getFocus().id, .{ .widget = diff, .rect = null, .min_size = .{ .width = 60, .height = null } });
            }

            var git_log = Log(Widget, repo_kind, repo_opts){
                .box = box,
                .repo = repo,
                .io = io,
                .allocator = allocator,
            };
            git_log.getFocus().child_id = box.children.keys()[0];
            try git_log.updateDiff();

            return git_log;
        }

        pub fn deinit(self: *Log(Widget, repo_kind, repo_opts)) void {
            self.box.deinit();
        }

        pub fn build(self: *Log(Widget, repo_kind, repo_opts), constraint: layout.Constraint, root_focus: *Focus) !void {
            self.clearGrid();
            try self.box.build(constraint, root_focus);
        }

        pub fn input(self: *Log(Widget, repo_kind, repo_opts), key: inp.Key, root_focus: *Focus) !void {
            const diff_scroll_x = self.box.children.values()[1].widget.ui_diff.box.children.values()[0].widget.scroll.x;

            if (self.getFocus().child_id) |child_id| {
                if (self.box.children.getIndex(child_id)) |current_index| {
                    const child = &self.box.children.values()[current_index].widget;

                    const index = blk: {
                        switch (key) {
                            .arrow_left => {
                                if (child.* == .ui_diff and diff_scroll_x == 0) {
                                    break :blk 0;
                                }
                            },
                            .arrow_right => {
                                if (child.* == .ui_log_commit_list) {
                                    break :blk 1;
                                }
                            },
                            .codepoint => |codepoint| {
                                switch (codepoint) {
                                    13 => {
                                        if (child.* == .ui_log_commit_list) {
                                            break :blk 1;
                                        }
                                    },
                                    127, '\x1B' => {
                                        if (child.* == .ui_diff) {
                                            break :blk 0;
                                        }
                                    },
                                    else => {},
                                }
                            },
                            else => {},
                        }
                        try child.input(key, root_focus);
                        if (child.* == .ui_log_commit_list) {
                            try self.updateDiff();
                        }
                        break :blk current_index;
                    };

                    if (index != current_index) {
                        try root_focus.setFocus(self.box.children.keys()[index]);
                    }
                }
            }
        }

        pub fn clearGrid(self: *Log(Widget, repo_kind, repo_opts)) void {
            self.box.clearGrid();
        }

        pub fn getGrid(self: Log(Widget, repo_kind, repo_opts)) ?Grid {
            return self.box.getGrid();
        }

        pub fn getFocus(self: *Log(Widget, repo_kind, repo_opts)) *Focus {
            return self.box.getFocus();
        }

        pub fn scrolledToTop(self: Log(Widget, repo_kind, repo_opts)) bool {
            if (self.box.focus.child_id) |child_id| {
                if (self.box.children.getIndex(child_id)) |current_index| {
                    const child = &self.box.children.values()[current_index].widget;
                    switch (child.*) {
                        .ui_log_commit_list => |child_ui_log_commit_list| {
                            const commit_list = &child_ui_log_commit_list;
                            if (commit_list.getSelectedIndex()) |commit_index| {
                                return commit_index == 0;
                            }
                        },
                        .ui_diff => |child_ui_diff| {
                            const diff = &child_ui_diff;
                            return diff.getScrollY() == 0;
                        },
                        else => {},
                    }
                }
            }
            return true;
        }

        fn updateDiff(self: *Log(Widget, repo_kind, repo_opts)) !void {
            const commit_list = &self.box.children.values()[0].widget.ui_log_commit_list;
            if (commit_list.getSelectedIndex()) |commit_index| {
                const commit_object = commit_list.commits.items[commit_index];

                const commit_oid = &commit_object.oid;
                const parent_oid_maybe = commit_object.content.commit.metadata.firstParent();

                var diff = &self.box.children.values()[1].widget.ui_diff;
                try diff.clearDiffs();

                const tree_diff = try diff.iter_arena.allocator().create(tr.TreeDiff(repo_kind, repo_opts));
                tree_diff.* = try self.repo.treeDiff(self.io, diff.iter_arena.allocator(), parent_oid_maybe, commit_oid);

                diff.file_iter = try self.repo.filePairs(self.io, diff.iter_arena.allocator(), .{ .tree = .{ .tree_diff = tree_diff } });
            }
        }
    };
}
