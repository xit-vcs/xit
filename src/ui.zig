const std = @import("std");
const cmd = @import("./command.zig");
const xitui = @import("xitui");
const term = xitui.terminal;
const wgt = xitui.widget;
const layout = xitui.layout;
const Key = xitui.input.Key;
const Grid = xitui.grid.Grid;
const Focus = xitui.focus.Focus;
const ui_root = @import("./ui/root.zig");
const ui_log = @import("./ui/log.zig");
const ui_diff = @import("./ui/diff.zig");
const ui_status = @import("./ui/status.zig");
const ui_undo = @import("./ui/undo.zig");
const ui_config = @import("./ui/config.zig");
const rp = @import("./repo.zig");

// shared by the widgets and their host for the lifetime of the root widget.
pub const Session = struct {
    pending: ?Action = null,

    pub const Action = union(enum) { gc, undo: u64 };

    // widgets queue requests during input; the host applies them after rendering.
    pub fn applyPending(
        self: *Session,
        comptime repo_kind: rp.RepoKind,
        comptime repo_opts: rp.RepoOpts(repo_kind),
        repo: *rp.Repo(repo_kind, repo_opts),
        io: std.Io,
        allocator: std.mem.Allocator,
    ) !void {
        const action = self.pending orelse return;
        defer self.pending = null;
        switch (action) {
            .gc => if (repo_kind == .xit) {
                _ = try repo.garbageCollect(io, allocator, .{});
            },
            .undo => |history_index| if (repo_kind == .xit) {
                try repo.undo(io, history_index);
            },
        }
    }
};

pub fn Widget(comptime repo_kind: rp.RepoKind, comptime repo_opts: rp.RepoOpts(repo_kind)) type {
    return union(enum) {
        text: wgt.Text,
        box: wgt.Box(Widget(repo_kind, repo_opts)),
        text_box: wgt.TextBox,
        text_input: wgt.TextInput,
        scroll: wgt.Scroll(Widget(repo_kind, repo_opts)),
        stack: wgt.Stack(Widget(repo_kind, repo_opts)),
        ui_root: ui_root.Root(Widget(repo_kind, repo_opts), repo_kind, repo_opts),
        ui_root_tabs: ui_root.RootTabs(Widget(repo_kind, repo_opts), repo_kind),
        ui_log: ui_log.Log(Widget(repo_kind, repo_opts), repo_kind, repo_opts),
        ui_log_commit_list: ui_log.LogCommitList(Widget(repo_kind, repo_opts), repo_kind, repo_opts),
        ui_diff: ui_diff.Diff(Widget(repo_kind, repo_opts), repo_kind, repo_opts),
        ui_status: ui_status.Status(Widget(repo_kind, repo_opts), repo_kind, repo_opts),
        ui_status_content: ui_status.StatusContent(Widget(repo_kind, repo_opts), repo_kind, repo_opts),
        ui_status_tabs: ui_status.StatusTabs(Widget(repo_kind, repo_opts), repo_kind, repo_opts),
        ui_status_list: ui_status.StatusList(Widget(repo_kind, repo_opts)),
        ui_status_list_item: ui_status.StatusListItem(Widget(repo_kind, repo_opts)),
        ui_undo: ui_undo.Undo(Widget(repo_kind, repo_opts), repo_kind, repo_opts),
        ui_undo_list: ui_undo.UndoList(Widget(repo_kind, repo_opts), repo_kind, repo_opts),
        ui_config_list: ui_config.ConfigList(Widget(repo_kind, repo_opts), repo_kind, repo_opts),
        ui_config_list_item: ui_config.ConfigListItem(Widget(repo_kind, repo_opts)),
        ui_config_add_list_item: ui_config.ConfigAddListItem(Widget(repo_kind, repo_opts)),

        pub fn deinit(self: *Widget(repo_kind, repo_opts), allocator: std.mem.Allocator) void {
            switch (self.*) {
                inline else => |*case| case.deinit(allocator),
            }
        }

        pub fn build(self: *Widget(repo_kind, repo_opts), allocator: std.mem.Allocator, constraint: layout.Constraint, root_focus: *Focus) anyerror!void {
            switch (self.*) {
                inline else => |*case| try case.build(allocator, constraint, root_focus),
            }
        }

        pub fn input(self: *Widget(repo_kind, repo_opts), allocator: std.mem.Allocator, key: Key, root_focus: *Focus) anyerror!void {
            switch (self.*) {
                inline else => |*case| try case.input(allocator, key, root_focus),
            }
        }

        pub fn clearGrid(self: *Widget(repo_kind, repo_opts)) void {
            switch (self.*) {
                inline else => |*case| case.clearGrid(),
            }
        }

        pub fn getGrid(self: Widget(repo_kind, repo_opts)) ?Grid {
            switch (self) {
                inline else => |*case| return case.getGrid(),
            }
        }

        pub fn getFocus(self: *Widget(repo_kind, repo_opts)) *Focus {
            switch (self.*) {
                inline else => |*case| return case.getFocus(),
            }
        }
    };
}

pub fn rootWidget(
    comptime repo_kind: rp.RepoKind,
    comptime repo_opts: rp.RepoOpts(repo_kind),
    repo: *rp.Repo(repo_kind, repo_opts),
    io: std.Io,
    allocator: std.mem.Allocator,
    cmd_kind_maybe: ?cmd.CommandKind,
) !Widget(repo_kind, repo_opts) {
    var root = Widget(repo_kind, repo_opts){ .ui_root = try ui_root.Root(Widget(repo_kind, repo_opts), repo_kind, repo_opts).init(io, allocator, repo) };
    errdefer root.deinit(allocator);

    // build once so the root settles focus onto its initial child
    try root.build(allocator, .{
        .min_size = .{ .width = null, .height = null },
        .max_size = .{ .width = 10, .height = 10 },
    }, root.getFocus());

    // focus on the correct tab if sub command is provided
    if (cmd_kind_maybe) |cmd_kind| {
        const child_id_maybe = switch (cmd_kind) {
            .status, .diff_dir, .diff_added => root.ui_root.getTabs().getChildFocusId(.status) orelse return error.BareRepository,
            .log => root.ui_root.getTabs().getChildFocusId(.log),
            .config => root.ui_root.getTabs().getChildFocusId(.config),
            else => null,
        };
        if (child_id_maybe) |child_id| {
            root.getFocus().setFocus(child_id);
        }
    }

    // if we're using this for UI testing, build the root widget several more times
    // to ensure that the content has a chance to load
    if (repo_opts.is_test) {
        for (0..5) |_| {
            try root.build(allocator, .{
                .min_size = .{ .width = null, .height = null },
                .max_size = .{ .width = 100, .height = 50 },
            }, root.getFocus());
        }
    }

    return root;
}

pub fn input(
    comptime repo_kind: rp.RepoKind,
    comptime repo_opts: rp.RepoOpts(repo_kind),
    root: *Widget(repo_kind, repo_opts),
    allocator: std.mem.Allocator,
    key: Key,
) !void {
    try root.input(allocator, key, root.getFocus());

    // if we're using this for UI testing, build the root widget several more times
    // to ensure that the content has a chance to load
    if (repo_opts.is_test) {
        for (0..5) |_| {
            try root.build(allocator, .{
                .min_size = .{ .width = null, .height = null },
                .max_size = .{ .width = 100, .height = 50 },
            }, root.getFocus());
        }
    }
}

pub fn start(
    comptime repo_kind: rp.RepoKind,
    comptime repo_opts: rp.RepoOpts(repo_kind),
    repo: *rp.Repo(repo_kind, repo_opts),
    io: std.Io,
    allocator: std.mem.Allocator,
    cmd_kind_maybe: ?cmd.CommandKind,
) !void {
    // init root widget
    var root = try rootWidget(repo_kind, repo_opts, repo, io, allocator, cmd_kind_maybe);
    defer root.deinit(allocator);

    // init term
    var terminal = try term.Terminal.init(io, allocator);
    defer terminal.deinit(io);

    // set term as active so it will be properly cooked
    // when a panic/segfault happens
    term.setActive(&terminal);
    defer term.setActive(null);

    while (!term.quit.load(.monotonic)) {
        // render to tty
        const grid_changed = try terminal.render(&root);

        // process any inputs.
        //
        // if the grid didn't change, then first do a blocking
        // read, so the thread will sleep until further input.
        // after that, all remaining reads are non-blocking so
        // we can process the rest of the queued inputs.
        //
        // if the grid *did* change, then only do non-blocking
        // reads. we do not want to sleep the thread because
        // there may be an animation that requires more looping.
        var blocking = !grid_changed;
        while (try terminal.readKey(io, blocking)) |key| {
            blocking = false;
            switch (key) {
                .escape => return,
                .ctrl => |letter| switch (letter) {
                    // ctrl+r: refresh by reopening the repo and recreating
                    // the root widget, preserving the currently selected tab
                    'r' => {
                        const new_repo = try rp.Repo(repo_kind, repo_opts).open(io, allocator, .{
                            .cwd_path = repo.core.cwd_path,
                            .path = repo.core.work_path,
                            .global_config_path = repo.core.global_config_path,
                        });
                        repo.deinit(io, allocator);
                        repo.* = new_repo;

                        try refreshRoot(repo_kind, repo_opts, &root, repo, io, allocator, terminal.size, .{
                            .tab = root.ui_root.getTabs().getSelectedKind(),
                        });
                    },
                    else => try root.input(allocator, key, root.getFocus()),
                },
                .mouse => |mouse| {
                    if (mouse.action == .press and mouse.action.press == .left) {
                        const root_focus = root.getFocus();
                        if (root_focus.hitTest(mouse.x, mouse.y)) |hit| root_focus.setFocus(hit.id);
                    }
                    try root.input(allocator, key, root.getFocus());
                },
                else => try root.input(allocator, key, root.getFocus()),
            }
            // render the action before processing more queued input, including
            // double-clicks or a tab change that would hide the busy label.
            if (root.ui_root.session.pending != null) break;
        }

        if (root.ui_root.session.pending != null) {
            // show the busy label before applying long-running actions.
            try root.build(allocator, .{
                .min_size = .{ .width = null, .height = null },
                .max_size = .{ .width = terminal.size.width, .height = terminal.size.height },
            }, root.getFocus());
            _ = try terminal.render(&root);
            try applyPendingActions(repo_kind, repo_opts, &root, repo, io, allocator, terminal.size);
        }

        // rebuild widget
        try root.build(allocator, .{
            .min_size = .{ .width = null, .height = null },
            .max_size = .{ .width = terminal.size.width, .height = terminal.size.height },
        }, root.getFocus());
    }
}

// apply widget requests and refresh views whose database cursors are now stale.
pub fn applyPendingActions(
    comptime repo_kind: rp.RepoKind,
    comptime repo_opts: rp.RepoOpts(repo_kind),
    root: *Widget(repo_kind, repo_opts),
    repo: *rp.Repo(repo_kind, repo_opts),
    io: std.Io,
    allocator: std.mem.Allocator,
    size: layout.Size,
) !void {
    const session = root.ui_root.session;
    const action = session.pending orelse return;
    try session.applyPending(repo_kind, repo_opts, repo, io, allocator);
    try refreshRoot(repo_kind, repo_opts, root, repo, io, allocator, size, switch (action) {
        .gc => .undo_buttons,
        .undo => .undo_list,
    });
}

pub fn refreshRoot(
    comptime repo_kind: rp.RepoKind,
    comptime repo_opts: rp.RepoOpts(repo_kind),
    root: *Widget(repo_kind, repo_opts),
    repo: *rp.Repo(repo_kind, repo_opts),
    io: std.Io,
    allocator: std.mem.Allocator,
    size: layout.Size,
    focus: union(enum) { tab: ?ui_root.TabKind, undo_buttons, undo_list },
) !void {
    // rebuild all views to read the restored state after undo, or to replace
    // database cursors invalidated by compaction.
    var refreshed = Widget(repo_kind, repo_opts){ .ui_root = try ui_root.Root(Widget(repo_kind, repo_opts), repo_kind, repo_opts).init(io, allocator, repo) };
    errdefer refreshed.deinit(allocator);
    const tabs = refreshed.ui_root.getTabs();
    const tab_kind = switch (focus) {
        .tab => |kind| kind,
        .undo_buttons, .undo_list => .undo,
    };
    if (tab_kind) |kind| {
        if (tabs.getChildFocusId(kind)) |id| tabs.getFocus().child_id = id;
    }
    if (focus != .tab) {
        const stack = refreshed.ui_root.getStack();
        refreshed.getFocus().child_id = stack.getFocus().id;
        if (focus == .undo_list) {
            stack.children.values()[tabs.getSelectedIndex().?].ui_undo.focusList(refreshed.getFocus());
        }
    }
    try refreshed.build(allocator, .{
        .min_size = .{ .width = null, .height = null },
        .max_size = .{ .width = size.width, .height = size.height },
    }, refreshed.getFocus());

    root.deinit(allocator);
    root.* = refreshed;
}
