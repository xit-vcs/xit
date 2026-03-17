const std = @import("std");
const cmd = @import("./command.zig");
const xitui = @import("xitui");
const term = xitui.terminal;
const wgt = xitui.widget;
const layout = xitui.layout;
const inp = xitui.input;
const Grid = xitui.grid.Grid;
const Focus = xitui.focus.Focus;
const ui_root = @import("./ui/root.zig");
const ui_log = @import("./ui/log.zig");
const ui_diff = @import("./ui/diff.zig");
const ui_status = @import("./ui/status.zig");
const ui_undo = @import("./ui/undo.zig");
const ui_config = @import("./ui/config.zig");
const rp = @import("./repo.zig");
const hash = @import("./hash.zig");

pub fn Widget(comptime repo_kind: rp.RepoKind, comptime repo_opts: rp.RepoOpts(repo_kind)) type {
    return union(enum) {
        text: wgt.Text(Widget(repo_kind, repo_opts)),
        box: wgt.Box(Widget(repo_kind, repo_opts)),
        text_box: wgt.TextBox(Widget(repo_kind, repo_opts)),
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

        pub fn deinit(self: *Widget(repo_kind, repo_opts)) void {
            switch (self.*) {
                inline else => |*case| case.deinit(),
            }
        }

        pub fn build(self: *Widget(repo_kind, repo_opts), constraint: layout.Constraint, root_focus: *Focus) anyerror!void {
            switch (self.*) {
                inline else => |*case| try case.build(constraint, root_focus),
            }
        }

        pub fn input(self: *Widget(repo_kind, repo_opts), key: inp.Key, root_focus: *Focus) anyerror!void {
            switch (self.*) {
                inline else => |*case| try case.input(key, root_focus),
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
    errdefer root.deinit();

    // set initial focus for root widget
    try root.build(.{
        .min_size = .{ .width = null, .height = null },
        .max_size = .{ .width = 10, .height = 10 },
    }, root.getFocus());
    if (root.getFocus().child_id) |child_id| {
        try root.getFocus().setFocus(child_id);
    }

    // focus on the correct tab if sub command is provided
    if (cmd_kind_maybe) |cmd_kind| {
        const child_id_maybe = switch (cmd_kind) {
            .status, .diff_dir, .diff_added => root.ui_root.box.children.values()[0].widget.ui_root_tabs.getChildFocusId(.status),
            .log => root.ui_root.box.children.values()[0].widget.ui_root_tabs.getChildFocusId(.log),
            .config => root.ui_root.box.children.values()[0].widget.ui_root_tabs.getChildFocusId(.config),
            else => null,
        };
        if (child_id_maybe) |child_id| {
            try root.getFocus().setFocus(child_id);
        }
    }

    // if we're using this for UI testing, build the root widget several more times
    // to ensure that the content has a chance to load
    if (repo_opts.is_test) {
        for (0..5) |_| {
            try root.build(.{
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
    key: inp.Key,
) !void {
    try root.input(key, root.getFocus());

    // if we're using this for UI testing, build the root widget several more times
    // to ensure that the content has a chance to load
    if (repo_opts.is_test) {
        for (0..5) |_| {
            try root.build(.{
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
    defer root.deinit();

    // init term
    var terminal = try term.Terminal.init(io, allocator);
    defer terminal.deinit(io);

    var last_size = layout.Size{ .width = 0, .height = 0 };
    var last_grid = try Grid.init(allocator, last_size);
    defer last_grid.deinit();

    while (!term.quit) {
        // render to tty
        try terminal.render(&root, &last_grid, &last_size);

        // process any inputs
        while (try terminal.readKey(io)) |key| {
            switch (key) {
                .codepoint => |cp| if (cp == 'q') return,
                else => {},
            }
            try input(repo_kind, repo_opts, &root, key);
        }

        // rebuild widget
        try root.build(.{
            .min_size = .{ .width = null, .height = null },
            .max_size = .{ .width = last_size.width, .height = last_size.height },
        }, root.getFocus());

        // TODO: do variable sleep with target frame rate
        try std.Io.sleep(io, .fromMilliseconds(5), .real);
    }
}
