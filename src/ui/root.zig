const std = @import("std");
const xitui = @import("xitui");
const wgt = xitui.widget;
const layout = xitui.layout;
const inp = xitui.input;
const Grid = xitui.grid.Grid;
const Focus = xitui.focus.Focus;
const ui_log = @import("./log.zig");
const ui_status = @import("./status.zig");
const ui_undo = @import("./undo.zig");
const ui_config = @import("./config.zig");
const rp = @import("../repo.zig");
const hash = @import("../hash.zig");

pub fn RootTabs(comptime Widget: type, comptime repo_kind: rp.RepoKind) type {
    return struct {
        box: wgt.Box(Widget),

        const FocusKind = enum { log, status, config, undo };

        pub fn init(allocator: std.mem.Allocator) !RootTabs(Widget, repo_kind) {
            var box = try wgt.Box(Widget).init(allocator, null, .horiz);
            errdefer box.deinit();

            inline for (@typeInfo(FocusKind).@"enum".fields) |focus_kind_field| {
                const focus_kind: FocusKind = @enumFromInt(focus_kind_field.value);
                const name = switch (focus_kind) {
                    .log => "log",
                    .status => "status",
                    .config => "config",
                    .undo => if (repo_kind == .xit) "undo" else continue,
                };
                var text_box = try wgt.TextBox(Widget).init(allocator, name, .single, .none);
                errdefer text_box.deinit();
                text_box.getFocus().focusable = true;
                try box.children.put(text_box.getFocus().id, .{ .widget = .{ .text_box = text_box }, .rect = null, .min_size = null });
            }

            var ui_root_tabs = RootTabs(Widget, repo_kind){
                .box = box,
            };
            ui_root_tabs.getFocus().child_id = box.children.keys()[0];
            return ui_root_tabs;
        }

        pub fn deinit(self: *RootTabs(Widget, repo_kind)) void {
            self.box.deinit();
        }

        pub fn build(self: *RootTabs(Widget, repo_kind), constraint: layout.Constraint, root_focus: *Focus) !void {
            self.clearGrid();
            for (self.box.children.keys(), self.box.children.values()) |id, *tab| {
                tab.widget.text_box.border_style = if (self.getFocus().child_id == id)
                    (if (root_focus.grandchild_id == id) .double else .single)
                else
                    .hidden;
            }
            try self.box.build(constraint, root_focus);
        }

        pub fn input(self: *RootTabs(Widget, repo_kind), key: inp.Key, root_focus: *Focus) !void {
            if (self.getFocus().child_id) |child_id| {
                const children = &self.box.children;
                if (children.getIndex(child_id)) |current_index| {
                    var index = current_index;

                    switch (key) {
                        .arrow_left => {
                            index -|= 1;
                        },
                        .arrow_right => {
                            if (index + 1 < self.box.children.count()) {
                                index += 1;
                            }
                        },
                        else => {},
                    }

                    if (index != current_index) {
                        try root_focus.setFocus(children.keys()[index]);
                    }
                }
            }
        }

        pub fn clearGrid(self: *RootTabs(Widget, repo_kind)) void {
            self.box.clearGrid();
        }

        pub fn getGrid(self: RootTabs(Widget, repo_kind)) ?Grid {
            return self.box.getGrid();
        }

        pub fn getFocus(self: *RootTabs(Widget, repo_kind)) *Focus {
            return self.box.getFocus();
        }

        pub fn getSelectedIndex(self: RootTabs(Widget, repo_kind)) ?usize {
            if (self.box.focus.child_id) |child_id| {
                const children = &self.box.children;
                return children.getIndex(child_id);
            } else {
                return null;
            }
        }

        pub fn getChildFocusId(self: *RootTabs(Widget, repo_kind), focus_kind: FocusKind) usize {
            return self.box.children.keys()[@intFromEnum(focus_kind)];
        }
    };
}

pub fn Root(comptime Widget: type, comptime repo_kind: rp.RepoKind, comptime repo_opts: rp.RepoOpts(repo_kind)) type {
    return struct {
        box: wgt.Box(Widget),

        const FocusKind = enum { tabs, stack };

        pub fn init(io: std.Io, allocator: std.mem.Allocator, repo: *rp.Repo(repo_kind, repo_opts)) !Root(Widget, repo_kind, repo_opts) {
            var box = try wgt.Box(Widget).init(allocator, null, .vert);
            errdefer box.deinit();

            inline for (@typeInfo(FocusKind).@"enum".fields) |focus_kind_field| {
                const focus_kind: FocusKind = @enumFromInt(focus_kind_field.value);
                switch (focus_kind) {
                    .tabs => {
                        var ui_root_tabs = try RootTabs(Widget, repo_kind).init(allocator);
                        errdefer ui_root_tabs.deinit();
                        try box.children.put(ui_root_tabs.getFocus().id, .{ .widget = .{ .ui_root_tabs = ui_root_tabs }, .rect = null, .min_size = null });
                    },
                    .stack => {
                        var stack = wgt.Stack(Widget).init(allocator);
                        errdefer stack.deinit();

                        {
                            var log = Widget{ .ui_log = try ui_log.Log(Widget, repo_kind, repo_opts).init(io, allocator, repo) };
                            errdefer log.deinit();
                            try stack.children.put(log.getFocus().id, log);
                        }

                        {
                            var status = Widget{ .ui_status = try ui_status.Status(Widget, repo_kind, repo_opts).init(io, allocator, repo) };
                            errdefer status.deinit();
                            try stack.children.put(status.getFocus().id, status);
                        }

                        {
                            var config = Widget{ .ui_config_list = try ui_config.ConfigList(Widget, repo_kind, repo_opts).init(io, allocator, repo) };
                            errdefer config.deinit();
                            try stack.children.put(config.getFocus().id, config);
                        }

                        if (repo_kind == .xit) {
                            var undo = Widget{ .ui_undo = try ui_undo.Undo(Widget, repo_kind, repo_opts).init(allocator, repo) };
                            errdefer undo.deinit();
                            try stack.children.put(undo.getFocus().id, undo);
                        }

                        try box.children.put(stack.getFocus().id, .{ .widget = .{ .stack = stack }, .rect = null, .min_size = null });
                    },
                }
            }

            var ui_root = Root(Widget, repo_kind, repo_opts){
                .box = box,
            };
            ui_root.getFocus().child_id = box.children.keys()[0];
            return ui_root;
        }

        pub fn deinit(self: *Root(Widget, repo_kind, repo_opts)) void {
            self.box.deinit();
        }

        pub fn build(self: *Root(Widget, repo_kind, repo_opts), constraint: layout.Constraint, root_focus: *Focus) !void {
            self.clearGrid();
            const ui_root_tabs = &self.box.children.values()[@intFromEnum(FocusKind.tabs)].widget.ui_root_tabs;
            const ui_root_stack = &self.box.children.values()[@intFromEnum(FocusKind.stack)].widget.stack;
            if (ui_root_tabs.getSelectedIndex()) |index| {
                ui_root_stack.getFocus().child_id = ui_root_stack.children.keys()[index];
            }
            try self.box.build(constraint, root_focus);
        }

        pub fn input(self: *Root(Widget, repo_kind, repo_opts), key: inp.Key, root_focus: *Focus) !void {
            if (self.getFocus().child_id) |child_id| {
                if (self.box.children.getIndex(child_id)) |current_index| {
                    const child = &self.box.children.values()[current_index].widget;
                    var index = current_index;

                    switch (key) {
                        .arrow_up => {
                            switch (child.*) {
                                .ui_root_tabs => {
                                    try child.input(key, root_focus);
                                },
                                .stack => |stack| {
                                    if (stack.getSelected()) |selected_widget| {
                                        switch (selected_widget.*) {
                                            .ui_log => {
                                                if (selected_widget.ui_log.scrolledToTop()) {
                                                    index = @intFromEnum(FocusKind.tabs);
                                                } else {
                                                    try child.input(key, root_focus);
                                                }
                                            },
                                            .ui_status => {
                                                if (selected_widget.ui_status.getSelectedIndex() == 0) {
                                                    index = @intFromEnum(FocusKind.tabs);
                                                } else {
                                                    try child.input(key, root_focus);
                                                }
                                            },
                                            .ui_undo => {
                                                if (selected_widget.ui_undo.scrolledToTop()) {
                                                    index = @intFromEnum(FocusKind.tabs);
                                                } else {
                                                    try child.input(key, root_focus);
                                                }
                                            },
                                            .ui_config_list => {
                                                if (selected_widget.ui_config_list.getSelectedIndex() == 0) {
                                                    index = @intFromEnum(FocusKind.tabs);
                                                } else {
                                                    try child.input(key, root_focus);
                                                }
                                            },
                                            else => {},
                                        }
                                    }
                                },
                                else => {},
                            }
                        },
                        .arrow_down => {
                            switch (child.*) {
                                .ui_root_tabs => {
                                    index = @intFromEnum(FocusKind.stack);
                                },
                                .stack => {
                                    try child.input(key, root_focus);
                                },
                                else => {},
                            }
                        },
                        else => {
                            try child.input(key, root_focus);
                        },
                    }

                    if (index != current_index) {
                        try root_focus.setFocus(self.box.children.keys()[index]);
                    }
                }
            }
        }

        pub fn clearGrid(self: *Root(Widget, repo_kind, repo_opts)) void {
            self.box.clearGrid();
        }

        pub fn getGrid(self: Root(Widget, repo_kind, repo_opts)) ?Grid {
            return self.box.getGrid();
        }

        pub fn getFocus(self: *Root(Widget, repo_kind, repo_opts)) *Focus {
            return self.box.getFocus();
        }
    };
}
