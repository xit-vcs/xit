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
            var box = try wgt.Box(Widget).init(allocator, null, .horiz);
            errdefer box.deinit();

            var name_text_box = try wgt.TextBox(Widget).init(allocator, full_name, .single, .none);
            errdefer name_text_box.deinit();
            name_text_box.getFocus().focusable = true;
            try box.children.put(name_text_box.getFocus().id, .{ .widget = .{ .text_box = name_text_box }, .rect = null, .min_size = .{ .width = 30, .height = null } });

            var value_text_box = try wgt.TextBox(Widget).init(allocator, value, .single, .none);
            errdefer value_text_box.deinit();
            value_text_box.getFocus().focusable = true;
            try box.children.put(value_text_box.getFocus().id, .{ .widget = .{ .text_box = value_text_box }, .rect = null, .min_size = .{ .width = 30, .height = null } });

            var self = ConfigListItem(Widget){
                .box = box,
            };
            self.getFocus().child_id = box.children.keys()[0];
            return self;
        }

        pub fn deinit(self: *ConfigListItem(Widget)) void {
            self.box.deinit();
        }

        pub fn build(self: *ConfigListItem(Widget), constraint: layout.Constraint, root_focus: *Focus) !void {
            self.clearGrid();
            for (self.box.children.keys(), self.box.children.values()) |id, *item| {
                item.widget.text_box.border_style = if (self.getFocus().child_id == id)
                    (if (root_focus.grandchild_id == id) .double_dashed else .single_dashed)
                else
                    .single_dashed;
            }
            try self.box.build(constraint, root_focus);
        }

        pub fn input(self: *ConfigListItem(Widget), key: inp.Key, root_focus: *Focus) !void {
            if (self.getFocus().child_id) |child_id| {
                const children = &self.box.children;
                if (children.getIndex(child_id)) |current_index| {
                    var index = current_index;

                    switch (key) {
                        .arrow_left => {
                            index -|= 1;
                        },
                        .arrow_right => {
                            if (index + 1 < children.count()) {
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

        pub fn clearGrid(self: *ConfigListItem(Widget)) void {
            self.box.clearGrid();
        }

        pub fn getGrid(self: ConfigListItem(Widget)) ?Grid {
            return self.box.getGrid();
        }

        pub fn getFocus(self: *ConfigListItem(Widget)) *Focus {
            return self.box.getFocus();
        }

        pub fn setBorder(self: *ConfigListItem(Widget), border_style: ?wgt.Box(Widget).BorderStyle) void {
            self.box.children.values()[1].widget.text_box.border_style = border_style;
        }
    };
}

pub fn ConfigList(comptime Widget: type, comptime repo_kind: rp.RepoKind, comptime repo_opts: rp.RepoOpts(repo_kind)) type {
    return struct {
        scroll: wgt.Scroll(Widget),
        config: cfg.Config(repo_kind, repo_opts),
        allocator: std.mem.Allocator,
        arena: *std.heap.ArenaAllocator,

        pub fn init(io: std.Io, allocator: std.mem.Allocator, repo: *rp.Repo(repo_kind, repo_opts)) !ConfigList(Widget, repo_kind, repo_opts) {
            var config = try repo.listConfig(io, allocator);
            errdefer config.deinit();

            const arena = try allocator.create(std.heap.ArenaAllocator);
            arena.* = std.heap.ArenaAllocator.init(allocator);
            errdefer {
                arena.deinit();
                allocator.destroy(arena);
            }

            // init box
            var inner_box = try wgt.Box(Widget).init(allocator, null, .vert);
            errdefer inner_box.deinit();

            for (config.sections.keys(), config.sections.values()) |section_name, variables| {
                for (variables.keys(), variables.values()) |name, value| {
                    const full_name = try std.fmt.allocPrint(arena.allocator(), "{s}.{s}", .{ section_name, name });
                    var config_item = try ConfigListItem(Widget).init(allocator, full_name, value);
                    try inner_box.children.put(config_item.getFocus().id, .{ .widget = .{ .ui_config_list_item = config_item }, .rect = null, .min_size = null });
                }
            }

            // init scroll
            var scroll = try wgt.Scroll(Widget).init(allocator, .{ .box = inner_box }, .vert);
            errdefer scroll.deinit();
            if (inner_box.children.count() > 0) {
                scroll.getFocus().child_id = inner_box.children.keys()[0];
            }

            return ConfigList(Widget, repo_kind, repo_opts){
                .scroll = scroll,
                .config = config,
                .allocator = allocator,
                .arena = arena,
            };
        }

        pub fn deinit(self: *ConfigList(Widget, repo_kind, repo_opts)) void {
            self.scroll.deinit();
            self.config.deinit();
            self.arena.deinit();
            self.allocator.destroy(self.arena);
        }

        pub fn build(self: *ConfigList(Widget, repo_kind, repo_opts), constraint: layout.Constraint, root_focus: *Focus) !void {
            self.clearGrid();
            try self.scroll.build(constraint, root_focus);
        }

        pub fn input(self: *ConfigList(Widget, repo_kind, repo_opts), key: inp.Key, root_focus: *Focus) !void {
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
                        else => {
                            try children.values()[index].widget.input(key, root_focus);
                        },
                    }

                    if (index != current_index) {
                        try root_focus.setFocus(children.keys()[index]);
                        self.updateScroll(index);
                    }
                }
            }
        }

        pub fn clearGrid(self: *ConfigList(Widget, repo_kind, repo_opts)) void {
            self.scroll.clearGrid();
        }

        pub fn getGrid(self: ConfigList(Widget, repo_kind, repo_opts)) ?Grid {
            return self.scroll.getGrid();
        }

        pub fn getFocus(self: *ConfigList(Widget, repo_kind, repo_opts)) *Focus {
            return self.scroll.getFocus();
        }

        pub fn getSelectedIndex(self: ConfigList(Widget, repo_kind, repo_opts)) ?usize {
            if (self.scroll.child.box.focus.child_id) |child_id| {
                const children = &self.scroll.child.box.children;
                return children.getIndex(child_id);
            } else {
                return null;
            }
        }

        fn updateScroll(self: *ConfigList(Widget, repo_kind, repo_opts), index: usize) void {
            const box = &self.scroll.child.box;
            if (box.children.values()[index].rect) |rect| {
                self.scroll.scrollToRect(rect);
            }
        }
    };
}
