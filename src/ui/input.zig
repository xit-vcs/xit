const xitui = @import("xitui");
const Key = xitui.input.Key;
const Grid = xitui.grid.Grid;

/// the new selection index for a navigation key press in a scrollable list.
/// each list item is 3 rows tall, so page up/down moves by half the visible items.
pub fn vertIndex(key: Key, current_index: usize, count: usize, grid_maybe: ?Grid) usize {
    switch (key) {
        .arrow_up => return current_index -| 1,
        .arrow_down => if (current_index + 1 < count) {
            return current_index + 1;
        },
        .home => return 0,
        .end => if (count > 0) {
            return count - 1;
        },
        .page_up => if (grid_maybe) |grid| {
            const half_count = (grid.size.height / 3) / 2;
            return current_index -| half_count;
        },
        .page_down => if (grid_maybe) |grid| {
            if (count > 0) {
                const half_count = (grid.size.height / 3) / 2;
                return @min(current_index + half_count, count - 1);
            }
        },
        .mouse => |mouse| switch (mouse.action) {
            .scroll => |dir| switch (dir) {
                .up => return current_index -| 1,
                .down => if (current_index + 1 < count) {
                    return current_index + 1;
                },
            },
            else => {},
        },
        else => {},
    }
    return current_index;
}

/// the new focus index for a key press in a two-pane list-detail layout,
/// where 0 is the list and 1 is the detail. returns null if the key doesn't
/// switch panes and should be forwarded to the focused child instead.
/// arrow left only returns to the list when the detail isn't scrolled
/// horizontally, because the arrow keys also scroll the detail.
pub fn horizIndex(key: Key, list_focused: bool, diff_scroll_x: isize) ?usize {
    switch (key) {
        .arrow_left => if (!list_focused and diff_scroll_x == 0) {
            return 0;
        },
        .arrow_right => if (list_focused) {
            return 1;
        },
        .codepoint => |codepoint| switch (codepoint) {
            13 => if (list_focused) {
                return 1;
            },
            127, '\x1B' => if (!list_focused) {
                return 0;
            },
            else => {},
        },
        else => {},
    }
    return null;
}
