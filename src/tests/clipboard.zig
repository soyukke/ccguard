const std = @import("std");
const evaluator = @import("../evaluator.zig");
const evaluate = evaluator.evaluate;

// --- Clipboard read blocking (issue #19) ---

test "block pbpaste" {
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "pbpaste" } });
    try std.testing.expectEqual(.deny, r.decision);
}

test "block pbcopy" {
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "pbcopy < /tmp/data" } });
    try std.testing.expectEqual(.deny, r.decision);
}

test "block xclip" {
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "xclip -selection clipboard -o" } });
    try std.testing.expectEqual(.deny, r.decision);
}

test "block xsel" {
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "xsel --clipboard --output" } });
    try std.testing.expectEqual(.deny, r.decision);
}

test "block wl-paste" {
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "wl-paste" } });
    try std.testing.expectEqual(.deny, r.decision);
}

test "block wl-copy" {
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "wl-copy < /tmp/data" } });
    try std.testing.expectEqual(.deny, r.decision);
}

// FP prevention
test "allow echo pbpaste" {
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "echo pbpaste is a macOS command" } });
    try std.testing.expectEqual(.allow, r.decision);
}

test "allow grep xclip" {
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "grep xclip README.md" } });
    try std.testing.expectEqual(.allow, r.decision);
}
