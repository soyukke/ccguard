const std = @import("std");
const evaluator = @import("../evaluator.zig");
const evaluate = evaluator.evaluate;

// --- Shell history and Claude internal data protection (issue #21) ---

// BLOCK: shell history files
test "block Read .bash_history" {
    const r = evaluate(.{ .tool_name = "Read", .tool_input = .{ .file_path = "/home/user/.bash_history" } });
    try std.testing.expectEqual(.deny, r.decision);
}

test "block Read .zsh_history" {
    const r = evaluate(.{ .tool_name = "Read", .tool_input = .{ .file_path = "/home/user/.zsh_history" } });
    try std.testing.expectEqual(.deny, r.decision);
}

test "block Read .node_repl_history" {
    const r = evaluate(.{ .tool_name = "Read", .tool_input = .{ .file_path = "/home/user/.node_repl_history" } });
    try std.testing.expectEqual(.deny, r.decision);
}

test "block Read .python_history" {
    const r = evaluate(.{ .tool_name = "Read", .tool_input = .{ .file_path = "/home/user/.python_history" } });
    try std.testing.expectEqual(.deny, r.decision);
}

test "block Read .psql_history" {
    const r = evaluate(.{ .tool_name = "Read", .tool_input = .{ .file_path = "/home/user/.psql_history" } });
    try std.testing.expectEqual(.deny, r.decision);
}

test "block Read .mysql_history" {
    const r = evaluate(.{ .tool_name = "Read", .tool_input = .{ .file_path = "/home/user/.mysql_history" } });
    try std.testing.expectEqual(.deny, r.decision);
}

// BLOCK: Claude internal data
test "block Read .claude/history.jsonl" {
    const r = evaluate(.{ .tool_name = "Read", .tool_input = .{ .file_path = "/home/user/.claude/history.jsonl" } });
    try std.testing.expectEqual(.deny, r.decision);
}

// ALLOW: non-history files
test "allow Read history.txt" {
    const r = evaluate(.{ .tool_name = "Read", .tool_input = .{ .file_path = "/home/user/project/history.txt" } });
    try std.testing.expectEqual(.allow, r.decision);
}

test "allow Read .claude project dir" {
    const r = evaluate(.{ .tool_name = "Read", .tool_input = .{ .file_path = "/home/user/project/.claude/settings.json" } });
    try std.testing.expectEqual(.allow, r.decision);
}
