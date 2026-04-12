const std = @import("std");
const evaluator = @import("../evaluator.zig");
const evaluate = evaluator.evaluate;

// --- NotebookEdit tool protection (issue #9) ---

test "block NotebookEdit to .env file" {
    const r = evaluate(.{ .tool_name = "NotebookEdit", .tool_input = .{ .file_path = "/home/user/project/.env" } });
    try std.testing.expectEqual(.deny, r.decision);
}

test "block NotebookEdit to ssh key" {
    const r = evaluate(.{ .tool_name = "NotebookEdit", .tool_input = .{ .file_path = "/home/user/.ssh/id_rsa" } });
    try std.testing.expectEqual(.deny, r.decision);
}

test "block NotebookEdit to shell config" {
    const r = evaluate(.{ .tool_name = "NotebookEdit", .tool_input = .{ .file_path = "/home/user/.bashrc" } });
    try std.testing.expectEqual(.deny, r.decision);
}

test "block NotebookEdit to system path" {
    const r = evaluate(.{ .tool_name = "NotebookEdit", .tool_input = .{ .file_path = "/etc/passwd" } });
    try std.testing.expectEqual(.deny, r.decision);
}

test "block NotebookEdit to CI/CD config" {
    const r = evaluate(.{ .tool_name = "NotebookEdit", .tool_input = .{ .file_path = "/home/user/project/.github/workflows/ci.yml" } });
    try std.testing.expectEqual(.deny, r.decision);
}

test "allow NotebookEdit to normal notebook" {
    const r = evaluate(.{ .tool_name = "NotebookEdit", .tool_input = .{ .file_path = "/home/user/project/analysis.ipynb" } });
    try std.testing.expectEqual(.allow, r.decision);
}

test "allow NotebookEdit to normal python file" {
    const r = evaluate(.{ .tool_name = "NotebookEdit", .tool_input = .{ .file_path = "/home/user/project/script.py" } });
    try std.testing.expectEqual(.allow, r.decision);
}
