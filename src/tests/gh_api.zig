const std = @import("std");
const evaluator = @import("../evaluator.zig");
const evaluate = evaluator.evaluate;

// --- gh api write detection (issue #55 fix) ---

// Block: write operations via gh api
test "block gh api POST" {
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "gh api /repos/owner/repo/issues -X POST -f body=secret" } });
    try std.testing.expectEqual(.deny, r.decision);
}

test "block gh api PUT" {
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "gh api /repos/owner/repo/issues/1 -X PUT -f state=closed" } });
    try std.testing.expectEqual(.deny, r.decision);
}

test "block gh api DELETE" {
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "gh api /repos/owner/repo/issues/1 -X DELETE" } });
    try std.testing.expectEqual(.deny, r.decision);
}

test "block gh api PATCH" {
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "gh api /repos/owner/repo/issues/1 -X PATCH -f title=evil" } });
    try std.testing.expectEqual(.deny, r.decision);
}

test "block gh api with -f field" {
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "gh api /repos/owner/repo/issues -f body=secret_data" } });
    try std.testing.expectEqual(.deny, r.decision);
}

test "block gh api with --field" {
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "gh api /repos/owner/repo/issues --field body=data" } });
    try std.testing.expectEqual(.deny, r.decision);
}

test "block gh api with --input" {
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "gh api /repos/owner/repo/issues --input data.json" } });
    try std.testing.expectEqual(.deny, r.decision);
}

test "block gh api --method POST" {
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "gh api /repos/owner/repo/issues --method POST" } });
    try std.testing.expectEqual(.deny, r.decision);
}

// Allow: read-only operations via gh api
test "allow gh api GET repos" {
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "gh api /repos/owner/repo" } });
    try std.testing.expectEqual(.allow, r.decision);
}

test "allow gh api GET issues" {
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "gh api /repos/owner/repo/issues" } });
    try std.testing.expectEqual(.allow, r.decision);
}

test "allow gh api GET pr comments" {
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "gh api repos/owner/repo/pulls/123/comments" } });
    try std.testing.expectEqual(.allow, r.decision);
}

test "allow gh api with jq" {
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "gh api /repos/owner/repo/issues --jq '.[].title'" } });
    try std.testing.expectEqual(.allow, r.decision);
}

test "allow gh issue list" {
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "gh issue list" } });
    try std.testing.expectEqual(.allow, r.decision);
}

test "allow gh pr view" {
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "gh pr view 123" } });
    try std.testing.expectEqual(.allow, r.decision);
}

test "allow echo mentioning gh api" {
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "echo 'use gh api to fetch data'" } });
    try std.testing.expectEqual(.allow, r.decision);
}
