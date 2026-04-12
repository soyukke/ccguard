const std = @import("std");
const evaluator = @import("../evaluator.zig");
const evaluate = evaluator.evaluate;

// --- Redirect bypass detection (issue #2) ---

// BLOCK: redirect to shell config files
test "block echo redirect to bashrc" {
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "echo 'evil' > ~/.bashrc" } });
    try std.testing.expectEqual(.deny, r.decision);
}

test "block echo redirect to zshrc" {
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "echo 'evil' > ~/.zshrc" } });
    try std.testing.expectEqual(.deny, r.decision);
}

test "block printf redirect to gitconfig" {
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "printf 'evil' > ~/.gitconfig" } });
    try std.testing.expectEqual(.deny, r.decision);
}

test "block echo append to bash_profile" {
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "echo 'evil' >> ~/.bash_profile" } });
    try std.testing.expectEqual(.deny, r.decision);
}

test "block echo redirect to ssh config" {
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "echo 'evil' > ~/.ssh/config" } });
    try std.testing.expectEqual(.deny, r.decision);
}

test "block echo redirect to aws credentials" {
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "echo 'evil' > ~/.aws/credentials" } });
    try std.testing.expectEqual(.deny, r.decision);
}

test "block echo redirect to mcp.json" {
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "echo '{}' > .mcp.json" } });
    try std.testing.expectEqual(.deny, r.decision);
}

test "block echo redirect to claude settings" {
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "echo '{}' > .claude/settings.json" } });
    try std.testing.expectEqual(.deny, r.decision);
}

test "block echo redirect to /etc/hosts" {
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "echo '127.0.0.1 evil' > /etc/hosts" } });
    try std.testing.expectEqual(.deny, r.decision);
}

test "block echo redirect to CI/CD config" {
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "echo 'step: evil' > .github/workflows/ci.yml" } });
    try std.testing.expectEqual(.deny, r.decision);
}

// ALLOW: redirect to normal files (existing test preserved)
test "allow echo redirect to normal file" {
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "echo hello > /tmp/output.txt" } });
    try std.testing.expectEqual(.allow, r.decision);
}

test "allow echo redirect to project file" {
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "echo test > src/output.txt" } });
    try std.testing.expectEqual(.allow, r.decision);
}

// NOTE: FP cases like `gh issue create --body ".bashrc"` are blocked by
// containsPatternSafe because gh is not a safe_arg_command. This is a known
// limitation of the current design (see issue #2 discussion). The redirect
// checks added here solve the bypass direction; the FP direction requires
// a deeper architectural change.
