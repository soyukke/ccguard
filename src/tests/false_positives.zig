const std = @import("std");
const evaluator = @import("../evaluator.zig");
const evaluate = evaluator.evaluate;

test "allow npm run build" {
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "npm run build" } });
    try std.testing.expectEqual(.allow, r.decision);
}

test "allow cargo test" {
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "cargo test" } });
    try std.testing.expectEqual(.allow, r.decision);
}

test "allow env in variable name" {
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "echo $ENVIRONMENT" } });
    try std.testing.expectEqual(.allow, r.decision);
}

test "allow git push normal" {
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "git push origin main" } });
    try std.testing.expectEqual(.allow, r.decision);
}

test "allow editing normal source file" {
    const r = evaluate(.{ .tool_name = "Edit", .tool_input = .{ .file_path = "/Users/user/project/src/app.ts" } });
    try std.testing.expectEqual(.allow, r.decision);
}

test "allow direnv exec" {
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "direnv exec . vhs --version" } });
    try std.testing.expectEqual(.allow, r.decision);
}

test "allow direnv allow" {
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "direnv allow" } });
    try std.testing.expectEqual(.allow, r.decision);
}

test "allow echo security" {
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "echo security review done" } });
    try std.testing.expectEqual(.allow, r.decision);
}

test "block security find-generic-password still works" {
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "security find-generic-password -s myservice" } });
    try std.testing.expectEqual(.deny, r.decision);
}

test "block security bare command" {
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "security" } });
    try std.testing.expectEqual(.deny, r.decision);
}

test "allow git log format at" {
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "git log --format=\"%at\"" } });
    try std.testing.expectEqual(.allow, r.decision);
}

test "allow docker build" {
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "docker build ." } });
    try std.testing.expectEqual(.allow, r.decision);
}

test "allow zig build test" {
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "zig build test" } });
    try std.testing.expectEqual(.allow, r.decision);
}

test "allow grep import socket" {
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "grep 'import socket' src/server.py" } });
    try std.testing.expectEqual(.allow, r.decision);
}

test "allow grep SOCK_STREAM" {
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "grep SOCK_STREAM src/network.c" } });
    try std.testing.expectEqual(.allow, r.decision);
}

test "allow git log grep sudo rm" {
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "git log --grep=\"sudo rm\"" } });
    try std.testing.expectEqual(.allow, r.decision);
}

test "allow grep docker privileged in docs" {
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "grep 'docker run --privileged' README.md" } });
    try std.testing.expectEqual(.allow, r.decision);
}

test "allow echo HISTFILE in docs" {
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "echo 'HISTFILE= is dangerous'" } });
    try std.testing.expectEqual(.allow, r.decision);
}

test "allow grep chown in readme" {
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "grep 'chown ' README.md" } });
    try std.testing.expectEqual(.allow, r.decision);
}

test "allow echo chown instruction" {
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "echo 'run chown root:root on the file'" } });
    try std.testing.expectEqual(.allow, r.decision);
}

test "allow echo pip install instruction" {
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "echo 'pip install -r requirements.txt'" } });
    try std.testing.expectEqual(.allow, r.decision);
}

test "allow grep brew install in docs" {
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "grep 'brew install' README.md" } });
    try std.testing.expectEqual(.allow, r.decision);
}

test "allow grep nsenter in docs" {
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "grep 'nsenter ' docs/security.md" } });
    try std.testing.expectEqual(.allow, r.decision);
}

test "allow ssh after echo mentioning ssh -R" {
    // echo argument should not trigger SSH tunnel detection for a legitimate ssh command
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "echo 'ssh -R forwarding' && ssh user@host" } });
    try std.testing.expectEqual(.allow, r.decision);
}

test "allow grep ssh tunnel flags in docs" {
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "grep 'ssh -L 8080' README.md" } });
    try std.testing.expectEqual(.allow, r.decision);
}

// --- Quote-aware normalization (issue #40) ---
// Quoted text containing shell metacharacters should not create false chain splits or redirects.

test "allow echo with double-quoted chain operator" {
    // "&&" inside double quotes is literal text, not a chain operator
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "echo \"hello && world\"" } });
    try std.testing.expectEqual(.allow, r.decision);
}

test "allow echo with single-quoted chain operator" {
    // '&&' inside single quotes is literal text
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "echo 'hello && world'" } });
    try std.testing.expectEqual(.allow, r.decision);
}

test "allow echo with double-quoted redirect" {
    // ">" inside double quotes is literal text, not a redirect
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "echo \"output > .bashrc\"" } });
    try std.testing.expectEqual(.allow, r.decision);
}

test "allow echo with single-quoted redirect" {
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "echo 'output > .bashrc'" } });
    try std.testing.expectEqual(.allow, r.decision);
}

test "allow echo with quoted semicolon" {
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "echo \"step1; step2; done\"" } });
    try std.testing.expectEqual(.allow, r.decision);
}

test "allow echo with quoted pipe" {
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "echo \"data | process\"" } });
    try std.testing.expectEqual(.allow, r.decision);
}

test "block real chain after quoted text" {
    // Real && outside quotes must still be detected
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "echo \"safe\" && sudo reboot" } });
    try std.testing.expectEqual(.deny, r.decision);
}

test "block real redirect outside quotes" {
    // Real > outside quotes must still be detected
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "echo \"safe\" > .bashrc" } });
    try std.testing.expectEqual(.deny, r.decision);
}

test "block command substitution inside double quotes" {
    // $() inside double quotes IS executed — must still be caught
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "echo \"$(sudo reboot)\"" } });
    try std.testing.expectEqual(.deny, r.decision);
}

test "allow command substitution literal in single quotes" {
    // $() inside single quotes is literal text — not executed
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "echo '$(sudo reboot)'" } });
    try std.testing.expectEqual(.allow, r.decision);
}
