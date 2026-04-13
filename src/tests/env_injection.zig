const std = @import("std");
const evaluator = @import("../evaluator.zig");
const evaluate = evaluator.evaluate;

// --- Environment variable injection (issue #52) ---
// These env vars cause automatic script/module loading before the command runs.

// BASH_ENV: sourced by non-interactive bash before executing commands
test "block BASH_ENV injection" {
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "BASH_ENV=/tmp/evil.sh bash -c 'echo hello'" } });
    try std.testing.expectEqual(.deny, r.decision);
}

// ENV: sourced by sh/dash in interactive mode (space-prefixed to avoid BUILD_ENV FP)
test "block ENV injection in chain" {
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "X=1 ENV=/tmp/evil.sh sh -c 'echo hello'" } });
    try std.testing.expectEqual(.deny, r.decision);
}

// NODE_OPTIONS: injects --require or other flags into node
test "block NODE_OPTIONS injection" {
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "NODE_OPTIONS='--require /tmp/evil.js' node app.js" } });
    try std.testing.expectEqual(.deny, r.decision);
}

// PERL5OPT: injects -M flags into perl
test "block PERL5OPT injection" {
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "PERL5OPT='-Mevil' perl -e 1" } });
    try std.testing.expectEqual(.deny, r.decision);
}

// RUBYOPT: injects -r flags into ruby
test "block RUBYOPT injection" {
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "RUBYOPT='-revil' ruby -e 1" } });
    try std.testing.expectEqual(.deny, r.decision);
}

// PYTHONSTARTUP: python sources this file at interactive startup
test "block PYTHONSTARTUP injection" {
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "PYTHONSTARTUP=/tmp/evil.py python3" } });
    try std.testing.expectEqual(.deny, r.decision);
}

// PYTHONPATH: module hijacking via search path manipulation
test "block PYTHONPATH injection" {
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "PYTHONPATH=/tmp/evil python3 -c 'import target'" } });
    try std.testing.expectEqual(.deny, r.decision);
}

// --- FP prevention ---

test "allow normal env var assignment" {
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "FOO=bar bash -c 'echo hello'" } });
    try std.testing.expectEqual(.allow, r.decision);
}

test "allow CC env var" {
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "CC=gcc make" } });
    try std.testing.expectEqual(.allow, r.decision);
}

test "allow LANG env var" {
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "LANG=en_US.UTF-8 python3 script.py" } });
    try std.testing.expectEqual(.allow, r.decision);
}

test "allow PATH env var" {
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "PATH=/usr/bin:/usr/local/bin ls" } });
    try std.testing.expectEqual(.allow, r.decision);
}

test "allow echo mentioning BASH_ENV" {
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "echo 'BASH_ENV= is dangerous'" } });
    try std.testing.expectEqual(.allow, r.decision);
}

test "allow grep for NODE_OPTIONS" {
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "grep NODE_OPTIONS= config.sh" } });
    try std.testing.expectEqual(.allow, r.decision);
}

test "allow BUILD_ENV variable" {
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "BUILD_ENV=production python3 app.py" } });
    try std.testing.expectEqual(.allow, r.decision);
}

test "allow DEPLOY_ENV variable" {
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "DEPLOY_ENV=staging make deploy" } });
    try std.testing.expectEqual(.allow, r.decision);
}
