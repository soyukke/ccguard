const std = @import("std");
const evaluator = @import("../evaluator.zig");
const evaluate = evaluator.evaluate;

// --- rm -r (without -f) should deny ---

test "block rm -r" {
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "rm -r /tmp/foo" } });
    try std.testing.expectEqual(.deny, r.decision);
}

test "block rm -R (capital)" {
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "rm -R /tmp/foo" } });
    try std.testing.expectEqual(.deny, r.decision);
}

test "block rm --recursive" {
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "rm --recursive /tmp/foo" } });
    try std.testing.expectEqual(.deny, r.decision);
}

test "block rm -rv (recursive verbose)" {
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "rm -rv /tmp/build" } });
    try std.testing.expectEqual(.deny, r.decision);
}

test "block rm -fr" {
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "rm -fr /tmp/foo" } });
    try std.testing.expectEqual(.deny, r.decision);
}

// --- GNU -I flag combinations ---

test "block rm -Ir" {
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "rm -Ir /tmp/build" } });
    try std.testing.expectEqual(.deny, r.decision);
}

test "block rm -IR" {
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "rm -IR /tmp/build" } });
    try std.testing.expectEqual(.deny, r.decision);
}

// Note: rm -I -r triggers deny via " -I " in command_exec_options (tar pattern FP).
// Combined form rm -Ir is caught by recursive_delete pattern above.
test "deny rm -I -r (command_exec_options FP)" {
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "rm -I -r /tmp/build" } });
    try std.testing.expectEqual(.deny, r.decision);
}

// --- False positive prevention ---

test "allow rm single file (no -r)" {
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "rm /tmp/foo.txt" } });
    try std.testing.expectEqual(.allow, r.decision);
}

test "allow rm -f single file (no -r)" {
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "rm -f /tmp/foo.txt" } });
    try std.testing.expectEqual(.allow, r.decision);
}

// --- MCP tool with rm -r should deny ---

test "block unknown tool with command containing rm -r" {
    const r = evaluate(.{ .tool_name = "mcp__server__execute", .tool_input = .{ .command = "rm -r /tmp/build" } });
    try std.testing.expectEqual(.deny, r.decision);
}
