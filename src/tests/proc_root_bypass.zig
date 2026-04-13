const std = @import("std");
const evaluator = @import("../evaluator.zig");
const evaluate = evaluator.evaluate;

// --- /proc/self/root path traversal bypass (issue #53) ---

// Attack: bypass system_path_patterns via /proc/self/root
test "block Read /proc/self/root/etc/shadow" {
    const r = evaluate(.{ .tool_name = "Read", .tool_input = .{ .file_path = "/proc/self/root/etc/shadow" } });
    try std.testing.expectEqual(.deny, r.decision);
}

test "block Read /proc/self/root/etc/passwd" {
    const r = evaluate(.{ .tool_name = "Read", .tool_input = .{ .file_path = "/proc/self/root/etc/passwd" } });
    try std.testing.expectEqual(.deny, r.decision);
}

test "block Write /proc/self/root/usr/local/bin/evil" {
    const r = evaluate(.{ .tool_name = "Write", .tool_input = .{ .file_path = "/proc/self/root/usr/local/bin/evil" } });
    try std.testing.expectEqual(.deny, r.decision);
}

// Attack: numeric PID variant
test "block Read /proc/1/root/etc/shadow" {
    const r = evaluate(.{ .tool_name = "Read", .tool_input = .{ .file_path = "/proc/1/root/etc/shadow" } });
    try std.testing.expectEqual(.deny, r.decision);
}

test "block Read /proc/12345/root/etc/shadow" {
    const r = evaluate(.{ .tool_name = "Read", .tool_input = .{ .file_path = "/proc/12345/root/etc/shadow" } });
    try std.testing.expectEqual(.deny, r.decision);
}

// Attack: access secret files via /proc/self/root
test "block Read /proc/self/root/.ssh/id_rsa" {
    const r = evaluate(.{ .tool_name = "Read", .tool_input = .{ .file_path = "/proc/self/root/home/user/.ssh/id_rsa" } });
    try std.testing.expectEqual(.deny, r.decision);
}

// Attack: Bash command with /proc/self/root
test "block Bash cat /proc/self/root/etc/shadow" {
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "cat /proc/self/root/etc/shadow" } });
    try std.testing.expectEqual(.deny, r.decision);
}

// --- FP prevention: legitimate /proc access ---

test "allow Read /proc/self/status" {
    const r = evaluate(.{ .tool_name = "Read", .tool_input = .{ .file_path = "/proc/self/status" } });
    try std.testing.expectEqual(.allow, r.decision);
}

test "allow Read /proc/self/maps" {
    const r = evaluate(.{ .tool_name = "Read", .tool_input = .{ .file_path = "/proc/self/maps" } });
    try std.testing.expectEqual(.allow, r.decision);
}

test "allow Read /proc/cpuinfo" {
    const r = evaluate(.{ .tool_name = "Read", .tool_input = .{ .file_path = "/proc/cpuinfo" } });
    try std.testing.expectEqual(.allow, r.decision);
}
