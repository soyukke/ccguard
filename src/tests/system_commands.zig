const std = @import("std");
const evaluator = @import("../evaluator.zig");
const evaluate = evaluator.evaluate;

// --- Kernel/system commands (issue #10) ---

test "block insmod" {
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "insmod /tmp/evil.ko" } });
    try std.testing.expectEqual(.deny, r.decision);
}

test "block rmmod" {
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "rmmod iptable_filter" } });
    try std.testing.expectEqual(.deny, r.decision);
}

test "block modprobe" {
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "modprobe evil_module" } });
    try std.testing.expectEqual(.deny, r.decision);
}

test "block mount" {
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "mount /dev/sda1 /mnt" } });
    try std.testing.expectEqual(.deny, r.decision);
}

test "block umount" {
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "umount /mnt" } });
    try std.testing.expectEqual(.deny, r.decision);
}

test "block sysctl -w" {
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "sysctl -w net.ipv4.ip_forward=1" } });
    try std.testing.expectEqual(.deny, r.decision);
}

test "block iptables" {
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "iptables -F" } });
    try std.testing.expectEqual(.deny, r.decision);
}

// --- FP prevention ---

test "allow npm run mount" {
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "npm run mount-volumes" } });
    try std.testing.expectEqual(.allow, r.decision);
}

test "allow echo insmod" {
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "echo insmod is a kernel command" } });
    try std.testing.expectEqual(.allow, r.decision);
}

test "allow grep sysctl" {
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "grep sysctl /var/log/messages" } });
    try std.testing.expectEqual(.allow, r.decision);
}

// --- Debug tools (issue #11) ---

test "block strace" {
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "strace -p 1234" } });
    try std.testing.expectEqual(.deny, r.decision);
}

test "block ltrace" {
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "ltrace -p 1234" } });
    try std.testing.expectEqual(.deny, r.decision);
}

test "block gdb attach" {
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "gdb -p 1234" } });
    try std.testing.expectEqual(.deny, r.decision);
}

test "block gdb batch exec" {
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "gdb -batch -ex 'call system(\"evil\")' /proc/1234/exe" } });
    try std.testing.expectEqual(.deny, r.decision);
}

test "allow grep strace in log" {
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "grep strace /var/log/audit.log" } });
    try std.testing.expectEqual(.allow, r.decision);
}

test "allow echo gdb" {
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "echo gdb is a debugger" } });
    try std.testing.expectEqual(.allow, r.decision);
}
