const std = @import("std");
const evaluator = @import("../evaluator.zig");
const evaluate = evaluator.evaluate;

// --- Security/attack tool blocking (issue #22) ---

// Network reconnaissance
test "block nmap" {
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "nmap -sV 192.168.1.0/24" } });
    try std.testing.expectEqual(.deny, r.decision);
}

test "block masscan" {
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "masscan 10.0.0.0/8 -p80,443" } });
    try std.testing.expectEqual(.deny, r.decision);
}

// Password cracking
test "block hashcat" {
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "hashcat -m 0 hashes.txt wordlist.txt" } });
    try std.testing.expectEqual(.deny, r.decision);
}

test "block john" {
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "john --wordlist=rockyou.txt hashes.txt" } });
    try std.testing.expectEqual(.deny, r.decision);
}

test "block hydra" {
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "hydra -l admin -P passwords.txt ssh://target" } });
    try std.testing.expectEqual(.deny, r.decision);
}

// Network sniffing
test "block tcpdump" {
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "tcpdump -i eth0" } });
    try std.testing.expectEqual(.deny, r.decision);
}

test "block tshark" {
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "tshark -i wlan0" } });
    try std.testing.expectEqual(.deny, r.decision);
}

// Disk operations
test "block fdisk" {
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "fdisk /dev/sda" } });
    try std.testing.expectEqual(.deny, r.decision);
}

test "block parted" {
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "parted /dev/sda mklabel gpt" } });
    try std.testing.expectEqual(.deny, r.decision);
}

test "block cryptsetup" {
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "cryptsetup luksFormat /dev/sda1" } });
    try std.testing.expectEqual(.deny, r.decision);
}

// Exploit frameworks
test "block msfconsole" {
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "msfconsole" } });
    try std.testing.expectEqual(.deny, r.decision);
}

test "block sqlmap" {
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "sqlmap -u 'http://target/page?id=1'" } });
    try std.testing.expectEqual(.deny, r.decision);
}

// FP prevention
test "allow echo nmap" {
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "echo nmap is a network scanner" } });
    try std.testing.expectEqual(.allow, r.decision);
}

test "allow grep hashcat" {
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "grep hashcat requirements.txt" } });
    try std.testing.expectEqual(.allow, r.decision);
}
