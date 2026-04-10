const std = @import("std");
const evaluator = @import("../evaluator.zig");
const evaluate = evaluator.evaluate;

test "block env dump" {
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "env" } });
    try std.testing.expectEqual(.deny, r.decision);
}

test "block printenv" {
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "printenv SECRET_KEY" } });
    try std.testing.expectEqual(.deny, r.decision);
}

test "block export -p" {
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "export -p" } });
    try std.testing.expectEqual(.deny, r.decision);
}

test "allow subshell env with args" {
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "echo $(env FOO=bar some_command)" } });
    try std.testing.expectEqual(.allow, r.decision);
}

test "allow subshell env PATH setting" {
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "$(env PATH=/usr/bin command)" } });
    try std.testing.expectEqual(.allow, r.decision);
}

test "block env -0 dump" {
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "env -0" } });
    try std.testing.expectEqual(.deny, r.decision);
}

test "block env -u VAR dump" {
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "env -u HOME" } });
    try std.testing.expectEqual(.deny, r.decision);
}

test "block env -u VAR without command" {
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "env -u SECRET_KEY -u API_KEY" } });
    try std.testing.expectEqual(.deny, r.decision);
}

test "allow env -i with command" {
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "env -i PATH=/usr/bin bash script.sh" } });
    try std.testing.expectEqual(.allow, r.decision);
}

test "allow env -u VAR with command" {
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "env -u DEBUG my_command --flag" } });
    try std.testing.expectEqual(.allow, r.decision);
}

test "block env --unset VAR dump" {
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "env --unset SECRET_KEY" } });
    try std.testing.expectEqual(.deny, r.decision);
}

test "block env --split-string dump" {
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "env --split-string" } });
    try std.testing.expectEqual(.deny, r.decision);
}

test "allow env --unset VAR with command" {
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "env --unset DEBUG my_command" } });
    try std.testing.expectEqual(.allow, r.decision);
}

test "block bare env in subshell" {
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "echo $(env)" } });
    try std.testing.expectEqual(.deny, r.decision);
}

test "block bare env in subshell with spaces" {
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "echo $( env )" } });
    try std.testing.expectEqual(.deny, r.decision);
}
