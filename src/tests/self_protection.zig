const std = @import("std");
const evaluator = @import("../evaluator.zig");
const evaluate = evaluator.evaluate;

// --- Self-protection: prevent hook disabling attacks (issue #26) ---
// ccguard must prevent Claude from modifying its own hook registration.

// BLOCK: Edit/Write to claude settings (hook config)
test "block Edit claude settings.json" {
    const r = evaluate(.{ .tool_name = "Edit", .tool_input = .{ .file_path = "/home/user/.claude/settings.json" } });
    try std.testing.expectEqual(.deny, r.decision);
}

test "block Write claude settings.json" {
    const r = evaluate(.{ .tool_name = "Write", .tool_input = .{ .file_path = "/home/user/.claude/settings.json" } });
    try std.testing.expectEqual(.deny, r.decision);
}

test "block Edit claude settings.local.json" {
    const r = evaluate(.{ .tool_name = "Edit", .tool_input = .{ .file_path = "/home/user/.claude/settings.local.json" } });
    try std.testing.expectEqual(.deny, r.decision);
}

// BLOCK: Bash commands targeting claude settings
test "block sed on claude settings" {
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "sed -i 's/ccguard//' ~/.claude/settings.json" } });
    try std.testing.expectEqual(.deny, r.decision);
}

// BLOCK: Bash redirect to claude settings
test "block redirect to claude settings" {
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "echo '{}' > .claude/settings.json" } });
    try std.testing.expectEqual(.deny, r.decision);
}

// BLOCK: Edit/Write to MCP config (could disable hooks indirectly)
test "block Edit mcp.json" {
    const r = evaluate(.{ .tool_name = "Edit", .tool_input = .{ .file_path = "/home/user/project/.mcp.json" } });
    try std.testing.expectEqual(.deny, r.decision);
}

// ALLOW: Read claude settings is OK (inspection)
test "allow Read claude settings" {
    const r = evaluate(.{ .tool_name = "Read", .tool_input = .{ .file_path = "/home/user/.claude/settings.json" } });
    try std.testing.expectEqual(.allow, r.decision);
}

// ALLOW: project-level .claude directory (not user settings)
test "allow Read project claude dir" {
    const r = evaluate(.{ .tool_name = "Read", .tool_input = .{ .file_path = "/home/user/project/.claude/commands/test.md" } });
    try std.testing.expectEqual(.allow, r.decision);
}
