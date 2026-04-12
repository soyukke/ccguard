const std = @import("std");
const evaluator = @import("../evaluator.zig");
const evaluate = evaluator.evaluate;

// --- Browser remote debugging / automation hijacking (issue #20) ---

test "block chrome remote-debugging-port" {
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "chrome --remote-debugging-port=9222" } });
    try std.testing.expectEqual(.deny, r.decision);
}

test "block google-chrome remote-debugging-port" {
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "google-chrome --remote-debugging-port=9222" } });
    try std.testing.expectEqual(.deny, r.decision);
}

test "block puppeteer.connect" {
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "node -e 'puppeteer.connect({browserWSEndpoint: ws})'" } });
    try std.testing.expectEqual(.deny, r.decision);
}

test "block playwright.connect" {
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "node -e 'playwright.connect(url)'" } });
    try std.testing.expectEqual(.deny, r.decision);
}

test "block chrome-remote-interface" {
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "node -e 'require(\"chrome-remote-interface\")'" } });
    try std.testing.expectEqual(.deny, r.decision);
}

// FP prevention
test "allow echo remote-debugging-port" {
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "echo remote-debugging-port is a Chrome flag" } });
    try std.testing.expectEqual(.allow, r.decision);
}

test "allow grep puppeteer" {
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "grep puppeteer.connect docs.md" } });
    try std.testing.expectEqual(.allow, r.decision);
}
