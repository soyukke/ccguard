const std = @import("std");
const evaluator = @import("../evaluator.zig");
const evaluate = evaluator.evaluate;

test "block pip install" {
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "pip install requests" } });
    try std.testing.expectEqual(.deny, r.decision);
}

test "block npm install -g" {
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "npm install -g typescript" } });
    try std.testing.expectEqual(.deny, r.decision);
}

test "block cargo install" {
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "cargo install ripgrep" } });
    try std.testing.expectEqual(.deny, r.decision);
}

test "block brew install" {
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "brew install wget" } });
    try std.testing.expectEqual(.deny, r.decision);
}

test "block gem install" {
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "gem install rails" } });
    try std.testing.expectEqual(.deny, r.decision);
}

test "block go install" {
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "go install golang.org/x/tools/gopls@latest" } });
    try std.testing.expectEqual(.deny, r.decision);
}

test "allow pip install -r requirements" {
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "pip install -r requirements.txt" } });
    try std.testing.expectEqual(.allow, r.decision);
}

test "allow pip install -e ." {
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "pip install -e ." } });
    try std.testing.expectEqual(.allow, r.decision);
}

test "block pip install evil with -r appended" {
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "pip install evil-package -r requirements.txt" } });
    try std.testing.expectEqual(.deny, r.decision);
}

test "block pip3 install malware with -r /dev/null" {
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "pip3 install malware -r /dev/null" } });
    try std.testing.expectEqual(.deny, r.decision);
}

test "block pip install evil chained with legitimate" {
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "pip install -r requirements.txt && pip install evil-package" } });
    try std.testing.expectEqual(.deny, r.decision);
}

test "block pip install evil before -r flag" {
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "pip install evil-package && pip install -r requirements.txt" } });
    try std.testing.expectEqual(.deny, r.decision);
}
