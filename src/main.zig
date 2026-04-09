const std = @import("std");
const types = @import("types.zig");
const evaluator = @import("evaluator.zig");

fn writeOutput(writer: anytype, result: types.RuleResult) !void {
    switch (result.decision) {
        .allow => try writer.writeAll(
            \\{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"allow"}}
            \\
        ),
        .deny => {
            try writer.writeAll(
                \\{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"
            );
            try writer.writeAll(result.reason);
            try writer.writeAll(
                \\"}}
                \\
            );
        },
    }
}

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const stdin: std.fs.File = .stdin();
    const raw = try stdin.readToEndAlloc(allocator, 1024 * 64);
    defer allocator.free(raw);

    const parsed = std.json.parseFromSlice(types.HookInput, allocator, raw, .{
        .ignore_unknown_fields = true,
    }) catch {
        const out: std.fs.File = .stdout();
        try writeOutput(out.deprecatedWriter(), .{ .decision = .allow, .reason = "" });
        return;
    };
    defer parsed.deinit();

    const result = evaluator.evaluate(parsed.value);
    const out: std.fs.File = .stdout();
    try writeOutput(out.deprecatedWriter(), result);

    if (result.decision == .deny) {
        const err_out: std.fs.File = .stderr();
        try err_out.deprecatedWriter().print("ccguard: {s}\n", .{result.reason});
        std.process.exit(2);
    }
}

test {
    _ = @import("tests.zig");
}
