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

fn printUsage(writer: anytype) !void {
    try writer.writeAll(
        \\Usage:
        \\  ccguard                              Read hook JSON from stdin (default)
        \\  ccguard check <command>               Check if a Bash command would be blocked
        \\  ccguard check --tool <T> --file-path <P>  Check file access
        \\  ccguard version                       Show version
        \\
    );
}

fn runCheck(args: []const [:0]const u8) !void {
    const err_out: std.fs.File = .stderr();
    const writer = err_out.deprecatedWriter();

    if (args.len < 1) {
        try printUsage(writer);
        std.process.exit(1);
    }

    var tool_name: []const u8 = "Bash";
    var command: ?[]const u8 = null;
    var file_path: ?[]const u8 = null;

    var i: usize = 0;
    while (i < args.len) : (i += 1) {
        const arg = args[i];
        if (std.mem.eql(u8, arg, "--tool")) {
            i += 1;
            if (i < args.len) tool_name = args[i];
        } else if (std.mem.eql(u8, arg, "--file-path")) {
            i += 1;
            if (i < args.len) file_path = args[i];
        } else {
            command = arg;
        }
    }

    const input = types.HookInput{
        .tool_name = tool_name,
        .tool_input = .{
            .command = command,
            .file_path = file_path,
        },
    };

    const result = evaluator.evaluate(input);

    const out: std.fs.File = .stdout();
    const out_writer = out.deprecatedWriter();

    switch (result.decision) {
        .allow => {
            try out_writer.writeAll("ALLOW\n");
        },
        .deny => {
            try out_writer.print("DENY: {s}\n", .{result.reason});
            std.process.exit(2);
        },
    }
}

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    // Subcommand dispatch
    if (args.len >= 2) {
        if (std.mem.eql(u8, args[1], "check")) {
            try runCheck(args[2..]);
            return;
        }
        if (std.mem.eql(u8, args[1], "version")) {
            const out: std.fs.File = .stdout();
            try out.deprecatedWriter().writeAll("ccguard 0.2.0\n");
            return;
        }
        if (std.mem.eql(u8, args[1], "--help") or std.mem.eql(u8, args[1], "-h")) {
            const out: std.fs.File = .stdout();
            try printUsage(out.deprecatedWriter());
            return;
        }
    }

    // Default: read hook JSON from stdin
    const stdin: std.fs.File = .stdin();
    const raw = try stdin.readToEndAlloc(allocator, 1024 * 64);
    defer allocator.free(raw);

    const parsed = std.json.parseFromSlice(types.HookInput, allocator, raw, .{
        .ignore_unknown_fields = true,
    }) catch {
        const out: std.fs.File = .stdout();
        try writeOutput(out.deprecatedWriter(), .{ .decision = .deny, .reason = "invalid input" });
        const err_out: std.fs.File = .stderr();
        try err_out.deprecatedWriter().writeAll("ccguard: invalid input\n");
        std.process.exit(2);
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
