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
        .ask => {
            // Output nothing to stdout — Claude Code falls back to its default
            // permission flow (user confirmation prompt in auto-mode).
            // Warning is emitted to stderr by the caller.
        },
    }
}

const max_log_size = 1024 * 1024; // 1MB cap

fn logDeny(allocator: std.mem.Allocator, input: types.HookInput, reason: []const u8) void {
    const home = std.process.getEnvVarOwned(allocator, "HOME") catch return;
    defer allocator.free(home);

    const log_dir = std.fmt.allocPrint(allocator, "{s}/.local/share/ccguard", .{home}) catch return;
    defer allocator.free(log_dir);

    std.fs.cwd().makePath(log_dir) catch return;

    const log_path = std.fmt.allocPrint(allocator, "{s}/denied.jsonl", .{log_dir}) catch return;
    defer allocator.free(log_path);

    // Check file size — rotate if > 1MB
    if (std.fs.cwd().statFile(log_path)) |stat| {
        if (stat.size > max_log_size) {
            // Truncate by deleting (simple rotation)
            std.fs.cwd().deleteFile(log_path) catch {};
        }
    } else |_| {}

    const file = std.fs.cwd().createFile(log_path, .{ .truncate = false }) catch return;
    defer file.close();
    file.seekFromEnd(0) catch return;

    const tool = input.tool_name orelse "unknown";
    const cmd = if (input.tool_input) |ti| (ti.command orelse "") else "";
    const fp = if (input.tool_input) |ti| (ti.file_path orelse "") else "";

    const writer = file.deprecatedWriter();
    writer.print("{{\"tool\":\"{s}\",\"command\":\"{s}\",\"file_path\":\"{s}\",\"reason\":\"{s}\"}}\n", .{ tool, cmd, fp, reason }) catch {};
}

fn runLog(allocator: std.mem.Allocator) !void {
    const out: std.fs.File = .stdout();
    const writer = out.deprecatedWriter();

    const home = std.process.getEnvVarOwned(allocator, "HOME") catch {
        try writer.writeAll("error: HOME not set\n");
        std.process.exit(1);
    };
    defer allocator.free(home);

    const log_path = std.fmt.allocPrint(allocator, "{s}/.local/share/ccguard/denied.jsonl", .{home}) catch unreachable;
    defer allocator.free(log_path);

    const content = std.fs.cwd().readFileAlloc(allocator, log_path, max_log_size + 1) catch |err| {
        if (err == error.FileNotFound) {
            try writer.writeAll("No denied commands logged yet.\n");
            return;
        }
        try writer.writeAll("error: cannot read log file\n");
        std.process.exit(1);
    };
    defer allocator.free(content);

    if (content.len == 0) {
        try writer.writeAll("No denied commands logged yet.\n");
        return;
    }

    try writer.writeAll(content);
}

fn printUsage(writer: anytype) !void {
    try writer.writeAll(
        \\Usage:
        \\  ccguard                              Read hook JSON from stdin (default)
        \\  ccguard check <command>               Check if a Bash command would be blocked
        \\  ccguard check --tool <T> --file-path <P>  Check file access
        \\  ccguard setup                         Add ccguard hook to ~/.claude/settings.json
        \\  ccguard log                           Show denied commands log
        \\  ccguard version                       Show version
        \\
    );
}

const hook_json =
    \\{
    \\  "matcher": "",
    \\  "hooks": [
    \\    {
    \\      "type": "command",
    \\      "command": "ccguard"
    \\    }
    \\  ]
    \\}
;

fn runSetup(allocator: std.mem.Allocator) !void {
    const out: std.fs.File = .stdout();
    const writer = out.deprecatedWriter();

    // Resolve ~/.claude/settings.json
    const home = std.process.getEnvVarOwned(allocator, "HOME") catch {
        try writer.writeAll("error: HOME not set\n");
        std.process.exit(1);
    };
    defer allocator.free(home);

    const claude_dir = try std.fmt.allocPrint(allocator, "{s}/.claude", .{home});
    defer allocator.free(claude_dir);

    const settings_path = try std.fmt.allocPrint(allocator, "{s}/settings.json", .{claude_dir});
    defer allocator.free(settings_path);

    // Ensure ~/.claude/ directory exists
    std.fs.cwd().makePath(claude_dir) catch {};

    // Read existing settings or start fresh
    const content = std.fs.cwd().readFileAlloc(allocator, settings_path, 1024 * 64) catch |err| blk: {
        if (err == error.FileNotFound) {
            break :blk null;
        }
        try writer.print("error: cannot read {s}\n", .{settings_path});
        std.process.exit(1);
    };
    defer if (content) |c| allocator.free(c);

    // Check if already configured
    if (content) |c| {
        if (std.mem.indexOf(u8, c, "\"command\": \"ccguard\"") != null or
            std.mem.indexOf(u8, c, "\"command\":\"ccguard\"") != null)
        {
            try writer.writeAll("ccguard hook is already configured.\n");
            return;
        }
    }

    // Build new settings content
    var result = std.ArrayListUnmanaged(u8){};
    defer result.deinit(allocator);

    if (content) |c| {
        // Find insertion point: look for "hooks" key or add before last '}'
        if (std.mem.indexOf(u8, c, "\"PreToolUse\"")) |_| {
            // PreToolUse already exists — find the array and append
            if (std.mem.indexOf(u8, c, "\"PreToolUse\": [")) |pt_idx| {
                const insert_pos = pt_idx + "\"PreToolUse\": [".len;
                try result.appendSlice(allocator,c[0..insert_pos]);
                try result.appendSlice(allocator,"\n      ");
                try result.appendSlice(allocator,hook_json);
                try result.appendSlice(allocator,",");
                try result.appendSlice(allocator,c[insert_pos..]);
            } else {
                // Unexpected format, bail out
                try writer.writeAll("error: unexpected PreToolUse format, please add manually\n");
                std.process.exit(1);
            }
        } else if (std.mem.indexOf(u8, c, "\"hooks\"")) |_| {
            // hooks exists but no PreToolUse — add it
            if (std.mem.indexOf(u8, c, "\"hooks\": {")) |h_idx| {
                const insert_pos = h_idx + "\"hooks\": {".len;
                try result.appendSlice(allocator,c[0..insert_pos]);
                try result.appendSlice(allocator,"\n    \"PreToolUse\": [\n      ");
                try result.appendSlice(allocator,hook_json);
                try result.appendSlice(allocator,"\n    ],");
                try result.appendSlice(allocator,c[insert_pos..]);
            } else {
                try writer.writeAll("error: unexpected hooks format, please add manually\n");
                std.process.exit(1);
            }
        } else {
            // No hooks at all — add before last '}'
            if (std.mem.lastIndexOfScalar(u8, c, '}')) |last_brace| {
                try result.appendSlice(allocator,c[0..last_brace]);
                try result.appendSlice(allocator,
                    \\,
                    \\  "hooks": {
                    \\    "PreToolUse": [
                    \\
                );
                try result.appendSlice(allocator,hook_json);
                try result.appendSlice(allocator,
                    \\
                    \\    ]
                    \\  }
                    \\}
                    \\
                );
            } else {
                try writer.writeAll("error: malformed settings.json\n");
                std.process.exit(1);
            }
        }
    } else {
        // No settings file — create from scratch
        try result.appendSlice(allocator,
            \\{
            \\  "hooks": {
            \\    "PreToolUse": [
            \\
        );
        try result.appendSlice(allocator,hook_json);
        try result.appendSlice(allocator,
            \\
            \\    ]
            \\  }
            \\}
            \\
        );
    }

    // Write result
    const file = try std.fs.cwd().createFile(settings_path, .{});
    defer file.close();
    try file.writeAll(result.items);

    try writer.print("ccguard hook added to {s}\n", .{settings_path});
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
        .ask => {
            try out_writer.print("ASK: {s}\n", .{result.reason});
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
        if (std.mem.eql(u8, args[1], "log")) {
            try runLog(allocator);
            return;
        }
        if (std.mem.eql(u8, args[1], "setup")) {
            try runSetup(allocator);
            return;
        }
        if (std.mem.eql(u8, args[1], "version")) {
            const out: std.fs.File = .stdout();
            try out.deprecatedWriter().writeAll("ccguard 0.4.0\n");
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
        logDeny(allocator, parsed.value, result.reason);
        const err_out: std.fs.File = .stderr();
        try err_out.deprecatedWriter().print("ccguard: {s}\n", .{result.reason});
        std.process.exit(2);
    }
    if (result.decision == .ask) {
        // Warn on stderr but exit 0 — Claude Code's default permission flow handles it
        const err_out: std.fs.File = .stderr();
        try err_out.deprecatedWriter().print("ccguard: [ask] {s}\n", .{result.reason});
    }
}

test {
    _ = @import("tests.zig");
}
