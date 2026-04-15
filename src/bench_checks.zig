// Benchmark: individual check costs in checkBashCommand
// Measures the cost of each security check stage for allowed commands (worst case).

const std = @import("std");
const rules = struct {
    pub const execution = @import("rules/execution.zig");
    pub const network = @import("rules/network.zig");
    pub const filesystem = @import("rules/filesystem.zig");
};
const normalizer = @import("normalizer.zig");
const analyzer = @import("shell_analyzer.zig");
const detector = @import("shell_detector.zig");
const path_matcher = @import("path_matcher.zig");
const tok = @import("tokenizer.zig");
const evaluator = @import("evaluator.zig");

const test_commands = [_][]const u8{
    // Short
    "ls -la",
    // Medium
    "git status && git diff --stat",
    // Long chain
    "cd /tmp && mkdir test && cd test && touch file.txt && echo 'data' > file.txt && cat file.txt && ls -la",
    // Control flow
    "if [ -f file ]; then echo exists; fi",
};

fn benchFn(comptime f: anytype, args: anytype, iterations: usize) u64 {
    var timer = std.time.Timer.start() catch return 0;
    for (0..iterations) |_| {
        const result = @call(.auto, f, args);
        std.mem.doNotOptimizeAway(&result);
    }
    return timer.read();
}

pub fn main() !void {
    const iterations: usize = 100_000;
    const stdout: std.fs.File = .stdout();
    const out = stdout.deprecatedWriter();

    try out.print("=== Check cost breakdown (ns/call, {d} iterations) ===\n\n", .{iterations});

    for (test_commands) |raw| {
        var norm_buf: [65536]u8 = undefined;
        const command = normalizer.normalizeShellEvasion(&norm_buf, raw);

        try out.print("Input: {s:.70}\n", .{raw});

        // Normalization pipeline
        const t_norm = benchFn(struct {
            fn call(r: []const u8) []const u8 {
                var b: [65536]u8 = undefined;
                return normalizer.normalizeShellEvasion(&b, r);
            }
        }.call, .{raw}, iterations);
        try out.print("  normalizeShellEvasion:         {d:>6} ns\n", .{t_norm / iterations});

        const t_heredoc = benchFn(struct {
            fn call(r: []const u8) []const u8 {
                var b: [65536]u8 = undefined;
                return normalizer.stripHeredocBodies(&b, r);
            }
        }.call, .{raw}, iterations);
        try out.print("  stripHeredocBodies:            {d:>6} ns\n", .{t_heredoc / iterations});

        // Heavy containsPatternSafe checks
        const t_dangerous = benchFn(analyzer.containsPatternSafe, .{ command, &rules.execution.dangerous_commands }, iterations);
        try out.print("  containsPatternSafe(dangerous):{d:>6} ns  ({d} patterns)\n", .{ t_dangerous / iterations, rules.execution.dangerous_commands.len });

        const t_reverse = benchFn(analyzer.containsPatternSafe, .{ command, &rules.execution.reverse_shell_patterns }, iterations);
        try out.print("  containsPatternSafe(revshell): {d:>6} ns  ({d} patterns)\n", .{ t_reverse / iterations, rules.execution.reverse_shell_patterns.len });

        const t_pipe = benchFn(analyzer.containsPatternSafe, .{ command, &rules.execution.pipe_shell_patterns }, iterations);
        try out.print("  containsPatternSafe(pipe):     {d:>6} ns  ({d} patterns)\n", .{ t_pipe / iterations, rules.execution.pipe_shell_patterns.len });

        const prefix_deny = @import("rules/prefix_deny.zig");
        const t_prefix = benchFn(analyzer.matchesPrefixInChain, .{ command, &prefix_deny.all_prefix_deny }, iterations);
        try out.print("  matchesPrefixInChain(prefix):  {d:>6} ns  ({d} patterns)\n", .{ t_prefix / iterations, prefix_deny.all_prefix_deny.len });

        const t_tokprefix = benchFn(tok.hasBlockedCommandPrefix, .{ command, &prefix_deny.all_prefix_deny }, iterations);
        try out.print("  hasBlockedCommandPrefix(tok):  {d:>6} ns  ({d} patterns)\n", .{ t_tokprefix / iterations, prefix_deny.all_prefix_deny.len });

        const t_shellcfg = benchFn(analyzer.containsPatternSafe, .{ command, &rules.filesystem.shell_config_patterns }, iterations);
        try out.print("  containsPatternSafe(shellcfg): {d:>6} ns  ({d} patterns)\n", .{ t_shellcfg / iterations, rules.filesystem.shell_config_patterns.len });

        const t_network = benchFn(analyzer.containsPatternSafe, .{ command, &rules.network.network_commands }, iterations);
        try out.print("  containsPatternSafe(network):  {d:>6} ns  ({d} patterns)\n", .{ t_network / iterations, rules.network.network_commands.len });

        // Detector checks
        const t_pipeshell = benchFn(detector.hasPipeToShell, .{command}, iterations);
        try out.print("  hasPipeToShell:                {d:>6} ns\n", .{t_pipeshell / iterations});

        const t_shellexec = benchFn(detector.hasShellScriptExec, .{command}, iterations);
        try out.print("  hasShellScriptExec:            {d:>6} ns\n", .{t_shellexec / iterations});

        const t_redirect = benchFn(detector.hasRedirectToPattern, .{ command, &rules.filesystem.shell_config_patterns }, iterations);
        try out.print("  hasRedirectToPattern(shellcfg): {d:>5} ns  ({d} patterns)\n", .{ t_redirect / iterations, rules.filesystem.shell_config_patterns.len });

        // Full evaluate
        const types = @import("types.zig");
        const input = types.HookInput{ .tool_name = "Bash", .tool_input = .{ .command = raw } };
        const t_eval = benchFn(evaluator.evaluate, .{input}, iterations);
        try out.print("  >> evaluate() TOTAL:           {d:>6} ns\n", .{t_eval / iterations});

        try out.print("\n", .{});
    }
}
