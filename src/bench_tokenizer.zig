// Benchmark: internal processing stages
// Run: zig build-exe -OReleaseFast src/bench_tokenizer.zig && ./bench_tokenizer

const std = @import("std");
const tokenizer = @import("tokenizer.zig");
const normalizer = @import("normalizer.zig");

const test_cases = [_][]const u8{
    "echo hello world",
    "echo 'hello && world > file'",
    "python3 -c 'import json; print(json.dumps({\"a\": 1}))' && grep -r 'pattern' src/ | head -20 && echo done",
    "git add src/main.zig && git commit -m 'fix: update version' && git push origin main",
    "cd /tmp && mkdir test && cd test && touch file.txt && echo 'data' > file.txt && cat file.txt && ls -la",
    "if [ -f file ]; then echo exists; fi",
};

pub fn main() !void {
    const iterations: usize = 100_000;
    const stdout: std.fs.File = .stdout();
    const out = stdout.deprecatedWriter();

    try out.print("=== Benchmark: {d} iterations per test case ===\n\n", .{iterations});

    // Warm up
    for (test_cases) |tc| {
        var buf: [65536]u8 = undefined;
        _ = normalizer.normalizeShellEvasion(&buf, tc);
        var buf2: [65536]u8 = undefined;
        _ = normalizer.stripHeredocBodies(&buf2, tc);
    }

    // Benchmark normalizeShellEvasion
    var norm_total: u64 = 0;
    for (test_cases) |tc| {
        var timer = try std.time.Timer.start();
        for (0..iterations) |_| {
            var buf: [65536]u8 = undefined;
            std.mem.doNotOptimizeAway(&buf);
            const result = normalizer.normalizeShellEvasion(&buf, tc);
            std.mem.doNotOptimizeAway(result);
        }
        const elapsed = timer.read();
        norm_total += elapsed;
        try out.print("normalizeShellEvasion: {s:.60}\n", .{tc});
        try out.print("  {d} ns/iter\n\n", .{elapsed / iterations});
    }

    // Benchmark stripHeredocBodies
    var heredoc_total: u64 = 0;
    for (test_cases) |tc| {
        var timer = try std.time.Timer.start();
        for (0..iterations) |_| {
            var buf: [65536]u8 = undefined;
            std.mem.doNotOptimizeAway(&buf);
            const result = normalizer.stripHeredocBodies(&buf, tc);
            std.mem.doNotOptimizeAway(result);
        }
        const elapsed = timer.read();
        heredoc_total += elapsed;
        try out.print("stripHeredocBodies:    {s:.60}\n", .{tc});
        try out.print("  {d} ns/iter\n\n", .{elapsed / iterations});
    }

    // Benchmark tokenizer iterator (hasBlockedCommandPrefix)
    const rules = @import("rules.zig");
    var tok_total: u64 = 0;
    for (test_cases) |tc| {
        var timer = try std.time.Timer.start();
        for (0..iterations) |_| {
            const result = tokenizer.hasBlockedCommandPrefix(tc, &rules.prefix_only_commands);
            std.mem.doNotOptimizeAway(&result);
        }
        const elapsed = timer.read();
        tok_total += elapsed;
        try out.print("hasBlockedCommandPrefix: {s:.60}\n", .{tc});
        try out.print("  {d} ns/iter\n\n", .{elapsed / iterations});
    }

    try out.print("=== Summary (per call, averaged over {d} cases) ===\n", .{test_cases.len});
    try out.print("normalizeShellEvasion:   {d} ns\n", .{norm_total / iterations / test_cases.len});
    try out.print("stripHeredocBodies:      {d} ns\n", .{heredoc_total / iterations / test_cases.len});
    try out.print("hasBlockedCommandPrefix: {d} ns\n", .{tok_total / iterations / test_cases.len});
    try out.print("total added overhead:    {d} ns\n", .{(heredoc_total + tok_total) / iterations / test_cases.len});
}
