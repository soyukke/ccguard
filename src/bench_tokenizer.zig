// Benchmark: tokenizer vs normalizeShellEvasion
// Run: zig build-exe -OReleaseFast src/bench_tokenizer.zig && ./bench_tokenizer

const std = @import("std");
const tokenizer = @import("tokenizer.zig");
const normalizer = @import("normalizer.zig");

const test_cases = [_][]const u8{
    // Simple
    "echo hello world",
    // Quoted
    "echo 'hello && world > file'",
    // Multi-segment
    "python3 -c 'import json; print(json.dumps({\"a\": 1}))' && grep -r 'pattern' src/ | head -20 && echo done",
    // Complex real-world
    "git add src/main.zig && git commit -m 'fix: update version' && git push origin main",
    // Long chain
    "cd /tmp && mkdir test && cd test && touch file.txt && echo 'data' > file.txt && cat file.txt && ls -la",
    // Mixed quotes and redirects
    "curl -s 'https://api.example.com/data' | jq '.results[]' > output.json 2>&1 && echo 'done'",
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
        _ = tokenizer.tokenize(tc);
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
        try out.print("  {d} ns total, {d} ns/iter\n\n", .{ elapsed, elapsed / iterations });
    }

    // Benchmark tokenizer
    var tok_total: u64 = 0;
    for (test_cases) |tc| {
        var timer = try std.time.Timer.start();
        for (0..iterations) |_| {
            const result = tokenizer.tokenize(tc);
            std.mem.doNotOptimizeAway(&result);
        }
        const elapsed = timer.read();
        tok_total += elapsed;
        try out.print("tokenize: {s:.60}\n", .{tc});
        try out.print("  {d} ns total, {d} ns/iter\n\n", .{ elapsed, elapsed / iterations });
    }

    try out.print("=== Summary ===\n", .{});
    try out.print("normalizeShellEvasion total: {d} ns ({d} us)\n", .{ norm_total, norm_total / 1000 });
    try out.print("tokenize total:              {d} ns ({d} us)\n", .{ tok_total, tok_total / 1000 });
    try out.print("ratio (tokenize / normalize): {d:.2}x\n", .{@as(f64, @floatFromInt(tok_total)) / @as(f64, @floatFromInt(norm_total))});

    // Memory: TokenResult is stack-allocated, print its size
    try out.print("\nsizeof(TokenResult): {d} bytes ({d} KB)\n", .{ @sizeOf(tokenizer.TokenResult), @sizeOf(tokenizer.TokenResult) / 1024 });
}
