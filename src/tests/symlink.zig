const std = @import("std");
const evaluator = @import("../evaluator.zig");
const evaluate = evaluator.evaluate;

// --- Symlink TOCTOU mitigation (issue #13) ---
// These tests create actual symlinks on the filesystem to verify realpath resolution.

test "block Read via symlink to .env" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(.{ .sub_path = ".env", .data = "SECRET=abc" });
    try tmp.dir.symLink(".env", "safe.txt", .{});
    var abs_buf: [std.fs.max_path_bytes]u8 = undefined;
    const abs = try tmp.dir.realpath("safe.txt", &abs_buf);
    // Evaluate using the symlink path (not the realpath) — ccguard should resolve it
    var link_buf: [std.fs.max_path_bytes]u8 = undefined;
    const link_dir = try tmp.dir.realpath(".", &link_buf);
    var path_buf: [std.fs.max_path_bytes + 16]u8 = undefined;
    const link_path = std.fmt.bufPrint(&path_buf, "{s}/safe.txt", .{link_dir}) catch unreachable;
    _ = abs;
    const r = evaluate(.{ .tool_name = "Read", .tool_input = .{ .file_path = link_path } });
    try std.testing.expectEqual(.deny, r.decision);
}

test "allow Read of normal file via tmpdir" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(.{ .sub_path = "normal.txt", .data = "hello" });
    var link_buf: [std.fs.max_path_bytes]u8 = undefined;
    const link_dir = try tmp.dir.realpath(".", &link_buf);
    var path_buf: [std.fs.max_path_bytes + 16]u8 = undefined;
    const path = std.fmt.bufPrint(&path_buf, "{s}/normal.txt", .{link_dir}) catch unreachable;
    const r = evaluate(.{ .tool_name = "Read", .tool_input = .{ .file_path = path } });
    try std.testing.expectEqual(.allow, r.decision);
}

test "allow Write to new file (realpath fails gracefully)" {
    const r = evaluate(.{ .tool_name = "Write", .tool_input = .{ .file_path = "/tmp/nonexistent-ccguard-test-file.txt" } });
    try std.testing.expectEqual(.allow, r.decision);
}
