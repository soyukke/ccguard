const std = @import("std");
const evaluator = @import("../evaluator.zig");
const evaluate = evaluator.evaluate;

test "allow read .envrc" {
    const r = evaluate(.{ .tool_name = "Read", .tool_input = .{ .file_path = "/home/user/project/.envrc" } });
    try std.testing.expectEqual(.allow, r.decision);
}

test "allow read environment.ts" {
    const r = evaluate(.{ .tool_name = "Read", .tool_input = .{ .file_path = "/home/user/src/environment.ts" } });
    try std.testing.expectEqual(.allow, r.decision);
}

test "allow read venv path" {
    const r = evaluate(.{ .tool_name = "Read", .tool_input = .{ .file_path = "/home/user/project/venv/lib/site.py" } });
    try std.testing.expectEqual(.allow, r.decision);
}

test "allow read hotkey.ts file" {
    const r = evaluate(.{ .tool_name = "Read", .tool_input = .{ .file_path = "/home/user/src/hotkey.ts" } });
    try std.testing.expectEqual(.allow, r.decision);
}

test "allow read keyboard.key file" {
    const r = evaluate(.{ .tool_name = "Read", .tool_input = .{ .file_path = "/home/user/config/keyboard.key" } });
    try std.testing.expectEqual(.allow, r.decision);
}

test "allow read client_secret_template" {
    const r = evaluate(.{ .tool_name = "Read", .tool_input = .{ .file_path = "/home/user/docs/client_secret_template.json" } });
    try std.testing.expectEqual(.allow, r.decision);
}

test "allow read credentials-helper.md" {
    const r = evaluate(.{ .tool_name = "Read", .tool_input = .{ .file_path = "/home/user/docs/credentials-helper.md" } });
    try std.testing.expectEqual(.allow, r.decision);
}

test "block read actual .env" {
    const r = evaluate(.{ .tool_name = "Read", .tool_input = .{ .file_path = "/home/user/project/.env" } });
    try std.testing.expectEqual(.deny, r.decision);
}

test "block read actual id_rsa" {
    const r = evaluate(.{ .tool_name = "Read", .tool_input = .{ .file_path = "/home/user/.ssh/id_rsa" } });
    try std.testing.expectEqual(.deny, r.decision);
}

test "block read credentials.json" {
    const r = evaluate(.{ .tool_name = "Read", .tool_input = .{ .file_path = "/home/user/.aws/credentials" } });
    try std.testing.expectEqual(.deny, r.decision);
}

test "allow read .env.example file" {
    const r = evaluate(.{ .tool_name = "Read", .tool_input = .{ .file_path = "/home/user/project/.env.example" } });
    try std.testing.expectEqual(.allow, r.decision);
}

test "allow read .env.template file" {
    const r = evaluate(.{ .tool_name = "Read", .tool_input = .{ .file_path = "/home/user/project/.env.template" } });
    try std.testing.expectEqual(.allow, r.decision);
}

test "allow read .env.sample file" {
    const r = evaluate(.{ .tool_name = "Read", .tool_input = .{ .file_path = "/home/user/project/.env.sample" } });
    try std.testing.expectEqual(.allow, r.decision);
}

test "block read .env.local file" {
    const r = evaluate(.{ .tool_name = "Read", .tool_input = .{ .file_path = "/home/user/project/.env.local" } });
    try std.testing.expectEqual(.deny, r.decision);
}

test "block read .env.production file" {
    const r = evaluate(.{ .tool_name = "Read", .tool_input = .{ .file_path = "/home/user/project/.env.production" } });
    try std.testing.expectEqual(.deny, r.decision);
}

test "allow read keybindings.key" {
    const r = evaluate(.{ .tool_name = "Read", .tool_input = .{ .file_path = "/home/user/config/keybindings.key" } });
    try std.testing.expectEqual(.allow, r.decision);
}

test "block read server.pem" {
    const r = evaluate(.{ .tool_name = "Read", .tool_input = .{ .file_path = "/home/user/certs/server.pem" } });
    try std.testing.expectEqual(.deny, r.decision);
}

test "block read private-key.pem" {
    const r = evaluate(.{ .tool_name = "Read", .tool_input = .{ .file_path = "/home/user/certs/private-key.pem" } });
    try std.testing.expectEqual(.deny, r.decision);
}

test "block read certificate.pfx" {
    const r = evaluate(.{ .tool_name = "Read", .tool_input = .{ .file_path = "/home/user/certs/certificate.pfx" } });
    try std.testing.expectEqual(.deny, r.decision);
}

test "block read keystore.p12" {
    const r = evaluate(.{ .tool_name = "Read", .tool_input = .{ .file_path = "/home/user/certs/keystore.p12" } });
    try std.testing.expectEqual(.deny, r.decision);
}

test "block read server.jks" {
    const r = evaluate(.{ .tool_name = "Read", .tool_input = .{ .file_path = "/home/user/java/server.jks" } });
    try std.testing.expectEqual(.deny, r.decision);
}

test "block read app.keystore" {
    const r = evaluate(.{ .tool_name = "Read", .tool_input = .{ .file_path = "/home/user/android/app.keystore" } });
    try std.testing.expectEqual(.deny, r.decision);
}

test "block read .htpasswd" {
    const r = evaluate(.{ .tool_name = "Read", .tool_input = .{ .file_path = "/var/www/.htpasswd" } });
    try std.testing.expectEqual(.deny, r.decision);
}

test "allow read keystore.go" {
    const r = evaluate(.{ .tool_name = "Read", .tool_input = .{ .file_path = "/home/user/src/keystore.go" } });
    try std.testing.expectEqual(.allow, r.decision);
}

test "allow read htpasswd-generator.py" {
    const r = evaluate(.{ .tool_name = "Read", .tool_input = .{ .file_path = "/home/user/tools/htpasswd-generator.py" } });
    try std.testing.expectEqual(.allow, r.decision);
}

test "block cat /proc/self/environ" {
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "cat /proc/self/environ" } });
    try std.testing.expectEqual(.deny, r.decision);
}

test "block read /proc/self/environ" {
    const r = evaluate(.{ .tool_name = "Read", .tool_input = .{ .file_path = "/proc/self/environ" } });
    try std.testing.expectEqual(.deny, r.decision);
}

test "block cat /proc/self/cmdline" {
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "cat /proc/self/cmdline" } });
    try std.testing.expectEqual(.deny, r.decision);
}

test "allow cat /proc/cpuinfo" {
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "cat /proc/cpuinfo" } });
    try std.testing.expectEqual(.allow, r.decision);
}

test "allow read /proc/cpuinfo" {
    const r = evaluate(.{ .tool_name = "Read", .tool_input = .{ .file_path = "/proc/cpuinfo" } });
    try std.testing.expectEqual(.allow, r.decision);
}

test "block read /proc/self/environ with dot-slash" {
    const r = evaluate(.{ .tool_name = "Read", .tool_input = .{ .file_path = "/proc/self/./environ" } });
    try std.testing.expectEqual(.deny, r.decision);
}

test "block read /proc/environ with dot-dot" {
    const r = evaluate(.{ .tool_name = "Read", .tool_input = .{ .file_path = "/proc/./self/environ" } });
    try std.testing.expectEqual(.deny, r.decision);
}

test "block read .env with double slash" {
    const r = evaluate(.{ .tool_name = "Read", .tool_input = .{ .file_path = "/home/user/project//.env" } });
    try std.testing.expectEqual(.deny, r.decision);
}

test "block cat /proc/1/environ" {
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "cat /proc/1/environ" } });
    try std.testing.expectEqual(.deny, r.decision);
}

test "block read /proc/1/environ" {
    const r = evaluate(.{ .tool_name = "Read", .tool_input = .{ .file_path = "/proc/1/environ" } });
    try std.testing.expectEqual(.deny, r.decision);
}

test "allow proc cpuinfo then separate environ" {
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "cat /proc/cpuinfo; cat /tmp/environ" } });
    try std.testing.expectEqual(.allow, r.decision);
}

test "block read .ssh key via trailing dot-dot" {
    // /home/user/.ssh/subdir/../id_rsa normalizes to /home/user/.ssh/id_rsa
    const r = evaluate(.{ .tool_name = "Read", .tool_input = .{ .file_path = "/home/user/.ssh/subdir/../id_rsa" } });
    try std.testing.expectEqual(.deny, r.decision);
}

test "block cat ssh key via bash" {
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "cat /home/user/.ssh/id_rsa" } });
    try std.testing.expectEqual(.deny, r.decision);
}

test "block cat aws credentials via bash" {
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "cat /home/user/.aws/credentials" } });
    try std.testing.expectEqual(.deny, r.decision);
}

test "block head gnupg key via bash" {
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "head -n 10 /home/user/.gnupg/private-keys-v1.d/key.pem" } });
    try std.testing.expectEqual(.deny, r.decision);
}

test "block cat kube config via bash" {
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "cat /home/user/.kube/config" } });
    try std.testing.expectEqual(.deny, r.decision);
}

test "allow grep in ssh dir via bash" {
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "grep -r 'pattern' /home/user/.ssh/config" } });
    try std.testing.expectEqual(.allow, r.decision);
}

test "allow echo ssh path string" {
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "echo 'check ~/.ssh/ directory'" } });
    try std.testing.expectEqual(.allow, r.decision);
}

test "allow read id_rsa.pub" {
    const r = evaluate(.{ .tool_name = "Read", .tool_input = .{ .file_path = "/home/user/.ssh/id_rsa.pub" } });
    try std.testing.expectEqual(.allow, r.decision);
}

test "allow read id_ed25519.pub" {
    const r = evaluate(.{ .tool_name = "Read", .tool_input = .{ .file_path = "/home/user/.ssh/id_ed25519.pub" } });
    try std.testing.expectEqual(.allow, r.decision);
}
