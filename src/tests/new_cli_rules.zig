const std = @import("std");
const evaluator = @import("../evaluator.zig");
const evaluate = evaluator.evaluate;

// === Package publish (deny) ===

test "deny npm publish" {
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "npm publish" } });
    try std.testing.expectEqual(.deny, r.decision);
}

test "deny npm publish scoped" {
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "npm publish --access public" } });
    try std.testing.expectEqual(.deny, r.decision);
}

test "deny cargo publish" {
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "cargo publish" } });
    try std.testing.expectEqual(.deny, r.decision);
}

test "deny twine upload" {
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "twine upload dist/*" } });
    try std.testing.expectEqual(.deny, r.decision);
}

test "deny gem push" {
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "gem push my-gem-1.0.gem" } });
    try std.testing.expectEqual(.deny, r.decision);
}

test "deny pub publish" {
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "pub publish" } });
    try std.testing.expectEqual(.deny, r.decision);
}

// Package publish FP prevention
test "allow npm install (not publish)" {
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "npm install lodash" } });
    try std.testing.expectEqual(.allow, r.decision);
}

test "allow cargo build (not publish)" {
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "cargo build --release" } });
    try std.testing.expectEqual(.allow, r.decision);
}

// === Network tunnel (deny) ===

test "deny ngrok" {
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "ngrok http 3000" } });
    try std.testing.expectEqual(.deny, r.decision);
}

test "deny localtunnel" {
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "localtunnel --port 8080" } });
    try std.testing.expectEqual(.deny, r.decision);
}

// === Database destructive (deny) ===

test "deny dropdb" {
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "dropdb mydb" } });
    try std.testing.expectEqual(.deny, r.decision);
}

test "deny dropuser" {
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "dropuser admin" } });
    try std.testing.expectEqual(.deny, r.decision);
}

// === Mail sending (deny) ===

test "deny mail command" {
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "mail user@example.com" } });
    try std.testing.expectEqual(.deny, r.decision);
}

test "deny sendmail" {
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "sendmail user@example.com" } });
    try std.testing.expectEqual(.deny, r.decision);
}

test "deny mutt" {
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "mutt -s 'subject' user@example.com" } });
    try std.testing.expectEqual(.deny, r.decision);
}

// === Deploy commands (ask) ===

test "ask vercel deploy" {
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "vercel deploy" } });
    try std.testing.expectEqual(.ask, r.decision);
}

test "ask vercel --prod" {
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "vercel --prod" } });
    try std.testing.expectEqual(.ask, r.decision);
}

test "ask netlify deploy" {
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "netlify deploy --prod" } });
    try std.testing.expectEqual(.ask, r.decision);
}

test "ask fly deploy" {
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "fly deploy" } });
    try std.testing.expectEqual(.ask, r.decision);
}

test "ask firebase deploy" {
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "firebase deploy --only functions" } });
    try std.testing.expectEqual(.ask, r.decision);
}

test "ask wrangler deploy" {
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "wrangler deploy" } });
    try std.testing.expectEqual(.ask, r.decision);
}

test "ask railway deploy" {
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "railway deploy" } });
    try std.testing.expectEqual(.ask, r.decision);
}

test "ask serverless deploy" {
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "serverless deploy --stage production" } });
    try std.testing.expectEqual(.ask, r.decision);
}

test "ask sls deploy" {
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "sls deploy" } });
    try std.testing.expectEqual(.ask, r.decision);
}

test "ask sam deploy" {
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "sam deploy --guided" } });
    try std.testing.expectEqual(.ask, r.decision);
}

test "ask gcloud app deploy" {
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "gcloud app deploy" } });
    try std.testing.expectEqual(.ask, r.decision);
}

test "ask gcloud run deploy" {
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "gcloud run deploy my-service" } });
    try std.testing.expectEqual(.ask, r.decision);
}

// === glab write commands (ask) ===

test "ask glab mr create" {
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "glab mr create --title 'fix'" } });
    try std.testing.expectEqual(.ask, r.decision);
}

test "ask glab mr merge" {
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "glab mr merge 42" } });
    try std.testing.expectEqual(.ask, r.decision);
}

test "ask glab issue create" {
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "glab issue create --title 'bug'" } });
    try std.testing.expectEqual(.ask, r.decision);
}

test "ask glab issue close" {
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "glab issue close 10" } });
    try std.testing.expectEqual(.ask, r.decision);
}

test "ask glab release create" {
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "glab release create v1.0" } });
    try std.testing.expectEqual(.ask, r.decision);
}

// glab FP prevention
test "allow glab mr list" {
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "glab mr list" } });
    try std.testing.expectEqual(.allow, r.decision);
}

test "allow glab issue list" {
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "glab issue list" } });
    try std.testing.expectEqual(.allow, r.decision);
}

test "allow glab mr view" {
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "glab mr view 42" } });
    try std.testing.expectEqual(.allow, r.decision);
}

// === Docker push/login (ask) ===

test "ask docker push" {
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "docker push myimage:latest" } });
    try std.testing.expectEqual(.ask, r.decision);
}

test "ask docker push with registry" {
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "docker push registry.example.com/myimage:v1" } });
    try std.testing.expectEqual(.ask, r.decision);
}

test "ask docker login" {
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "docker login" } });
    try std.testing.expectEqual(.ask, r.decision);
}

// Docker FP prevention
test "allow docker build" {
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "docker build -t myimage ." } });
    try std.testing.expectEqual(.allow, r.decision);
}

test "allow docker pull" {
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "docker pull ubuntu:latest" } });
    try std.testing.expectEqual(.allow, r.decision);
}

test "allow docker run" {
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "docker run -it ubuntu bash" } });
    try std.testing.expectEqual(.allow, r.decision);
}

// === Domain-specific reason messages ===

test "deny nmap has specific reason" {
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "nmap 192.168.1.0/24" } });
    try std.testing.expectEqual(.deny, r.decision);
}

test "deny kubectl exec has specific reason" {
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "kubectl exec -it pod -- bash" } });
    try std.testing.expectEqual(.deny, r.decision);
}

test "deny pbcopy has specific reason" {
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "pbcopy < secret.txt" } });
    try std.testing.expectEqual(.deny, r.decision);
}

// === Chain/background operator tests for new patterns ===

test "deny npm publish in chain" {
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "cd pkg && npm publish" } });
    try std.testing.expectEqual(.deny, r.decision);
}

test "deny ngrok in background" {
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "ngrok http 3000 &" } });
    try std.testing.expectEqual(.deny, r.decision);
}

test "deny dropdb in chain" {
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "echo 'yes' | dropdb production" } });
    try std.testing.expectEqual(.deny, r.decision);
}
