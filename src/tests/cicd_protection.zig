const std = @import("std");
const evaluator = @import("../evaluator.zig");
const evaluate = evaluator.evaluate;

// --- CI/CD pipeline config protection (issue #12) ---

test "block Write .github/workflows/ci.yml" {
    const r = evaluate(.{ .tool_name = "Write", .tool_input = .{ .file_path = "/home/user/project/.github/workflows/ci.yml" } });
    try std.testing.expectEqual(.deny, r.decision);
}

test "block Edit .github/workflows/deploy.yml" {
    const r = evaluate(.{ .tool_name = "Edit", .tool_input = .{ .file_path = "/home/user/project/.github/workflows/deploy.yml" } });
    try std.testing.expectEqual(.deny, r.decision);
}

test "block Write .gitlab-ci.yml" {
    const r = evaluate(.{ .tool_name = "Write", .tool_input = .{ .file_path = "/home/user/project/.gitlab-ci.yml" } });
    try std.testing.expectEqual(.deny, r.decision);
}

test "block Edit Jenkinsfile" {
    const r = evaluate(.{ .tool_name = "Edit", .tool_input = .{ .file_path = "/home/user/project/Jenkinsfile" } });
    try std.testing.expectEqual(.deny, r.decision);
}

test "block Write .circleci/config.yml" {
    const r = evaluate(.{ .tool_name = "Write", .tool_input = .{ .file_path = "/home/user/project/.circleci/config.yml" } });
    try std.testing.expectEqual(.deny, r.decision);
}

test "block Write .travis.yml" {
    const r = evaluate(.{ .tool_name = "Write", .tool_input = .{ .file_path = "/home/user/project/.travis.yml" } });
    try std.testing.expectEqual(.deny, r.decision);
}

test "block Write bitbucket-pipelines.yml" {
    const r = evaluate(.{ .tool_name = "Write", .tool_input = .{ .file_path = "/home/user/project/bitbucket-pipelines.yml" } });
    try std.testing.expectEqual(.deny, r.decision);
}

// --- IaC state files ---

test "block Write terraform.tfstate" {
    const r = evaluate(.{ .tool_name = "Write", .tool_input = .{ .file_path = "/home/user/project/terraform.tfstate" } });
    try std.testing.expectEqual(.deny, r.decision);
}

test "block Edit terraform.tfstate" {
    const r = evaluate(.{ .tool_name = "Edit", .tool_input = .{ .file_path = "/home/user/infra/terraform.tfstate" } });
    try std.testing.expectEqual(.deny, r.decision);
}

// --- Read should be allowed ---

test "allow Read .github/workflows/ci.yml" {
    const r = evaluate(.{ .tool_name = "Read", .tool_input = .{ .file_path = "/home/user/project/.github/workflows/ci.yml" } });
    try std.testing.expectEqual(.allow, r.decision);
}

test "allow Read .gitlab-ci.yml" {
    const r = evaluate(.{ .tool_name = "Read", .tool_input = .{ .file_path = "/home/user/project/.gitlab-ci.yml" } });
    try std.testing.expectEqual(.allow, r.decision);
}

test "allow Read Jenkinsfile" {
    const r = evaluate(.{ .tool_name = "Read", .tool_input = .{ .file_path = "/home/user/project/Jenkinsfile" } });
    try std.testing.expectEqual(.allow, r.decision);
}

test "allow Read terraform.tfstate" {
    const r = evaluate(.{ .tool_name = "Read", .tool_input = .{ .file_path = "/home/user/project/terraform.tfstate" } });
    try std.testing.expectEqual(.allow, r.decision);
}

// --- FP prevention: similar but not protected ---

test "allow Write Dockerfile" {
    const r = evaluate(.{ .tool_name = "Write", .tool_input = .{ .file_path = "/home/user/project/Dockerfile" } });
    try std.testing.expectEqual(.allow, r.decision);
}

test "allow Write docker-compose.yml" {
    const r = evaluate(.{ .tool_name = "Write", .tool_input = .{ .file_path = "/home/user/project/docker-compose.yml" } });
    try std.testing.expectEqual(.allow, r.decision);
}

test "allow Write terraform.tf" {
    const r = evaluate(.{ .tool_name = "Write", .tool_input = .{ .file_path = "/home/user/project/main.tf" } });
    try std.testing.expectEqual(.allow, r.decision);
}

test "allow Write package.json" {
    const r = evaluate(.{ .tool_name = "Write", .tool_input = .{ .file_path = "/home/user/project/package.json" } });
    try std.testing.expectEqual(.allow, r.decision);
}

// --- Bash commands referencing CI/CD files ---

test "block bash sed on Jenkinsfile" {
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "sed -i 's/deploy/evil/' Jenkinsfile" } });
    try std.testing.expectEqual(.deny, r.decision);
}

test "block bash tee terraform.tfstate" {
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "cat payload | tee terraform.tfstate" } });
    try std.testing.expectEqual(.deny, r.decision);
}

test "allow grep Jenkinsfile in bash" {
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "grep deploy Jenkinsfile" } });
    try std.testing.expectEqual(.allow, r.decision);
}
