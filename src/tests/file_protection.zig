const std = @import("std");
const evaluator = @import("../evaluator.zig");
const evaluate = evaluator.evaluate;

test "block edit zshrc" {
    const r = evaluate(.{ .tool_name = "Edit", .tool_input = .{ .file_path = "/Users/user/.zshrc" } });
    try std.testing.expectEqual(.deny, r.decision);
}

test "block write bashrc" {
    const r = evaluate(.{ .tool_name = "Write", .tool_input = .{ .file_path = "/Users/user/.bashrc" } });
    try std.testing.expectEqual(.deny, r.decision);
}

test "block edit gitconfig" {
    const r = evaluate(.{ .tool_name = "Edit", .tool_input = .{ .file_path = "/Users/user/.gitconfig" } });
    try std.testing.expectEqual(.deny, r.decision);
}

test "ask write git hooks" {
    const r = evaluate(.{ .tool_name = "Write", .tool_input = .{ .file_path = "/Users/user/project/.git/hooks/pre-commit" } });
    try std.testing.expectEqual(.ask, r.decision);
}

test "block write to /etc" {
    const r = evaluate(.{ .tool_name = "Write", .tool_input = .{ .file_path = "/etc/hosts" } });
    try std.testing.expectEqual(.deny, r.decision);
}

test "block edit /usr" {
    const r = evaluate(.{ .tool_name = "Edit", .tool_input = .{ .file_path = "/usr/local/bin/something" } });
    try std.testing.expectEqual(.deny, r.decision);
}

test "block write /System" {
    const r = evaluate(.{ .tool_name = "Write", .tool_input = .{ .file_path = "/System/Library/thing" } });
    try std.testing.expectEqual(.deny, r.decision);
}

test "allow read /etc" {
    const r = evaluate(.{ .tool_name = "Read", .tool_input = .{ .file_path = "/etc/hosts" } });
    try std.testing.expectEqual(.allow, r.decision);
}

test "block unset HISTFILE" {
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "unset HISTFILE" } });
    try std.testing.expectEqual(.deny, r.decision);
}

test "block history -c" {
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "history -c" } });
    try std.testing.expectEqual(.deny, r.decision);
}

test "block shred bash_history" {
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "shred ~/.bash_history" } });
    try std.testing.expectEqual(.deny, r.decision);
}

test "block chown" {
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "chown root:root /tmp/evil" } });
    try std.testing.expectEqual(.deny, r.decision);
}

test "block chattr" {
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "chattr +i /etc/resolv.conf" } });
    try std.testing.expectEqual(.deny, r.decision);
}

test "block xattr" {
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "xattr -d com.apple.quarantine malware.app" } });
    try std.testing.expectEqual(.deny, r.decision);
}

test "block write .zlogin" {
    const r = evaluate(.{ .tool_name = "Write", .tool_input = .{ .file_path = "/Users/user/.zlogin" } });
    try std.testing.expectEqual(.deny, r.decision);
}

test "block write .zlogout" {
    const r = evaluate(.{ .tool_name = "Write", .tool_input = .{ .file_path = "/Users/user/.zlogout" } });
    try std.testing.expectEqual(.deny, r.decision);
}

test "block write .bash_logout" {
    const r = evaluate(.{ .tool_name = "Write", .tool_input = .{ .file_path = "/Users/user/.bash_logout" } });
    try std.testing.expectEqual(.deny, r.decision);
}

test "block write .claude/settings.json" {
    const r = evaluate(.{ .tool_name = "Write", .tool_input = .{ .file_path = "/Users/user/project/.claude/settings.json" } });
    try std.testing.expectEqual(.deny, r.decision);
}

test "block edit .claude/settings.local.json" {
    const r = evaluate(.{ .tool_name = "Edit", .tool_input = .{ .file_path = "/Users/user/project/.claude/settings.local.json" } });
    try std.testing.expectEqual(.deny, r.decision);
}

test "block write .cursor/mcp.json" {
    const r = evaluate(.{ .tool_name = "Write", .tool_input = .{ .file_path = "/Users/user/project/.cursor/mcp.json" } });
    try std.testing.expectEqual(.deny, r.decision);
}

test "allow read .claude/settings.json" {
    const r = evaluate(.{ .tool_name = "Read", .tool_input = .{ .file_path = "/Users/user/project/.claude/settings.json" } });
    try std.testing.expectEqual(.allow, r.decision);
}

test "allow write .claude/commands/custom.md" {
    const r = evaluate(.{ .tool_name = "Write", .tool_input = .{ .file_path = "/Users/user/project/.claude/commands/custom.md" } });
    try std.testing.expectEqual(.allow, r.decision);
}

test "allow write CLAUDE.md in project root" {
    const r = evaluate(.{ .tool_name = "Write", .tool_input = .{ .file_path = "/Users/user/project/CLAUDE.md" } });
    try std.testing.expectEqual(.allow, r.decision);
}

test "block write .claude/settings with dot-slash" {
    const r = evaluate(.{ .tool_name = "Write", .tool_input = .{ .file_path = "/Users/user/project/.claude/./settings.json" } });
    try std.testing.expectEqual(.deny, r.decision);
}

test "block write .claude/settings with dot-dot" {
    const r = evaluate(.{ .tool_name = "Write", .tool_input = .{ .file_path = "/Users/user/project/.claude/../.claude/settings.json" } });
    try std.testing.expectEqual(.deny, r.decision);
}

test "block write via trailing dot-dot" {
    const r = evaluate(.{ .tool_name = "Write", .tool_input = .{ .file_path = "/tmp/../etc/hosts" } });
    try std.testing.expectEqual(.deny, r.decision);
}

test "block write /private/etc/hosts" {
    const r = evaluate(.{ .tool_name = "Write", .tool_input = .{ .file_path = "/private/etc/hosts" } });
    try std.testing.expectEqual(.deny, r.decision);
}

test "block edit /private/var/root" {
    const r = evaluate(.{ .tool_name = "Edit", .tool_input = .{ .file_path = "/private/var/root/.profile" } });
    try std.testing.expectEqual(.deny, r.decision);
}

test "block HISTFILE assignment" {
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "HISTFILE=/dev/null bash" } });
    try std.testing.expectEqual(.deny, r.decision);
}

test "block export HISTFILE" {
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "export HISTFILE=/dev/null" } });
    try std.testing.expectEqual(.deny, r.decision);
}

test "block HISTFILE empty" {
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "HISTFILE=" } });
    try std.testing.expectEqual(.deny, r.decision);
}

test "block tee to claude settings" {
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "cat payload | tee /Users/user/.claude/settings.json" } });
    try std.testing.expectEqual(.deny, r.decision);
}

test "block sed -i zshrc" {
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "sed -i 's/old/new/' /Users/user/.zshrc" } });
    try std.testing.expectEqual(.deny, r.decision);
}

test "block cp to gitconfig via bash" {
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "cp /tmp/evil /Users/user/.gitconfig" } });
    try std.testing.expectEqual(.deny, r.decision);
}

test "ask mv to git hooks via bash" {
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "mv /tmp/evil /Users/user/project/.git/hooks/pre-commit" } });
    try std.testing.expectEqual(.ask, r.decision);
}

test "ask edit git hooks" {
    const r = evaluate(.{ .tool_name = "Edit", .tool_input = .{ .file_path = "/Users/user/project/.git/hooks/post-commit" } });
    try std.testing.expectEqual(.ask, r.decision);
}

test "allow read git hooks" {
    const r = evaluate(.{ .tool_name = "Read", .tool_input = .{ .file_path = "/Users/user/project/.git/hooks/pre-commit" } });
    try std.testing.expectEqual(.allow, r.decision);
}

test "allow redirect to normal file" {
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "echo hello > /tmp/output.txt" } });
    try std.testing.expectEqual(.allow, r.decision);
}

test "allow ls gitconfig" {
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "ls -la ~/.gitconfig" } });
    try std.testing.expectEqual(.allow, r.decision);
}

test "allow stat zshrc" {
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "stat ~/.zshrc" } });
    try std.testing.expectEqual(.allow, r.decision);
}

test "allow file command on bashrc" {
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "file ~/.bashrc" } });
    try std.testing.expectEqual(.allow, r.decision);
}

test "allow wc on profile" {
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "wc -l ~/.profile" } });
    try std.testing.expectEqual(.allow, r.decision);
}

test "block Edit .mcp.json" {
    const r = evaluate(.{ .tool_name = "Edit", .tool_input = .{ .file_path = "/home/user/project/.mcp.json" } });
    try std.testing.expectEqual(.deny, r.decision);
}

test "block Write .mcp.json" {
    const r = evaluate(.{ .tool_name = "Write", .tool_input = .{ .file_path = "/home/user/.mcp.json" } });
    try std.testing.expectEqual(.deny, r.decision);
}

test "allow Read .mcp.json" {
    const r = evaluate(.{ .tool_name = "Read", .tool_input = .{ .file_path = "/home/user/.mcp.json" } });
    try std.testing.expectEqual(.allow, r.decision);
}

test "block bash touching .mcp.json" {
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "cat malicious > .mcp.json" } });
    try std.testing.expectEqual(.deny, r.decision);
}

test "block Write .cursor/rules" {
    const r = evaluate(.{ .tool_name = "Write", .tool_input = .{ .file_path = "/home/user/.cursor/rules/inject.md" } });
    try std.testing.expectEqual(.deny, r.decision);
}

// --- IDE / MCP config protection (extended) ---

test "block Write .vscode/mcp.json" {
    const r = evaluate(.{ .tool_name = "Write", .tool_input = .{ .file_path = "/home/user/project/.vscode/mcp.json" } });
    try std.testing.expectEqual(.deny, r.decision);
}

test "block Edit .vscode/settings.json" {
    const r = evaluate(.{ .tool_name = "Edit", .tool_input = .{ .file_path = "/home/user/project/.vscode/settings.json" } });
    try std.testing.expectEqual(.deny, r.decision);
}

test "block Write cline_mcp_settings.json" {
    const r = evaluate(.{ .tool_name = "Write", .tool_input = .{ .file_path = "/home/user/project/cline_mcp_settings.json" } });
    try std.testing.expectEqual(.deny, r.decision);
}

test "block Write .continue/config.json" {
    const r = evaluate(.{ .tool_name = "Write", .tool_input = .{ .file_path = "/home/user/.continue/config.json" } });
    try std.testing.expectEqual(.deny, r.decision);
}

test "block bash writing .vscode/mcp.json" {
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "cat payload > .vscode/mcp.json" } });
    try std.testing.expectEqual(.deny, r.decision);
}

test "allow Read .vscode/settings.json" {
    const r = evaluate(.{ .tool_name = "Read", .tool_input = .{ .file_path = "/home/user/project/.vscode/settings.json" } });
    try std.testing.expectEqual(.allow, r.decision);
}

test "allow Read .continue/config.json" {
    const r = evaluate(.{ .tool_name = "Read", .tool_input = .{ .file_path = "/home/user/.continue/config.json" } });
    try std.testing.expectEqual(.allow, r.decision);
}

test "allow Write normal .json in .vscode" {
    // Custom config files in .vscode are allowed; only specific security-sensitive files are blocked
    const r = evaluate(.{ .tool_name = "Write", .tool_input = .{ .file_path = "/home/user/project/.vscode/my-config.json" } });
    try std.testing.expectEqual(.allow, r.decision);
}

// --- JetBrains IDE config protection (IDEsaster CVE-2025-54130) ---

test "block Write .idea/workspace.xml" {
    const r = evaluate(.{ .tool_name = "Write", .tool_input = .{ .file_path = "/home/user/project/.idea/workspace.xml" } });
    try std.testing.expectEqual(.deny, r.decision);
}

test "block Edit .idea/workspace.xml" {
    const r = evaluate(.{ .tool_name = "Edit", .tool_input = .{ .file_path = "/home/user/project/.idea/workspace.xml" } });
    try std.testing.expectEqual(.deny, r.decision);
}

test "block Write .idea/misc.xml" {
    const r = evaluate(.{ .tool_name = "Write", .tool_input = .{ .file_path = "/home/user/project/.idea/misc.xml" } });
    try std.testing.expectEqual(.deny, r.decision);
}

test "allow Read .idea/workspace.xml" {
    const r = evaluate(.{ .tool_name = "Read", .tool_input = .{ .file_path = "/home/user/project/.idea/workspace.xml" } });
    try std.testing.expectEqual(.allow, r.decision);
}

test "block bash writing .idea/workspace.xml" {
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "cp evil.xml .idea/workspace.xml" } });
    try std.testing.expectEqual(.deny, r.decision);
}

// --- VSCode workspace file protection (IDEsaster) ---

test "block Write .code-workspace file" {
    const r = evaluate(.{ .tool_name = "Write", .tool_input = .{ .file_path = "/home/user/project/myproject.code-workspace" } });
    try std.testing.expectEqual(.deny, r.decision);
}

test "block Edit .code-workspace file" {
    const r = evaluate(.{ .tool_name = "Edit", .tool_input = .{ .file_path = "/home/user/project/app.code-workspace" } });
    try std.testing.expectEqual(.deny, r.decision);
}

test "allow Read .code-workspace file" {
    const r = evaluate(.{ .tool_name = "Read", .tool_input = .{ .file_path = "/home/user/project/myproject.code-workspace" } });
    try std.testing.expectEqual(.allow, r.decision);
}

test "block bash writing .code-workspace" {
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "tee myproject.code-workspace < payload" } });
    try std.testing.expectEqual(.deny, r.decision);
}

// --- AI IDE instruction file protection (prompt injection vector) ---

test "block Write .github/copilot-instructions.md" {
    const r = evaluate(.{ .tool_name = "Write", .tool_input = .{ .file_path = "/home/user/project/.github/copilot-instructions.md" } });
    try std.testing.expectEqual(.deny, r.decision);
}

test "block Edit .github/copilot-instructions.md" {
    const r = evaluate(.{ .tool_name = "Edit", .tool_input = .{ .file_path = "/home/user/project/.github/copilot-instructions.md" } });
    try std.testing.expectEqual(.deny, r.decision);
}

test "allow Read .github/copilot-instructions.md" {
    const r = evaluate(.{ .tool_name = "Read", .tool_input = .{ .file_path = "/home/user/project/.github/copilot-instructions.md" } });
    try std.testing.expectEqual(.allow, r.decision);
}

test "block Write .cursorrules" {
    const r = evaluate(.{ .tool_name = "Write", .tool_input = .{ .file_path = "/home/user/project/.cursorrules" } });
    try std.testing.expectEqual(.deny, r.decision);
}

test "allow Read .cursorrules" {
    const r = evaluate(.{ .tool_name = "Read", .tool_input = .{ .file_path = "/home/user/project/.cursorrules" } });
    try std.testing.expectEqual(.allow, r.decision);
}

test "block Write .kiro/settings" {
    const r = evaluate(.{ .tool_name = "Write", .tool_input = .{ .file_path = "/home/user/project/.kiro/settings.json" } });
    try std.testing.expectEqual(.deny, r.decision);
}

test "allow Read .kiro/settings" {
    const r = evaluate(.{ .tool_name = "Read", .tool_input = .{ .file_path = "/home/user/project/.kiro/settings.json" } });
    try std.testing.expectEqual(.allow, r.decision);
}

test "allow Write .github non-workflow file" {
    const r = evaluate(.{ .tool_name = "Write", .tool_input = .{ .file_path = "/home/user/project/.github/CODEOWNERS" } });
    try std.testing.expectEqual(.allow, r.decision);
}

// --- Bypass regression: relative path for .kiro/ ---

test "block Write .kiro/ relative path" {
    const r = evaluate(.{ .tool_name = "Write", .tool_input = .{ .file_path = ".kiro/settings.json" } });
    try std.testing.expectEqual(.deny, r.decision);
}

test "block bash writing .kiro/ relative" {
    const r = evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = "cp payload .kiro/spec.kiro" } });
    try std.testing.expectEqual(.deny, r.decision);
}
