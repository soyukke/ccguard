// Rule evaluation orchestration — dispatches tool calls to appropriate checkers.

const std = @import("std");
const types = @import("types.zig");
const rules = @import("rules.zig");
const normalizer = @import("normalizer.zig");
const path_matcher = @import("path_matcher.zig");
const analyzer = @import("shell_analyzer.zig");
const detector = @import("shell_detector.zig");

const RuleResult = types.RuleResult;
const HookInput = types.HookInput;

fn checkBashCommand(raw_command: []const u8) RuleResult {
    // Block ANSI-C quoting early (on raw input, before normalization)
    if (analyzer.containsPattern(raw_command, &rules.shell_obfuscation_patterns)) {
        return .{ .decision = .deny, .reason = "shell obfuscation blocked" };
    }

    // Strip commit message FIRST (on raw input, before quote removal)
    var commit_buf: [65536]u8 = undefined;
    const commit_stripped = normalizer.stripCommitMessage(&commit_buf, raw_command);

    // Then normalize shell evasion patterns
    var norm_buf: [65536]u8 = undefined;
    const command = normalizer.normalizeShellEvasion(&norm_buf, commit_stripped);

    // Block excessive command chaining (50+ segment bypass defense)
    if (analyzer.countChainSegments(command) > 50) {
        return .{ .decision = .deny, .reason = "excessive command chaining blocked" };
    }

    if (analyzer.containsPatternSafe(command, &rules.dangerous_commands)) {
        return .{ .decision = .deny, .reason = "dangerous command blocked" };
    }

    if (analyzer.containsPatternSafe(command, &rules.reverse_shell_patterns)) {
        return .{ .decision = .deny, .reason = "reverse shell / code injection blocked" };
    }

    // Intentionally uses containsPattern (not containsPatternSafe) — secrets in args
    // of ANY command (including grep/echo) still indicate exfiltration risk
    if (analyzer.containsPattern(command, &rules.network_commands) and (analyzer.containsPattern(command, &rules.secret_keywords) or std.mem.endsWith(u8, command, " .env"))) {
        return .{ .decision = .deny, .reason = "potential secret exfiltration blocked" };
    }

    if (analyzer.containsPatternSafe(command, &rules.pipe_shell_patterns) or detector.hasPipeToShell(command) or detector.hasProcessSubstitutionShell(command)) {
        return .{ .decision = .deny, .reason = "pipe-to-shell execution blocked" };
    }

    if (analyzer.containsPatternSafe(command, &rules.global_install_commands) and !detector.isPipLocalInstall(command)) {
        return .{ .decision = .deny, .reason = "global package install blocked" };
    }

    if (analyzer.containsPatternSafe(command, &rules.history_evasion_commands)) {
        return .{ .decision = .deny, .reason = "history evasion blocked" };
    }

    if (analyzer.containsPatternSafe(command, &rules.file_attr_commands)) {
        return .{ .decision = .deny, .reason = "file ownership/attribute change blocked" };
    }

    if (analyzer.matchesPrefixInChain(command, &rules.prefix_only_commands)) {
        return .{ .decision = .deny, .reason = "dangerous shell builtin blocked" };
    }

    if (detector.containsDnsCommand(command) and analyzer.containsPattern(command, &rules.cmd_subst_indicators)) {
        return .{ .decision = .deny, .reason = "DNS exfiltration blocked" };
    }

    if (analyzer.isEnvDump(command)) {
        return .{ .decision = .deny, .reason = "env dump blocked" };
    }

    if (analyzer.containsPatternSafe(command, &rules.container_escape_patterns)) {
        return .{ .decision = .deny, .reason = "container escape blocked" };
    }

    if (analyzer.containsPatternSafe(command, &rules.docker_context) and analyzer.containsPatternSafe(command, &rules.docker_dangerous_patterns)) {
        return .{ .decision = .deny, .reason = "dangerous docker operation blocked" };
    }

    if (path_matcher.matchesProcSecret(command)) {
        return .{ .decision = .deny, .reason = "proc secret access blocked" };
    }

    // Library injection
    if (analyzer.containsPatternSafe(command, &rules.lib_injection_patterns)) {
        return .{ .decision = .deny, .reason = "library injection blocked" };
    }

    // Cloud metadata endpoint access (IMDS credential theft)
    if (analyzer.containsPatternSafe(command, &rules.cloud_metadata_patterns)) {
        return .{ .decision = .deny, .reason = "cloud metadata access blocked" };
    }

    // SSH tunneling / port forwarding (requires "ssh " context + tunnel flag)
    if (analyzer.containsPatternSafe(command, &rules.ssh_context) and analyzer.containsPattern(command, &rules.ssh_tunnel_flags)) {
        return .{ .decision = .deny, .reason = "SSH tunneling blocked" };
    }

    // Bash secret file access: block commands referencing secret directories
    // Uses containsPatternSafe to avoid FP in grep/echo arguments
    if (analyzer.containsPatternSafe(command, &rules.secret_dir_patterns)) {
        return .{ .decision = .deny, .reason = "access to sensitive file blocked" };
    }

    // Bash write to protected files: block shell config references
    if (analyzer.containsPatternSafe(command, &rules.shell_config_patterns)) {
        return .{ .decision = .deny, .reason = "shell/git config modification blocked" };
    }

    return .{ .decision = .allow, .reason = "" };
}

fn checkFileAccess(raw_file_path: []const u8, tool_name: []const u8) RuleResult {
    // Normalize path to prevent bypass via /./, /../, //
    var path_buf: [65536]u8 = undefined;
    const file_path = normalizer.normalizePath(&path_buf, raw_file_path);

    if (path_matcher.matchesSecretPattern(file_path)) {
        return .{ .decision = .deny, .reason = "access to sensitive file blocked" };
    }
    // Block /proc sensitive paths for all file access tools
    if (path_matcher.matchesProcSecret(file_path)) {
        return .{ .decision = .deny, .reason = "proc secret access blocked" };
    }
    // Only block shell config and system paths for Edit/Write, not Read
    if (std.mem.eql(u8, tool_name, "Edit") or std.mem.eql(u8, tool_name, "Write")) {
        if (analyzer.containsPattern(file_path, &rules.shell_config_patterns)) {
            return .{ .decision = .deny, .reason = "shell/git config modification blocked" };
        }
        for (rules.system_path_patterns) |prefix| {
            if (std.mem.startsWith(u8, file_path, prefix)) {
                return .{ .decision = .deny, .reason = "system path write blocked" };
            }
        }
    }
    return .{ .decision = .allow, .reason = "" };
}

pub fn evaluate(input: HookInput) RuleResult {
    const tool_name = input.tool_name orelse return .{ .decision = .allow, .reason = "" };
    const tool_input = input.tool_input orelse return .{ .decision = .allow, .reason = "" };

    if (std.mem.eql(u8, tool_name, "Bash")) {
        if (tool_input.command) |cmd| return checkBashCommand(cmd);
    }

    if (std.mem.eql(u8, tool_name, "Read") or
        std.mem.eql(u8, tool_name, "Edit") or
        std.mem.eql(u8, tool_name, "Write"))
    {
        if (tool_input.file_path) |fp| return checkFileAccess(fp, tool_name);
    }

    return .{ .decision = .allow, .reason = "" };
}
