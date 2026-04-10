// Shell command segment analysis — chain splitting, safe-arg detection, pattern matching.

const std = @import("std");

// --- Internal tables (detection mechanics, not policy rules) ---

const chain_separators = [_][]const u8{ "&&", "||", ";", "$(", "`", "|", "\n", "(", "{" };

// Commands whose arguments are safe (search patterns, display text, etc.)
// For these commands, only the command name itself matters, not args.
// NOT included: sed (e flag executes), awk (system() executes), perl, python, ruby, etc.
const safe_arg_commands = [_][]const u8{
    "echo",  "printf", "print",
    "grep",  "egrep",  "fgrep", "rg", "ag", "ack",
    "test",  "[",
    "git log", "git show", "git diff", "git grep",
    // Metadata-only commands (args are file paths, output is metadata not content)
    "ls", "stat", "file", "wc", "du", "md5sum", "sha256sum",
    "diff", "cmp", "comm",
    "which", "type", "whereis",
    // NOTE: find is handled separately in isSafeArgCommand (safe only without -exec/-delete)
};

// --- Generic pattern matching ---

pub fn containsPattern(haystack: []const u8, patterns: []const []const u8) bool {
    for (patterns) |pattern| {
        if (std.mem.indexOf(u8, haystack, pattern) != null) return true;
    }
    return false;
}

// --- Shell prefix stripping ---

// Strip transparent shell prefixes: "command ", "builtin ", and leading VAR=val assignments
fn stripShellPrefix(segment: []const u8) []const u8 {
    var trimmed = std.mem.trimLeft(u8, segment, " \t\n\r");
    // Strip leading VAR=val assignments (e.g., "X=1 Y=2 eval ...")
    while (trimmed.len > 0) {
        // Check for NAME=VALUE pattern: starts with letter/underscore, has = before space
        if ((std.ascii.isAlphabetic(trimmed[0]) or trimmed[0] == '_')) {
            if (std.mem.indexOfAny(u8, trimmed, "= \t")) |first| {
                if (first < trimmed.len and trimmed[first] == '=') {
                    // Found VAR=, skip to after the value
                    const after_eq = trimmed[first + 1 ..];
                    const val_end = std.mem.indexOfAny(u8, after_eq, " \t") orelse after_eq.len;
                    if (first + 1 + val_end < trimmed.len) {
                        trimmed = std.mem.trimLeft(u8, after_eq[val_end..], " \t");
                        continue;
                    } else {
                        // VAR=val is the entire segment, no command follows
                        return trimmed;
                    }
                }
            }
        }
        break;
    }
    // Strip command/builtin prefix
    const transparent = [_][]const u8{ "command ", "builtin " };
    for (transparent) |prefix| {
        if (std.mem.startsWith(u8, trimmed, prefix)) {
            return std.mem.trimLeft(u8, trimmed[prefix.len..], " \t");
        }
    }
    return trimmed;
}

// --- Segment matching ---

fn isExactOrPrefixMatch(command: []const u8, patterns: []const []const u8) bool {
    const trimmed = stripShellPrefix(command);
    for (patterns) |pattern| {
        if (std.mem.eql(u8, trimmed, pattern)) return true;
        if (std.mem.startsWith(u8, trimmed, pattern) and pattern[pattern.len - 1] == ' ') return true;
        if (std.mem.startsWith(u8, trimmed, pattern) and trimmed.len > pattern.len and std.ascii.isWhitespace(trimmed[pattern.len])) return true;
    }
    return false;
}

// Check if a segment starts with a safe-arg command
fn isSafeArgCommand(segment: []const u8) bool {
    const trimmed = stripShellPrefix(segment);

    // find is safe only without -exec/-execdir/-ok/-delete
    if (std.mem.startsWith(u8, trimmed, "find") and
        (trimmed.len == 4 or (trimmed.len > 4 and std.ascii.isWhitespace(trimmed[4]))))
    {
        const dangerous_find_flags = [_][]const u8{ "-exec", "-execdir", "-ok", "-delete" };
        for (dangerous_find_flags) |flag| {
            if (std.mem.indexOf(u8, trimmed, flag) != null) return false;
        }
        return true;
    }

    for (safe_arg_commands) |cmd| {
        if (std.mem.startsWith(u8, trimmed, cmd)) {
            if (trimmed.len == cmd.len or
                (trimmed.len > cmd.len and std.ascii.isWhitespace(trimmed[cmd.len])))
            {
                return true;
            }
        }
    }
    return false;
}

// --- Env dump detection ---

fn isEnvDumpSegment(segment: []const u8) bool {
    // Trim whitespace and trailing ')' from subshell syntax, then strip command/builtin prefix
    const trimmed = stripShellPrefix(std.mem.trim(u8, std.mem.trimRight(u8, std.mem.trim(u8, segment, " \t\n\r"), ")"), " \t\n\r"));
    // "env" exactly (dump all env vars)
    if (std.mem.eql(u8, trimmed, "env")) return true;
    // "env" + whitespace → parse args to determine if a command follows
    if (std.mem.startsWith(u8, trimmed, "env") and trimmed.len > 3 and std.ascii.isWhitespace(trimmed[3])) {
        // Skip past flags (-x, -u VAR) and VAR=val assignments to find a command
        var rest = std.mem.trimLeft(u8, trimmed[4..], " \t");
        while (rest.len > 0) {
            if (rest[0] == '-') {
                const end = std.mem.indexOfAny(u8, rest, " \t") orelse rest.len;
                const flag = rest[0..end];
                rest = std.mem.trimLeft(u8, rest[end..], " \t");
                const flags_with_arg = [_][]const u8{ "-u", "--unset", "-S", "--split-string", "-C", "--chdir" };
                var takes_arg = false;
                for (flags_with_arg) |fa| {
                    if (std.mem.eql(u8, flag, fa)) {
                        takes_arg = true;
                        break;
                    }
                }
                if (takes_arg and rest.len > 0) {
                    const arg_end = std.mem.indexOfAny(u8, rest, " \t") orelse rest.len;
                    rest = std.mem.trimLeft(u8, rest[arg_end..], " \t");
                }
            } else if (std.mem.indexOf(u8, rest, "=")) |eq_idx| {
                const sp_idx = std.mem.indexOfAny(u8, rest, " \t") orelse rest.len;
                if (eq_idx < sp_idx) {
                    rest = std.mem.trimLeft(u8, rest[sp_idx..], " \t");
                } else {
                    return false;
                }
            } else {
                return false;
            }
        }
        return true;
    }
    return false;
}

pub fn isEnvDump(command: []const u8) bool {
    var remaining = command;
    while (remaining.len > 0) {
        var earliest: ?usize = null;
        var sep_len: usize = 0;
        for (chain_separators) |sep| {
            if (std.mem.indexOf(u8, remaining, sep)) |idx| {
                if (earliest == null or idx < earliest.?) {
                    earliest = idx;
                    sep_len = sep.len;
                }
            }
        }
        const segment = if (earliest) |idx| remaining[0..idx] else remaining;
        if (isEnvDumpSegment(segment)) return true;
        if (earliest) |idx| {
            remaining = remaining[idx + sep_len ..];
        } else break;
    }
    return false;
}

// --- Chain-aware matching ---

pub fn matchesPrefixInChain(command: []const u8, patterns: []const []const u8) bool {
    var remaining = command;
    while (remaining.len > 0) {
        var earliest: ?usize = null;
        var sep_len: usize = 0;
        for (chain_separators) |sep| {
            if (std.mem.indexOf(u8, remaining, sep)) |idx| {
                if (earliest == null or idx < earliest.?) {
                    earliest = idx;
                    sep_len = sep.len;
                }
            }
        }
        const segment = if (earliest) |idx| remaining[0..idx] else remaining;
        if (isExactOrPrefixMatch(segment, patterns)) return true;
        if (earliest) |idx| {
            remaining = remaining[idx + sep_len ..];
        } else break;
    }
    return false;
}

// Count chain segments (for excessive chaining detection)
pub fn countChainSegments(command: []const u8) usize {
    // Only count && and || — semicolons excluded because normalizeShellEvasion
    // strips quotes, causing semicolons inside quoted strings to be miscounted
    const major_separators = [_][]const u8{ "&&", "||" };
    var count: usize = 1;
    var remaining = command;
    while (remaining.len > 0) {
        var earliest: ?usize = null;
        var sep_len: usize = 0;
        for (major_separators) |sep| {
            if (std.mem.indexOf(u8, remaining, sep)) |idx| {
                if (earliest == null or idx < earliest.?) {
                    earliest = idx;
                    sep_len = sep.len;
                }
            }
        }
        if (earliest) |idx| {
            count += 1;
            remaining = remaining[idx + sep_len ..];
        } else break;
    }
    return count;
}

// Check if a pattern exists in any NON-safe-arg segment of a chained command
pub fn containsPatternSafe(command: []const u8, patterns: []const []const u8) bool {
    var remaining = command;
    while (remaining.len > 0) {
        var earliest: ?usize = null;
        var sep_len: usize = 0;
        for (chain_separators) |sep| {
            if (std.mem.indexOf(u8, remaining, sep)) |idx| {
                if (earliest == null or idx < earliest.?) {
                    earliest = idx;
                    sep_len = sep.len;
                }
            }
        }
        const segment = if (earliest) |idx| remaining[0..idx] else remaining;
        if (!isSafeArgCommand(segment)) {
            if (containsPattern(segment, patterns)) return true;
        }
        if (earliest) |idx| {
            remaining = remaining[idx + sep_len ..];
        } else break;
    }
    return false;
}
