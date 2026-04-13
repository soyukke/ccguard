// Shell command segment analysis — chain splitting, safe-arg detection, pattern matching.

const std = @import("std");

// --- Internal tables (detection mechanics, not policy rules) ---

pub const chain_separators = [_][]const u8{ "&&", "||", ";", "$(", "`", "|", "\n", "(", "{" };

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
pub fn stripShellPrefix(segment: []const u8) []const u8 {
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
    // Strip transparent wrapper prefixes (command/builtin/nohup/time/watch)
    // Loop to handle multiple levels: e.g. "nohup command eval ..." → "eval ..."
    const transparent = [_][]const u8{
        "command ", "builtin ", "nohup ", "time ", "watch ",
        // Shell keywords that introduce command lists (not commands themselves)
        "then ", "do ", "else ", "elif ",
    };
    var changed = true;
    while (changed) {
        changed = false;
        for (transparent) |prefix| {
            if (std.mem.startsWith(u8, trimmed, prefix)) {
                trimmed = std.mem.trimLeft(u8, trimmed[prefix.len..], " \t");
                changed = true;
                break;
            }
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

// --- Chain segment iterator ---

pub const ChainIterator = struct {
    remaining: []const u8,
    separators: []const []const u8,

    pub fn next(self: *ChainIterator) ?[]const u8 {
        if (self.remaining.len == 0) return null;
        var earliest: ?usize = null;
        var sep_len: usize = 0;
        for (self.separators) |sep| {
            if (std.mem.indexOf(u8, self.remaining, sep)) |idx| {
                if (earliest == null or idx < earliest.?) {
                    earliest = idx;
                    sep_len = sep.len;
                }
            }
        }
        const segment = if (earliest) |idx| self.remaining[0..idx] else self.remaining;
        if (earliest) |idx| {
            self.remaining = self.remaining[idx + sep_len ..];
        } else {
            self.remaining = self.remaining[self.remaining.len..];
        }
        return segment;
    }
};

pub fn chainSegments(command: []const u8) ChainIterator {
    return .{ .remaining = command, .separators = &chain_separators };
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
    var it = chainSegments(command);
    while (it.next()) |segment| {
        if (isEnvDumpSegment(segment)) return true;
    }
    return false;
}

// --- Chain-aware matching ---

pub fn matchesPrefixInChain(command: []const u8, patterns: []const []const u8) bool {
    var it = chainSegments(command);
    while (it.next()) |segment| {
        if (isExactOrPrefixMatch(segment, patterns)) return true;
    }
    return false;
}

// Count chain segments (for excessive chaining detection)
// Only count && and || — semicolons excluded because normalizeShellEvasion
// strips quotes, causing semicolons inside quoted strings to be miscounted
pub fn countChainSegments(command: []const u8) usize {
    const major_separators = [_][]const u8{ "&&", "||" };
    var it = ChainIterator{ .remaining = command, .separators = &major_separators };
    var count: usize = 0;
    while (it.next()) |_| count += 1;
    return count;
}

// Check if a pattern exists in any NON-safe-arg segment of a chained command
pub fn containsPatternSafe(command: []const u8, patterns: []const []const u8) bool {
    var it = chainSegments(command);
    while (it.next()) |segment| {
        if (!isSafeArgCommand(segment)) {
            if (containsPattern(segment, patterns)) return true;
        }
    }
    return false;
}

// Check if BOTH context and payload patterns exist in the SAME non-safe-arg segment.
// Used for compound checks where cross-segment matching causes false positives (issue #41).
pub fn containsCompoundInSegment(
    command: []const u8,
    context_patterns: []const []const u8,
    payload_patterns: []const []const u8,
) bool {
    var it = chainSegments(command);
    while (it.next()) |segment| {
        if (!isSafeArgCommand(segment)) {
            if (containsPattern(segment, context_patterns) and
                containsPattern(segment, payload_patterns))
            {
                return true;
            }
        }
    }
    return false;
}
