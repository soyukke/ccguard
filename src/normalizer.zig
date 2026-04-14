// Input normalization pipeline — transforms raw shell input before pattern matching.

const std = @import("std");

// Normalize path in-place: collapse //, /./, and simple /../ sequences
pub fn normalizePath(buf: []u8, path: []const u8) []const u8 {
    if (path.len == 0) return path;
    const len = @min(path.len, buf.len);
    @memcpy(buf[0..len], path[0..len]);
    var out: usize = 0;
    var i: usize = 0;
    while (i < len) {
        if (buf[i] == '/' and i + 1 < len and buf[i + 1] == '/') {
            // Skip duplicate slash
            i += 1;
        } else if (buf[i] == '/' and i + 2 < len and buf[i + 1] == '.' and buf[i + 2] == '/') {
            // Skip /./
            i += 2;
        } else if (buf[i] == '/' and i + 2 < len and buf[i + 1] == '.' and buf[i + 2] == '.' and (i + 3 >= len or buf[i + 3] == '/')) {
            // Handle /.. and /../ — go back to previous /
            if (out > 0) {
                out -= 1;
                while (out > 0 and buf[out] != '/') out -= 1;
            }
            i += 3;
        } else {
            buf[out] = buf[i];
            out += 1;
            i += 1;
        }
    }
    return buf[0..out];
}

fn isShellSeparator(c: u8) bool {
    return std.ascii.isWhitespace(c) or c == ';' or c == '|' or c == '&' or c == '(' or c == ')' or c == '{' or c == '}' or c == '<' or c == '>';
}

// Sentinel byte for shell metacharacters that were inside quotes.
// Prevents false chain splits and redirect detection while preserving text for pattern matching.
const quote_sentinel: u8 = '\x01';

// Shell structural operators that are literal inside single quotes (everything is literal).
fn isSingleQuoteMetachar(c: u8) bool {
    return c == '&' or c == '|' or c == ';' or c == '>' or c == '<' or
        c == '\n' or c == '(' or c == ')' or c == '{' or c == '}' or c == '`';
}

// Shell structural operators that are literal inside double quotes.
// $, `, \, ! remain active inside double quotes — do NOT replace.
fn isDoubleQuoteMetachar(c: u8) bool {
    return c == '&' or c == '|' or c == ';' or c == '>' or c == '<' or c == '\n';
}

// Check if the quote at position `pos` follows a code-execution flag (-c or -e),
// meaning the quoted content is executable code and metacharacters should be preserved.
// Matches: bash -c '...', python -c '...', ruby -e '...', node -e '...',
//          perl -e '...', osascript -e '...'
fn isCodeExecArg(input: []const u8, pos: usize) bool {
    var j = pos;
    // Skip spaces between flag and quote
    while (j > 0 and input[j - 1] == ' ') j -= 1;
    // Check for "-c" or "-e"
    if (j >= 2 and input[j - 2] == '-' and (input[j - 1] == 'c' or input[j - 1] == 'e')) {
        // Must be preceded by a word boundary (space, tab, or start of string)
        if (j == 2 or input[j - 3] == ' ' or input[j - 3] == '\t') {
            return true;
        }
    }
    return false;
}

// Check if position starts a zero-width Unicode character (invisible obfuscation).
// Returns byte length to skip, or 0 if not a zero-width char.
fn zeroWidthLen(input: []const u8, i: usize) usize {
    if (i + 2 < input.len and input[i] == 0xE2 and input[i + 1] == 0x80) {
        // U+200B zero-width space, U+200C non-joiner, U+200D joiner
        if (input[i + 2] >= 0x8B and input[i + 2] <= 0x8D) return 3;
    }
    if (i + 2 < input.len and input[i] == 0xE2 and input[i + 1] == 0x81 and input[i + 2] == 0xA0) {
        return 3; // U+2060 word joiner
    }
    if (i + 2 < input.len and input[i] == 0xEF and input[i + 1] == 0xBB and input[i + 2] == 0xBF) {
        return 3; // U+FEFF BOM / zero-width no-break space
    }
    return 0;
}

// Pass 1: Zero-width char strip, tabs → space, ${IFS}/$IFS → space, quote stripping, backslash-newline removal.
// Quote-aware: replaces shell metacharacters inside quotes with a sentinel byte
// to prevent false chain splits and redirect detection (issue #40).
// Exception: quotes that are arguments to code-execution flags (-c, -e) are NOT
// modified, since their content is executable code.
fn normalizeBasic(buf: []u8, input: []const u8) usize {
    var out: usize = 0;
    var i: usize = 0;
    const len = @min(input.len, buf.len);
    while (i < len) {
        // Strip zero-width Unicode characters (obfuscation defense)
        const zwl = zeroWidthLen(input, i);
        if (zwl > 0) {
            i += zwl;
            continue;
        }
        if (input[i] == '\\' and i + 1 < len and input[i + 1] == '\n') {
            i += 2;
        } else if (input[i] == '\t') {
            buf[out] = ' ';
            out += 1;
            i += 1;
        } else if (i + 5 < len and std.mem.eql(u8, input[i .. i + 6], "${IFS}")) {
            buf[out] = ' ';
            out += 1;
            i += 6;
        } else if (i + 3 < len and std.mem.eql(u8, input[i .. i + 4], "$IFS") and
            (i + 4 >= len or (!std.ascii.isAlphanumeric(input[i + 4]) and input[i + 4] != '_')))
        {
            buf[out] = ' ';
            out += 1;
            i += 4;
        } else if (input[i] == '\'') {
            if (std.mem.indexOfPos(u8, input, i + 1, "'")) |close| {
                const is_code = isCodeExecArg(input, i);
                const content = input[i + 1 .. close];
                for (content) |c| {
                    if (out < buf.len) {
                        buf[out] = if (!is_code and isSingleQuoteMetachar(c)) quote_sentinel else c;
                        out += 1;
                    }
                }
                i = close + 1;
            } else {
                buf[out] = input[i];
                out += 1;
                i += 1;
            }
        } else if (input[i] == '"') {
            if (std.mem.indexOfPos(u8, input, i + 1, "\"")) |close| {
                const is_code = isCodeExecArg(input, i);
                const content = input[i + 1 .. close];
                for (content) |c| {
                    if (out < buf.len) {
                        buf[out] = if (!is_code and isDoubleQuoteMetachar(c)) quote_sentinel else c;
                        out += 1;
                    }
                }
                i = close + 1;
            } else {
                buf[out] = input[i];
                out += 1;
                i += 1;
            }
        } else {
            buf[out] = input[i];
            out += 1;
            i += 1;
        }
    }
    return out;
}

// Pass 2: Brace expansion {a,b,c} → a b c (only in command position)
fn expandBraces(buf: []u8, len: usize) usize {
    var out: usize = 0;
    var j: usize = 0;
    while (j < len) {
        if (buf[j] == '{') {
            const prev_is_sep = j == 0 or isShellSeparator(buf[j - 1]);
            if (std.mem.indexOfPos(u8, buf[0..len], j + 1, "}")) |close| {
                const inner = buf[j + 1 .. close];
                if (std.mem.indexOf(u8, inner, ",") != null and prev_is_sep) {
                    buf[out] = ' ';
                    out += 1;
                    for (inner) |c| {
                        if (c == ',') {
                            buf[out] = ' ';
                        } else {
                            buf[out] = c;
                        }
                        out += 1;
                    }
                    buf[out] = ' ';
                    out += 1;
                    j = close + 1;
                } else {
                    buf[out] = buf[j];
                    out += 1;
                    j += 1;
                }
            } else {
                buf[out] = buf[j];
                out += 1;
                j += 1;
            }
        } else {
            buf[out] = buf[j];
            out += 1;
            j += 1;
        }
    }
    return out;
}

// Pass 3: Collapse consecutive spaces
fn collapseSpaces(buf: []u8, len: usize) usize {
    var out: usize = 0;
    var prev_space = false;
    for (buf[0..len]) |c| {
        if (c == ' ') {
            if (!prev_space) {
                buf[out] = c;
                out += 1;
            }
            prev_space = true;
        } else {
            buf[out] = c;
            out += 1;
            prev_space = false;
        }
    }
    return out;
}

// Shell-aware normalizer: applies 3 passes in-place on buf.
pub fn normalizeShellEvasion(buf: []u8, input: []const u8) []const u8 {
    const len1 = normalizeBasic(buf, input);
    const len2 = expandBraces(buf, len1);
    const len3 = collapseSpaces(buf, len2);
    return buf[0..len3];
}

fn isAtSegmentStart(command: []const u8, idx: usize) bool {
    if (idx == 0) return true;
    var i = idx;
    while (i > 0 and command[i - 1] == ' ') i -= 1;
    if (i == 0) return true;
    const prev = command[i - 1];
    return prev == '&' or prev == '|' or prev == ';' or prev == '(' or prev == '\n';
}

// Git subcommands that use -m/--message for user-provided text.
const git_message_subcommands = [_][]const u8{
    "git commit",
    "git tag",
    "git merge",
    "git notes",
    "git stash",
};

const FlagMatch = struct {
    flag_start: usize, // absolute position of space before the flag
    val_start: usize, // absolute position where message value begins
};

/// Find -m/--message flag in command text within [search_start, search_end).
/// Handles: " -m ", " -am ", " -sam " (combined flags ending in m),
///           " --message ", " --message=", and quote-adjacent variants.
/// search_end limits the scan to the current chain segment to prevent
/// cross-segment stripping (e.g., `git tag && bash -m 'payload'`).
fn findMessageFlag(command: []const u8, search_start: usize, search_end: usize) ?FlagMatch {
    var i = search_start;
    while (i < search_end) {
        if (command[i] != ' ') {
            i += 1;
            continue;
        }
        // command[i] == ' '
        if (i + 1 >= search_end or command[i + 1] != '-') {
            i += 1;
            continue;
        }

        // " --message" long form
        if (i + 2 < search_end and command[i + 2] == '-') {
            if (std.mem.startsWith(u8, command[i..], " --message")) {
                const after = i + " --message".len;
                if (after >= search_end) return .{ .flag_start = i, .val_start = after };
                const c = command[after];
                if (c == '=') return .{ .flag_start = i, .val_start = after + 1 };
                if (c == ' ' or c == '"' or c == '\'') return .{ .flag_start = i, .val_start = after };
            }
            i += 1;
            continue;
        }

        // " -[a-z]*m" short flag (possibly combined like -am, -sam)
        var j = i + 2; // skip " -"
        while (j < search_end and std.ascii.isAlphabetic(command[j])) j += 1;
        if (j > i + 2 and command[j - 1] == 'm') {
            // Last flag letter is 'm' — message follows
            if (j >= search_end or command[j] == ' ' or command[j] == '"' or command[j] == '\'') {
                return .{ .flag_start = i, .val_start = j };
            }
        }

        i += 1;
    }
    return null;
}

/// Skip quoted or unquoted message content starting at `pos`.
/// Returns the position just past the message end.
fn skipMessageContent(command: []const u8, start: usize) usize {
    // Skip whitespace
    var pos = start;
    while (pos < command.len and command[pos] == ' ') pos += 1;
    if (pos >= command.len) return command.len;

    if (command[pos] == '"') {
        // Double-quoted: find closing " (respecting backslash escapes)
        var j = pos + 1;
        while (j < command.len) {
            if (command[j] == '\\' and j + 1 < command.len) {
                j += 2;
            } else if (command[j] == '"') {
                return j + 1;
            } else {
                j += 1;
            }
        }
        return command.len;
    } else if (command[pos] == '\'') {
        // Single-quoted: find closing '
        if (std.mem.indexOfPos(u8, command, pos + 1, "'")) |end| {
            return end + 1;
        }
        return command.len;
    } else {
        // Unquoted: single word (up to space/tab)
        return pos + (std.mem.indexOfAny(u8, command[pos..], " \t") orelse command[pos..].len);
    }
}

/// Build stripped result: command[0..cut_start] ++ command[cut_end..] into buf.
fn buildStrippedResult(buf: []u8, command: []const u8, cut_start: usize, cut_end: usize) ?[]const u8 {
    const before = command[0..cut_start];
    const after = command[cut_end..];
    const total = before.len + after.len;
    if (total > buf.len) return null;
    @memcpy(buf[0..before.len], before);
    @memcpy(buf[before.len..total], after);
    return buf[0..total];
}

pub fn stripCommitMessage(buf: []u8, command: []const u8) []const u8 {
    // Strip -m/--message content from git commands, preserving chained commands after.
    // "git commit -am "msg" && rm -rf /" → "git commit -a && rm -rf /"
    // Only matches git subcommands at chain segment starts (not inside echo/grep arguments).
    const result = stripOneGitMessage(buf, command);
    // Handle chained git commands: git commit -m "msg" && git tag -m "msg"
    if (result.ptr != command.ptr) {
        var buf2: [65536]u8 = undefined;
        const second = stripOneGitMessage(&buf2, result);
        if (second.ptr != result.ptr) {
            @memcpy(buf[0..second.len], second);
            return buf[0..second.len];
        }
    }
    return result;
}

/// Find the end of the current chain segment (next unquoted chain separator).
/// Stops at &&, ||, ;, |, or newline, respecting single and double quotes.
fn findSegmentEnd(command: []const u8, start: usize) usize {
    var i = start;
    var in_sq = false;
    var in_dq = false;
    while (i < command.len) {
        const c = command[i];
        if (!in_dq and c == '\'' and !in_sq) {
            in_sq = true;
            i += 1;
            while (i < command.len and command[i] != '\'') i += 1;
            if (i < command.len) i += 1;
            in_sq = false;
            continue;
        }
        if (!in_sq and c == '"') {
            in_dq = !in_dq;
            i += 1;
            continue;
        }
        if (!in_sq and !in_dq) {
            if (c == ';' or c == '\n' or c == '|' or c == '`' or c == '(') return i;
            if (c == '&' and i + 1 < command.len and command[i + 1] == '&') return i;
            if (c == '$' and i + 1 < command.len and command[i + 1] == '(') return i;
        }
        i += 1;
    }
    return command.len;
}

fn stripOneGitMessage(buf: []u8, command: []const u8) []const u8 {
    // Find the earliest matching git subcommand at a segment start
    var best_idx: usize = command.len;
    for (git_message_subcommands) |subcmd| {
        if (std.mem.indexOf(u8, command, subcmd)) |idx| {
            if (isAtSegmentStart(command, idx) and idx < best_idx) {
                best_idx = idx;
            }
        }
    }
    if (best_idx == command.len) return command;

    // Limit flag search to the current chain segment
    const seg_end = findSegmentEnd(command, best_idx);

    // Find message flag within this segment only
    const flag = findMessageFlag(command, best_idx, seg_end) orelse return command;
    const msg_end = skipMessageContent(command, flag.val_start);

    // Don't strip messages containing active shell expansion ($(), backtick).
    // These are executable code, not plain text data. Single-quoted messages
    // are literal text (safe to strip).
    const msg_content = command[flag.val_start..msg_end];
    if (messageContainsExpansion(msg_content)) return command;

    return buildStrippedResult(buf, command, flag.flag_start, msg_end) orelse command;
}

/// Check if a message value (including surrounding quotes) contains
/// shell expansion syntax ($() or backtick) that is NOT inside single quotes.
fn messageContainsExpansion(msg: []const u8) bool {
    if (msg.len == 0) return false;
    // Skip leading whitespace
    var start: usize = 0;
    while (start < msg.len and msg[start] == ' ') start += 1;
    if (start >= msg.len) return false;

    // Single-quoted messages: all content is literal, no expansion possible
    if (msg[start] == '\'') return false;

    // Double-quoted or unquoted: check for $() or backtick
    for (start..msg.len) |i| {
        if (msg[i] == '`') return true;
        if (msg[i] == '$' and i + 1 < msg.len and msg[i + 1] == '(') return true;
    }
    return false;
}

/// Strip heredoc body content from shell commands.
/// Heredoc bodies are DATA, not executable commands, so they should not be
/// analyzed for security patterns. Removes lines between <<DELIM and DELIM.
/// The << marker line (including any pipes/redirects) is preserved.
pub fn stripHeredocBodies(buf: []u8, command: []const u8) []const u8 {
    var out: usize = 0;
    var i: usize = 0;
    const len = @min(command.len, buf.len);
    var in_single_quote = false;
    var in_double_quote = false;

    while (i < len) {
        const c = command[i];

        // Track quoting context (skip heredoc detection inside quotes)
        if (!in_double_quote and c == '\'' and !in_single_quote) {
            in_single_quote = true;
            if (out < buf.len) {
                buf[out] = c;
                out += 1;
            }
            i += 1;
            // Copy until closing '
            while (i < len and command[i] != '\'') {
                if (out < buf.len) {
                    buf[out] = command[i];
                    out += 1;
                }
                i += 1;
            }
            if (i < len) {
                if (out < buf.len) {
                    buf[out] = command[i];
                    out += 1;
                }
                i += 1;
            }
            in_single_quote = false;
            continue;
        }
        if (!in_single_quote and c == '"') {
            in_double_quote = !in_double_quote;
            if (out < buf.len) {
                buf[out] = c;
                out += 1;
            }
            i += 1;
            continue;
        }
        if (in_single_quote or in_double_quote) {
            if (out < buf.len) {
                buf[out] = c;
                out += 1;
            }
            i += 1;
            continue;
        }

        // Detect << (heredoc) but not <<< (here-string)
        if (c == '<' and i + 1 < len and command[i + 1] == '<' and
            (i + 2 >= len or command[i + 2] != '<'))
        {
            // Copy << to output
            if (out + 1 < buf.len) {
                buf[out] = '<';
                out += 1;
                buf[out] = '<';
                out += 1;
            }
            i += 2;

            // Skip optional -
            if (i < len and command[i] == '-') {
                if (out < buf.len) {
                    buf[out] = '-';
                    out += 1;
                }
                i += 1;
            }

            // Skip whitespace (copy to output)
            while (i < len and (command[i] == ' ' or command[i] == '\t')) {
                if (out < buf.len) {
                    buf[out] = command[i];
                    out += 1;
                }
                i += 1;
            }

            // Extract delimiter
            var delim_start: usize = i;
            var delim_end: usize = i;
            if (i < len and (command[i] == '\'' or command[i] == '"')) {
                const quote = command[i];
                if (out < buf.len) {
                    buf[out] = command[i];
                    out += 1;
                }
                i += 1;
                delim_start = i;
                while (i < len and command[i] != quote) {
                    if (out < buf.len) {
                        buf[out] = command[i];
                        out += 1;
                    }
                    i += 1;
                }
                delim_end = i;
                if (i < len) {
                    if (out < buf.len) {
                        buf[out] = command[i];
                        out += 1;
                    }
                    i += 1;
                }
            } else {
                delim_start = i;
                while (i < len and command[i] != ' ' and command[i] != '\t' and
                    command[i] != '\n' and command[i] != ';' and
                    command[i] != '&' and command[i] != '|')
                {
                    if (out < buf.len) {
                        buf[out] = command[i];
                        out += 1;
                    }
                    i += 1;
                }
                delim_end = i;
            }

            const delimiter = command[delim_start..delim_end];
            if (delimiter.len == 0) continue;

            // Copy rest of current line (preserves pipes, redirects, etc.)
            while (i < len and command[i] != '\n') {
                if (out < buf.len) {
                    buf[out] = command[i];
                    out += 1;
                }
                i += 1;
            }
            if (i < len) {
                if (out < buf.len) {
                    buf[out] = '\n';
                    out += 1;
                }
                i += 1;
            }

            // Skip heredoc body lines until delimiter line
            while (i < len) {
                const line_start = i;
                while (i < len and command[i] != '\n') i += 1;
                const line = command[line_start..i];
                if (i < len) i += 1; // skip \n

                const trimmed = std.mem.trimLeft(u8, line, "\t");
                if (std.mem.eql(u8, trimmed, delimiter)) break;
            }
            continue;
        }

        if (out < buf.len) {
            buf[out] = c;
            out += 1;
        }
        i += 1;
    }

    return buf[0..out];
}
