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

// Shell-aware normalizer:
// - Tabs → space, ${IFS}/$IFS → space
// - Single-quoted mid-word → quotes stripped, content kept (evasion detection)
// - Double-quoted mid-word → quotes stripped, content kept (evasion detection)
// - Double-quoted whole arguments → quotes stripped, content kept (secret detection needs it)
// - Consecutive spaces collapsed
pub fn normalizeShellEvasion(buf: []u8, input: []const u8) []const u8 {
    var out: usize = 0;
    var i: usize = 0;
    const len = @min(input.len, buf.len);
    while (i < len) {
        // Backslash-newline (line continuation) → remove both
        if (input[i] == '\\' and i + 1 < len and input[i + 1] == '\n') {
            i += 2;
        }
        // Tab → space
        else if (input[i] == '\t') {
            buf[out] = ' ';
            out += 1;
            i += 1;
        }
        // ${IFS} → space
        else if (i + 5 < len and std.mem.eql(u8, input[i .. i + 6], "${IFS}")) {
            buf[out] = ' ';
            out += 1;
            i += 6;
        }
        // $IFS → space (without braces)
        else if (i + 3 < len and std.mem.eql(u8, input[i .. i + 4], "$IFS") and
            (i + 4 >= len or (!std.ascii.isAlphanumeric(input[i + 4]) and input[i + 4] != '_')))
        {
            buf[out] = ' ';
            out += 1;
            i += 4;
        }
        // Single quote
        else if (input[i] == '\'') {
            if (std.mem.indexOfPos(u8, input, i + 1, "'")) |close| {
                // Strip quotes, keep content (evasion detection + security)
                const content = input[i + 1 .. close];
                for (content) |c| {
                    if (out < buf.len) {
                        buf[out] = c;
                        out += 1;
                    }
                }
                i = close + 1;
            } else {
                buf[out] = input[i];
                out += 1;
                i += 1;
            }
        }
        // Double quote: strip quotes but always keep content
        // (content must remain visible for secret keyword detection)
        else if (input[i] == '"') {
            if (std.mem.indexOfPos(u8, input, i + 1, "\"")) |close| {
                // Always strip quotes and copy content
                const content = input[i + 1 .. close];
                for (content) |c| {
                    if (out < buf.len) {
                        buf[out] = c;
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

    // Pass 2: normalize brace expansion {a,b,c} → a b c
    // Only when preceded by whitespace/start/separator (command position)
    var brace_out: usize = 0;
    {
        var j: usize = 0;
        while (j < out) {
            if (buf[j] == '{') {
                const prev_is_sep = j == 0 or isShellSeparator(buf[j - 1]);
                // Find matching }
                if (std.mem.indexOfPos(u8, buf[0..out], j + 1, "}")) |close| {
                    // Check if it contains commas (brace expansion)
                    const inner = buf[j + 1 .. close];
                    if (std.mem.indexOf(u8, inner, ",") != null and prev_is_sep) {
                        // Replace { and } with space, commas with space
                        buf[brace_out] = ' ';
                        brace_out += 1;
                        for (inner) |c| {
                            if (c == ',') {
                                buf[brace_out] = ' ';
                            } else {
                                buf[brace_out] = c;
                            }
                            brace_out += 1;
                        }
                        buf[brace_out] = ' ';
                        brace_out += 1;
                        j = close + 1;
                    } else {
                        buf[brace_out] = buf[j];
                        brace_out += 1;
                        j += 1;
                    }
                } else {
                    buf[brace_out] = buf[j];
                    brace_out += 1;
                    j += 1;
                }
            } else {
                buf[brace_out] = buf[j];
                brace_out += 1;
                j += 1;
            }
        }
    }

    // Pass 3: collapse consecutive spaces
    var final_out: usize = 0;
    var prev_space = false;
    for (buf[0..brace_out]) |c| {
        if (c == ' ') {
            if (!prev_space) {
                buf[final_out] = c;
                final_out += 1;
            }
            prev_space = true;
        } else {
            buf[final_out] = c;
            final_out += 1;
            prev_space = false;
        }
    }
    return buf[0..final_out];
}

pub fn stripCommitMessage(buf: []u8, command: []const u8) []const u8 {
    // Strip only the -m message content from git commit, preserving chained commands after.
    // "git commit -m "msg" && rm -rf /" → "git commit  && rm -rf /"
    const commit_idx = std.mem.indexOf(u8, command, "git commit") orelse return command;
    const after_commit = command[commit_idx..];

    // Find -m flag
    const m_offset = std.mem.indexOf(u8, after_commit, " -m ") orelse
        std.mem.indexOf(u8, after_commit, " -m\"") orelse
        std.mem.indexOf(u8, after_commit, " -m'") orelse
        return command;

    const abs_m = commit_idx + m_offset; // position of " -m"
    const msg_start = abs_m + 3; // skip " -m"

    // Skip whitespace after -m
    var pos = msg_start;
    while (pos < command.len and command[pos] == ' ') pos += 1;
    if (pos >= command.len) return command[0..abs_m];

    // Find end of message
    var msg_end: usize = command.len;
    if (command[pos] == '"') {
        // Double-quoted: find closing "
        var j = pos + 1;
        while (j < command.len) {
            if (command[j] == '\\' and j + 1 < command.len) {
                j += 2;
            } else if (command[j] == '"') {
                msg_end = j + 1;
                break;
            } else {
                j += 1;
            }
        }
    } else if (command[pos] == '\'') {
        // Single-quoted: find closing '
        if (std.mem.indexOfPos(u8, command, pos + 1, "'")) |end| {
            msg_end = end + 1;
        }
    } else {
        // Unquoted: single word (up to space)
        msg_end = pos + (std.mem.indexOfAny(u8, command[pos..], " \t") orelse command[pos..].len);
    }

    // Concatenate: before -m + after message
    const before = command[0..abs_m];
    const after = command[msg_end..];
    const total = before.len + after.len;
    if (total > buf.len) return command; // safety fallback
    @memcpy(buf[0..before.len], before);
    @memcpy(buf[before.len..total], after);
    return buf[0..total];
}
