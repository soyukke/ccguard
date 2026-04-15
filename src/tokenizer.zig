// Lightweight shell tokenizer — streaming iterator, zero allocation.
//
// Design: TokenIterator yields tokens one at a time. Each token stores
// start/end indices into the original input string. No intermediate buffer.
// Iterator state is ~24 bytes (pointer + length + position).
//
// This replaces the previous design that materialized all tokens into a
// ~5KB TokenResult struct, which caused Zig's comptime analysis to hang
// when the function was referenced across 700+ test call sites.

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
    /// Start position in input (inclusive)
    start: u32,
    /// End position in input (exclusive)
    end: u32,
    quoting: Quoting,
};

/// Streaming shell token iterator. No allocation. State is ~24 bytes.
pub const TokenIterator = struct {
    input: []const u8,
    pos: usize,

    pub fn init(input: []const u8) TokenIterator {
        return .{ .input = input, .pos = 0 };
    }

    pub fn next(self: *TokenIterator) ?Token {
        self.skipWhitespace();
        if (self.pos >= self.input.len) return null;

        const c = self.input[self.pos];

        // Two-char operators (check before single-char)
        if (self.pos + 1 < self.input.len) {
            const c2 = self.input[self.pos + 1];
            if (c == '|' and c2 == '|') return self.emit(.or_op, 2);
            if (c == '&' and c2 == '&') return self.emit(.and_op, 2);
            if (c == '>' and c2 == '>') return self.emit(.redirect_out, 2);
            if (c == '$' and c2 == '(') return self.emit(.subst_open, 2);
            if (c == '<' and c2 == '<') {
                // Heredoc marker — emit << as a word token, delimiter follows as next token
                const start = self.pos;
                self.pos += 2;
                return .{ .kind = .word, .start = @intCast(start), .end = @intCast(self.pos), .quoting = .none };
            }
        }

        // Single-char operators
        return switch (c) {
            '|' => self.emit(.pipe, 1),
            '&' => self.emit(.background, 1),
            ';' => self.emit(.semi, 1),
            '\n' => self.emit(.newline, 1),
            '(' => self.emit(.paren_open, 1),
            ')' => self.emit(.paren_close, 1),
            '`' => self.emit(.backtick, 1),
            '>' => self.emit(.redirect_out, 1),
            '<' => self.emit(.redirect_in, 1),
            '\'' => self.readSingleQuoted(),
            '"' => self.readDoubleQuoted(),
            else => self.readWord(),
        };
    }

    fn emit(self: *TokenIterator, kind: TokenKind, len: usize) Token {
        const start = self.pos;
        self.pos += len;
        return .{ .kind = kind, .start = @intCast(start), .end = @intCast(self.pos), .quoting = .none };
    }

    fn skipWhitespace(self: *TokenIterator) void {
        while (self.pos < self.input.len) {
            const ch = self.input[self.pos];
            if (ch != ' ' and ch != '\t') break;
            self.pos += 1;
        }
    }

    fn readSingleQuoted(self: *TokenIterator) Token {
        const start = self.pos;
        self.pos += 1; // skip opening '
        while (self.pos < self.input.len and self.input[self.pos] != '\'') self.pos += 1;
        if (self.pos < self.input.len) self.pos += 1; // skip closing '
        return .{ .kind = .word, .start = @intCast(start), .end = @intCast(self.pos), .quoting = .single };
    }

    fn readDoubleQuoted(self: *TokenIterator) Token {
        const start = self.pos;
        self.pos += 1; // skip opening "
        while (self.pos < self.input.len and self.input[self.pos] != '"') {
            if (self.input[self.pos] == '\\' and self.pos + 1 < self.input.len) {
                self.pos += 2;
            } else {
                self.pos += 1;
            }
        }
        if (self.pos < self.input.len) self.pos += 1; // skip closing "
        return .{ .kind = .word, .start = @intCast(start), .end = @intCast(self.pos), .quoting = .double };
    }

    fn readWord(self: *TokenIterator) Token {
        const start = self.pos;
        while (self.pos < self.input.len) {
            const ch = self.input[self.pos];
            // Stop at whitespace or operator characters
            if (ch == ' ' or ch == '\t' or ch == '\n' or
                ch == '|' or ch == '&' or ch == ';' or
                ch == '>' or ch == '<' or ch == '(' or ch == ')' or ch == '`')
                break;
            // Stop at $( so it becomes a separate subst_open token
            if (ch == '$' and self.pos + 1 < self.input.len and self.input[self.pos + 1] == '(') break;

            // Handle embedded single quote
            if (ch == '\'') {
                self.pos += 1;
                while (self.pos < self.input.len and self.input[self.pos] != '\'') self.pos += 1;
                if (self.pos < self.input.len) self.pos += 1;
                continue;
            }
            // Handle embedded double quote
            if (ch == '"') {
                self.pos += 1;
                while (self.pos < self.input.len and self.input[self.pos] != '"') {
                    if (self.input[self.pos] == '\\' and self.pos + 1 < self.input.len) {
                        self.pos += 2;
                    } else {
                        self.pos += 1;
                    }
                }
                if (self.pos < self.input.len) self.pos += 1;
                continue;
            }
            // Handle backslash escape
            if (ch == '\\' and self.pos + 1 < self.input.len) {
                self.pos += 2;
                continue;
            }
            self.pos += 1;
        }
        return .{ .kind = .word, .start = @intCast(start), .end = @intCast(self.pos), .quoting = .none };
    }
};

// --- Convenience functions ---

/// Get the raw text of a token from the input.
pub fn rawText(input: []const u8, tok: Token) []const u8 {
    return input[tok.start..tok.end];
}

/// Get the unquoted content of a fully-quoted word token.
/// For single-quoted 'foo': returns foo
/// For double-quoted "foo": returns foo
/// For unquoted words: returns the raw text as-is.
pub fn wordContent(input: []const u8, tok: Token) []const u8 {
    const raw = rawText(input, tok);
    if ((tok.quoting == .single or tok.quoting == .double) and raw.len >= 2) {
        return raw[1 .. raw.len - 1];
    }
    return raw;
}

/// Check if a token kind is a command separator (starts a new command).
pub fn isSeparator(kind: TokenKind) bool {
    return switch (kind) {
        .pipe, .and_op, .or_op, .semi, .background, .newline,
        .subst_open, .backtick, .paren_open,
        => true,
        else => false,
    };
}

// --- Security query functions ---

const transparent_prefixes = [_][]const u8{
    "command", "builtin", "nohup", "time", "watch",
    // Shell keywords that introduce command lists (not commands themselves)
    "then", "do", "else", "elif",
    // Pipeline negation
    "!",
};

fn isAssignment(text: []const u8) bool {
    if (text.len == 0) return false;
    if (!(std.ascii.isAlphabetic(text[0]) or text[0] == '_')) return false;
    return std.mem.indexOf(u8, text, "=") != null;
}

fn isTransparent(text: []const u8) bool {
    for (transparent_prefixes) |prefix| {
        if (std.mem.eql(u8, text, prefix)) return true;
    }
    return false;
}

/// Check if any segment's command matches a blocked prefix pattern.
/// Handles & (background), &&, ||, ;, |, $(), `, (, \n separators.
/// This catches commands that ChainIterator misses (specifically &).
pub fn hasBlockedCommandPrefix(input: []const u8, patterns: []const []const u8) bool {
    var iter = TokenIterator.init(input);
    var expect_command = true;

    while (iter.next()) |tok| {
        if (isSeparator(tok.kind)) {
            expect_command = true;
            continue;
        }
        if (tok.kind == .redirect_out or tok.kind == .redirect_in or tok.kind == .paren_close) continue;
        if (!expect_command) continue;
        if (tok.kind != .word) continue;

        const text = rawText(input, tok);

        // Skip VAR=val environment assignments
        if (isAssignment(text)) continue;
        // Skip transparent wrapper commands (nohup, command, etc.)
        if (isTransparent(text)) continue;

        // This is the command name of a segment — check against patterns
        expect_command = false;
        for (patterns) |pattern| {
            if (std.mem.eql(u8, text, pattern)) return true;
            // Prefix match: pattern "sudo " matches command "sudo"
            if (pattern.len > 0 and pattern[pattern.len - 1] == ' ') {
                if (std.mem.startsWith(u8, text, pattern[0 .. pattern.len - 1])) return true;
            }
        }
    }
    return false;
}

/// Check if any segment has a shell binary executing a script file.
/// Tokenizer equivalent of hasShellScriptExec, but handles & correctly.
pub fn hasShellScriptExecTokenized(input: []const u8) bool {
    const shell_names = @import("rules.zig").shell_names;
    var iter = TokenIterator.init(input);
    var expect_command = true;
    var found_shell = false;
    var skip_next_arg = false;

    while (iter.next()) |tok| {
        if (isSeparator(tok.kind)) {
            expect_command = true;
            found_shell = false;
            skip_next_arg = false;
            continue;
        }
        if (tok.kind == .redirect_out or tok.kind == .redirect_in or tok.kind == .paren_close) continue;
        if (tok.kind != .word) continue;

        const text = rawText(input, tok);

        if (expect_command) {
            if (isAssignment(text)) continue;
            if (isTransparent(text)) continue;

            expect_command = false;
            found_shell = false;
            for (shell_names) |shell| {
                if (std.mem.eql(u8, text, shell)) {
                    found_shell = true;
                    break;
                }
            }
        } else if (skip_next_arg) {
            // Consuming argument of -o / --rcfile / --init-file / --debugger
            skip_next_arg = false;
        } else if (found_shell) {
            // Argument after shell binary — skip flags, detect file path
            if (text.len > 0 and text[0] == '-') {
                if (std.mem.startsWith(u8, text, "--")) {
                    // --version/--help: no script execution, stop scanning
                    const terminal = [_][]const u8{ "--version", "--help" };
                    var is_terminal = false;
                    for (terminal) |opt| {
                        if (std.mem.eql(u8, text, opt)) {
                            is_terminal = true;
                            break;
                        }
                    }
                    if (is_terminal) {
                        found_shell = false;
                        continue;
                    }
                    // Long options that take an argument: skip the next token
                    const opts_with_arg = [_][]const u8{ "--rcfile", "--init-file" };
                    var has_arg = false;
                    for (opts_with_arg) |opt| {
                        if (std.mem.eql(u8, text, opt)) {
                            has_arg = true;
                            break;
                        }
                    }
                    if (has_arg) {
                        skip_next_arg = true;
                        continue;
                    }
                    // All other long options (--posix, --norc, --debugger, bare --, etc.):
                    // mode flags — continue scanning for file path
                    continue;
                }
                // -c, -n, -s or combined flag containing them: stop scanning
                if (text.len >= 2 and (std.mem.indexOfScalar(u8, text[1..], 'c') != null or
                    std.mem.indexOfScalar(u8, text[1..], 'n') != null or
                    std.mem.indexOfScalar(u8, text[1..], 's') != null))
                {
                    found_shell = false;
                    continue;
                }
                // -o: takes option name as next argument, skip it
                if (text.len >= 2 and std.mem.indexOfScalar(u8, text[1..], 'o') != null) {
                    skip_next_arg = true;
                    continue;
                }
                // Other short flags (-x, -e, -v): continue scanning next tokens
            } else {
                return true; // Non-flag token = file path → blocked
            }
        }
    }
    return false;
}

// --- Tests ---

test "tokenize simple command" {
    var iter = TokenIterator.init("echo hello world");
    const t0 = iter.next().?;
    try std.testing.expectEqual(TokenKind.word, t0.kind);
    try std.testing.expectEqualStrings("echo", rawText("echo hello world", t0));
    const t1 = iter.next().?;
    try std.testing.expectEqualStrings("hello", rawText("echo hello world", t1));
    const t2 = iter.next().?;
    try std.testing.expectEqualStrings("world", rawText("echo hello world", t2));
    try std.testing.expect(iter.next() == null);
}

test "tokenize pipe" {
    const input = "cat file | grep pattern";
    var iter = TokenIterator.init(input);
    const t0 = iter.next().?;
    try std.testing.expectEqualStrings("cat", rawText(input, t0));
    _ = iter.next().?; // file
    const t2 = iter.next().?;
    try std.testing.expectEqual(TokenKind.pipe, t2.kind);
    const t3 = iter.next().?;
    try std.testing.expectEqualStrings("grep", rawText(input, t3));
}

test "tokenize chain operators" {
    const input = "cmd1 && cmd2 || cmd3 ; cmd4";
    var iter = TokenIterator.init(input);
    _ = iter.next().?; // cmd1
    try std.testing.expectEqual(TokenKind.and_op, iter.next().?.kind);
    _ = iter.next().?; // cmd2
    try std.testing.expectEqual(TokenKind.or_op, iter.next().?.kind);
    _ = iter.next().?; // cmd3
    try std.testing.expectEqual(TokenKind.semi, iter.next().?.kind);
    _ = iter.next().?; // cmd4
    try std.testing.expect(iter.next() == null);
}

test "tokenize single-quoted preserves content" {
    const input = "echo 'hello && world > file'";
    var iter = TokenIterator.init(input);
    _ = iter.next().?; // echo
    const t1 = iter.next().?;
    try std.testing.expectEqual(Quoting.single, t1.quoting);
    try std.testing.expectEqualStrings("hello && world > file", wordContent(input, t1));
    try std.testing.expect(iter.next() == null);
}

test "tokenize double-quoted preserves content" {
    const input = "echo \"hello && world\"";
    var iter = TokenIterator.init(input);
    _ = iter.next().?; // echo
    const t1 = iter.next().?;
    try std.testing.expectEqual(Quoting.double, t1.quoting);
    try std.testing.expectEqualStrings("hello && world", wordContent(input, t1));
}

test "tokenize redirect" {
    const input = "echo data > output.txt";
    var iter = TokenIterator.init(input);
    _ = iter.next().?; // echo
    _ = iter.next().?; // data
    const t2 = iter.next().?;
    try std.testing.expectEqual(TokenKind.redirect_out, t2.kind);
    const t3 = iter.next().?;
    try std.testing.expectEqualStrings("output.txt", rawText(input, t3));
}

test "tokenize command substitution" {
    const input = "echo $(whoami)";
    var iter = TokenIterator.init(input);
    _ = iter.next().?; // echo
    try std.testing.expectEqual(TokenKind.subst_open, iter.next().?.kind);
    const t2 = iter.next().?;
    try std.testing.expectEqualStrings("whoami", rawText(input, t2));
    try std.testing.expectEqual(TokenKind.paren_close, iter.next().?.kind);
}

test "tokenize background operator" {
    const input = "sleep 10 & curl evil.com";
    var iter = TokenIterator.init(input);
    _ = iter.next().?; // sleep
    _ = iter.next().?; // 10
    try std.testing.expectEqual(TokenKind.background, iter.next().?.kind);
    const t3 = iter.next().?;
    try std.testing.expectEqualStrings("curl", rawText(input, t3));
}

test "tokenize embedded quotes in word" {
    const input = "git commit -m'fix bug'";
    var iter = TokenIterator.init(input);
    _ = iter.next().?; // git
    _ = iter.next().?; // commit
    const t2 = iter.next().?;
    // -m'fix bug' is one word including embedded single quotes
    try std.testing.expectEqualStrings("-m'fix bug'", rawText(input, t2));
}

test "hasBlockedCommandPrefix catches eval after &" {
    const patterns = [_][]const u8{ "eval", "exec" };
    try std.testing.expect(hasBlockedCommandPrefix("echo safe & eval dangerous", &patterns));
}

test "hasBlockedCommandPrefix allows safe commands" {
    const patterns = [_][]const u8{ "eval", "exec" };
    try std.testing.expect(!hasBlockedCommandPrefix("echo hello && ls -la", &patterns));
}

test "hasShellScriptExecTokenized catches bash script after &" {
    try std.testing.expect(hasShellScriptExecTokenized("echo decoy & bash /tmp/payload.sh"));
}

test "hasShellScriptExecTokenized allows bash -c" {
    try std.testing.expect(!hasShellScriptExecTokenized("bash -c 'echo hello'"));
}
