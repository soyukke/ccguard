// Path-based matching — file path secret detection and /proc sensitivity checks.

const std = @import("std");
const rules = @import("rules.zig");

pub fn basename(path: []const u8) []const u8 {
    if (std.mem.lastIndexOfScalar(u8, path, '/')) |idx| {
        return path[idx + 1 ..];
    }
    return path;
}

pub fn matchesSecretPattern(file_path: []const u8) bool {
    const name = basename(file_path);

    // Public keys are safe — allow early before dir pattern check
    if (std.mem.endsWith(u8, name, ".pub")) return false;

    // Exact basename match: .env, .env.local, .env.production, etc.
    for (rules.secret_exact_names) |pattern| {
        if (std.mem.eql(u8, name, pattern)) return true;
        // .env.local, .env.production etc. (starts with .env.)
        if (pattern[0] == '.' and std.mem.startsWith(u8, name, pattern) and name.len > pattern.len and name[pattern.len] == '.') {
            // Allow template files: .env.example, .env.template, .env.sample
            const suffix = name[pattern.len..];
            var is_template = false;
            for (rules.env_template_suffixes) |tmpl| {
                if (std.mem.eql(u8, suffix, tmpl)) {
                    is_template = true;
                    break;
                }
            }
            if (!is_template) return true;
        }
    }

    // Directory patterns: /.ssh/, /.aws/, etc.
    for (rules.secret_dir_patterns) |pattern| {
        if (std.mem.indexOf(u8, file_path, pattern) != null) return true;
    }

    // Basename starts with pattern: id_rsa, id_ed25519, credentials
    // Matches: credentials, credentials.json, id_rsa (exact)
    // Does NOT match: credentials-helper.md, id_rsa.pub, id_ed25519.pub
    for (rules.secret_file_patterns) |pattern| {
        if (std.mem.startsWith(u8, name, pattern)) {
            // Exact match or followed by '.' (but not .pub — public keys are safe)
            if (name.len == pattern.len) return true;
            if (name[pattern.len] == '.' and !std.mem.endsWith(u8, name, ".pub")) return true;
        }
    }

    // Extension match on basename only: .pem, .key
    for (rules.secret_extensions) |ext| {
        if (std.mem.endsWith(u8, name, ext)) return true;
    }

    return false;
}

// Check if a path refers to a sensitive /proc file (e.g., /proc/self/environ, /proc/1/environ)
pub fn matchesProcSecret(text: []const u8) bool {
    var search = text;
    while (std.mem.indexOf(u8, search, "/proc/")) |idx| {
        const after_proc = search[idx + 6 ..]; // after "/proc/"
        // Extract the single path token (up to space, tab, newline, semicolon, pipe, or end)
        const path_end = std.mem.indexOfAny(u8, after_proc, " \t\n;|&") orelse after_proc.len;
        const path_token = after_proc[0..path_end];
        for (rules.proc_secret_files) |sensitive| {
            if (std.mem.indexOf(u8, path_token, sensitive)) |_| return true;
        }
        search = search[idx + 6 ..];
    }
    return false;
}
