// Shell execution detection — pipe-to-shell, process substitution, pip install, DNS exfiltration.

const std = @import("std");
const rules = @import("rules.zig");
const path_matcher = @import("path_matcher.zig");

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
    const shell_names = [_][]const u8{ "bash", "sh", "zsh" };
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

// Check if command uses process substitution to execute a shell: bash <(...), sh <(...), source <(...), . <(...)
pub fn hasProcessSubstitutionShell(command: []const u8) bool {
    const shell_names = [_][]const u8{ "bash", "sh", "zsh", "source" };
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

// --- Pip install detection ---

pub fn isPipLocalInstall(command: []const u8) bool {
    // Check ALL occurrences of pip install. If any lacks a local flag, return false.
    const prefixes = [_][]const u8{ "pip install ", "pip3 install " };
    var found_any = false;
    for (prefixes) |prefix| {
        var offset: usize = 0;
        while (offset < command.len) {
            if (std.mem.indexOfPos(u8, command, offset, prefix)) |idx| {
                found_any = true;
                const after = command[idx + prefix.len ..];
                var has_local_flag = false;
                for (pip_local_flags) |flag| {
                    if (std.mem.startsWith(u8, after, flag)) {
                        has_local_flag = true;
                        break;
                    }
                }
                if (!has_local_flag) return false;
                offset = idx + prefix.len;
            } else break;
        }
    }
    return found_any;
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
