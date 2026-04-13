const std = @import("std");

pub const HookInput = struct {
    tool_name: ?[]const u8 = null,
    tool_input: ?ToolInput = null,
};

pub const ToolInput = struct {
    command: ?[]const u8 = null,
    file_path: ?[]const u8 = null,
    url: ?[]const u8 = null,
};

pub const Decision = enum {
    allow,
    deny,
    /// Delegate to Claude Code's default permission flow (user confirmation prompt).
    /// Hook outputs warning to stderr but does not emit permissionDecision JSON.
    ask,
};

pub const RuleResult = struct {
    decision: Decision,
    reason: []const u8,
};
