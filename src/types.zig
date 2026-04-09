const std = @import("std");

pub const HookInput = struct {
    tool_name: ?[]const u8 = null,
    tool_input: ?ToolInput = null,
};

pub const ToolInput = struct {
    command: ?[]const u8 = null,
    file_path: ?[]const u8 = null,
};

pub const Decision = enum {
    allow,
    deny,
};

pub const RuleResult = struct {
    decision: Decision,
    reason: []const u8,
};
