// Integration tests — organized by attack category.

comptime {
    _ = @import("tests/basic.zig");
    _ = @import("tests/reverse_shell.zig");
    _ = @import("tests/dangerous_commands.zig");
    _ = @import("tests/global_install.zig");
    _ = @import("tests/env_dump.zig");
    _ = @import("tests/pipe_to_shell.zig");
    _ = @import("tests/shell_evasion.zig");
    _ = @import("tests/exfiltration.zig");
    _ = @import("tests/secret_files.zig");
    _ = @import("tests/file_protection.zig");
    _ = @import("tests/container_cloud.zig");
    _ = @import("tests/chain_bypass.zig");
    _ = @import("tests/false_positives.zig");
    _ = @import("tests/git.zig");
}
