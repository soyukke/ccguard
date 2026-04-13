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
    _ = @import("tests/supply_chain.zig");
    _ = @import("tests/compound_commands.zig");
    _ = @import("tests/system_commands.zig");
    _ = @import("tests/cicd_protection.zig");
    _ = @import("tests/notebook.zig");
    _ = @import("tests/upload_exfil.zig");
    _ = @import("tests/redirect.zig");
    _ = @import("tests/download_execute.zig");
    _ = @import("tests/symlink.zig");
    _ = @import("tests/mcp_tools.zig");
    _ = @import("tests/var_indirection.zig");
    _ = @import("tests/encoding_exfil.zig");
    _ = @import("tests/clipboard.zig");
    _ = @import("tests/browser_hijack.zig");
    _ = @import("tests/history_files.zig");
    _ = @import("tests/attack_tools.zig");
    _ = @import("tests/interpreter_exec.zig");
    _ = @import("tests/self_protection.zig");
    _ = @import("tests/background_operator.zig");
}
