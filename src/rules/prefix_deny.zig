// Aggregated prefix-deny patterns — single source of truth for all domain-specific
// prefix_only arrays. Used by evaluator (tokenizer backup) and benchmarks.
// Domain-specific matchesPrefixInChain checks in evaluator use individual arrays
// for domain-specific reason messages; this combined array is for hasBlockedCommandPrefix
// which catches the `&` (background) separator that ChainIterator misses.

const execution = @import("execution.zig");
const infra = @import("infra.zig");
const tools = @import("tools.zig");
const packages = @import("packages.zig");

pub const all_prefix_deny = execution.shell_builtins
    ++ infra.kernel_commands
    ++ tools.debug_commands
    ++ tools.recon_commands
    ++ tools.cracking_commands
    ++ tools.sniffing_commands
    ++ tools.disk_commands
    ++ tools.exploit_commands
    ++ infra.cloud_transfer_commands
    ++ tools.clipboard_commands
    ++ packages.npx_commands
    ++ infra.k8s_commands
    ++ infra.iac_commands
    ++ packages.package_publish_commands
    ++ infra.tunnel_commands
    ++ tools.db_destructive_commands
    ++ tools.mail_commands;
