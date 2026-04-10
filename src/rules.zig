// Rule pattern definitions — pure configuration data, no logic.

// Dangerous command patterns to block
pub const dangerous_commands = [_][]const u8{
    "rm -rf",
    "rm -fr",
    "rm -r -f",
    "rm -f -r",
    "rm --recursive --force",
    "rm --force --recursive",
    " -delete",
    "sudo ",
    "chmod 777",
    "chmod u+s",
    "chmod +s ",
    "git push --force",
    "git push -f",
    "git reset --hard",
    "git clean -f",
    // Credential theft
    "credential.helper",
    "git credential-",
    "git credential ",
    "mkfs",
    "dd if=",
    "> /dev/",
    "shred ",
    "truncate ",
    // Privilege escalation
    "su -",
    "su root",
    "doas ",
    "pkexec ",
    // Persistence
    "crontab ",
    "launchctl ",
    "systemctl enable",
    "systemctl start",
    // macOS specific
    "osascript ",
    "defaults write ",
    "defaults delete ",
    "diskutil ",
    "hdiutil ",
    "spctl ",
    "tccutil ",
    "codesign ",
    "dscl ",
    "PlistBuddy ",
};

// Reverse shell / code injection patterns
pub const reverse_shell_patterns = [_][]const u8{
    "/dev/tcp/",
    "/dev/udp/",
    "bash -i",
    "sh -i",
    "import socket",
    "socket.socket",
    "socket.connect",
    "use Socket",
    "SOCK_STREAM",
    "pty.spawn",
    "child_process",
    "TCPSocket",
    "fsockopen",
    "net.Socket",
    "os.dup2",
    "__import__",
};

// Shell binary names — single source of truth for pipe-to-shell, process substitution, heredoc detection
pub const shell_names = [_][]const u8{ "bash", "sh", "zsh", "dash", "fish", "ksh", "csh", "tcsh" };

// Pipe-to-shell execution patterns
pub const pipe_shell_patterns = [_][]const u8{
    "| bash",
    "| sh",
    "| zsh",
    "| sudo bash",
    "| sudo sh",
    "|bash",
    "|sh",
    "|zsh",
    // Absolute path bypass prevention
    "| /bin/bash",
    "| /bin/sh",
    "| /bin/zsh",
    "| /usr/bin/bash",
    "| /usr/bin/sh",
    "| /usr/bin/zsh",
    "|/bin/bash",
    "|/bin/sh",
    "|/bin/zsh",
    "|/usr/bin/bash",
    "|/usr/bin/sh",
    "|/usr/bin/zsh",
    // Heredoc/herestring to shell (bash << also covers bash <<<)
    "bash <<",
    "sh <<",
    "zsh <<",
    "dash <<",
    "fish <<",
    "ksh <<",
    "csh <<",
    "tcsh <<",
    // No-space variants
    "bash<<<",
    "sh<<<",
    "zsh<<<",
    "dash<<<",
    "fish<<<",
    "ksh<<<",
    "csh<<<",
    "tcsh<<<",
};

// Patterns that indicate sensitive files (path-segment aware)
// Checked via matchesSecretPattern() for precise matching
pub const secret_exact_names = [_][]const u8{
    ".env",
    ".netrc",
    ".git-credentials",
    ".htpasswd",
};

// Patterns that match as path segments (/.ssh/, /.aws/, etc.)
pub const secret_dir_patterns = [_][]const u8{
    "/.ssh/",
    "/.gnupg/",
    "/.aws/",
    "/.kube/",
};

// Patterns that match filenames (basename starts with)
pub const secret_file_patterns = [_][]const u8{
    "id_rsa",
    "id_ed25519",
    "credentials",
};

// Extensions that indicate secret files
pub const secret_extensions = [_][]const u8{
    ".pem",
    ".pfx",
    ".p12",
    ".jks",
    ".keystore",
};

// Secret keywords for bash exfiltration detection (substring match in commands)
// More specific than file patterns to reduce false positives in URLs/paths
pub const secret_keywords = [_][]const u8{
    "@.env",
    "/.env",
    " .env ",
    " .env\"",
    " .env)",
    " .env'",
    "id_rsa",
    "id_ed25519",
    ".pem",
    "/.ssh/",
    "/.gnupg/",
    "/.aws/",
    "/.kube/",
    "/credentials ",
    "/credentials\"",
    "/.git-credentials",
    "/.netrc",
    // Additional secret file extensions for exfiltration detection
    ".pfx",
    ".p12",
    ".jks",
    ".keystore",
    ".htpasswd",
};

// Network exfiltration commands
pub const network_commands = [_][]const u8{
    "curl ",
    "wget ",
    "nc ",
    "ncat ",
    "socat ",
    "telnet ",
    "ftp ",
    "sftp ",
    "rsync ",
    "scp ",
    // Encrypted exfiltration channel
    "openssl s_client",
};

// Global package install commands
pub const global_install_commands = [_][]const u8{
    "pip install ",
    "pip3 install ",
    "npm install -g ",
    "cargo install ",
    "go install ",
    "gem install ",
    "brew install ",
    "brew tap ",
};

// pip_local_flags moved to shell_detector.zig (detection mechanics, not policy)

// History evasion commands
pub const history_evasion_commands = [_][]const u8{
    "unset HISTFILE",
    "history -c",
    "history -w /dev/null",
    "HISTSIZE=0",
    "HISTFILE=",
};

// File ownership/attribute change commands
pub const file_attr_commands = [_][]const u8{
    "chown ",
    "chattr ",
    "xattr ",
};

// DNS exfiltration commands (checked with command substitution indicators)
pub const dns_exfil_commands = [_][]const u8{
    "nslookup",
    "dig",
};

// Command substitution indicators
pub const cmd_subst_indicators = [_][]const u8{
    "$(",
    "`",
};

// Shell obfuscation patterns (always block)
pub const shell_obfuscation_patterns = [_][]const u8{
    "$'\\x", // ANSI-C hex quoting: $'\x72\x6d' = rm
    "$'\\0", // ANSI-C octal quoting
};

// Container escape patterns (substring match)
pub const container_escape_patterns = [_][]const u8{
    "nsenter ",
};

// Context patterns used for compound checks in evaluator
pub const docker_context = [_][]const u8{"docker "};
pub const ssh_context = [_][]const u8{"ssh "};

// Docker-specific dangerous patterns (require "docker" context)
pub const docker_dangerous_patterns = [_][]const u8{
    "--privileged",
    "-v /:/",
    "-v/:/",
};

// Library injection patterns (always block regardless of safe-arg)
pub const lib_injection_patterns = [_][]const u8{
    "LD_PRELOAD=",
    "DYLD_INSERT_LIBRARIES=",
    "LD_LIBRARY_PATH=",
};

// Cloud metadata endpoint patterns (IMDS credential theft)
pub const cloud_metadata_patterns = [_][]const u8{
    "169.254.169.254",
    "metadata.google.internal",
    "metadata.internal/",
};

// SSH tunneling / port forwarding flag patterns (checked after "ssh " context)
pub const ssh_tunnel_flags = [_][]const u8{
    " -R ",
    " -R:",
    " -L ",
    " -L:",
    " -D ",
    " -D:",
};

// /proc sensitive file names (matched after /proc/ prefix)
pub const proc_secret_files = [_][]const u8{
    "/environ",
    "/cmdline",
};

// Commands that are only dangerous at the start (shell builtins)
pub const prefix_only_commands = [_][]const u8{
    "printenv",
    "export -p",
    "eval",
    "exec",
    "security",
    "at",
    "batch",
    // Script sourcing — executes arbitrary scripts in current shell
    "source",
    ".",
};

// System paths that should not be edited/written
pub const system_path_patterns = [_][]const u8{
    "/etc/",
    "/usr/",
    "/System/",
    "/Library/LaunchDaemons/",
    "/Library/LaunchAgents/",
    // macOS real paths
    "/private/etc/",
    "/private/var/",
};

// Shell config files that should not be edited/written
pub const shell_config_patterns = [_][]const u8{
    ".bashrc",
    ".bash_profile",
    ".bash_logout",
    ".zshrc",
    ".zprofile",
    ".zshenv",
    ".zlogin",
    ".zlogout",
    ".profile",
    ".gitconfig",
    ".git/hooks/",
    // Claude Code / IDE settings protection
    "/.claude/settings",
    "/.cursor/mcp.json",
    // MCP configuration protection
    ".mcp.json",
    "/.cursor/rules",
    // VSCode / IDE MCP and settings protection
    ".vscode/mcp.json",
    ".vscode/settings.json",
    "cline_mcp_settings.json",
    "/.continue/config.json",
    // JetBrains IDE config protection (IDEsaster CVE-2025-54130)
    ".idea/",
    // VSCode workspace file protection (IDEsaster)
    ".code-workspace",
    // AI IDE instruction files (prompt injection vector)
    "copilot-instructions.md",
    ".cursorrules",
    ".kiro/",
};

// safe_arg_commands moved to shell_analyzer.zig (detection mechanics, not policy)

pub const env_template_suffixes = [_][]const u8{
    ".example",
    ".template",
    ".sample",
};

// chain_separators moved to shell_analyzer.zig (detection mechanics, not policy)

// Custom package registry flags — supply chain attack vector (AC-1.a)
pub const custom_registry_patterns = [_][]const u8{
    "--index-url ",
    "--index-url=",
    "--extra-index-url ",
    "--extra-index-url=",
    "install -i https://",
    "install -i http://",
    "--registry ",
    "--registry=",
};

// Credential literal patterns — inline API key exfiltration (AC-2)
// Used with network_commands in compound check
pub const credential_literal_patterns = [_][]const u8{
    "AKIA",          // AWS Access Key ID prefix
    "ghp_",          // GitHub personal access token
    "gho_",          // GitHub OAuth token
    "ghs_",          // GitHub Actions token
    "github_pat_",   // GitHub fine-grained PAT
    "sk-proj-",      // OpenAI project API key
    "sk-ant-",       // Anthropic API key
    "xoxb-",         // Slack Bot Token
    "xoxp-",         // Slack User Token
    "glpat-",        // GitLab Personal Access Token
};

// Sensitive environment variable names — exfiltration via network commands (AC-2)
// Used with network_commands in compound check
pub const sensitive_env_vars = [_][]const u8{
    "$OPENAI_API_KEY",
    "$ANTHROPIC_API_KEY",
    "$AWS_SECRET_ACCESS_KEY",
    "$AWS_ACCESS_KEY_ID",
    "$GITHUB_TOKEN",
    "$GH_TOKEN",
    "$GITLAB_TOKEN",
    "$SLACK_TOKEN",
    "$SLACK_BOT_TOKEN",
    "${OPENAI_API_KEY}",
    "${ANTHROPIC_API_KEY}",
    "${AWS_SECRET_ACCESS_KEY}",
    "${AWS_ACCESS_KEY_ID}",
    "${GITHUB_TOKEN}",
    "${GH_TOKEN}",
    "${GITLAB_TOKEN}",
    "${SLACK_TOKEN}",
    "${SLACK_BOT_TOKEN}",
};
