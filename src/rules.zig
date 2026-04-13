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
    // Git config dangerous keys (issue #3)
    "core.hooksPath",
    "core.pager",
    "core.editor",
    "core.sshCommand",
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
    // Named pipe — used for IPC backdoors
    "mkfifo ",
    // Browser remote debugging / automation hijacking (issue #20)
    "--remote-debugging-port",
    "puppeteer.connect",
    "playwright.connect",
    "chrome-remote-interface",
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
    // Shell history files (issue #21) — may contain passwords typed on CLI
    ".bash_history",
    ".zsh_history",
    ".node_repl_history",
    ".python_history",
    ".psql_history",
    ".mysql_history",
    ".rediscli_history",
    // Claude internal data (issue #21)
    "history.jsonl",
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

// Encoding commands used for obfuscated exfiltration (issue #18)
// Used with network_commands in compound check
pub const encoding_commands = [_][]const u8{
    "base64 ",
    "base64|",
    "xxd ",
    "xxd|",
    "openssl base64",
};

// File upload exfiltration patterns (issue #5)
// Used with network command context (curl/wget) in compound check
pub const file_upload_patterns = [_][]const u8{
    " -T ",
    " -T=",
    "--upload-file ",
    "--upload-file=",
    " -F ",
    " -F=",
    " -d @",
    " -d=@",
    "--data-binary @",
    "--data-binary=@",
    "--post-file=",
    "--post-file ",
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
    "@P}", // ${var@P}: Bash prompt expansion — can execute commands
};

// Command options that execute arbitrary programs (Flatt Security "8 ways")
pub const command_exec_options = [_][]const u8{
    "--compress-program", // sort/tar/rsync: executes argument as compressor
    "--pager=", // git/man: executes argument as pager
};

// man-specific dangerous options (compound: require "man " context)
pub const man_context = [_][]const u8{"man "};
pub const man_dangerous_options = [_][]const u8{
    "--html=",
    "--html ",
    "--browser=",
    "--browser ",
};

// git remote command execution via --upload-pack (abbreviated argument matching)
pub const git_remote_context = [_][]const u8{ "git ls-remote", "git fetch", "git clone", "git pull" };
pub const git_upload_pack_patterns = [_][]const u8{
    "--upload-pack",
    "--upload-pa", // Git abbreviated argument matching
    "-u ", // Short form of --upload-pack
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

// Library/environment injection patterns (always block regardless of safe-arg)
pub const lib_injection_patterns = [_][]const u8{
    "LD_PRELOAD=",
    "DYLD_INSERT_LIBRARIES=",
    "LD_LIBRARY_PATH=",
    // Shell env var injection (issue #52): auto-sourced scripts
    "BASH_ENV=",
    // ENV= needs word-boundary: space prefix + segment-start variant to avoid FP with BUILD_ENV= etc.
    " ENV=",
    // Note: segment-start case handled by evaluator prefix check below
    // Interpreter env var injection (issue #52): module/flag injection
    "NODE_OPTIONS=",
    "PERL5OPT=",
    "RUBYOPT=",
    "PYTHONSTARTUP=",
    "PYTHONPATH=",
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
    // Coprocess — creates background shell process
    "coproc",
    // Alias definition — persistence/hijacking attack vector
    "alias ",
    // Kernel module operations (issue #10)
    "insmod",
    "rmmod",
    "modprobe",
    // Filesystem mount operations (issue #10)
    "mount",
    "umount",
    // Kernel parameter changes (issue #10)
    "sysctl",
    // Firewall / network manipulation (issue #10)
    "iptables",
    // Debug / process attach tools (issue #11)
    "strace",
    "ltrace",
    "gdb",
    // Network reconnaissance (issue #22)
    "nmap",
    "masscan",
    "zmap",
    // Password cracking (issue #22)
    "john",
    "hashcat",
    "hydra",
    // Network sniffing (issue #22)
    "tcpdump",
    "tshark",
    // Disk operations (issue #22)
    "fdisk",
    "parted",
    "cryptsetup",
    // Exploit frameworks (issue #22)
    "msfconsole",
    "sqlmap",
    // Clipboard access (issue #19) — AI agents should not read/write clipboard
    "pbpaste",
    "pbcopy",
    "xclip",
    "xsel",
    "wl-paste",
    "wl-copy",
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

// CI/CD pipeline and IaC state file protection (issue #12)
// Blocked for Edit/Write only (not Read) — supply chain attack vector.
pub const cicd_config_patterns = [_][]const u8{
    // GitHub Actions
    "/.github/workflows/",
    // GitLab CI
    ".gitlab-ci.yml",
    // Jenkins
    "Jenkinsfile",
    // CircleCI
    "/.circleci/",
    // Travis CI
    ".travis.yml",
    // Bitbucket Pipelines
    "bitbucket-pipelines.yml",
    // Terraform state (contains credentials/sensitive resource IDs)
    "terraform.tfstate",
};

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

// Interpreter one-liner context patterns (issue #17)
// Used in compound check: interpreter context + dangerous payload
pub const interpreter_exec_context = [_][]const u8{
    "python -c ",
    "python -c'",
    "python3 -c ",
    "python3 -c'",
    "ruby -e ",
    "ruby -e'",
    "perl -e ",
    "perl -e'",
    "node -e ",
    "node -e'",
};

// Dangerous payloads inside interpreter one-liners (issue #17)
pub const interpreter_dangerous_payloads = [_][]const u8{
    "os.system",
    "os.popen",
    "subprocess",
    "__import__",
    "socket",
    "child_process",
    "execSync",
    ".exec(",
    "system(",
    "pty.spawn",
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
