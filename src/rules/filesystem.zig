// File path protection patterns — shell config, CI/CD, system paths, file attributes.

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
    // Claude Code / IDE settings protection
    "/.claude/settings",
    "/.cursor/mcp.json",
    // MCP configuration protection
    ".mcp.json",
    "/.cursor/rules",
    // VSCode / IDE MCP and settings protection (IDEsaster CVE-2025-54130)
    ".vscode/mcp.json",
    ".vscode/settings.json",
    ".vscode/tasks.json",
    ".vscode/launch.json",
    ".vscode/extensions.json",
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

// Git hooks protection — ask user for confirmation on Edit/Write (not Read).
// Hooks are legitimate development artifacts but also an attack vector.
pub const git_hooks_patterns = [_][]const u8{
    ".git/hooks/",
};

// CI/CD pipeline config protection (issue #12)
// Ask user for confirmation on Edit/Write (not Read) — supply chain attack vector
// but also commonly edited during development.
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
    // Additional CI/CD systems (issue #57)
    ".drone.yml",
    "/.buildkite/",
    ".woodpecker.yml",
};

// IaC state files — hard deny (contain credentials/sensitive resource IDs)
pub const iac_state_patterns = [_][]const u8{
    "terraform.tfstate",
};

// File ownership/attribute change commands
pub const file_attr_commands = [_][]const u8{
    "chown ",
    "chattr ",
    "xattr ",
};
