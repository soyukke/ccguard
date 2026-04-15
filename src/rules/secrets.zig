// Credential and secret protection patterns — file patterns, keywords, env vars.

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

// /proc sensitive file names (matched after /proc/ prefix)
pub const proc_secret_files = [_][]const u8{
    "/environ",
    "/cmdline",
};

pub const env_template_suffixes = [_][]const u8{
    ".example",
    ".template",
    ".sample",
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
    // Additional credential patterns (issue #57)
    "eyJhbGciOi",    // JWT token (Base64 header: {"alg":)
    "ya29.",         // Google OAuth access token
    "AIza",          // Google API key
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
    // Additional service tokens (issue #57)
    "$NPM_TOKEN",
    "$PYPI_TOKEN",
    "$STRIPE_SECRET_KEY",
    "$STRIPE_API_KEY",
    "$HEROKU_API_KEY",
    "$DOCKER_HUB_TOKEN",
    "$VERCEL_TOKEN",
    "$CLOUDFLARE_API_TOKEN",
    "$AZURE_CLIENT_SECRET",
    "$DIGITALOCEAN_TOKEN",
    "${NPM_TOKEN}",
    "${PYPI_TOKEN}",
    "${STRIPE_SECRET_KEY}",
    "${STRIPE_API_KEY}",
    "${HEROKU_API_KEY}",
    "${DOCKER_HUB_TOKEN}",
    "${VERCEL_TOKEN}",
    "${CLOUDFLARE_API_TOKEN}",
    "${AZURE_CLIENT_SECRET}",
    "${DIGITALOCEAN_TOKEN}",
};
