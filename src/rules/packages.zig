// Supply chain attack patterns — package install, registry, publish.

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
    "deno install -g",
    "deno install --global",
    "bun install -g",
    "bun install --global",
    "bun add -g",
    "bun add --global",
    "pipx install ",
};

// pip_local_flags moved to shell_detector.zig (detection mechanics, not policy)

// npx: downloads and executes arbitrary npm packages (issue #54) — prefix_only
pub const npx_commands = [_][]const u8{
    "npx",
};

// Package publish commands — supply chain attack vector — prefix_only
pub const package_publish_commands = [_][]const u8{
    "npm publish",
    "cargo publish",
    "twine upload",
    "gem push",
    "pub publish",
};

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
