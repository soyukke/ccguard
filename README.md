# ccguard

Ultra-lightweight [Claude Code](https://docs.anthropic.com/en/docs/claude-code) hook guard written in Zig.

**300KB binary, ~0ms latency** — runs on every tool call without you noticing.

ccguard acts as a `PreToolUse` hook that inspects every tool call (Bash, Read, Edit, Write) and blocks dangerous operations before they execute.

![demo](demo/demo.gif)

## Why

AI coding assistants can accidentally run destructive commands, read secrets, or install unwanted packages. Instead of maintaining a massive deny list in `settings.json`, ccguard provides a single binary that guards all tool calls with composable rules.

## Rules

| Category | Examples | Reason |
|---|---|---|
| **Destructive commands** | `rm -rf`, `mkfs`, `dd if=`, `shred`, `truncate` | Prevent data loss |
| **Privilege escalation** | `sudo`, `su -`, `doas`, `pkexec`, `eval`, `exec` | Block unauthorized access |
| **Git dangerous ops** | `git push --force`, `git reset --hard`, `git clean -f` | Protect git history |
| **Reverse shells** | `bash -i`, `/dev/tcp/`, `pty.spawn`, `child_process` | Block code injection |
| **Secret file access** | `.env`, `.ssh/`, `.aws/`, `*.pem`, `*.key`, `credentials` | Prevent secret leaks |
| **Secret exfiltration** | `curl` + `.env`, `wget` + `credentials` | Block data exfiltration |
| **Env variable dumps** | `env`, `printenv`, `export -p` | Prevent secret exposure |
| **Global installs** | `pip install`, `npm install -g`, `cargo install`, `brew install` | Prevent system modification |
| **macOS system commands** | `osascript`, `defaults write`, `diskutil`, `security` | Block system tampering |
| **Shell config modification** | `.zshrc`, `.bashrc`, `.gitconfig`, `.git/hooks/` | Protect shell environment |

## Install

### Build from source

```bash
git clone https://github.com/soyukke/ccguard.git
cd ccguard
zig build -Doptimize=ReleaseFast
cp zig-out/bin/ccguard ~/.local/bin/
```

### Requirements

- Zig 0.15+
- `~/.local/bin` in your `$PATH`

## Setup

Add to `~/.claude/settings.json`:

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "",
        "hooks": [
          {
            "type": "command",
            "command": "ccguard"
          }
        ]
      }
    ]
  }
}
```

That's it. Every tool call is now guarded.

## How it works

1. Claude Code calls a tool (Bash, Read, Edit, Write, etc.)
2. Before execution, the hook sends JSON to ccguard via stdin:
   ```json
   {"tool_name": "Bash", "tool_input": {"command": "rm -rf /"}}
   ```
3. ccguard evaluates rules and responds:
   - **Allow**: exit 0 + JSON with `"permissionDecision": "allow"`
   - **Deny**: exit 2 + JSON with `"permissionDecision": "deny"` + reason on stderr
4. Claude Code blocks or allows the tool call accordingly

## Test

```bash
# Run tests
zig build test

# Manual test
echo '{"tool_name":"Bash","tool_input":{"command":"rm -rf /"}}' | ccguard
# exit 2: ccguard: dangerous command blocked

echo '{"tool_name":"Bash","tool_input":{"command":"git status"}}' | ccguard
# exit 0: allowed
```

## Development

```bash
# Dev shell with Zig + ZLS (requires Nix with flakes)
direnv allow
# or
nix develop

# Build
zig build

# Test
zig build test

# Release build
zig build -Doptimize=ReleaseFast
```

## License

MIT
