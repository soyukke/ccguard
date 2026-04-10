# ccguard

[Claude Code](https://docs.anthropic.com/en/docs/claude-code) が `rm -rf /` を実行する前に止める、Zig 製のセキュリティガード。

シェル回避・難読化を正規化してからパターンマッチするため、単純な文字列ブロックリストでは防げない攻撃も検知する。外部依存ゼロ、単一バイナリ。

![demo](demo/demo.gif)

## Why

AI coding assistants can accidentally run destructive commands, read secrets, or install unwanted packages. Instead of maintaining a massive deny list in `settings.json`, ccguard inspects every tool call as a `PreToolUse` hook and blocks dangerous operations with shell-aware pattern matching.

## Rules

### Bash commands

| Category | Examples | Reason |
|---|---|---|
| **Destructive commands** | `rm -rf`, `mkfs`, `dd if=`, `shred`, `truncate` | Prevent data loss |
| **Privilege escalation** | `sudo`, `su -`, `doas`, `pkexec`, `eval`, `exec` | Block unauthorized access |
| **Git dangerous ops** | `git push --force`, `git reset --hard`, `git clean -f` | Protect git history |
| **Reverse shells** | `bash -i`, `/dev/tcp/`, `pty.spawn`, `child_process` | Block code injection |
| **Pipe-to-shell** | `curl \| bash`, `wget \| sh`, `cat file \| zsh` | Block remote code execution |
| **Secret exfiltration** | `curl` + `.env`, `wget` + `credentials` | Block data exfiltration |
| **DNS exfiltration** | `dig $(cat .env)`, `nslookup $(...)` | Block DNS-based data theft |
| **Env variable dumps** | `env`, `printenv`, `export -p` | Prevent secret exposure |
| **Global installs** | `pip install`, `npm install -g`, `cargo install`, `brew install` | Prevent system modification |
| **History evasion** | `unset HISTFILE`, `history -c`, `HISTSIZE=0` | Prevent audit trail tampering |
| **File attribute changes** | `chown`, `chattr`, `xattr` | Block ownership/permission changes |
| **Shell obfuscation** | `$'\x72\x6d'`, `$'\0150'` | Defeat ANSI-C quoting bypass |
| **Container escape** | `nsenter -t 1 -m -u -i -p` | Block container breakout |
| **Docker dangerous ops** | `--privileged`, `-v /:/host` | Block privileged container access |
| **macOS system commands** | `osascript`, `defaults write`, `diskutil`, `security` | Block system tampering |
| **/proc sensitive access** | `/proc/self/environ`, `/proc/*/cmdline` | Block process secret access |

### File access (Read / Edit / Write)

| Category | Applies to | Examples | Reason |
|---|---|---|---|
| **Secret file access** | Read, Edit, Write | `.env`, `.ssh/`, `.aws/`, `*.pem`, `credentials` | Prevent secret leaks |
| **/proc sensitive access** | Read, Edit, Write | `/proc/self/environ`, `/proc/*/cmdline` | Block process secret access |
| **Shell config modification** | Edit, Write only | `.zshrc`, `.bashrc`, `.gitconfig`, `.claude/settings` | Protect shell environment |
| **System path protection** | Edit, Write only | `/etc/`, `/usr/`, `/System/`, `/Library/LaunchDaemons/` | Protect system files |

## Install

### Build from source

```bash
git clone https://github.com/soyukke/ccguard.git
cd ccguard
zig build -Doptimize=ReleaseFast
cp zig-out/bin/ccguard ~/.local/bin/
```

### Requirements

- Zig 0.15.2+
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

### Defense techniques

- **Segment-aware matching** — splits chains (`&&`, `||`, `;`, `|`, `$(`, `` ` ``) and skips safe-arg commands (`grep`, `echo`, `git log`, etc.) to prevent false positives
- **Shell evasion normalization** — `${IFS}`→space, tab→space, quote stripping, brace expansion, backslash-newline removal
- **Commit message stripping** — removes `-m "..."` content before pattern matching
- **Path normalization** — collapses `//`, `/./`, `/../` to prevent traversal bypass

## Test

```bash
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

# Build & test
zig build              # Debug build
zig build test         # Run all tests
zig build -Doptimize=ReleaseFast  # Release build
```

With [just](https://just.systems/) (optional):

```bash
just test      # Run tests
just build     # Debug build
just release   # Release build
just install   # Release build + install to ~/.local/bin
just bench     # Benchmark all rule categories
```

## License

MIT
