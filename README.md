# ccguard

Ultra-lightweight Claude Code hook guard written in Zig.

Reads JSON from stdin, evaluates security rules, outputs a permission decision.

## Rules

- **Dangerous commands**: `rm -rf`, `sudo`, `git push --force`, `git reset --hard`, etc.
- **Secret file access**: `.env`, `.ssh/`, `.aws/`, `*.pem`, `*.key`, `credentials`, etc.
- **Exfiltration**: `curl`/`wget`/`nc` combined with secret file patterns

## Build

```bash
zig build -Doptimize=ReleaseFast
```

## Install

```bash
cp zig-out/bin/ccguard ~/.local/bin/
```

## Configure Claude Code

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

## Test

```bash
echo '{"tool_name":"Bash","tool_input":{"command":"rm -rf /"}}' | zig-out/bin/ccguard
# exit 2, blocked

echo '{"tool_name":"Bash","tool_input":{"command":"git status"}}' | zig-out/bin/ccguard
# exit 0, allowed
```
