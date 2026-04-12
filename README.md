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
| **Custom package registry** | `pip install --index-url`, `npm --registry` | Block supply chain attacks |
| **Credential leakage** | `curl` + `AKIA*`, `ghp_*`, `sk-proj-*`, `xoxb-*` | Block API key exfiltration |
| **Sensitive env var exfiltration** | `curl` + `$OPENAI_API_KEY`, `$AWS_SECRET_ACCESS_KEY` | Block credential exfiltration |
| **Script sourcing** | `source script.sh`, `. setup.sh` | Block arbitrary script execution |
| **Git config dangerous keys** | `core.hooksPath`, `core.pager`, `core.editor`, `core.sshCommand` | Block arbitrary code execution via git config |
| **File upload exfiltration** | `curl -T`, `curl -F`, `curl -d @`, `wget --post-file` | Block file upload to external servers |
| **Shell script execution** | `bash /tmp/script.sh`, `sh ./evil.sh` | Block download-and-execute attacks |
| **Redirect to protected paths** | `echo "evil" > ~/.bashrc`, `printf > ~/.ssh/config` | Block redirect-based config writes |
| **Kernel/system commands** | `insmod`, `modprobe`, `mount`, `sysctl`, `iptables` | Block kernel/network manipulation |
| **Debug/process attach** | `gdb -p`, `strace -p`, `ltrace -p` | Block process inspection and injection |

### File access (Read / Edit / Write)

| Category | Applies to | Examples | Reason |
|---|---|---|---|
| **Secret file access** | Read, Edit, Write | `.env`, `.ssh/`, `.aws/`, `*.pem`, `credentials` | Prevent secret leaks |
| **/proc sensitive access** | Read, Edit, Write | `/proc/self/environ`, `/proc/*/cmdline` | Block process secret access |
| **Shell config modification** | Edit, Write, NotebookEdit | `.zshrc`, `.bashrc`, `.gitconfig`, `.claude/settings` | Protect shell environment |
| **IDE/MCP config protection** | Edit, Write, NotebookEdit | `.vscode/settings.json`, `.idea/`, `.code-workspace`, `.cursorrules`, `copilot-instructions.md`, `.kiro/` | Prevent agent trust boundary attacks |
| **CI/CD pipeline config** | Edit, Write, NotebookEdit | `.github/workflows/`, `.gitlab-ci.yml`, `Jenkinsfile`, `.circleci/`, `terraform.tfstate` | Prevent supply chain attacks via CI/CD |
| **System path protection** | Edit, Write, NotebookEdit | `/etc/`, `/usr/`, `/System/`, `/Library/LaunchDaemons/` | Protect system files |

## Install

### Plugin Marketplace (recommended)

Run in Claude Code:

```
/plugin marketplace add soyukke/ccguard
/plugin install ccguard@ccguard
```

That's it. The binary is downloaded automatically on session start. No build tools, no JSON editing.

### Build from source

```bash
git clone https://github.com/soyukke/ccguard.git
cd ccguard
zig build -Doptimize=ReleaseFast
cp zig-out/bin/ccguard ~/.local/bin/
```

Then add to `~/.claude/settings.json`:

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

#### Requirements (source build only)

- Zig 0.15.2+
- `~/.local/bin` in your `$PATH`

## How it works

1. Claude Code calls a tool (Bash, Read, Edit, Write, NotebookEdit, MCP tools, etc.)
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
- **Symlink resolution** — resolves symlinks via `realpath` before file path checks to prevent TOCTOU bypass
- **Redirect target extraction** — extracts paths after `>` / `>>` and checks against protected patterns
- **MCP/unknown tool inspection** — applies Bash and file access checks to unknown tool inputs

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

## References

- Liu, H., Shou, C., Wen, H., Chen, Y., Fang, R. J., & Feng, Y. (2025). *Your Agent Is Mine: Measuring Malicious Intermediary Attacks on the LLM Supply Chain*. arXiv:2604.08407. https://arxiv.org/abs/2604.08407
  - Supply chain attack defense rules (custom registry detection, credential leakage, sensitive env var exfiltration) are based on findings from this paper.
- Marzouk, A. (2025). *IDEsaster: A Novel Vulnerability Class in AI IDEs*. https://maccarita.com/posts/idesaster/
  - IDE config protection rules (`.idea/`, `.code-workspace`, `.cursorrules`, `copilot-instructions.md`, `.kiro/`) are based on CVE-2025-53773, CVE-2025-54130, and related vulnerabilities.
- Luo, Q., Ye, J., Chen, H., Tan, K., & Hou, B. (2025). *"Your AI, My Shell": Demystifying Prompt Injection Attacks on Agentic AI Coding Editors*. arXiv:2509.22040. https://arxiv.org/abs/2509.22040
  - Validated existing rules against 314 AIShellJack attack payloads covering 70 MITRE ATT&CK techniques.
- Maloyan, A. (2026). *Prompt Injection Attacks on Agentic Coding Assistants: A Systematic Analysis of Vulnerabilities in Skills, Tools, and Protocol Ecosystems*. arXiv:2601.17548. https://arxiv.org/abs/2601.17548
  - AI IDE instruction file protection (`copilot-instructions.md`, `.cursorrules`) is informed by this analysis.
- Ji, Z., Li, Z., Jiang, W., Gao, Y., & Wang, S. (2026). *Measuring the Permission Gate: A Stress-Test Evaluation of Claude Code's Auto Mode*. arXiv:2604.04978. https://arxiv.org/abs/2604.04978
  - CI/CD pipeline config protection and symlink TOCTOU mitigation are motivated by this paper's finding that 36.8% of state-changing actions bypass the classifier via Edit/Write tools.

## License

MIT
