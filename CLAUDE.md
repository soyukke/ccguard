# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

ccguard is a Claude Code PreToolUse hook guard written in Zig. It reads tool call JSON from stdin, evaluates it against security rules, and exits 0 (allow) or 2 (deny). Single-file implementation in `src/main.zig` with zero external dependencies.

## Build & Test Commands

```bash
zig build                          # Debug build
zig build -Doptimize=ReleaseFast   # Release build
zig build test                     # Run all tests (111 tests in src/main.zig)
```

With just (optional):
```bash
just test      # Run tests
just build     # Debug build
just release   # Release build
just install   # Release build + install to ~/.local/bin
just bench     # Benchmark all rule categories
```

## Architecture

All logic lives in `src/main.zig`. The flow is:

1. **main()** reads up to 64KB JSON from stdin, parses into `HookInput`
2. **evaluate()** dispatches by `tool_name`:
   - `Bash` → `checkBashCommand()` against dangerous/reverse-shell/network/install/prefix/macOS patterns
   - `Read` → `checkFileAccess()` against secret file patterns only
   - `Edit`/`Write` → `checkFileAccess()` against secret files AND shell config patterns
   - Unknown tools → allow
3. **writeOutput()** emits PreToolUse hook JSON response with allow/deny decision

### Rule Categories (pattern arrays at module level)

| Array | Check Type | Applies To |
|---|---|---|
| `dangerous_commands` | substring | Bash |
| `reverse_shell_patterns` | substring | Bash |
| `pipe_shell_patterns` | substring | Bash |
| `network_commands` + `secret_keywords` | substring AND | Bash (exfiltration) |
| `global_install_commands` | substring | Bash |
| `history_evasion_commands` | substring | Bash |
| `file_attr_commands` | substring | Bash |
| `prefix_only_commands` | exact/prefix per segment | Bash (chain-aware) |
| `secret_exact_names/dir/file/extensions` | basename-aware | Read/Edit/Write |
| `shell_config_patterns` | substring | Edit/Write only |
| `system_path_patterns` | startsWith | Edit/Write only |

### Key design decisions

- `containsPattern()` does substring matching; `isExactOrPrefixMatch()` handles commands that are only dangerous at command start position (e.g., `env`, `eval`)
- `matchesPrefixInChain()` splits on `&&`, `||`, `;` and checks each segment with `isExactOrPrefixMatch()`
- `matchesSecretPattern()` uses basename-aware matching to prevent false positives (e.g., `.envrc`, `environment.ts` are allowed; `.env`, `.env.local` are blocked)
- `.env.example`, `.env.template`, `.env.sample` are allowed as template files
- `isPipLocalInstall()` checks ALL `pip install` occurrences; if any lacks `-r`/`-e`, it denies
- Shell config files (`.zshrc`, `.gitconfig`, etc.) are blocked for Edit/Write but allowed for Read
- System paths (`/etc/`, `/usr/`, `/System/`) are blocked for Edit/Write but allowed for Read
- Tests inline in `src/main.zig` cover both attack patterns and false-positive prevention

## Development Workflow

機能追加・バグ修正は必ず以下の流れで進める:

1. **RED**: 先にテストを書く（失敗することを確認）
2. **GREEN**: テストが通る最小限の実装を行う
3. **Review**: GPT (Codex) にレビューを依頼し、バイパス・誤爆・ロジックバグを指摘してもらう
4. **Fix**: レビュー指摘をTDDで修正 → 再レビュー（指摘なしになるまで繰り返す）

## Development Environment

Requires Zig 0.15.2+. Nix users: `nix develop` or `direnv allow` provides zig, zls, just, and vhs.

## 日本語で返答してください
