# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

ccguard is a Claude Code PreToolUse hook guard written in Zig. It reads tool call JSON from stdin, evaluates it against security rules, and exits 0 (allow) or 2 (deny). Zero external dependencies.

## Build & Test Commands

```bash
zig build                          # Debug build
zig build -Doptimize=ReleaseFast   # Release build
zig build test                     # Run all tests (341 tests in src/tests.zig)
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

### Module Structure

| Module | Responsibility |
|---|---|
| `src/types.zig` | Data types: `HookInput`, `ToolInput`, `Decision`, `RuleResult` |
| `src/rules.zig` | Security policy pattern arrays (pure configuration data, no logic) |
| `src/normalizer.zig` | Input normalization pipeline: `normalizePath`, `normalizeShellEvasion` (delegates to `normalizeBasic`, `expandBraces`, `collapseSpaces`), `stripCommitMessage` |
| `src/path_matcher.zig` | Path-based matching: `basename`, `matchesSecretPattern`, `matchesProcSecret` |
| `src/shell_analyzer.zig` | Shell segment analysis: `ChainIterator`, `containsPattern(Safe)`, `stripShellPrefix`, `isSafeArgCommand`, `isEnvDump`, `matchesPrefixInChain`, `countChainSegments`. Owns internal tables: `chain_separators`, `safe_arg_commands` |
| `src/shell_detector.zig` | Shell execution detection: `hasPipeToShell`, `hasProcessSubstitutionShell`, `isPipLocalInstall`, `containsDnsCommand`. Owns internal table: `pip_local_flags` |
| `src/evaluator.zig` | Rule evaluation orchestration: `checkBashCommand`, `checkFileAccess`, `evaluate` |
| `src/main.zig` | Entry point & I/O: `main`, `writeOutput` |
| `src/tests.zig` | All 341 integration tests (category-based sections) |

Dependency graph (no cycles):
```
types        (standalone)
rules        (standalone — policy patterns only)
normalizer   (standalone)
path_matcher ← rules
shell_analyzer (standalone — owns detection-mechanics tables)
shell_detector ← rules, path_matcher
evaluator    ← types, rules, normalizer, path_matcher, shell_analyzer, shell_detector
main         ← types, evaluator
tests        ← evaluator
```

### Flow

1. **main()** (`main.zig`) reads up to 64KB JSON from stdin, parses into `HookInput`
2. **evaluate()** (`evaluator.zig`) dispatches by `tool_name`:
   - `Bash` → `checkBashCommand()` with normalization pipeline + pattern matching
   - `Read` → `checkFileAccess()` against secret file patterns only
   - `Edit`/`Write` → `checkFileAccess()` against secret files, shell config, and system paths
   - Unknown tools → allow
3. **writeOutput()** (`main.zig`) emits PreToolUse hook JSON response with allow/deny decision

### checkBashCommand Normalization Pipeline (`normalizer.zig` → `shell_analyzer.zig`)

1. Block ANSI-C quoting (`\x`, `\0`) on raw input
2. `stripCommitMessage()` — remove `-m "..."` content to prevent FPs from commit messages
3. `normalizeShellEvasion()` — tab→space, `${IFS}`/`$IFS`→space, quote stripping, brace expansion, backslash-newline removal, space collapse
4. `containsPatternSafe()` for dangerous_commands, reverse_shell, pipe_shell (skips safe-arg segments)
5. `containsPattern()` for network+secret exfiltration (intentionally not safe-arg aware)
6. `hasPipeToShell()` — dynamic pipe-to-shell detection with basename matching
7. Other checks: global_install, history_evasion, file_attr, prefix_only, env_dump, dns_exfil, container_escape, docker, proc_secret

### checkFileAccess Flow

1. `normalizePath()` — collapse `//`, `/./`, `/../`
2. `matchesSecretPattern()` — basename-aware secret file detection
3. `matchesProcSecret()` — `/proc/*/environ`, `/proc/*/cmdline`
4. Edit/Write only: `shell_config_patterns`, `system_path_patterns`

### Rule Categories (pattern arrays in `rules.zig`)

| Array | Check Type | Applies To |
|---|---|---|
| `dangerous_commands` | segment-aware (`containsPatternSafe`) | Bash |
| `reverse_shell_patterns` | segment-aware (`containsPatternSafe`) | Bash |
| `pipe_shell_patterns` | segment-aware (`containsPatternSafe`) | Bash |
| `shell_obfuscation_patterns` | substring (raw input) | Bash |
| `network_commands` + `secret_keywords` | substring AND (intentionally not safe-arg aware) | Bash (exfiltration) |
| `global_install_commands` | substring | Bash |
| `history_evasion_commands` | substring | Bash |
| `file_attr_commands` | substring | Bash |
| `dns_exfil_commands` + `cmd_subst_indicators` | word-boundary + substring AND | Bash (DNS exfiltration) |
| `container_escape_patterns` | substring | Bash |
| `docker_context` + `docker_dangerous_patterns` | compound (docker context + flag substring) | Bash |
| `lib_injection_patterns` | segment-aware (`containsPatternSafe`) | Bash |
| `cloud_metadata_patterns` | segment-aware (`containsPatternSafe`) | Bash |
| `ssh_context` + `ssh_tunnel_flags` | compound (ssh context + flag substring) | Bash |
| `prefix_only_commands` | exact/prefix per segment | Bash (chain-aware) |
| `safe_arg_commands` | prefix match per segment | Bash (FP prevention) |
| `proc_secret_files` | path-token aware | Read/Edit/Write + Bash |
| `secret_exact_names/dir/file/extensions` | basename-aware | Read/Edit/Write |
| `shell_config_patterns` | substring | Edit/Write only |
| `system_path_patterns` | startsWith | Edit/Write only |

### Key design decisions

- **Segment-aware matching (`containsPatternSafe`)**: Uses `ChainIterator` to split command by `chain_separators` (`&&`, `||`, `;`, `$(`, `` ` ``, `|`, `\n`, `(`, `{`), identifies the first token of each segment, skips pattern matching for `safe_arg_commands` (grep, echo, git log, etc.) to prevent FPs like `grep 'import socket'` triggering reverse shell detection. `ChainIterator` is also reused by `isEnvDump`, `matchesPrefixInChain`, and `countChainSegments`
- **Shell evasion normalization (`normalizeShellEvasion`)**: 3-pass pipeline via `normalizeBasic` → `expandBraces` → `collapseSpaces`, all operating in-place on a single buffer. Pass 1: tab→space, `${IFS}`/`$IFS`→space, quote stripping, backslash-newline removal. Pass 2: brace expansion `{a,b,c}`→`a b c`. Pass 3: consecutive space collapse. Applied before pattern matching to defeat obfuscation
- **Path normalization (`normalizePath`)**: Collapses `//`, `/./`, `/../` before file path checks to prevent traversal bypasses
- **Pipe-to-shell detection (`hasPipeToShell`)**: Basename matching of pipe target token, including `env` wrapper detection (`| /usr/bin/env bash`)
- **Commit message stripping (`stripCommitMessage`)**: Parses quoted/unquoted `-m` messages, preserves chained commands after the message. Applied BEFORE `normalizeShellEvasion` (which strips quotes)
- **DNS exfiltration (`containsDnsCommand`)**: Word-boundary aware check prevents FPs like "digital"/"digest" matching "dig"
- **Proc secret detection (`matchesProcSecret`)**: Extracts single path token after `/proc/` to prevent cross-command FPs
- `containsPattern()` does simple substring matching; used intentionally for exfiltration checks where safe-arg skipping would create security holes
- `matchesPrefixInChain()` splits on `&&`, `||`, `;` and checks each segment with `isExactOrPrefixMatch()`
- `matchesSecretPattern()` uses basename-aware matching to prevent false positives (e.g., `.envrc`, `environment.ts` are allowed; `.env`, `.env.local` are blocked)
- `.env.example`, `.env.template`, `.env.sample` are allowed as template files
- `isPipLocalInstall()` checks ALL `pip install` occurrences; if any lacks `-r`/`-e`, it denies
- Shell config files (`.zshrc`, `.gitconfig`, `.claude/settings`, `.cursor/mcp.json`, `.mcp.json`, `.cursor/rules`) are blocked for Edit/Write but allowed for Read
- System paths (`/etc/`, `/usr/`, `/System/`, `/private/etc/`, `/private/var/`) are blocked for Edit/Write but allowed for Read
- **Excessive chaining defense (`countChainSegments`)**: Counts `&&` and `||` separators; >50 segments denied to prevent deny-rules bypass attacks
- **Library injection defense**: Blocks `LD_PRELOAD=`, `DYLD_INSERT_LIBRARIES=`, `LD_LIBRARY_PATH=` (segment-aware)
- **Cloud metadata defense**: Blocks `169.254.169.254`, `metadata.google.internal`, `metadata.internal/` (segment-aware)
- **SSH tunneling defense**: Compound check requiring `ssh ` context plus tunnel flags (`-R`, `-L`, `-D`)
- **Git credential theft defense**: Blocks `credential.helper`, `git credential-`, `git credential ` in commands
- **Heredoc/herestring to shell**: Blocks `bash <<`, `sh <<`, `zsh <<` and no-space variants
- Tests in `src/tests.zig` cover both attack patterns and false-positive prevention (341 tests, organized by category)

## Development Workflow

機能追加・バグ修正は必ず以下の流れで進める:

1. **RED**: 先にテストを書く（失敗することを確認）
2. **GREEN**: テストが通る最小限の実装を行う
3. **Review**: GPT (Codex) にレビューを依頼し、バイパス・誤爆・ロジックバグを指摘してもらう
4. **Fix**: レビュー指摘をTDDで修正 → 再レビュー（指摘なしになるまで繰り返す）

## Development Environment

Requires Zig 0.15.2+. Nix users: `nix develop` or `direnv allow` provides zig, zls, just, and vhs.

## 日本語で返答してください
