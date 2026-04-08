Output demo.gif

Set FontSize 14
Set Width 1000
Set Height 450
Set Theme "TokyoNight"
Set TypingSpeed 40ms
Set Padding 15
Set Shell "bash"
Env PS1 "$ "
Env BASH_SILENCE_DEPRECATION_WARNING "1"

Type "# ccguard - Claude Code hook guard"
Enter
Sleep 1s

Type "# 1. Dangerous command -> blocked"
Enter
Sleep 300ms
Type `echo '{"tool_name":"Bash","tool_input":{"command":"rm -rf /"}}' | ccguard`
Enter
Sleep 1.5s

Type "# 2. Secret file access -> blocked"
Enter
Sleep 300ms
Type `echo '{"tool_name":"Read","tool_input":{"file_path":"~/.ssh/id_ed25519"}}' | ccguard`
Enter
Sleep 1.5s

Type "# 3. Safe command -> allowed"
Enter
Sleep 300ms
Type `echo '{"tool_name":"Bash","tool_input":{"command":"git status"}}' | ccguard`
Enter
Sleep 1.5s

Type "# 279KB binary, ~0ms latency"
Enter
Type "du -h $(which ccguard)"
Enter
Sleep 2s
