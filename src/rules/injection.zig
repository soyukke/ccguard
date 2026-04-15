// Code and environment injection patterns — library injection, interpreter one-liners, exec options.

// Library/environment injection patterns (always block regardless of safe-arg)
pub const lib_injection_patterns = [_][]const u8{
    "LD_PRELOAD=",
    "DYLD_INSERT_LIBRARIES=",
    "LD_LIBRARY_PATH=",
    // Shell env var injection (issue #52): auto-sourced scripts
    "BASH_ENV=",
    // ENV= needs word-boundary: space prefix + segment-start variant to avoid FP with BUILD_ENV= etc.
    " ENV=",
    // Note: segment-start case handled by evaluator prefix check below
    // Interpreter env var injection (issue #52): module/flag injection
    "NODE_OPTIONS=",
    "PERL5OPT=",
    "RUBYOPT=",
    "PYTHONSTARTUP=",
    "PYTHONPATH=",
};

// Interpreter one-liner context patterns (issue #17)
// Used in compound check: interpreter context + dangerous payload
pub const interpreter_exec_context = [_][]const u8{
    "python -c ",
    "python -c'",
    "python3 -c ",
    "python3 -c'",
    "ruby -e ",
    "ruby -e'",
    "perl -e ",
    "perl -e'",
    "node -e ",
    "node -e'",
};

// Dangerous payloads inside interpreter one-liners (issue #17)
pub const interpreter_dangerous_payloads = [_][]const u8{
    "os.system",
    "os.popen",
    "subprocess",
    "__import__",
    "socket",
    "child_process",
    "execSync",
    ".exec(",
    "system(",
    "pty.spawn",
};

// Command options that execute arbitrary programs (Flatt Security "8 ways")
pub const command_exec_options = [_][]const u8{
    "--compress-program", // sort/tar/rsync: executes argument as compressor
    "--use-compress-program", // GNU tar synonym for --compress-program
    "--pager=", // git/man: executes argument as pager
    "--to-command", // tar: passes extracted files to command via stdin (issue #51)
    "--checkpoint-action=exec", // tar: inline form --checkpoint-action=exec=CMD (issue #51)
    "--checkpoint-action exec", // tar: space form --checkpoint-action exec=CMD (issue #51)
    "--info-script", // tar: volume change script execution (issue #51)
    "--new-volume-script", // tar: volume change script execution (issue #51)
    " -I ", // tar: short form of --use-compress-program (issue #51)
};

// man-specific dangerous options (compound: require "man " context)
pub const man_context = [_][]const u8{"man "};
pub const man_dangerous_options = [_][]const u8{
    "--html=",
    "--html ",
    "--browser=",
    "--browser ",
};
