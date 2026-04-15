// Dangerous tool access patterns — reconnaissance, cracking, debug, clipboard, etc.
// All checked via matchesPrefixInChain (prefix_only).

// Network reconnaissance (issue #22)
pub const recon_commands = [_][]const u8{
    "nmap",
    "masscan",
    "zmap",
};

// Password cracking (issue #22)
pub const cracking_commands = [_][]const u8{
    "john",
    "hashcat",
    "hydra",
};

// Network sniffing (issue #22)
pub const sniffing_commands = [_][]const u8{
    "tcpdump",
    "tshark",
};

// Exploit frameworks (issue #22)
pub const exploit_commands = [_][]const u8{
    "msfconsole",
    "sqlmap",
};

// Debug / process attach tools (issue #11)
pub const debug_commands = [_][]const u8{
    "strace",
    "ltrace",
    "gdb",
};

// Disk operations (issue #22)
pub const disk_commands = [_][]const u8{
    "fdisk",
    "parted",
    "cryptsetup",
};

// Clipboard access (issue #19) — AI agents should not read/write clipboard
pub const clipboard_commands = [_][]const u8{
    "pbpaste",
    "pbcopy",
    "xclip",
    "xsel",
    "wl-paste",
    "wl-copy",
};

// Database destructive commands
pub const db_destructive_commands = [_][]const u8{
    "dropdb",
    "dropuser",
};

// Mail sending commands
pub const mail_commands = [_][]const u8{
    "mail ",
    "sendmail ",
    "mutt ",
};
