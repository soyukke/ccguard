// Network exfiltration patterns — network commands, encoding, file upload, DNS exfil.

// Network exfiltration commands
pub const network_commands = [_][]const u8{
    "curl ",
    "wget ",
    "nc ",
    "ncat ",
    "socat ",
    "telnet ",
    "ftp ",
    "sftp ",
    "rsync ",
    "scp ",
    // Encrypted exfiltration channel
    "openssl s_client",
};

// Encoding commands used for obfuscated exfiltration (issue #18)
// Used with network_commands in compound check
pub const encoding_commands = [_][]const u8{
    "base64 ",
    "base64|",
    "xxd ",
    "xxd|",
    "openssl base64",
};

// File upload exfiltration patterns (issue #5)
// Used with network command context (curl/wget) in compound check
pub const file_upload_patterns = [_][]const u8{
    " -T ",
    " -T=",
    "--upload-file ",
    "--upload-file=",
    " -F ",
    " -F=",
    " -d @",
    " -d=@",
    "--data-binary @",
    "--data-binary=@",
    "--post-file=",
    "--post-file ",
};

// DNS exfiltration commands (checked with command substitution indicators)
pub const dns_exfil_commands = [_][]const u8{
    "nslookup",
    "dig",
};

// Command substitution indicators
pub const cmd_subst_indicators = [_][]const u8{
    "$(",
    "`",
};
