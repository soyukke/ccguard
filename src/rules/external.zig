// External state mutation patterns — GitHub/GitLab CLI, git push, open, deploy.
// These return "ask" decision (user confirmation) rather than hard deny.

// gh api write operations — read-only GET is allowed, mutations are blocked
pub const gh_api_context = [_][]const u8{"gh api"};
pub const gh_api_write_flags = [_][]const u8{
    " -X POST",
    " -X PUT",
    " -X PATCH",
    " -X DELETE",
    " -f ",    // --field (sends data)
    " -F ",    // --field (file upload)
    " --field ",
    " --input ",
    " --method POST",
    " --method PUT",
    " --method PATCH",
    " --method DELETE",
};

// macOS/Linux URL/application opener — ask user confirmation (not deny)
// Uses prefix_only matching via matchesPrefixInChain for bare "open" / "xdg-open",
// plus containsPatternSafe for full-path variants like /usr/bin/open.
pub const open_commands = [_][]const u8{
    "open ",
    "xdg-open ",
    "/usr/bin/open ",
    "/usr/bin/xdg-open ",
};

// Irreversible external write operations — ask user confirmation
// git push (non-force; force push is already in dangerous_commands as deny)
pub const git_push_context = [_][]const u8{"git push"};

// gh CLI write subcommands — these mutate remote state and are not easily reversible.
// Format: "gh <resource> <subcommand>" — only mutation subcommands are listed.
// Read-only subcommands (list, view, status, checks, diff, checkout, clone) are allowed.
pub const gh_write_commands = [_][]const u8{
    // Pull requests
    "gh pr create",
    "gh pr merge",
    "gh pr close",
    "gh pr comment",
    "gh pr edit",
    "gh pr review",
    "gh pr ready",
    "gh pr reopen",
    "gh pr lock",
    "gh pr unlock",
    // Issues
    "gh issue create",
    "gh issue close",
    "gh issue comment",
    "gh issue edit",
    "gh issue reopen",
    "gh issue delete",
    "gh issue lock",
    "gh issue transfer",
    "gh issue pin",
    "gh issue unpin",
    // Releases
    "gh release create",
    "gh release delete",
    "gh release edit",
    "gh release upload",
    // Repositories
    "gh repo create",
    "gh repo delete",
    "gh repo edit",
    "gh repo fork",
    "gh repo archive",
    "gh repo rename",
    "gh repo unarchive",
    "gh repo sync",
    // Labels
    "gh label create",
    "gh label delete",
    "gh label edit",
    "gh label clone",
    // Secrets & variables
    "gh secret set",
    "gh secret delete",
    "gh variable set",
    "gh variable delete",
    // Workflows
    "gh workflow run",
    "gh workflow enable",
    "gh workflow disable",
    // Gists
    "gh gist create",
    "gh gist delete",
    "gh gist edit",
    // SSH keys & GPG keys
    "gh ssh-key add",
    "gh ssh-key delete",
    "gh gpg-key add",
    "gh gpg-key delete",
    // Projects
    "gh project create",
    "gh project delete",
    "gh project edit",
    "gh project close",
    // Cache
    "gh cache delete",
};

// Note: no safe-flag exemptions for irreversible write commands.
// Minor FPs (git push --help → ask) are acceptable because:
// 1. ask is a UX guard, not a security boundary — user can simply approve
// 2. Exemptions introduce bypass vectors (e.g. echo --help && git push)

// glab CLI write subcommands — GitLab CLI, same rationale as gh_write_commands.
pub const glab_write_commands = [_][]const u8{
    // Merge requests
    "glab mr create",
    "glab mr merge",
    "glab mr close",
    "glab mr comment",
    "glab mr edit",
    "glab mr reopen",
    // Issues
    "glab issue create",
    "glab issue close",
    "glab issue comment",
    "glab issue edit",
    "glab issue reopen",
    // Releases
    "glab release create",
    "glab release delete",
    // Labels
    "glab label create",
    "glab label delete",
};

// Deployment commands — external state mutation, ask user confirmation.
// Uses matchesPrefixInChain for prefix-based matching.
pub const deploy_commands = [_][]const u8{
    "vercel deploy",
    "vercel --prod",
    "netlify deploy",
    "fly deploy",
    "firebase deploy",
    "wrangler deploy",
    "wrangler publish",
    "railway deploy",
    "serverless deploy",
    "sls deploy",
    "sam deploy",
    "gcloud app deploy",
    "gcloud run deploy",
};

// git remote command execution via --upload-pack (abbreviated argument matching)
pub const git_remote_context = [_][]const u8{ "git ls-remote", "git fetch", "git clone", "git pull" };
pub const git_upload_pack_patterns = [_][]const u8{
    "--upload-pack",
    "--upload-pa", // Git abbreviated argument matching
    "-u ", // Short form of --upload-pack
};
