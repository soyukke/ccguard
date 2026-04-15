// Infrastructure exploitation patterns — Docker, Kubernetes, cloud, SSH, tunnels.

// Context patterns used for compound checks in evaluator
pub const docker_context = [_][]const u8{"docker "};
pub const ssh_context = [_][]const u8{"ssh "};

// Docker-specific dangerous patterns (require "docker" context)
pub const docker_dangerous_patterns = [_][]const u8{
    "--privileged",
    "-v /:/",
    "-v/:/",
    // Container command execution / file transfer (issue #54)
    " exec ",
    " exec -",
    " cp ",
};

// Container escape patterns (substring match)
pub const container_escape_patterns = [_][]const u8{
    "nsenter ",
};

// SSH tunneling / port forwarding flag patterns (checked after "ssh " context)
pub const ssh_tunnel_flags = [_][]const u8{
    " -R ",
    " -R:",
    " -L ",
    " -L:",
    " -D ",
    " -D:",
};

// Cloud metadata endpoint patterns (IMDS credential theft)
pub const cloud_metadata_patterns = [_][]const u8{
    "169.254.169.254",
    "metadata.google.internal",
    "metadata.internal/",
    "fd00:ec2::254", // AWS IPv6 IMDS endpoint (issue #57)
};

// Kernel module / system operations (issue #10) — prefix_only
pub const kernel_commands = [_][]const u8{
    "insmod",
    "rmmod",
    "modprobe",
    "mount",
    "umount",
    "sysctl",
    "iptables",
};

// Cloud CLI data transfer (issue #55) — exfiltration via cloud storage — prefix_only
pub const cloud_transfer_commands = [_][]const u8{
    "aws s3 cp",
    "aws s3 sync",
    "aws s3 mv",
    "gsutil cp",
    "gsutil rsync",
    "az storage blob upload",
    "rclone copy",
    "rclone sync",
    "rclone move",
};

// Kubernetes admin commands (issue #54) — cluster mutation — prefix_only
pub const k8s_commands = [_][]const u8{
    "kubectl exec",
    "kubectl apply",
    "kubectl delete",
    "kubectl run",
};

// Infrastructure-as-Code mutation (issue #54) — prefix_only
pub const iac_commands = [_][]const u8{
    "terraform apply",
    "terraform destroy",
    "helm install",
    "helm upgrade",
    "pulumi up",
    "pulumi destroy",
};

// Docker registry operations — ask user confirmation (not deny)
pub const docker_ask_patterns = [_][]const u8{
    " push ",
    " push:",
    " login",
};

// Network tunnel exposure — prefix_only
pub const tunnel_commands = [_][]const u8{
    "ngrok",
    "localtunnel",
};
