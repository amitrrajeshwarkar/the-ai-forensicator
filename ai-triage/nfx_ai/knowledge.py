"""What each nfx finding tag means: category, base severity and MITRE ATT&CK mapping.

Severity is a starting weight for ranking, not a verdict:
    1 = context   (worth knowing, common on healthy hosts)
    2 = low       (often benign, review in context)
    3 = medium    (unusual, should be explained)
    4 = high      (rarely benign, explain before closing the case)

Rules are matched top to bottom; the first pattern that matches a tag wins.
"""
from __future__ import annotations

import re

SEVERITY_NAMES = {1: "context", 2: "low", 3: "medium", 4: "high"}

# (tag regex, category, severity, ATT&CK techniques)
RULES = [
    # Hiding and kernel-level tampering
    (r"HIDDEN-(PID|MODULE.*)|KPROBE|FTRACE-HOOK|PROC-BIND-MOUNT|SYSTEM-OVERMOUNT", "Defense evasion: hiding", 4, ["T1014", "T1564"]),
    (r"PAM-BACKDOOR|LD_PRELOAD|DYLD$", "Persistence: hijacked loading", 4, ["T1556.003", "T1574.006"]),
    (r"CRITICAL-BIN-MODIFIED|PKG-MODIFIED", "Integrity: modified system files", 4, ["T1554"]),
    (r"WEBSHELL-LIKELY|KNOWN-SHELL", "Persistence: web shell", 4, ["T1505.003"]),
    (r"IOC-.*", "Threat intel match", 4, []),
    (r"BRUTE-THEN-SUCCESS", "Credential access: brute force then login", 4, ["T1110", "T1078"]),
    (r"UID0|GID0|DUP-UID|EMPTY-PASSWORD|HIDDEN-USER", "Accounts: privileged or hidden", 4, ["T1136.001", "T1078.003"]),
    (r"AUTHKEY-CMD|SSHD-KEYCMD|SSHCFG-CMD|SSH-RC|SSHRC", "Persistence: SSH execution hooks", 4, ["T1098.004"]),
    (r"DELETED-EXE", "Execution: deleted binary still running", 4, ["T1070.004", "T1055"]),
    (r"LOG-ERASE|JOURNAL-VACUUM|HIST-NULL", "Defense evasion: log or history cleared", 4, ["T1070.002", "T1070.003"]),
    (r"SIP-(OFF|DISABLED)|GATEKEEPER-OFF|ASLR-OFF|AUTHROOT-DISABLED", "Defense evasion: protection disabled", 3, ["T1562.001"]),

    # Medium
    (r"TEMP-(EXEC|EXE|PROC-SOCKET)|STAGED-ARCHIVE|TOOL-TRANSFER", "Execution: temp-directory activity", 3, ["T1105", "T1074.001"]),
    (r"SHELL-WITH-SOCKET|RAW-SOCKET|PROMISC|NAT-REDIRECT|ODD-(LISTEN|REMOTE)-PORT|ARP-DUP-MAC", "Network: unusual sockets or traffic", 3, ["T1071", "T1040", "T1571"]),
    (r"ANON-EXE|COMM-MISMATCH|PS-MISMATCH|LD-ENV|DYLD-ENV|TRACED-BY.*|KTHREAD.*|MINER-NAME|SUSP-CMDLINE", "Execution: unusual process", 3, ["T1036", "T1055", "T1059"]),
    (r"SUSPICIOUS|SUSP-CMD|SHELL-HOOK|PTH-CODE|APT-HOOK|GIT-HOOK|UDEV-RUN|MODPROBE-INSTALL|LOGINHOOK|EMOND|STARTUPITEMS|APPLE-MASQ|UNSIGNED", "Persistence: suspicious autostart entry", 3, ["T1053", "T1543", "T1546", "T1547"]),
    (r"CRED-IN-HIST", "Credential exposure in history", 3, ["T1552.003"]),
    (r"SUDO-(NOPASSWD|ALL)|SUID-(GTFOBIN|WW|ODD-PATH|NONROOT|ADDED|CHANGED)|UNEXPECTED-SUID|CAPABILITY|CAP-ADD", "Privilege: escalation paths", 3, ["T1548.001", "T1548.003"]),
    (r"ROOT-SSH|SSHD-(ROOT|EMPTYPW|USERENV|AUTH|CA|KEYFILE)|AUTHKEYS-(RECENT|SYMLINK)|GLOBAL-KEYS|HOSTKEY-RECENT", "Access: SSH configuration and keys", 3, ["T1098.004", "T1021.004"]),
    (r"BRUTE-FORCE|SU-FAILURES|SUDO-DENIED", "Credential access: failed logins", 3, ["T1110"]),
    (r"NO-AUTH-LOGS|EMPTY-LOG|LOG-(GAP|SYMLINK)|JOURNAL-(CORRUPT|VOLATILE)|HIST-(EMPTY|CONFIG)", "Evidence gap: logs missing or empty", 3, ["T1070.002"]),
    (r"MODULE-(UNSIGNED|ODD-PATH|NOFILE)|TAINT-.*|THIRD-PARTY-KEXT|DMESG-MODULE|BPF-DEVICE", "Kernel: unusual modules", 3, ["T1547.006"]),
    (r"PRIVILEGED(-SELF)?|HOST-MOUNT|PID-HOST|DOCKER-(TCP|SOCK-.*)|K8S-PRIV|CONTAINER-SUSP|PRIV-BASE-IMAGE", "Containers: escape or exposure risk", 3, ["T1610", "T1611"]),
    (r"TCC-SENSITIVE-GRANT|NO-QUARANTINE|DOWNLOADED-INSTALLER|DOCK-ODD-APP|UNSIGNED-APP|AUTOLOGIN|ROOT-ENABLED", "macOS: security posture", 3, ["T1548.006", "T1553.001"]),
    (r"SCRIPT-IN-UPLOADS|HANDLER-TRICK|WEBUSER-WROTE-SCRIPT", "Web: suspicious scripts", 3, ["T1505.003"]),
    (r"ACCOUNT-CHANGE|RECENT-(PASSWD|ACCOUNT)|SYSTEM-PASSWD", "Accounts: recent changes", 3, ["T1098", "T1136"]),
    (r"PAM-INTERESTING|NSSWITCH", "Authentication stack changes", 3, ["T1556"]),
    (r"TIMESTOMP(-NS)?", "Defense evasion: timestamp anomaly", 2, ["T1070.006"]),

    # Low and context
    (r"HIDDEN-DOTS|DEV-FILE|ORPHAN-BIN|MISSING-BIN", "Filesystem: unusual files", 2, ["T1564.001"]),
    (r"SUID-(RECENT|REMOVED)|SUDO-(RECENT|INTERESTING|DEFAULTS)", "Privilege: recent changes", 2, ["T1548"]),
    (r"PRIVKEY-RECENT|AUTHKEY-(NOCOMMENT|COMMENT)|SSH-(OWNER|ENV)|HOME-PERMS", "Access: key hygiene", 2, ["T1552.004"]),
    (r"SYSTEM-SHELL|ODD-HOME", "Accounts: unusual configuration", 2, ["T1078.003"]),
    (r"LOG-(EMPTY|STALE)", "Evidence gap: logs missing or empty", 2, ["T1070.002"]),
    (r"HOSTS-(ENTRY|BLOCK)|PROXY-ENV", "Network: name resolution and proxies", 2, ["T1565.001", "T1090"]),
    (r"TOOL-INSTALL", "Software: tools installed", 2, ["T1072"]),
    (r"RECENT|HIST-LIVE|NEW-FINDING|USER-GREP|ODD-NAME|FSTAB-BIND", "Recent change", 1, []),
]
_COMPILED = [(re.compile(f"^(?:{p})$"), c, s, a) for p, c, s, a in RULES]


def describe(tag: str) -> dict:
    for rx, category, severity, attack in _COMPILED:
        if rx.match(tag):
            return {"category": category, "severity": severity, "attack": attack}
    return {"category": "Other", "severity": 2, "attack": []}


# Themes: groups of related tags. A theme fires when at least `min_tags` different tags from
# the set are present, which is how separate weak signals become one explainable lead.
THEMES = [
    {
        "id": "log-gap",
        "title": "Logging gap: authentication or system logs missing, empty or cleared",
        "tags": {"NO-AUTH-LOGS", "EMPTY-LOG", "LOG-EMPTY", "LOG-ERASE", "LOG-GAP", "LOG-SYMLINK",
                 "JOURNAL-VACUUM", "JOURNAL-VOLATILE", "JOURNAL-CORRUPT", "HIST-NULL", "HIST-EMPTY"},
        "min_tags": 2,
        "question": "Were logs never configured on this host, rotated normally, or deliberately cleared?",
    },
    {
        "id": "ssh-access",
        "title": "SSH access and key changes",
        "tags": {"AUTHKEYS-RECENT", "AUTHKEY-CMD", "AUTHKEYS-SYMLINK", "ROOT-SSH", "SSHD-ROOT", "SSHD-KEYCMD",
                 "SSHD-EMPTYPW", "BRUTE-FORCE", "BRUTE-THEN-SUCCESS", "PRIVKEY-RECENT", "SSH-RC", "SSHRC",
                 "SSHCFG-CMD", "GLOBAL-KEYS", "HOSTKEY-RECENT"},
        "min_tags": 2,
        "question": "Who added or changed SSH keys or settings, and does it match a known change?",
    },
    {
        "id": "privilege",
        "title": "Privilege escalation paths",
        "tags": {"SUDO-NOPASSWD", "SUDO-ALL", "UID0", "GID0", "DUP-UID", "SUID-GTFOBIN", "SUID-WW", "SUID-ODD-PATH",
                 "SUID-NONROOT", "SUID-ADDED", "SUID-CHANGED", "UNEXPECTED-SUID", "CAPABILITY", "EMPTY-PASSWORD"},
        "min_tags": 2,
        "question": "Is each privilege path intended and documented for this host's role?",
    },
    {
        "id": "process-tamper",
        "title": "Processes that hide or disguise what they run",
        "tags": {"DELETED-EXE", "ANON-EXE", "HIDDEN-PID", "COMM-MISMATCH", "PS-MISMATCH", "LD-ENV", "DYLD-ENV",
                 "LD_PRELOAD", "HIDDEN-MODULE", "HIDDEN-MODULE-KSYMS", "KTHREAD-NAME-WITH-EXE"},
        "min_tags": 2,
        "question": "Which software owns these processes, and is in-memory or deleted-binary execution expected for it?",
    },
    {
        "id": "temp-exec",
        "title": "Activity in temporary directories",
        "tags": {"TEMP-EXEC", "TEMP-EXE", "TEMP-PROC-SOCKET", "STAGED-ARCHIVE", "TOOL-TRANSFER", "HIDDEN-DOTS"},
        "min_tags": 2,
        "question": "What created the files in temporary directories, and are they still running or persisted?",
    },
    {
        "id": "persistence",
        "title": "New or unusual autostart entries",
        "tags": {"SUSPICIOUS", "SHELL-HOOK", "PTH-CODE", "APT-HOOK", "GIT-HOOK", "UDEV-RUN", "MODPROBE-INSTALL",
                 "LOGINHOOK", "EMOND", "STARTUPITEMS", "APPLE-MASQ", "LD_PRELOAD", "PAM-BACKDOOR"},
        "min_tags": 1,
        "question": "Does each autostart entry belong to installed software the owner recognises?",
    },
]

# Entities so common that sharing them says nothing about a link between findings.
GENERIC_ENTITIES = {
    "path": {"/", "/bin/bash", "/bin/sh", "/usr/bin/bash", "/bin/zsh", "/usr/bin/zsh", "/dev", "/tmp", "/etc",
             "/usr", "/var", "/var/log", "/home", "/root", "/proc", "/sys", "/usr/bin", "/usr/sbin", "/bin", "/sbin"},
    "ip": {"127.0.0.1", "0.0.0.0", "255.255.255.255"},
    "user": set(),
    "pid": set(),
}
