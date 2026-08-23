"""Refuses to let a credential into the repository.

Called from both CI pipelines (GitLab and GitHub Actions) rather than being
written out inline in each. Two copies of a check are one copy that quietly
falls behind, and this is not a check worth having half of.

Scope is the tracked files - `.env` and friends are gitignored and never
reach here anyway. What this does NOT do is scan the history: a secret removed
three commits ago is still in every clone, and once a repository is public it
has to be treated as burned rather than fixed. Do that check before publishing,
not on every push, because it costs a walk over every blob ever written.

Exit code 1 on a finding, so the pipeline stops.
"""
from __future__ import annotations

import re
import subprocess
import sys

PATTERNS = [
    (re.compile(r"SECRET_KEY\s*[:=]\s*['\"][A-Za-z0-9+/=_-]{16,}"), "hard-coded SECRET_KEY"),
    (re.compile(r"(?i)(password|passwort)\s*[:=]\s*['\"][^'\"]{8,}"), "hard-coded password"),
    (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"), "private key"),
    (re.compile(r"\bglpat-[A-Za-z0-9_-]{20,}"), "GitLab token"),
    (re.compile(r"\bghp_[A-Za-z0-9]{30,}"), "GitHub token"),
    (re.compile(r"(?i)\bnetbox[_-]?token\s*[:=]\s*['\"][A-Za-z0-9]{20,}"), "NetBox token"),
    (re.compile(r"(?i)aws_secret_access_key\s*[:=]\s*\S{20,}"), "AWS secret"),
]

# Not real secrets: shell and compose variables, command substitution, and the
# placeholders the documentation is full of on purpose.
PLACEHOLDER = re.compile(r"\$\(|\$\{|\$[A-Z_]+|change-?me|example|xxx|\.\.\.|your-", re.I)

# Demo credentials and test fixtures are published deliberately - they are in
# the README and on the public demo. Flagging them buries the real findings.
ALLOWED_PATHS = ("tests/", "seed_demo.py", "seed.py", ".gitlab-ci.yml",
                 ".github/workflows/", "docs/", "README", "scripts/secret_scan.py")

SKIP_SUFFIXES = (".png", ".jpg", ".jpeg", ".gif", ".ico", ".lock", ".woff", ".woff2", ".pdf")


def tracked_files() -> list[str]:
    out = subprocess.run(["git", "ls-files"], capture_output=True, text=True, check=True)
    return out.stdout.split()


def scan() -> list[str]:
    hits: list[str] = []
    for path in tracked_files():
        if path.endswith(SKIP_SUFFIXES) or any(a in path for a in ALLOWED_PATHS):
            continue
        try:
            with open(path, encoding="utf-8", errors="ignore") as handle:
                text = handle.read()
        except OSError:
            continue
        for pattern, label in PATTERNS:
            for match in pattern.finditer(text):
                if PLACEHOLDER.search(match.group(0)):
                    continue
                hits.append(f"{path}: {label} -> {match.group(0)[:60]}")
    return hits


if __name__ == "__main__":
    findings = scan()
    if findings:
        print("Possible secrets found in the repository:")
        for finding in findings:
            print("  " + finding)
        print("\nIf one of these is a placeholder, widen PLACEHOLDER in this file "
              "rather than deleting the check.")
        sys.exit(1)
    print("No secrets found in tracked files.")
