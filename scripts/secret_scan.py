"""Refuses to let a credential or an internal name into the repository.

Called from both CI pipelines (GitLab and GitHub Actions) rather than being
written out inline in each. Two copies of a check are one copy that quietly
falls behind, and this is not a check worth having half of.

Two kinds of finding:

* **Secrets** - token shapes, private keys, hard-coded passwords. The patterns
  are generic and live here, in the open.
* **Internal terms** - host names, addresses, user names, paths that belong to
  the maintainer's infrastructure and not into a public repository. The list
  itself is such information, so it is not in the repository: it is read from
  the gitignored file `.secret_scan_internal` next to this script's repository
  root (one term per line, `#` comments allowed) and from the environment
  variable `SECRET_SCAN_INTERNAL_TERMS` (comma-separated), which a CI pipeline
  can provide as a protected variable. Terms match case-insensitively as plain
  substrings, so `10.20.30.` catches a whole subnet and `host01` catches
  `host01.example.org`. Without a list this half of the check is silently off,
  which is what a fork or an outside contributor's pipeline should get.

Scope is the tracked files - `.env` and friends are gitignored and never reach
here anyway. `--history` additionally walks every blob and every commit
message ever written, because a secret removed three commits ago is still in
every clone; once a repository is public that has to be treated as burned
rather than fixed. `--ref <rev>` limits that walk to what is reachable from
one revision - `--ref main` answers "what would the next push publish" when
the mirror's merge commits are not meant to leave the mirror. Run that check
before publishing, not on every push, as it costs a walk over every object.
Binary blobs (a database, an image) are searched for internal terms only.

When `CI` is set, the matched text of an internal term is not printed, because
public job logs would otherwise show exactly what the check exists to hide.

Exit code 1 on a finding, so the pipeline stops.
"""
from __future__ import annotations

import os
import re
import subprocess
import sys
from pathlib import Path

PATTERNS = [
    (re.compile(r"SECRET_KEY\s*[:=]\s*['\"][A-Za-z0-9+/=_-]{16,}"), "hard-coded SECRET_KEY"),
    (re.compile(r"(?i)(password|passwort)\s*[:=]\s*['\"][^'\"]{8,}"), "hard-coded password"),
    (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"), "private key"),
    (re.compile(r"\bglpat-[A-Za-z0-9_-]{20,}"), "GitLab token"),
    (re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,}"), "GitHub token"),
    (re.compile(r"\bgithub_pat_[A-Za-z0-9_]{30,}"), "GitHub fine-grained token"),
    (re.compile(r"(?i)\bnetbox[_-]?token\s*[:=]\s*['\"][A-Za-z0-9]{20,}"), "NetBox token"),
    (re.compile(r"(?i)aws_secret_access_key\s*[:=]\s*\S{20,}"), "AWS secret"),
    (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "AWS access key id"),
    (re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}"), "Slack token"),
    (re.compile(r"\bsk-(?:ant-|proj-)?[A-Za-z0-9_-]{32,}"), "API key (sk-...)"),
    (re.compile(r"(?i)\bsmtp[_-]?pass(?:word)?\s*[:=]\s*['\"][^'\"]{6,}"), "SMTP password"),
]

# Not real secrets: shell and compose variables, command substitution, and the
# placeholders the documentation is full of on purpose.
PLACEHOLDER = re.compile(r"\$\(|\$\{|\$[A-Z_]+|change-?me|example|xxx|\.\.\.|your-", re.I)

# Demo credentials and test fixtures are published deliberately - they are in
# the README and on the public demo. Flagging them buries the real findings.
# Internal terms are not excused anywhere: a host name in the README is the
# finding, not the noise.
ALLOWED_PATHS = ("tests/", "seed_demo.py", "seed.py", ".gitlab-ci.yml",
                 ".github/workflows/", "docs/", "README", "scripts/secret_scan.py")

SKIP_SUFFIXES = (".png", ".jpg", ".jpeg", ".gif", ".ico", ".lock", ".woff", ".woff2", ".pdf")

INTERNAL_TERMS_FILE = ".secret_scan_internal"
INTERNAL_TERMS_ENV = "SECRET_SCAN_INTERNAL_TERMS"


def git(*args: str, binary: bool = False) -> str | bytes:
    out = subprocess.run(["git", *args], capture_output=True, check=True, text=not binary)
    return out.stdout


def repo_root() -> Path:
    return Path(git("rev-parse", "--show-toplevel").strip())


def internal_terms() -> list[str]:
    """The maintainer's list, from the gitignored file and the environment."""
    terms: list[str] = []
    path = repo_root() / INTERNAL_TERMS_FILE
    if path.exists():
        for line in path.read_text(encoding="utf-8").splitlines():
            line = line.split("#", 1)[0].strip()
            if line:
                terms.append(line)
    for term in os.environ.get(INTERNAL_TERMS_ENV, "").split(","):
        if term.strip():
            terms.append(term.strip())
    return [t.lower() for t in dict.fromkeys(terms)]


def describe_term(term: str) -> str:
    """What to print for a hit: the term itself locally, a number under CI."""
    if os.environ.get("CI"):
        return f"internal term #{internal_terms().index(term) + 1}"
    return term


def scan_text(path: str, text: str, terms: list[str]) -> list[str]:
    hits: list[str] = []
    if not any(a in path for a in ALLOWED_PATHS):
        for pattern, label in PATTERNS:
            for match in pattern.finditer(text):
                if PLACEHOLDER.search(match.group(0)):
                    continue
                hits.append(f"{path}: {label} -> {match.group(0)[:60]}")
    lowered = text.lower()
    for term in terms:
        if term in lowered:
            hits.append(f"{path}: internal name -> {describe_term(term)}")
    return hits


def tracked_files() -> list[str]:
    return git("ls-files").split()


def scan(terms: list[str]) -> list[str]:
    hits: list[str] = []
    for path in tracked_files():
        if path.endswith(SKIP_SUFFIXES):
            continue
        try:
            with open(path, encoding="utf-8", errors="ignore") as handle:
                text = handle.read()
        except OSError:
            continue
        hits.extend(scan_text(path, text, terms))
    return hits


def scan_history(terms: list[str], ref: str = "--all") -> list[str]:
    """Every blob ever written, each once, and every commit message."""
    hits: list[str] = []
    seen: set[str] = set()
    listing = git("rev-list", ref, "--objects")
    names: dict[str, str] = {}
    for line in listing.splitlines():
        sha, _, name = line.partition(" ")
        if name and sha not in names:
            names[sha] = name
    wanted = [sha for sha, name in names.items() if not name.endswith(SKIP_SUFFIXES)]
    proc = subprocess.run(["git", "cat-file", "--batch"], input="\n".join(wanted).encode(),
                          capture_output=True, check=True)
    data = proc.stdout
    pos = 0
    while pos < len(data):
        end = data.index(b"\n", pos)
        header = data[pos:end].decode()
        pos = end + 1
        parts = header.split()
        if len(parts) != 3:       # "<sha> missing"
            continue
        sha, kind, size = parts[0], parts[1], int(parts[2])
        body = data[pos:pos + size]
        pos += size + 1
        if kind != "blob" or sha in seen:
            continue
        seen.add(sha)
        text = body.decode("utf-8", errors="ignore")
        if b"\0" in body[:8000]:
            # Binary - a database, an image: the token patterns would only
            # produce noise, but a host name inside a dump is still a leak.
            found = [f"{names[sha]}: internal name -> {describe_term(t)}" for t in terms if t in text.lower()]
        else:
            found = scan_text(names[sha], text, terms)
        for hit in found:
            hits.append(f"[blob {sha[:10]}] {hit}")
    for entry in git("log", ref, "--format=%h%x00%B%x1e").split("\x1e"):
        if not entry.strip():
            continue
        short, _, message = entry.strip().partition("\0")
        for hit in scan_text("commit message", message, terms):
            hits.append(f"[commit {short}] {hit}")
    return hits


if __name__ == "__main__":
    terms = internal_terms()
    args = sys.argv[1:]
    history = "--history" in args
    ref = args[args.index("--ref") + 1] if "--ref" in args else "--all"
    findings = scan_history(terms, ref) if history else scan(terms)
    where = ("the whole history" if ref == "--all" else f"the history of {ref}") if history else "tracked files"
    if findings:
        print(f"Possible secrets or internal names found in {where}:")
        for finding in findings:
            print("  " + finding)
        print("\nIf one of these is a placeholder, widen PLACEHOLDER in this file "
              "rather than deleting the check. Internal terms come from "
              f"{INTERNAL_TERMS_FILE} and ${INTERNAL_TERMS_ENV}.")
        sys.exit(1)
    note = f"{len(terms)} internal terms" if terms else "no internal-term list"
    print(f"No secrets found in {where} ({note}).")
