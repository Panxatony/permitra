"""scripts/secret_scan.py is what stands between a host name or a token and
the public repository. The test builds a throw-away git repository, plants
one finding of each kind and checks the scanner refuses it, keeps quiet when
the planted text is a placeholder or the term list is empty, and hides the
matched internal term under CI, where job logs are public.
"""
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "secret_scan.py"
GIT = shutil.which("git") or "git"


def _git(repo: Path, *args: str) -> None:
    # Fixed arguments from this file, nothing from outside: S603 does not apply.
    subprocess.run([GIT, *args], cwd=repo, check=True, capture_output=True)  # noqa: S603


@pytest.fixture
def repo(tmp_path):
    """A git repository with a copy of the scanner and one neutral file."""
    _git(tmp_path, "init", "-q")
    _git(tmp_path, "config", "user.email", "t@example.org")
    _git(tmp_path, "config", "user.name", "t")
    (tmp_path / "scripts").mkdir()
    shutil.copy(SCRIPT, tmp_path / "scripts" / "secret_scan.py")
    (tmp_path / "notes.md").write_text("Deploy with docker compose up -d.\n")
    _git(tmp_path, "add", "-A")
    _git(tmp_path, "commit", "-q", "-m", "init")
    return tmp_path


def run(repo: Path, *args: str, env: dict | None = None) -> subprocess.CompletedProcess:
    full = {k: v for k, v in os.environ.items() if k not in ("CI", "SECRET_SCAN_INTERNAL_TERMS")}
    full.update(env or {})
    return subprocess.run([sys.executable, "scripts/secret_scan.py", *args], cwd=repo,  # noqa: S603
                          capture_output=True, text=True, env=full)


def commit(repo: Path, name: str, text: str, message: str = "change") -> None:
    (repo / name).write_text(text)
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", message)


def test_clean_repository_passes(repo):
    result = run(repo)
    assert result.returncode == 0, result.stdout
    assert "no internal-term list" in result.stdout


def test_a_token_shape_is_refused(repo):
    commit(repo, "config.py", 'TOKEN = "glpat-' + "A" * 24 + '"\n')
    result = run(repo)
    assert result.returncode == 1
    assert "GitLab token" in result.stdout


def test_a_placeholder_is_not_a_secret(repo):
    commit(repo, "docs.md", 'PASSWORD = "change-me-please"\n')
    assert run(repo).returncode == 0


def test_internal_terms_come_from_the_file_and_the_environment(repo):
    commit(repo, "README.md", "Runs on srv-intern01.corp.example and 10.20.30.4.\n")
    assert run(repo).returncode == 0, "no list, no finding"
    (repo / ".secret_scan_internal").write_text("# comment\nsrv-intern01\n")
    result = run(repo)
    assert result.returncode == 1
    assert "README.md: internal name -> srv-intern01" in result.stdout
    (repo / ".secret_scan_internal").unlink()
    result = run(repo, env={"SECRET_SCAN_INTERNAL_TERMS": "nothing-here, 10.20.30."})
    assert result.returncode == 1
    assert "internal name -> 10.20.30." in result.stdout


def test_under_ci_the_matched_term_is_not_printed(repo):
    commit(repo, "README.md", "Runs on srv-intern01.\n")
    result = run(repo, env={"CI": "1", "SECRET_SCAN_INTERNAL_TERMS": "srv-intern01"})
    assert result.returncode == 1
    assert "srv-intern01" not in result.stdout
    assert "internal term #1" in result.stdout


def test_history_finds_what_was_removed_again_and_commit_messages(repo):
    commit(repo, "old.txt", "db host is srv-intern01\n")
    (repo / "old.txt").unlink()
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "remove it; it lived on hosting-box7")
    env = {"SECRET_SCAN_INTERNAL_TERMS": "srv-intern01,hosting-box7"}
    assert run(repo, env=env).returncode == 0, "the tracked tree is clean"
    result = run(repo, "--history", env=env)
    assert result.returncode == 1
    assert "old.txt: internal name -> srv-intern01" in result.stdout
    assert "commit message: internal name -> hosting-box7" in result.stdout


def test_history_can_be_limited_to_one_ref(repo):
    _git(repo, "checkout", "-q", "-b", "mirror")
    commit(repo, "m.txt", "mirror only: srv-intern01\n")
    _git(repo, "checkout", "-q", "-")
    env = {"SECRET_SCAN_INTERNAL_TERMS": "srv-intern01"}
    assert run(repo, "--history", env=env).returncode == 1
    assert run(repo, "--history", "--ref", "HEAD", env=env).returncode == 0
