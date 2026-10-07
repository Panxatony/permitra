# CLAUDE.md

Guidance for Claude Code in this repository. Personal, machine- and
infrastructure-specific notes live in `CLAUDE.local.md` (gitignored).

## What this is

**Permitra** documents, reviews and exports firewall rules (Juniper SRX, Check
Point, Cisco ACI, host firewalls, Aerleon targets) and replaces Excel
communication matrices. Core ideas: a review workflow with four-eyes approval,
a BSI P-A-P zone matrix, drift comparison against device configuration, and a
hash-chained audit log. See `docs/CONCEPTS.md`.

- Backend: FastAPI, SQLAlchemy 2.0, Pydantic v2, Alembic — `backend/`
- Frontend: React 19 + Vite — `frontend/`
- Deployment: Docker Compose (`docker-compose.yml`), Kubernetes (`k8s/`)
- Docs: `docs/` (API, CONCEPTS, DEPLOYMENT, EXPORTS, ADMINISTRATION, AUDIT)

## Conventions

- **Repository language is English**: code, comments, docs, commit messages,
  and everything on GitHub (issues, pull requests, reviews). Conversation with
  the maintainer is German.
- **The private GitLab mirror is German**: issues, merge-request titles and
  descriptions, and comments there are written in German. Commit messages stay
  English, because the same commits end up on GitHub.
- Comments explain *why*, in full sentences; match the density of the
  surrounding code. Tests carry a docstring that states the reason they exist.
- Every new test for a fix should **fail without the fix** — check it by
  reverting the fix once (stash the source file, run the test, restore).
- Backend messages go through `_()` in `backend/app/messages.py`; every message
  needs a German entry in the catalogue (`tests/test_all_messages_translated.py`
  enforces it). Frontend strings: `frontend/src/i18n.jsx`, keys are single
  string literals.
- `CHANGELOG.md`: an entry under *Unreleased* for every user- or
  operator-visible change; call out anything an operator must act on.
- Never commit secrets. `.env` is gitignored and mode 600. Run
  `python3 scripts/secret_scan.py` before pushing.

## Commands

```sh
# Backend tests (CI uses Python 3.14, matching backend/Dockerfile)
cd backend && PERMITRA_DEV=1 python -m pytest tests/ -q
cd backend && ruff check .

# Frontend
cd frontend && npm ci && npm run build

# End-to-end (needs a running instance with demo data) - see e2e/README.md
pytest e2e/

# Local stack
docker compose up -d --build
docker compose exec -T backend python seed_demo.py --wipe
```

### Dependencies

`backend/requirements.in` / `requirements-dev.in` are edited by hand;
`requirements.txt` / `requirements-dev.txt` are **generated, pinned, with
hashes**. After editing an `.in` file:

```sh
./scripts/lock_requirements.sh            # keep existing pins
./scripts/lock_requirements.sh --upgrade  # pull newer versions
```

It resolves inside the backend image (Python 3.14). Commit both halves — the
CI job `requirements lock` refuses a lock that drifted from its `.in` file.

## Workflow

- `main` on GitHub (`Panxatony/permitra`, remote `github`) is the public source
  of truth. Changes go through a pull request with green CI, squash-merged.
- Changes are prepared on the private GitLab mirror first (merge request with
  GitLab CI), then brought to GitHub as one PR on a branch based on
  `github/main`, cherry-picking the commits so the GitLab merge commits stay
  out. Check that the resulting tree equals GitLab `main`.
- Security issues are handled privately (see `SECURITY.md`) — never as public
  issues or with exploit details in public PRs.
- Dependency audits are non-blocking in PRs/MRs and blocking on `main`.
