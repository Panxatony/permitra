# End-to-end checks

These answer the question the unit tests and the build cannot: **does the
interface actually run?**

A component that calls `t()` without `useLang()` in scope is valid JavaScript
and builds cleanly — it fails the moment it mounts. A React major bump bundles
fine and then behaves differently. Both happened here, and both were caught by
starting the application and looking at it, not by any check in the pipeline.
That gap is what this closes.

## Running them

They need a Permitra instance with the demo dataset:

```sh
# from the repository root
PERMITRA_DEMO=1 FRONTEND_PORT=8090 docker compose up -d --build
docker compose exec -T backend python seed_demo.py --wipe

pip install -r e2e/requirements.txt
playwright install --with-deps chromium      # or set PERMITRA_E2E_CHROME
pytest e2e/
```

| Variable | Meaning |
|---|---|
| `PERMITRA_E2E_URL` | the instance to check (default `http://localhost:8090`) |
| `PERMITRA_E2E_CHROME` | path to a system Chromium, instead of Playwright's own |
| `PERMITRA_E2E_ALLOW_REMOTE=1` | permit a non-local target — see below |

## These tests change data

They create a rule and delete it, flip the instance language, and change
implementation statuses. Against the public demo or a real installation that is
vandalism, and the mistake is one environment variable away — the URL is the
only thing that differs between a throwaway stack and a live one.

So `conftest.py` refuses any target that is not localhost unless
`PERMITRA_E2E_ALLOW_REMOTE=1` says otherwise. Set it only for a stack you are
willing to lose.

Everything they change, they change back. The language is restored by a fixture
and implementation statuses are put back in a `finally`. The rule they create is
deliberately *not* cleaned up: rules are never deleted in Permitra, and the test
proves exactly that by leaving it visible as `deleted`.

## What they cover

| File | Question |
|---|---|
| `test_every_page_renders.py` | does every route come up, in both languages, as the role that uses it — with a quiet console? Plus: does the language setting actually take effect, is the zone plan free of leftover German, and are the zone bands coloured rather than fallen back to black? |
| `test_risk_criteria.py` | can an approver look up the criteria a hint was raised by, and is the edit form reserved for admins? |
| `test_rule_lifecycle.py` | does a rule confirmed on every component become `active`, and does a deleted rule stay visible while ceasing to take effect? |

The page assertions are deliberately weak on wording and strict on errors. What
matters is that the page came up and nothing threw; anything more specific
breaks on the next copy change and gets deleted within a month.
