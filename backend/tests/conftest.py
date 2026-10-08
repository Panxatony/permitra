"""Shared test setup. Hashing a password costs 600,000 PBKDF2 rounds in
production (app/auth.py); the fixtures here create a handful of users per
test, which at full cost would add minutes to the run and prove nothing
about the code. The count is lowered for the whole run, before the
application is imported anywhere. The tests that care about the cost assert
against the constant, not against a number."""
import os

os.environ.setdefault("PERMITRA_DEV", "1")
os.environ.setdefault("PERMITRA_PBKDF2_ITERATIONS", "1000")
