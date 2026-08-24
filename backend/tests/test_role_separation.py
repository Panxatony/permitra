"""The admin is an administrator, not a superuser.

require_roles used to carry an implicit bypass - `user.role != Role.admin` let
admins through every check in the application. The navigation hid the pages,
and a user testing the first run noticed what that hiding was worth: an admin
following a direct link could open the zones page, and the backend would have
let them create zones, write rules, even approve them. The role table promises
the admin manages Permitra, not rules; the four-eyes principle is worth little
when a fifth role slips past it.

These tests pin the repair from both sides: the admin is rejected wherever not
named, and still passes wherever named - because the fix that locks the admin
out of user management too would be reverted within the hour, and rightly so.
"""
import os

os.environ.setdefault("PERMITRA_DEV", "1")

import pytest
from fastapi import HTTPException

from app.auth import require_roles
from app.models import Role, User


def user_with(role: Role) -> User:
    return User(username=f"test-{role.value}", password_hash="x",
                role=role, is_active=True)


def check(dependency, role: Role):
    """Runs the extracted dependency the way FastAPI would."""
    return dependency(user_with(role))


def test_the_admin_is_rejected_where_not_named():
    """The core of the repair. Every architect-only, operations-only and
    approver-only endpoint in the application goes through this function."""
    for roles in ((Role.architect,),
                  (Role.operations,),
                  (Role.change_approver,),
                  (Role.architect, Role.operations)):
        dependency = require_roles(*roles)
        with pytest.raises(HTTPException) as exc:
            check(dependency, Role.admin)
        assert exc.value.status_code == 403


def test_the_admin_passes_where_named():
    """The other half, without which the fix gets reverted within the hour:
    user management, settings and campaign management name the admin, and
    naming has to keep working."""
    assert check(require_roles(Role.admin), Role.admin).role == Role.admin
    assert check(require_roles(Role.admin, Role.change_approver),
                 Role.admin).role == Role.admin


def test_no_role_slips_past_a_check_for_another():
    """The same property for everyone - the bypass was special-cased to admin,
    but the invariant worth having is that require_roles means what it says."""
    for holder in Role:
        for required in Role:
            dependency = require_roles(required)
            if holder == required:
                assert check(dependency, holder).role == holder
            else:
                with pytest.raises(HTTPException):
                    check(dependency, holder)


def test_four_eyes_cannot_borrow_the_admin():
    """Matrix requests need two different change approvers. With the bypass, an
    admin counted as an approver, and "two different approvers" could quietly
    mean one approver plus whoever runs the instance."""
    with pytest.raises(HTTPException) as exc:
        check(require_roles(Role.change_approver), Role.admin)
    assert exc.value.status_code == 403
