"""A message must never be the reason a request fails.

_() is called on error paths. A template whose fields do not fit the values it
is given has to come back as text, not raise - otherwise the attempt to report
one error produces another one, and the client gets a 500 instead of the
explanation.
"""
import os

os.environ.setdefault("PERMITRA_DEV", "1")

import pytest

from app.messages import _


@pytest.mark.parametrize("template, values", [
    ("{missing} entries", {"count": 3}),          # KeyError
    ("{0} entries", {"count": 3}),                # IndexError
    ("{count:d} entries", {"count": "three"}),    # ValueError: spec does not fit
    ("{count.real.x} entries", {"count": 3}),     # AttributeError
])
def test_a_template_that_does_not_fit_its_values_still_returns_text(template, values):
    assert isinstance(_(template, **values), str)


def test_a_fitting_template_is_filled_in():
    assert _("{count} entries", count=3) == "3 entries"
