"""Where this instance's Impressum and Datenschutzerklärung live.

Permitra is installed by other people, and § 5 DDG names the operator of an
instance - not us. So the product must not link to permitra.de's Impressum:
that would print our name and address under somebody else's service, which is
worse than having no link at all. Nor can the links simply be left out, because
a publicly reachable instance needs them, and our own demo is one.

So they are configuration. Unset in a fresh installation, and the footer stays
quiet - an instance inside a company network has no imprint obligation and
should not be nagged about one. Set on an instance that is reachable from the
internet, and every page carries them, the sign-in page above all: somebody who
cannot get past it is exactly the visitor the requirement exists for.

Only absolute http(s) URLs are accepted. The value is rendered into an `href`
on every page of the application, so `javascript:...` there would be a stored
cross-site scripting hole handed over by a typo, and a bare path would resolve
against whichever page the visitor happens to be on. A value that does not pass
is dropped rather than shown, and says so in the log - a broken imprint link
looks like compliance from a distance and is not.
"""
import logging
import os
from urllib.parse import urlparse

log = logging.getLogger(__name__)

# The variable name per link, in the order the footer renders them.
VARIABLES = (("imprint_url", "PERMITRA_IMPRINT_URL"),
             ("privacy_url", "PERMITRA_PRIVACY_URL"))


def _accepted(variable: str) -> str:
    """The configured URL, or "" when it is unset or unusable."""
    raw = (os.environ.get(variable) or "").strip()
    if not raw:
        return ""
    parsed = urlparse(raw)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        log.warning("%s is not an absolute http(s) URL (%r) - the link is not shown",
                    variable, raw)
        return ""
    return raw


def links() -> dict[str, str]:
    """The two links for the footer. Empty strings mean: render nothing."""
    return {key: _accepted(variable) for key, variable in VARIABLES}
