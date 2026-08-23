"""Every route renders, in both languages, as the role that uses it.

This is the check that a build cannot make. Two defects found this way, neither
of which broke the build:

  - `EpgSection` and `RuleRows` called t() with no useLang() in scope. Valid
    JavaScript, clean build, blank page the moment the component mounts.
  - React 18 → 19 bundled fine. Whether the application still ran was a separate
    question, and only clicking through answered it.

The assertions are deliberately weak on content and strict on errors: what
matters is that the page came up and the console stayed quiet. Anything more
specific would break on every wording change and get deleted within a month.
"""
import pytest

# The route, and a role that is actually allowed to use it. Admins are sent
# straight to /admin from "/", so rule pages are checked as the architect.
ROUTES = [
    ("/", "architekt"),
    ("/rules", "architekt"),
    ("/rules/new", "architekt"),
    ("/zones", "architekt"),
    ("/networks", "architekt"),
    ("/components", "architekt"),
    ("/gateways", "architekt"),
    ("/objects", "architekt"),
    ("/search", "architekt"),
    ("/export", "architekt"),
    ("/recertification", "betrieb"),
    ("/approvals", "approver"),
    ("/account", "architekt"),
    ("/admin", "admin"),
]


@pytest.mark.parametrize("language", ["en", "de"])
@pytest.mark.parametrize(("route", "user"), ROUTES, ids=[r for r, _ in ROUTES])
def test_route_renders(open_page, instance_language, route, user, language):
    instance_language(language)
    page = open_page(route, user)

    body = page.inner_text("body")
    assert len(body.strip()) > 40, f"{route} came up empty"
    assert not page.permitra_errors, f"{route} [{language}]: {page.permitra_errors[:2]}"


def test_the_language_setting_actually_changes_the_interface(open_page, instance_language):
    """Otherwise the parametrisation above would pass while proving nothing."""
    instance_language("en")
    assert "Security zones" in open_page("/zones").inner_text("body")

    instance_language("de")
    assert "Sicherheitszonen" in open_page("/zones").inner_text("body")


def test_the_zone_plan_carries_no_leftover_german_on_an_english_instance(
        open_page, instance_language):
    """It did: the caption and the export helpers were hard-coded, because they
    live in template literals that the translation sweep never looked at."""
    instance_language("en")
    body = open_page("/zones").inner_text("body")

    assert "Zone plan" in body
    for leftover in ("Zonenplan", "generiert von", "Stand "):
        assert leftover not in body, f"still German: {leftover!r}"


def test_the_zone_bands_are_not_black(open_page, instance_language):
    """A value rename once left `band-external` pointing at CSS that still said
    `band-extern`, and SVG falls back to black fill. It looked like a broken
    diagram and nothing anywhere reported an error."""
    instance_language("en")
    page = open_page("/zones")

    fills = page.eval_on_selector_all(
        ".pap-band", "els => els.map(e => getComputedStyle(e).fill)")
    assert fills, "no zone bands rendered at all"
    for fill in fills:
        assert fill not in ("rgb(0, 0, 0)", "black"), \
            f"a band fell back to black - the class does not match the CSS: {fills}"
