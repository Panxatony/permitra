"""The reports page, exercised rather than merely opened.

The page-renders suite loads every route and catches a component that dies on
mount. It cannot catch one that dies on interaction: the drift panel rendered
fine empty and crashed the moment a component with stale rules was selected,
because a status badge lost its import in a refactor. The blank grey page
showed up in a person's browser and in nothing automated - this test is that
person, automated.
"""


def test_selecting_a_component_renders_the_drift_report(open_page):
    page = open_page("/reports", user="betrieb", wait=1.5)

    # The seed uploads a configuration for FW-Cluster-BER including rules that
    # are stale and unjustified - the report with the most moving parts.
    page.select_option("select", label="FW-Cluster-BER")
    page.wait_for_timeout(1500)

    assert page.permitra_errors == [], page.permitra_errors
    body = page.inner_text("body")
    # Coverage plus the unjustified rule the SEED plants - not one a manual
    # upload happened to leave behind, which is what this asserted first and
    # what broke on the next reseed.
    assert "%" in body
    assert "quickfix-payment" in body         # unjustified, by name


def test_the_requestor_table_shows_accounts_not_typed_names(open_page):
    page = open_page("/reports", user="betrieb", wait=1.5)

    assert page.permitra_errors == [], page.permitra_errors
    body = page.inner_text("body")
    # The requestor is the account that created the rule - in the demo, the
    # architect account for every seeded rule.
    assert "architekt" in body
