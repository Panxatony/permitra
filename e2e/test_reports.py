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
    # The three finding classes with content on this component, plus coverage.
    assert "%" in body
    assert "quickfix-friday" in body          # unjustified, by name


def test_the_requestor_table_names_the_orphans(open_page):
    page = open_page("/reports", user="betrieb", wait=1.5)

    assert page.permitra_errors == [], page.permitra_errors
    body = page.inner_text("body")
    # The demo's requestors are fictional people without accounts - exactly the
    # finding the table exists for.
    assert "Deniz Yilmaz" in body
