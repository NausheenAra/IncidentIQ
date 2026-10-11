"""Stage 6: static contract tests for the dashboard.

The API sends a strict Content-Security-Policy (no inline script, no inline style,
no external hosts). These tests make sure the pages obey it and that every element
the JavaScript looks up really exists, without needing a browser.
"""

from __future__ import annotations

import re
from html.parser import HTMLParser
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from backend import api, db

DASHBOARD = Path(__file__).resolve().parent.parent / "dashboard"
PAGES = {"index.html": "index", "incident.html": "incident"}


class _Collector(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.ids: set[str] = set()
        self.inline_scripts = 0
        self.style_attrs = 0
        self.style_tags = 0
        self.event_attrs: list[str] = []
        self.external: list[str] = []
        self.script_srcs: list[str] = []
        self.css_hrefs: list[str] = []
        self.body_page = None
        self._in_script = False

    def handle_starttag(self, tag, attrs):
        attr = dict(attrs)
        if "id" in attr:
            self.ids.add(attr["id"])
        if "style" in attr:
            self.style_attrs += 1
        for name in attr:
            if name.startswith("on"):
                self.event_attrs.append(name)
        if tag == "style":
            self.style_tags += 1
        if tag == "script":
            if attr.get("src"):
                self.script_srcs.append(attr["src"])
            else:
                self.inline_scripts += 1
        if tag == "link" and attr.get("rel") == "stylesheet":
            self.css_hrefs.append(attr.get("href", ""))
        for key in ("src", "href"):
            value = attr.get(key, "")
            if re.match(r"^(https?:)?//", value):
                self.external.append(value)
        if tag == "body":
            self.body_page = attr.get("data-page")


def _parse(name: str) -> _Collector:
    parser = _Collector()
    parser.feed((DASHBOARD / name).read_text(encoding="utf-8"))
    return parser


@pytest.mark.parametrize("name", sorted(PAGES))
def test_pages_obey_the_csp(name):
    page = _parse(name)
    assert page.inline_scripts == 0, "inline <script> is blocked by the CSP"
    assert page.style_attrs == 0, "style= attributes are blocked by the CSP"
    assert page.style_tags == 0, "<style> blocks are blocked by the CSP"
    assert page.event_attrs == [], "inline event handlers are blocked by the CSP"
    assert page.external == [], "external hosts are blocked by the CSP"
    assert page.script_srcs == ["/static/app.js"]
    assert page.css_hrefs == ["/static/style.css"]
    assert page.body_page == PAGES[name]


def test_stylesheet_has_no_external_resources():
    css = (DASHBOARD / "style.css").read_text(encoding="utf-8")
    assert "@import" not in css
    assert not re.search(r"url\(\s*['\"]?(https?:)?//", css)


def test_script_never_uses_dangerous_dom_apis():
    js = (DASHBOARD / "app.js").read_text(encoding="utf-8")
    for forbidden in ("innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "eval(", "new Function"):
        assert forbidden not in js, f"{forbidden} would make untrusted log text dangerous"
    assert not re.search(r"setAttribute\(\s*['\"]style", js)
    assert "localStorage" not in js, "the API key must stay in the tab (sessionStorage) only"


def test_every_id_the_script_reads_exists_in_the_page():
    js = (DASHBOARD / "app.js").read_text(encoding="utf-8")
    wanted_by_page = {
        "index.html": {"status-strip", "error-banner", "metric-total", "metric-resolved", "metric-mttd", "metric-mttr",
                       "incident-state", "incident-table-wrap", "incident-rows"},
        "incident.html": {"status-strip", "error-banner", "detail-state", "detail", "detail-title", "detail-status", "summary",
                          "approval-panel", "approval-text", "approval-msg", "api-key-input", "approve-btn",
                          "diagnosis-state", "diagnosis", "rca-source", "rca-action", "rca-confidence",
                          "rca-confidence-text", "rca-cause", "rca-evidence", "timeline", "evidence-state", "evidence",
                          "ev-pods", "ev-logs", "ev-events", "ev-rollout", "ev-pods-count", "ev-logs-count",
                          "ev-events-count", "ev-rollout-count"},
    }
    for name, wanted in wanted_by_page.items():
        missing = wanted - _parse(name).ids
        assert not missing, f"{name} is missing ids used by app.js: {sorted(missing)}"
        for element_id in wanted:
            assert f'"{element_id}"' in js, f"app.js never references {element_id}"


def test_refresh_interval_is_three_seconds():
    js = (DASHBOARD / "app.js").read_text(encoding="utf-8")
    assert re.search(r"POLL_MS\s*=\s*3000\b", js)


@pytest.fixture()
def client(temp_db):
    application = api.create_app(start_detector=False, configure_logging=False)
    with TestClient(application) as test_client:
        yield test_client


def test_pages_are_served_with_security_headers(client):
    incident_id = db.create_incident("shop-api", "default", "CrashLoopBackOff")
    for path in ("/", f"/incidents/{incident_id}"):
        response = client.get(path)
        assert response.status_code == 200
        assert response.headers["content-type"].startswith("text/html")
        csp = response.headers["content-security-policy"]
        assert "script-src 'self'" in csp and "style-src 'self'" in csp
        assert response.headers["x-content-type-options"] == "nosniff"
        assert response.headers["x-frame-options"] == "DENY"


def test_static_assets_are_served(client):
    js = client.get("/static/app.js")
    css = client.get("/static/style.css")
    assert js.status_code == 200 and "javascript" in js.headers["content-type"]
    assert css.status_code == 200 and "text/css" in css.headers["content-type"]
    assert client.get("/static/does-not-exist.js").status_code == 404
