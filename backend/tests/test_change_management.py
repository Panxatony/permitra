"""Tests for the optional change management webhook (e.g. ServiceNow)."""
import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

from app import change_management


def test_disabled_without_url(monkeypatch):
    monkeypatch.delenv("CHANGE_WEBHOOK_URL", raising=False)
    assert not change_management.enabled()
    change_management.notify("rule.approved", {"rule_id": "SR0001"})  # must do nothing


def test_notify_posts_json(monkeypatch):
    received = {}
    done = threading.Event()

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            received["path"] = self.path
            received["auth"] = self.headers.get("Authorization")
            received["body"] = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            self.send_response(200)
            self.end_headers()
            done.set()

        def log_message(self, *args):
            pass

    server = HTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        monkeypatch.setenv("CHANGE_WEBHOOK_URL", f"http://127.0.0.1:{server.server_port}/hook")
        monkeypatch.setenv("CHANGE_WEBHOOK_TOKEN", "geheim")
        assert change_management.enabled()
        change_management.notify("rule.approved", {"rule_id": "SR0001", "components": ["FW-A"]})
        assert done.wait(5), "webhook was not called"
    finally:
        server.shutdown()

    assert received["path"] == "/hook"
    assert received["auth"] == "Bearer geheim"
    assert received["body"]["event"] == "rule.approved"
    assert received["body"]["source"] == "permitra"
    assert received["body"]["data"]["rule_id"] == "SR0001"
    assert received["body"]["timestamp"]


def test_failures_never_raise(monkeypatch):
    # Unreachable target: notify must not raise an error (fire-and-forget)
    monkeypatch.setenv("CHANGE_WEBHOOK_URL", "http://127.0.0.1:1/unerreichbar")
    change_management.notify("rule.rejected", {"rule_id": "SR0002"})
