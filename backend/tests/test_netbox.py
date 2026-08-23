"""Tests for the NetBox import (GitLab issue 23)."""
import json
import os
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

# The fake NetBox listens on loopback, which validate_url refuses unless it is
# allowed on purpose. Set here rather than patched away, so the tests go through
# the same check a real installation does.
os.environ.setdefault("PERMITRA_ALLOW_LOCAL_NETBOX", "1")

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app import netbox
from app.database import Base
from app.models import NetboxConfig, NetboxPrefix, Vrf


@pytest.fixture()
def db():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    s = sessionmaker(bind=engine)()
    s.add(Vrf(id=1, name="IT"))
    s.commit()
    yield s
    s.close()


def test_token_encryption_roundtrip():
    enc = netbox.encrypt_token("s3cr3t-token")
    assert enc and enc != "s3cr3t-token"
    assert netbox.decrypt_token(enc) == "s3cr3t-token"


PREFIXES = {
    "count": 2,
    "next": None,
    "results": [
        {"id": 1, "prefix": "10.20.0.0/24", "status": {"value": "active"},
         "vrf": {"name": "IT"}, "description": "Server-Netz"},
        {"id": 2, "prefix": "10.20.1.0/24", "status": {"value": "planned"},
         "vrf": None, "description": ""},
    ],
}


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(PREFIXES).encode())

    def log_message(self, *a):
        pass


@pytest.fixture()
def netbox_server():
    server = HTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{server.server_port}"
    server.shutdown()


def test_import_prefixes(db, netbox_server):
    db.add(NetboxConfig(url=netbox_server, token_enc=netbox.encrypt_token("x"),
                        verify_tls=True, statuses="active,reserved"))
    db.commit()
    result = netbox.import_prefixes(db)
    # Deduplicated by netbox_id, even though it is queried per status
    assert result["pending"] == 2
    cidrs = {p.cidr for p in db.query(NetboxPrefix).all()}
    assert cidrs == {"10.20.0.0/24", "10.20.1.0/24"}
    # Idempotent: a repeated import updates instead of duplicating
    netbox.import_prefixes(db)
    assert db.query(NetboxPrefix).count() == 2


def test_import_requires_config(db):
    with pytest.raises(ValueError):
        netbox.import_prefixes(db)
