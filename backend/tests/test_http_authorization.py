"""HTTP-Ebene: Durchsetzung der Rollenrechte über die echte FastAPI-App.

Die übrigen Tests rufen Router-Funktionen direkt auf und übergeben das
User-Objekt als Parameter – dabei wird die Dependency `require_roles` NIE
ausgeführt. Fiele sie an einem Endpunkt weg, blieben jene Tests grün.
Diese Tests gehen deshalb durch die echte HTTP-Schicht inklusive aller
Dependencies und sichern damit die Rechteprüfung selbst ab.
"""
import os

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

os.environ.setdefault("PERMITRA_DEV", "1")

from app.auth import hash_password  # noqa: E402
from app.database import Base, get_db  # noqa: E402
from app.main import app  # noqa: E402
from app.models import Role, User, Vrf  # noqa: E402


@pytest.fixture()
def client():
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False},
                           poolclass=StaticPool)
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine)

    s = Session()
    s.add(Vrf(id=1, name="IT"))
    for name, role in [("arch", Role.architect), ("ops", Role.operations),
                       ("appr", Role.change_approver), ("adm", Role.admin)]:
        s.add(User(username=name, full_name=name, role=role, is_active=True,
                   password_hash=hash_password(f"{name}-pw-123")))
    s.commit()
    s.close()

    def override_db():
        db = Session()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = override_db
    # Bewusst OHNE `with`: so laufen die Startup-Hooks (Alembic-Migrationen gegen
    # die echte Datei-DB, Seed, Hintergrund-Jobs) nicht mit. Getestet wird allein
    # die HTTP-/Dependency-Schicht gegen die In-Memory-DB oben.
    yield TestClient(app, raise_server_exceptions=False)
    app.dependency_overrides.clear()


def token(client, username):
    r = client.post("/api/auth/login",
                    data={"username": username, "password": f"{username}-pw-123"})
    assert r.status_code == 200, r.text
    return r.json()["access_token"]


def auth(client, username):
    return {"Authorization": f"Bearer {token(client, username)}"}


# ---------- Admin-only Endpunkte -------------------------------------------

ADMIN_ONLY_GET = [
    "/api/users",
    "/api/audit-log",
    "/api/audit-log/verify",
    "/api/audit-log/siem-status",
    "/api/api-tokens",
    "/api/netbox/config",
]


@pytest.mark.parametrize("path", ADMIN_ONLY_GET)
def test_admin_only_endpoints_reject_other_roles(client, path):
    """Nicht-Admins dürfen administrative Endpunkte nicht lesen."""
    for user in ("arch", "ops", "appr"):
        r = client.get(path, headers=auth(client, user))
        assert r.status_code == 403, f"{path} war für {user} erreichbar: {r.status_code}"


@pytest.mark.parametrize("path", ADMIN_ONLY_GET)
def test_admin_only_endpoints_require_authentication(client, path):
    """Ohne Token gibt es keinen Zugriff."""
    r = client.get(path)
    assert r.status_code == 401, f"{path} ohne Token: {r.status_code}"


@pytest.mark.parametrize("path", ADMIN_ONLY_GET)
def test_admin_reaches_admin_endpoints(client, path):
    """Gegenprobe: der Admin kommt durch (sonst prüfen die Tests oben nichts)."""
    r = client.get(path, headers=auth(client, "adm"))
    assert r.status_code == 200, f"{path} für Admin nicht erreichbar: {r.text}"


def test_settings_write_is_admin_only(client):
    """Einstellungen darf nur der Admin ändern – Lesen ist für alle erlaubt."""
    body = {"require_justification": "no"}
    for user in ("arch", "ops", "appr"):
        r = client.put("/api/settings", json=body, headers=auth(client, user))
        assert r.status_code == 403, f"{user} konnte Einstellungen ändern"
    assert client.put("/api/settings", json=body,
                      headers=auth(client, "adm")).status_code == 200


def test_user_creation_is_admin_only(client):
    payload = {"username": "eindringling", "email": "x@example.org", "role": "admin"}
    for user in ("arch", "ops", "appr"):
        r = client.post("/api/users", json=payload, headers=auth(client, user))
        assert r.status_code == 403, f"{user} konnte einen Benutzer anlegen"


def test_rule_deletion_is_admin_only(client):
    """Löschen (Soft-Delete) ist Admins vorbehalten."""
    for user in ("arch", "ops", "appr"):
        r = client.delete("/api/rules/SR00001", headers=auth(client, user))
        assert r.status_code == 403, f"{user} durfte löschen ({r.status_code})"


# ---------- Read-only API-Token ---------------------------------------------

def _create_pat(client) -> str:
    r = client.post("/api/api-tokens", json={"name": "ci-readonly"},
                    headers=auth(client, "adm"))
    assert r.status_code == 201, r.text
    return r.json()["token"]


def test_api_token_allows_reading(client):
    pat = _create_pat(client)
    r = client.get("/api/rules", headers={"Authorization": f"Bearer {pat}"})
    assert r.status_code == 200


@pytest.mark.parametrize("method,path,body", [
    ("post", "/api/rules", {"name": "x"}),
    ("put", "/api/settings", {"require_justification": "no"}),
    ("post", "/api/users", {"username": "y", "role": "admin"}),
    ("delete", "/api/rules/SR00001", None),
])
def test_api_token_cannot_write(client, method, path, body):
    """Read-only Tokens dürfen ausschließlich lesen – jede Schreiboperation 403."""
    pat = _create_pat(client)
    headers = {"Authorization": f"Bearer {pat}"}
    call = getattr(client, method)
    r = call(path, json=body, headers=headers) if body is not None else call(path, headers=headers)
    assert r.status_code == 403, f"{method.upper()} {path} war mit read-only Token möglich"


def test_api_token_cannot_reach_admin_endpoints(client):
    """Der Token-Principal hat operations-Rechte, also keine Admin-GETs."""
    pat = _create_pat(client)
    r = client.get("/api/users", headers={"Authorization": f"Bearer {pat}"})
    assert r.status_code == 403


def test_revoked_token_is_rejected(client):
    pat = _create_pat(client)
    listed = client.get("/api/api-tokens", headers=auth(client, "adm")).json()
    tid = listed[0]["id"]
    assert client.delete(f"/api/api-tokens/{tid}", headers=auth(client, "adm")).status_code == 204
    r = client.get("/api/rules", headers={"Authorization": f"Bearer {pat}"})
    assert r.status_code == 401, "Widerrufener Token wurde weiter akzeptiert"


# ---------- Token-Robustheit ------------------------------------------------

def test_garbage_and_missing_tokens_are_rejected(client):
    for value in ("Bearer nonsense", "Bearer ", "nonsense", ""):
        r = client.get("/api/users", headers={"Authorization": value})
        assert r.status_code == 401, f"Ungültiger Header {value!r} ergab {r.status_code}"


def test_deactivated_user_cannot_use_existing_token(client, ):
    """Ein bereits ausgestelltes Token verliert mit der Deaktivierung seine Wirkung."""
    tok = token(client, "arch")
    headers = {"Authorization": f"Bearer {tok}"}
    assert client.get("/api/rules", headers=headers).status_code == 200
    assert client.put("/api/users/arch", json={"is_active": False},
                      headers=auth(client, "adm")).status_code == 200
    assert client.get("/api/rules", headers=headers).status_code == 401
