import io
import os
import time

import pytest

from conftest import CHEAP, PW
from vaultlock.server.app import create_app

HOST = {"Host": "127.0.0.1:5555"}


@pytest.fixture
def client(tmp_path):
    app = create_app(token="tok", port=5555, home=tmp_path / "home")
    app.extensions["vaultlock"]["allowed_hosts"].add("localhost")   # Flask's test client sends Host: localhost
    c = app.test_client()
    c.t = {"X-VaultLock-Token": "tok"}
    return c


def post(c, path, body=None, **kw):
    return c.post(path, json=body or {}, headers=c.t, **kw)


def test_token_host_and_origin_guards(client):
    assert client.get("/api/info").status_code == 401
    assert client.get("/api/info", headers={"X-VaultLock-Token": "nope"}).status_code == 401
    assert client.get("/api/info", headers=client.t).status_code == 200
    assert client.get("/api/info", headers={**client.t, "Host": "evil.example"}).status_code == 403          # DNS rebinding
    assert client.get("/api/info", headers={**client.t, "Origin": "http://evil.example"}).status_code == 403  # cross-site
    assert client.get("/api/ping").status_code == 200


def test_security_headers_and_token_injection(client):
    r = client.get("/")
    assert b"__SESSION_TOKEN__" not in r.data and b"tok" in r.data
    h = r.headers
    assert "script-src 'self'" in h["Content-Security-Policy"] and "unsafe-inline" not in h["Content-Security-Policy"].split("script-src")[1].split(";")[0]
    assert h["Cache-Control"] == "no-store" and h["X-Content-Type-Options"] == "nosniff" and "Access-Control-Allow-Origin" not in h


def test_static_path_traversal_blocked(client):
    for p in ("/static/../server/app.py", "/static/..%2fserver%2fapp.py", "/static/%2e%2e/config.py"):
        assert client.get(p, headers=client.t).status_code in (400, 404)


def test_strength_and_generate(client):
    assert post(client, "/api/strength", {"password": "password"}).json["strength"]["score"] == 0
    g = post(client, "/api/generate", {"kind": "passphrase", "words": 6}).json
    assert g["strength"]["score"] >= 3 and len(g["value"].split("-")) == 6
    assert post(client, "/api/strength", {"password": 5}).status_code == 400


def test_settings_validation_and_persistence(client):
    assert post(client, "/api/settings", {"accent": "rose"}).json["settings"]["accent"] == "rose"
    assert post(client, "/api/settings", {"shred_passes": 5}).status_code == 400
    assert post(client, "/api/settings", {"bogus": 1}).status_code == 400


def test_upload_lock_unlock_and_staging_cleanup(client, tmp_path, monkeypatch):
    from vaultlock.core import kdf
    monkeypatch.setattr(kdf.PRESETS["standard"].__class__, "validate_secure", lambda self: None)
    out = tmp_path / "out"
    r = client.put("/api/stage", data=os.urandom(50_000), headers={**client.t, "X-Filename": "doc.pdf"}).json
    assert r["ok"] and r["size"] == 50_000
    staged = client.application.extensions["vaultlock"]["staging"]
    job = post(client, "/api/jobs/encrypt", {"sources": [{"staged": r["staged"]}], "password": PW,
                                             "options": {"output_dir": str(out), "profile": "standard", "chunk_kib": 64}}).json["job"]
    for _ in range(300):
        s = client.get(f"/api/jobs/{job['id']}", headers=client.t).json["job"]
        if s["status"] in ("done", "failed"): break
        time.sleep(0.05)
    assert s["status"] == "done", s
    assert staged.resolve(r["staged"]) is None            # plaintext upload shredded after use
    vault = s["items"][0]["output"]
    info = post(client, "/api/vault/inspect", {"path": vault}).json["info"]
    assert info["cipher"] == "AES-256-GCM"
    bad = post(client, "/api/vault/list", {"path": vault, "password": "wrong"})
    assert bad.status_code == 401 and bad.json["error"]["code"] == "bad_credentials"


def test_shred_requires_confirmation(client, tmp_path):
    f = tmp_path / "a"; f.write_text("x")
    assert post(client, "/api/jobs/shred", {"sources": [str(f)]}).json["error"]["code"] == "confirm_required"
    assert f.exists()


def test_bad_requests_get_clean_errors(client):
    assert post(client, "/api/jobs/encrypt", {"sources": []}).status_code == 400
    assert post(client, "/api/jobs/encrypt", {"sources": ["/x"], "password": ""}).status_code == 400
    assert post(client, "/api/jobs/nope/cancel").status_code == 404
    assert client.post("/api/strength", data="not json", headers=client.t).status_code == 400
    assert client.delete("/api/stage/../../etc", headers=client.t).status_code in (404, 405)
