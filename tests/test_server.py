"""HTTP API: authentication guards, security headers, upload -> lock -> preview -> unlock."""

import json
import time

import pytest

from vaultlock.server.app import create_app

PW = "Correct-Horse-Battery-42!"
HOST = "localhost"   # what Flask's test client sends; the guard compares it exactly


@pytest.fixture
def client(tmp_path):
    app = create_app(token="tok", home=tmp_path / "home", expected_host=HOST)
    return app.test_client()


H = {"X-VL-Token": "tok"}


def call(c, method, path, body=None, headers=None, **kw):
    h = {**H, **(headers or {})}
    return getattr(c, method)(path, json=body, headers=h, **kw) if body is not None else getattr(c, method)(path, headers=h, **kw)


def wait(c, jid):
    for _ in range(400):
        s = call(c, "get", f"/api/jobs/{jid}").get_json()
        if s["status"] not in ("queued", "running"):
            return s
        time.sleep(0.02)
    raise AssertionError("job timed out")


def test_auth_host_and_origin_guards(client):
    assert client.get("/api/info").status_code == 401
    assert client.get("/api/info", headers={"X-VL-Token": "bad"}).status_code == 401
    assert call(client, "get", "/api/info").status_code == 200
    assert client.get("/api/info", headers={**H, "Host": "evil.example"}).status_code == 403   # DNS rebinding
    assert client.get("/api/info", headers={**H, "Origin": "http://evil.example"}).status_code == 403  # cross-site


def test_hardening_headers_and_token_injection(client):
    r = client.get("/")
    assert b"__VL_TOKEN__" not in r.data and b'content="tok"' in r.data
    assert "default-src 'self'" in r.headers["Content-Security-Policy"] and "unsafe-eval" not in r.headers["Content-Security-Policy"]
    csp = r.headers["Content-Security-Policy"]
    assert "script-src 'self';" in csp and "http" not in csp          # no third-party code can ever load
    assert r.headers["Cache-Control"] == "no-store" and r.headers["X-Content-Type-Options"] == "nosniff"
    assert "Access-Control-Allow-Origin" not in r.headers


def test_static_traversal_blocked(client):
    for p in ("/static/../server/app.py", "/static/..%2fserver%2fapp.py", "/static/%2e%2e/config.py"):
        assert client.get(p, headers=H).status_code in (400, 404)


def test_upload_lock_preview_unlock_cycle(client, tmp_path):
    payload = b"hello vault " * 4000
    up = client.post("/api/upload", data=payload, headers={**H, "X-File-Name": "note.txt", "Content-Type": "application/octet-stream"}).get_json()
    assert up["size"] == len(payload)
    out = tmp_path / "out"
    j = call(client, "post", "/api/encrypt", {"files": [{"staged": up["staged"]}], "password": PW, "options": {"output_dir": str(out), "verify": True}}).get_json()
    s = wait(client, j["job"])
    assert s["status"] == "done"
    vault = s["items"][0]["output"]
    assert not list((tmp_path / "home" / "staging").iterdir())             # staged plaintext shredded

    pv = call(client, "post", "/api/vault/preview", {"files": [{"path": vault}], "password": PW}).get_json()
    assert pv["category"] == "text"
    body = call(client, "get", f"/api/preview/{pv['id']}")
    assert body.data == payload and "sandbox" in body.headers["Content-Security-Policy"]
    call(client, "delete", f"/api/preview/{pv['id']}")
    assert call(client, "get", f"/api/preview/{pv['id']}").status_code == 404

    bad = call(client, "post", "/api/vault/preview", {"files": [{"path": vault}], "password": "wrong"})
    assert bad.status_code == 403 and bad.get_json()["error"]["code"] == "bad_credentials"

    j = call(client, "post", "/api/decrypt", {"files": [{"path": vault}], "password": PW, "options": {"output_dir": str(tmp_path / "back")}}).get_json()
    s = wait(client, j["job"])
    assert s["status"] == "done" and (tmp_path / "back" / "note.txt").read_bytes() == payload


def test_input_validation(client, tmp_path):
    f = tmp_path / "x.txt"; f.write_text("x")
    assert call(client, "post", "/api/encrypt", {"files": [{"path": str(f)}], "password": "abc"}).get_json()["error"]["code"] == "weak_password"
    assert call(client, "post", "/api/encrypt", {"files": [{"staged": "../../etc"}], "password": PW}).status_code == 400
    assert call(client, "post", "/api/encrypt", {"files": [], "password": PW}).status_code == 400
    assert call(client, "post", "/api/encrypt", {"files": [{"path": str(f)}], "password": PW, "options": {"cipher": "rot13"}}).status_code == 400
    assert call(client, "post", "/api/shred", {"files": [{"path": str(f)}]}).status_code == 400     # needs explicit confirm
    assert f.exists()
    assert call(client, "post", "/api/settings", {"shred_passes": 5}).status_code == 400


def test_clear_scrubs_previews_and_staging(client, tmp_path):
    client.post("/api/upload", data=b"x" * 100, headers={**H, "X-File-Name": "a.txt"})
    assert call(client, "post", "/api/clear").status_code == 200
    assert not list((tmp_path / "home" / "staging").iterdir())


def test_secrets_never_appear_in_responses(client, tmp_path):
    f = tmp_path / "x.txt"; f.write_text("x")
    j = call(client, "post", "/api/encrypt", {"files": [{"path": str(f)}], "password": PW, "options": {"output_dir": str(tmp_path)}})
    s = wait(client, j.get_json()["job"])
    assert PW not in json.dumps(s) and PW not in j.get_data(as_text=True)
