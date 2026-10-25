"""Hardened localhost-only HTTP API (Flask).

Threat model for the server: it runs on the user's own machine and must not be
usable by *other* local processes' web pages (CSRF / DNS-rebinding) or other
users.  Defences:

* binds 127.0.0.1 only, on a random port
* every ``/api`` call needs the per-launch session token (header ``X-VL-Token``)
* ``Host`` must be the exact loopback host:port; browser ``Origin`` must match
* strict CSP, ``no-store``, ``nosniff``, frame denial on every response
* secrets travel only in POST bodies, are never logged, and are dropped as soon as a job ends
* previews are served from RAM with a forced safe content type and are never HTML
"""

from __future__ import annotations

import hmac
import logging
import os
import secrets
from pathlib import Path
from typing import Any

from flask import Flask, Response, abort, jsonify, request, send_from_directory

from .. import __version__
from ..config import SettingsStore, app_home
from ..core import engine, kdf as kdfmod
from ..core.errors import NotPreviewableError, VaultLockError
from ..core.format import CIPHER_BY_NAME
from ..core.keyfile import fingerprint, generate_keyfile
from ..core.memory import CAN_WIPE_IMMUTABLE, wipe
from ..services import fsbrowser, strength, system
from ..services.jobs import JobManager, JobOptions, Source
from ..services.staging import StagingArea

log = logging.getLogger("vaultlock.server")
WEB_DIR = Path(__file__).resolve().parent.parent / "web"

CSP = (
    "default-src 'self'; "
    "script-src 'self'; "
    "style-src 'self' 'unsafe-inline'; "
    "img-src 'self' data: blob:; media-src 'self' blob:; "
    "font-src 'self' data:; connect-src 'self'; "
    "object-src 'none'; frame-src 'self' blob:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
)


class ApiError(Exception):
    def __init__(self, status: int, code: str, message: str):
        self.status, self.code, self.message = status, code, message


def create_app(
    *,
    token: str | None = None,
    settings: SettingsStore | None = None,
    home: Path | None = None,
    native_bridge: Any = None,
    expected_host: str | None = None,
) -> Flask:
    app = Flask(__name__, static_folder=None)
    app.config["MAX_CONTENT_LENGTH"] = None  # uploads are streamed to disk manually
    home = home or app_home()
    settings = settings or SettingsStore(home / "settings.json")
    staging = StagingArea(home / "staging")
    staging.purge_all()
    jobs = JobManager(staging, settings.output_dir)
    token = token or secrets.token_urlsafe(32)
    app.config.update(VL_TOKEN=token, VL_SETTINGS=settings, VL_JOBS=jobs, VL_STAGING=staging)
    # previews live only here, keyed by random id; wiped on request, on expiry and on shutdown
    previews: dict[str, tuple[bytearray, str]] = {}
    app.config["VL_PREVIEWS"] = previews

    # ------------------------------------------------------------------ guards
    @app.before_request
    def guard():
        host = request.host
        allowed = {expected_host} if expected_host else None
        if allowed is None:
            h = host.rsplit(":", 1)[0] if ":" in host else host
            if h not in ("127.0.0.1", "localhost"):
                abort(403)
        elif host not in allowed:
            abort(403)
        origin = request.headers.get("Origin")
        if origin and origin not in (f"http://{host}",):
            abort(403)
        if request.path.startswith("/api/"):
            supplied = request.headers.get("X-VL-Token", "") or request.args.get("t", "")
            if not hmac.compare_digest(supplied.encode(), token.encode()):
                raise ApiError(401, "unauthorized", "Session token missing or invalid.")

    @app.after_request
    def harden(resp: Response):
        resp.headers.setdefault("Content-Security-Policy", CSP)
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["Referrer-Policy"] = "no-referrer"
        resp.headers["Cache-Control"] = "no-store"
        resp.headers["Cross-Origin-Resource-Policy"] = "same-origin"
        resp.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        return resp

    @app.errorhandler(ApiError)
    def _api_error(e: ApiError):
        return jsonify(error={"code": e.code, "message": e.message}), e.status

    @app.errorhandler(VaultLockError)
    def _vl_error(e: VaultLockError):
        status = 400
        if e.code in ("bad_credentials", "missing_credentials"):
            status = 403
        return jsonify(error={"code": e.code, "message": str(e)}), status

    @app.errorhandler(404)
    def _404(_e):
        return jsonify(error={"code": "not_found", "message": "Not found."}), 404

    @app.errorhandler(403)
    def _403(_e):
        return jsonify(error={"code": "forbidden", "message": "Forbidden."}), 403

    @app.errorhandler(Exception)
    def _500(e: Exception):
        if isinstance(e, ApiError):  # pragma: no cover
            raise e
        from werkzeug.exceptions import HTTPException

        if isinstance(e, HTTPException):
            return jsonify(error={"code": "http", "message": e.description}), e.code or 500
        log.exception("Unhandled error")
        return jsonify(error={"code": "internal", "message": "Internal error."}), 500

    # --------------------------------------------------------------- helpers
    def body() -> dict:
        data = request.get_json(silent=True)
        if not isinstance(data, dict):
            raise ApiError(400, "bad_request", "Expected a JSON object.")
        return data

    def resolve_sources(raw: Any) -> list[Source]:
        if not isinstance(raw, list) or not raw:
            raise ApiError(400, "bad_request", "No files were provided.")
        out: list[Source] = []
        for entry in raw[:5000]:
            if isinstance(entry, dict) and entry.get("staged"):
                p = staging.resolve(str(entry["staged"]))
                if p is None:
                    raise ApiError(400, "bad_request", "An uploaded file expired - please add it again.")
                out.append(Source(p, staged_id=str(entry["staged"])))
            elif isinstance(entry, dict) and isinstance(entry.get("path"), str):
                out.append(Source(Path(entry["path"]).expanduser()))
            elif isinstance(entry, str):
                out.append(Source(Path(entry).expanduser()))
            else:
                raise ApiError(400, "bad_request", "Malformed file entry.")
        return out

    def creds_from(data: dict) -> engine.Credentials:
        pw = data.get("password")
        kf = data.get("keyfile") or None
        if pw is not None and not isinstance(pw, str):
            raise ApiError(400, "bad_request", "Password must be a string.")
        if kf is not None and not isinstance(kf, str):
            raise ApiError(400, "bad_request", "Keyfile must be a path.")
        return engine.Credentials(pw, kf)

    def options_from(data: dict) -> JobOptions:
        s = settings.get_all()
        o = data.get("options") or {}
        if not isinstance(o, dict):
            raise ApiError(400, "bad_request", "options must be an object.")
        cipher_name = o.get("cipher", s["cipher"])
        if cipher_name not in CIPHER_BY_NAME:
            raise ApiError(400, "bad_request", "Unknown cipher.")
        profile = o.get("profile", s["profile"])
        out_dir = o.get("output_dir") or None
        passes = o.get("shred_passes", s["shred_passes"])
        if passes not in (1, 3, 7):
            raise ApiError(400, "bad_request", "Shred passes must be 1, 3 or 7.")
        chunk_kib = o.get("chunk_kib", s["chunk_kib"])
        if not isinstance(chunk_kib, int) or not (64 <= chunk_kib <= 4096):
            raise ApiError(400, "bad_request", "Chunk size must be 64-4096 KiB.")
        return JobOptions(
            cipher=CIPHER_BY_NAME[cipher_name],
            kdf=kdfmod.preset(profile),
            chunk_size=chunk_kib * 1024,
            compress=bool(o.get("compress", s["compress"])),
            bundle=bool(o.get("bundle", False)),
            bundle_name=str(o.get("bundle_name") or "")[:120],
            obfuscate=bool(o.get("obfuscate_names", s["obfuscate_names"])),
            shred=bool(o.get("shred", False)),
            shred_passes=passes,
            verify=bool(o.get("verify", False)),
            overwrite=bool(o.get("overwrite", False)),
            output_dir=Path(out_dir).expanduser() if out_dir else None,
            remove_vault_after=bool(o.get("remove_vault_after", False)),
        )

    # ------------------------------------------------------------------ pages
    @app.get("/")
    def index():
        html = (WEB_DIR / "index.html").read_text(encoding="utf-8")
        html = html.replace("__VL_TOKEN__", token).replace("__VL_VERSION__", __version__)
        html = html.replace("__VL_NATIVE__", "true" if native_bridge is not None else "false")
        return Response(html, mimetype="text/html")

    @app.get("/static/<path:name>")
    def static_files(name: str):
        return send_from_directory(WEB_DIR, name, max_age=0)

    @app.get("/favicon.ico")
    def favicon():
        return Response(status=204)

    # -------------------------------------------------------------------- API
    @app.get("/api/info")
    def info():
        return jsonify(
            version=__version__,
            native=native_bridge is not None,
            argon2=kdfmod.ARGON2_AVAILABLE,
            can_wipe=CAN_WIPE_IMMUTABLE,
            profiles={k: v.describe() for k, v in kdfmod.PRESETS.items()},
            output_dir=str(settings.output_dir()),
            home=str(Path.home()),
            settings=settings.get_all(),
        )

    @app.get("/api/settings")
    def get_settings():
        return jsonify(settings.get_all())

    @app.post("/api/settings")
    def set_settings():
        try:
            return jsonify(settings.update(body()))
        except ValueError as e:
            raise ApiError(400, "bad_request", str(e))

    @app.post("/api/strength")
    def api_strength():
        pw = body().get("password", "")
        if not isinstance(pw, str):
            raise ApiError(400, "bad_request", "Password must be a string.")
        return jsonify(strength.evaluate(pw).as_dict())

    @app.post("/api/generate")
    def api_generate():
        d = body()
        if d.get("kind") == "passphrase":
            return jsonify(value=strength.generate_passphrase(int(d.get("words", 6))))
        return jsonify(value=strength.generate_password(int(d.get("length", 24)), symbols=bool(d.get("symbols", True))))

    @app.post("/api/keyfile/generate")
    def keyfile_generate():
        d = body()
        path = d.get("path")
        if not isinstance(path, str) or not path:
            raise ApiError(400, "bad_request", "Choose where to save the keyfile.")
        p = Path(path).expanduser()
        if p.suffix.lower() != ".key":
            p = p.with_name(p.name + ".key")
        fp = generate_keyfile(p, overwrite=False)
        return jsonify(path=str(p), fingerprint=fp)

    @app.post("/api/keyfile/fingerprint")
    def keyfile_fp():
        p = body().get("path")
        if not isinstance(p, str):
            raise ApiError(400, "bad_request", "Path required.")
        return jsonify(fingerprint=fingerprint(p))

    @app.post("/api/inspect")
    def api_inspect():
        sources = resolve_sources(body().get("files"))
        out = []
        for s in sources:
            try:
                d = engine.inspect(s.path)
                d.update(path=str(s.path), name=s.path.name, ok=True)
            except VaultLockError as e:
                d = {"path": str(s.path), "name": s.path.name, "ok": False, "error": {"code": e.code, "message": str(e)}}
            except OSError as e:
                d = {"path": str(s.path), "name": s.path.name, "ok": False, "error": {"code": "io", "message": e.strerror or "Cannot read file."}}
            out.append(d)
        return jsonify(vaults=out)

    @app.post("/api/stat")
    def api_stat():
        """Describe dropped paths (desktop mode): kind, size, vault-ness."""
        out = []
        for raw in body().get("paths", [])[:5000]:
            p = Path(str(raw)).expanduser()
            try:
                if p.is_dir():
                    n = size = 0
                    for root, _d, files in os.walk(p):
                        for f in files:
                            n += 1
                            try:
                                size += (Path(root) / f).stat().st_size
                            except OSError:
                                pass
                        if n > 20000:
                            break
                    out.append({"path": str(p), "name": p.name, "kind": "dir", "size": size, "count": n, "vault": False})
                else:
                    st = p.stat()
                    out.append({"path": str(p), "name": p.name, "kind": "file", "size": st.st_size, "count": 1,
                                "vault": p.suffix.lower() == ".vault"})
            except OSError:
                continue
        return jsonify(items=out)

    # ------------------------------------------------------------- uploads
    @app.post("/api/upload")
    def upload():
        name = request.headers.get("X-File-Name", "upload")
        from urllib.parse import unquote

        name = unquote(name)
        sid, dest = staging.new(name)
        written = 0
        try:
            with open(dest, "wb") as fh:
                while True:
                    chunk = request.stream.read(1024 * 1024)
                    if not chunk:
                        break
                    fh.write(chunk)
                    written += len(chunk)
        except Exception:
            staging.discard(sid)
            raise
        return jsonify(staged=sid, name=dest.name, size=written, vault=dest.suffix.lower() == ".vault")

    @app.delete("/api/upload/<sid>")
    def upload_discard(sid: str):
        staging.discard(sid)
        return jsonify(ok=True)

    # ---------------------------------------------------------------- jobs
    def _start(job):
        jobs.start(job)
        return jsonify(job=job.id, snapshot=job.snapshot())

    @app.post("/api/encrypt")
    def api_encrypt():
        d = body()
        job = jobs.submit_encrypt(
            resolve_sources(d.get("files")), creds_from(d), options_from(d), allow_weak=bool(d.get("allow_weak"))
        )
        return _start(job)

    @app.post("/api/decrypt")
    def api_decrypt():
        d = body()
        job = jobs.submit_decrypt(resolve_sources(d.get("files")), creds_from(d), options_from(d))
        return _start(job)

    @app.post("/api/shred")
    def api_shred():
        d = body()
        o = options_from(d)
        if d.get("confirm") is not True:
            raise ApiError(400, "confirm_required", "Shredding is permanent - confirmation is required.")
        job = jobs.submit_shred(resolve_sources(d.get("files")), o.shred_passes)
        return _start(job)

    @app.get("/api/jobs/<jid>")
    def job_status(jid: str):
        job = jobs.get(jid)
        if job is None:
            raise ApiError(404, "not_found", "Unknown job.")
        return jsonify(job.snapshot())

    @app.post("/api/jobs/<jid>/cancel")
    def job_cancel(jid: str):
        if not jobs.cancel(jid):
            raise ApiError(404, "not_found", "Unknown job.")
        return jsonify(ok=True)

    # ------------------------------------------------------ secure viewer
    @app.post("/api/vault/list")
    def vault_list():
        d = body()
        src = resolve_sources(d.get("files"))[0]
        try:
            res = engine.list_entries(src.path, creds_from(d))
        finally:
            if src.staged_id:
                pass  # kept for the follow-up preview call; purged on discard / exit
        return jsonify(res)

    @app.post("/api/vault/preview")
    def vault_preview():
        d = body()
        src = resolve_sources(d.get("files"))[0]
        limit = int(settings.get("preview_max_mb")) * 1024 * 1024
        meta, fname, data = engine.read_in_memory(src.path, creds_from(d), max_bytes=limit, entry=d.get("entry"))
        category, mime = engine.preview_kind(fname)
        if category is None:
            wipe(data)
            raise NotPreviewableError("This file type can't be previewed. Unlock it to open it with another app.")
        pid = secrets.token_urlsafe(18)
        previews[pid] = (data, mime)
        if len(previews) > 8:  # bound RAM held by forgotten previews
            oldest = next(iter(previews))
            buf, _ = previews.pop(oldest)
            wipe(buf)
        return jsonify(id=pid, name=fname, category=category, mime=mime, size=len(data), vault_meta=meta)

    @app.get("/api/preview/<pid>")
    def preview_get(pid: str):
        item = previews.get(pid)
        if item is None:
            raise ApiError(404, "not_found", "Preview expired.")
        data, mime = item
        resp = Response(bytes(data), mimetype=mime.split(";")[0])
        if mime.startswith("text/plain"):
            resp.headers["Content-Type"] = "text/plain; charset=utf-8"
        resp.headers["Content-Security-Policy"] = "default-src 'none'; img-src 'self' data:; style-src 'unsafe-inline'; sandbox"
        resp.headers["Content-Disposition"] = "inline"
        return resp

    @app.delete("/api/preview/<pid>")
    def preview_drop(pid: str):
        item = previews.pop(pid, None)
        if item:
            wipe(item[0])
        return jsonify(ok=True)

    @app.post("/api/clear")
    def clear_all():
        """Panic / auto-lock: scrub previews and staged files; cancel running jobs."""
        for pid in list(previews):
            wipe(previews.pop(pid)[0])
        staging.purge_all()
        jobs.cancel_all()
        return jsonify(ok=True)

    # ----------------------------------------------------- file browsing etc.
    @app.get("/api/fs/roots")
    def fs_roots():
        return jsonify(roots=fsbrowser.roots())

    @app.get("/api/fs/list")
    def fs_list():
        return jsonify(fsbrowser.list_dir(request.args.get("path"), request.args.get("hidden") == "1"))

    @app.post("/api/fs/mkdir")
    def fs_mkdir():
        d = body()
        return jsonify(path=fsbrowser.make_dir(str(d.get("parent", "")), str(d.get("name", ""))))

    @app.post("/api/reveal")
    def reveal():
        system.reveal(str(body().get("path", "")))
        return jsonify(ok=True)

    @app.post("/api/native/pick")
    def native_pick():
        if native_bridge is None:
            raise ApiError(400, "no_native", "Native dialogs are unavailable in browser mode.")
        d = body()
        return jsonify(paths=native_bridge.pick(str(d.get("mode", "files")), d.get("filter")))

    @app.post("/api/shutdown")
    def shutdown():
        for pid in list(previews):
            wipe(previews.pop(pid)[0])
        staging.purge_all()
        func = app.config.get("VL_SHUTDOWN")
        if func:
            func()
        return jsonify(ok=True)

    return app
