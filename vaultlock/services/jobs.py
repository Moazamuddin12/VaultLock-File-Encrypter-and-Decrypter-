"""Background job runner: encrypt / decrypt / shred with live progress.

One *job* = one user action ("encrypt these 12 items").  A job is made of
*items* (one per file/folder, or a single item for a bundle) and each item
walks through *phases* (scanning -> encrypting -> verifying -> shredding).
Phases report byte counts; the job turns them into overall percentage, a
smoothed throughput figure and an ETA.

Safety rules enforced here (not just in the UI):

* **Verify-before-shred** - originals are only destroyed after the freshly
  written vault has been re-opened and every chunk authenticated.
* Originals are kept if anything in them was skipped (symlinks, unreadable
  files), if the vault would land inside the folder being shredded, or if the
  source was a browser upload.
* Credentials are dropped as soon as the job finishes.
* Browser-staged plaintext copies are shredded after use, pass or fail.
"""

from __future__ import annotations

import errno
import logging
import threading
import time
import uuid
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Optional

from ..core import engine, kdf as kdfmod
from ..core.errors import (
    CancelledError,
    MissingCredentialError,
    VaultLockError,
    WeakPasswordError,
)
from ..core.format import DEFAULT_CHUNK, Cipher
from ..core.fsutil import unique_path
from ..core.keyfile import digest_keyfile
from ..core.kdf import KdfParams
from . import shredder, strength
from .staging import StagingArea

log = logging.getLogger("vaultlock.jobs")


# ---------------------------------------------------------------------------
# data model
# ---------------------------------------------------------------------------

@dataclass
class Source:
    path: Path
    staged_id: Optional[str] = None


@dataclass
class JobOptions:
    cipher: Cipher = Cipher.AES_256_GCM
    kdf: Optional[KdfParams] = None  # None -> preset("strong")
    chunk_size: int = DEFAULT_CHUNK
    compress: bool = False
    bundle: bool = False
    bundle_name: str = ""
    obfuscate: bool = False
    shred: bool = False
    shred_passes: int = 3
    verify: bool = False
    overwrite: bool = False
    output_dir: Optional[Path] = None
    remove_vault_after: bool = False


@dataclass
class JobItem:
    id: int
    label: str
    sources: list[Source]
    kind: str = "file"
    size: int = 0
    status: str = "pending"  # pending | running | done | failed | cancelled
    phase: str = ""
    units_total: int = 0
    units_done: int = 0
    output: Optional[str] = None
    result_name: Optional[str] = None
    error: Optional[dict] = None
    notes: list[str] = field(default_factory=list)
    shredded: bool = False
    # internals
    plan: object = None
    shred_total: int = 0
    _base: int = 0
    _phase_total: int = 0

    @property
    def percent(self) -> float:
        if self.status == "done":
            return 100.0
        if self.units_total <= 0:
            return 0.0
        return min(99.9, 100.0 * self.units_done / self.units_total)


class SpeedMeter:
    """Sliding-window throughput with light exponential smoothing."""

    def __init__(self, window: float = 3.0):
        self._window = window
        self._samples: deque[tuple[float, int]] = deque()
        self._total = 0
        self._ema = 0.0

    def add(self, delta: int, now: Optional[float] = None) -> None:
        now = time.monotonic() if now is None else now
        self._total += delta
        self._samples.append((now, self._total))
        while len(self._samples) > 2 and now - self._samples[0][0] > self._window:
            self._samples.popleft()

    def speed(self, now: Optional[float] = None) -> float:
        now = time.monotonic() if now is None else now
        if len(self._samples) < 2:
            return 0.0
        (t0, u0), (t1, u1) = self._samples[0], self._samples[-1]
        if now - t1 > 2.0 or t1 - t0 < 0.05:
            self._ema *= 0.5
            return self._ema if self._ema > 1 else 0.0
        inst = (u1 - u0) / (t1 - t0)
        self._ema = inst if self._ema == 0 else 0.6 * self._ema + 0.4 * inst
        return self._ema


class Job:
    def __init__(self, op: str, items: list[JobItem], creds: Optional[engine.Credentials], opts: JobOptions):
        self.id = uuid.uuid4().hex[:12]
        self.op = op
        self.items = items
        self.creds = creds
        self.opts = opts
        self.status = "queued"  # queued | running | done | failed | cancelled
        self.phase = "queued"
        self.created = time.time()
        self.started: Optional[float] = None
        self.finished: Optional[float] = None
        self.warnings: list[str] = []
        self.error: Optional[dict] = None
        self.cancel = threading.Event()
        self.lock = threading.RLock()
        self.meter = SpeedMeter()

    # -- progress plumbing (called from worker threads) --------------------
    def begin_phase(self, item: JobItem, name: str, total: int, estimate: int = 0) -> None:
        with self.lock:
            item._base = item.units_done
            item._phase_total = max(total, 0)
            item.phase = name
            item.units_total += item._phase_total - estimate

    def tick(self, item: JobItem, n: int) -> None:
        with self.lock:
            done = item._base + min(max(n, 0), item._phase_total)
            delta = done - item.units_done
            if delta > 0:
                item.units_done = done
                self.meter.add(delta)

    def end_phase(self, item: JobItem) -> None:
        with self.lock:
            done = item._base + item._phase_total
            delta = done - item.units_done
            if delta > 0:
                self.meter.add(delta)
            item.units_done = done
            item._base = done
            item._phase_total = 0

    # -- reporting ----------------------------------------------------------
    def snapshot(self) -> dict:
        with self.lock:
            done = sum(i.units_done for i in self.items)
            total = sum(i.units_total for i in self.items)
            finished = self.status in ("done", "failed", "cancelled")
            percent = 100.0 if (finished and self.status == "done") else (min(99.9, 100.0 * done / total) if total else 0.0)
            speed = 0.0 if finished else self.meter.speed()
            remaining = max(total - done, 0)
            eta = (remaining / speed) if (speed > 1 and not finished) else None
            end = self.finished or time.time()
            current = next((i for i in self.items if i.status == "running"), None)
            return {
                "id": self.id,
                "op": self.op,
                "status": self.status,
                "phase": self.phase,
                "elapsed": round(end - (self.started or self.created), 2),
                "overall": {
                    "done": done,
                    "total": total,
                    "percent": round(percent, 2),
                    "speed_bps": round(speed),
                    "eta_s": None if eta is None else round(eta, 1),
                },
                "current": None
                if current is None
                else {"id": current.id, "label": current.label, "phase": current.phase, "percent": round(current.percent, 1)},
                "items": [
                    {
                        "id": i.id,
                        "label": i.label,
                        "kind": i.kind,
                        "size": i.size,
                        "status": i.status,
                        "phase": i.phase,
                        "percent": round(i.percent, 1),
                        "output": i.output,
                        "result_name": i.result_name,
                        "error": i.error,
                        "notes": list(i.notes),
                        "shredded": i.shredded,
                    }
                    for i in self.items
                ],
                "summary": {
                    "ok": sum(i.status == "done" for i in self.items),
                    "failed": sum(i.status == "failed" for i in self.items),
                    "cancelled": sum(i.status == "cancelled" for i in self.items),
                },
                "warnings": list(self.warnings),
                "error": self.error,
            }


# ---------------------------------------------------------------------------
# error presentation
# ---------------------------------------------------------------------------

def describe_error(e: BaseException) -> dict:
    if isinstance(e, VaultLockError):
        return {"code": e.code, "message": str(e)}
    if isinstance(e, PermissionError):
        return {"code": "permission", "message": f"Permission denied{f' for {Path(e.filename).name}' if e.filename else ''}."}
    if isinstance(e, FileNotFoundError):
        return {"code": "not_found", "message": f"File not found{f': {Path(e.filename).name}' if e.filename else ''}."}
    if isinstance(e, OSError) and e.errno == errno.ENOSPC:
        return {"code": "disk_full", "message": "Not enough free space on the destination drive."}
    if isinstance(e, MemoryError):
        return {"code": "memory", "message": "Not enough memory. Try a lighter security profile or a smaller chunk size."}
    if isinstance(e, OSError):
        return {"code": "io", "message": f"File system error: {e.strerror or e}."}
    log.exception("Unexpected error in job", exc_info=e)
    return {"code": "internal", "message": f"Unexpected error ({type(e).__name__}). See the log for details."}


def _is_within(child: Path, parent: Path) -> bool:
    try:
        child.resolve().relative_to(parent.resolve())
        return True
    except (ValueError, OSError):
        return False


# ---------------------------------------------------------------------------
# runner
# ---------------------------------------------------------------------------

class JobRunner:
    def __init__(self, staging: Optional[StagingArea], default_output: Callable[[], Path]):
        self.staging = staging
        self.default_output = default_output

    # -- driver ------------------------------------------------------------
    def run(self, job: Job) -> None:
        job.status = "running"
        job.started = time.time()
        try:
            job.phase = "scanning"
            self._scan(job)
            job.phase = "working"
            for item in job.items:
                if job.cancel.is_set():
                    item.status = "cancelled"
                    continue
                self._run_item(job, item)
        except BaseException as e:  # pragma: no cover - defensive
            job.error = describe_error(e)
            for item in job.items:
                if item.status in ("pending", "running"):
                    item.status = "failed"
                    item.error = job.error
        finally:
            for item in job.items:
                for s in item.sources:
                    if s.staged_id and self.staging:
                        self.staging.discard(s.staged_id)
            if job.creds is not None:
                job.creds.password = None
            with job.lock:
                oks = sum(i.status == "done" for i in job.items)
                bad = sum(i.status == "failed" for i in job.items)
                if job.cancel.is_set() and any(i.status == "cancelled" for i in job.items):
                    job.status = "cancelled"
                elif bad and not oks:
                    job.status = "failed"
                else:
                    job.status = "done"
                job.phase = job.status
                job.finished = time.time()

    # -- scanning ------------------------------------------------------------
    def _scan(self, job: Job) -> None:
        o = job.opts
        for item in job.items:
            if job.cancel.is_set():
                return
            try:
                paths = [s.path for s in item.sources]
                if job.op == "encrypt":
                    plan = engine.plan_encrypt(paths, job.cancel)
                    item.plan = plan
                    item.kind, item.size, enc_total = plan[1], plan[3], plan[4]
                    total = enc_total
                    if o.verify or o.shred:
                        total += enc_total  # estimate; corrected to the real vault size when verifying starts
                    if o.shred and not any(s.staged_id for s in item.sources):
                        item.shred_total = shredder.plan(paths, o.shred_passes)
                        total += item.shred_total
                    item.units_total = total
                elif job.op == "decrypt":
                    item.size = paths[0].stat().st_size
                    item.units_total = item.size
                else:  # shred
                    item.shred_total = shredder.plan(paths, o.shred_passes)
                    item.size = item.shred_total // max(o.shred_passes, 1)
                    item.units_total = item.shred_total
            except CancelledError:
                return
            except BaseException as e:
                item.status = "failed"
                item.error = describe_error(e)

    # -- one item ------------------------------------------------------------
    def _run_item(self, job: Job, item: JobItem) -> None:
        if item.status == "failed":
            return
        item.status = "running"
        try:
            if job.op == "encrypt":
                self._encrypt_item(job, item)
            elif job.op == "decrypt":
                self._decrypt_item(job, item)
            else:
                self._shred_item(job, item)
            job.end_phase(item)
            item.status = "done"
            item.phase = "done"
        except CancelledError:
            item.status = "cancelled"
            item.phase = "cancelled"
            item.notes.append("Cancelled before completion; no partial output was kept.")
        except BaseException as e:
            item.status = "failed"
            item.error = describe_error(e)
        finally:
            for s in item.sources:
                if s.staged_id and self.staging:
                    self.staging.discard(s.staged_id)

    def _dest_dir(self, job: Job, item: JobItem) -> Path:
        if job.opts.output_dir:
            return job.opts.output_dir
        first = item.sources[0]
        if first.staged_id:
            return self.default_output()
        return first.path.parent

    def _encrypt_item(self, job: Job, item: JobItem) -> None:
        o = job.opts
        paths = [s.path for s in item.sources]
        plan = item.plan
        enc_total = plan[4]
        dest_dir = self._dest_dir(job, item)
        for p in paths:
            if p.is_dir() and _is_within(dest_dir, p):
                raise VaultLockError("The output folder cannot be inside a folder you are encrypting.")
        name = engine.default_vault_name(paths, o.obfuscate, o.bundle_name or item.label)
        dest = (dest_dir / name) if o.overwrite else unique_path(dest_dir, name)

        job.begin_phase(item, "encrypting", enc_total, estimate=enc_total)
        report = engine.encrypt(
            paths,
            dest,
            job.creds,
            cipher=o.cipher,
            kdf=o.kdf or kdfmod.preset(kdfmod.DEFAULT_PRESET),
            chunk_size=o.chunk_size,
            compress=o.compress,
            bundle_name=o.bundle_name or item.label,
            overwrite=o.overwrite,
            on_bytes=lambda n: job.tick(item, n),
            cancel=job.cancel,
            plan=plan,
        )
        job.end_phase(item)
        item.output = str(report.output)
        item.result_name = report.output.name
        if report.skipped:
            shown = ", ".join(report.skipped[:4]) + ("..." if len(report.skipped) > 4 else "")
            item.notes.append(f"Skipped (not included in the vault): {shown}")

        if o.verify or o.shred:
            self._verify_vault(job, item, report.output, enc_total)

        if o.shred:
            self._maybe_shred_originals(job, item, report, paths)

    def _verify_vault(self, job: Job, item: JobItem, vault: Path, estimate: int) -> None:
        size = vault.stat().st_size
        job.begin_phase(item, "verifying", size, estimate=estimate)
        try:
            engine.verify(vault, job.creds, on_bytes=lambda n: job.tick(item, n), cancel=job.cancel)
        except CancelledError:
            raise
        except VaultLockError as e:
            try:
                vault.unlink()
            except OSError:
                pass
            item.output = None
            raise VaultLockError(f"Verification of the new vault failed ({e}). Your original was NOT touched.") from None
        job.end_phase(item)
        item.notes.append("Vault verified: every block re-authenticated.")

    def _maybe_shred_originals(self, job: Job, item: JobItem, report: engine.EncryptReport, paths: list[Path]) -> None:
        o = job.opts
        if any(s.staged_id for s in item.sources):
            item.notes.append("Original kept: this file was uploaded from a browser, so VaultLock can't know where your original lives. Delete it yourself.")
            return
        if report.skipped:
            item.notes.append("Originals kept: some items could not be included in the vault, so nothing was shredded.")
            return
        if any(p.is_dir() and _is_within(report.output, p) for p in paths):
            item.notes.append("Originals kept: the vault is stored inside the folder that would be shredded.")
            return
        job.begin_phase(item, "shredding", item.shred_total, estimate=item.shred_total)
        acc = 0

        def cb(n: int) -> None:
            nonlocal acc
            acc += n
            job.tick(item, acc)

        rep = shredder.ShredReport()
        for p in paths:
            shredder.shred_path(p, o.shred_passes, on_bytes=cb, cancel=job.cancel, report=rep)
        item.shredded = True
        item.notes.extend(rep.warnings)

    def _decrypt_item(self, job: Job, item: JobItem) -> None:
        o = job.opts
        src = item.sources[0].path
        dest_dir = self._dest_dir(job, item)
        job.begin_phase(item, "decrypting", item.size, estimate=item.size)
        rep = engine.decrypt(
            src,
            dest_dir,
            job.creds,
            overwrite=o.overwrite,
            on_bytes=lambda n: job.tick(item, n),
            cancel=job.cancel,
        )
        job.end_phase(item)
        item.output = str(rep.output)
        item.result_name = rep.output.name
        item.kind = rep.kind
        if o.remove_vault_after and not item.sources[0].staged_id:
            try:
                src.unlink()
                item.notes.append("Vault file removed after successful unlock.")
            except OSError:
                item.notes.append("Could not remove the vault file.")

    def _shred_item(self, job: Job, item: JobItem) -> None:
        o = job.opts
        job.begin_phase(item, "shredding", item.shred_total, estimate=item.shred_total)
        acc = 0

        def cb(n: int) -> None:
            nonlocal acc
            acc += n
            job.tick(item, acc)

        rep = shredder.ShredReport()
        for s in item.sources:
            shredder.shred_path(s.path, o.shred_passes, on_bytes=cb, cancel=job.cancel, report=rep)
        item.shredded = True
        item.notes.extend(rep.warnings)
        item.notes.append(f"{rep.files} file(s) overwritten with {rep.passes} pass(es) and deleted.")


# ---------------------------------------------------------------------------
# manager
# ---------------------------------------------------------------------------

class JobManager:
    def __init__(self, staging: Optional[StagingArea], default_output: Callable[[], Path], keep: int = 25):
        self.runner = JobRunner(staging, default_output)
        self._jobs: dict[str, Job] = {}
        self._lock = threading.Lock()
        self._keep = keep

    # -- submission ----------------------------------------------------------
    def submit_encrypt(
        self,
        sources: list[Source],
        creds: engine.Credentials,
        opts: JobOptions,
        *,
        allow_weak: bool = False,
        min_score: int = 2,
    ) -> Job:
        if not sources:
            raise VaultLockError("Add at least one file or folder first.")
        if not creds.password:
            raise MissingCredentialError("A password is required.")
        if not allow_weak and strength.evaluate(creds.password).score < min_score:
            raise WeakPasswordError("That password is too weak. Choose a stronger one or confirm to use it anyway.")
        if creds.keyfile:
            digest_keyfile(creds.keyfile).wipe()  # fail fast on a missing/unreadable keyfile
        (opts.kdf or kdfmod.preset(kdfmod.DEFAULT_PRESET)).validate_secure()
        if opts.bundle and len(sources) > 1:
            label = opts.bundle_name or f"{len(sources)} items"
            items = [JobItem(0, label, sources)]
        else:
            items = [JobItem(i, s.path.name or str(s.path), [s]) for i, s in enumerate(sources)]
        return self._register(Job("encrypt", items, creds, opts))

    def submit_decrypt(self, sources: list[Source], creds: engine.Credentials, opts: JobOptions) -> Job:
        if not sources:
            raise VaultLockError("Add at least one .vault file first.")
        if not creds.password:
            raise MissingCredentialError("A password is required.")
        if creds.keyfile:
            digest_keyfile(creds.keyfile).wipe()
        items = [JobItem(i, s.path.name, [s]) for i, s in enumerate(sources)]
        return self._register(Job("decrypt", items, creds, opts))

    def submit_shred(self, sources: list[Source], passes: int = 3) -> Job:
        if not sources:
            raise VaultLockError("Add at least one file or folder to shred.")
        if passes not in shredder.SCHEDULES:
            raise VaultLockError("Passes must be 1, 3 or 7.")
        items = [JobItem(i, s.path.name or str(s.path), [s]) for i, s in enumerate(sources)]
        return self._register(Job("shred", items, None, JobOptions(shred=True, shred_passes=passes)))

    # -- lifecycle -----------------------------------------------------------
    def _register(self, job: Job) -> Job:
        with self._lock:
            self._jobs[job.id] = job
            finished = sorted(
                (j for j in self._jobs.values() if j.status in ("done", "failed", "cancelled")),
                key=lambda j: j.finished or 0,
            )
            for old in finished[: max(len(finished) - self._keep, 0)]:
                self._jobs.pop(old.id, None)
        return job

    def start(self, job: Job) -> Job:
        threading.Thread(target=self.runner.run, args=(job,), name=f"job-{job.id}", daemon=True).start()
        return job

    def run_sync(self, job: Job) -> Job:
        self.runner.run(job)
        return job

    def get(self, job_id: str) -> Optional[Job]:
        with self._lock:
            return self._jobs.get(job_id)

    def cancel(self, job_id: str) -> bool:
        job = self.get(job_id)
        if job is None:
            return False
        job.cancel.set()
        return True

    def cancel_all(self) -> None:
        with self._lock:
            for j in self._jobs.values():
                j.cancel.set()
