"""Drives the real UI in headless Chromium: lock -> preview -> wrong password -> unlock.

Skipped automatically when Playwright or its browser is not installed.
"""

import os
import time

import pytest

sync_api = pytest.importorskip("playwright.sync_api")

from vaultlock.launcher import start_server  # noqa: E402

PW = "Correct-Horse-Battery-42!"


@pytest.fixture
def ui(tmp_path):
    srv = start_server(home=tmp_path / "home")
    try:
        with sync_api.sync_playwright() as p:
            try:
                browser = p.chromium.launch()
            except Exception as e:  # browser binary missing
                pytest.skip(f"Chromium unavailable: {e}")
            page = browser.new_page(viewport={"width": 1320, "height": 860})
            errors = []
            page.on("console", lambda m: errors.append(m.text) if m.type == "error" else None)
            page.on("pageerror", lambda e: errors.append(str(e)))
            page.goto(srv.url)
            page.wait_for_selector("#dial")
            yield page, errors
            browser.close()
    finally:
        srv.stop()


def browse_to(page, folder, names):
    """Navigate the in-app file browser to ``folder`` and tick ``names``."""
    page.wait_for_selector(".fb .row")
    page.click(".fb .side button:has-text('Computer')")
    for part in [p for p in str(folder).split(os.sep) if p]:
        page.wait_for_selector(f".fb .row .nm:text-is('{part}')")
        page.click(f".fb .row:has(.nm:text-is('{part}')) small")
    for n in names:
        page.wait_for_selector(f".fb .row .nm:text-is('{n}')")
        page.click(f".fb .row:has(.nm:text-is('{n}'))")
    page.click(".modal footer .btn-primary")


def test_lock_preview_wrong_password_unlock(ui, tmp_path):
    page, errors = ui
    docs = tmp_path / "docs"; docs.mkdir()
    (docs / "notes.txt").write_text("Quarterly notes\nThe vault is working.\n")
    out = tmp_path / "restored"; out.mkdir()

    # --- lock (cheap KDF isn't injectable here, so this also exercises the real default profile)
    page.click("#dial")
    browse_to(page, docs, ["notes.txt"])
    page.wait_for_selector(".card")
    page.fill("#pw", PW); page.fill("#pw2", PW)
    page.locator("#strLabel").filter(has_text="Excellent").wait_for()
    page.click("#go")
    page.wait_for_selector("#dial.done", timeout=60000)
    assert (docs / "notes.txt.vault").exists()
    assert (docs / "notes.txt").exists()          # originals kept unless shred was chosen

    # --- unlock mode, preview from RAM
    page.click(".modes button[data-mode=unlock]")
    page.click("#dial")
    browse_to(page, docs, ["notes.txt.vault"])
    page.wait_for_selector(".card")
    page.fill("#pw", PW)
    page.click(".card [data-a=preview]")
    page.wait_for_selector(".viewer pre")
    assert "The vault is working." in page.inner_text(".viewer pre")
    assert "Decrypted in memory only" in page.inner_text(".modal")
    page.click(".modal footer button")

    # --- wrong password is rejected with a clear message
    page.fill("#pw", "definitely-not-it")
    page.click("#go")
    page.wait_for_selector("#dial.fail", timeout=60000)
    assert "Incorrect password" in page.inner_text("#formError")

    # --- right password, custom output folder
    page.fill("#pw", PW)
    page.click("#pickOut")
    browse_to(page, out, [])        # nothing ticked -> "Use this folder" = current folder after navigation
    page.click("#go")
    page.wait_for_selector("#dial.done", timeout=60000)
    assert (out / "notes.txt").read_text().startswith("Quarterly notes")

    assert errors == []
