"""End-to-end admin UI test driving real Chromium via Playwright.

Skips automatically if no Chromium binary is available.  Also writes fresh
screenshots to docs/screenshots when RUN_SCREENSHOTS=1.
"""

import glob
import os
import threading
import time

import pytest
import uvicorn

from gmail_proxy.admin.app import build_admin_app
from gmail_proxy.config import Policy, Settings
from gmail_proxy.context import build_context
from gmail_proxy.gmail.mock_client import sample_backend

_CHROME = sorted(glob.glob("/opt/pw-browsers/chromium-*/chrome-linux/chrome"))
pytestmark = pytest.mark.skipif(not _CHROME, reason="no Chromium binary available")


@pytest.fixture
def admin_server(tmp_path):
    ctx = build_context(
        Settings(data_dir=str(tmp_path), gmail_backend="mock", admin_token="e2e-token"),
        backend=sample_backend(),
        policy=Policy(allowed_categories=["promotions", "social"]),
    )
    ctx.credentials.issue("openclaw-vm-1")
    server = uvicorn.Server(
        uvicorn.Config(build_admin_app(ctx), host="127.0.0.1", port=8792, log_level="error")
    )
    t = threading.Thread(target=server.run, daemon=True)
    t.start()
    for _ in range(100):
        if server.started:
            break
        time.sleep(0.05)
    yield "http://127.0.0.1:8792"
    server.should_exit = True
    t.join(timeout=5)


def test_login_and_navigate(admin_server):
    from playwright.sync_api import sync_playwright

    with sync_playwright() as p:
        browser = p.chromium.launch(executable_path=_CHROME[-1])
        page = browser.new_page(viewport={"width": 1280, "height": 900})
        page.goto(f"{admin_server}/login")
        page.fill("input[name=token]", "e2e-token")
        page.click("button[type=submit]")
        page.wait_for_url(f"{admin_server}/")
        assert "Dashboard" in page.content()

        page.goto(f"{admin_server}/config")
        assert "Allowed categories" in page.content()

        page.goto(f"{admin_server}/explain?id=m010")
        assert "NOT ELIGIBLE" in page.content()

        page.goto(f"{admin_server}/credentials")
        assert "openclaw-vm-1" in page.content()
        browser.close()
