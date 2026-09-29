"""Retake the screenshots in docs/screens/ from the running app (UI on :5173, API on :8000, demo estate scanned).

Uses Playwright with the installed Edge, so nothing is downloaded. Theme and language are set through the same
per-browser preference the Display menu writes (vera.prefs.v2), so each shot is what a user sees.

    python scripts/screens.py
"""
from __future__ import annotations

import json
from pathlib import Path

from playwright.sync_api import sync_playwright

OUT = Path(__file__).resolve().parents[1] / "docs/screens"
BASE = "http://localhost:5173/#"
SHOTS = [  # file, route, theme, language, viewport width, open the first asset panel
    ("overview-light", "/overview", "light", "en", 1440, False),
    ("overview-dark", "/overview", "dark", "en", 1440, False),
    ("overview-hindi", "/overview", "light", "hi", 1440, False),
    ("overview-mobile", "/overview", "light", "en", 390, False),
    ("scan-light", "/scan", "light", "en", 1440, False),
    ("inventory-light", "/inventory", "light", "en", 1440, False),
    ("inventory-panel-light", "/inventory", "light", "en", 1440, True),
    ("inventory-panel-dark", "/inventory", "dark", "en", 1440, True),
    ("risk-exposure-light", "/risk/exposure", "light", "en", 1440, False),
    ("risk-exposure-dark", "/risk/exposure", "dark", "en", 1440, False),
    ("risk-drift-light", "/risk/drift", "light", "en", 1440, False),
    ("risk-trust-graph-light", "/risk/dependencies", "light", "en", 1440, False),
    ("plan-actions-light", "/plan/actions", "light", "en", 1440, False),
    ("plan-suppliers-dark", "/plan/suppliers", "dark", "en", 1440, False),
    ("plan-timeline-light", "/plan/timeline", "light", "en", 1440, False),
    ("evidence-dark", "/evidence/reports", "dark", "en", 1440, False),
    ("evidence-certin-light", "/evidence/certin", "light", "en", 1440, False),
    ("evidence-integrity-dark", "/evidence/integrity", "dark", "en", 1440, False),
    ("evidence-detector-light", "/evidence/detector", "light", "en", 1440, False),
    ("settings-runtime-light", "/settings/runtime", "light", "en", 1440, False),
]


def main() -> None:
    with sync_playwright() as p:
        browser = p.chromium.launch(channel="msedge")
        for name, route, theme, lang, width, panel in SHOTS:
            ctx = browser.new_context(viewport={"width": width, "height": 900 if width > 500 else 844})
            prefs = json.dumps({"theme": theme, "text": "normal", "lang": lang})
            ctx.add_init_script(f"window.localStorage.setItem('vera.prefs.v2', {json.dumps(prefs)})")
            page = ctx.new_page()
            page.goto(BASE + route)
            page.wait_for_load_state("networkidle")
            page.wait_for_timeout(1500)
            if panel:
                page.locator("table tbody tr").first.click()
                page.wait_for_timeout(1000)
            page.screenshot(path=str(OUT / f"{name}.png"))
            ctx.close()
            print("saved", name)
        browser.close()


if __name__ == "__main__":
    main()
