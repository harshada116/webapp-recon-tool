"""
screenshot.py
-------------
Captures a screenshot of the target site's homepage using headless
Chrome via Selenium. Screenshot capture is optional: if Selenium or a
compatible browser/driver is not available in the environment, this
module returns a clear error rather than crashing the whole scan.
"""

from __future__ import annotations

import os
from typing import Any, Dict


def capture(url: str, output_path: str, width: int = 1366, height: int = 900, timeout: int = 20) -> Dict[str, Any]:
    try:
        from selenium import webdriver
        from selenium.webdriver.chrome.options import Options
        from selenium.webdriver.chrome.service import Service
    except ImportError:
        return {
            "captured": False,
            "error": (
                "Screenshot capture requires 'selenium' plus a Chrome/Chromium "
                "browser installed. Run: pip install selenium"
            ),
        }

    options = Options()
    options.add_argument("--headless=new")
    options.add_argument("--no-sandbox")
    options.add_argument("--disable-dev-shm-usage")
    options.add_argument(f"--window-size={width},{height}")
    options.add_argument("--disable-gpu")

    # In containers we point at the system-installed Chromium/driver via env
    # vars (see recon_tool/Dockerfile) to avoid downloading a browser at
    # runtime. Outside a container, fall back to webdriver-manager, which
    # downloads a matching driver automatically on first use.
    chrome_bin = os.environ.get("CHROME_BIN")
    chromedriver_path = os.environ.get("CHROMEDRIVER_PATH")
    if chrome_bin:
        options.binary_location = chrome_bin

    driver = None
    try:
        if chromedriver_path:
            service = Service(chromedriver_path)
        else:
            from webdriver_manager.chrome import ChromeDriverManager
            service = Service(ChromeDriverManager().install())
        driver = webdriver.Chrome(service=service, options=options)
        driver.set_page_load_timeout(timeout)
        driver.get(url)
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        driver.save_screenshot(output_path)
        return {"captured": True, "path": output_path}
    except Exception as exc:  # webdriver/browser errors vary widely
        return {"captured": False, "error": f"Screenshot capture failed: {exc}"}
    finally:
        if driver is not None:
            driver.quit()
