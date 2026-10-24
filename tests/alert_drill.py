"""Alert drill: stop nginx on one server, check that Prometheus raises NginxDown, then restore it.

    python tests/alert_drill.py [--node web1] [--screenshots docs/screenshots]

It measures the time from the outage to the alert, and from the repair to the alert clearing.
"""

import argparse
import sys
import threading
import time
from pathlib import Path

import requests

sys.path.insert(0, str(Path(__file__).parent))
from conftest import CA_CERT, SSH_KEY, ssh, terraform_outputs, wait_for  # noqa: E402


def nginx_alert(prometheus: str, node: str) -> str | None:
    alerts = requests.get(f"{prometheus}/api/v1/alerts", timeout=10).json()["data"]["alerts"]
    for a in alerts:
        if a["labels"]["alertname"] == "NginxDown" and a["labels"]["instance"] == node:
            return a["state"]
    return None


def supervisor(port: int, action: str) -> None:
    r = ssh(port, "ops", f"sudo -n supervisorctl {action} nginx", "-i", str(SSH_KEY))
    if r.returncode != 0:
        sys.exit(f"supervisorctl {action} failed: {r.stderr}")


def screenshots(out: Path, grafana: str, password: str, prometheus: str, shots: list[str]) -> None:
    """Shots: "alerts" (Prometheus firing alerts) and/or a dashboard file name such as "grafana-dashboard"."""
    from playwright.sync_api import sync_playwright

    out.mkdir(parents=True, exist_ok=True)
    with sync_playwright() as p:
        browser = p.chromium.launch()
        page = browser.new_page(viewport={"width": 1600, "height": 1000})
        for shot in shots:
            if shot == "alerts":
                page.goto(f"{prometheus}/alerts?state=firing")
                page.wait_for_timeout(3000)
                page.screenshot(path=out / "prometheus-alert-firing.png", full_page=True)
                continue
            if "/login" in page.url or page.url == "about:blank":
                page.goto(f"{grafana}/login")
                page.fill('input[name="user"]', "admin")
                page.fill('input[name="password"]', password)
                page.click('button[type="submit"]')
                page.wait_for_load_state("networkidle")
            page.goto(f"{grafana}/d/iol-overview?orgId=1&from=now-10m&to=now&kiosk")
            page.wait_for_timeout(8000)
            page.screenshot(path=out / f"{shot}.png", full_page=True)
        browser.close()


def traffic(urls: list[str], stop: threading.Event) -> None:
    """Steady requests so the dashboard graphs are not flat."""
    while not stop.is_set():
        for url in urls:
            try:
                requests.get(url, verify=CA_CERT, timeout=2)
            except requests.exceptions.RequestException:
                pass
        stop.wait(0.2)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--node", default="web1")
    parser.add_argument("--screenshots", type=Path)
    args = parser.parse_args()

    out = terraform_outputs()
    prometheus = out["prometheus_url"]
    node = out["web_nodes"][args.node]

    if nginx_alert(prometheus, args.node):
        sys.exit("NginxDown is already active before the drill")

    stop_traffic = threading.Event()
    threading.Thread(
        target=traffic, args=([n["https_url"] for n in out["web_nodes"].values()], stop_traffic), daemon=True
    ).start()
    shoot = None
    if args.screenshots:
        def shoot(*shots: str) -> None:
            screenshots(args.screenshots, out["grafana_url"], out["grafana_admin_password"], prometheus, list(shots))

    print(f"[drill] stopping nginx on {args.node}")
    supervisor(node["ssh_port"], "stop")
    stopped = time.monotonic()
    try:
        requests.get(node["https_url"], verify=CA_CERT, timeout=5)
        sys.exit("the site still answers after nginx was stopped")
    except requests.exceptions.ConnectionError:
        print("[drill] the site is down, as expected")

    if not wait_for(lambda: nginx_alert(prometheus, args.node) == "firing", timeout=150, every=2):
        supervisor(node["ssh_port"], "start")
        sys.exit("NginxDown did not fire within 150 s")
    print(f"[drill] NginxDown is firing, {time.monotonic() - stopped:.0f} s after the outage (rule: for 30s)")

    if shoot:
        shoot("alerts", "grafana-dashboard-outage")

    print(f"[drill] starting nginx on {args.node}")
    supervisor(node["ssh_port"], "start")
    restored = time.monotonic()
    if not wait_for(lambda: nginx_alert(prometheus, args.node) is None, timeout=120, every=2):
        sys.exit("NginxDown did not clear within 120 s")
    print(f"[drill] alert cleared {time.monotonic() - restored:.0f} s after the repair")

    if shoot:
        time.sleep(40)  # let the graphs show the recovery
        shoot("grafana-dashboard")
        print(f"[drill] screenshots saved in {args.screenshots}")
    stop_traffic.set()

    r = requests.get(node["https_url"], verify=CA_CERT, timeout=10)
    assert r.status_code == 200
    print("[drill] passed")


if __name__ == "__main__":
    main()
