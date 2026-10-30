"""WAF drill: simulate an attack campaign, check that WafAttackSpike fires, stop it, check that the alert clears.

    python tests/waf_drill.py [--screenshots docs/screenshots]

Meanwhile a legitimate client keeps browsing: it must never be blocked (no collateral damage).
"""

import argparse
import itertools
import sys
import threading
import time
from pathlib import Path

import requests

sys.path.insert(0, str(Path(__file__).parent))
from alert_drill import screenshots  # noqa: E402
from conftest import CA_CERT, terraform_outputs, wait_for  # noqa: E402
from waf_corpus import ATTACKS, LEGITIMATE, send  # noqa: E402

# Login cases are left out: the rate limit would answer 429 before the WAF, which is not what this drill measures.
CAMPAIGN = [c for c in ATTACKS if c.expect == 403 and c.path != "/api/login"]
BROWSING = [c for c in LEGITIMATE if c.path != "/api/login"]


def alert_state(prometheus: str) -> str | None:
    alerts = requests.get(f"{prometheus}/api/v1/alerts", timeout=10).json()["data"]["alerts"]
    return next((a["state"] for a in alerts if a["labels"]["alertname"] == "WafAttackSpike"), None)


def attacker(site: str, stop: threading.Event, sent: list) -> None:
    for case in itertools.cycle(CAMPAIGN):
        if stop.is_set():
            return
        r = send(site, case, CA_CERT)
        sent.append(r.status_code)
        stop.wait(0.4)  # about 2 requests per second, 4 times the alert threshold


def customer(site: str, stop: threading.Event, refused: list) -> None:
    for case in itertools.cycle(BROWSING):
        if stop.is_set():
            return
        r = send(site, case, CA_CERT)
        if r.status_code != case.expect:
            refused.append((case.name, r.status_code, r.headers.get("X-Request-ID")))
        stop.wait(1)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--screenshots", type=Path)
    args = parser.parse_args()

    out = terraform_outputs()
    site, prometheus = out["edge"]["https_url"], out["prometheus_url"]
    if alert_state(prometheus):
        sys.exit("WafAttackSpike is already active before the drill")

    stop_attack, stop_customer = threading.Event(), threading.Event()
    sent, refused = [], []
    threading.Thread(target=customer, args=(site, stop_customer, refused), daemon=True).start()
    threading.Thread(target=attacker, args=(site, stop_attack, sent), daemon=True).start()
    started = time.monotonic()
    print(f"[drill] attack campaign started: {len(CAMPAIGN)} payload types against {site}")

    if not wait_for(lambda: alert_state(prometheus) == "firing", timeout=180, every=3):
        stop_attack.set()
        sys.exit("WafAttackSpike did not fire within 180 s")
    print(f"[drill] WafAttackSpike is firing, {time.monotonic() - started:.0f} s after the first attack (rule: > 0.5/s for 30s)")

    if args.screenshots:
        screenshots(args.screenshots, out["grafana_url"], out["grafana_admin_password"], prometheus,
                    ["alerts", "edge-dashboard-attack"], alert="WafAttackSpike")
        print(f"[drill] screenshots saved in {args.screenshots}")

    stop_attack.set()
    blocked = sum(code == 403 for code in sent)
    print(f"[drill] attack stopped: {blocked}/{len(sent)} malicious requests blocked")
    stopped = time.monotonic()
    if not wait_for(lambda: alert_state(prometheus) is None, timeout=240, every=3):
        sys.exit("WafAttackSpike did not clear within 240 s")
    print(f"[drill] alert cleared {time.monotonic() - stopped:.0f} s after the attack stopped")

    stop_customer.set()
    if blocked != len(sent):
        sys.exit(f"some attacks went through: {len(sent) - blocked}")
    if refused:
        sys.exit(f"legitimate requests were refused during the attack: {refused[:5]}")
    print("[drill] no legitimate request was refused during the attack")
    print("[drill] passed")


if __name__ == "__main__":
    main()
