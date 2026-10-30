"""Summarise the ModSecurity JSON audit log: what was blocked, by which rules, from where, on which URLs.

    ssh -p 2220 -i .secrets/id_ed25519 ops@127.0.0.1 sudo cat /var/log/modsec/audit.json | python3 tools/waf_report.py
    python3 tools/waf_report.py audit.json --request-id 3f8760...   # one request, every rule that matched
    python3 tools/waf_report.py audit.json --detection-only          # allowed requests that matched rules
                                                                     # (paranoia level 2 in detection mode)

First thing to run during an incident (docs/runbooks/waf-attack-spike.md): it tells an attack campaign
(many IPs or payloads, one target) from a false positive (one rule, one URL, normal-looking clients).
"""

import argparse
import json
import sys
from collections import Counter

SKIP_RULES = {"949110", "959100", "980170"}  # score evaluation and correlation, not detections


def load(stream):
    for line in stream:
        line = line.strip()
        if line:
            try:
                yield json.loads(line)["transaction"]
            except (ValueError, KeyError):
                continue


def detections(tx: dict):
    for m in tx.get("messages") or []:
        d = m.get("details", {})
        if d.get("ruleId") not in SKIP_RULES:
            yield d.get("ruleId", "?"), m.get("message", ""), d


def show_request(transactions, request_id: str) -> int:
    for tx in transactions:
        if tx.get("unique_id") == request_id:
            req = tx["request"]
            print(f"{tx['time_stamp']}  {tx['client_ip']}  {req['method']} {req['uri']}  -> {tx['response']['http_code']}")
            for rule_id, msg, d in detections(tx):
                print(f"  {rule_id:>6}  {msg}\n          {d.get('data', '')[:150]}")
            return 0
    print(f"request id {request_id} not found", file=sys.stderr)
    return 1


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("file", nargs="?", help="audit log (default: standard input)")
    parser.add_argument("--request-id")
    parser.add_argument("--top", type=int, default=10)
    parser.add_argument("--detection-only", action="store_true",
                        help="requests that were allowed but matched rules: what a higher paranoia level would block")
    args = parser.parse_args()

    stream = open(args.file, encoding="utf-8") if args.file else sys.stdin
    everything = list(load(stream))
    if args.request_id:
        return show_request(everything, args.request_id)
    if args.detection_only:
        transactions = [tx for tx in everything if (tx.get("response", {}).get("http_code") or 0) < 400
                        and any(True for _ in detections(tx))]
    else:
        transactions = [tx for tx in everything if tx.get("response", {}).get("http_code") in (403, 415)]

    rules, ips, uris, attacks = Counter(), Counter(), Counter(), Counter()
    messages = {}
    for tx in transactions:
        ips[tx.get("client_ip", "?")] += 1
        uris[tx["request"]["uri"].split("?")[0]] += 1
        seen_attacks = set()
        for rule_id, msg, d in detections(tx):
            rules[rule_id] += 1
            messages[rule_id] = msg
            seen_attacks |= {t[len("attack-"):] for t in d.get("tags", []) if t.startswith("attack-")}
        for a in seen_attacks or {"other"}:
            attacks[a] += 1

    kind = "Allowed requests with detections" if args.detection_only else "Blocked requests"
    print(f"{kind}: {len(transactions)}   distinct client IPs: {len(ips)}   distinct paths: {len(uris)}\n")
    for title, counter, label in (
        ("Attack types", attacks, lambda k: k),
        ("Rules", rules, lambda k: f"{k}  {messages[k][:70]}"),
        ("Client IPs", ips, lambda k: k),
        ("Paths", uris, lambda k: k),
    ):
        print(title)
        for key, count in counter.most_common(args.top):
            print(f"  {count:6}  {label(key)}")
        print()
    return 0


if __name__ == "__main__":
    sys.exit(main())
