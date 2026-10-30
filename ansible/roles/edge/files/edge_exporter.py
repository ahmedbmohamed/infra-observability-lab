#!/usr/bin/env python3
"""Prometheus exporter for the edge: reads two JSON log files as they grow and serves /metrics.

- nginx access log (log_format edge_json): requests by status class and cache status.
- ModSecurity audit log (SecAuditLogFormat JSON): requests blocked by the WAF, by attack type.

Standard library only, so it runs on the server's own Python. Labels are bounded (status class, cache
status, CRS attack tags) to keep the number of time series small.
"""

import argparse
import json
import os
import threading
import time
from collections import Counter
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

LOCK = threading.Lock()
REQUESTS: Counter = Counter()  # (status_class, cache) -> count
WAF_BLOCKED: Counter = Counter()  # (phase,) -> count: "request" (inbound) or "response" (outbound)
WAF_ATTACKS: Counter = Counter()  # (attack,) -> count, once per blocked request and attack type
PARSE_ERRORS: Counter = Counter()  # (log,) -> count
CACHE_STATES = {"HIT", "MISS", "BYPASS", "EXPIRED", "STALE", "UPDATING", "REVALIDATED"}


def follow(path: str, handle_line, log_name: str, stop: threading.Event) -> None:
    """Like "tail -F": waits for the file, reads new lines, reopens it after a rotation."""
    position, inode = 0, None
    first_open = True
    while not stop.is_set():
        try:
            st = os.stat(path)
        except FileNotFoundError:
            first_open = False  # the file will be created later: read it from the start
            stop.wait(1)
            continue
        if st.st_ino != inode or st.st_size < position:
            # New or rotated file. On start-up, skip what was written before: counters start at zero.
            inode = st.st_ino
            position = st.st_size if first_open else 0
        first_open = False
        if st.st_size > position:
            with open(path, "rb") as f:
                f.seek(position)
                data = f.read()
            # Keep an unfinished last line for the next read.
            complete = data.rfind(b"\n") + 1
            position += complete
            for raw in data[:complete].splitlines():
                if raw.strip():
                    try:
                        handle_line(json.loads(raw))
                    except (ValueError, KeyError, TypeError, AttributeError):
                        with LOCK:
                            PARSE_ERRORS[(log_name,)] += 1
        stop.wait(0.5)


def on_access(entry: dict) -> None:
    status = int(entry["status"])
    cache = entry.get("cache") or "NONE"
    if cache not in CACHE_STATES:
        cache = "NONE"
    with LOCK:
        REQUESTS[(f"{status // 100}xx", cache)] += 1


def on_audit(entry: dict) -> None:
    tx = entry["transaction"]
    messages = tx.get("messages") or []
    rule_ids = {str(m.get("details", {}).get("ruleId", "")) for m in messages}
    if tx.get("response", {}).get("http_code") not in (403, 415):
        return  # logged but not blocked (for example a 400 from nginx itself)
    phase = "response" if "959100" in rule_ids else "request"
    attacks = set()
    for m in messages:
        for tag in m.get("details", {}).get("tags", []):
            if tag.startswith("attack-"):
                attacks.add(tag[len("attack-"):])
    with LOCK:
        WAF_BLOCKED[(phase,)] += 1
        for attack in attacks or {"other"}:
            WAF_ATTACKS[(attack,)] += 1


def render() -> str:
    def block(name: str, help_text: str, labels: tuple, counter: Counter) -> list[str]:
        lines = [f"# HELP {name} {help_text}", f"# TYPE {name} counter"]
        for values, count in sorted(counter.items()):
            pairs = ",".join(f'{k}="{v}"' for k, v in zip(labels, values))
            lines.append(f"{name}{{{pairs}}} {count}")
        return lines

    with LOCK:
        lines = (
            block("edge_http_requests_total", "Requests served by the edge.", ("status_class", "cache"), REQUESTS)
            + block("edge_waf_blocked_requests_total", "Requests blocked by the WAF.", ("phase",), WAF_BLOCKED)
            + block(
                "edge_waf_attacks_total",
                "Blocked requests by CRS attack type (one request can count for several types).",
                ("attack",),
                WAF_ATTACKS,
            )
            + block("edge_exporter_parse_errors_total", "Log lines that could not be parsed.", ("log",), PARSE_ERRORS)
        )
    return "\n".join(lines) + "\n"


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):  # noqa: N802 (name required by BaseHTTPRequestHandler)
        if self.path != "/metrics":
            self.send_error(404)
            return
        body = render().encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; version=0.0.4")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):  # one line per scrape would flood the log
        pass


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--access-log", required=True)
    parser.add_argument("--audit-log", required=True)
    parser.add_argument("--port", type=int, default=9145)
    args = parser.parse_args()

    stop = threading.Event()
    for path, handler, name in ((args.access_log, on_access, "access"), (args.audit_log, on_audit, "audit")):
        threading.Thread(target=follow, args=(path, handler, name, stop), daemon=True).start()

    server = ThreadingHTTPServer(("", args.port), Handler)
    print(f"edge_exporter listening on :{args.port}", flush=True)
    try:
        server.serve_forever()
    finally:
        stop.set()
        time.sleep(0.1)


if __name__ == "__main__":
    main()
