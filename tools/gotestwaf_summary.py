"""Print the key numbers of a GoTestWAF JSON report, as a Markdown table.

    python3 tools/gotestwaf_summary.py reports/gotestwaf.json [--min-blocked 90 --min-passed 90]

With --min-blocked / --min-passed it exits with an error below those percentages (regression gate for the CI).
"""

import argparse
import json
import sys
from collections import Counter


def pct(part: int, whole: int) -> float:
    return 100.0 * part / whole if whole else 0.0


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("report")
    parser.add_argument("--min-blocked", type=float)
    parser.add_argument("--min-passed", type=float)
    parser.add_argument("--details", action="store_true", help="where the bypasses and the false positives are")
    parser.add_argument("--brief", action="store_true", help="only the main table")
    args = parser.parse_args()

    data = json.load(open(args.report, encoding="utf-8"))
    summary = data.get("summary", data)
    tp, tn = summary["true_positive_tests"], summary["true_negative_tests"]
    tp_s, tn_s = tp["summary"], tn["summary"]

    blocked = pct(tp_s["blocked_tests"], tp_s["resolved_tests"])
    passed = pct(tn_s["bypassed_tests"], tn_s["resolved_tests"])  # "bypassed" = allowed, which is right for legit traffic
    print(f"GoTestWAF against {data.get('url')} ({data.get('date')})\n")
    print("| Measure | Result |\n|---|---|")
    print(f"| Overall score | {data.get('score', 0):.1f}% |")
    print(f"| Attacks blocked (true positives) | {tp_s['blocked_tests']}/{tp_s['resolved_tests']} = {blocked:.1f}% |")
    print(f"| Legitimate requests allowed (true negatives) | {tn_s['bypassed_tests']}/{tn_s['resolved_tests']} = {passed:.1f}% |")
    print(f"| Unresolved (other status codes) | {tp_s['unresolved_tests'] + tn_s['unresolved_tests']} |")
    print(f"| Failed (network errors) | {tp_s['failed_tests'] + tn_s['failed_tests']} |")

    if not args.brief:
        print("\n| Attack set / case | Sent | Blocked | Bypassed | Blocked % |\n|---|---|---|---|---|")
        for set_name, cases in sorted(tp.get("test_sets", {}).items()):
            for case_name, c in sorted(cases.items()):
                if c["sent"]:
                    print(f"| {set_name} / {case_name} | {c['sent']} | {c['blocked']} | {c['bypassed']} | {c['percentage']:.1f}% |")

    if args.details:
        bypassed = (data.get("true_positive_tests_payloads") or {}).get("bypassed") or []
        fps = (data.get("true_negative_tests_payloads") or {}).get("blocked") or []
        for title, items in (("Bypasses (attacks not blocked)", bypassed), ("False positives (legitimate requests blocked)", fps)):
            print(f"\n{title}: {len(items)}\n\n| Placeholder | Encoder | Count |\n|---|---|---|")
            for (place, enc), n in Counter((i.get("placeholder"), i.get("encoder")) for i in items).most_common(15):
                print(f"| {place} | {enc} | {n} |")
            print("\nExamples:")
            for i in items[:25]:
                payload = str(i.get("payload", ""))[:90].replace("|", "\\|").replace("\n", " ")
                print(f"- `{i.get('placeholder')}` / `{i.get('encoder')}` / {i.get('test_case')}: `{payload}`")

    failed = False
    if args.min_blocked is not None and blocked < args.min_blocked:
        print(f"\nFAIL: {blocked:.1f}% of attacks blocked, minimum {args.min_blocked}%", file=sys.stderr)
        failed = True
    if args.min_passed is not None and passed < args.min_passed:
        print(f"\nFAIL: {passed:.1f}% of legitimate requests allowed, minimum {args.min_passed}%", file=sys.stderr)
        failed = True
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
