# Runbook: WafAttackSpike

**Alert:** the WAF blocks more than 0.5 requests per second (30 per minute) for 30 seconds.
**Severity:** warning. **Dashboard:** Grafana > Infra Lab > *Edge security*.

A spike has two very different causes. The first job is to tell them apart, because the fixes are opposite:

| | Attack or scan | False positive |
|---|---|---|
| Who | Few IPs (or many IPs with the same payloads), unusual user agents | Many normal-looking clients |
| What | Many rules, many paths, payload-like values | One or two rules, one path, one parameter |
| When | Any time | Right after a release or a new feature |
| Fix | Keep blocking. Add a deny list entry or a rate limit if it costs resources | Narrow exclusion for that rule and that parameter |

## 1. Look at what is blocked (2 minutes)

```bash
ssh -p 2220 -i .secrets/id_ed25519 ops@127.0.0.1 sudo cat /var/log/modsec/audit.json \
  | python3 tools/waf_report.py --top 10
```

Read the four tables: attack types, rules, client IPs, paths.

If a customer reports a block, ask for the `X-Request-ID` shown in the response headers, then:

```bash
ssh -p 2220 -i .secrets/id_ed25519 ops@127.0.0.1 sudo cat /var/log/modsec/audit.json \
  | python3 tools/waf_report.py --request-id <id>
```

It lists every rule that matched, with the matched value.

## 2a. It is an attack

1. Check that it is **blocked**: the edge answers 403, and the origin logs show nothing for those requests
   (`EdgeHighErrorRate` is not firing).
2. Look for anything that went through: same IPs with 200 answers in `/var/log/nginx/edge-access.json`.
3. If one source causes load or noise, block it at the edge: add it to `edge_ip_denylist`
   (`ansible/roles/edge/defaults/main.yml` or `-e`) and run Ansible. Rule 10001 blocks it before the CRS.
4. If the payload targets a known vulnerability of the application, add a virtual patch in
   `custom-rules.conf.j2` (example: rule 10010) until the application is fixed.
5. Write down for the customer: time window, source, targets, what was blocked, what was done.

## 2b. It is a false positive

1. Reproduce it with the request from the audit log, and add it to `LEGITIMATE` in `tests/waf_corpus.py`.
   The test now fails: that is the proof of the problem.
2. Add the **narrowest** exclusion in `exclusions-before-crs.conf.j2`: one rule (or one rule tag),
   one parameter, one URL. See the three existing examples (10100 to 10102). Never disable a rule
   everywhere and never lower the paranoia level for the whole site.
3. Check that the attack cases still pass: `make test`. If the exclusion opened a hole, an attack
   case fails.
4. If the fix cannot wait for a change review: switch that one URL to detection only with a
   `ctl:ruleEngine=DetectionOnly` rule, never the whole site.

## 3. Close

The alert clears about one minute after the blocks stop. Check the dashboard, and add what you
learned to this runbook.
