"""Prometheus scrapes every server, the alert rules are loaded and Grafana shows the dashboard."""

import requests

from conftest import CA_CERT, wait_for

EXPECTED_RULES = {
    "TargetDown", "NginxDown", "HighCpuUsage", "LowMemory", "LowDiskSpace", "NginxNoTraffic",
    "EndpointProbeFailed", "CertificateExpiringSoon", "CertificateExpiryCritical", "WafAttackSpike", "EdgeHighErrorRate",
}


def targets(prometheus):
    return requests.get(f"{prometheus}/api/v1/targets", timeout=10).json()["data"]["activeTargets"]


def test_every_target_is_up(prometheus):
    all_up = wait_for(lambda: (t := targets(prometheus)) and all(x["health"] == "up" for x in t), timeout=90)
    assert all_up, [(x["labels"]["job"], x["labels"]["instance"], x["lastError"]) for x in targets(prometheus)]


def test_each_server_is_scraped_by_node_and_nginx_jobs(prometheus, nodes):
    found = {(t["labels"]["job"], t["labels"]["instance"]) for t in targets(prometheus)}
    for name in [*nodes, "edge"]:
        assert ("node", name) in found
        assert ("nginx", name) in found
    assert ("edge", "edge") in found
    assert ("blackbox", "https://edge/healthz") in found


def test_alert_rules_are_loaded(prometheus):
    groups = requests.get(f"{prometheus}/api/v1/rules", timeout=10).json()["data"]["groups"]
    loaded = {rule["name"] for group in groups for rule in group["rules"]}
    assert EXPECTED_RULES <= loaded
    assert all(rule["health"] == "ok" for group in groups for rule in group["rules"])


def test_no_critical_alert_is_firing(prometheus):
    alerts = requests.get(f"{prometheus}/api/v1/alerts", timeout=10).json()["data"]["alerts"]
    firing = [a["labels"] for a in alerts if a["state"] == "firing" and a["labels"].get("severity") == "critical"]
    assert firing == []


def test_requests_are_counted(prometheus, nodes):
    def total():
        q = requests.get(f"{prometheus}/api/v1/query", params={"query": "sum(nginx_http_requests_total)"}, timeout=10)
        result = q.json()["data"]["result"]
        return float(result[0]["value"][1]) if result else 0.0

    before = total()
    for node in nodes.values():
        for _ in range(20):
            requests.get(node["https_url"], verify=CA_CERT, timeout=10)
    assert wait_for(lambda: total() >= before + 20 * len(nodes), timeout=45)


def test_grafana_is_healthy(grafana):
    url, _ = grafana
    assert requests.get(f"{url}/api/health", timeout=10).json()["database"] == "ok"


def test_grafana_requires_login(grafana):
    url, _ = grafana
    assert requests.get(f"{url}/api/search", timeout=10).status_code == 401


def test_grafana_reaches_prometheus(grafana):
    url, auth = grafana
    r = requests.get(f"{url}/api/datasources/uid/prometheus/health", auth=auth, timeout=10)
    assert r.status_code == 200 and r.json()["status"] == "OK", r.text


def test_dashboard_is_provisioned(grafana):
    url, auth = grafana
    found = requests.get(f"{url}/api/search", params={"query": "Infra Lab overview"}, auth=auth, timeout=10).json()
    assert [d["uid"] for d in found] == ["iol-overview"]


def test_edge_dashboard_is_provisioned(grafana):
    url, auth = grafana
    found = requests.get(f"{url}/api/search", params={"query": "Edge security"}, auth=auth, timeout=10).json()
    assert [d["uid"] for d in found] == ["iol-edge"]


def test_root_disk_is_measured(prometheus, nodes):
    q = 'node_filesystem_avail_bytes{mountpoint="/"}'
    result = requests.get(f"{prometheus}/api/v1/query", params={"query": q}, timeout=10).json()["data"]["result"]
    assert {r["metric"]["instance"] for r in result} == set(nodes) | {"edge"}
