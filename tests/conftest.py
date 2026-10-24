"""Shared fixtures. The lab must be running (make up configure)."""

import json
import os
import subprocess
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
CA_CERT = ROOT / ".secrets" / "pki" / "ca.crt"
SSH_KEY = ROOT / ".secrets" / "id_ed25519"


def terraform_outputs() -> dict:
    tf = os.environ.get("TF", "terraform")
    out = subprocess.run(
        [tf, f"-chdir={ROOT / 'terraform'}", "output", "-json"], capture_output=True, text=True, check=True
    ).stdout
    return {name: item["value"] for name, item in json.loads(out).items()}


def wait_for(check, timeout: float = 60, every: float = 3):
    """Call check() until it returns a truthy value or the timeout is reached."""
    deadline = time.monotonic() + timeout
    while True:
        result = check()
        if result or time.monotonic() > deadline:
            return result
        time.sleep(every)


def ssh(port: int, user: str, command: str, *options: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [
            "ssh", "-p", str(port),
            "-o", "BatchMode=yes",
            "-o", "StrictHostKeyChecking=no",
            "-o", "UserKnownHostsFile=/dev/null",
            "-o", "ConnectTimeout=10",
            *options,
            f"{user}@127.0.0.1", command,
        ],
        capture_output=True, text=True, timeout=30,
    )


@pytest.fixture(scope="session")
def outputs() -> dict:
    return terraform_outputs()


@pytest.fixture(scope="session")
def nodes(outputs) -> dict:
    return outputs["web_nodes"]


@pytest.fixture(scope="session")
def prometheus(outputs) -> str:
    return outputs["prometheus_url"]


@pytest.fixture(scope="session")
def grafana(outputs) -> tuple[str, tuple[str, str]]:
    return outputs["grafana_url"], ("admin", outputs["grafana_admin_password"])
