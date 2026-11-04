"""Small Linux WireGuard agent for the Alif VPN Django API.

This agent only applies WireGuard peer changes. It deliberately refuses any
unknown protocol/action and does not execute commands received from the API.
"""

from __future__ import annotations

import json
import logging
import os
import subprocess
import tempfile
import time
from pathlib import Path

import psutil
import requests


API_BASE_URL = os.environ["ALIF_API_BASE_URL"].rstrip("/")
NODE_ID = os.environ["ALIF_NODE_ID"]
NODE_TOKEN = os.environ["ALIF_NODE_TOKEN"]
WG_INTERFACE = os.getenv("WG_INTERFACE", "wg0")
STATE_FILE = Path(os.getenv("AGENT_STATE_FILE", "/var/lib/alif-vpn-agent/state.json"))
POLL_INTERVAL = max(3, int(os.getenv("AGENT_POLL_INTERVAL", "10")))
AGENT_VERSION = "0.1.0"

logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO").upper(),
    format="%(asctime)s %(levelname)s %(message)s",
)
LOG = logging.getLogger("alif-vpn-agent")


def load_applied_version() -> int:
    try:
        return max(0, int(json.loads(STATE_FILE.read_text(encoding="utf-8"))["applied_version"]))
    except (FileNotFoundError, ValueError, KeyError, json.JSONDecodeError):
        return 0


def save_applied_version(version: int) -> None:
    STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
    fd, temp_name = tempfile.mkstemp(prefix="state-", dir=STATE_FILE.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump({"applied_version": version}, stream)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temp_name, STATE_FILE)
    finally:
        if os.path.exists(temp_name):
            os.unlink(temp_name)


def run_wg(*args: str) -> None:
    subprocess.run(
        ["wg", "set", WG_INTERFACE, *args],
        check=True,
        capture_output=True,
        text=True,
        timeout=15,
    )


def apply_peer(peer: dict) -> str | None:
    protocol = peer.get("protocol")
    action = peer.get("action")
    if protocol != "wireguard":
        raise RuntimeError(f"Unsupported protocol from API: {protocol!r}")

    public_key = peer.get("public_key")
    if not public_key:
        raise RuntimeError("WireGuard peer is missing public_key")

    if action == "REGISTER":
        allowed_ips = peer.get("internal_ip")
        if not allowed_ips:
            raise RuntimeError("WireGuard peer is missing internal_ip")
        run_wg("peer", public_key, "allowed-ips", allowed_ips)
        return None

    if action == "REVOKE":
        run_wg("peer", public_key, "remove")
        return peer.get("peer_id")

    raise RuntimeError(f"Unsupported peer action from API: {action!r}")


def metrics() -> dict:
    try:
        peer_output = subprocess.check_output(
            ["wg", "show", WG_INTERFACE, "peers"], text=True, timeout=10
        )
        peer_count = len(peer_output.splitlines())
    except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired):
        peer_count = 0
    return {
        "cpu_usage_percent": psutil.cpu_percent(interval=0.1),
        "memory_usage_percent": psutil.virtual_memory().percent,
        "active_peers_count": peer_count,
        "network_tx_bytes_sec": 0,
        "network_rx_bytes_sec": 0,
    }


def main() -> None:
    if os.name != "posix":
        raise SystemExit("The VPN node agent must run on Linux/POSIX.")

    base = f"{API_BASE_URL}/api/v1/agent"
    headers = {"X-Agent-ID": NODE_ID, "X-Agent-Token": NODE_TOKEN}
    session = requests.Session()
    session.headers.update(headers)
    applied_version = load_applied_version()
    LOG.info("Starting agent for node %s on interface %s", NODE_ID, WG_INTERFACE)

    while True:
        try:
            response = session.post(
                f"{base}/check-in/",
                json={
                    "node_id": NODE_ID,
                    "agent_version": AGENT_VERSION,
                    "applied_version": applied_version,
                    "metrics": metrics(),
                },
                timeout=20,
            )
            response.raise_for_status()
            payload = response.json()["data"]
            target_version = int(payload["desired_version"])
            revoked_ids = []

            # Replayed commands are safe: WireGuard set/remove operations are idempotent.
            for peer in payload.get("peers", []):
                revoked_id = apply_peer(peer)
                if revoked_id:
                    revoked_ids.append(revoked_id)

            if target_version != applied_version or revoked_ids:
                ack = session.post(
                    f"{base}/acknowledgements/",
                    json={
                        "applied_version": target_version,
                        "revoked_session_ids": revoked_ids,
                    },
                    timeout=20,
                )
                ack.raise_for_status()
                applied_version = target_version
                save_applied_version(applied_version)
                LOG.info("Applied node configuration version %s", applied_version)
        except (requests.RequestException, KeyError, ValueError, RuntimeError,
                subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
            LOG.exception("Check-in/apply failed: %s", exc)
        time.sleep(POLL_INTERVAL)


if __name__ == "__main__":
    main()
