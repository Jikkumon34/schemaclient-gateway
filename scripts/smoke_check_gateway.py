#!/usr/bin/env python
"""Smoke-check the deployed tunnel gateway before opening desktop app."""

from __future__ import annotations

import argparse
import asyncio
import json
import secrets
import string
import sys
from urllib.parse import urlparse

import requests
import websockets


def normalize_gateway_url(raw: str) -> str:
    value = raw.strip().rstrip("/")
    if not value.startswith(("http://", "https://")):
        raise ValueError("gateway URL must start with http:// or https://")
    return value


def random_tunnel_id(length: int = 10) -> str:
    alphabet = string.ascii_lowercase + string.digits
    return "chk" + "".join(secrets.choice(alphabet) for _ in range(length - 3))


def create_tunnel(gateway_url: str, tunnel_id: str | None) -> dict:
    payload = {"tunnel_id": tunnel_id} if tunnel_id else {}
    response = requests.post(
        f"{gateway_url}/api/tunnels/create",
        json=payload,
        timeout=20,
    )
    response.raise_for_status()
    data = response.json()
    for key in ("tunnel_id", "connect_key", "public_url"):
        if key not in data:
            raise RuntimeError(f"create response missing '{key}'")
    return data


def build_ws_url(gateway_url: str, tunnel_id: str, connect_key: str) -> str:
    parsed = urlparse(gateway_url)
    scheme = "wss" if parsed.scheme == "https" else "ws"
    return f"{scheme}://{parsed.netloc}/ws/tunnel/{tunnel_id}/?connect_key={connect_key}"


async def handshake(ws_url: str) -> dict:
    async with websockets.connect(ws_url, open_timeout=15) as websocket:
        raw = await asyncio.wait_for(websocket.recv(), timeout=8)
        return json.loads(raw)


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate tunnel gateway websocket readiness")
    parser.add_argument("--gateway", required=True, help="Gateway base URL, e.g. https://mysmeclabs.com")
    parser.add_argument("--tunnel-id", default=None, help="Optional manual tunnel ID")
    args = parser.parse_args()

    try:
        gateway_url = normalize_gateway_url(args.gateway)
    except ValueError as exc:
        print(f"[FAIL] {exc}")
        return 2

    tunnel_id = args.tunnel_id or random_tunnel_id()

    try:
        created = create_tunnel(gateway_url, tunnel_id)
        print(f"[OK] create: tunnel_id={created['tunnel_id']} public_url={created['public_url']}")
    except Exception as exc:  # pragma: no cover - operational script
        print(f"[FAIL] create endpoint: {exc}")
        return 3

    ws_url = build_ws_url(gateway_url, created["tunnel_id"], created["connect_key"])
    print(f"[INFO] ws_url={ws_url}")

    try:
        message = asyncio.run(handshake(ws_url))
    except Exception as exc:  # pragma: no cover - operational script
        print(f"[FAIL] websocket handshake: {exc}")
        return 4

    if message.get("type") != "connected":
        print(f"[FAIL] unexpected websocket first message: {message}")
        return 5

    print("[OK] websocket connected")
    print("[PASS] gateway is ready for desktop tunnel client")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
