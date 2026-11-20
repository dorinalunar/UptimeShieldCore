#!/usr/bin/env python3
"""Verify that deployed on-chain UptimeShield bytecode matches contracts/UptimeShield.py."""

import base64
import hashlib
import json
import os
import pathlib
import sys
import urllib.request

RPC = os.environ.get("GENLAYER_RPC", "https://studio-dev.genlayer.com/api")
ADDRESS = os.environ.get("UPTIMESHIELD_ADDRESS", "")
SOURCE = pathlib.Path(__file__).resolve().parents[1] / "contracts" / "UptimeShield.py"


def on_chain_sha256(address: str) -> str:
    payload = json.dumps(
        {"jsonrpc": "2.0", "id": 1, "method": "gen_getContractCode", "params": [address]}
    ).encode()
    request = urllib.request.Request(
        RPC,
        data=payload,
        headers={"content-type": "application/json", "user-agent": "uptimeshield-ci"},
    )
    with urllib.request.urlopen(request, timeout=30) as response:
        body = json.load(response)
    if "result" not in body:
        raise SystemExit(f"RPC error: {body.get('error')}")
    return hashlib.sha256(base64.b64decode(body["result"])).hexdigest()


def main() -> int:
    local = hashlib.sha256(SOURCE.read_bytes()).hexdigest()
    if not ADDRESS:
        print("local   ", local)
        print("UPTIMESHIELD_ADDRESS not set; skipping remote RPC check")
        return 0
    remote = on_chain_sha256(ADDRESS)
    if local != remote:
        print("MISMATCH: redeploy this exact source before submitting")
        print("local   ", local)
        print("on-chain", remote)
        return 1
    print("local   ", local)
    print("on-chain", remote)
    print("match")
    return 0


if __name__ == "__main__":
    sys.exit(main())
