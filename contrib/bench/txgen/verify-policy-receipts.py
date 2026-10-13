# /// script
# requires-python = ">=3.11"
# dependencies = ["pycryptodome==3.23.0"]
# ///
"""Verify the exact signed policy payments after the measured workload finishes."""

import json
import sys
import time
import urllib.request
from pathlib import Path

from Crypto.Hash import keccak


def verify(rpc_url, transactions, report, start_block, timeout=60):
    pending = set()
    with Path(transactions).open() as stream:
        for line in stream:
            tx = json.loads(line)
            if tx["phase"] != "workload":
                continue
            if tx.get("late_sign"):
                raise ValueError("Policy receipt validation requires fully signed transactions")
            raw = bytes.fromhex(tx["raw"].removeprefix("0x"))
            if not raw:
                raise ValueError("Policy workload contains an unsigned transaction")
            pending.add("0x" + keccak.new(digest_bits=256, data=raw).hexdigest())
    sent = json.loads(Path(report).read_text())["sent"]
    if not pending or len(pending) != sent:
        raise ValueError(f"Policy workload has {len(pending)} unique hashes but {sent} submissions")

    def rpc(method, params):
        request = urllib.request.Request(
            rpc_url,
            json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode(),
            {"Content-Type": "application/json"},
        )
        with urllib.request.urlopen(request, timeout=10) as response:
            result = json.load(response)
        if "error" in result:
            raise ValueError(f"{method}: {result['error']}")
        return result["result"]

    deadline = time.monotonic() + timeout
    next_block = start_block + 1
    while pending and time.monotonic() < deadline:
        last = int(rpc("eth_blockNumber", []), 16)
        while next_block <= last:
            for receipt in rpc("eth_getBlockReceipts", [hex(next_block)]):
                tx_hash = receipt["transactionHash"].lower()
                if tx_hash in pending:
                    if receipt["status"] != "0x1":
                        raise ValueError(f"Policy payment failed: {tx_hash}")
                    pending.remove(tx_hash)
            next_block += 1
        if pending:
            time.sleep(0.2)
    if pending:
        raise ValueError(f"Policy workload is missing {len(pending)} of {sent} receipts")
    print(f"  tip20-policy receipts: {sent} submitted payments included successfully")


if __name__ == "__main__":
    verify(*sys.argv[1:4], int(sys.argv[4]))
