"""Run with: uv run --with pycryptodome==3.23.0 python contrib/bench/txgen/test-policy-receipts.py"""

import importlib.util
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("receipts", Path(__file__).with_name("verify-policy-receipts.py"))
receipts = importlib.util.module_from_spec(spec)
spec.loader.exec_module(receipts)


class PolicyReceiptsTest(unittest.TestCase):
    def test_exact_workload_receipts(self):
        # Ethereum Keccak-256 vector, not NIST SHA3-256.
        expected = "0x4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45"
        wanted = {"transactionHash": expected, "status": "0x1"}
        unrelated = {"transactionHash": "0x" + "00" * 32, "status": "0x1"}
        cases = [
            ([wanted, unrelated], 1, False),
            ([unrelated], 1, True),
            ([dict(wanted, status="0x0"), unrelated], 1, True),
            ([wanted, wanted], 2, True),
            ([], 0, True),
        ]
        with tempfile.TemporaryDirectory() as directory:
            transactions = Path(directory) / "transactions.ndjson"
            report = Path(directory) / "report.json"
            transactions.write_text(json.dumps({"phase": "workload", "raw": "0x616263"}) + "\n")
            for block_receipts, sent, fails in cases:
                with self.subTest(receipts=block_receipts, sent=sent):
                    report.write_text(json.dumps({"sent": sent}))

                    def rpc(request, timeout):
                        method = json.loads(request.data)["method"]
                        result = "0x1" if method == "eth_blockNumber" else block_receipts
                        return io.BytesIO(json.dumps({"result": result}).encode())

                    with patch.object(receipts.urllib.request, "urlopen", rpc), patch.object(
                        receipts.time, "monotonic", side_effect=[0, 0, 2]
                    ), patch.object(receipts.time, "sleep"):
                        if fails:
                            with self.assertRaises(ValueError):
                                receipts.verify("http://localhost", transactions, report, 0, timeout=1)
                        else:
                            receipts.verify("http://localhost", transactions, report, 0, timeout=1)


if __name__ == "__main__":
    unittest.main()
