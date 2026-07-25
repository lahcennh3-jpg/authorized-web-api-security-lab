import copy
import json
import unittest
from datetime import datetime, timezone
from pathlib import Path

from scripts.authorization_gate import validate_authorization, validate_schema

ROOT = Path(__file__).resolve().parents[1]
EXAMPLE = ROOT / "scope" / "authorization.example.json"
NOW = datetime(2026, 7, 25, 12, 0, tzinfo=timezone.utc)


def load_example():
    with EXAMPLE.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def complete_record():
    record = load_example()
    record["status"] = "AUTHORIZED"
    record["target"].update(
        {
            "target_id": "juice-shop-private-lab-001",
            "version": "20.1.1",
            "source_ref": "v20.1.1",
            "artifact_reference": "locally-verified-artifact",
            "artifact_sha256": "a" * 64,
            "environment_id": "private-lab-001",
            "private_base_url": "http://127.0.0.1:3000",
            "authorized_interfaces": ["loopback:3000"],
        }
    )
    record["authorization"].update(
        {
            "target_owner": "laboratory owner",
            "authorized_by": "laboratory owner",
            "authority_basis": "self-owned isolated laboratory",
            "evidence_reference": "private-record-reference-001",
            "start_utc": "2026-07-25T00:00:00Z",
            "end_utc": "2026-07-26T00:00:00Z",
            "permitted_techniques": ["manual HTTP inspection"],
            "approved_tools": ["browser developer tools"],
        }
    )
    for field in record["attestations"]:
        record["attestations"][field] = True
    return record


class AuthorizationGateTests(unittest.TestCase):
    def test_public_example_has_valid_schema(self):
        self.assertEqual(validate_schema(load_example()), [])

    def test_public_example_fails_closed(self):
        errors = validate_authorization(load_example(), now=NOW)
        self.assertIn("status is not AUTHORIZED", errors)
        self.assertTrue(any("incomplete" in error for error in errors))

    def test_complete_active_record_is_accepted(self):
        self.assertEqual(validate_authorization(complete_record(), now=NOW), [])

    def test_public_demo_is_rejected(self):
        record = complete_record()
        record["target"]["private_base_url"] = "https://demo.owasp-juice.shop"
        errors = validate_authorization(record, now=NOW)
        self.assertIn(
            "target.private_base_url points to a prohibited public demo", errors
        )

    def test_expired_window_is_rejected(self):
        record = complete_record()
        record["authorization"]["end_utc"] = "2026-07-25T01:00:00Z"
        errors = validate_authorization(record, now=NOW)
        self.assertIn("authorization window is not currently active", errors)

    def test_weakened_safeguard_is_rejected(self):
        record = copy.deepcopy(complete_record())
        record["safeguards"]["private_ports_only"] = False
        errors = validate_authorization(record, now=NOW)
        self.assertIn("safeguards.private_ports_only must be true", errors)


if __name__ == "__main__":
    unittest.main()
