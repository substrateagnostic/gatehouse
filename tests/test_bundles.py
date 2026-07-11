"""E9 — dual bundles with a binding manifest (AER §5, F3).

Full + redacted export, round-trip verification, and the tamper cases the
binding is meant to catch: a dropped / reordered / substituted derived entry
fails ``verify_pair``; a tampered ``evidence_record.json`` fails ``verify_bundle``
through the manifest ``files{}`` hash (which the reference pair check ignores —
aer-feedback #4); a broken manifest seal fails ``verify_bundle``.
"""

from __future__ import annotations

import json

from gatehouse import evidence
from gatehouse.verify import verify_bundle, verify_pair


def _export_pair(store, session_id, tmp_path):
    full = tmp_path / "bundle-full"
    redacted = tmp_path / "bundle-redacted"
    evidence.export_bundle(store, session_id, full, mode="full")
    evidence.export_bundle(store, session_id, redacted, mode="redacted")
    return full, redacted


def test_full_bundle_round_trips_authenticated(store, session_id, tmp_path):
    full, _ = _export_pair(store, session_id, tmp_path)
    for name in ("evidence_record.json", "entries.ndjson", "intent_contract.json",
                 "audit_log.json", "hash_manifest.json"):
        assert (full / name).exists(), name
    report = verify_bundle(full)
    assert report.status == "authenticated"
    assert report.failing_step is None


def test_redacted_bundle_is_consistent_unattributed(store, session_id, tmp_path):
    _, redacted = _export_pair(store, session_id, tmp_path)
    report = verify_bundle(redacted)
    assert report.status == "consistent_unattributed"

    # The redacted evidence record surfaces the free-text redactions and the F5
    # contract linkage.
    record = json.loads((redacted / "evidence_record.json").read_text(encoding="utf-8"))
    pc = record["policy_context"]
    assert pc["contract_hash"] is None
    assert pc["contract_hash_original"] is not None
    assert pc["intent_contract"]["objective"] == "[REDACTED]"
    assert all(c == "[REDACTED]" for c in pc["intent_contract"]["constraints"])
    # A redacted resource identifier is stripped but its type/operation survive.
    res = record["data_accessed"]["resources"][0]
    assert res["identifier"] == "[REDACTED]"
    assert res["type"] == "api" and res["operation"] == "read"
    # No agent signatures in a derived record.
    assert all("agent_signature" not in op for op in record["operations"])


def test_verify_pair_accepts_the_faithful_pair(store, session_id, tmp_path):
    full, redacted = _export_pair(store, session_id, tmp_path)
    report = verify_pair(redacted, full / "audit_log.json")
    assert report.status == "consistent_unattributed"
    assert report.chain_valid is True
    assert report.failing_step is None


def test_manifest_is_operator_sealed_and_verifies(store, session_id, tmp_path):
    full, _ = _export_pair(store, session_id, tmp_path)
    manifest = json.loads((full / "hash_manifest.json").read_text(encoding="utf-8"))
    assert "operator_signature" in manifest  # gatehouse seals by default
    # Tampering the seal makes verify_bundle fail with a named step.
    manifest["operator_signature"]["signature"] = "A" * 88
    (full / "hash_manifest.json").write_text(
        json.dumps(manifest, indent=2, ensure_ascii=False), encoding="utf-8"
    )
    report = verify_bundle(full)
    assert report.status == "failed"
    assert "operator_signature" in report.failing_step


def test_tampered_evidence_record_fails_via_files_hash(store, session_id, tmp_path):
    full, _ = _export_pair(store, session_id, tmp_path)
    record_path = full / "evidence_record.json"
    record = json.loads(record_path.read_text(encoding="utf-8"))
    # Alter a byte of the record without updating the manifest.
    record["policy_context"]["org_id"] = "totally-different-org"
    record_path.write_text(json.dumps(record, indent=2, ensure_ascii=False), encoding="utf-8")

    report = verify_bundle(full)
    assert report.status == "failed"
    assert "evidence_record.json" in report.failing_step
    assert "hash mismatch" in report.failing_step


def test_verify_pair_fails_when_a_derived_entry_is_dropped(store, session_id, tmp_path):
    full, redacted = _export_pair(store, session_id, tmp_path)
    entries_path = redacted / "entries.ndjson"
    lines = entries_path.read_text(encoding="utf-8").splitlines()
    entries_path.write_text("\n".join(lines[:-1]) + "\n", encoding="utf-8")  # drop last

    report = verify_pair(redacted, full / "audit_log.json")
    assert report.status == "failed"
    assert report.failing_step is not None


def test_verify_pair_fails_when_derived_entries_reordered(store, session_id, tmp_path):
    full, redacted = _export_pair(store, session_id, tmp_path)
    entries_path = redacted / "entries.ndjson"
    lines = entries_path.read_text(encoding="utf-8").splitlines()
    lines[1], lines[2] = lines[2], lines[1]  # swap two entries
    entries_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    report = verify_pair(redacted, full / "audit_log.json")
    assert report.status == "failed"
    assert report.failing_step is not None


def test_verify_pair_fails_when_a_derived_entry_is_substituted(store, session_id, tmp_path):
    full, redacted = _export_pair(store, session_id, tmp_path)
    entries_path = redacted / "entries.ndjson"
    lines = [json.loads(l) for l in entries_path.read_text(encoding="utf-8").splitlines()]
    # Substitute entry 1's source binding so it no longer matches source-1.
    lines[1]["source_entry_hash"] = "f" * 64
    entries_path.write_text(
        "\n".join(json.dumps(e, separators=(",", ":")) for e in lines) + "\n",
        encoding="utf-8",
    )
    report = verify_pair(redacted, full / "audit_log.json")
    assert report.status == "failed"
    assert report.failing_step is not None
