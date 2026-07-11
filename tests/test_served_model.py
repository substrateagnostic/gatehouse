"""E8 — served_model: provider-asserted model on model_call entries.

``served_model`` is the model the PROVIDER said it ran, as distinct from
``model_id`` (what was requested). The two halves that must be kept separate:

- reroute_is_not_tampering: an HONEST record of served != requested verifies
  AUTHENTICATED, with the divergence surfaced in ``served_model_mismatches``. A
  silent stepdown is EVIDENCE, not an integrity fault.
- projection_disagreement_is_tampering: if the evidence record's operations
  projection disagrees with the chained entry on served_model, that IS tampering
  and ``verify_bundle`` fails with a named step.
"""

from __future__ import annotations

import json

from gatehouse import evidence
from gatehouse.verify import verify_bundle


def test_served_model_recorded_and_flagged_in_projection(store, session_id):
    record = evidence.build_evidence_record(store, session_id, mode="full")
    op0 = record["operations"][0]  # the requested!=served model_call
    assert op0["operation"] == "gpt-4o"
    assert op0["served_model"] == "gpt-4o-mini"
    assert op0["model_mismatch"] is True
    # served_model is projected right after operation, before status.
    keys = list(op0.keys())
    assert keys.index("served_model") == keys.index("operation") + 1
    assert keys.index("model_mismatch") == keys.index("served_model") + 1

    op3 = record["operations"][3]  # the faithful (served == requested) model_call
    assert op3["served_model"] == "gpt-4o"
    assert "model_mismatch" not in op3


def test_reroute_is_not_tampering(store, session_id, tmp_path):
    # An honest bundle whose entry 0 records a served!=requested stepdown must
    # verify AUTHENTICATED, and the mismatch must be reported (not fail closed).
    full = tmp_path / "bundle-full"
    evidence.export_bundle(store, session_id, full, mode="full")

    report = verify_bundle(full)
    assert report.status == "authenticated"
    assert report.failing_step is None
    assert report.served_model_mismatches == [
        {"sequence": 0, "model_id": "gpt-4o", "served_model": "gpt-4o-mini"}
    ]


def test_projection_disagreement_is_tampering(store, session_id, tmp_path):
    # Edit the evidence record's projection to hide the stepdown (claim served ==
    # requested) while the chained entry still says gpt-4o-mini. To prove the
    # DEDICATED served_model cross-check fires (not merely the files{} hash), we
    # also re-hash the edited file into the manifest and RE-SEAL the manifest, so
    # the file-hash and seal checks both pass and the served_model step is the one
    # that must reject the bundle.
    from gatehouse.canonical import jcs_bytes, sha256_hex

    full = tmp_path / "bundle-full"
    evidence.export_bundle(store, session_id, full, mode="full")

    record_path = full / "evidence_record.json"
    record = json.loads(record_path.read_text(encoding="utf-8"))
    record["operations"][0]["served_model"] = "gpt-4o"  # lie: hide the reroute
    record["operations"][0].pop("model_mismatch", None)
    new_bytes = json.dumps(record, indent=2, ensure_ascii=False).encode("utf-8")
    record_path.write_bytes(new_bytes)

    manifest_path = full / "hash_manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["files"]["evidence_record.json"] = sha256_hex(new_bytes)
    unsigned = {k: v for k, v in manifest.items() if k != "operator_signature"}
    key = store.operator_key()
    manifest["operator_signature"] = {
        "public_key": key.public_b64,
        "signature": key.sign_b64(jcs_bytes(unsigned)),
        "signed_at": manifest["operator_signature"]["signed_at"],
    }
    manifest_path.write_text(json.dumps(manifest, indent=2, ensure_ascii=False), encoding="utf-8")

    report = verify_bundle(full)
    assert report.status == "failed"
    assert report.failing_step == (
        "served_model mismatch between record and chained entry 0"
    )


def test_served_model_survives_redaction(store, session_id, tmp_path):
    # served_model is not free text; redaction preserves it, so a stepdown stays
    # visible in a derived bundle.
    redacted = tmp_path / "bundle-redacted"
    evidence.export_bundle(store, session_id, redacted, mode="redacted")
    record = json.loads((redacted / "evidence_record.json").read_text(encoding="utf-8"))
    assert record["operations"][0]["served_model"] == "gpt-4o-mini"
    assert record["operations"][0]["model_mismatch"] is True
