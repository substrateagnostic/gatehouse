"""E6 — tri-state verdict (AER §4.3, F2).

Each of the three verdicts is provable on real data:
- ``authenticated``   — a freshly built, operator-sealed session;
- ``consistent_unattributed`` — the same session with the seal stripped;
- ``failed`` — a session with one entry tampered, reported with a NAMED step.

Plus a cross-implementation check: the gatehouse verifier calls the TypeScript
reference implementation's demo audit log ``authenticated``.
"""

from __future__ import annotations

import json
from typing import Any

from gatehouse import evidence
from gatehouse.merkle import merkle_root
from gatehouse.store import SessionStore
from gatehouse.verify import verify_audit_log

from conftest import TS_DEMO_AUDIT_LOG


def _sealed_log(store: SessionStore, session_id: str) -> dict[str, Any]:
    session = store.close_session(session_id)
    entries = store.entries(session_id)
    log = {
        "version": "2.0.0",
        "schema_version": 2,
        "session": session,
        "entries": entries,
        "merkle_root": merkle_root([e["entry_hash"] for e in entries]),
    }
    log["org_signature"] = evidence._seal(store, log)
    return log


def test_authenticated_on_a_real_sealed_session(store, session_id):
    report = verify_audit_log(_sealed_log(store, session_id))
    assert report.status == "authenticated"
    assert report.chain_valid is True
    assert report.merkle_valid is True
    assert report.org_signature_valid is True
    assert report.agent_signatures_valid is True
    assert report.failing_step is None


def test_consistent_unattributed_when_seal_stripped(store, session_id):
    log = _sealed_log(store, session_id)
    log.pop("org_signature")
    report = verify_audit_log(log)
    assert report.status == "consistent_unattributed"
    assert report.org_signature_valid is None
    # An unattributed log is never "valid"; only authenticated is.
    assert report.failing_step is None


def test_failed_with_named_step_when_an_entry_is_tampered(store, session_id):
    log = _sealed_log(store, session_id)
    # Edit a payload field after sealing: the chain breaks at that entry.
    log["entries"][2]["entry"]["tool_name"] = "exfiltrate_api"
    report = verify_audit_log(log)
    assert report.status == "failed"
    assert report.chain_valid is False
    assert report.failing_step is not None
    assert "entry 2" in report.failing_step


def test_org_seal_over_wrong_material_fails(store, session_id):
    log = _sealed_log(store, session_id)
    # Flip the merkle_root after sealing: the operator signature no longer covers
    # the material, so the seal fails (and merkle fails too) -> failed.
    log["merkle_root"] = "0" * 64
    report = verify_audit_log(log)
    assert report.status == "failed"
    assert report.failing_step is not None


def test_cross_impl_ts_reference_demo_log_is_authenticated():
    # Ground-truth interop: the gatehouse verifier accepts a log produced by the
    # independent TypeScript reference implementation.
    log = json.loads(TS_DEMO_AUDIT_LOG.read_text(encoding="utf-8"))
    report = verify_audit_log(log)
    assert report.status == "authenticated"
    assert report.chain_valid is True
    assert report.merkle_valid is True
    assert report.org_signature_valid is True
    assert report.agent_signatures_valid is True
    assert report.agent_verified_count == len(log["entries"])
    assert report.contract_hash_valid is True


def test_legacy_v1_log_is_refused_with_explicit_message():
    # gatehouse is v2-only; a v1 / no-schema_version log is not silently accepted.
    log = {"version": "1.0.0", "session": {}, "entries": []}
    report = verify_audit_log(log)
    assert report.status == "failed"
    assert "legacy" in report.failing_step.lower()
