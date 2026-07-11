"""E4 — identity is a key, not a string (AER §3.1, F1).

The forgery regression: an entry can be validly signed by SOME key whose embedded
public key matches its own fingerprint, yet still not be the session's key. A
verifier that trusted the entry's claimed fingerprint string would bless it. The
gatehouse verifier recomputes the fingerprint from the embedded key and binds it
to the session identity, so the forgery fails.
"""

from __future__ import annotations

from typing import Any

from gatehouse.keys import AgentKey
from gatehouse.merkle import merkle_root
from gatehouse.store import SessionStore
from gatehouse.verify import verify_audit_log


def _unsealed_log(store: SessionStore, session_id: str) -> dict[str, Any]:
    """An AuditLog with a valid chain + agent signatures but NO operator seal, so
    the verdict hinges purely on the agent-signature layer."""
    session = store.close_session(session_id)
    entries = store.entries(session_id)
    return {
        "version": "2.0.0",
        "schema_version": 2,
        "session": session,
        "entries": entries,
        "merkle_root": merkle_root([e["entry_hash"] for e in entries]),
    }


def test_honestly_signed_log_is_consistent_unattributed(store, session_id):
    report = verify_audit_log(_unsealed_log(store, session_id))
    assert report.status == "consistent_unattributed"
    assert report.chain_valid is True
    assert report.agent_signatures_valid is True
    assert report.agent_verified_count == 5
    assert report.org_signature_valid is None


def test_signature_from_a_non_session_key_is_rejected(store, session_id):
    log = _unsealed_log(store, session_id)

    # A DIFFERENT, self-consistent key: it signs the real entry_hash validly and
    # its embedded public_key hashes to its own claimed fingerprint. The only
    # thing wrong is that it is not the session's key.
    forger = AgentKey.generate()
    target = log["entries"][0]
    forged_sig = forger.sign_entry_hash(target["entry_hash"])
    target["agent_signature"] = {
        "fingerprint": forger.fingerprint,  # self-consistent with the embedded key
        "public_key": forger.public_b64,
        "signature": forged_sig,
    }

    report = verify_audit_log(log)
    assert report.status == "failed"
    assert report.agent_signatures_valid is False
    assert report.failing_step is not None
    assert "F1" in report.failing_step or "agent signature" in report.failing_step

    # Sanity: the forged signature is cryptographically VALID on its own key —
    # the rejection is about identity binding, not a broken signature.
    from gatehouse.keys import load_public_key_b64, verify_signature

    assert verify_signature(
        load_public_key_b64(forger.public_b64),
        forged_sig,
        target["entry_hash"].encode("utf-8"),
    )


def test_session_without_fingerprint_but_signed_entries_fails_closed(store, session_id):
    log = _unsealed_log(store, session_id)
    # The session declares no agent identity, yet entries claim signatures.
    # Nothing binds the key -> reject, do not silently accept.
    log["session"].pop("agent_fingerprint", None)

    report = verify_audit_log(log)
    assert report.status == "failed"
    assert report.agent_signatures_valid is False
    assert report.failing_step is not None
