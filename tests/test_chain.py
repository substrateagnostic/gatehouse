"""E2 — hash chain (AER §4.1) against a TypeScript-produced golden vector.

Recomputes EVERY ``entry_hash`` in the reference demo audit log from
``{sequence, entry, previous_hash, authorized_by?}`` and requires a byte-for-byte
match. This is the cross-implementation proof that gatehouse's chain construction
is identical to the reference's.
"""

from __future__ import annotations

import json

from gatehouse.chain import chained_entry, entry_hash, verify_chain

from conftest import TS_DEMO_AUDIT_LOG


def _demo():
    return json.loads(TS_DEMO_AUDIT_LOG.read_text(encoding="utf-8"))


def test_genesis_entry_hash_matches_ts_reference():
    log = _demo()
    e0 = log["entries"][0]
    # Genesis links to "" and reproduces the exact TS entry_hash.
    assert e0["previous_hash"] == ""
    recomputed = entry_hash(0, e0["entry"], "")
    assert recomputed == e0["entry_hash"]
    assert recomputed == "a23f00acff027055990f2a9d993f3b83aaff3ce0522c72be54673a7e75bfc1a5"


def test_every_entry_hash_recomputes_byte_for_byte():
    log = _demo()
    prev = ""
    for i, chained in enumerate(log["entries"]):
        assert chained["sequence"] == i
        assert chained["previous_hash"] == prev
        recomputed = entry_hash(
            i, chained["entry"], prev, chained.get("authorized_by")
        )
        assert recomputed == chained["entry_hash"], f"entry {i} diverged"
        prev = chained["entry_hash"]


def test_verify_chain_accepts_the_reference_log():
    log = _demo()
    valid, count, detail = verify_chain(log["entries"])
    assert valid is True
    assert count == len(log["entries"])
    assert detail is None


def test_authorized_by_presence_changes_the_hash():
    # An operation-scoped authorization override is FOLDED IN as a member, so its
    # presence/absence must change the entry hash (and an injected/stripped
    # override must break verification).
    entry = {"type": "state_snapshot", "entry_id": "x", "timestamp": "t", "trigger": "manual"}
    without = entry_hash(0, entry, "")
    authorized_by = {"identifier": "cco@example", "role": "CCO"}
    with_override = entry_hash(0, entry, "", authorized_by)
    assert without != with_override

    # A chained entry that carries the override hashes as the 4-member object;
    # verify_chain recomputes with the override folded in.
    w = chained_entry(0, entry, "", authorized_by=authorized_by)
    assert w["entry_hash"] == with_override
    valid, _, _ = verify_chain([w])
    assert valid is True

    # Stripping the override from the wrapper (but keeping its hash) breaks it.
    tampered = dict(w)
    tampered.pop("authorized_by")
    valid, _, detail = verify_chain([tampered])
    assert valid is False
    assert detail is not None


def test_no_override_entry_hashes_as_three_member_object():
    entry = {"type": "state_snapshot", "entry_id": "x", "timestamp": "t", "trigger": "manual"}
    # entry_hash with authorized_by=None must equal the plain 3-member hash.
    assert entry_hash(0, entry, "", None) == entry_hash(0, entry, "")
