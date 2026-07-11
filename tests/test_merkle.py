"""E3 — domain-separated Merkle root (AER §4.2.1, F9).

Reproduces the reference demo log's ``merkle_root`` byte-for-byte, proves an
internal node cannot be replayed as a leaf (domain separation), checks the
odd-carry rule on a 3-leaf tree, and pins the empty log to "".
"""

from __future__ import annotations

import hashlib
import json

from gatehouse.merkle import LEAF_PREFIX, NODE_PREFIX, merkle_root

from conftest import TS_DEMO_AUDIT_LOG


def _leaf(h: str) -> bytes:
    return hashlib.sha256(LEAF_PREFIX + bytes.fromhex(h)).digest()


def _node(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(NODE_PREFIX + left + right).digest()


def test_merkle_root_matches_ts_reference():
    log = json.loads(TS_DEMO_AUDIT_LOG.read_text(encoding="utf-8"))
    hashes = [e["entry_hash"] for e in log["entries"]]
    assert merkle_root(hashes) == log["merkle_root"]
    assert merkle_root(hashes) == (
        "a9bbff8d030b54109a855eb8b32a50089bf825902f8be1ada29f4100571ef71f"
    )


def test_empty_log_root_is_empty_string():
    assert merkle_root([]) == ""


def test_single_leaf_root_equals_the_leaf():
    h = "a" * 64
    assert merkle_root([h]) == _leaf(h).hex()


def test_domain_separation_internal_node_cannot_be_replayed_as_leaf():
    # Two leaves -> root is NODE(leaf0, leaf1). If an attacker presents the raw
    # concatenation-hash of the two entry hashes as a single leaf, the domain
    # prefixes (0x00 leaf vs 0x01 node) guarantee it will NOT reproduce the root.
    a, b = "11" * 32, "22" * 32
    root = merkle_root([a, b])
    assert root == _node(_leaf(a), _leaf(b)).hex()

    # A forged "leaf" whose value is the internal node digest must not collide.
    internal = _node(_leaf(a), _leaf(b)).hex()
    assert merkle_root([internal]) != root
    # And a leaf hashed WITHOUT domain separation must differ from the real leaf.
    naive_leaf = hashlib.sha256(bytes.fromhex(a)).digest()
    assert naive_leaf != _leaf(a)


def test_odd_carry_three_leaves_carried_up_unchanged():
    a, b, c = "aa" * 32, "bb" * 32, "cc" * 32
    # Level 1: node(a,b) and c carried up unchanged (NOT duplicated).
    n_ab = _node(_leaf(a), _leaf(b))
    carried = _leaf(c)
    expected = _node(n_ab, carried).hex()
    assert merkle_root([a, b, c]) == expected

    # Prove the anti-CVE-2012-2459 property: duplicating the last leaf (the old
    # padding scheme) yields a DIFFERENT root, so the two are not confusable.
    n_cc = _node(_leaf(c), _leaf(c))
    duplicated = _node(n_ab, n_cc).hex()
    assert merkle_root([a, b, c]) != duplicated
