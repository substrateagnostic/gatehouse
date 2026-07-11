"""Domain-separated Merkle root, AER v0.1 §4.2.1 (red-team F9).

- leaf  = SHA-256(0x00 || entry_hash_bytes)   (32 raw bytes of the hex entry hash)
- node  = SHA-256(0x01 || left || right)      (32-byte child hashes)
- an odd node is carried up unchanged (never duplicated — CVE-2012-2459)
- the root of an empty log is the empty string

Verified against the TS reference implementation on a single-leaf log:
evidence/conformance/probe_golden_output.txt line 2.
"""

from __future__ import annotations

import hashlib
from collections.abc import Sequence

LEAF_PREFIX = b"\x00"
NODE_PREFIX = b"\x01"

__all__ = ["merkle_root", "LEAF_PREFIX", "NODE_PREFIX"]


def merkle_root(entry_hashes: Sequence[str]) -> str:
    """Merkle root (lowercase hex) over ordered entry_hash hex strings."""
    if not entry_hashes:
        return ""
    level = [
        hashlib.sha256(LEAF_PREFIX + bytes.fromhex(h)).digest()
        for h in entry_hashes
    ]
    while len(level) > 1:
        nxt = []
        for i in range(0, len(level) - 1, 2):
            nxt.append(
                hashlib.sha256(NODE_PREFIX + level[i] + level[i + 1]).digest()
            )
        if len(level) % 2 == 1:
            nxt.append(level[-1])  # carry up unchanged, no duplication
        level = nxt
    return level[0].hex()
