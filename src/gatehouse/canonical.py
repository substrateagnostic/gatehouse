"""RFC 8785 (JCS) canonicalization and hashing.

AER v0.1 §3: all hashing and signing operates over JSON canonicalized per
RFC 8785. Sorted-key stringify is NOT JCS (number serialization differs).
This module wraps the Trail of Bits `rfc8785` implementation, which also
rejects lone surrogates (red-team requirement F8) — verified empirically in
evidence/conformance/probe_golden_output.txt.
"""

from __future__ import annotations

import hashlib
from typing import Any

import rfc8785
from rfc8785 import CanonicalizationError

__all__ = ["CanonicalizationError", "jcs_bytes", "sha256_hex", "sha256_jcs"]


def jcs_bytes(obj: Any) -> bytes:
    """Canonical RFC 8785 bytes for *obj*.

    Raises CanonicalizationError on non-serializable input, including
    strings containing lone surrogates (F8: reject, never mangle).
    """
    return rfc8785.dumps(obj)


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_jcs(obj: Any) -> str:
    """Lowercase-hex SHA-256 of the JCS form of *obj* (spec §4.1, §4.2)."""
    return sha256_hex(jcs_bytes(obj))
