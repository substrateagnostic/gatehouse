"""Hash chain, AER v0.1 §4.1.

entry_hash(n) = SHA-256 hex of JCS({sequence, entry, previous_hash,
authorized_by?}) — previous folded in as a member, genesis links to "".
`authorized_by` omitted entirely when absent. See docs/INTEROP.md.
"""

from __future__ import annotations

from typing import Any, Optional

from .canonical import sha256_jcs

__all__ = ["entry_hash", "chained_entry", "verify_chain"]


def entry_hash(
    sequence: int,
    entry: dict[str, Any],
    previous_hash: str,
    authorized_by: Optional[dict[str, Any]] = None,
) -> str:
    preimage: dict[str, Any] = {
        "sequence": sequence,
        "entry": entry,
        "previous_hash": previous_hash,
    }
    if authorized_by is not None:
        preimage["authorized_by"] = authorized_by
    return sha256_jcs(preimage)


def chained_entry(
    sequence: int,
    entry: dict[str, Any],
    previous_hash: str,
    *,
    authorized_by: Optional[dict[str, Any]] = None,
    agent_signature: Optional[dict[str, str]] = None,
    source_entry_hash: Optional[str] = None,
) -> dict[str, Any]:
    """Build a ChainedEntry wrapper (INTEROP key order: sequence, entry,
    previous_hash, entry_hash, source_entry_hash?, authorized_by?,
    agent_signature?)."""
    h = entry_hash(sequence, entry, previous_hash, authorized_by)
    wrapper: dict[str, Any] = {
        "sequence": sequence,
        "entry": entry,
        "previous_hash": previous_hash,
        "entry_hash": h,
    }
    if source_entry_hash is not None:
        wrapper["source_entry_hash"] = source_entry_hash
    if authorized_by is not None:
        wrapper["authorized_by"] = authorized_by
    if agent_signature is not None:
        wrapper["agent_signature"] = agent_signature
    return wrapper


def verify_chain(entries: list[dict[str, Any]]) -> tuple[bool, int, Optional[str]]:
    """Recompute the chain from sequence 0.

    Returns (valid, verified_count, failure_detail). failure_detail names the
    failing entry and reason (F2: a failed report must name the step).
    """
    prev_hash = ""
    for i, wrapper in enumerate(entries):
        if not isinstance(wrapper, dict):
            return False, i, f"entry {i}: not a JSON object"
        seq = wrapper.get("sequence")
        # Strict: a real integer, not a bool and not a float that ==-coerces to
        # the index (Codex QA #5: `sequence: 0.0` / `True` must not verify).
        if not isinstance(seq, int) or isinstance(seq, bool) or seq != i:
            return False, i, f"entry {i}: sequence is {seq!r}, expected integer {i}"
        if wrapper.get("previous_hash") != prev_hash:
            return False, i, f"entry {i}: previous_hash does not match prior entry_hash"
        if "entry" not in wrapper:
            return False, i, f"entry {i}: missing 'entry' member"
        try:
            expected = entry_hash(
                i, wrapper["entry"], prev_hash, wrapper.get("authorized_by")
            )
        except Exception as exc:  # canonicalization failure on hostile input
            return False, i, f"entry {i}: not canonicalizable ({type(exc).__name__})"
        if wrapper.get("entry_hash") != expected:
            return False, i, f"entry {i}: entry_hash does not recompute"
        prev_hash = wrapper.get("entry_hash", "")
    return True, len(entries), None
