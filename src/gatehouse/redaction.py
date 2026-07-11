"""Redaction transforms (aer-0.1-basic), AER §5.

Extracted into a shared module (Codex QA #3) so both the producer
(``evidence.py``) and the verifier (``verify.py::verify_pair``) apply the
identical transformation: the producer to derive the redacted bundle, the
verifier to independently reconstruct the EXPECTED redaction from the original
and require the derived payload to match it exactly — so a redacted bundle that
substitutes arbitrary content (not just [REDACTED] over preserved structure)
is rejected rather than certified "faithful".
"""

from __future__ import annotations

import copy
from typing import Any, Optional

from .chain import chained_entry

REDACTED_VALUE = "[REDACTED]"
REDACTION_RULE = "aer-0.1-basic"


def redact_entry(entry: dict[str, Any]) -> dict[str, Any]:
    """Replace free-text/sensitive values with ``[REDACTED]`` while preserving
    structure, type, names, status, timestamps, and every hash (AER §5(1))."""
    e = copy.deepcopy(entry)
    t = e.get("type")
    if t == "model_call":
        if e.get("error"):
            e["error"]["message"] = REDACTED_VALUE
    elif t == "tool_invocation":
        if e.get("error"):
            e["error"]["message"] = REDACTED_VALUE
        if e.get("resources_accessed"):
            e["resources_accessed"] = [
                {**r, "identifier": REDACTED_VALUE} for r in e["resources_accessed"]
            ]
    elif t == "decision_point":
        e["options_considered"] = [
            {**o, "description": REDACTED_VALUE} for o in e.get("options_considered", [])
        ]
    elif t == "content_reference":
        if e.get("storage_uri"):
            e["storage_uri"] = REDACTED_VALUE
    return e


def redact_intent_contract(contract: dict[str, Any]) -> dict[str, Any]:
    """Redact the free-text fields of an intent contract (AER §5(3))."""
    c = dict(contract)
    c["objective"] = REDACTED_VALUE
    if c.get("jurisdiction"):
        c["jurisdiction"] = REDACTED_VALUE
    if c.get("role"):
        c["role"] = REDACTED_VALUE
    if c.get("revision_policy"):
        c["revision_policy"] = REDACTED_VALUE
    if c.get("constraints"):
        c["constraints"] = [REDACTED_VALUE for _ in c["constraints"]]
    if c.get("facts_provided"):
        c["facts_provided"] = [REDACTED_VALUE for _ in c["facts_provided"]]
    if c.get("success_criteria"):
        c["success_criteria"] = [REDACTED_VALUE for _ in c["success_criteria"]]
    return c


def redact_metadata(metadata: Optional[dict[str, Any]]) -> Optional[dict[str, Any]]:
    if not metadata:
        return metadata
    return {k: (REDACTED_VALUE if isinstance(v, str) else v) for k, v in metadata.items()}


def derive_redacted_entries(entries: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Re-chain redacted entries from sequence 0 (AER §5(2)). The per-entry agent
    signature is dropped; each derived entry carries ``source_entry_hash`` = the
    original entry_hash (F3)."""
    derived: list[dict[str, Any]] = []
    prev = ""
    for chained in entries:
        redacted_entry = redact_entry(chained["entry"])
        wrapper = chained_entry(
            chained["sequence"],
            redacted_entry,
            prev,
            authorized_by=chained.get("authorized_by"),
            source_entry_hash=chained["entry_hash"],
        )
        derived.append(wrapper)
        prev = wrapper["entry_hash"]
    return derived
