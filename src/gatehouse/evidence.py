"""Evidence record assembly and bundle export (AER v0.1 §3/§4/§5).

Builds the six-key evidence record and the dual (full + redacted) bundles with a
binding manifest, on the frozen gatehouse seam. Constructions are pinned to
docs/INTEROP.md and cross-checked against the AgentLedger v2 reference
(``packages/core/src/storage.ts``). The integrity attestation embedded in every
record is the result of a REAL verification pass (see ``verify.py``), never an
asserted ``true``.

gatehouse additions over the reference:
- ``served_model`` is projected into the operations list (after ``operation``)
  with a ``model_mismatch`` flag when the provider served a model other than the
  one requested (silent stepdown evidence).
- bundles additionally ship ``audit_log.json`` (the AuditLog shape the reference
  CLI verifies) so a gatehouse session verifies directly under the TS verifier.
- manifests are operator-sealed by default (the reference CLI leaves them
  unsigned — feedback #2).
"""

from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any, Optional

from .canonical import jcs_bytes, sha256_hex
from .merkle import merkle_root as compute_merkle_root
from .models import now_rfc3339
from .redaction import (
    REDACTED_VALUE,
    REDACTION_RULE,
    derive_redacted_entries as _derive_redacted_entries,
    redact_intent_contract as _redact_intent_contract,
    redact_metadata as _redact_metadata,
)
from .store import SessionStore
from .verify import _attestation_block, org_signature_block

__all__ = [
    "build_evidence_record",
    "export_bundle",
    "REDACTED_VALUE",
    "REDACTION_RULE",
    "AER_VERSION",
]

AER_VERSION = "0.1"


# ---------------------------------------------------------------------------
# Redaction (aer-0.1-basic) — transforms live in redaction.py, shared with the
# verifier so verify_pair reconstructs the same expected redaction (Codex #3).
# ---------------------------------------------------------------------------

def _redact_session(session: dict[str, Any]) -> dict[str, Any]:
    s = dict(session)
    if s.get("metadata") is not None:
        s["metadata"] = _redact_metadata(s["metadata"])
    if s.get("intent_contract"):
        s["intent_contract"] = _redact_intent_contract(s["intent_contract"])
        # contract_hash is intentionally retained (the ORIGINAL linkage value);
        # the record surfaces it as contract_hash_original in redacted mode (F5).
    return s


# ---------------------------------------------------------------------------
# AuditLog assembly + operator seal
# ---------------------------------------------------------------------------

def _seal(store: SessionStore, log: dict[str, Any]) -> dict[str, Any]:
    key = store.operator_key()
    signature = key.sign_b64(jcs_bytes(org_signature_block(log)))
    return {
        "public_key": key.public_b64,
        "signature": signature,
        "signed_at": now_rfc3339(),
    }


def _session_seal(store: SessionStore, session: dict[str, Any]) -> dict[str, Any]:
    """gatehouse-native seal over the WHOLE session envelope (Opus V1/V2, Codex
    #6). The reference §4.2 operator seal binds only {entry set + a few
    scalars}, leaving intent_contract, human_authorizer, org_id, etc. unsigned —
    so a standalone log could be re-scoped post-seal. This additional operator
    signature covers ``sha256_jcs`` of the entire session, closing that gap for
    gatehouse's produce+verify path. It is an EXTRA top-level field the
    reference verifier ignores, so byte-for-byte interop (C1) is preserved."""
    key = store.operator_key()
    return {
        "public_key": key.public_b64,
        "signature": key.sign_b64(jcs_bytes(session)),
        "signed_at": now_rfc3339(),
        "covers": "session",
    }


def _assemble_log(
    store: SessionStore,
    session: dict[str, Any],
    entries: list[dict[str, Any]],
    *,
    redacted: bool,
    sign: bool,
) -> dict[str, Any]:
    if redacted:
        derived = _derive_redacted_entries(entries)
        rsession = _redact_session(session)
        log: dict[str, Any] = {
            "version": "2.0.0",
            "schema_version": 2,
            "session": rsession,
            "entries": derived,
            "merkle_root": compute_merkle_root([e["entry_hash"] for e in derived]),
        }
        # A derived record is NOT operator-sealed as a log; the binding manifest
        # carries the operator seal instead (feedback #13).
        return log

    log = {
        "version": "2.0.0",
        "schema_version": 2,
        "session": session,
        "entries": entries,
        "merkle_root": compute_merkle_root([e["entry_hash"] for e in entries]),
    }
    if sign:
        log["org_signature"] = _seal(store, log)
        log["session_seal"] = _session_seal(store, log["session"])
    return log


# ---------------------------------------------------------------------------
# Evidence record projection (AER §3, six keys)
# ---------------------------------------------------------------------------

def _agent_identity(session: dict[str, Any]) -> dict[str, Any]:
    ident: dict[str, Any] = {"agent_id": session.get("agent_id")}
    if session.get("agent_version") is not None:
        ident["agent_version"] = session["agent_version"]
    ident["public_key"] = session.get("agent_public_key")
    ident["fingerprint"] = session.get("agent_fingerprint")
    if session.get("signature_scheme") is not None:
        ident["signature_scheme"] = session["signature_scheme"]
    return ident


def _human_authorizer(
    session: dict[str, Any], entries: list[dict[str, Any]]
) -> dict[str, Any]:
    operation_authorizations = [
        {"sequence": e["sequence"], "entry_id": e["entry"].get("entry_id"), **e["authorized_by"]}
        for e in entries
        if e.get("authorized_by")
    ]
    approvals = [
        {
            "entry_id": e["entry"].get("entry_id"),
            "timestamp": e["entry"].get("timestamp"),
            "approver_id": e["entry"].get("approver_id"),
            "approver_role": e["entry"].get("approver_role"),
            "decision_ref": e["entry"].get("decision_ref"),
            "approval_type": e["entry"].get("approval_type"),
        }
        for e in entries
        if e["entry"].get("type") == "human_approval"
    ]
    return {
        "session_authorizer": session.get("human_authorizer") or None,
        "operation_authorizations": operation_authorizations,
        "approvals": approvals,
    }


def _operations(entries: list[dict[str, Any]]) -> list[dict[str, Any]]:
    ops: list[dict[str, Any]] = []
    for e in entries:
        entry = e["entry"]
        t = entry["type"]
        operation: Any = None
        status: Any = None
        if t == "model_call":
            operation = entry.get("model_id")
            status = "error" if entry.get("error") else "ok"
        elif t == "tool_invocation":
            operation = entry.get("tool_name")
            status = "ok" if entry.get("success") else "error"
        elif t == "decision_point":
            operation = entry.get("decision_id")
            status = "pending_review" if entry.get("human_review_required") else "ok"
        elif t == "human_approval":
            operation = entry.get("decision_ref")
            status = entry.get("approval_type")
        elif t == "state_snapshot":
            operation = entry.get("trigger")
            status = "ok"
        elif t == "content_reference":
            operation = entry.get("content_type")
            status = "ok"

        proj: dict[str, Any] = {
            "sequence": e["sequence"],
            "timestamp": entry.get("timestamp"),
            "type": t,
            "operation": operation,
        }
        # gatehouse addition: served_model after operation; model_mismatch flag
        # when the provider served a different model than requested.
        if t == "model_call" and entry.get("served_model") is not None:
            proj["served_model"] = entry["served_model"]
            if entry["served_model"] != entry.get("model_id"):
                proj["model_mismatch"] = True
        proj["status"] = status
        proj["entry_hash"] = e["entry_hash"]
        if e.get("agent_signature"):
            proj["agent_signature"] = e["agent_signature"]
        ops.append(proj)
    return ops


def _data_accessed(entries: list[dict[str, Any]]) -> dict[str, Any]:
    resource_keys: set[str] = set()
    resources: list[dict[str, Any]] = []
    for e in entries:
        entry = e["entry"]
        if entry.get("type") == "tool_invocation" and entry.get("resources_accessed"):
            for r in entry["resources_accessed"]:
                key = f"{r.get('type')}|{r.get('identifier')}|{r.get('operation')}"
                if key not in resource_keys:
                    resource_keys.add(key)
                    resources.append(
                        {
                            "type": r.get("type"),
                            "identifier": r.get("identifier"),
                            "operation": r.get("operation"),
                        }
                    )
    pii_references = [
        {
            "entry_id": e["entry"].get("entry_id"),
            "content_type": e["entry"].get("content_type"),
            "contains_pii": e["entry"].get("contains_pii"),
            "pii_types": e["entry"].get("pii_types") or [],
        }
        for e in entries
        if e["entry"].get("type") == "content_reference" and e["entry"].get("contains_pii")
    ]
    return {"resources": resources, "pii_references": pii_references}


def _policy_context(
    session: dict[str, Any], log: dict[str, Any], *, redacted: bool
) -> dict[str, Any]:
    pc: dict[str, Any] = {
        "session_id": session.get("session_id"),
        "org_id": session.get("org_id"),
        "environment": session.get("environment"),
        "initiated_at": session.get("initiated_at"),
    }
    if session.get("closed_at") is not None:
        pc["closed_at"] = session["closed_at"]
    if session.get("compliance_contexts") is not None:
        pc["compliance_contexts"] = session["compliance_contexts"]
    pc["policy_context"] = session.get("policy_context") or []
    pc["intent_contract"] = session.get("intent_contract") if session.get("intent_contract") is not None else None
    if redacted:
        pc["contract_hash"] = None
        pc["contract_hash_original"] = session.get("contract_hash")
    else:
        pc["contract_hash"] = session.get("contract_hash")
    pc["retention_days"] = session.get("retention_days")
    pc["integrity_attestation"] = _attestation_block(log, now_rfc3339())
    return pc


def _project_record(log: dict[str, Any], *, redacted: bool) -> dict[str, Any]:
    session = log["session"]
    entries = log["entries"]
    return {
        "aer_version": AER_VERSION,
        "agent_identity": _agent_identity(session),
        "human_authorizer": _human_authorizer(session, entries),
        "operations": _operations(entries),
        "data_accessed": _data_accessed(entries),
        "policy_context": _policy_context(session, log, redacted=redacted),
    }


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def build_evidence_record(
    store: SessionStore, session_id: str, *, mode: str = "full"
) -> dict:
    """Assemble the six-key AER evidence record for *session_id* (AER §3/§4).

    ``mode="full"`` seals the assembled log with the operator key and returns an
    authenticated record. ``mode="redacted"`` derives a redacted, re-chained,
    unattributed record (no agent signatures, no operator seal). In both modes
    the embedded integrity attestation reflects a real verification pass. The
    session is closed (``closed_at``) before sealing if it is not already.
    """
    session = store.close_session(session_id)
    entries = store.entries(session_id)
    redacted = mode == "redacted"
    log = _assemble_log(store, session, entries, redacted=redacted, sign=not redacted)
    return _project_record(log, redacted=redacted)


def _json_pretty(obj: Any) -> bytes:
    return json.dumps(obj, indent=2, ensure_ascii=False).encode("utf-8")


def _ndjson_bytes(entries: list[dict[str, Any]]) -> bytes:
    if not entries:
        return b""
    lines = [json.dumps(e, separators=(",", ":"), ensure_ascii=False) for e in entries]
    return ("\n".join(lines) + "\n").encode("utf-8")


def _audit_log_file(log: dict[str, Any]) -> dict[str, Any]:
    """The AuditLog shape the reference CLI verifies (INTEROP "Conformance
    harness"). org_signature present only for the operational (sealed) log."""
    out: dict[str, Any] = {
        "version": "2.0.0",
        "schema_version": 2,
        "session": log["session"],
        "entries": log["entries"],
        "merkle_root": log["merkle_root"],
    }
    if log.get("org_signature") is not None:
        out["org_signature"] = log["org_signature"]
    if log.get("session_seal") is not None:
        out["session_seal"] = log["session_seal"]
    return out


def export_bundle(
    store: SessionStore,
    session_id: str,
    out_dir: Path,
    *,
    mode: str = "full",
    sign: bool = True,
) -> dict[str, str]:
    """Write a bundle to *out_dir* and return ``{filename: sha256-of-bytes}``.

    Files written: ``evidence_record.json`` (pretty), ``entries.ndjson``
    (compact, trailing newline when non-empty), ``intent_contract.json`` (when a
    contract is present), ``audit_log.json`` (AuditLog shape), and
    ``hash_manifest.json`` LAST. The manifest's ``files{}`` map holds the SHA-256
    of the exact written bytes of every other file (excluding itself); with
    ``sign=True`` (default) the manifest is operator-sealed over the JCS of the
    manifest minus ``operator_signature``.
    """
    out_path = Path(out_dir)
    out_path.mkdir(parents=True, exist_ok=True)

    session = store.close_session(session_id)
    entries = store.entries(session_id)
    redacted = mode == "redacted"

    # A redacted bundle's audit_log carries NO operator seal; a full one does.
    log = _assemble_log(store, session, entries, redacted=redacted, sign=not redacted)
    record = _project_record(log, redacted=redacted)
    bundle_entries = log["entries"]
    intent_contract = log["session"].get("intent_contract")

    # Serialize the payload files (order fixes files{} insertion order).
    file_bytes: dict[str, bytes] = {}
    file_bytes["evidence_record.json"] = _json_pretty(record)
    file_bytes["entries.ndjson"] = _ndjson_bytes(bundle_entries)
    if intent_contract is not None:
        file_bytes["intent_contract.json"] = _json_pretty(intent_contract)
    file_bytes["audit_log.json"] = _json_pretty(_audit_log_file(log))

    # Write payload files and record the SHA-256 of their exact bytes.
    files_map: dict[str, str] = {}
    for name, data in file_bytes.items():
        (out_path / name).write_bytes(data)
        files_map[name] = sha256_hex(data)

    source_hashes = [e["entry_hash"] for e in entries]
    manifest: dict[str, Any] = {
        "hash_alg": "sha256",
        "bundle_kind": "derived_redacted" if redacted else "operational",
        "source_entry_count": len(entries),
        "source_last_entry_hash": entries[-1]["entry_hash"] if entries else "",
        "derived_last_entry_hash": bundle_entries[-1]["entry_hash"] if bundle_entries else "",
        "source_entry_hashes": source_hashes,
        "files": files_map,
        "contract_hash": session.get("contract_hash"),
        "redaction_rule": REDACTION_RULE,
    }
    if sign:
        key = store.operator_key()
        manifest["operator_signature"] = {
            "public_key": key.public_b64,
            "signature": key.sign_b64(jcs_bytes(manifest)),
            "signed_at": now_rfc3339(),
        }

    manifest_bytes = _json_pretty(manifest)
    (out_path / "hash_manifest.json").write_bytes(manifest_bytes)

    result = dict(files_map)
    result["hash_manifest.json"] = sha256_hex(manifest_bytes)
    return result
