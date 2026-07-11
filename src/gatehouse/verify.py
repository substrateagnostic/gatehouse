"""Offline verification of AER v0.1 audit logs and evidence bundles.

This module re-implements the reference verifier's construction (AgentLedger v2,
``packages/core/src/crypto.ts::verifyAuditLog`` / ``verifyAgentSignatures`` and
``storage.ts::verifyRedactionBinding``) on the frozen gatehouse seam
(``canonical``, ``chain``, ``merkle``, ``keys``). It reports a tri-state verdict
(AER §4.3, red-team F2), never a bare boolean, and always names the failing step
when it fails.

Ground truth is the reference implementation (docs/INTEROP.md); where gatehouse
is deliberately STRICTER than the reference the divergence is documented in
docs/aer-feedback.md and surfaced in ``failing_step``:

- Merkle: the reference passes ``merkle_valid`` when ``merkle_root`` is absent on
  a populated log; gatehouse requires the root when entries exist (feedback #5).
- Legacy: v1 / sorted-key-stringify logs are out of scope; gatehouse is v2-only
  and fails them with an explicit message (feedback #10).
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

from .canonical import jcs_bytes, sha256_hex, sha256_jcs
from .chain import verify_chain
from .keys import fingerprint_of, load_public_key_b64, verify_signature
from .merkle import merkle_root as compute_merkle_root

__all__ = [
    "VerificationReport",
    "verify_audit_log",
    "verify_bundle",
    "verify_pair",
    "org_signature_block",
]

REDACTED_VALUE = "[REDACTED]"

LEGACY_STEP = (
    "legacy (v1) canonicalization not supported; use the reference verifier"
)


@dataclass
class VerificationReport:
    """Tri-state verdict for a log/bundle/pair verification (AER §4.3, F2).

    ``status`` is one of ``authenticated`` | ``consistent_unattributed`` |
    ``failed``. Only ``authenticated`` may be described as valid. ``failing_step``
    is REQUIRED (non-None) whenever ``status == "failed"``.
    """

    status: str
    chain_valid: bool
    chain_verified_count: int
    merkle_valid: bool
    org_signature_valid: Optional[bool]
    agent_signatures_valid: Optional[bool]
    agent_verified_count: int
    contract_hash_valid: Optional[bool]
    failing_step: Optional[str]
    served_model_mismatches: list[dict] = field(default_factory=list)
    # None when the session declares no agent identity; True when every entry
    # carries a verified agent signature; False when identity is declared but
    # some entries are unsigned (a signature-stripping / de-attribution signal —
    # Opus review V3). Does not by itself change ``status`` on a standalone log
    # (mixed attribution is valid under the reference), but ``verify_bundle``
    # fails an otherwise-authenticated gatehouse bundle that is not fully
    # attributed, and the CLI always surfaces it.
    fully_attributed: Optional[bool] = None
    # gatehouse-native full-envelope seal (Opus V1/V2, Codex #6). None when the
    # log carries no ``session_seal`` (e.g. a foreign reference log); True when a
    # present seal covers the session and verifies; False when present-but-broken
    # (a rewritten intent_contract / human_authorizer / org_id — hard failure).
    envelope_valid: Optional[bool] = None


# ---------------------------------------------------------------------------
# Construction helpers (shared with evidence.py)
# ---------------------------------------------------------------------------

def org_signature_block(log: dict[str, Any]) -> dict[str, Any]:
    """The exact object the operator seal is computed over (AER §4.2, F6).

    Members: ``session_id, merkle_root, entry_count, closed_at, schema_version,
    agent_fingerprint, canonicalization`` with the *signed* canonicalization
    value ``"RFC8785"`` (INTEROP "Operator seal"). Mirrors the reference's
    JS undefined-omission: a member whose value is ``None`` is dropped entirely,
    so ``agent_fingerprint`` is absent for a session with no agent identity.
    Key order is irrelevant — JCS re-sorts by UTF-16 code unit.
    """
    session = log.get("session", {})
    block = {
        "session_id": session.get("session_id"),
        "merkle_root": log.get("merkle_root"),
        "entry_count": len(log.get("entries", [])),
        "closed_at": session.get("closed_at"),
        "schema_version": log.get("schema_version"),
        "agent_fingerprint": session.get("agent_fingerprint"),
        "canonicalization": "RFC8785",
    }
    return {k: v for k, v in block.items() if v is not None}


def _is_v2(log: dict[str, Any]) -> bool:
    sv = log.get("schema_version")
    if sv is not None:
        return sv == 2
    # Fall back to the string version stamp (reference resolveCanonicalization).
    return log.get("version") == "2.0.0"


def _served_model_mismatches(entries: list[dict[str, Any]]) -> list[dict]:
    """Recorded requested!=served stepdowns. This is EVIDENCE, not tampering:
    a reroute is a fact the record faithfully carries, not an integrity fault.
    """
    out: list[dict] = []
    for chained in entries:
        if not isinstance(chained, dict):
            continue
        entry = chained.get("entry", {})
        if not isinstance(entry, dict) or entry.get("type") != "model_call":
            continue
        served = entry.get("served_model")
        if served is not None and served != entry.get("model_id"):
            out.append(
                {
                    "sequence": chained.get("sequence"),
                    "model_id": entry.get("model_id"),
                    "served_model": served,
                }
            )
    return out


def _verify_org_signature(log: dict[str, Any]) -> Optional[bool]:
    org = log.get("org_signature")
    if not isinstance(org, dict) or not org:
        return None
    try:
        pub = load_public_key_b64(org.get("public_key"))
    except Exception:
        return False
    return verify_signature(pub, org.get("signature"), jcs_bytes(org_signature_block(log)))


def _verify_session_seal(log: dict[str, Any]) -> Optional[bool]:
    """Verify the gatehouse-native envelope seal over ``sha256_jcs(session)``.
    None when absent (foreign/reference log); True/False when present. When an
    operator ``org_signature`` is also present, the envelope seal MUST be by the
    same operator key (else it is a foreign seal spliced in) — a key mismatch is
    a hard False."""
    seal = log.get("session_seal")
    if not isinstance(seal, dict) or not seal:
        return None
    session = log.get("session")
    if not isinstance(session, dict):
        return False
    org = log.get("org_signature")
    if isinstance(org, dict) and org.get("public_key") and seal.get("public_key") != org.get("public_key"):
        return False
    try:
        pub = load_public_key_b64(seal.get("public_key"))
    except Exception:
        return False
    return verify_signature(pub, seal.get("signature"), jcs_bytes(session))


def _verify_agent_signatures(
    log: dict[str, Any],
) -> tuple[bool, Optional[bool], int]:
    """F1-strict per-entry agent signature verification (INTEROP "Agent
    signature"). Returns (present, valid, verified_count).

    Fail closed when the session declares no agent fingerprint but an entry
    claims a signature. Recompute the fingerprint from the EMBEDDED public key
    and require it to equal the entry's claimed fingerprint AND the session
    fingerprint AND (when present) the session public key — never trust the
    claimed fingerprint string. Only then verify the Ed25519 signature over the
    UTF-8 bytes of the entry_hash hex string.
    """
    session = log.get("session", {})
    session_fp = session.get("agent_fingerprint")
    session_pk = session.get("agent_public_key")
    present = False
    verified = 0

    for chained in log.get("entries", []):
        sig = chained.get("agent_signature") if isinstance(chained, dict) else None
        if not sig:
            continue
        present = True
        if not isinstance(sig, dict):
            return True, False, verified

        if not session_fp:
            return True, False, verified

        try:
            embedded_fp = fingerprint_of(load_public_key_b64(sig.get("public_key")))
        except Exception:
            return True, False, verified

        if (
            embedded_fp != sig.get("fingerprint")
            or embedded_fp != session_fp
            or (session_pk is not None and sig.get("public_key") != session_pk)
        ):
            return True, False, verified

        try:
            pub = load_public_key_b64(sig.get("public_key"))
        except Exception:
            return True, False, verified

        message = str(chained.get("entry_hash", "")).encode("utf-8")
        if not verify_signature(pub, sig.get("signature"), message):
            return True, False, verified

        verified += 1

    return present, (True if present else None), verified


def _contract_hash_valid(session: dict[str, Any]) -> Optional[bool]:
    """AER §4.3 step 6 recompute. Reported for information only — the reference
    verifier does not enforce it (feedback #6), and gatehouse mirrors that so a
    redacted derived log (whose contract no longer hashes to the retained
    original value) is not rejected. None when no non-null contract_hash."""
    contract = session.get("intent_contract")
    stored = session.get("contract_hash")
    if not contract or stored is None:
        return None
    return sha256_jcs(contract) == stored


def _core(log: dict[str, Any]) -> dict[str, Any]:
    """The shared verification kernel. Returns the raw pieces both
    ``verify_audit_log`` and ``evidence.build_evidence_record`` project from."""
    entries = log.get("entries", [])
    served = _served_model_mismatches(entries)

    if not _is_v2(log):
        return {
            "status": "failed",
            "failing_step": LEGACY_STEP,
            "chain_valid": False,
            "chain_verified_count": 0,
            "merkle_valid": False,
            "org_valid": None,
            "agent_valid": None,
            "agent_verified": 0,
            "contract_hash_valid": None,
            "fully_attributed": None,
            "envelope_valid": None,
            "served": served,
        }

    # Minimal structural validation before crypto (Codex QA #5): a signed but
    # structurally empty/degenerate log must not authenticate just because
    # someone signed the reduced integrity block. Require a session object with a
    # non-empty session_id and a list of entries.
    def _schema_fail(step: str) -> dict[str, Any]:
        return {
            "status": "failed", "failing_step": step,
            "chain_valid": False, "chain_verified_count": 0, "merkle_valid": False,
            "org_valid": None, "agent_valid": None, "agent_verified": 0,
            "contract_hash_valid": None, "fully_attributed": None,
            "envelope_valid": None, "served": served,
        }

    session_obj = log.get("session")
    if not isinstance(session_obj, dict) or not session_obj.get("session_id"):
        return _schema_fail("session envelope missing or has no session_id")
    if not isinstance(entries, list):
        return _schema_fail("entries is not a list")

    chain_valid, chain_count, chain_detail = verify_chain(entries)

    try:
        computed_root = compute_merkle_root(
            [e.get("entry_hash", "") if isinstance(e, dict) else "" for e in entries]
        )
    except Exception:
        # A non-hex entry_hash cannot form a Merkle leaf. The chain check above
        # has already flagged this entry; treat the root as non-recomputing
        # rather than crashing the verifier (Opus review V5a).
        computed_root = None
    log_root = log.get("merkle_root")
    merkle_strict_fail = False
    if entries and not log_root:
        # gatehouse strictness: a populated log MUST carry its Merkle root
        # (reference is lenient here — feedback #5).
        merkle_valid = False
        merkle_strict_fail = True
    elif log_root:
        merkle_valid = log_root == computed_root
    else:
        merkle_valid = True  # genuinely empty log

    org_valid = _verify_org_signature(log)
    agent_present, agent_valid, agent_verified = _verify_agent_signatures(log)
    session = log.get("session", {}) if isinstance(log.get("session"), dict) else {}
    contract_hash_valid = _contract_hash_valid(session)

    # contract_hash is a §3.5 MUST. gatehouse ENFORCES it (stricter than the
    # reference — feedback #6) for a sealed or agent-signed log, so a full log
    # whose intent_contract was edited without updating the hash fails. A
    # derived_redacted log is exempt: it deliberately retains the ORIGINAL
    # contract_hash while carrying a redacted contract, so a recompute is not
    # expected to match (Opus review V1, partial mitigation — the seal still
    # does not cover the contract; see docs/aer-feedback.md #17b).
    contract_enforced = bool(log.get("org_signature")) or agent_present
    # A present intent_contract on an enforced log MUST carry a matching
    # contract_hash: a MISMATCH fails, and so does ABSENCE/null (Codex QA #7 —
    # deleting contract_hash must not downgrade to "no judgment").
    intent_contract = session.get("intent_contract")
    contract_missing = (
        contract_enforced
        and intent_contract is not None
        and session.get("contract_hash") is None
    )
    contract_fail = contract_enforced and (contract_hash_valid is False or contract_missing)

    # gatehouse-native full-envelope seal (Opus V1/V2, Codex #6).
    envelope_valid = _verify_session_seal(log)

    # De-attribution signal (Opus review V3): identity declared but not every
    # entry signed.
    session_fp = session.get("agent_fingerprint")
    if not session_fp:
        fully_attributed: Optional[bool] = None
    else:
        signed = sum(
            1 for e in entries if isinstance(e, dict) and e.get("agent_signature")
        )
        fully_attributed = bool(entries) and signed == len(entries)

    any_present_failed = (
        not chain_valid
        or not merkle_valid
        or org_valid is False
        or agent_valid is False
        or contract_fail
        or envelope_valid is False
    )

    if any_present_failed:
        status = "failed"
        if not chain_valid:
            failing_step = chain_detail or "hash chain does not verify"
        elif not merkle_valid:
            if merkle_strict_fail:
                failing_step = (
                    "merkle_root absent on a populated log "
                    "(gatehouse requires merkle_root when entries exist)"
                )
            else:
                failing_step = "merkle_root does not recompute"
        elif org_valid is False:
            failing_step = "operator org_signature does not verify"
        elif agent_valid is False:
            failing_step = "agent signature verification failed (F1)"
        elif envelope_valid is False:
            failing_step = (
                "session_seal does not verify (the session envelope — "
                "intent_contract / human_authorizer / org_id / ... — was altered "
                "after sealing, or the seal is by a different operator key)"
            )
        elif contract_missing:
            failing_step = "intent_contract present but contract_hash is absent (§3.5)"
        else:
            failing_step = (
                "contract_hash does not match the recomputed intent_contract hash "
                "(§3.5)"
            )
    elif org_valid is True:
        status = "authenticated"
        failing_step = None
    else:
        status = "consistent_unattributed"
        failing_step = None

    return {
        "status": status,
        "failing_step": failing_step,
        "chain_valid": chain_valid,
        "chain_verified_count": chain_count,
        "merkle_valid": merkle_valid,
        "org_valid": org_valid,
        "agent_valid": agent_valid,
        "agent_verified": agent_verified,
        "contract_hash_valid": contract_hash_valid,
        "fully_attributed": fully_attributed,
        "envelope_valid": envelope_valid,
        "served": served,
    }


def _report_from_core(core: dict[str, Any]) -> VerificationReport:
    return VerificationReport(
        status=core["status"],
        chain_valid=core["chain_valid"],
        chain_verified_count=core["chain_verified_count"],
        merkle_valid=core["merkle_valid"],
        org_signature_valid=core["org_valid"],
        agent_signatures_valid=core["agent_valid"],
        agent_verified_count=core["agent_verified"],
        contract_hash_valid=core["contract_hash_valid"],
        failing_step=core["failing_step"],
        served_model_mismatches=core["served"],
        fully_attributed=core.get("fully_attributed"),
        envelope_valid=core.get("envelope_valid"),
    )


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def verify_audit_log(log: dict[str, Any]) -> VerificationReport:
    """Verify an AuditLog dict (AER §4.3). Tri-state verdict, F1-strict agent
    signatures, gatehouse-strict Merkle, v2-only.

    Total: a malformed log yields a ``failed`` verdict, never a raised
    exception (a verifier that crashes on hostile input is a denial-of-evidence
    — Opus review V5)."""
    if not isinstance(log, dict):
        return VerificationReport(
            "failed", False, 0, False, None, None, 0, None,
            "audit log is not a JSON object", [],
        )
    try:
        return _report_from_core(_core(log))
    except Exception as exc:  # noqa: BLE001 — totality is the contract
        return VerificationReport(
            "failed", False, 0, False, None, None, 0, None,
            f"verifier error on malformed input: {type(exc).__name__}", [],
        )


def _attestation_block(log: dict[str, Any], export_timestamp: str) -> dict[str, Any]:
    """Build the ``integrity_attestation`` block for an evidence record from a
    REAL verification pass over *log* (never asserted, always computed)."""
    core = _core(log)
    org = log.get("org_signature")
    org_block: Optional[dict[str, Any]] = None
    if org:
        org_block = {
            "public_key": org.get("public_key"),
            "signature": org.get("signature"),
            "signed_at": org.get("signed_at"),
            "valid": core["org_valid"],
        }
    agent_present = core["agent_valid"] is not None
    status = core["status"]
    return {
        "schema_version": 2,
        "canonicalization": "jcs",
        "chain_valid": core["chain_valid"],
        "chain_verified_count": core["chain_verified_count"],
        "merkle_root": log.get("merkle_root"),
        "merkle_valid": core["merkle_valid"],
        "org_signature": org_block,
        "agent_signatures": {
            "present": agent_present,
            "valid": core["agent_valid"],
            "verified_count": core["agent_verified"],
        },
        "status": status,
        "attribution": "operator" if status == "authenticated" else "unattributed",
        "overall_valid": status == "authenticated",
        "export_timestamp": export_timestamp,
    }


def _read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def _read_ndjson(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    return [
        json.loads(line)
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def _manifest_seal_key(manifest: dict[str, Any]) -> Optional[str]:
    sig = manifest.get("operator_signature")
    return sig.get("public_key") if isinstance(sig, dict) else None


def _verify_manifest_seal(manifest: dict[str, Any]) -> Optional[bool]:
    sig = manifest.get("operator_signature")
    if not isinstance(sig, dict) or not sig:
        return None
    unsigned = {k: v for k, v in manifest.items() if k != "operator_signature"}
    try:
        pub = load_public_key_b64(sig.get("public_key"))
    except Exception:
        return False
    return verify_signature(pub, sig.get("signature"), jcs_bytes(unsigned))


def _fail(base: VerificationReport, step: str) -> VerificationReport:
    return VerificationReport(
        status="failed",
        chain_valid=base.chain_valid,
        chain_verified_count=base.chain_verified_count,
        merkle_valid=base.merkle_valid,
        org_signature_valid=base.org_signature_valid,
        agent_signatures_valid=base.agent_signatures_valid,
        agent_verified_count=base.agent_verified_count,
        contract_hash_valid=base.contract_hash_valid,
        failing_step=step,
        served_model_mismatches=base.served_model_mismatches,
        fully_attributed=base.fully_attributed,  # Codex QA #10: don't drop base judgments
        envelope_valid=base.envelope_valid,
    )


def _served_projection_disagreement(
    record: dict[str, Any], entries: list[dict[str, Any]]
) -> Optional[str]:
    """Record-vs-entry integrity check. An HONEST reroute (served!=requested,
    consistently recorded in BOTH the projection and the chained entry) is fine.
    A disagreement — the evidence record's operations projection saying one thing
    about served_model while the chained entry says another — IS tampering."""
    ops_by_seq = {op.get("sequence"): op for op in record.get("operations", [])}
    for chained in entries:
        entry = chained.get("entry", {})
        if entry.get("type") != "model_call":
            continue
        seq = chained.get("sequence")
        op = ops_by_seq.get(seq)
        if op is None:
            return f"served_model mismatch between record and chained entry {seq}"
        if op.get("served_model") != entry.get("served_model"):
            return f"served_model mismatch between record and chained entry {seq}"
    return None


def _safe_bundle_path(bundle_dir: Path, name: Any) -> Optional[Path]:
    """A manifest file name must be a simple relative name that resolves INSIDE
    the bundle directory. Reject absolute paths, ``..`` traversal, and anything
    that escapes the bundle (Codex QA #8 — a manifest could otherwise make the
    verifier read arbitrary files on disk)."""
    if not isinstance(name, str) or not name:
        return None
    candidate = Path(name)
    if candidate.is_absolute() or ".." in candidate.parts:
        return None
    try:
        base = bundle_dir.resolve()
        resolved = (bundle_dir / candidate).resolve()
    except (OSError, ValueError):
        return None
    if resolved != base and base not in resolved.parents:
        return None
    return bundle_dir / candidate


def _mask_export_timestamp(record: Any) -> Any:
    import copy as _copy

    r = _copy.deepcopy(record)
    if isinstance(r, dict):
        ia = r.get("policy_context", {})
        ia = ia.get("integrity_attestation") if isinstance(ia, dict) else None
        if isinstance(ia, dict):
            ia["export_timestamp"] = None
    return r


def verify_bundle(bundle_dir: Path) -> VerificationReport:
    """Verify an exported bundle end to end. Total over malformed input."""
    try:
        return _verify_bundle_impl(Path(bundle_dir))
    except Exception as exc:  # noqa: BLE001 — totality is the contract
        return VerificationReport(
            "failed", False, 0, False, None, None, 0, None,
            f"bundle verifier error: {type(exc).__name__}", [],
        )


def _verify_bundle_impl(bundle_dir: Path) -> VerificationReport:
    manifest_path = bundle_dir / "hash_manifest.json"
    audit_log_path = bundle_dir / "audit_log.json"
    record_path = bundle_dir / "evidence_record.json"
    entries_path = bundle_dir / "entries.ndjson"

    def bare(step: str) -> VerificationReport:
        return VerificationReport("failed", False, 0, False, None, None, 0, None, step, [])

    if not manifest_path.exists():
        return bare("hash_manifest.json missing from bundle")
    if not audit_log_path.exists():
        return bare("audit_log.json missing from bundle")
    try:
        manifest = _read_json(manifest_path)
        audit_log = _read_json(audit_log_path)
    except (json.JSONDecodeError, OSError, UnicodeDecodeError) as exc:
        return bare(f"bundle contains unparseable JSON: {type(exc).__name__}")
    if not isinstance(manifest, dict):
        return bare("hash_manifest.json is not a JSON object")

    base = verify_audit_log(audit_log)

    # (1) File-byte integrity, with path-traversal defense (Codex #8).
    files = manifest.get("files")
    if not isinstance(files, dict):
        return _fail(base, "manifest.files is missing or not an object")
    for name, expected in files.items():
        safe = _safe_bundle_path(bundle_dir, name)
        if safe is None:
            return _fail(base, f"manifest names an unsafe file path: {name!r}")
        if not safe.exists() or safe.is_dir():
            return _fail(base, f"bundle file {name} listed in manifest is missing")
        if sha256_hex(safe.read_bytes()) != expected:
            return _fail(base, f"bundle file {name} hash mismatch (tampered)")

    # (2) Manifest operator seal MUST verify — an absent or replaced seal must
    # not pass (Codex #1). gatehouse seals every bundle by default.
    seal = _verify_manifest_seal(manifest)
    if seal is None:
        return _fail(base, "bundle manifest is not operator-sealed")
    if seal is False:
        return _fail(base, "manifest operator_signature does not verify")
    # ...and, for an operational bundle, by the SAME operator as the audit log.
    org_key = (audit_log.get("org_signature") or {}).get("public_key") if isinstance(audit_log, dict) else None
    seal_key = _manifest_seal_key(manifest)
    if org_key and seal_key and seal_key != org_key:
        return _fail(base, "manifest is sealed by a different key than the audit-log operator")

    # (3) Audit-log verdict.
    if base.status == "failed":
        return base

    # (4) Full attribution (Opus V3): a sealed gatehouse bundle signs every
    # entry; a partially-attributed one had a signature stripped.
    if base.status == "authenticated" and base.fully_attributed is False:
        return _fail(
            base,
            f"partial attribution: {base.agent_verified_count} of "
            f"{len(audit_log.get('entries', []))} entries signed "
            "(an agent signature was stripped from a sealed bundle)",
        )

    # (5) entries.ndjson MUST equal the verified audit-log entries (Codex #2) —
    # so the NDJSON any downstream check reads is the verified data, not a
    # parallel copy.
    if entries_path.exists():
        try:
            entries_file = _read_ndjson(entries_path)
        except (json.JSONDecodeError, OSError, UnicodeDecodeError) as exc:
            return _fail(base, f"entries.ndjson unparseable: {type(exc).__name__}")
        if entries_file != (audit_log.get("entries") or []):
            return _fail(base, "entries.ndjson does not equal the audit-log entries")

    # (6) evidence_record MUST be the faithful projection of the VERIFIED audit
    # log (Codex #2) — not an independently editable file.
    if record_path.exists():
        try:
            record = _read_json(record_path)
        except (json.JSONDecodeError, OSError, UnicodeDecodeError) as exc:
            return _fail(base, f"evidence_record.json unparseable: {type(exc).__name__}")

        # (6a) A served_model projection lie gets a precise forensic message
        # (E8) before the general projection comparison.
        step = _served_projection_disagreement(record, audit_log.get("entries") or [])
        if step is not None:
            return _fail(base, step)

        # (6b) Full projection consistency: reproject from the verified log and
        # compare (ignoring only the informational export_timestamp).
        from . import evidence  # lazy import breaks the evidence<->verify cycle

        redacted = manifest.get("bundle_kind") == "derived_redacted"
        try:
            rebuilt = evidence._project_record(audit_log, redacted=redacted)
        except Exception:  # noqa: BLE001
            return _fail(base, "evidence_record.json could not be reprojected from the audit log")
        if _mask_export_timestamp(record) != _mask_export_timestamp(rebuilt):
            return _fail(
                base,
                "evidence_record.json does not match the projection of the verified audit log",
            )

    return base


def verify_pair(redacted_dir: Path, original_log_path: Path) -> VerificationReport:
    """Confirm a redacted bundle is a FAITHFUL derivation of a sealed original
    (AER §5, F3). Given the redacted bundle's manifest + derived entries and the
    original log, check per entry that derived-n binds to source-n, that nothing
    was dropped/reordered/substituted, that the derived chain self-verifies, and
    that the manifest's source/derived tips are correct."""
    redacted_dir = Path(redacted_dir)

    def failed(step: str, chain_valid: bool = False, chain_count: int = 0) -> VerificationReport:
        return VerificationReport(
            "failed", chain_valid, chain_count, False, None, None, 0, None, step, [],
        )

    try:
        manifest = _read_json(redacted_dir / "hash_manifest.json")
        derived = _read_ndjson(redacted_dir / "entries.ndjson")
        original = _read_json(Path(original_log_path))
    except (json.JSONDecodeError, OSError, UnicodeDecodeError) as exc:
        return failed(f"pair inputs unreadable: {type(exc).__name__}")
    if not isinstance(manifest, dict) or not isinstance(original, dict):
        return failed("manifest or original is not a JSON object")

    # A "faithful derivation" claim is only meaningful against a SEALED,
    # AUTHENTIC original (AER §5: "the original — produced under seal"). Require
    # the original to verify AUTHENTICATED, not merely consistent (Opus V4 /
    # Codex #4).
    original_report = verify_audit_log(original)
    if original_report.status != "authenticated":
        return failed(
            f"original log is not authenticated ({original_report.status}: "
            f"{original_report.failing_step}); cannot certify a redaction binding "
            "against a non-sealed original"
        )

    # The redacted bundle is itself operator-sealed; verify its manifest seal and
    # every file hash, and require the SAME operator as the original (Codex #4).
    red_seal = _verify_manifest_seal(manifest)
    if red_seal is None:
        return failed("redacted bundle manifest is not operator-sealed")
    if red_seal is False:
        return failed("redacted bundle manifest operator_signature does not verify")
    original_org_key = (original.get("org_signature") or {}).get("public_key")
    red_seal_key = _manifest_seal_key(manifest)
    if original_org_key and red_seal_key and red_seal_key != original_org_key:
        return failed("redacted manifest is sealed by a different key than the original operator")
    red_files = manifest.get("files")
    if not isinstance(red_files, dict):
        return failed("redacted manifest.files is missing or not an object")
    for name, expected_hash in red_files.items():
        safe = _safe_bundle_path(redacted_dir, name)
        if safe is None:
            return failed(f"redacted manifest names an unsafe file path: {name!r}")
        if not safe.exists() or safe.is_dir():
            return failed(f"redacted bundle file {name} is missing")
        if sha256_hex(safe.read_bytes()) != expected_hash:
            return failed(f"redacted bundle file {name} hash mismatch (tampered)")

    source_hashes = [
        e.get("entry_hash") for e in original.get("entries", []) if isinstance(e, dict)
    ]
    source_count = len(source_hashes)
    derived_count = len(derived)
    served = _served_model_mismatches(derived)

    # (#3) Reconstruct the EXPECTED aer-0.1-basic redaction from the
    # authenticated original and require the derived payload to match it exactly.
    # Positional source-hash binding alone let an attacker substitute arbitrary
    # content into a derived entry and rechain; comparing to the prescribed
    # redaction closes that.
    from .redaction import derive_redacted_entries

    try:
        expected_derived = derive_redacted_entries(
            [e for e in original.get("entries", []) if isinstance(e, dict)]
        )
    except Exception:  # noqa: BLE001
        return failed("could not reconstruct the expected redaction from the original")
    if derived != expected_derived:
        for i in range(max(len(derived), len(expected_derived))):
            d = derived[i] if i < len(derived) else None
            x = expected_derived[i] if i < len(expected_derived) else None
            if d != x:
                return failed(
                    f"derived entry {i} is not the prescribed aer-0.1-basic redaction "
                    "of the corresponding original entry"
                )
        return failed("derived entries are not the prescribed redaction of the original")

    if manifest.get("bundle_kind") != "derived_redacted":
        return failed(
            f'manifest.bundle_kind is "{manifest.get("bundle_kind")}", '
            'expected "derived_redacted"'
        )

    if manifest.get("source_entry_count") != source_count:
        return failed(
            f"manifest.source_entry_count ({manifest.get('source_entry_count')}) "
            f"!= original entry count ({source_count})"
        )

    manifest_sources = manifest.get("source_entry_hashes")
    if not isinstance(manifest_sources, list):
        return failed("manifest.source_entry_hashes is missing or not an array")
    if len(manifest_sources) != source_count:
        return failed(
            f"manifest.source_entry_hashes length ({len(manifest_sources)}) "
            f"!= original entry count ({source_count})"
        )
    for i in range(source_count):
        if manifest_sources[i] != source_hashes[i]:
            return failed(
                f"manifest.source_entry_hashes[{i}] does not match the original entry hash"
            )

    if derived_count != source_count:
        return failed(
            f"derived entry count ({derived_count}) != source entry count "
            f"({source_count}) - entries dropped or added"
        )

    # Per-entry binding: derived-n names source-n.
    for i in range(source_count):
        bound = derived[i].get("source_entry_hash")
        if bound is None:
            return failed(f"derived entry {i} has no source_entry_hash - not bound")
        if bound != source_hashes[i]:
            return failed(
                f"derived entry {i} binds to the wrong source entry - reordered or substituted"
            )

    chain_valid, chain_count, chain_detail = verify_chain(derived)
    if not chain_valid:
        return failed(
            f"derived chain does not verify: {chain_detail}", chain_valid, chain_count
        )

    if source_count > 0 and manifest.get("source_last_entry_hash") != source_hashes[-1]:
        return failed(
            "manifest.source_last_entry_hash does not match the original chain tip",
            chain_valid,
            chain_count,
        )
    if (
        derived_count > 0
        and manifest.get("derived_last_entry_hash") != derived[-1].get("entry_hash")
    ):
        return failed(
            "manifest.derived_last_entry_hash does not match the redacted chain tip",
            chain_valid,
            chain_count,
        )

    # Report Merkle honestly rather than asserting a field we did not check
    # (Fable review B3). Recompute the derived root; when the redacted bundle
    # ships its own audit_log.json, confirm its stored root matches.
    try:
        derived_root = compute_merkle_root(
            [e.get("entry_hash", "") if isinstance(e, dict) else "" for e in derived]
        )
    except Exception:
        derived_root = None
    red_log_path = redacted_dir / "audit_log.json"
    if red_log_path.exists():
        try:
            stored_root = _read_json(red_log_path).get("merkle_root")
        except Exception:
            stored_root = None
        merkle_ok = derived_root is not None and stored_root == derived_root
        if not merkle_ok:
            return failed(
                "redacted audit_log.json merkle_root does not match the derived entries",
                chain_valid,
                chain_count,
            )
    else:
        # No stored root to check in this bundle; the derived chain (which
        # covers the same entry hashes) has already verified above.
        merkle_ok = derived_root is not None

    # A faithful derived bundle is internally consistent but unattributed: it
    # carries no agent signatures and is not operator-sealed as a log (the
    # binding manifest carries the operator seal instead).
    return VerificationReport(
        status="consistent_unattributed",
        chain_valid=chain_valid,
        chain_verified_count=chain_count,
        merkle_valid=merkle_ok,
        org_signature_valid=None,
        agent_signatures_valid=None,
        agent_verified_count=0,
        contract_hash_valid=None,
        failing_step=None,
        served_model_mismatches=served,
    )
