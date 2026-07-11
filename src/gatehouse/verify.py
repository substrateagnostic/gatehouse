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
            "served": served,
        }

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
    contract_fail = contract_enforced and contract_hash_valid is False

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


def _verify_manifest_seal(manifest: dict[str, Any]) -> Optional[bool]:
    sig = manifest.get("operator_signature")
    if not sig:
        return None
    unsigned = {k: v for k, v in manifest.items() if k != "operator_signature"}
    try:
        pub = load_public_key_b64(sig["public_key"])
    except Exception:
        return False
    return verify_signature(pub, sig["signature"], jcs_bytes(unsigned))


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


def verify_bundle(bundle_dir: Path) -> VerificationReport:
    """Verify an exported bundle end to end: re-hash every file named in the
    manifest against its bytes on disk, verify the manifest operator seal when
    present, verify the embedded ``audit_log.json`` (AER §4.3), and cross-check
    the evidence record's served_model projection against the chained entries.
    Any mismatch => ``failed`` with a named step."""
    bundle_dir = Path(bundle_dir)

    manifest_path = bundle_dir / "hash_manifest.json"
    audit_log_path = bundle_dir / "audit_log.json"
    record_path = bundle_dir / "evidence_record.json"
    entries_path = bundle_dir / "entries.ndjson"

    if not manifest_path.exists():
        return VerificationReport(
            "failed", False, 0, False, None, None, 0, None,
            "hash_manifest.json missing from bundle", [],
        )
    if not audit_log_path.exists():
        return VerificationReport(
            "failed", False, 0, False, None, None, 0, None,
            "audit_log.json missing from bundle", [],
        )

    try:
        manifest = _read_json(manifest_path)
        audit_log = _read_json(audit_log_path)
    except (json.JSONDecodeError, OSError, UnicodeDecodeError) as exc:
        return VerificationReport(
            "failed", False, 0, False, None, None, 0, None,
            f"bundle contains unparseable JSON: {type(exc).__name__}", [],
        )
    if not isinstance(manifest, dict):
        return VerificationReport(
            "failed", False, 0, False, None, None, 0, None,
            "hash_manifest.json is not a JSON object", [],
        )

    base = verify_audit_log(audit_log)

    # (1) File-byte integrity: every file the manifest names must hash to the
    # recorded value (this is what catches a tampered evidence_record.json —
    # feedback #4: the reference pair check ignores files{}).
    for name, expected in (manifest.get("files") or {}).items():
        fpath = bundle_dir / name
        if not fpath.exists():
            return _fail(base, f"bundle file {name} listed in manifest is missing")
        actual = sha256_hex(fpath.read_bytes())
        if actual != expected:
            return _fail(base, f"bundle file {name} hash mismatch (tampered)")

    # (2) Manifest operator seal (gatehouse seals by default — feedback #2).
    seal = _verify_manifest_seal(manifest)
    if seal is False:
        return _fail(base, "manifest operator_signature does not verify")

    # (3) Audit-log verdict.
    if base.status == "failed":
        return base

    # (4) Full attribution: a gatehouse bundle signs every entry, so a sealed
    # bundle that is not fully attributed has had a signature stripped (Opus
    # review V3). Standalone log verification only surfaces this; the bundle
    # format is gatehouse's own, so here it is a hard failure.
    if base.status == "authenticated" and base.fully_attributed is False:
        return _fail(
            base,
            f"partial attribution: {base.agent_verified_count} of "
            f"{len(audit_log.get('entries', []))} entries signed "
            "(an agent signature was stripped from a sealed bundle)",
        )

    # (5) served_model record-vs-entry integrity (E8).
    if record_path.exists() and entries_path.exists():
        try:
            record = _read_json(record_path)
            entries = _read_ndjson(entries_path)
        except (json.JSONDecodeError, OSError, UnicodeDecodeError) as exc:
            return _fail(base, f"bundle payload unparseable: {type(exc).__name__}")
        step = _served_projection_disagreement(record, entries)
        if step is not None:
            return _fail(base, step)

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

    # A "faithful derivation" claim is only meaningful against an AUTHENTIC
    # original. Verify the original first; refuse to certify a binding to a
    # document that does not itself verify (Opus review V4). An unsigned but
    # internally-consistent original (consistent_unattributed) is an acceptable
    # source; only a FAILED original is refused.
    original_report = verify_audit_log(original)
    if original_report.status == "failed":
        return failed(
            f"original log does not verify ({original_report.failing_step}); "
            "cannot certify a redaction binding against a non-authentic original"
        )

    source_hashes = [
        e.get("entry_hash") for e in original.get("entries", []) if isinstance(e, dict)
    ]
    source_count = len(source_hashes)
    derived_count = len(derived)
    served = _served_model_mismatches(derived)

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

    # A faithful derived bundle is internally consistent but unattributed: it
    # carries no agent signatures and is not operator-sealed as a log (the
    # binding manifest carries the operator seal instead).
    return VerificationReport(
        status="consistent_unattributed",
        chain_valid=chain_valid,
        chain_verified_count=chain_count,
        merkle_valid=True,
        org_signature_valid=None,
        agent_signatures_valid=None,
        agent_verified_count=0,
        contract_hash_valid=None,
        failing_step=None,
        served_model_mismatches=served,
    )
