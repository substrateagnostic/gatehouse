"""Regression tests for the Opus 4.8 verifier-hardening pass (2026-07-11).

Locks in the guarantees added after the adversarial review documented in
docs/redteam/2026-07-11-opus-verifier-review.md:

- totality: malformed input yields `failed`, never a raised exception;
- verify_pair refuses a non-authentic original (V4);
- contract_hash is enforced on sealed/signed logs (V1 lazy variant);
- signature stripping is surfaced on the standalone path (fully_attributed)
  and hard-failed in the bundle path (V3).
"""

from __future__ import annotations

import copy
import json
import shutil
from pathlib import Path

import pytest

from gatehouse.canonical import sha256_hex, sha256_jcs
from gatehouse.evidence import export_bundle
from gatehouse.store import SessionStore
from gatehouse.verify import verify_audit_log, verify_bundle, verify_pair


@pytest.fixture
def full_bundle(store: SessionStore, session_id: str, tmp_path: Path) -> Path:
    out = tmp_path / "bundle-full"
    out.mkdir()
    export_bundle(store, session_id, out, mode="full")
    return out


@pytest.fixture
def redacted_bundle(store: SessionStore, session_id: str, tmp_path: Path) -> Path:
    out = tmp_path / "bundle-redacted"
    out.mkdir()
    export_bundle(store, session_id, out, mode="redacted")
    return out


def _log(bundle: Path) -> dict:
    return json.loads((bundle / "audit_log.json").read_text(encoding="utf-8"))


# --- Totality -------------------------------------------------------------

@pytest.mark.parametrize(
    "mutate",
    [
        pytest.param(lambda l: l["entries"][0].__setitem__("entry_hash", "zz"), id="nonhex-entry_hash"),
        pytest.param(lambda l: l["entries"][0].pop("entry"), id="missing-entry"),
        pytest.param(lambda l: l["org_signature"].pop("signature"), id="missing-org-sig"),
        pytest.param(lambda l: l["org_signature"].__setitem__("signature", "not!b64!"), id="bad-b64-sig"),
        pytest.param(lambda l: l["entries"][0]["agent_signature"].pop("signature"), id="agentsig-no-sig"),
        pytest.param(lambda l: l.__setitem__("entries", "nope"), id="entries-not-list"),
        pytest.param(lambda l: l["entries"].__setitem__(0, "nope"), id="entry-not-object"),
        pytest.param(lambda l: l.__setitem__("session", "nope"), id="session-not-object"),
    ],
)
def test_malformed_input_fails_never_crashes(full_bundle: Path, mutate) -> None:
    log = _log(full_bundle)
    mutate(log)
    report = verify_audit_log(log)  # must not raise
    assert report.status == "failed"
    assert report.failing_step  # a failed verdict always names the step


def test_non_dict_log_fails():
    assert verify_audit_log("not a log").status == "failed"  # type: ignore[arg-type]
    assert verify_audit_log([]).status == "failed"  # type: ignore[arg-type]


def test_malformed_bundle_json_fails(tmp_path: Path) -> None:
    bad = tmp_path / "bad"
    bad.mkdir()
    (bad / "hash_manifest.json").write_text("{ not json", encoding="utf-8")
    (bad / "audit_log.json").write_text("{}", encoding="utf-8")
    assert verify_bundle(bad).status == "failed"


# --- V4: verify_pair must vet the original --------------------------------

def test_verify_pair_rejects_non_authentic_original(
    full_bundle: Path, redacted_bundle: Path, tmp_path: Path
) -> None:
    doctored = _log(full_bundle)
    doctored["entries"][0]["entry"]["provider"] = "forged"  # breaks the original chain
    dp = tmp_path / "doctored.json"
    dp.write_text(json.dumps(doctored, indent=2), encoding="utf-8")
    report = verify_pair(redacted_bundle, dp)
    assert report.status == "failed"
    assert "original" in report.failing_step.lower()


def test_verify_pair_accepts_honest_pair(full_bundle: Path, redacted_bundle: Path) -> None:
    report = verify_pair(redacted_bundle, full_bundle / "audit_log.json")
    assert report.status != "failed"


# --- V1 lazy: contract_hash is enforced on sealed logs --------------------

def test_contract_hash_lazy_edit_fails(full_bundle: Path) -> None:
    log = _log(full_bundle)
    # Strip the gatehouse envelope seal to isolate the contract_hash guard (on a
    # gatehouse log the session_seal would catch the edit first; this exercises
    # the guard as it applies to a foreign/reference log that has no seal).
    log.pop("session_seal", None)
    log["session"]["intent_contract"]["objective"] = "Do something entirely different"
    # attacker does NOT update contract_hash
    report = verify_audit_log(log)
    assert report.status == "failed"
    assert "contract_hash" in report.failing_step


def test_contract_hash_absence_fails(full_bundle: Path) -> None:
    # Codex QA #7: deleting contract_hash while keeping intent_contract must fail,
    # not downgrade to "no judgment".
    log = _log(full_bundle)
    log.pop("session_seal", None)
    del log["session"]["contract_hash"]
    report = verify_audit_log(log)
    assert report.status == "failed"
    assert "contract_hash" in report.failing_step


def test_contract_hash_match_still_authenticates(full_bundle: Path) -> None:
    # sanity: an untouched log authenticates and its contract_hash is valid
    report = verify_audit_log(_log(full_bundle))
    assert report.status == "authenticated"
    assert report.contract_hash_valid is True


# --- V3: signature stripping ----------------------------------------------

def test_strip_signature_surfaced_on_standalone(full_bundle: Path) -> None:
    log = _log(full_bundle)
    del log["entries"][0]["agent_signature"]
    report = verify_audit_log(log)
    # standalone stays reference-compatible (authenticated) but flags partial
    # attribution so an automated consumer can catch the de-attribution.
    assert report.status == "authenticated"
    assert report.fully_attributed is False
    assert report.agent_verified_count < len(log["entries"])


def test_full_bundle_is_fully_attributed(full_bundle: Path) -> None:
    assert verify_bundle(full_bundle).fully_attributed is True


def test_strip_signature_hard_fails_in_bundle(full_bundle: Path) -> None:
    log = _log(full_bundle)
    del log["entries"][0]["agent_signature"]
    data = json.dumps(log, indent=2, ensure_ascii=False).encode("utf-8")
    (full_bundle / "audit_log.json").write_bytes(data)
    # attacker refreshes the file hash so the file-integrity check passes...
    manifest = json.loads((full_bundle / "hash_manifest.json").read_text(encoding="utf-8"))
    manifest["files"]["audit_log.json"] = sha256_hex(data)
    (full_bundle / "hash_manifest.json").write_text(
        json.dumps(manifest, indent=2, ensure_ascii=False), encoding="utf-8"
    )
    # ...but the manifest seal no longer verifies (they cannot re-sign), and
    # even absent the seal the partial-attribution check would fail it.
    assert verify_bundle(full_bundle).status == "failed"


# --- The documented spec gap (V1-sophisticated / V2) ----------------------

def test_envelope_rewrite_now_caught_by_session_seal(full_bundle: Path) -> None:
    """The AER operator seal does not cover the session envelope, so on a
    STANDALONE reference log a tamperer who also refreshes contract_hash could
    rewrite intent_contract/human_authorizer and still authenticate (the headline
    finding, aer-feedback #17b). gatehouse closes this with a native full-envelope
    ``session_seal``: on a gatehouse log the rewrite is now CAUGHT."""
    log = _log(full_bundle)
    log["session"]["intent_contract"]["objective"] = "Do anything at all"
    log["session"]["contract_hash"] = sha256_jcs(log["session"]["intent_contract"])
    report = verify_audit_log(log)
    assert report.status == "failed"
    assert report.envelope_valid is False
    assert "session_seal" in report.failing_step


def test_authorizer_rewrite_now_caught_by_session_seal(full_bundle: Path) -> None:
    log = _log(full_bundle)
    log["session"]["human_authorizer"] = {"identifier": "nobody", "role": "intern"}
    report = verify_audit_log(log)
    assert report.status == "failed"
    assert report.envelope_valid is False


def test_envelope_rewrite_without_seal_is_the_documented_reference_gap(full_bundle: Path) -> None:
    """With the gatehouse ``session_seal`` stripped (i.e. a bare reference-shaped
    log), the standalone envelope-rewrite gap is still present — this is the
    AER-spec-level finding that a foreign log without an envelope seal cannot
    detect. Asserted so the residual scope of the gap stays visible."""
    log = _log(full_bundle)
    log.pop("session_seal", None)
    log["session"]["intent_contract"]["objective"] = "Do anything at all"
    log["session"]["contract_hash"] = sha256_jcs(log["session"]["intent_contract"])
    assert verify_audit_log(log).status == "authenticated"  # documented residual gap


def test_envelope_rewrite_is_caught_in_the_bundle_path(full_bundle: Path) -> None:
    log = _log(full_bundle)
    log["session"]["human_authorizer"] = {"identifier": "nobody", "role": "intern"}
    (full_bundle / "audit_log.json").write_text(
        json.dumps(log, indent=2, ensure_ascii=False), encoding="utf-8"
    )
    assert verify_bundle(full_bundle).status == "failed"


# --- Codex QA fixes -------------------------------------------------------

def _reseal_manifest(bundle: Path, store: SessionStore, key=None) -> None:
    """Recompute files{} hashes and re-sign the manifest (optionally with a
    different key) so file-hash and seal checks would otherwise pass."""
    from gatehouse.canonical import jcs_bytes

    key = key or store.operator_key()
    manifest = json.loads((bundle / "hash_manifest.json").read_text(encoding="utf-8"))
    for name in list(manifest["files"].keys()):
        manifest["files"][name] = sha256_hex((bundle / name).read_bytes())
    unsigned = {k: v for k, v in manifest.items() if k != "operator_signature"}
    manifest["operator_signature"] = {
        "public_key": key.public_b64,
        "signature": key.sign_b64(jcs_bytes(unsigned)),
        "signed_at": "2026-07-11T00:00:00.000Z",
    }
    (bundle / "hash_manifest.json").write_text(
        json.dumps(manifest, indent=2, ensure_ascii=False), encoding="utf-8"
    )


def test_manifest_seal_strip_fails(full_bundle: Path) -> None:
    # Codex #1: edit a payload, refresh its file hash, then DELETE the seal.
    log = _log(full_bundle)
    log["session"]["org_id"] = "somewhere-else"
    data = json.dumps(log, indent=2, ensure_ascii=False).encode("utf-8")
    (full_bundle / "audit_log.json").write_bytes(data)
    manifest = json.loads((full_bundle / "hash_manifest.json").read_text(encoding="utf-8"))
    manifest["files"]["audit_log.json"] = sha256_hex(data)
    manifest.pop("operator_signature", None)  # strip the seal
    (full_bundle / "hash_manifest.json").write_text(
        json.dumps(manifest, indent=2, ensure_ascii=False), encoding="utf-8"
    )
    report = verify_bundle(full_bundle)
    assert report.status == "failed"
    assert "seal" in report.failing_step.lower()


def test_manifest_seal_replaced_by_foreign_key_fails(full_bundle: Path, store: SessionStore) -> None:
    # Codex #1: re-seal with a DIFFERENT operator key than the audit-log operator.
    from gatehouse.keys import AgentKey

    log = _log(full_bundle)
    log["session"]["org_id"] = "somewhere-else"
    (full_bundle / "audit_log.json").write_text(
        json.dumps(log, indent=2, ensure_ascii=False), encoding="utf-8"
    )
    _reseal_manifest(full_bundle, store, key=AgentKey.generate())
    report = verify_bundle(full_bundle)
    assert report.status == "failed"


def test_bundle_projection_edit_fails(full_bundle: Path, store: SessionStore) -> None:
    # Codex #2: edit a NON-served_model projection, refresh hash + reseal.
    record_path = full_bundle / "evidence_record.json"
    record = json.loads(record_path.read_text(encoding="utf-8"))
    record["agent_identity"]["agent_id"] = "someone-else"
    record_path.write_text(json.dumps(record, indent=2, ensure_ascii=False), encoding="utf-8")
    _reseal_manifest(full_bundle, store)
    report = verify_bundle(full_bundle)
    assert report.status == "failed"
    assert "projection" in report.failing_step


def test_bundle_entries_ndjson_must_equal_log(full_bundle: Path, store: SessionStore) -> None:
    # Codex #2: entries.ndjson diverging from the audit log fails.
    entries = _read_ndjson_lines(full_bundle / "entries.ndjson")
    entries[0]["entry"]["provider"] = "forged"
    (full_bundle / "entries.ndjson").write_text(
        "".join(json.dumps(e, separators=(",", ":"), ensure_ascii=False) + "\n" for e in entries),
        encoding="utf-8",
    )
    _reseal_manifest(full_bundle, store)
    report = verify_bundle(full_bundle)
    assert report.status == "failed"


def _read_ndjson_lines(path: Path) -> list:
    return [json.loads(l) for l in path.read_text(encoding="utf-8").splitlines() if l.strip()]


def test_verify_pair_rejects_substituted_content(
    full_bundle: Path, redacted_bundle: Path, store: SessionStore
) -> None:
    # Codex #3: substitute arbitrary content into a derived entry, rechain, fix
    # the manifest tips + reseal, keep source_entry_hash. Positional binding
    # passes but the redaction-reconstruction check must reject it.
    from gatehouse.chain import chained_entry

    derived = _read_ndjson_lines(redacted_bundle / "entries.ndjson")
    # rebuild derived[0] with forged content, rechaining downstream
    prev = ""
    forged = []
    for i, d in enumerate(derived):
        entry = dict(d["entry"])
        if i == 0:
            entry["provider"] = "forged-provider"  # not a [REDACTED] transform
        w = chained_entry(i, entry, prev, source_entry_hash=d["source_entry_hash"])
        forged.append(w)
        prev = w["entry_hash"]
    (redacted_bundle / "entries.ndjson").write_text(
        "".join(json.dumps(e, separators=(",", ":"), ensure_ascii=False) + "\n" for e in forged),
        encoding="utf-8",
    )
    manifest = json.loads((redacted_bundle / "hash_manifest.json").read_text(encoding="utf-8"))
    manifest["derived_last_entry_hash"] = forged[-1]["entry_hash"]
    (redacted_bundle / "hash_manifest.json").write_text(
        json.dumps(manifest, indent=2, ensure_ascii=False), encoding="utf-8"
    )
    _reseal_manifest(redacted_bundle, store)
    report = verify_pair(redacted_bundle, full_bundle / "audit_log.json")
    assert report.status == "failed"
    assert "redaction" in report.failing_step or "prescribed" in report.failing_step


def test_verify_pair_requires_authenticated_original(
    full_bundle: Path, redacted_bundle: Path, tmp_path: Path
) -> None:
    # Codex #4: an unsigned (consistent_unattributed) original is not a sealed
    # original and must be refused.
    log = _log(full_bundle)
    log.pop("org_signature", None)
    log.pop("session_seal", None)
    p = tmp_path / "unsigned_original.json"
    p.write_text(json.dumps(log, indent=2, ensure_ascii=False), encoding="utf-8")
    report = verify_pair(redacted_bundle, p)
    assert report.status == "failed"
    assert "authenticated" in report.failing_step or "sealed" in report.failing_step


def test_empty_degenerate_log_does_not_authenticate() -> None:
    # Codex #5: a signed but structurally empty log must not authenticate.
    from gatehouse.store import SessionStore as _S
    import tempfile
    store = _S(Path(tempfile.mkdtemp()) / "var")
    key = store.operator_key()
    from gatehouse.verify import org_signature_block
    from gatehouse.canonical import jcs_bytes

    log = {"version": "2.0.0", "schema_version": 2, "session": {}, "entries": [], "merkle_root": ""}
    log["org_signature"] = {
        "public_key": key.public_b64,
        "signature": key.sign_b64(jcs_bytes(org_signature_block(log))),
        "signed_at": "2026-07-11T00:00:00.000Z",
    }
    report = verify_audit_log(log)
    assert report.status == "failed"
    assert "session" in report.failing_step


def test_manifest_path_traversal_rejected(full_bundle: Path, store: SessionStore) -> None:
    # Codex #8: a manifest file name escaping the bundle dir must be rejected,
    # not read off disk.
    manifest = json.loads((full_bundle / "hash_manifest.json").read_text(encoding="utf-8"))
    manifest["files"]["../../etc/passwd"] = "00" * 32
    (full_bundle / "hash_manifest.json").write_text(
        json.dumps(manifest, indent=2, ensure_ascii=False), encoding="utf-8"
    )
    report = verify_bundle(full_bundle)
    assert report.status == "failed"
    assert "unsafe" in report.failing_step


def test_bundle_verifier_is_total_on_bad_input(tmp_path: Path) -> None:
    # Codex #8: verify_bundle / verify_pair never raise.
    assert verify_bundle(tmp_path / "does-not-exist").status == "failed"
    from gatehouse.verify import verify_pair as _vp
    assert _vp(tmp_path / "nope", tmp_path / "nope.json").status == "failed"


def test_invalid_base64_signature_is_not_accepted(full_bundle: Path) -> None:
    # Codex #9: junk-prefixed base64 must not decode to the valid bytes.
    log = _log(full_bundle)
    sig = log["org_signature"]["signature"]
    log["org_signature"]["signature"] = "!!!" + sig
    assert verify_audit_log(log).status == "failed"


# --- Sign-off round 2 (both reviewers converged) --------------------------

def test_verify_pair_is_total_on_none_and_bad_types(tmp_path: Path) -> None:
    # Fable + Codex #8: verify_pair(None, ...) must return failed, not raise.
    from gatehouse.verify import verify_pair as _vp

    assert _vp(None, None).status == "failed"  # type: ignore[arg-type]
    assert _vp(123, 456).status == "failed"  # type: ignore[arg-type]
    assert _vp(tmp_path, None).status == "failed"  # type: ignore[arg-type]


def test_verify_pair_total_on_nonfinite_manifest_number(
    redacted_bundle: Path, full_bundle: Path
) -> None:
    # Codex sign-off: a non-finite JSON number in the manifest must not crash
    # the canonicalizer out of the verifier.
    raw = (redacted_bundle / "hash_manifest.json").read_text(encoding="utf-8")
    raw = raw.replace('"hash_alg": "sha256"', '"hash_alg": "sha256", "x": Infinity', 1)
    (redacted_bundle / "hash_manifest.json").write_text(raw, encoding="utf-8")
    report = verify_pair(redacted_bundle, full_bundle / "audit_log.json")
    assert report.status == "failed"


def test_operational_bundle_missing_payload_fails(full_bundle: Path, store: SessionStore) -> None:
    # Codex sign-off new-obs: a signed manifest naming only audit_log.json must
    # not authenticate — the full payload set is required.
    (full_bundle / "entries.ndjson").unlink()
    manifest = json.loads((full_bundle / "hash_manifest.json").read_text(encoding="utf-8"))
    manifest["files"].pop("entries.ndjson", None)
    (full_bundle / "hash_manifest.json").write_text(
        json.dumps(manifest, indent=2, ensure_ascii=False), encoding="utf-8"
    )
    _reseal_manifest(full_bundle, store)
    report = verify_bundle(full_bundle)
    assert report.status == "failed"
    assert "entries.ndjson" in report.failing_step


def test_operational_bundle_missing_session_seal_fails(full_bundle: Path, store: SessionStore) -> None:
    # Codex sign-off #6/#7: stripping the session_seal from a sealed bundle must
    # fail (the envelope would otherwise be unprotected).
    log = _log(full_bundle)
    log.pop("session_seal", None)
    (full_bundle / "audit_log.json").write_text(
        json.dumps(log, indent=2, ensure_ascii=False), encoding="utf-8"
    )
    _reseal_manifest(full_bundle, store)
    report = verify_bundle(full_bundle)
    assert report.status == "failed"
    assert "session_seal" in report.failing_step


def test_verify_pair_binds_redacted_representations(
    redacted_bundle: Path, full_bundle: Path, store: SessionStore
) -> None:
    # Codex sign-off new-obs: faithful NDJSON but a forged redacted audit_log.json
    # must fail — the three representations must agree.
    red_log = json.loads((redacted_bundle / "audit_log.json").read_text(encoding="utf-8"))
    red_log["entries"][0]["entry"]["provider"] = "forged"
    (redacted_bundle / "audit_log.json").write_text(
        json.dumps(red_log, indent=2, ensure_ascii=False), encoding="utf-8"
    )
    _reseal_manifest(redacted_bundle, store)
    report = verify_pair(redacted_bundle, full_bundle / "audit_log.json")
    assert report.status == "failed"


def test_schema_requires_core_envelope_fields(full_bundle: Path) -> None:
    # Codex sign-off #5: session_id alone is not enough.
    log = _log(full_bundle)
    log["session"] = {"session_id": "x"}  # drop org_id/environment/initiated_at
    report = verify_audit_log(log)
    assert report.status == "failed"
    assert "required field" in report.failing_step


def test_session_seal_covers_tamper_fails(full_bundle: Path) -> None:
    log = _log(full_bundle)
    log["session_seal"]["covers"] = "nothing"
    report = verify_audit_log(log)
    assert report.status == "failed"
    assert report.envelope_valid is False


def test_strict_mode_downgrades_partial_attribution(full_bundle: Path) -> None:
    # Codex #10: strict mode gives callers the bundle-grade policy on a log.
    log = _log(full_bundle)
    del log["entries"][0]["agent_signature"]
    assert verify_audit_log(log).status == "authenticated"  # lenient default
    assert verify_audit_log(log, strict=True).status == "failed"  # strict
