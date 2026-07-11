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
    log["session"]["intent_contract"]["objective"] = "Do something entirely different"
    # attacker does NOT update contract_hash
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

def test_envelope_rewrite_is_a_documented_standalone_gap(full_bundle: Path) -> None:
    """The operator seal does not cover the session envelope, so on the
    STANDALONE log a determined tamperer who also refreshes contract_hash can
    rewrite intent_contract/human_authorizer and still authenticate. This is
    the headline AER-level finding (aer-feedback #17b) — asserted here so the
    gap is tracked and its later closure is visible as a test change."""
    log = _log(full_bundle)
    log["session"]["intent_contract"]["objective"] = "Do anything at all"
    log["session"]["contract_hash"] = sha256_jcs(log["session"]["intent_contract"])
    assert verify_audit_log(log).status == "authenticated"  # documented gap


def test_envelope_rewrite_is_caught_in_the_bundle_path(full_bundle: Path) -> None:
    log = _log(full_bundle)
    log["session"]["human_authorizer"] = {"identifier": "nobody", "role": "intern"}
    (full_bundle / "audit_log.json").write_text(
        json.dumps(log, indent=2, ensure_ascii=False), encoding="utf-8"
    )
    assert verify_bundle(full_bundle).status == "failed"
