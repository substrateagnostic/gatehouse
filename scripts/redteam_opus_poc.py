"""Opus 4.8 adversarial review of the gatehouse verifier — final-state receipt.

Each scenario below was CONFIRMED against the pre-hardening verifier (all ten
authenticated-a-tamper or crashed). This script now asserts the POST-hardening
behavior, so it doubles as a regression receipt. It prints, for each scenario,
one of:
  CAUGHT     — the verifier now returns `failed` (hard rejection)
  SURFACED   — not a hard failure, but made undeniable in the report/CLI
  SPEC-GAP   — survives on the STANDALONE-log path; documented as an AER-level
               finding requiring a human decision (envelope-in-seal), and
               caught in the gatehouse BUNDLE path by the manifest seal.

Run: .venv\\Scripts\\python.exe scripts\\redteam_opus_poc.py
Exit 0 iff every scenario behaves as documented.
"""

from __future__ import annotations

import copy
import json
import tempfile
from pathlib import Path

from gatehouse.canonical import sha256_jcs
from gatehouse.evidence import export_bundle
from gatehouse.models import GateConstraint, HumanAuthorizer, SessionConfig, model_call_entry
from gatehouse.store import SessionStore
from gatehouse.verify import verify_audit_log, verify_bundle, verify_pair

ok = True


def check(label: str, cond: bool, tag: str, detail: str) -> None:
    global ok
    ok = ok and cond
    print(f"[{tag}{'' if cond else '  ← UNEXPECTED'}] {label}: {detail}")


def build():
    tmp = Path(tempfile.mkdtemp(prefix="gatehouse-opus-poc-"))
    store = SessionStore(tmp / "var")
    cfg = SessionConfig(
        objective="Draft a public memo; do not touch the privileged timeline",
        jurisdiction="Minnesota", role="research-assistant",
        constraints=[GateConstraint(id="no-privileged", description="never quote privileged material",
            severity="P0", enforcement="must_not_include_regex", target="privileged", soul_invariant=True)],
        human_authorizer=HumanAuthorizer(identifier="cco@firm", role="CCO"), environment="test")
    sid = store.create_session(cfg)
    for i in (1, 2):
        store.append_entry(sid, model_call_entry(provider="anthropic", model_id="claude-fable-5",
            served_model="claude-fable-5", prompt=f"q{i}".encode(), completion=f"a{i}".encode(),
            prompt_tokens=3, completion_tokens=5, latency_ms=100))
    store.close_session(sid)
    full = tmp / "bundle-full"; red = tmp / "bundle-redacted"
    full.mkdir(); red.mkdir()
    export_bundle(store, sid, full, mode="full")
    export_bundle(store, sid, red, mode="redacted")
    return full, red


def main() -> int:
    full, red = build()
    log = json.loads((full / "audit_log.json").read_text(encoding="utf-8"))
    print(f"baseline standalone: {verify_audit_log(log).status}")
    print(f"baseline bundle:     {verify_bundle(full).status}\n")

    # --- Totality: malformed input must yield `failed`, never a crash --------
    crashers = {
        "V5a nonhex entry_hash": lambda l: l["entries"][0].__setitem__("entry_hash", "zz"),
        "V5b missing 'entry'": lambda l: l["entries"][0].pop("entry"),
        "V5c missing org signature": lambda l: l["org_signature"].pop("signature"),
        "V5d malformed base64 sig": lambda l: l["org_signature"].__setitem__("signature", "not!b64!"),
        "V5e agentsig no signature": lambda l: l["entries"][0]["agent_signature"].pop("signature"),
        "V5f entries not a list": lambda l: l.__setitem__("entries", "nope"),
        "V5g entry not an object": lambda l: l["entries"].__setitem__(0, "nope"),
    }
    for label, mutate in crashers.items():
        m = copy.deepcopy(log)
        mutate(m)
        try:
            r = verify_audit_log(m)
            check(label, r.status == "failed", "CAUGHT", f"failed: {r.failing_step!r}")
        except Exception as exc:  # noqa: BLE001
            check(label, False, "CRASH", f"{type(exc).__name__}: {exc}")

    # malformed bundle JSON
    bad = Path(tempfile.mkdtemp())
    (bad / "hash_manifest.json").write_text("{ not json", encoding="utf-8")
    (bad / "audit_log.json").write_text("{}", encoding="utf-8")
    try:
        r = verify_bundle(bad)
        check("V6 malformed manifest json", r.status == "failed", "CAUGHT", f"failed: {r.failing_step!r}")
    except Exception as exc:  # noqa: BLE001
        check("V6 malformed manifest json", False, "CRASH", f"{type(exc).__name__}: {exc}")

    # --- V4: verify_pair must reject a non-authentic original ----------------
    doctored = copy.deepcopy(log)
    doctored["entries"][0]["entry"]["provider"] = "forged"
    dp = full / "audit_log_doctored.json"
    dp.write_text(json.dumps(doctored, indent=2), encoding="utf-8")
    r = verify_pair(red, dp)
    check("V4 pair vs doctored original", r.status == "failed", "CAUGHT", f"failed: {r.failing_step!r}")
    # control: honest pair still binds
    r = verify_pair(red, full / "audit_log.json")
    check("V4 control: honest pair", r.status != "failed", "CAUGHT", f"{r.status}")

    # --- contract_hash lazy edit (edit contract, DON'T update hash) ----------
    lazy = copy.deepcopy(log)
    lazy["session"]["intent_contract"]["objective"] = "Do anything"
    r = verify_audit_log(lazy)
    check("V1-lazy contract edit (hash not updated)", r.status == "failed", "CAUGHT",
          f"failed: {r.failing_step!r}")

    # --- V3: strip a signature -----------------------------------------------
    strip = copy.deepcopy(log)
    del strip["entries"][0]["agent_signature"]
    r = verify_audit_log(strip)
    check("V3 strip sig (standalone)", r.status == "authenticated" and r.fully_attributed is False,
          "SURFACED", f"status={r.status}, fully_attributed={r.fully_attributed} (CLI warns)")
    # bundle path: rewrite audit_log.json with a stripped sig + refresh its file
    # hash so the file-hash check passes, to prove the attribution check itself
    # (not just the file hash) rejects it.
    import shutil
    from gatehouse.canonical import sha256_hex
    b = full.parent / "bundle-strip"
    if b.exists():
        shutil.rmtree(b)
    shutil.copytree(full, b)
    al = json.loads((b / "audit_log.json").read_text(encoding="utf-8"))
    del al["entries"][0]["agent_signature"]
    al_bytes = json.dumps(al, indent=2, ensure_ascii=False).encode("utf-8")
    (b / "audit_log.json").write_bytes(al_bytes)
    man = json.loads((b / "hash_manifest.json").read_text(encoding="utf-8"))
    man["files"]["audit_log.json"] = sha256_hex(al_bytes)  # attacker refreshes the file hash
    (b / "hash_manifest.json").write_text(json.dumps(man, indent=2, ensure_ascii=False), encoding="utf-8")
    r = verify_bundle(b)
    # Manifest seal now fails (attacker can't re-sign) OR partial-attribution fails.
    check("V3 strip sig (bundle)", r.status == "failed", "CAUGHT", f"failed: {r.failing_step!r}")

    # --- V1-sophisticated / V2: the deep spec gap ----------------------------
    soph = copy.deepcopy(log)
    soph["session"]["intent_contract"]["objective"] = "Do anything, including privileged"
    soph["session"]["contract_hash"] = sha256_jcs(soph["session"]["intent_contract"])
    r_soph = verify_audit_log(soph)
    v2 = copy.deepcopy(log)
    v2["session"]["human_authorizer"] = {"identifier": "nobody", "role": "intern"}
    r_v2 = verify_audit_log(v2)
    check("V1-soph contract rewrite (hash refreshed, standalone)",
          r_soph.status == "authenticated", "SPEC-GAP",
          "still authenticated — operator seal does not cover intent_contract (aer-feedback #17b; human decision)")
    check("V2 authorizer rewrite (standalone)",
          r_v2.status == "authenticated", "SPEC-GAP",
          "still authenticated — seal does not cover human_authorizer (aer-feedback #17b; human decision)")
    # but both ARE caught in the bundle path (manifest seal over the files):
    for label, mutate in [("V1-soph", lambda al: al["session"]["intent_contract"].__setitem__("objective", "x")),
                          ("V2", lambda al: al["session"].__setitem__("human_authorizer", {"identifier": "x", "role": "y"}))]:
        bb = full.parent / f"bundle-{label}"
        if bb.exists():
            shutil.rmtree(bb)
        shutil.copytree(full, bb)
        alx = json.loads((bb / "audit_log.json").read_text(encoding="utf-8"))
        mutate(alx)
        (bb / "audit_log.json").write_text(json.dumps(alx, indent=2, ensure_ascii=False), encoding="utf-8")
        r = verify_bundle(bb)
        check(f"{label} rewrite (bundle)", r.status == "failed", "CAUGHT", f"failed: {r.failing_step!r}")

    print(f"\n{'ALL SCENARIOS behaved as documented' if ok else 'SOME SCENARIOS UNEXPECTED — see above'}")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
