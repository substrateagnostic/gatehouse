"""QA self-pass: prove the verifier rejects what it must and preserves what
it must (DEFINITION_OF_DONE §6, Q1-Q5).

Builds a real session, exports bundles, then runs each tamper scenario on a
COPY. Prints one receipt line per scenario; exits nonzero if any scenario
does not behave as required. Run:
    .venv\\Scripts\\python.exe scripts\\qa_tamper_pass.py
"""

from __future__ import annotations

import json
import shutil
import sys
import tempfile
from pathlib import Path

from gatehouse.evidence import export_bundle
from gatehouse.keys import AgentKey
from gatehouse.models import (
    GateConstraint,
    HumanAuthorizer,
    SessionConfig,
    model_call_entry,
    tool_invocation_entry,
)
from gatehouse.store import SessionStore
from gatehouse.verify import verify_audit_log, verify_bundle, verify_pair

PASS = "PASS"
FAIL = "FAIL"
results: list[tuple[str, str, str]] = []


def record(qid: str, ok: bool, detail: str) -> None:
    results.append((qid, PASS if ok else FAIL, detail))
    print(f"[{PASS if ok else FAIL}] {qid}: {detail}")


def fresh_copy(src: Path, tag: str) -> Path:
    dst = src.parent / f"{src.name}-{tag}"
    if dst.exists():
        shutil.rmtree(dst)
    shutil.copytree(src, dst)
    return dst


def load_log(bundle: Path) -> dict:
    return json.loads((bundle / "audit_log.json").read_text(encoding="utf-8"))


def dump_log(bundle: Path, log: dict) -> None:
    (bundle / "audit_log.json").write_text(
        json.dumps(log, indent=2, ensure_ascii=False), encoding="utf-8", newline="\n"
    )


def main() -> int:
    tmp = Path(tempfile.mkdtemp(prefix="gatehouse-qa-"))
    store = SessionStore(tmp / "var")
    cfg = SessionConfig(
        objective="QA tamper pass",
        jurisdiction="Minnesota",
        constraints=[
            GateConstraint(
                id="no-privileged",
                description="never quote privileged material",
                severity="P0",
                enforcement="must_not_include_regex",
                target="privileged",
                soul_invariant=True,
            )
        ],
        human_authorizer=HumanAuthorizer(identifier="qa@gatehouse", role="qa"),
        environment="test",
    )
    sid = store.create_session(cfg)
    store.append_entry(
        sid,
        model_call_entry(
            provider="anthropic",
            model_id="claude-fable-5",
            served_model="claude-sonnet-5",  # an honest reroute, recorded
            prompt=b"q1",
            completion=b"a1",
            prompt_tokens=3,
            completion_tokens=5,
            latency_ms=100,
        ),
    )
    store.append_entry(
        sid,
        tool_invocation_entry(
            tool_name="search",
            input_bytes=b"in",
            output_bytes=b"out",
            duration_ms=10,
            success=True,
            resources_accessed=[
                {"type": "api", "identifier": "internal://search", "operation": "read"}
            ],
        ),
    )
    store.append_entry(
        sid,
        model_call_entry(
            provider="anthropic",
            model_id="claude-fable-5",
            served_model="claude-fable-5",
            prompt=b"q2",
            completion=b"a2",
            prompt_tokens=3,
            completion_tokens=5,
            latency_ms=90,
        ),
    )
    store.close_session(sid)

    full = tmp / "bundle-full"
    red = tmp / "bundle-redacted"
    full.mkdir()
    red.mkdir()
    export_bundle(store, sid, full, mode="full")
    export_bundle(store, sid, red, mode="redacted")

    # Baseline: untampered bundle authenticates; honest reroute surfaced (Q4a)
    base = verify_bundle(full)
    record(
        "Q4a-honest-reroute",
        base.status == "authenticated"
        and any(m["served_model"] == "claude-sonnet-5" for m in base.served_model_mismatches),
        f"status={base.status}, mismatches={base.served_model_mismatches} "
        "(a reroute recorded honestly verifies AUTHENTICATED and is surfaced, not rejected)",
    )

    # Q1 — modified entry payload after seal
    q1 = fresh_copy(full, "q1")
    log = load_log(q1)
    log["entries"][1]["entry"]["tool_name"] = "exfiltrate"
    dump_log(q1, log)
    r = verify_audit_log(load_log(q1))
    record(
        "Q1-modified-entry",
        r.status == "failed" and r.failing_step is not None and "1" in r.failing_step,
        f"status={r.status}, step={r.failing_step!r}",
    )

    # Q2a — broken chain link: entry removed
    q2 = fresh_copy(full, "q2a")
    log = load_log(q2)
    del log["entries"][1]
    dump_log(q2, log)
    r = verify_audit_log(load_log(q2))
    record("Q2a-entry-removed", r.status == "failed", f"status={r.status}, step={r.failing_step!r}")

    # Q2b — broken chain link: previous_hash cut
    q2b = fresh_copy(full, "q2b")
    log = load_log(q2b)
    log["entries"][2]["previous_hash"] = "0" * 64
    dump_log(q2b, log)
    r = verify_audit_log(load_log(q2b))
    record("Q2b-prev-hash-cut", r.status == "failed", f"status={r.status}, step={r.failing_step!r}")

    # Q2c — reordered entries (sequence swap)
    q2c = fresh_copy(full, "q2c")
    log = load_log(q2c)
    log["entries"][0], log["entries"][1] = log["entries"][1], log["entries"][0]
    dump_log(q2c, log)
    r = verify_audit_log(load_log(q2c))
    record("Q2c-reordered", r.status == "failed", f"status={r.status}, step={r.failing_step!r}")

    # Q3 — signature from a valid NON-SESSION key (the F1 forgery):
    # attacker key signs the entry hash; embedded key+fingerprint are the
    # attacker's own and self-consistent — only session binding catches it.
    q3 = fresh_copy(full, "q3")
    log = load_log(q3)
    attacker = AgentKey.generate()
    target = log["entries"][0]
    target["agent_signature"] = {
        "fingerprint": attacker.fingerprint,
        "public_key": attacker.public_b64,
        "signature": attacker.sign_entry_hash(target["entry_hash"]),
    }
    dump_log(q3, log)
    r = verify_audit_log(load_log(q3))
    record(
        "Q3-non-session-key",
        r.status == "failed" and "signature" in (r.failing_step or "").lower(),
        f"status={r.status}, step={r.failing_step!r} "
        "(valid signature, self-consistent key — rejected on session binding alone)",
    )

    # Q4b — served_model projection disagreement (record-integrity, not anomaly):
    # tamper evidence_record.json only -> caught by manifest file hash
    q4 = fresh_copy(full, "q4b")
    rec_path = q4 / "evidence_record.json"
    rec = json.loads(rec_path.read_text(encoding="utf-8"))
    rec["operations"][0]["served_model"] = "claude-fable-5"  # hide the reroute
    rec_path.write_text(json.dumps(rec, indent=2, ensure_ascii=False), encoding="utf-8", newline="\n")
    r = verify_bundle(q4)
    record(
        "Q4b-projection-tamper",
        r.status == "failed",
        f"status={r.status}, step={r.failing_step!r} "
        "(hiding a recorded reroute in the projection is tampering and is rejected)",
    )

    # Q5a — redacted-pair: derived entry dropped
    q5 = fresh_copy(red, "q5a")
    lines = (q5 / "entries.ndjson").read_text(encoding="utf-8").splitlines()
    (q5 / "entries.ndjson").write_text("\n".join(lines[:-1]) + "\n", encoding="utf-8", newline="\n")
    r = verify_pair(q5, full / "audit_log.json")
    record("Q5a-derived-drop", r.status == "failed", f"status={r.status}, step={r.failing_step!r}")

    # Q5b — redacted-pair: manifest source list rewritten (drop-and-reseal
    # without the true original fails against the real original's hashes)
    q5b = fresh_copy(red, "q5b")
    man_path = q5b / "hash_manifest.json"
    man = json.loads(man_path.read_text(encoding="utf-8"))
    man["source_entry_hashes"] = man["source_entry_hashes"][::-1]
    man_path.write_text(json.dumps(man, indent=2, ensure_ascii=False), encoding="utf-8", newline="\n")
    r = verify_pair(q5b, full / "audit_log.json")
    record("Q5b-source-list-rewrite", r.status == "failed", f"status={r.status}, step={r.failing_step!r}")

    # Control: untampered pair still binds
    r = verify_pair(red, full / "audit_log.json")
    record("control-pair-ok", r.status != "failed", f"status={r.status}")

    failures = [x for x in results if x[1] == FAIL]
    print(f"\n{len(results) - len(failures)}/{len(results)} scenarios behaved as required")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
