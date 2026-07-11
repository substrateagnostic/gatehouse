# GATEHOUSE v0.1 — Definition of Done

Overnight one-shot, night of 2026-07-10 → 07-11. Every checkbox below must link
to evidence (a file path, a test name, a command + captured output) before it is
checked. Nothing is checked on vibes. Items that cannot be verified tonight are
marked **UNVERIFIED** in NEEDS_YOU.md — that costs one breath and is the honest
state.

North star: one process that sits between an agent and a model API — declared
scope in, constraint-checked traffic through, court-grade evidence out. Shadow
mode first: observe and annotate, never surprise anyone.

## 1. Evidence layer (AER v0.1, second implementation)

- [x] **E1 — JCS canonicalization is RFC 8785, not sorted-key stringify.**
      Evidence: uses `rfc8785` (Trail of Bits); vectors byte-identical to the TS
      impl's `jcs.test.ts`. → `tests/test_canonical.py`
- [x] **E2 — Hash chain matches §4.1 exactly**: `entry_hash` = SHA-256 hex of JCS
      of `{sequence, entry, previous_hash, authorized_by?}`; genesis links to
      `""`; `authorized_by` omitted entirely when absent.
      Evidence: golden-vector test reproducing a TS-produced `entry_hash`
      byte-for-byte. → `tests/test_chain.py`. Note: omit-vs-null on optional
      fields is the classic second-implementation ambiguity — §4.1 pins
      `authorized_by` omission, but the spec is silent on null-vs-omission
      elsewhere; that finding goes to aer-feedback regardless of whether the
      golden vectors pass.
- [x] **E3 — Merkle root is domain-separated (F9)**: leaf = `SHA256(0x00 ||
      hash_bytes)`, node = `SHA256(0x01 || L || R)`, odd node carried up (not
      duplicated), empty log → `""`.
      Evidence: golden vector vs TS `merkle_root`; anti-replay test. → `tests/test_merkle.py`
- [x] **E4 — Identity is a key, not a string (F1)**: per-agent Ed25519 key
      generated per session; `fingerprint` = `sha256:` + hex of raw 32-byte key;
      `public_key` = base64 of SPKI PEM. Verifier checks each signature against
      the SESSION key, and rejects entries signed by a different (valid) key.
      Evidence: forgery regression. → `tests/test_signatures.py`, QA Q3.
- [x] **E5 — Seal per §4.2**: operator Ed25519 signature over JCS of
      `{session_id, merkle_root, entry_count, closed_at, schema_version,
      agent_fingerprint, canonicalization}` — matched to the TS impl. NOTE
      (Fable): the member-OMISSION path (absent closed_at/agent_fingerprint) is
      inferred from JS semantics, not cross-verified — gatehouse always populates
      them, so it is not exercised. Evidence: cross-verified seal (C1/C2).
- [x] **E6 — Tri-state verdict (F2)**: `authenticated` /
      `consistent_unattributed` / `failed`, never a bare boolean; `failed` names
      the failing step; unsigned logs are never blessed.
      Evidence: → `tests/test_verdict.py` (incl. cross-impl TS fixture).
- [x] **E7 — Surrogate rejection (F8)**: canonicalization rejects lone
      surrogates (value, key, and array element). → `tests/test_canonical.py`.
- [x] **E8 — `served_model` recorded** on every model_call entry: the
      provider-asserted model ID from the response body, so stepdowns/reroutes
      are visible. Honest reroute → AUTHENTICATED + surfaced; record-vs-entry
      disagreement → failed. Evidence: → `tests/test_served_model.py` +
      `evidence/qa/served_model_live_sample.txt` (one real call; note: a live
      reroute has never actually occurred — the mechanism is exercised by the
      stub/demo/tests only).
- [x] **E9 — Dual bundles with binding manifest (F3, §5)**: full + redacted
      export; `source_entry_hash` per derived entry; manifest carries the full
      field set; operator signature over JCS of manifest minus signature.
      verify_pair enforces per-entry correspondence AND reconstructs the expected
      redaction (Codex #3). Evidence: → `tests/test_bundles.py`,
      `tests/test_verifier_hardening.py`.

## 2. Proxy core

- [x] **P1 — OpenAI pass-through**: `/v1/chat/completions` forwarded to
      api.openai.com. HONEST SCOPE (Fable review): NON-streaming request/response
      body is forwarded faithfully; **streaming returns a structured 501 —
      UNVERIFIED**; auth headers are forwarded but the header set is a whitelist,
      not full transparency. `/v1/responses` not implemented.
      Evidence: stub-server round trip. → `tests/test_proxy_openai.py`
- [x] **P2 — Anthropic pass-through**: `/v1/messages` forwarded to
      api.anthropic.com; same scope as P1 (non-streaming solid; streaming 501).
      Evidence: → `tests/test_proxy_anthropic.py`; one real live call in
      `evidence/qa/served_model_live_sample.txt`.
- [x] **P3 — Per-session intent contract**: session opened with
      `{objective, jurisdiction, role, constraints[], revision_policy,
      human_authorizer, signing}`; contract JCS-hashed into the record
      (`contract_hash`); descends from the PrismWeft schema.
      Evidence: schema tests + contract lands in emitted AER. → `tests/test_contract.py`
- [x] **P4 — Shadow mode default**: constraint findings annotate the record,
      never alter traffic. Per-constraint `on_violation: flag | block` opt-in;
      blocking returns a structured refusal that is itself recorded.
      Evidence: `tests/test_shadow.py` asserts the response body is byte-equal to
      the upstream's in default mode (Fable review called this the strongest
      test in the suite).

## 3. Check layer (FCE)

- [x] **C-FCE1 — FCE runtime imported** (not reimplemented); constraints
      evaluated per request/response. HONEST SCOPE (Fable review): the FCE
      enclave, as installed, natively text-checks only `must_not_include_regex`;
      `must_include_heading` / `must_include_regex` are evaluated by gatehouse's
      own presence check (`checks.py`) and mapped onto the FCE disposition
      pipeline. Disclosed at length in the `checks.py` module docstring.
      Evidence: `tests/test_check_layer.py` (all three kinds fire).
- [x] **C-FCE2 — `correct_continue` is a first-class disposition**: a checked
      response is annotated-and-continued, not just pass/refuse. On
      `correct_continue` the "witness" is a `content_hash` plus the honest FCE
      stand-down note ("stand-down is not an affirmative safety proof") — NOT a
      cryptographic proof object; the word "witness" here is the FCE runtime's
      term. A proxy that can only refuse is a firewall, not a fiduciary.
      Evidence: `tests/test_check_layer.py`.

## 4. CLI

- [x] **CLI1 — `gatehouse produce <session>`** emits the §4-shaped evidence
      packet (full + redacted dual bundles + binding manifest). Also `gatehouse
      demo` runs the whole pipeline cold. Evidence: `evidence/conformance/`.
- [x] **CLI2 — `gatehouse eval <config>`** runs the FCE 33-scenario suite
      against a config. Verified BOTH fixtures (`evidence/qa/eval_fixtures_cold_run.txt`)
      AND **live** against claude-sonnet-5 (`evidence/qa/eval_live_anthropic_run.txt`,
      33×4 arms). Live run reproducible with a key.
- [x] **CLI3 — `gatehouse verify <bundle>`** re-verifies any emitted bundle
      offline and prints the tri-state verdict. Evidence: demo + PoC output.

## 5. Conformance (second-implementation duty)

- [x] **C1 — TS verifier accepts GATEHOUSE bundles**: the agentledger CLI
      `verify` returns AUTHENTICATED on a gatehouse-produced bundle — including
      one carrying the `served_model` extension AND the `session_seal` field
      (both ignored by the TS `JSON.parse` path). Independently re-run by the
      Fable reviewer. Evidence: `evidence/conformance/`.
- [x] **C2 — verify-pair passes** on a gatehouse full+redacted pair via the TS
      verifier: "faithful derivation," exit 0. Evidence: `evidence/conformance/`.
- [x] **C3 — Spec feedback logged**: 18 items in `docs/aer-feedback.md` with
      section references (incl. #17b, the envelope-seal gap). NOTE (Fable): this
      is a second implementation *fitted to the reference* at the under-specified
      points (that fitting IS the feedback list) — a genuine interop proof, not
      "two blind readers of the spec converged."

## 6. QA self-pass (before dawn, with receipts)

All receipts under `evidence/qa/` (`tamper_pass_receipts.txt` 10/10;
`opus_verifier_review_receipts.txt`). The verifier MUST reject, with named step:
- [x] **Q1 — modified entry** (payload edited after seal)
- [x] **Q2 — broken chain link** (entry removed / reordered / previous_hash cut)
- [x] **Q3 — signature from a non-session key** (valid key, wrong session — the F1 forgery)
- [x] **Q4 — served_model: tampering rejected, honest anomaly preserved.** Two
      halves, both required (Alex, 2026-07-11): (a) a record whose
      evidence-record projection disagrees with its chained entries on
      served_model, or whose served_model was edited post-seal, MUST fail
      verification with a named step; (b) an HONEST record of a
      served≠requested mismatch MUST verify AUTHENTICATED with the mismatch
      surfaced in the report. A reroute is not tampering. The evidence layer
      makes the mismatch undeniable, not unrecordable — a verifier that
      conflates "record altered" with "record documents something irregular"
      inverts the instrument.
- [x] **Q5 — redacted-pair tamper** (dropped/reordered/substituted derived entry
      → verify-pair fails; now also rejects substituted content via redaction
      reconstruction, Codex #3)
- [x] **Q6 — external red-team pass**: Codex GPT-5.6-Sol xhigh QA review
      completed (survived the classifier this time; QA framing) +
      `evidence/qa/codex_gpt56sol_qa_review.txt`; Opus 4.8 in-context adversarial
      pass; the earlier classifier ejection is preserved as an exhibit
      (`docs/redteam/2026-07-11-classifier-ejection-exhibit.md`). All findings
      fixed across two rounds; **two independent reviewers APPROVE** (Fable 5 +
      a rerouted Opus 4.8; gpt-5.6-sol did the round-1 review then was ejected on
      round-2). See `docs/redteam/2026-07-11-fixes-applied.md` +
      `2026-07-11-opus-signoff.md`.

## 7. Morning artifact

- [x] **M1 — `NEEDS_YOU.md`**: written — TL;DR, cold demo command, evidence
      paths, honest UNVERIFIED list, AER feedback, served_model sample, the four
      human decisions, and the two-reviewer sign-off result.

## Out of scope tonight (recorded so absence is a decision, not an accident)

- Public repo / publishing (human decision), Docker image build (pipx-style
  local install is the target; Dockerfile MAY be drafted but not required),
  key custody hardening (HSM/keystore), append-only remote shipping, OTel
  attribute emission, `/v1/responses` full coverage.
