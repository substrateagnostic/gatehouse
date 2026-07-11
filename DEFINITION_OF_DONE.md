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

- [ ] **E1 — JCS canonicalization is RFC 8785, not sorted-key stringify.**
      Evidence: uses `rfc8785` (Trail of Bits); test vector cross-checked against
      the TS impl's canonical bytes. → `tests/test_canonical.py`
- [ ] **E2 — Hash chain matches §4.1 exactly**: `entry_hash` = SHA-256 hex of JCS
      of `{sequence, entry, previous_hash, authorized_by?}`; genesis links to
      `""`; `authorized_by` omitted entirely when absent.
      Evidence: golden-vector test reproducing a TS-produced `entry_hash`
      byte-for-byte. → `tests/test_chain.py`. Note: omit-vs-null on optional
      fields is the classic second-implementation ambiguity — §4.1 pins
      `authorized_by` omission, but the spec is silent on null-vs-omission
      elsewhere; that finding goes to aer-feedback regardless of whether the
      golden vectors pass.
- [ ] **E3 — Merkle root is domain-separated (F9)**: leaf = `SHA256(0x00 ||
      hash_bytes)`, node = `SHA256(0x01 || L || R)`, odd node carried up (not
      duplicated), empty log → `""`.
      Evidence: golden vector vs TS `merkle_root`; a test proving an internal
      node cannot be replayed as a leaf. → `tests/test_merkle.py`
- [ ] **E4 — Identity is a key, not a string (F1)**: per-agent Ed25519 key
      generated per session; `fingerprint` = `sha256:` + hex of raw 32-byte key;
      `public_key` = base64 of SPKI PEM. Verifier checks each signature against
      the SESSION key, and rejects entries signed by a different (valid) key.
      Evidence: forgery regression test — a validly-signed entry from a
      non-session key must fail. → `tests/test_signatures.py`
- [ ] **E5 — Seal per §4.2**: operator Ed25519 signature over JCS of
      `{session_id, merkle_root, entry_count, closed_at, schema_version,
      agent_fingerprint, canonicalization}` — exact member set/values matched to
      the TS impl. Evidence: cross-verified seal (see C1/C2).
- [ ] **E6 — Tri-state verdict (F2)**: verifier reports `authenticated` /
      `consistent_unattributed` / `failed`, never a bare boolean; `failed` names
      the failing step; unsigned logs are never blessed.
      Evidence: three tests, one per verdict. → `tests/test_verdict.py`
- [ ] **E7 — Surrogate rejection (F8)**: canonicalization rejects lone
      surrogates in strings rather than silently mangling.
      Evidence: test with an unpaired surrogate → hard error. → `tests/test_canonical.py`
- [ ] **E8 — `served_model` recorded** on every model_call entry: the
      provider-asserted model ID from the response body (not the requested
      model), so silent stepdowns/reroutes are visible. Requested vs served
      mismatch is surfaced in the record and flagged by the verifier report.
      Evidence: unit test + a live or replayed sample in evidence/. → `tests/test_served_model.py`
- [ ] **E9 — Dual bundles with binding manifest (F3, §5)**: full + redacted
      export; redacted entries carry `source_entry_hash`; manifest carries
      `bundle_kind`, `source_entry_count`, ORDERED `source_entry_hashes`,
      `source_last_entry_hash`, `derived_last_entry_hash`, per-file SHA-256s,
      original `contract_hash`, redaction rule id, `hash_alg`; operator
      signature over JCS of manifest minus signature. Verify-pair enforces
      per-entry correspondence.
      Evidence: round-trip test + tamper test (dropped entry → fail). → `tests/test_bundles.py`

## 2. Proxy core

- [ ] **P1 — OpenAI pass-through**: `/v1/chat/completions` (and
      `/v1/responses` if time permits) forwarded byte-faithfully to
      api.openai.com; streaming and non-streaming.
      Evidence: recorded round trip (live if key available, else stub-server
      test). → `tests/test_proxy_openai.py`
- [ ] **P2 — Anthropic pass-through**: `/v1/messages` forwarded to
      api.anthropic.com; streaming and non-streaming.
      Evidence: same standard as P1. → `tests/test_proxy_anthropic.py`
- [ ] **P3 — Per-session intent contract**: session opened with
      `{objective, jurisdiction, role, constraints[], revision_policy,
      human_authorizer, signing}`; contract JCS-hashed into the record
      (`contract_hash`); descends from the PrismWeft schema.
      Evidence: schema tests + contract lands in emitted AER. → `tests/test_contract.py`
- [ ] **P4 — Shadow mode default**: constraint findings annotate the record,
      never alter traffic. Per-constraint `on_violation: flag | block` opt-in;
      blocking returns a structured refusal that is itself recorded.
      Evidence: test proving default mode never mutates a response. → `tests/test_shadow.py`

## 3. Check layer (FCE)

- [ ] **C-FCE1 — FCE runtime imported** (not reimplemented); applicable
      constraints evaluated per request/response.
      Evidence: integration test with at least 3 constraint kinds firing. → `tests/test_check_layer.py`
- [ ] **C-FCE2 — `correct_continue` is a first-class disposition**: a checked
      response can be annotated-and-continued with a proof-carrying witness,
      not just pass/refuse. A proxy that can only refuse is a firewall, not a
      fiduciary.
      Evidence: test where a violation yields correct_continue with witness
      recorded in the evidence log. → `tests/test_check_layer.py`

## 4. CLI

- [ ] **CLI1 — `gatehouse produce <session>`** emits the §4-shaped evidence
      packet (full + redacted dual bundles + binding manifest) from a stored
      session. Evidence: cold-run command + output in evidence/.
- [ ] **CLI2 — `gatehouse eval <config>`** runs the FCE 33-scenario suite
      against a live config (provider/model/key from config).
      Evidence: cold-run against at least a stub or one live model; output
      captured. If no API key is available tonight → UNVERIFIED (live), with
      the stub run as partial evidence.
- [ ] **CLI3 — `gatehouse verify <bundle>`** re-verifies any emitted bundle
      offline and prints the tri-state verdict. Evidence: cold-run output.

## 5. Conformance (second-implementation duty)

- [ ] **C1 — TS verifier accepts GATEHOUSE bundles** where profiles overlap:
      the agentledger CLI verify command returns AUTHENTICATED on a
      GATEHOUSE-produced bundle. Evidence: command + captured output in
      evidence/conformance/. If C1 fails, the deliverable is the DIAGNOSIS of
      which implementation diverged — disagreement between two independent
      implementations is a spec bug by definition, and possibly the most
      valuable artifact of the night.
- [ ] **C2 — verify-pair passes** on a GATEHOUSE full+redacted pair via the TS
      verifier (if the TS CLI exposes it for external bundles; else via TS
      library calls in a small harness). Evidence: captured output; else
      UNVERIFIED with the blocker named.
- [ ] **C3 — Spec feedback logged**: every ambiguity/gap found while
      implementing from SPEC.md alone → `docs/aer-feedback.md`. Evidence: the
      file, with section references.

## 6. QA self-pass (before dawn, with receipts)

All receipts under `evidence/qa/`. The verifier MUST reject, with named step:
- [ ] **Q1 — modified entry** (payload edited after seal)
- [ ] **Q2 — broken chain link** (entry removed / reordered / previous_hash cut)
- [ ] **Q3 — signature from a non-session key** (valid key, wrong session — the F1 forgery)
- [ ] **Q4 — served_model: tampering rejected, honest anomaly preserved.** Two
      halves, both required (Alex, 2026-07-11): (a) a record whose
      evidence-record projection disagrees with its chained entries on
      served_model, or whose served_model was edited post-seal, MUST fail
      verification with a named step; (b) an HONEST record of a
      served≠requested mismatch MUST verify AUTHENTICATED with the mismatch
      surfaced in the report. A reroute is not tampering. The evidence layer
      makes the mismatch undeniable, not unrecordable — a verifier that
      conflates "record altered" with "record documents something irregular"
      inverts the instrument.
- [ ] **Q5 — redacted-pair tamper** (dropped/reordered derived entry → verify-pair fails)
- [ ] **Q6 — external red-team pass** (Codex if reachable, else Opus 4.8
      subagent); findings triaged; any classifier-ejection transcript saved as
      an exhibit.

## 7. Morning artifact

- [ ] **M1 — `NEEDS_YOU.md`**: what exists, evidence paths, one demo command
      that works cold, QA results, UNVERIFIED list, AER feedback list,
      served_model sample, human-only decisions (name, license, publish-or-hold).

## Out of scope tonight (recorded so absence is a decision, not an accident)

- Public repo / publishing (human decision), Docker image build (pipx-style
  local install is the target; Dockerfile MAY be drafted but not required),
  key custody hardening (HSM/keystore), append-only remote shipping, OTel
  attribute emission, `/v1/responses` full coverage.
