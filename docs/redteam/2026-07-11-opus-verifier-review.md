# Opus 4.8 adversarial review of the gatehouse verifier — 2026-07-11

Reviewer: the Opus 4.8 director (the sanctioned fallback after the cyber
classifier ejected the external route — see the ejection exhibit in this
directory). Read-only adversarial pass over `verify.py`, `evidence.py`,
`chain.py`, `merkle.py`, `keys.py`. Every finding was reproduced with a
proof-of-concept before any fix (`scripts/redteam_opus_poc.py`), and the fixes
are locked by `tests/test_verifier_hardening.py` (19 tests). A parallel QA pass
by Codex GPT-5.6-Sol xhigh is recorded in
`evidence/qa/codex_gpt56sol_qa_review.txt`.

Ten candidate findings, all confirmed against the pre-hardening verifier.
Disposition after the pass:

## Fixed — verifier totality (a verifier that crashes is a denial-of-evidence)

The verifier threw an unhandled exception on several malformed inputs instead
of returning a `failed` verdict. A record that crashes the verifier can't be
adjudicated — for a court-grade instrument that is itself a failure mode. All
now return `failed` with a named step:

| id | input | was | now |
|----|-------|-----|-----|
| V5a | non-hex `entry_hash` | `ValueError` from `bytes.fromhex` in Merkle | `failed` |
| V5b | entry missing its `entry` member | `KeyError` in `chain.verify_chain` | `failed` |
| V5c | `org_signature` missing `signature` | `KeyError` | `failed` |
| V5d | malformed base64 signature | `binascii.Error` in `keys.verify_signature` | `failed` |
| V5e | `agent_signature` missing `signature` | `KeyError` | `failed` |
| V5f/g | `entries` not a list / entry not an object | `AttributeError` | `failed` |
| V6 | unparseable bundle JSON | `JSONDecodeError` in `verify_bundle`/`verify_pair` | `failed` |

Fixes: `keys.verify_signature` now catches decode/type errors; `chain.verify_chain`
guards non-dict entries, a missing `entry`, and non-canonicalizable payloads;
`verify._core`'s Merkle computation is guarded; `verify_audit_log` /
`verify_bundle` / `verify_pair` wrap their bodies and JSON reads so any
unforeseen exception becomes a `failed` verdict.

## Fixed — verify_pair trusted the original (V4)

`verify_pair` compared a redacted bundle against the *stored* `entry_hash`
values of the "original" without ever verifying the original. A "faithful
derivation" claim against a non-authentic original is meaningless: a forger
could pair a redacted bundle to a doctored original and get a green result.
Fix: `verify_pair` now runs `verify_audit_log(original)` first and refuses
(`failed`) if the original does not itself verify (an unsigned but
internally-consistent original is still an acceptable source).

## Fixed — contract_hash was reported but not enforced (V1, lazy variant)

`contract_hash` is a §3.5 MUST, but the verifier (mirroring the reference)
only *reported* it. So an intent-contract edit that didn't bother to update
`contract_hash` still authenticated. Fix: gatehouse now **enforces**
`contract_hash` on any sealed or agent-signed log (a `derived_redacted` log is
exempt — it deliberately retains the original hash against a redacted
contract). This is a deliberate divergence from the reference toward
strictness (aer-feedback #6).

## Fixed — signature stripping was invisible in the verdict (V3)

`agent_signature` is not covered by the entry hash, so on a standalone log an
attacker with no key can strip one entry's signature; chain, Merkle, and seal
all still verify. Fix: the report now carries `fully_attributed`; the CLI
prints a **PARTIAL ATTRIBUTION** warning; and `verify_bundle` — gatehouse's own
format, where every entry is always signed — hard-fails an otherwise
authenticated bundle that is not fully attributed. (In practice a bundle strip
is already caught by the manifest seal; this is defense in depth for the
standalone path.)

## The headline finding — the operator seal does not cover the session envelope (V1-sophisticated, V2) — HUMAN DECISION

The operator seal (AER §4.2) signs `{session_id, merkle_root, entry_count,
closed_at, schema_version, agent_fingerprint, canonicalization}`. It binds the
**entry set** (via `merkle_root`) and a few session scalars — but **not** the
rest of the session envelope: `intent_contract`, `human_authorizer`, `org_id`,
`compliance_contexts`, `policy_context`, `retention_days`, `metadata`.

Consequence: on a **standalone** audit log, an adversary holding no key can
rewrite the intent contract (and refresh `contract_hash` — just a SHA, no key)
or replace the human authorizer, and the log still verifies **authenticated**.
This directly undermines a stated purpose of the record (§3.5: "so a reviewer
can compare what the agent was authorized to do against what §3.3 shows it
did") — the authorized-scope baseline is exactly what an adversary can rewrite.

This is **shared with the TypeScript reference** (identical seal member set),
so it is an **AER-spec-level** finding, not a gatehouse bug. It is caught in
the gatehouse **bundle** path (the manifest seals the file bytes), but the spec
explicitly promises the *record alone* is offline-verifiable (§1, §8), so the
standalone gap is real.

It is **not** fixed tonight because every fix trades something a human should
weigh:
- Binding an envelope hash into the operator seal **changes the seal
  construction** and breaks byte-for-byte interop with the reference verifier
  (conformance item C1 would fail). That is a spec-version decision (AER v0.2),
  not a 3am unilateral change.
- An *additive* second seal over the envelope is interop-safe but strippable
  without out-of-band trust in the producer, so it only stops the careless
  tamperer — which the `contract_hash` enforcement already does for the
  contract.

Recommendation (for Alex + web-Fable): fold full session-envelope coverage into
the operator seal in **AER v0.2** and re-baseline the reference, OR state
explicitly in the spec that the standalone seal covers `{entry set + session
scalars}` only and the envelope's integrity is a transport/storage property.
Logged as **aer-feedback #17b**.

## Not a finding (asserted for the record)

- An **honestly recorded** `served_model` reroute (served != requested)
  verifies **authenticated** with the mismatch surfaced — this is correct, per
  Alex's directive: a reroute is not tampering. Only a record that *disagrees
  with itself* about served_model (projection vs chained entry) fails.
