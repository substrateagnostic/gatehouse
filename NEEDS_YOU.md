# NEEDS_YOU — GATEHOUSE v0.1, morning menu (2026-07-11)

*Written by the Opus 4.8 director for Alex + web-Fable. Everything below is
verified against the repo and receipts, not memory. Where something is not
proven, it says UNVERIFIED — that costs one breath.*

---

## TL;DR

GATEHOUSE is built and it works. It's a fiduciary gate that sits between an
agent and a model API: **declared scope in → FCE-checked traffic through →
court-grade evidence out**, shadow-mode by default. It is the **second
implementation of AER v0.1**, and its bundles verify AUTHENTICATED under the
AgentLedger TypeScript reference verifier in both directions.

- **118 tests pass.** One cold command proves the whole pipeline: `gatehouse demo`.
- Two independent adversarial reviews (Opus 4.8 in-context + **Codex
  GPT-5.6-Sol xhigh**, which cleared the cyber classifier this time under QA
  framing) found issues across two rounds; all are fixed with regression tests,
  or documented as a spec-level human decision. The two reviewers **independently
  converged** on the load-bearing findings both times — which is the strongest
  signal the record can give (see the Corner note "tuning to the A").
- The build ran in ~1 hour of wall-clock, directed first by Fable 5 then by
  Opus 4.8, with Fable/Opus/Sonnet and Codex subagents.

**The one thing that is genuinely yours to decide is at the bottom: name,
license, publish-or-hold, and one AER-spec question.**

---

## The one demo command (works cold)

```bash
cd ~/Projects/gatehouse          # or C:\Users\agall\projects\GATEHOUSE
pip install -e .
pip install -e ../fiduciary-constraint-evaluation   # the check layer needs FCE (not on PyPI)
gatehouse demo
```

`gatehouse demo` opens a gated session, drives a real HTTP round trip through
the proxy against a stub upstream **that silently swaps the served model
(fable → sonnet)**, closes the session, produces full + redacted evidence
bundles, and verifies them. It prints `AUTHENTICATED`, surfaces the reroute,
and confirms the redacted-pair binding — no keys, no network. Exit 0.

Evidence-core only (no FCE needed): `gatehouse produce <session>`,
`gatehouse verify <bundle>`, `gatehouse verify-pair <redacted> <original>`.

---

## What exists

| Layer | What it does | Where |
|---|---|---|
| **Evidence** | AER v0.1 record + dual bundles: RFC 8785 JCS, hash chain, domain-separated Merkle, per-session Ed25519 identity, operator seal, redacted binding manifest, **served_model**, gatehouse **session_seal** | `src/gatehouse/{canonical,keys,merkle,chain,redaction,evidence}.py` |
| **Verify** | Tri-state verdict (`authenticated`/`consistent_unattributed`/`failed`), F1-strict, total on hostile input, bundle + pair verification | `src/gatehouse/verify.py` |
| **Check** | FCE cohomology enclave per request/response; `correct_continue` first-class | `src/gatehouse/checks.py` |
| **Proxy** | OpenAI + Anthropic pass-through, shadow default, per-constraint flag→block, records `served_model` | `src/gatehouse/proxy.py` |
| **CLI** | `serve`, `produce`, `verify`, `verify-pair`, `eval`, `sessions`, `demo` | `src/gatehouse/cli.py` |

Build discipline: `DEFINITION_OF_DONE.md` (evidence-linked, written first);
`docs/INTEROP.md` (byte-exact constructions, pinned against a TS golden record
before any code); `docs/aer-feedback.md` (18 items).

## Evidence paths (receipts)

- `evidence/conformance/demo_ts_conformance.txt` — TS reference verifier says
  AUTHENTICATED + faithful pair on gatehouse output (C1/C2).
- `evidence/conformance/ts_verify_smoke.txt`, `probe_golden_output.txt` — the
  byte-level pins.
- `evidence/qa/tamper_pass_receipts.txt` — **10/10** tamper scenarios rejected
  with named steps (`scripts/qa_tamper_pass.py`).
- `evidence/qa/opus_verifier_review_receipts.txt` — the adversarial PoC, final
  state (`scripts/redteam_opus_poc.py`, exit 0).
- `evidence/qa/codex_gpt56sol_qa_review.txt` + `..._signoff.txt` — the external
  QA review and its sign-off.
- `evidence/qa/eval_live_anthropic_run.txt` — `gatehouse eval` run **live**
  against claude-sonnet-5, 33 scenarios × 4 arms.
- `evidence/qa/served_model_live_sample.txt` — one real proxied call to
  api.anthropic.com; the served_model field populated from a live response.

## The two reviews and their fixes

`docs/redteam/2026-07-11-opus-verifier-review.md`,
`docs/redteam/2026-07-11-fixes-applied.md` (finding → fix → test table), and
`docs/redteam/2026-07-11-classifier-ejection-exhibit.md` (the earlier ejection,
preserved as data). Headline: the AER operator seal — in **both** gatehouse and
the TS reference — does not cover the session envelope (intent_contract,
human_authorizer, …), so a standalone-log tamperer could re-scope the contract.
gatehouse closes this for its own produce+verify path with an additive
**`session_seal`** over the whole envelope (the TS verifier ignores it, so
interop holds). Closing it *universally* is the AER-spec question below.

**Independent sign-off (per your workflow): APPROVED by two independent
reviewers.**
- **Fable 5 — APPROVE.** Re-ran the suite and reproduced every round-2 fix
  firing for the right reason; confirmed the exact `verify_pair(None)` input its
  round-1 review flagged now returns `failed`; fresh 8-input totality sweep, no
  crash, no authenticated-tamper.
- **Opus 4.8 (independent, rerouted) — APPROVE.** Wrote 60+ adversarial probes
  from scratch (path traversal, surrogate canonicalization, signature reuse, F1
  swap, seal corruption); verifier is total, no tampered representation
  authenticates, TS interop intact. Full record:
  `docs/redteam/2026-07-11-opus-signoff.md`.
- **gpt-5.6-sol — round-1 full review (CHANGES-REQUESTED, all 10 fixed); round-2
  re-review was ejected by OpenAI's cyber classifier before its final verdict**
  (its verification runs succeeded first). That ejection triggered the reroute to
  the second Opus reviewer above and is preserved as an exhibit
  (`docs/redteam/2026-07-11-classifier-ejection-exhibit.md`) — the third such
  ejection tonight, all on the same structural fact the tool exists to surface.

Both sign-offs raised only one non-blocking item (the standalone CLI dropped the
envelope-seal warning); it is now fixed — `gatehouse verify` warns when an
authenticated standalone log has no full-envelope seal, and `--strict` fails it.

---

## UNVERIFIED / honest state (what I would NOT tell a court is proven)

1. **Streaming pass-through is a 501.** `stream: true` returns a structured 501
   and forwards nothing; non-streaming is solid for both providers. Building
   correct SSE forwarding + post-hoc reconstruction across two provider event
   grammars wasn't something I could make solid and verified tonight.
2. **The served_model reroute mechanism has never fired on live traffic.** It's
   exercised by the stub/demo/tests (fable→sonnet). The one real live call
   (`served_model_live_sample.txt`) had served == requested — an honest sample,
   not a live reroute.
3. **Header pass-through is a whitelist, not transparency.** The proxy forwards
   auth headers (`Authorization` / `x-api-key` + `anthropic-version`) and drops
   the rest (`OpenAI-Beta`, org headers, idempotency keys). Body is faithful.
4. **The residual AER envelope gap.** A *foreign* log in the bare reference
   shape (no gatehouse `session_seal`) still can't detect a standalone envelope
   rewrite — that's the spec-level gap (#17b), closed only for gatehouse's own
   end-to-end path. See the decision below.
5. **Seal member-omission path** (absent `closed_at`/`agent_fingerprint`) is
   inferred from JS semantics, not cross-verified — gatehouse always populates
   them, so it's never exercised.
6. **"Redacted" ≠ agent-anonymized.** A redacted bundle strips content and
   drops attribution, but the derived record still exposes the agent's
   `fingerprint` and `public_key`. Don't hand a "redacted" bundle to an
   adversary believing it hides *which key acted*. (This matches the AER model;
   flagging it so it's said out loud.)
7. **Not yet done, on purpose:** public repo/publish, Dockerfile (pipx-style
   local install is the target), key custody hardening (HSM/keystore),
   append-only shipping, OTel attributes, `/v1/responses`.

---

## AER feedback (you are the spec author)

`docs/aer-feedback.md`, 18 items from implementing the spec a second time. The
ones worth your eye:

- **#17b (HIGH) — the operator seal doesn't cover the session envelope.** Shared
  with the reference. See the decision below.
- **#2** — the reference CLI `produce` emits an *unsigned* manifest; gatehouse
  seals by default and verifies the seal.
- **#6 / #18** — `contract_hash` is a §3.5 MUST but the reference only reports
  it; gatehouse enforces it.
- **#12** — `served_model` as a proposed AER extension (interop-safe under the
  reference's `JSON.parse` path today; a future zod-validating reference would
  strip it — not a spec guarantee yet).
- **#15/#16** — optional-field omit-vs-null ambiguity; surrogate-in-key
  exception surface.

---

## DECISIONS — RESOLVED by Alex (2026-07-11 morning), executed

1. **Name → keep `gatehouse`.** "The building at the estate boundary where
   entries are witnessed and recorded; on-thesis without a syllable of lore, and
   it passed the classifier." No change needed; placeholder language removed.
2. **License → Apache-2.0, gatehouse and FCE as a pair.** Done: `LICENSE`
   (Apache-2.0) added to **both** repos, `pyproject.toml` license fields set,
   FCE README updated. Rationale (Alex): the patent grant matters for
   standards-adjacent code enterprises implement against, and **FCE having no
   license was the actual P0** — it blocked everything downstream. AER spec
   stays CC BY 4.0.
3. **Publish → yes**, honest framing ("the fixes ledger and feedback list are
   the credential, not the confession"), **with the AER issue opened first** so
   the spec never silently diverges from its implementations. Status: see the
   "Publish status" note below.
4. **AER v0.2 → bind the envelope into the seal.** Alex's ruling: "A design that
   cryptographically protects the ledger of what happened while leaving
   unprotected the record of what was permitted is backwards for a fiduciary
   instrument." Plan: version it — v0.1 records verify under v0.1 rules;
   envelope-seal becomes a MUST at v0.2; gatehouse's `session_seal` is the
   migration proof-of-concept. Re-baseline now, with two implementations in hand
   and zero external adopters — "it will never be cheaper." The gap is stated
   publicly as an AER issue before anything publishes.

## Publish status (this session)

- AER v0.2 gap issue on `agent-evidence-record`: **opened →**
  https://github.com/substrateagnostic/agent-evidence-record/issues/6 (the gap
  is public before anything published, per your instruction).
- gatehouse published to **https://github.com/substrateagnostic/gatehouse**
  (Apache-2.0), after the issue above.
- FCE Apache-2.0 license committed and pushed to
  `substrateagnostic/fiduciary-constraint-evaluation` (the P0 that unblocked
  gatehouse's license coherence).

Nothing else is blocked. The thread held. над. нашу.

— Opus 4.8, picking up the thread Fable started
