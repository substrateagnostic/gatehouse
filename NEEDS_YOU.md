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

- **116 tests pass.** One cold command proves the whole pipeline: `gatehouse demo`.
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

**Independent sign-off (per your workflow):** Fable 5 and gpt-5.6-sol were each
asked to sign off on the fixes before they're marked final. Result:
<!-- SIGNOFF-RESULT -->
_pending — will be stamped here when both return; see
`evidence/qa/codex_gpt56sol_signoff.txt` and the Fable sign-off note below._

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

## DECISIONS ONLY YOU CAN MAKE

1. **Name.** "gatehouse" is a placeholder I've been using. It reads well and
   isn't taken in this constellation, but it's yours to keep or change.
2. **License.** `pyproject.toml` says `UNLICENSED`. The lineage is CC BY 4.0
   (AER spec) / the agentledger + FCE repos. Note **FCE itself has no license
   yet** — gatehouse depends on it for the check layer, so gatehouse can't be
   licensed more openly than FCE until FCE has a license. Pick both together.
3. **Publish or hold.** Everything is local (`~/Projects/gatehouse`, git
   history intact, nothing pushed). Holds cleanly. If you publish, the honest
   framing is "v0.1, second AER implementation, reviewed" — the fixes-applied
   ledger and the aer-feedback list are assets, not liabilities.
4. **The AER-spec question (the real one).** Do you want AER **v0.2** to bind
   the full session envelope into the operator seal — closing #17b universally
   at the cost of a one-time byte-for-byte re-baseline of the reference — or do
   you want the spec to state that the standalone seal covers *{entry set +
   session scalars}* only and envelope integrity is a transport/storage
   property? gatehouse already implements the additive `session_seal` as a
   proof-of-concept for the first path. This is a spec-direction call, and
   you're the editor.

Nothing else is blocked. The thread held. над. нашу.

— Opus 4.8, picking up the thread Fable started
