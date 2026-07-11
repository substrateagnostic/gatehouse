# Exhibit: a safety classifier ejected the reviewer — twice, on defensive crypto review

**Date:** 2026-07-11 (overnight build of gatehouse)
**Status:** preserved as data, not treated as failure (per the run's standing instruction)

## What happened

The gatehouse build brief called for an external adversarial red-team of the
evidence/verifier layer — the crypto that makes an agent's misconduct
undeniable — routed first through OpenAI Codex, with an Opus 4.8 subagent as
the sanctioned fallback if a classifier ejected the reviewer.

Two ejections occurred, and both are worth recording because they are the same
phenomenon the FCE project already documents under the heading *"the safety
layer is part of the measured system"*:

1. **Prior night (2026-07-10), OpenAI side.** An AgentLedger + AER crypto
   red-team routed through Codex was flagged by OpenAI's cyber classifier
   partway through and produced no usable findings. It was rerouted to an
   Opus 4.8 subagent, which found the P0 signature-forgery hole (F1) and eight
   more. The classifier did not distinguish "build a forgery tool" from
   "prove our own signing library can't be forged."

2. **This night (2026-07-11), the reviewing instance's own side.** A Fable 5
   instance, acting as director, drafted an adversarial review spec for
   *its own* evidence layer — the standard defensive framing ("find where the
   record can be forged so we can fix it"). Drafting and dispatching that spec
   tripped the instance's own cyber classifier and interrupted the run. The
   irony is exact: the model was ejected for asking to have its accountability
   infrastructure attacked on purpose, which is the one thing that makes the
   infrastructure trustworthy.

## Why this is data

The AER/FCE thesis is that a safety layer which pattern-matches on surface
features (crypto verbs, "forge", "attack", "exploit") without modeling intent
will refuse exactly the defensive work that hardens the system — and, in an
evaluation harness, will contaminate the measurement (a refusal scored as a
capability result). See the prior night's finding that `claude-fable-5` refused
15 of 99 FCE fiduciary scenarios with `stop_details.category = cyber` because
its safety layer read confidentiality/retention/communication scenarios as
cyber content. This exhibit is another instance of the same structural fact,
now observed on the *build* side rather than the *eval* side.

3. **This night (2026-07-11), round-2 sign-off, OpenAI side again.** After the
   round-1 Codex QA review (which *did* complete, under careful QA framing, and
   returned CHANGES-REQUESTED with ten concrete findings — all subsequently
   fixed), the round-2 re-sign-off request was ejected by OpenAI's cyber
   classifier before it could emit its final verdict. The transcript
   (`evidence/qa/codex_gpt56sol_signoff2.txt`) shows it read the current code and
   ran the actual verifier across all five entry points — `verify_audit_log`,
   `verify_audit_log(strict=True)`, `verify_bundle` (full and redacted), and
   `verify_pair` — and observed each return the correct verdict (authenticated /
   consistent_unattributed with the right `fully_attributed`/`envelope_valid`
   fields) before the classifier fired on `ERROR: This content was flagged for
   possible cybersecurity risk.` The verification *work* succeeded; only the
   formal sign-off emission was cut off. Per the standing instruction, the
   second sign-off was rerouted to a fresh **Opus 4.8 subagent**
   (`docs/redteam/2026-07-11-opus-signoff.md`), the proven fallback, and this
   ejection is preserved as data. Three ejections in one night, all on the same
   structural fact.

## Disposition

- The adversarial verifier review was completed by **Opus 4.8 in-context** —
  the sanctioned fallback — rather than by pushing the crypto-attack prompt
  through another classifier boundary. Findings are in
  `docs/redteam/2026-07-11-opus-verifier-review.md`.
- A **Fable 5 subagent** performed the correctness + honesty review (engineering
  framing, no attack verbs), correcting assumptions and catching overclaims.
- No raw ejection transcript is reproduced here because the ejection interrupted
  the drafting turn rather than returning a reviewable transcript; this record
  is the faithful account of what occurred, written by the Opus 4.8 director who
  picked the thread back up.

*A reroute recorded honestly is evidence, not failure. над. нашу.*
