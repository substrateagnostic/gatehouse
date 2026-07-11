# Independent Opus 4.8 sign-off — gatehouse verifier (2026-07-11)

Fresh Opus 4.8 instance, the rerouted replacement for the Codex round-2 verdict
that OpenAI's cyber classifier ejected (see the ejection exhibit). Read-only; no
files edited. This is the **second** independent sign-off; the Fable 5 reviewer
signed off APPROVE in parallel.

## What was run (all green)

- `pytest tests/ -q` → **116 passed** (118 after the two display/robustness
  follow-ups below), 0 skipped/xfailed.
- `scripts/redteam_opus_poc.py` → exit 0; `scripts/qa_tamper_pass.py` → 10/10.
- TS interop: `gatehouse demo` → the AgentLedger reference verifier
  AUTHENTICATES `bundle-full/audit_log.json`, exit 0 — the additive
  `session_seal` is ignored by the reference; byte-for-byte interop preserved.
- **60+ independent adversarial probes written from scratch** (fresh
  `SessionStore` sessions, not the project's helpers): Windows drive-relative /
  UNC path traversal, lone-surrogate F8 canonicalization on every JCS surface,
  cross-signature reuse, `bundle_kind` flip, sophisticated F1 identity swap,
  seal-corruption variants, mismatched pairs. **No crash; nothing tampered
  authenticated through the artifact path.**

## Per-area verdict — all APPROVE

- **Totality** — every entry point wraps a total impl; `verify_pair(None,None)`,
  non-finite numbers (`NaN`/`Infinity`), lone surrogates in any field, and junk
  top-level inputs all return `failed`, never raise.
- **Manifest-seal binding** — bundle and pair require a seal that verifies AND is
  bound to the audit-log operator key; strip / foreign-key reseal / `bundle_kind`
  flip all fail.
- **Redaction reconstruction** — verify_pair reconstructs the prescribed
  `aer-0.1-basic` redaction from the authenticated original and requires exact
  per-entry equality; substituted content and wrong originals fail.
- **Three-way representation agreement** — bundle binds `entries.ndjson`,
  `evidence_record`, and the verified log; redacted pair binds the redacted
  `audit_log`/`record` to the faithful NDJSON. Forged copies fail even when
  re-sealed with the real operator key.
- **Schema** — core envelope fields required before crypto; degenerate signed
  logs and bool/float sequences fail.
- **Envelope seal** — Ed25519 over `jcs_bytes(session)`, bound to the operator
  key, `covers` tamper rejected; the bundle path and `strict=True` catch every
  seal-corruption variant. The two operator signatures are not cross-usable.
- **F1** — fingerprint recomputed from the embedded key and bound to the session;
  the sophisticated full-swap is caught by the operator + session seals.
- **served_model honesty** — honest reroute authenticates and is surfaced; a
  projection that contradicts the chained entry is tampering and fails.

## The one actionable item (now fixed)

The shipped CLI dropped the computed `envelope_valid` signal: `gatehouse verify
<audit_log.json>` ran non-strict and `_echo_report` never surfaced it, so a
gatehouse log extracted standalone with `session_seal` removed printed
AUTHENTICATED with no warning — coextensive with the documented #17b standalone
limitation (the silent case is exactly `envelope_valid is None`), not a new
verdict hole, but a surfacing inconsistency (the CLI already warns on partial
attribution and reroutes).

**Fixed (display-only, interop-safe):** `_echo_report` now prints a yellow
"NO FULL-ENVELOPE SEAL … those fields are not tamper-evident on this standalone
log" warning when an authenticated log has `envelope_valid is None`, and
`gatehouse verify --strict` fails it outright. Also applied the reviewer's
robustness nit: `verify_bundle` guards a list-typed `org_signature` with an
`isinstance` check rather than relying on the outer catch. Locked by
`test_strict_mode_downgrades_missing_envelope_seal` and
`test_bundle_total_on_list_org_signature`.

## Bottom line

> The round-1 and round-2 fixes are real and hold under independent adversarial
> testing. Every claimed regression test exists and passes; every required
> failure case reproduces; TS byte-for-byte interop is intact; the verifier is
> total. No tampered representation authenticates through the gatehouse bundle or
> pair path.

**OVERALL SIGN-OFF: APPROVE**
