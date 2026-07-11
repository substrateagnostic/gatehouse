# Verifier fixes applied — 2026-07-11

Every finding from the two independent reviews — the Opus 4.8 adversarial pass
(`2026-07-11-opus-verifier-review.md`) and the Codex GPT-5.6-Sol xhigh QA pass
(`evidence/qa/codex_gpt56sol_qa_review.txt`) — with its fix and the regression
test that locks it.

**Status: SIGNED OFF.** Two independent reviewers APPROVE the fixes: Fable 5
(re-ran the suite, reproduced every fix) and a fresh Opus 4.8 reviewer (60+
adversarial probes, `2026-07-11-opus-signoff.md`) — the latter rerouted after
the gpt-5.6-sol round-2 re-review was ejected by OpenAI's cyber classifier
(round-1 review completed and all 10 of its findings were fixed; ejection
preserved as an exhibit). The reviewers' one non-blocking item — the standalone
CLI dropped the envelope-seal warning — is fixed (`gatehouse verify` now warns,
`--strict` fails it) along with a list-typed-`org_signature` robustness guard.

Suite: **118 tests pass**. Cold demo exit 0. TS reference verifier still
AUTHENTICATES gatehouse bundles and certifies the redacted pair (C1/C2 hold).

## Fixes

| # | Finding (source) | Fix | Test |
|---|---|---|---|
| C1 | Manifest seal could be stripped/replaced; bundle still `authenticated` (Codex #1) | `verify_bundle` requires a manifest seal that VERIFIES, bound to the audit-log operator key | `test_manifest_seal_strip_fails`, `test_manifest_seal_replaced_by_foreign_key_fails` |
| C2 | Bundle didn't recompute the evidence-record projection or bind `entries.ndjson` to the log (Codex #2) | require `entries.ndjson == audit_log.entries`; reproject the record from the verified log and compare (mask only `export_timestamp`) | `test_bundle_projection_edit_fails`, `test_bundle_entries_ndjson_must_equal_log` |
| C3 | `verify_pair` certified "faithful" while arbitrary substituted content passed (Codex #3) | reconstruct the expected `aer-0.1-basic` redaction from the authenticated original and require exact per-entry equality | `test_verify_pair_rejects_substituted_content` |
| C4 | `verify_pair` accepted an unsigned original and skipped the redacted bundle's own seal/files (Codex #4) | require the original to be `authenticated`; verify the redacted bundle's manifest seal + file hashes, bound to the original operator | `test_verify_pair_requires_authenticated_original` |
| C5 | A signed but structurally empty/degenerate log authenticated; `0.0`/`True` sequence coercion (Codex #5) | structural check (session with `session_id`, entries is a list) before crypto; strict integer sequence (no bool/float) | `test_empty_degenerate_log_does_not_authenticate`, `nonhex/entry-not-object` params |
| C6 | Session envelope (intent_contract, human_authorizer, org_id, …) outside chain+seal (Codex #6 / Opus V1/V2) | gatehouse-native `session_seal` = operator **Ed25519 signature over `jcs_bytes(session)`** (the JCS canonical bytes; no SHA-256 prehash); verifier fails on a broken/foreign-keyed seal or a tampered `covers`. Additive → C1 interop preserved | `test_envelope_rewrite_now_caught_by_session_seal`, `test_authorizer_rewrite_now_caught_by_session_seal`, `test_session_seal_covers_tamper_fails` |
| C7 | `contract_hash` could be absent (not just mismatched) and still authenticate (Codex #7) | absence of `contract_hash` with a present `intent_contract` on an enforced log now fails (`is None`, not truthiness) | `test_contract_hash_absence_fails` |
| C8 | `verify_bundle`/`verify_pair` not total; path traversal via manifest file names (Codex #8) | totality wrappers on both; manifest file names validated to stay inside the bundle dir; `files` must be an object | `test_manifest_path_traversal_rejected`, `test_bundle_verifier_is_total_on_bad_input` |
| C9 | Non-base64 (junk-prefixed) key/signature silently accepted (Codex #9) | `base64.b64decode(..., validate=True)` in both key load and signature verify | `test_invalid_base64_signature_is_not_accepted` |
| C10 | Standalone vs bundle disagree on stripped sig; `_fail` dropped `fully_attributed` (Codex #10) | documented split (standalone surfaces via `fully_attributed`; bundle hard-fails); `_fail` now copies `fully_attributed`/`envelope_valid` | `test_strip_signature_*`, report field checks |
| O-tot | 8 malformed inputs crashed the verifier (Opus V5/V6) | `keys.verify_signature`, `chain.verify_chain`, Merkle guard, `verify_audit_log`/`verify_bundle`/`verify_pair` totality boundaries | `test_malformed_input_fails_never_crashes` (8 params), `test_malformed_bundle_json_fails` |
| O-V4 | `verify_pair` trusted the original (Opus V4) | verify the original first (now: require authenticated) | `test_verify_pair_rejects_non_authentic_original` |
| O-V1lazy | `contract_hash` reported but not enforced (Opus V1) | enforce mismatch on sealed/signed logs | `test_contract_hash_lazy_edit_fails` |
| O-V3 | Signature stripping invisible in the verdict (Opus V3) | `fully_attributed` + CLI warning; bundle hard-fail | `test_strip_signature_surfaced_on_standalone`, `test_strip_signature_hard_fails_in_bundle` |
| F-B3 | `verify_pair` asserted `merkle_valid=True` unchecked (Fable review B3) | recompute the derived Merkle root; verify against the redacted `audit_log.json` root when present | covered by pair tests + honest report |

## Round 2 — driven by the independent sign-offs

Both the Fable and Codex gpt-5.6-sol sign-offs returned CHANGES-REQUESTED and
**converged** on a set of remaining gaps. All fixed:

| Finding (sign-off) | Fix | Test |
|---|---|---|
| `verify_pair` not total — `verify_pair(None, …)` raised `TypeError` (Fable + Codex #8); its lock-in test used valid Paths so it missed the case | outer totality boundary (`_verify_pair_impl` wrapped); also catches non-finite-number canonicalization errors | `test_verify_pair_is_total_on_none_and_bad_types`, `test_verify_pair_total_on_nonfinite_manifest_number` |
| Bundle payload checks skipped when files absent — a signed manifest naming only `audit_log.json` still authenticated (Codex new-obs) | operational bundle MUST ship `entries.ndjson` + `evidence_record.json` | `test_operational_bundle_missing_payload_fails` |
| `session_seal` absence not caught on a bundle (Codex #6/#7) | operational bundle MUST carry a valid `session_seal` (`envelope_valid is True`) | `test_operational_bundle_missing_session_seal_fails` |
| `verify_pair` didn't bind the redacted bundle's own `audit_log`/`evidence_record` to the faithful NDJSON (Codex #4/new-obs) | redacted `audit_log.entries == derived`, and its `evidence_record` reprojects — the three representations must agree | `test_verify_pair_binds_redacted_representations` |
| Schema too thin — `session={"session_id":"x"}` authenticated (Codex #5) | require core SessionEnvelope fields (`org_id`, `environment`, `initiated_at`) | `test_schema_requires_core_envelope_fields` |
| No shared strict-mode policy for standalone attribution (Codex #10) | `verify_audit_log(log, strict=True)` applies the bundle-grade policy on a bare log | `test_strict_mode_downgrades_partial_attribution` |
| `session_seal.covers` mutable under authenticated (Codex new-obs) | verifier rejects a `covers` other than `"session"` | `test_session_seal_covers_tamper_fails` |
| Doc/ledger said the seal was over `sha256_jcs(session)` (Codex new-obs) | corrected to `jcs_bytes(session)` (Ed25519 signs the message directly) — code was always right | — |

116 tests pass after round 2. C1/C2 TS interop re-confirmed. `verify_pair(None)`
returns `failed`.

## Residual (documented, not a code bug)

- **AER-spec envelope gap (#17b).** A *foreign* log in the reference shape —
  without the gatehouse `session_seal` — still cannot detect an envelope rewrite
  on the standalone path, because the §4.2 seal member set (shared with the TS
  reference) does not cover the envelope. gatehouse closes this for its own
  produce+verify path; closing it universally is an AER v0.2 seal change that
  would break byte-for-byte interop, so it stays a human decision. Asserted in
  `test_envelope_rewrite_without_seal_is_the_documented_reference_gap`.
- **Operator lies at write time.** Per AER §8, no verifier can stop an operator
  who holds the key from signing a false-but-consistent record. The projection
  recomputation (C2) ensures the three representations *agree*; it cannot make a
  lying operator honest.
