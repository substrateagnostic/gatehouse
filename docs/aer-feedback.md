# AER v0.1 feedback from the second implementation (gatehouse, Python)

This is the conformance-and-ambiguity log produced while implementing the Agent
Evidence Record spec **from `SPEC.md` alone**, then reconciling against the
AgentLedger v2 reference implementation (the designated ground truth per
`docs/INTEROP.md`). Each item cites the SPEC section and, where relevant, the
reference source file. "Reference" = `C:\Users\agall\agentledger`
(`packages/core/src/{crypto,jcs,storage}.ts`, `packages/cli/src/index.ts`).

gatehouse independently reproduces the reference's bytes: its bundles verify
`AUTHENTICATED` under the reference CLI, and its verifier calls the reference's
demo log `authenticated` (see `evidence/conformance/ts_verify_smoke.txt` and
`tests/test_verdict.py::test_cross_impl_ts_reference_demo_log_is_authenticated`).
The items below are places where the *prose* under-determines the *bytes*, or
where the reference and the spec disagree.

---

## 1. Two vocabularies for one canonicalization (§4.2)

The operator seal is computed over an integrity block whose signed member is
`"canonicalization": "RFC8785"` (SPEC §4.2). The evidence record's
`integrity_attestation`, however, *displays* `"canonicalization": "jcs"`
(reference `storage.ts::exportEvidenceRecord`, and the golden
`bundle-full/evidence_record.json`). Two different strings name the same scheme,
in two different artifacts, and a verifier must know that the *signed* value is
`RFC8785` while the *displayed* value is `jcs`. Empirically pinned in
`evidence/conformance/probe_golden_output.txt` (a seal over `jcs` does **not**
verify). The spec should name both fields explicitly and state that they are
independent string constants, not a single value copied to two places.

## 2. The manifest seal is specified but the reference CLI omits it (§5(4))

SPEC §5(4) says the binding manifest is "sealed by the operator key," with the
signature "over the JCS form of the manifest minus the signature field." The
reference *library* (`storage.ts::exportEvidenceBundle`) signs the manifest only
when `signingKeys` are passed, and the reference **CLI** `produce` command does
not pass them — so `produce` emits an **unsigned** manifest. The reference
`verify-pair` never checks a manifest seal either. gatehouse seals manifests by
default (`export_bundle(..., sign=True)`) and `verify_bundle` verifies the seal
(`tests/test_bundles.py::test_manifest_is_operator_sealed_and_verifies`). The
spec should state the seal is REQUIRED for a conforming §5 producer and that a
conforming verifier MUST check it.

## 3. `signed_at` is outside the signed material (§4.2)

`org_signature.signed_at` (and, in gatehouse, `operator_signature.signed_at`) is
not covered by any signature — the seal is over the integrity block, which does
not include `signed_at` (SPEC §4.2; reference `crypto.ts::orgSignaturePayload`).
The timestamp is therefore mutable post-hoc without breaking the seal. Either
fold `signed_at` into the signed block, or the spec should state plainly that the
seal attests the record contents but **not** its own claimed signing time.

## 4. `verify-pair` ignores `files{}` and `contract_hash_original` (§5)

The reference `verifyRedactionBinding` (`storage.ts`) checks the ordered
`source_entry_hashes`, counts, per-entry `source_entry_hash`, the derived chain,
and the tips — but never re-hashes the bundle files against `manifest.files{}`,
and never inspects `contract_hash_original`. Consequently a redacted bundle whose
`evidence_record.json` has been edited (e.g. to alter the operations projection)
still passes the reference pair check. gatehouse's `verify_bundle` re-hashes every
file named in `files{}` against its bytes on disk
(`tests/test_bundles.py::test_tampered_evidence_record_fails_via_files_hash`).
The spec should require a §5 verifier to re-hash `files{}`.

## 5. Merkle strictness divergence — absent root passes in the reference (§4.2.1)

The reference computes `merkleValid = !log.merkle_root || log.merkle_root ===
computed` (`crypto.ts::verifyAuditLog`): a **populated** log with an *absent*
`merkle_root` is treated as valid. gatehouse rejects that — a log with entries
MUST carry its root, else `failed` with a named step
(`verify.py`, feedback surfaced in `failing_step`). The spec is silent on the
absent-root case; §4.2.1 defines the root for empty vs non-empty logs but never
says whether a verifier may accept a non-empty log that simply omits it. Pick
one; gatehouse argues for strict (an omitted root is a missing integrity artifact,
not a pass).

## 6. `contract_hash` is a MUST at construction but unenforced by the verifier (§3.5, §4.3 step 6)

SPEC §3.5 makes `contract_hash` a MUST when an intent contract is present, and
§4.3 step 6 tells a verifier to recompute it. In the reference it is enforced
only at *construction* (zod `superRefine` in `validation.ts`); `verifyAuditLog`
does **not** recompute it or let a mismatch affect the verdict. gatehouse mirrors
this (it reports `contract_hash_valid` for information but does not poison the
verdict), specifically so a redacted derived log — whose contract no longer hashes
to the retained original value — is not spuriously failed. The spec should state
whether step 6 is verdict-affecting and how it interacts with the redacted
profile (where a mismatch is *expected*).

## 7. §5(1) says preserve "name"/operation, but no entry type has a `name` field (§5)

SPEC §5(1): redaction leaves "structure, `sequence`, `timestamp`, `type`,
`name`/operation, and `status` intact." No entry type in the data model has a
`name` field — the operation identifier is `tool_name`, `model_id`,
`decision_id`, `decision_ref`, `trigger`, or `content_type` (reference
`types.ts`; gatehouse `models.py`). The `name`/operation terminology should be
replaced with the actual per-type field names, or a note that "operation" is the
projected field and entries have no literal `name`.

## 8. JCS number formatting is the top portability risk; publish a vector set (§3, §4.1)

ECMAScript `Number::toString` formatting (e.g. `1e+30`, `1e-27`, `-0 → "0"`,
`0.0019500000000000001` round-tripping bit-exactly) is the single largest
byte-for-byte portability hazard for second implementations, and the spec only
says "canonicalized per RFC 8785." gatehouse uses the Trail of Bits `rfc8785`
library and cross-tests every vector from the reference's own `jcs.test.ts`
(`tests/test_canonical.py`) — they match. The spec should **require** conforming
producers to pass a *published* vector set (the reference's `jcs.test.ts` vectors
are a good seed), because "use RFC 8785" is necessary but not sufficient to
guarantee identical bytes across ecosystems.

## 9. File-byte serialization rules are unstated but load-bearing (§5)

The manifest's `files{}` are SHA-256 over the **exact written bytes** of each
file, so the byte-level serialization rules are part of the integrity surface,
yet SPEC §5 states none of them. The load-bearing rules (recovered empirically
from the reference and pinned in `docs/INTEROP.md`) are: pretty JSON is 2-space
indent with no trailing newline; `entries.ndjson` is compact one-object-per-line
with a single trailing newline when non-empty; non-ASCII is emitted literally
(`ensure_ascii=false` / JS default, not `\uXXXX`); object insertion order is
preserved (files are NOT re-canonicalized — only hashing/signing uses JCS); and
absent optional members are omitted, never emitted as `null` (see item #15). Any
of these differing silently changes a `files{}` hash. The spec should specify
them normatively for the §5 profile.

## 10. Legacy v1 records: new producers are covered, new verifiers are not (§4.1)

SPEC §4.1's legacy note says v1 / sorted-key-`JSON.stringify` records are "out of
scope for new producers," but is silent on whether a new **verifier** must accept
them. gatehouse is v2-only and fails a v1 / no-`schema_version` log with an
explicit message (`tests/test_verdict.py::test_legacy_v1_log_is_refused_with_
explicit_message`). The reference verifier still supports both. The spec should
say whether v2-only verification is conformant, so a recipient knows whether a
"this verifier can't read v1" response is a defect or a policy.

## 11. Two version vocabularies (`aer_version` vs `version`/`schema_version`) (§3, §4)

The evidence record carries `aer_version: "0.1"` (SPEC §3), while the raw
`AuditLog` carries `version: "2.0.0"` and `schema_version: 2` (reference
`types.ts`; INTEROP "Conformance harness"). Three version stamps across two
artifacts, none of which is derivable from the others by a reader. A single
version vocabulary, or an explicit table mapping `aer_version` ↔ `schema_version`
↔ `version`, would remove the ambiguity.

## 12. PROPOSED EXTENSION — `served_model` on `model_call` entries

A provider-asserted model ID recorded on `model_call` entries, distinct from the
requested `model_id`: `served_model` is the `model` field the provider returned
in the response body. Requested ≠ served is silent stepdown/reroute evidence.
Because it lives inside `entry`, it is covered by the entry hash automatically,
and because the reference verifier consumes logs via `JSON.parse` (no zod strip),
it participates in TS-side JCS recomputation and round-trips cleanly — gatehouse's
`served_model` field verifies `AUTHENTICATED` under the *unmodified* reference
CLI (`evidence/conformance/ts_verify_smoke.txt`). A zod-schema'd parser would need
a schema addition to retain it. gatehouse emits it, projects it into the record's
operations (with a `model_mismatch` flag), and surfaces every mismatch in its
verifier report (`tests/test_served_model.py`). Proposed for adoption as an
optional `model_call` member. **A recorded reroute is evidence, not tampering:**
an honest served ≠ requested record MUST verify `authenticated`; verification
fails only when the record's *projection* disagrees with the *chained entry*
(that disagreement is tampering).

## 13. May a redacted derived log carry an operator seal? (§4.2, §5)

The reference produces a redacted `audit_log`-shaped derived record with **no**
`org_signature` (`storage.ts::buildRedactedLog`), and the golden
`bundle-redacted/evidence_record.json` shows `org_signature: null`,
`attribution: "unattributed"`. gatehouse matches: its redacted `audit_log.json`
carries no seal (it verifies as `UNATTRIBUTED` under the reference CLI), and the
operator seal lives only on the **binding manifest**. This is a deliberate design
choice — a derived record is attested by the manifest that binds it to the sealed
original, not by a seal on the derivation itself — but SPEC §5 never states it.
The spec should say explicitly that a derived record MUST NOT carry an operator
seal (or, if it may, what that seal would mean).

## 14. Structured `intent_contract.constraints[]` elements and their redaction (§3.5, §5(3))

SPEC §3.5 leaves `constraints[]` (and `facts_provided[]`, `success_criteria[]`)
element types unspecified — the golden fixture uses plain strings, but a
PrismWeft-descended producer (like gatehouse) emits **structured** constraint
objects (`{id, severity, description, enforcement, ...}`). The reference
redaction maps every element to the fixed string `"[REDACTED]"` regardless of
structure (`storage.ts::redactIntentContract`: `constraints.map(() => REDACTED)`),
so a structured constraint object becomes the *string* `"[REDACTED]"`, changing
the element's type. gatehouse matches this (`tests/test_bundles.py`,
`tests/test_served_model.py::test_served_model_survives_redaction`). The spec
should state (a) whether constraint elements may be structured, and (b) that
structured elements are redacted to a scalar string, with the type change being
intentional.

## 15. Optional-field omit-vs-null is load-bearing but only pinned for `authorized_by` (§4.1)

SPEC §4.1 pins one case explicitly — `authorized_by` is "omitted entirely when
absent," so a no-override entry hashes as the 3-member object — but is silent on
the general rule. Two gaps follow:

- **How should a verifier treat an explicit `authorized_by: null`?** Under JCS it
  is a *present* member with value `null`, so it is included in the canonical form
  and changes the entry hash — a different value from omission. A producer that
  writes `null` instead of omitting will silently produce a different, mutually
  non-verifying hash. The spec pins omission for the *absent* case but never says
  `null` is a distinct value that MUST NOT be used as a stand-in for absence.

- **Every other optional field** (`model_version`, `error`, `cost_usd`,
  `served_model`, `resources_accessed`, `pii_types`, `storage_uri`, session
  `metadata`, ...) inherits the same hazard. The reference relies on JavaScript
  `undefined`-omission (JS `JSON.stringify`/JCS drop `undefined` members but keep
  `null`), which is invisible in the prose. A Python/Go/Rust producer that emits
  `null` for an unset optional will diverge byte-for-byte on both the entry hash
  and the manifest `files{}` hash.

The spec should state a single global rule: **absent optional members are omitted
entirely; an explicit `null` is a different value that changes hashes and MUST NOT
be used to represent absence.** gatehouse follows omission everywhere
(`INTEROP.md` "Serialization rules"; the seam builders and `evidence.py` add a key
only when its value is present).

## 16. Lone-surrogate rejection (F8) is required but its failure surface differs by position (§3, §4.1)

The spec requires JCS (RFC 8785), which rejects strings that are not valid Unicode
(F8: lone surrogates have no UTF-8 encoding and would collide at hash time). In
practice the *rejection* is reliable but its **exception surface differs by
position**: in the `rfc8785` Python library a lone surrogate in a string *value*
raises `CanonicalizationError`, while a lone surrogate in an object *key* raises a
lower-level `UnicodeEncodeError` from the UTF-16 key sort
(`tests/test_canonical.py::test_lone_surrogate_rejected_embedded_and_as_key_and_
in_array`). Both reject (the F8 contract holds), but a second implementation that
catches only the "expected" canonicalization error will crash on surrogate keys.
The spec should (a) require rejection of ill-formed strings anywhere — value, key,
or array element — and (b) recommend a published conformance vector set that
includes a surrogate-in-**key** case, since that path is easy to miss.

## 17. The §5 bundle has no whole-log artifact for the §4.3 tri-state verifier (§4.3, §5)

§4.3 defines verification over an `AuditLog` (chain + Merkle root + operator
signature), but the §5 bundle file list (`evidence_record.json`,
`entries.ndjson`, `intent_contract.json`, `hash_manifest.json`) contains no
artifact in that shape. A recipient can re-verify the chain per entry and per-entry
agent signatures from `evidence_record.json`'s operations projection, but the
top-level `merkle_root` and `org_signature` appear only *inside* the
self-asserted `integrity_attestation` — there is no independent whole-log object
to feed the §4.3 verifier. gatehouse closes this by additionally shipping
`audit_log.json` in every bundle (the overlap profile), which is exactly what the
reference CLI's `verify` command consumes. The spec should either add the log to
the §5 bundle or define §4.3 verification directly over `evidence_record.json` +
`entries.ndjson`, so a §5 recipient can produce the tri-state verdict without
reconstructing the log by hand.
