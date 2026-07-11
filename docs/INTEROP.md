# INTEROP — byte-exact constructions (AER v0.1 / AgentLedger v2)

This is the load-bearing reference for the gatehouse evidence layer. Every
construction below was either pinned empirically against a TS-produced golden
record (see `evidence/conformance/probe_golden_output.txt`) or copied from the
reference implementation source (paths cited). Where SPEC prose and impl
differ, **the impl is ground truth** (director decision recorded in
`agentledger/docs/redteam/2026-07-10-response.md`) and the discrepancy goes to
`docs/aer-feedback.md`.

Reference repos (local, in sync with public origin):
- Spec: `C:\Users\agall\projects\agent-evidence-record\SPEC.md`
- Impl: `C:\Users\agall\agentledger` (core: `packages/core/src/{crypto,jcs,types,storage}.ts`)
- Golden fixtures: `agentledger/examples/demo/output/` (audit-log.json, bundle-full/, bundle-redacted/)

## Crypto stack summary

| Layer | Preimage | Serialization | Digest/Sig | Encoding |
|---|---|---|---|---|
| Entry hash | `{sequence, entry, previous_hash, authorized_by?}` | RFC 8785 JCS | SHA-256 | lowercase hex |
| Agent signature | the entry_hash **hex string** (64 ASCII bytes, UTF-8) | raw | Ed25519 | base64 |
| Merkle leaf | `0x00 ‖ raw32(entry_hash)` | raw bytes | SHA-256 | hex |
| Merkle node | `0x01 ‖ left32 ‖ right32` | raw bytes | SHA-256 | hex |
| Operator seal | integrity block (below) | RFC 8785 JCS | Ed25519 | base64 |
| Contract hash | `intent_contract` object | RFC 8785 JCS | SHA-256 | lowercase hex |
| Manifest seal | manifest minus `operator_signature` | RFC 8785 JCS | Ed25519 | base64 |
| Manifest `files{}` | exact file bytes as written (NOT JCS) | — | SHA-256 | lowercase hex |

Keys: public = base64 of SPKI **PEM text** (double-encoded); private = PKCS#8
PEM. Fingerprint = `"sha256:" + hex(SHA256(raw 32-byte public key))`.

## Entry hash (§4.1)

`entry_hash(n) = sha256_hex( JCS({ "sequence": n, "entry": <full nested typed
entry>, "previous_hash": <prev entry_hash | "" for n=0>, "authorized_by":
<AuthorizationRef — ONLY when an operation-scoped override exists> }) )`

- `entry` = the complete typed object exactly as stored in `entries.ndjson`
  (with `type`, `entry_id`, `timestamp`, every type-specific field) — NOT the
  ChainedEntry wrapper, NOT a projection.
- `authorized_by` omitted entirely when absent (no-override entries hash as the
  3-member object).
- Verification: seq dense ascending from 0; `previous_hash` equals prior
  `entry_hash`; recompute and compare.

## Merkle root (§4.2.1, F9)

leaf = `SHA256(0x00 ‖ bytes.fromhex(entry_hash))`; node = `SHA256(0x01 ‖ L ‖ R)`;
odd node carried up UNCHANGED (never duplicated); empty log → `""`.
Pinned: single-leaf root equals leaf (probe line 2).

## Operator seal (§4.2, F6)

Ed25519 over UTF-8 bytes of `JCS({ "session_id": ..., "merkle_root": ...,
"entry_count": <int>, "closed_at": ..., "schema_version": 2,
"agent_fingerprint": "sha256:<hex>", "canonicalization": "RFC8785" })`.
Pinned empirically (probe line 4): "RFC8785" exactly — note the record's
integrity_attestation *displays* `canonicalization: "jcs"`; the *signed* value
is `"RFC8785"`. `signed_at` is informational, NOT signed (aer-feedback item).
`agent_fingerprint` omitted from the block if session has no agent identity.

## Agent signature (F1)

`agent_signature = {fingerprint, public_key, signature}`; `signature` =
base64(Ed25519 over UTF-8 bytes of the entry_hash hex string). Verifier MUST:
1. fail closed if the session declares no `agent_fingerprint` but an entry
   claims a signature;
2. recompute fingerprint from embedded `public_key`; require it equal the
   entry's claimed fingerprint AND the session fingerprint AND (when present)
   require embedded key == session `agent_public_key`. NEVER trust the claimed
   fingerprint string;
3. only then verify the signature over the entry_hash.

## Tri-state verdict (§4.3, F2)

`authenticated` | `consistent_unattributed` | `failed`.
`anyPresentFailed = !chain_valid || !merkle_valid || org_valid === False ||
agent_valid === False` (None/absent never fails — only explicit False).
failed if anyPresentFailed; else authenticated iff org_valid is True; else
consistent_unattributed. `failed` MUST name the failing step. Only
`authenticated` may be called valid.
Note (aer-feedback): in the reference, an absent merkle_root on a populated
log passes; gatehouse's own verifier is stricter for its own bundles (root
required when entries exist) but mirrors reference behavior when verifying
foreign logs.

## Evidence record (§3/§4-shaped packet)

Six keys, insertion order: `aer_version` ("0.1"), `agent_identity`,
`human_authorizer`, `operations`, `data_accessed`, `policy_context`.
Integrity nested at `policy_context.integrity_attestation`.
- operations[i] = `{sequence, timestamp, type, operation, status, entry_hash,
  agent_signature?}`; per-type derivations: model_call→(model_id,
  error?"error":"ok"); tool_invocation→(tool_name, success?"ok":"error");
  decision_point→(decision_id, human_review_required?"pending_review":"ok");
  human_approval→(decision_ref, approval_type); state_snapshot→(trigger,"ok");
  content_reference→(content_type,"ok").
- integrity_attestation = `{schema_version, canonicalization ("jcs"),
  chain_valid, chain_verified_count, merkle_root, merkle_valid,
  org_signature{public_key, signature, signed_at, valid}|null,
  agent_signatures{present, valid, verified_count}, status, attribution
  ("operator"|"unattributed"), overall_valid, export_timestamp}`.
- Redacted record: `contract_hash: null` + `contract_hash_original: <orig>` (F5).

## Bundle layout (§5)

Files: `evidence_record.json` (pretty, 2-space), `entries.ndjson` (compact,
one ChainedEntry per line, trailing `\n` when non-empty),
`intent_contract.json` (when contract present), `hash_manifest.json`.
ChainedEntry key order: `sequence, entry, previous_hash, entry_hash,
source_entry_hash?, authorized_by?, agent_signature?`.
Manifest key order: `hash_alg ("sha256"), bundle_kind
("operational"|"derived_redacted"), source_entry_count,
source_last_entry_hash, derived_last_entry_hash, source_entry_hashes[],
files{}, contract_hash, redaction_rule ("aer-0.1-basic"),
operator_signature?`. `files{}` excludes hash_manifest.json itself; hashes are
over the exact written bytes. Manifest seal = Ed25519 over JCS of the manifest
without `operator_signature`. NOTE: the reference CLI `produce` emits an
UNSIGNED manifest; **gatehouse seals its manifests by default** (aer-feedback).

Redaction (`aer-0.1-basic`): replace with `"[REDACTED]"` — model_call
error.message; tool_invocation error.message + each resources_accessed[]
.identifier (keep type+operation); decision_point options_considered[]
.description; content_reference storage_uri; intent_contract objective/
jurisdiction/role/revision_policy and every element of constraints/
facts_provided/success_criteria; string-valued session metadata. Derived
entries: recompute chain, drop agent_signature, add `source_entry_hash` =
original entry_hash (F3).

## served_model (gatehouse addition — REQUIRED)

New optional field on `model_call` entries, adjacent to `model_id`:
`served_model` = the model ID the PROVIDER asserted in the response body
(`model` field of OpenAI/Anthropic responses), vs `model_id` = what was
requested. Inside `entry`, so covered by the entry hash automatically.
Verified safe for TS interop: the reference CLI uses plain JSON.parse (no zod
strip), so served_model participates in TS-side JCS recomputation and
round-trips cleanly. Also surfaced in the evidence record's operations
projection as `served_model`, and any requested≠served mismatch is flagged in
the record annotations and by `gatehouse verify`. Logged in aer-feedback as a
proposed AER extension.

## Serialization rules (Python)

- Hashing/signing: ALWAYS `rfc8785.dumps` (handles ECMAScript number
  formatting, UTF-16 key ordering, lone-surrogate rejection — F8).
- File bytes: `json.dumps(obj, indent=2, ensure_ascii=False)` for .json;
  `json.dumps(obj, separators=(",", ":"), ensure_ascii=False)` per NDJSON
  line. Insertion order preserved; keys with absent values OMITTED (never
  `null` unless the value is genuinely null). No trailing newline on .json.
- Timestamps: RFC 3339 UTC with milliseconds, e.g. `2026-07-11T04:50:33.955Z`.
- Avoid floats where ints suffice (latency_ms int); floats that must round-trip
  through JS are hashed via rfc8785 so formatting is spec-consistent.

## Conformance harness

From `C:\Users\agall\agentledger` (dist is built):
- `node packages/cli/dist/index.js verify <log-file>` → AUTHENTICATED exit 0 /
  UNATTRIBUTED exit 0 / FAILED exit 1.
- `node packages/cli/dist/index.js verify-pair <redacted-bundle-dir>
  <original-log-file>` → faithful exit 0 / FAILED exit 1.
- The TS verifier consumes the **AuditLog** shape: `{version: "2.0.0",
  schema_version: 2, session: <SessionEnvelope>, entries: [<ChainedEntry>...],
  merkle_root, org_signature}` — gatehouse `produce` also emits
  `audit_log.json` in the bundle so the TS CLI can verify gatehouse sessions
  directly (this is the overlap profile).
- SessionEnvelope fields: session_id (uuid), org_id, agent_id, agent_version?,
  agent_public_key?, agent_fingerprint?, signature_scheme? ("ed25519"),
  environment ("production"|"staging"|"development"|"test"), initiated_by
  {type: "user"|"system"|"scheduled"|"api", identifier}, initiated_at,
  closed_at?, compliance_contexts[] ("FINRA_4511"|"FINRA_3110"|"EU_AI_ACT"|
  "HIPAA"|"SOC2"|"GDPR"|"CCPA"|"CUSTOM"), policy_context?[], human_authorizer?,
  intent_contract?, contract_hash? (required when intent_contract present),
  retention_days (int, default 2555), metadata?.
