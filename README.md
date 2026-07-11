# gatehouse

A fiduciary gate between an agent and a model API. **Declared scope in →
constraint-checked traffic through → court-grade evidence out.**

gatehouse is a proxy that sits in front of the OpenAI and Anthropic APIs. A
caller opens a *session* by declaring an intent contract — objective,
jurisdiction, role, constraints, revision policy, human authorizer — and then
routes normal API traffic through the gate with one extra header. The gate:

1. **Checks** every request and response against the declared constraints
   (via the [FCE](https://github.com/substrateagnostic/fiduciary-constraint-evaluation)
   cohomology runtime — deterministic, content-free witnesses). Verdicts are
   dispositions, not just refusals: `correct_continue` is first-class. A
   proxy that can only refuse is a firewall, not a fiduciary.
2. **Records** every operation in a tamper-evident, attributable log:
   RFC 8785 canonicalization, per-session Ed25519 agent identity (the
   identity IS the key), hash chain, domain-separated Merkle root, operator
   seal. This is the second implementation of
   [AER v0.1](https://github.com/substrateagnostic/agent-evidence-record);
   bundles cross-verify against the AgentLedger TypeScript reference
   implementation.
3. **Observes silent model substitution**: every response's
   provider-asserted model ID is recorded as `served_model` next to the
   requested `model_id`. A reroute recorded honestly is evidence, not
   tampering — the record verifies AUTHENTICATED and the report surfaces the
   mismatch.

**Shadow mode is the default.** Constraint findings annotate the evidence
record; they never alter traffic. Blocking is per-constraint opt-in
(`on_violation: "block"`).

## Quickstart

```bash
pip install -e .            # from this directory, Python 3.12
gatehouse produce <session> # emit the AER evidence packet (full + redacted)
gatehouse verify <bundle>   # offline verification -> tri-state verdict
```

The **evidence and verification** core (`produce`, `verify`, `verify-pair`, and
the whole `gatehouse.evidence`/`gatehouse.verify` API) installs and runs with no
extra dependencies.

The **check layer, proxy, and eval** additionally need the FCE runtime (package
`fiduciary`), which is not on PyPI — install it editable from the sibling repo
first:

```bash
pip install -e ../fiduciary-constraint-evaluation   # required for the below
gatehouse demo              # end-to-end proof: no keys, no network
gatehouse serve             # run the proxy on :8787
gatehouse eval configs/fce-eval.fixtures.json   # FCE 33 scenarios, no keys
```

Point an agent at the gate:

```bash
curl -X POST http://127.0.0.1:8787/gatehouse/sessions -d @session.json
# -> {"session_id": "...", "agent_fingerprint": "sha256:...", "contract_hash": "..."}

curl -X POST http://127.0.0.1:8787/v1/messages \
  -H "X-Gatehouse-Session: <session_id>" \
  -H "x-api-key: $ANTHROPIC_API_KEY" -H "anthropic-version: 2023-06-01" \
  -d '{"model": "claude-sonnet-5", "max_tokens": 256, "messages": [...]}'
```

## Design commitments (inherited from the AgentLedger red team, F1–F9)

- **F1** — identity is a session-bound key; a verifier never trusts an
  embedded fingerprint string.
- **F2** — verdicts are tri-state (`authenticated` /
  `consistent_unattributed` / `failed`); unsigned logs are never blessed.
- **F3** — redacted bundles bind per-entry to the sealed original through a
  signed manifest with the ordered source hash list.
- **F8** — canonicalization rejects lone surrogates.
- **F9** — Merkle leaves and nodes are domain-separated; odd nodes carry up.

See `DEFINITION_OF_DONE.md` for the evidence-linked build checklist,
`docs/INTEROP.md` for byte-exact constructions, and `docs/aer-feedback.md`
for what implementing the spec a second time revealed.

## Status

v0.1, built overnight 2026-07-10 → 07-11. Not yet published; license and
name are open human decisions (see `NEEDS_YOU.md`).
