# TypeScript reference vectors (AgentLedger v2)

Golden output produced by the AgentLedger v2 reference implementation
(github.com/substrateagnostic/agentledger, `examples/demo` + CLI `produce`),
vendored here so gatehouse's byte-for-byte conformance tests (test_chain,
test_merkle, test_verdict cross-impl) are self-contained on a gatehouse-only
clone rather than depending on a sibling checkout (Fable review E2/E3 caveat).

- `ts-reference-audit-log.json` — a 6-entry sealed AuditLog; gatehouse
  recomputes every entry_hash and the merkle_root byte-for-byte and verifies it
  AUTHENTICATED (cross-implementation verification).
- `ts-reference-evidence-record.json` — a §4 evidence record used to pin the
  seal/fingerprint/contract_hash constructions.

These are inputs to gatehouse's verifier, not gatehouse output. Regenerate from
the agentledger repo if the reference construction changes.
