"""Probe the TS-produced golden evidence record to pin down exact constructions."""
import base64, hashlib, json, sys
import rfc8785
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.exceptions import InvalidSignature

rec = json.load(open(r"C:\Users\agall\agentledger\packages\cli\v2-log-1783745433958.evidence_record.json", encoding="utf-8"))

ai = rec["agent_identity"]
op = rec["operations"][0]
pc = rec["policy_context"]
att = pc["integrity_attestation"]

# 1. fingerprint = sha256: + hex(sha256(raw 32-byte pubkey))
pem = base64.b64decode(ai["public_key"])
pub = load_pem_public_key(pem)
raw = pub.public_bytes_raw()
fp = "sha256:" + hashlib.sha256(raw).hexdigest()
print("1. fingerprint match:", fp == ai["fingerprint"])

# 2. single-leaf merkle root: leaf = sha256(0x00 || entry_hash_bytes)
leaf = hashlib.sha256(b"\x00" + bytes.fromhex(op["entry_hash"])).hexdigest()
print("2. merkle single-leaf==root:", leaf == att["merkle_root"])
# alt: leaf over utf-8 hex string
leaf2 = hashlib.sha256(b"\x00" + op["entry_hash"].encode()).hexdigest()
print("   (alt utf8-hex leaf):", leaf2 == att["merkle_root"])

# 3. agent_signature preimage: try utf-8 bytes of entry_hash hex string
sig = base64.b64decode(op["agent_signature"]["signature"])
for label, preimage in [
    ("utf8 hex string", op["entry_hash"].encode()),
    ("raw 32 bytes", bytes.fromhex(op["entry_hash"])),
]:
    try:
        pub.verify(sig, preimage)
        print(f"3. agent_signature over {label}: VERIFIES")
    except InvalidSignature:
        print(f"3. agent_signature over {label}: no")

# 4. seal preimage: integrity block variants
org_pem = base64.b64decode(att["org_signature"]["public_key"])
org_pub = load_pem_public_key(org_pem)
org_sig = base64.b64decode(att["org_signature"]["signature"])
base = {
    "session_id": pc["session_id"],
    "merkle_root": att["merkle_root"],
    "entry_count": len(rec["operations"]),
    "closed_at": pc["closed_at"],
    "schema_version": 2,
    "agent_fingerprint": ai["fingerprint"],
}
for canon_label in ["RFC8785", "jcs", None]:
    block = dict(base)
    if canon_label is not None:
        block["canonicalization"] = canon_label
    data = rfc8785.dumps(block)
    try:
        org_pub.verify(org_sig, data)
        print(f"4. seal over block with canonicalization={canon_label!r}: VERIFIES")
    except InvalidSignature:
        print(f"4. seal with canonicalization={canon_label!r}: no")

# 5. contract_hash = sha256 hex of JCS of intent_contract
ch = hashlib.sha256(rfc8785.dumps(pc["intent_contract"])).hexdigest()
print("5. contract_hash match:", ch == pc["contract_hash"])

# 6. rfc8785 lone surrogate behavior
try:
    rfc8785.dumps({"s": "bad\ud800"})
    print("6. lone surrogate: ACCEPTED (must add our own rejection)")
except Exception as e:
    print("6. lone surrogate: rejected ->", type(e).__name__)
