"""Ed25519 identity: the identity IS the key (AER v0.1 §3.1, red-team F1).

- public_key: base64 of the SPKI PEM text (matching the TS reference impl)
- fingerprint: "sha256:" + lowercase hex SHA-256 of the raw 32-byte public key
- per-entry agent signature: Ed25519 over the UTF-8 bytes of the entry_hash
  hex string (pinned against the TS impl — probe_golden_output.txt line 3)

A per-agent key is generated per session and bound to it; a verifier checks
signatures against the SESSION key, never against whatever key an entry
happens to embed (that was the F1 forgery).
"""

from __future__ import annotations

import base64
import hashlib
from dataclasses import dataclass

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

__all__ = [
    "AgentKey",
    "fingerprint_of",
    "load_public_key_b64",
    "public_key_b64",
    "verify_signature",
]


def public_key_b64(public: Ed25519PublicKey) -> str:
    """base64 of the SPKI PEM text of *public* (TS-impl-compatible)."""
    pem = public.public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return base64.b64encode(pem).decode("ascii")


def load_public_key_b64(b64_pem: str) -> Ed25519PublicKey:
    pem = base64.b64decode(b64_pem)
    key = serialization.load_pem_public_key(pem)
    if not isinstance(key, Ed25519PublicKey):
        raise ValueError("public key is not Ed25519")
    return key


def fingerprint_of(public: Ed25519PublicKey) -> str:
    raw = public.public_bytes_raw()
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def verify_signature(public: Ed25519PublicKey, signature_b64: str, message: bytes) -> bool:
    try:
        public.verify(base64.b64decode(signature_b64), message)
        return True
    except InvalidSignature:
        return False


@dataclass
class AgentKey:
    """An Ed25519 keypair with AER identity projections."""

    private: Ed25519PrivateKey

    @classmethod
    def generate(cls) -> "AgentKey":
        return cls(private=Ed25519PrivateKey.generate())

    @property
    def public(self) -> Ed25519PublicKey:
        return self.private.public_key()

    @property
    def public_b64(self) -> str:
        return public_key_b64(self.public)

    @property
    def fingerprint(self) -> str:
        return fingerprint_of(self.public)

    def sign_b64(self, message: bytes) -> str:
        return base64.b64encode(self.private.sign(message)).decode("ascii")

    def sign_entry_hash(self, entry_hash_hex: str) -> str:
        """Sign the UTF-8 bytes of the entry_hash hex string (TS-compatible)."""
        return self.sign_b64(entry_hash_hex.encode("utf-8"))

    def private_pem(self) -> bytes:
        return self.private.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )

    @classmethod
    def from_private_pem(cls, pem: bytes) -> "AgentKey":
        key = serialization.load_pem_private_key(pem, password=None)
        if not isinstance(key, Ed25519PrivateKey):
            raise ValueError("private key is not Ed25519")
        return cls(private=key)
