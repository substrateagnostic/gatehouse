"""Session persistence.

Layout, per session, under var/sessions/<session_id>/:
  session.json       — session envelope config + public identity + lifecycle
  agent_key.pem      — the per-session agent Ed25519 private key (F1: the
                       identity is a key bound to THIS session)
  operator_key.pem   — the operator (seal) private key for this gatehouse
                       instance (shared across sessions, stored per install
                       under var/operator_key.pem)
  entries.ndjson     — ChainedEntry per line, appended as operations happen
                       (compact JSON, trailing newline)
  annotations.ndjson — check-layer verdicts (shadow annotations), one per
                       checked payload; NOT part of the hash chain, but each
                       annotation names the entry_id it annotates
  content/<sha256>   — raw payload bytes, content-addressed, so hashes in the
                       record are reproducible against stored content

Key custody note: plaintext PEMs on disk are a deployment shortcut for v0.1;
production custody (platform keystore/HSM) is spec §8's problem and is listed
in NEEDS_YOU.md.
"""

from __future__ import annotations

import json
import uuid
from pathlib import Path
from typing import Any, Optional

from .chain import chained_entry
from .keys import AgentKey
from .models import SessionConfig, now_rfc3339


def _write_json(path: Path, obj: Any) -> None:
    path.write_text(json.dumps(obj, indent=2, ensure_ascii=False), encoding="utf-8", newline="\n")


def _append_ndjson(path: Path, obj: Any) -> None:
    with path.open("a", encoding="utf-8", newline="\n") as f:
        f.write(json.dumps(obj, separators=(",", ":"), ensure_ascii=False) + "\n")


class SessionStore:
    """Filesystem-backed session state. One instance per gatehouse process."""

    def __init__(self, root: Path | str = "var"):
        self.root = Path(root)
        self.sessions_dir = self.root / "sessions"
        self.sessions_dir.mkdir(parents=True, exist_ok=True)

    # -- operator identity (per install) ------------------------------------

    def operator_key(self) -> AgentKey:
        path = self.root / "operator_key.pem"
        if path.exists():
            return AgentKey.from_private_pem(path.read_bytes())
        key = AgentKey.generate()
        path.write_bytes(key.private_pem())
        return key

    # -- session lifecycle ---------------------------------------------------

    def create_session(self, config: SessionConfig) -> str:
        session_id = str(uuid.uuid4())
        sdir = self.sessions_dir / session_id
        (sdir / "content").mkdir(parents=True)

        agent_key = AgentKey.generate()
        (sdir / "agent_key.pem").write_bytes(agent_key.private_pem())

        contract = config.intent_contract()
        from .canonical import sha256_jcs

        session = {
            "session_id": session_id,
            "org_id": config.org_id,
            "agent_id": config.agent_id,
            **({"agent_version": config.agent_version} if config.agent_version else {}),
            "agent_public_key": agent_key.public_b64,
            "agent_fingerprint": agent_key.fingerprint,
            "signature_scheme": "ed25519",
            "environment": config.environment,
            "initiated_by": {
                "type": "api",
                "identifier": config.human_authorizer.identifier,
            },
            "initiated_at": now_rfc3339(),
            "compliance_contexts": list(config.compliance_contexts),
            "policy_context": [],
            "human_authorizer": config.human_authorizer.model_dump(exclude_none=True),
            "intent_contract": contract,
            "contract_hash": sha256_jcs(contract),
            "retention_days": config.retention_days,
            **({"metadata": config.metadata} if config.metadata else {}),
        }
        _write_json(sdir / "session.json", session)
        _write_json(
            sdir / "gate_config.json",
            json.loads(config.model_dump_json(exclude_none=True)),
        )
        return session_id

    def session_dir(self, session_id: str) -> Path:
        sdir = self.sessions_dir / session_id
        if not sdir.exists():
            raise KeyError(f"unknown session: {session_id}")
        return sdir

    def load_session(self, session_id: str) -> dict[str, Any]:
        return json.loads((self.session_dir(session_id) / "session.json").read_text(encoding="utf-8"))

    def load_gate_config(self, session_id: str) -> SessionConfig:
        raw = (self.session_dir(session_id) / "gate_config.json").read_text(encoding="utf-8")
        return SessionConfig.model_validate_json(raw)

    def agent_key(self, session_id: str) -> AgentKey:
        return AgentKey.from_private_pem(
            (self.session_dir(session_id) / "agent_key.pem").read_bytes()
        )

    def close_session(self, session_id: str) -> dict[str, Any]:
        sdir = self.session_dir(session_id)
        session = self.load_session(session_id)
        if "closed_at" not in session:
            session["closed_at"] = now_rfc3339()
            _write_json(sdir / "session.json", session)
        return session

    # -- entries ---------------------------------------------------------------

    def entries(self, session_id: str) -> list[dict[str, Any]]:
        path = self.session_dir(session_id) / "entries.ndjson"
        if not path.exists():
            return []
        return [
            json.loads(line)
            for line in path.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]

    def append_entry(
        self,
        session_id: str,
        entry: dict[str, Any],
        *,
        authorized_by: Optional[dict[str, Any]] = None,
    ) -> dict[str, Any]:
        """Chain, sign (session agent key), persist. Returns the ChainedEntry."""
        sdir = self.session_dir(session_id)
        existing = self.entries(session_id)
        sequence = len(existing)
        previous_hash = existing[-1]["entry_hash"] if existing else ""

        key = self.agent_key(session_id)
        wrapper = chained_entry(
            sequence,
            entry,
            previous_hash,
            authorized_by=authorized_by,
        )
        wrapper["agent_signature"] = {
            "fingerprint": key.fingerprint,
            "public_key": key.public_b64,
            "signature": key.sign_entry_hash(wrapper["entry_hash"]),
        }
        _append_ndjson(sdir / "entries.ndjson", wrapper)
        return wrapper

    # -- annotations (shadow-mode check verdicts; not chained) -----------------

    def append_annotation(self, session_id: str, annotation: dict[str, Any]) -> None:
        _append_ndjson(self.session_dir(session_id) / "annotations.ndjson", annotation)

    def annotations(self, session_id: str) -> list[dict[str, Any]]:
        path = self.session_dir(session_id) / "annotations.ndjson"
        if not path.exists():
            return []
        return [
            json.loads(line)
            for line in path.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]

    # -- content store ----------------------------------------------------------

    def put_content(self, session_id: str, content: bytes) -> str:
        from .canonical import sha256_hex

        h = sha256_hex(content)
        path = self.session_dir(session_id) / "content" / h
        if not path.exists():
            path.write_bytes(content)
        return h

    def list_sessions(self) -> list[str]:
        return sorted(p.name for p in self.sessions_dir.iterdir() if p.is_dir())
