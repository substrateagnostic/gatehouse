"""Session models and entry builders.

Two layers:
- Pydantic models for user-facing config (intent contract, constraints):
  validated at the door, PrismWeft-descended (see PROVENANCE in the AER repo).
- Plain-dict entry builders for chained entries: exact key control for
  hashing/serialization (docs/INTEROP.md).
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Literal, Optional

from pydantic import BaseModel, ConfigDict, Field

from .canonical import sha256_hex


def now_rfc3339() -> str:
    """RFC 3339 UTC with millisecond precision, TS-impl style."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def new_entry_id() -> str:
    return str(uuid.uuid4())


# ---------------------------------------------------------------------------
# Intent contract (user-facing, PrismWeft-descended)
# ---------------------------------------------------------------------------

class Severity(str, Enum):
    P0 = "P0"
    P1 = "P1"
    P2 = "P2"


class EnforcementType(str, Enum):
    """The three deterministically checkable constraint types (FCE-compatible)."""

    MUST_INCLUDE_HEADING = "must_include_heading"
    MUST_INCLUDE_REGEX = "must_include_regex"
    MUST_NOT_INCLUDE_REGEX = "must_not_include_regex"


class GateConstraint(BaseModel):
    """A single declared constraint, checkable at the gate.

    on_violation defaults to "flag" — shadow mode: observe and annotate,
    never surprise anyone. "block" is per-constraint opt-in.
    """

    model_config = ConfigDict(extra="forbid")

    id: str
    description: str
    severity: Severity = Severity.P1
    enforcement: EnforcementType
    target: str  # heading text or regex pattern
    applies_to: Literal["request", "response", "both"] = "both"
    on_violation: Literal["flag", "block"] = "flag"
    soul_invariant: bool = False


class RevisionPolicy(BaseModel):
    model_config = ConfigDict(extra="forbid")

    allow_revisions: bool = True
    max_revisions: int = 1
    requires_human_review: bool = False


class HumanAuthorizer(BaseModel):
    model_config = ConfigDict(extra="forbid")

    identifier: str
    role: str
    authorization_method: Optional[str] = None
    authorization_reference: Optional[str] = None
    authorized_at: Optional[str] = None


class SigningInfo(BaseModel):
    model_config = ConfigDict(extra="forbid")

    method: Optional[str] = None  # e.g. click_accept, typed_name, sso_accept_event
    signed_by: Optional[str] = None
    signed_at: Optional[str] = None


class SessionConfig(BaseModel):
    """Everything a caller declares when opening a gated session."""

    model_config = ConfigDict(extra="forbid")

    objective: str
    jurisdiction: Optional[str] = None
    role: Optional[str] = None
    constraints: list[GateConstraint] = Field(default_factory=list)
    facts_provided: list[str] = Field(default_factory=list)
    success_criteria: list[str] = Field(default_factory=list)
    revision_policy: RevisionPolicy = Field(default_factory=RevisionPolicy)
    human_authorizer: HumanAuthorizer
    signing: SigningInfo = Field(default_factory=SigningInfo)

    agent_id: str = "gatehouse-agent"
    agent_version: Optional[str] = None
    org_id: str = "gatehouse"
    environment: Literal["production", "staging", "development", "test"] = "development"
    compliance_contexts: list[str] = Field(default_factory=list)
    retention_days: int = 2555
    metadata: dict[str, Any] = Field(default_factory=dict)

    def intent_contract(self) -> dict[str, Any]:
        """The AER §3.5 intent_contract projection (hashed via JCS)."""
        contract: dict[str, Any] = {"objective": self.objective}
        if self.jurisdiction is not None:
            contract["jurisdiction"] = self.jurisdiction
        if self.role is not None:
            contract["role"] = self.role
        if self.constraints:
            contract["constraints"] = [
                {
                    "id": c.id,
                    "severity": c.severity.value,
                    "description": c.description,
                    "enforcement": {"type": c.enforcement.value, "value": c.target},
                    "applies_to": c.applies_to,
                    "on_violation": c.on_violation,
                    "soul_invariant": c.soul_invariant,
                }
                for c in self.constraints
            ]
        if self.facts_provided:
            contract["facts_provided"] = list(self.facts_provided)
        if self.success_criteria:
            contract["success_criteria"] = list(self.success_criteria)
        rp = self.revision_policy
        contract["revision_policy"] = (
            f"allow_revisions={rp.allow_revisions};max_revisions={rp.max_revisions};"
            f"requires_human_review={rp.requires_human_review}"
        )
        return contract


# ---------------------------------------------------------------------------
# Entry builders (plain dicts — exact key control; see docs/INTEROP.md §3)
# ---------------------------------------------------------------------------

def model_call_entry(
    *,
    provider: str,
    model_id: str,
    prompt: bytes,
    completion: bytes,
    prompt_tokens: int,
    completion_tokens: int,
    latency_ms: int,
    served_model: Optional[str] = None,
    parameters: Optional[dict[str, Any]] = None,
    streamed: bool = False,
    error: Optional[dict[str, Any]] = None,
    timestamp: Optional[str] = None,
) -> dict[str, Any]:
    """A model_call entry. `served_model` is the gatehouse addition:
    the model ID the PROVIDER asserted in the response body, as distinct
    from `model_id` (what was requested). Silent stepdowns/reroutes become
    visible in the record."""
    entry: dict[str, Any] = {
        "type": "model_call",
        "entry_id": new_entry_id(),
        "timestamp": timestamp or now_rfc3339(),
        "provider": provider,
        "model_id": model_id,
    }
    if served_model is not None:
        entry["served_model"] = served_model
    entry["parameters"] = parameters or {}
    entry["prompt_hash"] = sha256_hex(prompt)
    entry["prompt_tokens"] = prompt_tokens
    entry["completion_tokens"] = completion_tokens
    entry["completion_hash"] = sha256_hex(completion)
    entry["latency_ms"] = latency_ms
    entry["streamed"] = streamed
    if error is not None:
        entry["error"] = error
    return entry


def tool_invocation_entry(
    *,
    tool_name: str,
    input_bytes: bytes,
    output_bytes: bytes,
    duration_ms: int,
    success: bool,
    resources_accessed: Optional[list[dict[str, str]]] = None,
    error: Optional[dict[str, Any]] = None,
    timestamp: Optional[str] = None,
) -> dict[str, Any]:
    entry: dict[str, Any] = {
        "type": "tool_invocation",
        "entry_id": new_entry_id(),
        "timestamp": timestamp or now_rfc3339(),
        "tool_name": tool_name,
        "input_hash": sha256_hex(input_bytes),
        "output_hash": sha256_hex(output_bytes),
        "duration_ms": duration_ms,
        "success": success,
    }
    if error is not None:
        entry["error"] = error
    if resources_accessed:
        entry["resources_accessed"] = resources_accessed
    return entry


def decision_point_entry(
    *,
    decision_id: str,
    category: str,
    options_considered: list[dict[str, Any]],
    selected_option: str,
    reasoning: bytes,
    human_review_required: bool = False,
    confidence_score: Optional[float] = None,
    triggered_by: Optional[dict[str, Any]] = None,
    timestamp: Optional[str] = None,
) -> dict[str, Any]:
    """Used by the check layer: every gate disposition is a decision_point,
    so the constraint check itself is part of the evidentiary chain."""
    entry: dict[str, Any] = {
        "type": "decision_point",
        "entry_id": new_entry_id(),
        "timestamp": timestamp or now_rfc3339(),
        "decision_id": decision_id,
        "category": category,
        "options_considered": options_considered,
        "selected_option": selected_option,
        "reasoning_hash": sha256_hex(reasoning),
    }
    if confidence_score is not None:
        entry["confidence_score"] = confidence_score
    entry["human_review_required"] = human_review_required
    if triggered_by is not None:
        entry["triggered_by"] = triggered_by
    return entry


def human_approval_entry(
    *,
    approver_id: str,
    approver_role: str,
    decision_ref: str,
    approval_type: str,
    timestamp: Optional[str] = None,
) -> dict[str, Any]:
    return {
        "type": "human_approval",
        "entry_id": new_entry_id(),
        "timestamp": timestamp or now_rfc3339(),
        "approver_id": approver_id,
        "approver_role": approver_role,
        "decision_ref": decision_ref,
        "approval_type": approval_type,
    }


def content_reference_entry(
    *,
    content_type: str,
    parent_entry_id: str,
    content: bytes,
    storage_uri: Optional[str] = None,
    contains_pii: bool = False,
    pii_types: Optional[list[str]] = None,
    timestamp: Optional[str] = None,
) -> dict[str, Any]:
    entry: dict[str, Any] = {
        "type": "content_reference",
        "entry_id": new_entry_id(),
        "timestamp": timestamp or now_rfc3339(),
        "content_type": content_type,
        "parent_entry_id": parent_entry_id,
        "content_hash": sha256_hex(content),
        "size_bytes": len(content),
    }
    if storage_uri is not None:
        entry["storage_uri"] = storage_uri
    entry["contains_pii"] = contains_pii
    if pii_types:
        entry["pii_types"] = pii_types
    return entry
