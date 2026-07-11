"""Shared test fixtures.

Builds a real, closed session through the frozen ``SessionStore`` seam with a
representative mix of entries — including one ``model_call`` whose provider
served a different model than requested (``served_model`` != ``model_id``), a
``tool_invocation`` with resources, a ``decision_point``, and a
``content_reference`` flagged as containing PII — so every projection path in the
evidence layer is exercised by real data.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from gatehouse.models import (
    EnforcementType,
    GateConstraint,
    HumanAuthorizer,
    SessionConfig,
    Severity,
    content_reference_entry,
    decision_point_entry,
    model_call_entry,
    tool_invocation_entry,
)
from gatehouse.store import SessionStore

# Golden fixtures produced by the TypeScript reference implementation.
TS_DEMO_AUDIT_LOG = Path(
    r"C:\Users\agall\agentledger\examples\demo\output\audit-log.json"
)


@pytest.fixture
def store(tmp_path: Path) -> SessionStore:
    return SessionStore(root=tmp_path / "var")


def _config() -> SessionConfig:
    return SessionConfig(
        objective="Answer a customer weather question and summarize the exchange",
        jurisdiction="Minnesota",
        role="customer support assistant",
        constraints=[
            GateConstraint(
                id="no-advice",
                description="no financial or medical advice",
                severity=Severity.P0,
                enforcement=EnforcementType.MUST_NOT_INCLUDE_REGEX,
                target=r"(?i)\b(invest|diagnos)",
            )
        ],
        facts_provided=["customer opened a general support session"],
        success_criteria=["question answered", "session summarized"],
        agent_id="gatehouse-test-agent",
        agent_version="0.1.0",
        org_id="gatehouse-test",
        environment="test",
        compliance_contexts=["FINRA_4511", "EU_AI_ACT"],
        human_authorizer=HumanAuthorizer(
            identifier="compliance-officer@example.test",
            role="Chief Compliance Officer",
            authorization_method="written_directive",
            authorization_reference="DIR-TEST-001",
        ),
        metadata={"demo": True, "note": "a string value that redaction should strip"},
    )


def _populate(store: SessionStore, session_id: str) -> None:
    # 0: a model_call where the provider served a DIFFERENT model than requested
    # (silent stepdown evidence — served_model != model_id).
    store.append_entry(
        session_id,
        model_call_entry(
            provider="openai",
            model_id="gpt-4o",
            served_model="gpt-4o-mini",
            prompt=b"what is the weather in minneapolis?",
            completion=b"it is cold",
            prompt_tokens=12,
            completion_tokens=4,
            latency_ms=210,
        ),
    )
    # 1: a decision_point (free-text option descriptions get redacted).
    store.append_entry(
        session_id,
        decision_point_entry(
            decision_id="decision-weather-tool",
            category="tool_selection",
            options_considered=[
                {"option_id": "weather_api", "description": "Use the weather API tool", "score": 0.9},
                {"option_id": "direct_answer", "description": "Answer from knowledge", "score": 0.3},
            ],
            selected_option="weather_api",
            reasoning=b"the weather api is authoritative",
        ),
    )
    # 2: a tool_invocation with a resource identifier (redacted in derived form).
    store.append_entry(
        session_id,
        tool_invocation_entry(
            tool_name="weather_api",
            input_bytes=b"minneapolis",
            output_bytes=b"cold and clear",
            duration_ms=88,
            success=True,
            resources_accessed=[
                {"type": "api", "identifier": "weather.example.com", "operation": "read"}
            ],
        ),
    )
    # 3: a model_call with a faithful (served == requested) model.
    store.append_entry(
        session_id,
        model_call_entry(
            provider="openai",
            model_id="gpt-4o",
            served_model="gpt-4o",
            prompt=b"summarize the exchange",
            completion=b"the customer asked about weather; it is cold",
            prompt_tokens=40,
            completion_tokens=12,
            latency_ms=305,
        ),
    )
    # 4: a content_reference flagged as containing PII (populates data_accessed).
    store.append_entry(
        session_id,
        content_reference_entry(
            content_type="customer_message",
            parent_entry_id="00000000-0000-0000-0000-000000000000",
            content=b"my name is Jane Doe and my SSN is 000-00-0000",
            storage_uri="s3://private-bucket/customer/jane.txt",
            contains_pii=True,
            pii_types=["name", "ssn"],
        ),
    )


@pytest.fixture
def session_id(store: SessionStore) -> str:
    sid = store.create_session(_config())
    _populate(store, sid)
    store.close_session(sid)
    return sid
