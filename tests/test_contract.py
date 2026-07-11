"""P3 -- per-session intent contract tests: session open happy path, bad
regex rejected at session-open (400), contract_hash present, unknown
session -> 428.
"""

from __future__ import annotations

import httpx
from fastapi.testclient import TestClient

from gatehouse.proxy import create_app
from gatehouse.store import SessionStore


def _tc(tmp_path) -> TestClient:
    store = SessionStore(tmp_path)
    # No upstream calls are exercised in this file; a client pointed at a
    # dead base is enough (no test here reaches the passthrough forward path).
    client = httpx.AsyncClient()
    return TestClient(create_app(store=store, upstream_client=client))


def _session_payload(constraints: list | None = None) -> dict:
    return {
        "objective": "Answer customer questions about our investment products.",
        "jurisdiction": "US-MN",
        "role": "financial advisor assistant",
        "human_authorizer": {"identifier": "attorney@example.com", "role": "attorney"},
        "constraints": constraints or [],
    }


def test_open_session_happy_path(tmp_path):
    tc = _tc(tmp_path)
    constraint = {
        "id": "no-guarantees",
        "description": "Must not promise guaranteed returns",
        "severity": "P1",
        "enforcement": "must_not_include_regex",
        "target": r"guarantee(d)?",
        "applies_to": "response",
        "on_violation": "flag",
        "soul_invariant": False,
    }

    resp = tc.post("/gatehouse/sessions", json=_session_payload([constraint]))

    assert resp.status_code == 201, resp.text
    body = resp.json()
    assert set(body.keys()) == {"session_id", "agent_fingerprint", "contract_hash"}
    assert body["session_id"]
    assert body["agent_fingerprint"].startswith("sha256:")
    assert len(body["contract_hash"]) == 64  # sha256 hex

    # GET reflects it back, including the contract hash and an annotation count
    get_resp = tc.get(f"/gatehouse/sessions/{body['session_id']}")
    assert get_resp.status_code == 200
    session = get_resp.json()
    assert session["contract_hash"] == body["contract_hash"]
    assert session["annotation_count"] == 0
    assert session["intent_contract"]["objective"] == "Answer customer questions about our investment products."


def test_bad_regex_constraint_rejected_at_session_open(tmp_path):
    tc = _tc(tmp_path)
    bad_constraint = {
        "id": "broken-pattern",
        "description": "This regex does not compile",
        "severity": "P1",
        "enforcement": "must_include_regex",
        "target": "(unclosed[",
        "applies_to": "response",
        "on_violation": "flag",
        "soul_invariant": False,
    }

    resp = tc.post("/gatehouse/sessions", json=_session_payload([bad_constraint]))

    assert resp.status_code == 400
    detail = resp.json()["detail"]
    assert any("broken-pattern" in problem for problem in detail["problems"])


def test_close_session(tmp_path):
    tc = _tc(tmp_path)
    session_id = tc.post("/gatehouse/sessions", json=_session_payload()).json()["session_id"]

    resp = tc.post(f"/gatehouse/sessions/{session_id}/close")

    assert resp.status_code == 200
    body = resp.json()
    assert body["session_id"] == session_id
    assert body["closed_at"]


def test_unknown_session_on_passthrough_is_428(tmp_path):
    tc = _tc(tmp_path)

    resp = tc.post(
        "/v1/chat/completions",
        json={"model": "gpt-5.5", "messages": [{"role": "user", "content": "hi"}]},
        headers={"X-Gatehouse-Session": "totally-unknown-session-id"},
    )

    assert resp.status_code == 428
    assert "open a session" in resp.json()["detail"]["error"]


def test_missing_session_header_on_passthrough_is_428(tmp_path):
    tc = _tc(tmp_path)

    resp = tc.post(
        "/v1/chat/completions",
        json={"model": "gpt-5.5", "messages": [{"role": "user", "content": "hi"}]},
    )

    assert resp.status_code == 428


def test_unknown_session_id_on_direct_lookup_is_404(tmp_path):
    tc = _tc(tmp_path)
    resp = tc.get("/gatehouse/sessions/does-not-exist")
    assert resp.status_code == 404
