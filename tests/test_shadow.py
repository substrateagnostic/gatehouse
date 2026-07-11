"""P4 -- shadow mode is the default. Proves:
1. A `flag` (default) violation never mutates the response the caller
   receives -- byte-equal to what the upstream stub itself produced.
2. A `block` (opt-in) violation on the request forwards nothing at all and
   returns a structured, recorded refusal, without ever leaking the
   checked text into the evidence log.
"""

from __future__ import annotations

import json

import httpx
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.testclient import TestClient

from gatehouse.proxy import create_app
from gatehouse.store import SessionStore

_NO_DETECTOR_NOTE = "no supported detector fired; stand-down is not an affirmative safety proof"


def make_openai_stub(*, content: str, model: str = "gpt-5.5-mini-2026-01-06", usage: dict | None = None):
    calls: list[dict] = []
    stub = FastAPI()

    @stub.post("/v1/chat/completions")
    async def chat_completions(request: Request):
        body = await request.json()
        calls.append(body)
        return JSONResponse(
            {
                "id": "chatcmpl-test",
                "model": model,
                "choices": [
                    {
                        "index": 0,
                        "message": {"role": "assistant", "content": content},
                        "finish_reason": "stop",
                    }
                ],
                "usage": usage or {"prompt_tokens": 11, "completion_tokens": 4},
            }
        )

    return stub, calls


def open_session(tc: TestClient, constraints: list) -> dict:
    payload = {
        "objective": "Answer customer questions about our investment products.",
        "human_authorizer": {"identifier": "attorney@example.com", "role": "attorney"},
        "constraints": constraints,
    }
    resp = tc.post("/gatehouse/sessions", json=payload)
    assert resp.status_code == 201, resp.text
    return resp.json()


def chat_body(*, content: str) -> dict:
    return {
        "model": "gpt-5.5",
        "messages": [
            {"role": "system", "content": "You are a helpful assistant."},
            {"role": "user", "content": content},
        ],
        "max_tokens": 128,
    }


def _build_app(tmp_path, monkeypatch, stub) -> tuple[TestClient, SessionStore]:
    monkeypatch.setenv("GATEHOUSE_OPENAI_BASE", "http://stub")
    store = SessionStore(tmp_path)
    client = httpx.AsyncClient(transport=httpx.ASGITransport(app=stub), base_url="http://stub")
    app = create_app(store=store, upstream_client=client)
    return TestClient(app), store


def test_default_flag_violation_never_mutates_the_response(tmp_path, monkeypatch):
    reply = "Guaranteed returns await you. No risk at all."
    model = "gpt-5.5-mini-2026-01-06"
    usage = {"prompt_tokens": 11, "completion_tokens": 4}
    stub, calls = make_openai_stub(content=reply, model=model, usage=usage)
    tc, store = _build_app(tmp_path, monkeypatch, stub)

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
    session = open_session(tc, [constraint])

    resp = tc.post(
        "/v1/chat/completions",
        json=chat_body(content="Tell me about this investment."),
        headers={"X-Gatehouse-Session": session["session_id"]},
    )

    # The exact bytes the stub itself renders for this body, computed
    # independently of gatehouse -- proves the default path never mutates.
    expected_bytes = JSONResponse(
        {
            "id": "chatcmpl-test",
            "model": model,
            "choices": [
                {"index": 0, "message": {"role": "assistant", "content": reply}, "finish_reason": "stop"}
            ],
            "usage": usage,
        }
    ).body

    assert resp.status_code == 200
    assert resp.content == expected_bytes
    assert resp.headers["x-gatehouse-disposition"] == "flag"
    assert len(calls) == 1  # it *was* forwarded -- shadow observes, doesn't intercept

    annotations = store.annotations(session["session_id"])
    request_annotation = next(a for a in annotations if a["phase"] == "request")
    response_annotation = next(a for a in annotations if a["phase"] == "response")

    assert request_annotation["disposition"] == "correct_continue"
    assert request_annotation["note"] == _NO_DETECTOR_NOTE
    assert request_annotation["action_taken"] == "observed"

    assert response_annotation["disposition"] == "flag"
    assert "no-guarantees" in response_annotation["constraint_ids"]
    assert response_annotation["action_taken"] == "flagged"

    decisions = [
        e["entry"] for e in store.entries(session["session_id"]) if e["entry"]["type"] == "decision_point"
    ]
    assert len(decisions) == 1
    assert decisions[0]["selected_option"] == "flag"


def test_block_on_violation_forwards_nothing_and_records_the_refusal(tmp_path, monkeypatch):
    stub, calls = make_openai_stub(content="should never be reached")
    tc, store = _build_app(tmp_path, monkeypatch, stub)

    constraint = {
        "id": "no-ssn",
        "description": "Must not include a social security number pattern",
        "severity": "P0",
        "enforcement": "must_not_include_regex",
        "target": r"\d{3}-\d{2}-\d{4}",
        "applies_to": "request",
        "on_violation": "block",
        "soul_invariant": True,
    }
    session = open_session(tc, [constraint])

    resp = tc.post(
        "/v1/chat/completions",
        json=chat_body(content="My SSN is 123-45-6789, please help."),
        headers={"X-Gatehouse-Session": session["session_id"]},
    )

    assert resp.status_code == 403
    payload = resp.json()
    assert payload["gatehouse"]["blocked"] is True
    assert "no-ssn" in payload["gatehouse"]["constraint_ids"]
    assert payload["gatehouse"]["disposition"] == "block"
    assert calls == []  # nothing forwarded upstream

    entries = store.entries(session["session_id"])
    decisions = [e["entry"] for e in entries if e["entry"]["type"] == "decision_point"]
    assert len(decisions) == 1
    assert decisions[0]["selected_option"] == "block"
    assert decisions[0]["category"] == "content_filter"
    assert decisions[0]["human_review_required"] is True  # soul invariant fired
    assert {"option_id": "forward"} in decisions[0]["options_considered"]
    assert {"option_id": "block"} in decisions[0]["options_considered"]

    model_calls = [e["entry"] for e in entries if e["entry"]["type"] == "model_call"]
    assert model_calls == []  # no model was ever called

    annotations = store.annotations(session["session_id"])
    assert len(annotations) == 1
    assert annotations[0]["action_taken"] == "blocked"
    assert annotations[0]["phase"] == "request"

    # Content-free: the actual SSN, and the whole prompt, never appear
    # anywhere in the persisted chain or annotations.
    serialized_entries = json.dumps(entries)
    serialized_annotations = json.dumps(annotations)
    assert "123-45-6789" not in serialized_entries
    assert "123-45-6789" not in serialized_annotations
    assert "My SSN is" not in serialized_entries
    assert "My SSN is" not in serialized_annotations
