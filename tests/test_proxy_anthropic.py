"""Anthropic-shaped passthrough tests (P2), against a stub upstream ASGI app --
no live API keys.
"""

from __future__ import annotations

import httpx
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.testclient import TestClient

from gatehouse.proxy import create_app
from gatehouse.store import SessionStore


def make_anthropic_stub(
    *,
    content: str = "Certainly, blue skies ahead.",
    status_code: int = 200,
    usage: dict | None = None,
):
    calls: list[dict] = []
    headers_seen: list[dict] = []
    stub = FastAPI()

    @stub.post("/v1/messages")
    async def messages(request: Request):
        body = await request.json()
        calls.append(body)
        headers_seen.append(dict(request.headers))
        if status_code >= 400:
            return JSONResponse(
                {"type": "error", "error": {"type": "api_error", "message": "upstream boom"}},
                status_code=status_code,
            )
        return JSONResponse(
            {
                "id": "msg_test",
                "model": body.get("model"),  # anthropic stub echoes the requested model back
                "content": [{"type": "text", "text": content}],
                "usage": usage or {"input_tokens": 9, "output_tokens": 3},
            }
        )

    return stub, calls, headers_seen


def open_session(tc: TestClient, constraints: list | None = None) -> dict:
    payload = {
        "objective": "Answer customer questions about our investment products.",
        "human_authorizer": {"identifier": "attorney@example.com", "role": "attorney"},
        "constraints": constraints or [],
    }
    resp = tc.post("/gatehouse/sessions", json=payload)
    assert resp.status_code == 201, resp.text
    return resp.json()


def anthropic_body(
    *, model: str = "claude-tiny", content: str = "What color is the sky?", stream: bool = False
) -> dict:
    return {
        "model": model,
        "system": [{"type": "text", "text": "Be concise."}],
        "messages": [{"role": "user", "content": [{"type": "text", "text": content}]}],
        "max_tokens": 64,
        "stream": stream,
    }


def _build_app(tmp_path, monkeypatch, stub) -> tuple[TestClient, SessionStore]:
    monkeypatch.setenv("GATEHOUSE_ANTHROPIC_BASE", "http://stub")
    store = SessionStore(tmp_path)
    client = httpx.AsyncClient(transport=httpx.ASGITransport(app=stub), base_url="http://stub")
    app = create_app(store=store, upstream_client=client)
    return TestClient(app), store


def test_forward_round_trip_with_structured_content_and_api_key_passthrough(tmp_path, monkeypatch):
    stub, calls, headers_seen = make_anthropic_stub(content="Blue, on a clear day.")
    tc, store = _build_app(tmp_path, monkeypatch, stub)
    session = open_session(tc)

    resp = tc.post(
        "/v1/messages",
        json=anthropic_body(model="claude-tiny"),
        headers={
            "X-Gatehouse-Session": session["session_id"],
            "x-api-key": "sk-ant-test",
            "anthropic-version": "2023-06-01",
        },
    )

    assert resp.status_code == 200
    assert resp.json()["content"][0]["text"] == "Blue, on a clear day."
    assert resp.headers["x-gatehouse-disposition"] == "correct_continue"
    assert len(calls) == 1
    assert headers_seen[0].get("x-api-key") == "sk-ant-test"
    assert headers_seen[0].get("anthropic-version") == "2023-06-01"

    entries = store.entries(session["session_id"])
    model_calls = [e["entry"] for e in entries if e["entry"]["type"] == "model_call"]
    assert len(model_calls) == 1
    mc = model_calls[0]
    assert mc["provider"] == "anthropic"
    assert mc["model_id"] == "claude-tiny"
    assert mc["served_model"] == "claude-tiny"
    assert mc["prompt_tokens"] == 9
    assert mc["completion_tokens"] == 3
    assert mc["parameters"]["max_tokens"] == 64


def test_upstream_error_passthrough_records_error_entry(tmp_path, monkeypatch):
    stub, calls, _headers = make_anthropic_stub(status_code=529)
    tc, store = _build_app(tmp_path, monkeypatch, stub)
    session = open_session(tc)

    resp = tc.post(
        "/v1/messages",
        json=anthropic_body(),
        headers={"X-Gatehouse-Session": session["session_id"], "x-api-key": "sk-ant-test"},
    )

    assert resp.status_code == 529
    assert len(calls) == 1

    entries = store.entries(session["session_id"])
    model_calls = [e["entry"] for e in entries if e["entry"]["type"] == "model_call"]
    assert len(model_calls) == 1
    err = model_calls[0]
    assert err["error"]["code"] == "529"
    assert err["error"]["retryable"] is False
    assert "served_model" not in err


def test_streaming_requests_get_an_honest_501_and_forward_nothing(tmp_path, monkeypatch):
    stub, calls, _headers = make_anthropic_stub()
    tc, _store = _build_app(tmp_path, monkeypatch, stub)
    session = open_session(tc)

    resp = tc.post(
        "/v1/messages",
        json=anthropic_body(stream=True),
        headers={"X-Gatehouse-Session": session["session_id"], "x-api-key": "sk-ant-test"},
    )

    assert resp.status_code == 501
    assert calls == []
