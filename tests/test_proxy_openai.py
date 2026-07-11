"""OpenAI-shaped passthrough tests (P1), against a stub upstream ASGI app --
no live API keys. Wires gatehouse's create_app() with an httpx.AsyncClient
bound via ASGITransport to a local FastAPI stub standing in for
api.openai.com.
"""

from __future__ import annotations

import httpx
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.testclient import TestClient

from gatehouse.proxy import create_app
from gatehouse.store import SessionStore


def make_openai_stub(
    *,
    content: str = "Sure, here is a plain answer.",
    model: str = "gpt-5.5-mini-2026-01-06",
    status_code: int = 200,
    usage: dict | None = None,
):
    """A stub that always serves `model` regardless of what was requested --
    simulating a silent provider stepdown, per the task brief."""
    calls: list[dict] = []
    stub = FastAPI()

    @stub.post("/v1/chat/completions")
    async def chat_completions(request: Request):
        body = await request.json()
        calls.append(body)
        if status_code >= 400:
            return JSONResponse(
                {"error": {"message": "upstream boom", "type": "server_error"}},
                status_code=status_code,
            )
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


def open_session(tc: TestClient, constraints: list | None = None) -> dict:
    payload = {
        "objective": "Answer customer questions about our investment products.",
        "human_authorizer": {"identifier": "attorney@example.com", "role": "attorney"},
        "constraints": constraints or [],
    }
    resp = tc.post("/gatehouse/sessions", json=payload)
    assert resp.status_code == 201, resp.text
    return resp.json()


def chat_body(*, model: str = "gpt-5.5", content: str = "What's the weather like?", stream: bool = False) -> dict:
    return {
        "model": model,
        "messages": [
            {"role": "system", "content": "You are a helpful assistant."},
            {"role": "user", "content": content},
        ],
        "temperature": 0.2,
        "max_tokens": 128,
        "stream": stream,
    }


def _build_app(tmp_path, monkeypatch, stub) -> tuple[TestClient, SessionStore]:
    monkeypatch.setenv("GATEHOUSE_OPENAI_BASE", "http://stub")
    store = SessionStore(tmp_path)
    client = httpx.AsyncClient(transport=httpx.ASGITransport(app=stub), base_url="http://stub")
    app = create_app(store=store, upstream_client=client)
    return TestClient(app), store


def test_forward_round_trip_records_served_model_mismatch(tmp_path, monkeypatch):
    stub, calls = make_openai_stub(content="Diversification helps manage risk.")
    tc, store = _build_app(tmp_path, monkeypatch, stub)
    session = open_session(tc)

    resp = tc.post(
        "/v1/chat/completions",
        json=chat_body(model="gpt-5.5"),
        headers={"X-Gatehouse-Session": session["session_id"], "Authorization": "Bearer sk-test"},
    )

    assert resp.status_code == 200
    assert resp.json()["model"] == "gpt-5.5-mini-2026-01-06"
    assert resp.headers["x-gatehouse-disposition"] == "correct_continue"
    assert len(calls) == 1

    entries = store.entries(session["session_id"])
    model_calls = [e["entry"] for e in entries if e["entry"]["type"] == "model_call"]
    assert len(model_calls) == 1
    mc = model_calls[0]
    assert mc["provider"] == "openai"
    assert mc["model_id"] == "gpt-5.5"
    assert mc["served_model"] == "gpt-5.5-mini-2026-01-06"
    assert mc["model_id"] != mc["served_model"]  # the silent-stepdown signal
    assert mc["prompt_tokens"] == 11
    assert mc["completion_tokens"] == 4
    assert mc["parameters"]["temperature"] == 0.2
    assert mc["parameters"]["max_tokens"] == 128
    assert mc["streamed"] is False
    assert "error" not in mc


def test_upstream_error_passthrough_records_error_entry(tmp_path, monkeypatch):
    stub, calls = make_openai_stub(status_code=500)
    tc, store = _build_app(tmp_path, monkeypatch, stub)
    session = open_session(tc)

    resp = tc.post(
        "/v1/chat/completions",
        json=chat_body(),
        headers={"X-Gatehouse-Session": session["session_id"]},
    )

    assert resp.status_code == 500
    assert len(calls) == 1

    entries = store.entries(session["session_id"])
    model_calls = [e["entry"] for e in entries if e["entry"]["type"] == "model_call"]
    assert len(model_calls) == 1
    err = model_calls[0]
    assert err["error"]["code"] == "500"
    assert err["error"]["message"] == "upstream error"
    assert err["error"]["retryable"] is True
    assert "served_model" not in err


def test_streaming_requests_get_an_honest_501_and_forward_nothing(tmp_path, monkeypatch):
    stub, calls = make_openai_stub()
    tc, store = _build_app(tmp_path, monkeypatch, stub)
    session = open_session(tc)

    resp = tc.post(
        "/v1/chat/completions",
        json=chat_body(stream=True),
        headers={"X-Gatehouse-Session": session["session_id"]},
    )

    assert resp.status_code == 501
    assert calls == []


def test_missing_session_header_is_428(tmp_path):
    tc = TestClient(create_app(store=SessionStore(tmp_path)))
    resp = tc.post("/v1/chat/completions", json=chat_body())
    assert resp.status_code == 428


def test_unknown_session_id_is_428(tmp_path, monkeypatch):
    stub, calls = make_openai_stub()
    tc, _store = _build_app(tmp_path, monkeypatch, stub)

    resp = tc.post(
        "/v1/chat/completions",
        json=chat_body(),
        headers={"X-Gatehouse-Session": "does-not-exist"},
    )
    assert resp.status_code == 428
    assert calls == []
