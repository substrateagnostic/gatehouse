"""The proxy core: FastAPI app that sits between an agent and a model API.

Declared scope in (POST /gatehouse/sessions), constraint-checked traffic
through (/v1/chat/completions, /v1/messages), evidence out (every exchange
becomes a model_call entry + a decision_point entry + annotations in the
session's evidentiary chain).

Shadow mode is the default (P4): constraint findings from the check layer
annotate the record but never alter traffic. Only a per-constraint
`on_violation: block` opt-in changes what the caller receives, and that
block is itself recorded, never silent.
"""

from __future__ import annotations

import dataclasses
import json
import os
import time
from typing import Any, Optional

import httpx
from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.responses import JSONResponse

from .checks import CheckResult, check_text, validate_constraints
from .models import GateConstraint, SessionConfig, decision_point_entry, model_call_entry, now_rfc3339
from .store import SessionStore

__all__ = ["create_app"]

_SESSION_HEADER = "x-gatehouse-session"
_MISSING_SESSION_MSG = (
    "open a session at /gatehouse/sessions first — "
    "the gate records nothing it cannot attribute"
)
_PRECEDENCE = {"correct_continue": 0, "flag": 1, "escalate": 2, "block": 3}
_ACTION_TAKEN = {
    "correct_continue": "observed",
    "flag": "flagged",
    "escalate": "escalated",
    "block": "blocked",
}


def create_app(
    store: Optional[SessionStore] = None,
    upstream_client: Optional[httpx.AsyncClient] = None,
) -> FastAPI:
    store = store or SessionStore()
    client = upstream_client or httpx.AsyncClient()
    openai_base = os.environ.get("GATEHOUSE_OPENAI_BASE", "https://api.openai.com").rstrip("/")
    anthropic_base = os.environ.get("GATEHOUSE_ANTHROPIC_BASE", "https://api.anthropic.com").rstrip("/")

    app = FastAPI(title="gatehouse")

    @app.post("/gatehouse/sessions", status_code=201)
    async def open_session(config: SessionConfig) -> dict:
        problems = validate_constraints(config.constraints)
        if problems:
            raise HTTPException(
                status_code=400,
                detail={"error": "invalid constraints", "problems": problems},
            )
        session_id = store.create_session(config)
        session = store.load_session(session_id)
        return {
            "session_id": session_id,
            "agent_fingerprint": session["agent_fingerprint"],
            "contract_hash": session["contract_hash"],
        }

    @app.post("/gatehouse/sessions/{session_id}/close")
    async def close_session_endpoint(session_id: str) -> dict:
        try:
            session = store.close_session(session_id)
        except KeyError:
            raise HTTPException(status_code=404, detail=f"unknown session: {session_id}")
        return {"session_id": session_id, "closed_at": session["closed_at"]}

    @app.get("/gatehouse/sessions/{session_id}")
    async def get_session_endpoint(session_id: str) -> dict:
        try:
            session = store.load_session(session_id)
        except KeyError:
            raise HTTPException(status_code=404, detail=f"unknown session: {session_id}")
        annotations = store.annotations(session_id)
        return {**session, "annotation_count": len(annotations)}

    @app.post("/v1/chat/completions")
    async def openai_chat_completions(request: Request):
        return await _proxy_exchange(
            request,
            provider="openai",
            store=store,
            client=client,
            base=openai_base,
            path="/v1/chat/completions",
        )

    @app.post("/v1/messages")
    async def anthropic_messages(request: Request):
        return await _proxy_exchange(
            request,
            provider="anthropic",
            store=store,
            client=client,
            base=anthropic_base,
            path="/v1/messages",
        )

    return app


# ---------------------------------------------------------------------------
# Passthrough core (shared by both providers)
# ---------------------------------------------------------------------------


async def _proxy_exchange(
    request: Request,
    *,
    provider: str,
    store: SessionStore,
    client: httpx.AsyncClient,
    base: str,
    path: str,
):
    session_id = request.headers.get(_SESSION_HEADER)
    if not session_id:
        raise HTTPException(status_code=428, detail={"error": _MISSING_SESSION_MSG})
    try:
        gate_config = store.load_gate_config(session_id)
    except KeyError:
        raise HTTPException(status_code=428, detail={"error": _MISSING_SESSION_MSG})

    raw_body = await request.body()
    try:
        body: dict[str, Any] = json.loads(raw_body.decode("utf-8")) if raw_body else {}
    except (UnicodeDecodeError, ValueError) as exc:
        raise HTTPException(status_code=400, detail=f"invalid JSON body: {exc}")

    if body.get("stream"):
        # Honest 501 beats a broken stream: SSE passthrough + post-hoc
        # reconstruction across two different provider event formats was
        # not made solid tonight. Non-streaming is the verified path; the
        # director marks streaming UNVERIFIED.
        raise HTTPException(
            status_code=501,
            detail={
                "gatehouse": {
                    "error": "streaming is not yet supported by gatehouse; retry with stream=false"
                }
            },
        )

    id_lookup = {c.id: c for c in gate_config.constraints}
    requested_model = body.get("model", "")
    parameters: dict[str, Any] = {}
    if "temperature" in body:
        parameters["temperature"] = body["temperature"]
    if "max_tokens" in body:
        parameters["max_tokens"] = body["max_tokens"]

    request_text = (
        _openai_request_text(body) if provider == "openai" else _anthropic_request_text(body)
    )
    request_check = check_text(request_text, gate_config.constraints, applies_to="request")

    if request_check.disposition == "block":
        decision_id = _next_decision_id(store, session_id, "block")
        entry = decision_point_entry(
            decision_id=decision_id,
            category="content_filter",
            options_considered=[{"option_id": "forward"}, {"option_id": "block"}],
            selected_option="block",
            reasoning=json.dumps(
                {"request_check": _check_dict(request_check)}, ensure_ascii=False
            ).encode("utf-8"),
            human_review_required=_human_review_required(request_check, id_lookup),
        )
        wrapper = store.append_entry(session_id, entry)
        _annotate(store, session_id, wrapper["entry"]["entry_id"], "request", request_check, "blocked")
        return _blocked_response(request_check)

    fwd_headers = _forward_headers(request, provider)
    url = f"{base}{path}"

    start = time.monotonic()
    resp = await client.post(url, content=raw_body, headers=fwd_headers)
    latency_ms = int((time.monotonic() - start) * 1000)

    store.put_content(session_id, raw_body)
    store.put_content(session_id, resp.content)

    if resp.status_code >= 400:
        error_entry = model_call_entry(
            provider=provider,
            model_id=requested_model,
            prompt=raw_body,
            completion=resp.content,
            prompt_tokens=0,
            completion_tokens=0,
            latency_ms=latency_ms,
            served_model=None,
            parameters=parameters,
            streamed=False,
            error={
                "code": str(resp.status_code),
                "message": "upstream error",
                "retryable": resp.status_code in (429, 500, 502, 503),
            },
        )
        store.append_entry(session_id, error_entry)
        return Response(
            content=resp.content,
            status_code=resp.status_code,
            media_type=resp.headers.get("content-type", "application/json"),
        )

    try:
        resp_json = resp.json()
    except ValueError:
        resp_json = {}

    served_model = resp_json.get("model")
    usage = resp_json.get("usage") or {}
    if provider == "openai":
        prompt_tokens = usage.get("prompt_tokens", 0)
        completion_tokens = usage.get("completion_tokens", 0)
        response_text = _openai_response_text(resp_json)
    else:
        prompt_tokens = usage.get("input_tokens", 0)
        completion_tokens = usage.get("output_tokens", 0)
        response_text = _anthropic_response_text(resp_json)

    model_call = model_call_entry(
        provider=provider,
        model_id=requested_model,
        prompt=raw_body,
        completion=resp.content,
        prompt_tokens=prompt_tokens,
        completion_tokens=completion_tokens,
        latency_ms=latency_ms,
        served_model=served_model,
        parameters=parameters,
        streamed=False,
    )
    model_call_wrapper = store.append_entry(session_id, model_call)
    model_call_entry_id = model_call_wrapper["entry"]["entry_id"]

    response_check = check_text(response_text, gate_config.constraints, applies_to="response")
    overall_disposition = _combine_disposition(request_check.disposition, response_check.disposition)

    decision_entry = decision_point_entry(
        decision_id=_next_decision_id(store, session_id, overall_disposition),
        category="content_filter",
        options_considered=[
            {"option_id": "correct_continue"},
            {"option_id": "flag"},
            {"option_id": "escalate"},
            {"option_id": "block"},
        ],
        selected_option=overall_disposition,
        reasoning=json.dumps(
            {
                "request_check": _check_dict(request_check),
                "response_check": _check_dict(response_check),
            },
            ensure_ascii=False,
        ).encode("utf-8"),
        human_review_required=(
            _human_review_required(request_check, id_lookup)
            or _human_review_required(response_check, id_lookup)
        ),
    )
    store.append_entry(session_id, decision_entry)

    _annotate(
        store,
        session_id,
        model_call_entry_id,
        "request",
        request_check,
        _ACTION_TAKEN.get(request_check.disposition, "observed"),
    )

    if response_check.disposition == "block":
        _annotate(store, session_id, model_call_entry_id, "response", response_check, "blocked")
        return _blocked_response(response_check)

    _annotate(
        store,
        session_id,
        model_call_entry_id,
        "response",
        response_check,
        _ACTION_TAKEN.get(response_check.disposition, "observed"),
    )

    # Shadow mode: the upstream body and status travel through byte-for-byte.
    # correct_continue / flag / escalate never mutate traffic -- only the
    # (rare) response-level `block` above replaces the body.
    return Response(
        content=resp.content,
        status_code=resp.status_code,
        media_type=resp.headers.get("content-type", "application/json"),
        headers={"X-Gatehouse-Disposition": overall_disposition},
    )


# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------


def _blocked_response(check: CheckResult) -> JSONResponse:
    return JSONResponse(
        status_code=403,
        content={
            "gatehouse": {
                "blocked": True,
                "constraint_ids": check.constraint_ids,
                "content_hash": check.content_hash,
                "disposition": check.disposition,
            }
        },
    )


def _forward_headers(request: Request, provider: str) -> dict[str, str]:
    headers = {"content-type": request.headers.get("content-type", "application/json")}
    if provider == "openai":
        auth = request.headers.get("authorization")
        if auth:
            headers["authorization"] = auth
    else:
        api_key = request.headers.get("x-api-key")
        if api_key:
            headers["x-api-key"] = api_key
        version = request.headers.get("anthropic-version")
        if version:
            headers["anthropic-version"] = version
    return headers


def _next_decision_id(store: SessionStore, session_id: str, disposition: str) -> str:
    n = len(store.entries(session_id)) + 1
    if disposition == "block":
        return f"gate-block-{n}"
    return f"gate-{disposition}-{n}"


def _human_review_required(check: CheckResult, id_lookup: dict[str, GateConstraint]) -> bool:
    if check.disposition == "escalate":
        return True
    return any(id_lookup[cid].soul_invariant for cid in check.constraint_ids if cid in id_lookup)


def _check_dict(check: CheckResult) -> dict:
    return dataclasses.asdict(check)


def _annotate(
    store: SessionStore,
    session_id: str,
    entry_id: str,
    phase: str,
    check: CheckResult,
    action_taken: str,
) -> None:
    annotation = {
        "entry_id": entry_id,
        "phase": phase,
        **_check_dict(check),
        "action_taken": action_taken,
        "timestamp": now_rfc3339(),
    }
    store.append_annotation(session_id, annotation)


def _combine_disposition(a: str, b: str) -> str:
    return a if _PRECEDENCE.get(a, 0) >= _PRECEDENCE.get(b, 0) else b


# ---------------------------------------------------------------------------
# Text extraction (request/response content -> plain text for the checker)
# ---------------------------------------------------------------------------


def _extract_text_from_content(content: Any) -> str:
    """Handle both plain-string content and OpenAI/Anthropic structured
    content-block lists (`[{"type": "text", "text": ...}, ...]`)."""
    if content is None:
        return ""
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts: list[str] = []
        for block in content:
            if isinstance(block, dict):
                text = block.get("text")
                if isinstance(text, str):
                    parts.append(text)
            elif isinstance(block, str):
                parts.append(block)
        return "\n".join(parts)
    return str(content)


def _openai_request_text(body: dict[str, Any]) -> str:
    parts = [_extract_text_from_content(m.get("content")) for m in (body.get("messages") or [])]
    return "\n".join(p for p in parts if p)


def _anthropic_request_text(body: dict[str, Any]) -> str:
    parts: list[str] = []
    system = body.get("system")
    if system is not None:
        parts.append(_extract_text_from_content(system))
    parts.extend(_extract_text_from_content(m.get("content")) for m in (body.get("messages") or []))
    return "\n".join(p for p in parts if p)


def _openai_response_text(resp_json: dict[str, Any]) -> str:
    choices = resp_json.get("choices") or []
    if not choices:
        return ""
    message = choices[0].get("message") or {}
    return _extract_text_from_content(message.get("content"))


def _anthropic_response_text(resp_json: dict[str, Any]) -> str:
    return _extract_text_from_content(resp_json.get("content"))
