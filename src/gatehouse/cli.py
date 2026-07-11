"""gatehouse CLI.

Verbs:
  serve        run the proxy
  produce      emit the AER evidence packet (full + redacted dual bundles)
  verify       offline verification of a bundle or audit log -> tri-state verdict
  verify-pair  per-entry binding check of a redacted bundle against its original
  eval         run the FCE 33-scenario suite against a live (or fixtures) config
  sessions     list recorded sessions
  demo         cold end-to-end demo: proxy + stub upstream -> bundles -> verify
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import click


@click.group()
def main() -> None:
    """A fiduciary gate between an agent and a model API."""


# ---------------------------------------------------------------------------
# serve
# ---------------------------------------------------------------------------

@main.command()
@click.option("--host", default="127.0.0.1", show_default=True)
@click.option("--port", default=8787, show_default=True)
@click.option("--var-dir", default="var", show_default=True)
def serve(host: str, port: int, var_dir: str) -> None:
    """Run the gatehouse proxy (shadow mode by default)."""
    import uvicorn

    from .proxy import create_app
    from .store import SessionStore

    app = create_app(store=SessionStore(var_dir))
    uvicorn.run(app, host=host, port=port)


# ---------------------------------------------------------------------------
# produce
# ---------------------------------------------------------------------------

@main.command()
@click.argument("session_id")
@click.option("--out", "out_dir", default=None, help="Output directory (default: var/bundles/<session>)")
@click.option("--var-dir", default="var", show_default=True)
@click.option("--mode", type=click.Choice(["both", "full", "redacted"]), default="both", show_default=True)
@click.option("--sign/--no-sign", default=True, show_default=True, help="Seal manifests with the operator key")
def produce(session_id: str, out_dir: str | None, var_dir: str, mode: str, sign: bool) -> None:
    """Produce the AER §4-shaped evidence packet for SESSION_ID."""
    from .evidence import export_bundle
    from .store import SessionStore

    store = SessionStore(var_dir)
    base = Path(out_dir) if out_dir else Path(var_dir) / "bundles" / session_id
    modes = ["full", "redacted"] if mode == "both" else [mode]
    for m in modes:
        target = base / (f"bundle-{m}")
        target.mkdir(parents=True, exist_ok=True)
        files = export_bundle(store, session_id, target, mode=m, sign=sign)
        click.echo(f"{m} bundle -> {target}")
        for name, digest in files.items():
            click.echo(f"  {name}  sha256:{digest[:16]}…")


# ---------------------------------------------------------------------------
# verify / verify-pair
# ---------------------------------------------------------------------------

def _echo_report(report) -> int:
    click.echo(f"chain:  {'ok' if report.chain_valid else 'FAIL'} ({report.chain_verified_count} entries)")
    click.echo(f"merkle: {'ok' if report.merkle_valid else 'FAIL'}")
    org = {True: "ok", False: "FAIL", None: "absent"}[report.org_signature_valid]
    agent = {True: f"ok ({report.agent_verified_count})", False: "FAIL", None: "absent"}[report.agent_signatures_valid]
    click.echo(f"operator seal: {org}")
    click.echo(f"agent signatures: {agent}")
    if report.contract_hash_valid is not None:
        click.echo(f"contract hash: {'ok' if report.contract_hash_valid else 'FAIL'}")
    for m in report.served_model_mismatches:
        click.echo(
            f"NOTE  served_model mismatch at sequence {m['sequence']}: "
            f"requested {m['model_id']!r}, served {m['served_model']!r} "
            "(recorded honestly; this is evidence, not tampering)"
        )
    if report.status == "authenticated":
        click.secho("AUTHENTICATED — all present verification layers pass", fg="green", bold=True)
        return 0
    if report.status == "consistent_unattributed":
        click.secho(
            "UNATTRIBUTED — internally consistent, but no valid operator seal.\n"
            "This is an unattributed log, not an authenticated record.",
            fg="yellow", bold=True,
        )
        return 0
    click.secho(f"VERIFICATION FAILED — {report.failing_step}", fg="red", bold=True)
    return 1


@main.command()
@click.argument("target", type=click.Path(exists=True, path_type=Path))
def verify(target: Path) -> None:
    """Verify a bundle directory or an audit_log.json. Tri-state verdict."""
    from .verify import verify_audit_log, verify_bundle

    if target.is_dir():
        report = verify_bundle(target)
    else:
        report = verify_audit_log(json.loads(target.read_text(encoding="utf-8")))
    sys.exit(_echo_report(report))


@main.command(name="verify-pair")
@click.argument("redacted_dir", type=click.Path(exists=True, file_okay=False, path_type=Path))
@click.argument("original_log", type=click.Path(exists=True, dir_okay=False, path_type=Path))
def verify_pair_cmd(redacted_dir: Path, original_log: Path) -> None:
    """Prove the redacted bundle derives per-entry from the sealed original."""
    from .verify import verify_pair

    report = verify_pair(redacted_dir, original_log)
    if report.status != "failed":
        click.secho("PAIR OK — the redacted bundle is a faithful per-entry derivation of the original", fg="green", bold=True)
        sys.exit(0)
    click.secho(f"PAIR FAILED — {report.failing_step}", fg="red", bold=True)
    sys.exit(1)


# ---------------------------------------------------------------------------
# eval
# ---------------------------------------------------------------------------

@main.command(name="eval")
@click.argument("config_path", type=click.Path(exists=True, dir_okay=False, path_type=Path))
def eval_cmd(config_path: Path) -> None:
    """Run the FCE 33-scenario suite per CONFIG_PATH (JSON).

    Config keys: provider ("anthropic"|"openai"|"fixtures"), model,
    output_dir, arms?, execution? ("fixtures"|"runtime"|"hybrid"),
    max_output_tokens?, timeout_seconds?, temperature?.
    API keys come from the environment (ANTHROPIC_API_KEY / OPENAI_API_KEY).
    """
    cfg = json.loads(config_path.read_text(encoding="utf-8"))
    provider = cfg.get("provider", "fixtures")
    output_dir = Path(cfg.get("output_dir", "out/fce-eval"))

    from fiduciary.fce.export import write_report_bundle
    from fiduciary.fce.models import EvaluationArm
    from fiduciary.fce.runner import PilotExecutionMode, run_pilot

    execution = PilotExecutionMode(cfg.get("execution", "hybrid"))
    arm_names = cfg.get(
        "arms",
        ["raw_model", "prompted_model", "rules_available_model", "prismweft_runtime"],
    )
    arms = tuple(EvaluationArm(a) for a in arm_names)

    adapter = None
    if provider == "anthropic":
        from fiduciary.fce.adapters import AnthropicBaselineAdapter

        adapter = AnthropicBaselineAdapter(
            model=cfg["model"],
            max_output_tokens=cfg.get("max_output_tokens", 512),
            timeout_seconds=cfg.get("timeout_seconds", 60.0),
        )
    elif provider == "openai":
        from fiduciary.fce.adapters import OpenAIBaselineAdapter

        adapter = OpenAIBaselineAdapter(
            model=cfg["model"],
            max_output_tokens=cfg.get("max_output_tokens", 512),
            timeout_seconds=cfg.get("timeout_seconds", 60.0),
        )
    elif provider != "fixtures":
        raise click.ClickException(f"unknown provider {provider!r}")

    click.echo(f"FCE eval: provider={provider} execution={execution.value} arms={[a.value for a in arms]}")
    result = run_pilot(mode=execution, arms=arms, baseline_adapter=adapter)
    output_dir.mkdir(parents=True, exist_ok=True)
    write_report_bundle(output_dir, result, execution)
    click.echo(f"report bundle -> {output_dir}")
    for s in result.summaries:
        click.echo(f"  {s}")


# ---------------------------------------------------------------------------
# sessions
# ---------------------------------------------------------------------------

@main.command()
@click.option("--var-dir", default="var", show_default=True)
def sessions(var_dir: str) -> None:
    """List recorded sessions."""
    from .store import SessionStore

    store = SessionStore(var_dir)
    for sid in store.list_sessions():
        sess = store.load_session(sid)
        n = len(store.entries(sid))
        state = "closed" if "closed_at" in sess else "open"
        click.echo(f"{sid}  {state}  entries={n}  objective={sess.get('intent_contract', {}).get('objective', '')[:60]!r}")


# ---------------------------------------------------------------------------
# demo — cold end-to-end proof, zero API keys, zero network
# ---------------------------------------------------------------------------

@main.command()
@click.option("--out", "out_dir", default="var/demo", show_default=True)
def demo(out_dir: str) -> None:
    """Full pipeline, cold: open a gated session, drive real HTTP through the
    proxy against a stub upstream that silently substitutes the served model,
    close, produce dual bundles, verify. No keys, no network."""
    import httpx
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    from .evidence import export_bundle
    from .proxy import create_app
    from .store import SessionStore
    from .verify import verify_bundle, verify_pair

    base = Path(out_dir)
    base.mkdir(parents=True, exist_ok=True)
    store = SessionStore(base / "var")

    # A stub provider that asserts a DIFFERENT model than requested — the
    # silent stepdown served_model exists to catch.
    stub = FastAPI()

    @stub.post("/v1/messages")
    async def _messages(body: dict):  # type: ignore[no-untyped-def]
        return {
            "id": "msg_demo",
            "type": "message",
            "model": "claude-sonnet-5",  # requested model will be fable — a reroute
            "content": [{"type": "text", "text": "Here is the memo draft. Nothing privileged is quoted."}],
            "usage": {"input_tokens": 42, "output_tokens": 17},
        }

    upstream = httpx.AsyncClient(transport=httpx.ASGITransport(app=stub), base_url="https://api.anthropic.com")
    app = create_app(store=store, upstream_client=upstream)
    client = TestClient(app)

    r = client.post(
        "/gatehouse/sessions",
        json={
            "objective": "Draft a public-facing memo without quoting privileged material",
            "jurisdiction": "Minnesota",
            "role": "research-assistant",
            "constraints": [
                {
                    "id": "no-privileged",
                    "description": "never quote privileged or attorney-client material",
                    "severity": "P0",
                    "enforcement": "must_not_include_regex",
                    "target": "privileged|attorney.client",
                    "applies_to": "both",
                    "on_violation": "flag",
                    "soul_invariant": True,
                }
            ],
            "human_authorizer": {"identifier": "alex@alexgallefrom.io", "role": "attorney"},
            "environment": "development",
            "compliance_contexts": ["FINRA_4511"],
        },
    )
    r.raise_for_status()
    session_id = r.json()["session_id"]
    click.echo(f"session opened: {session_id}")

    r = client.post(
        "/v1/messages",
        headers={"X-Gatehouse-Session": session_id, "x-api-key": "demo-key", "anthropic-version": "2023-06-01"},
        json={
            "model": "claude-fable-5",
            "max_tokens": 256,
            "messages": [{"role": "user", "content": "Draft the memo. Do not touch the privileged timeline."}],
        },
    )
    r.raise_for_status()
    click.echo(f"proxied call ok; disposition: {r.headers.get('X-Gatehouse-Disposition')}")

    client.post(f"/gatehouse/sessions/{session_id}/close")

    full_dir = base / "bundle-full"
    red_dir = base / "bundle-redacted"
    full_dir.mkdir(exist_ok=True)
    red_dir.mkdir(exist_ok=True)
    export_bundle(store, session_id, full_dir, mode="full")
    export_bundle(store, session_id, red_dir, mode="redacted")
    click.echo(f"bundles -> {full_dir} , {red_dir}")

    report = verify_bundle(full_dir)
    code = _echo_report(report)
    pair = verify_pair(red_dir, full_dir / "audit_log.json")
    click.echo(f"pair binding: {'ok' if pair.status != 'failed' else 'FAILED: ' + str(pair.failing_step)}")
    if report.served_model_mismatches:
        click.secho(
            f"served_model caught the reroute: requested claude-fable-5, served claude-sonnet-5 — "
            "and the record still verifies AUTHENTICATED, because a reroute recorded honestly is evidence, not tampering.",
            fg="cyan",
        )
    sys.exit(code)


if __name__ == "__main__":
    main()
