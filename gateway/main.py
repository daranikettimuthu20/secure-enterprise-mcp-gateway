"""
Secure Enterprise MCP Gateway - FastAPI entrypoint.

Pipeline for every /gateway/call request:
  1. OAuth2/JWT auth       -> who is calling (Principal.subject/role)
  2. RBAC policy engine    -> is this role allowed to call this tool/args
  3. Injection scanner     -> do the arguments contain prompt-injection content
  4. PII/secrets scanner   -> do the arguments contain PII/secrets (block/redact/allow per role)
  5. Forward to upstream   -> only if all of the above pass
  6. PII/secrets scanner   -> re-run on the *response* (output-side leakage)
  7. Audit log             -> every decision, allowed or blocked

Run:  uvicorn gateway.main:app --reload --port 8080
"""
from __future__ import annotations
import time
from fastapi import FastAPI, Depends, HTTPException
from fastapi.security import OAuth2PasswordRequestForm

from gateway.config import settings
from gateway.models import ToolCallRequest, ToolCallResult, Principal, Finding
from gateway.auth.oauth2 import authenticate_user, create_access_token, get_current_principal
from gateway.security.policy_engine import PolicyEngine
from gateway.security import injection_scanner, pii_scanner
from gateway.proxy import forward_tool_call
from gateway import audit

app = FastAPI(
    title="Secure Enterprise MCP Gateway",
    description="Security-scanning proxy for MCP tool calls: RBAC + prompt-injection + PII/secret detection.",
    version="0.1.0",
)

policy_engine = PolicyEngine(settings.POLICY_FILE)


@app.post("/token")
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    principal = authenticate_user(form_data.username, form_data.password)
    if not principal:
        raise HTTPException(status_code=400, detail="Incorrect username or password")
    token = create_access_token(principal)
    return {"access_token": token, "token_type": "bearer", "role": principal.role.value}


@app.get("/whoami")
async def whoami(principal: Principal = Depends(get_current_principal)):
    return principal


@app.post("/gateway/call", response_model=ToolCallResult)
async def gateway_call(
    call: ToolCallRequest,
    principal: Principal = Depends(get_current_principal),
):
    start = time.perf_counter()

    # 1. RBAC
    ok, reason = policy_engine.authorize(principal.role, call.tool_name, call.arguments)
    if not ok:
        _audit(principal, call, "blocked", "policy", [], start)
        return ToolCallResult(success=False, error=reason, blocked_by="policy")

    # 2. Prompt injection scan
    injection_verdict = injection_scanner.scan_arguments(
        call.arguments, block_threshold=settings.INJECTION_BLOCK_THRESHOLD
    )
    if not injection_verdict.allowed:
        _audit(principal, call, "blocked", "injection_scanner", injection_verdict.findings, start)
        return ToolCallResult(
            success=False, error=injection_verdict.reason,
            blocked_by="injection_scanner", findings=injection_verdict.findings,
        )

    # 3. PII/secrets scan (policy decides block/redact/allow per role)
    pii_action = policy_engine.pii_action(principal.role)
    pii_verdict = pii_scanner.scan_arguments(call.arguments, action=pii_action)
    if not pii_verdict.allowed:
        _audit(principal, call, "blocked", "pii_scanner", pii_verdict.findings, start)
        return ToolCallResult(
            success=False, error=pii_verdict.reason,
            blocked_by="pii_scanner", findings=pii_verdict.findings,
        )

    # 4. Forward to upstream (only reached if every check above passed)
    upstream_result = await forward_tool_call(call.upstream, call.tool_name, call.arguments)

    # 5. Scan the response too - a tool's OUTPUT can leak secrets just as easily
    response_findings: list[Finding] = []
    if isinstance(upstream_result.get("result"), str):
        response_findings = pii_scanner.scan_text(upstream_result["result"])
        if response_findings and pii_action == "block":
            _audit(principal, call, "blocked", "pii_scanner_response", response_findings, start)
            return ToolCallResult(
                success=False,
                error="Blocked: upstream tool response contained PII/secrets",
                blocked_by="pii_scanner",
                findings=response_findings,
            )
        if response_findings and pii_action == "redact":
            upstream_result["result"] = pii_scanner.redact(upstream_result["result"], response_findings)

    _audit(principal, call, "allowed", None, pii_verdict.findings + response_findings, start)
    return ToolCallResult(
        success=upstream_result.get("success", False),
        result=upstream_result.get("result"),
        error=upstream_result.get("error"),
        findings=pii_verdict.findings + response_findings,
    )


def _audit(principal, call, decision, blocked_by, findings, start_time):
    audit.log_event(
        principal_subject=principal.subject,
        role=principal.role.value,
        upstream=call.upstream,
        tool_name=call.tool_name,
        decision=decision,
        blocked_by=blocked_by,
        findings=[f.model_dump() for f in findings],
        latency_ms=round((time.perf_counter() - start_time) * 1000, 2),
    )


@app.get("/healthz")
async def healthz():
    return {"status": "ok"}
