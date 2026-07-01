"""
PII / secrets scanner for tool call arguments AND upstream responses
(leakage can happen in either direction).

Regex-based detection with an optional redaction mode. Each finding carries
a category so policy can decide block vs redact vs allow per category
(see config.PII_ACTION_DEFAULT and per-role overrides in policies/roles.yaml).
"""
from __future__ import annotations
import re
from gateway.models import Finding, ScanVerdict

_PATTERNS: dict[str, re.Pattern] = {
    "aws_access_key": re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    "aws_secret_key": re.compile(r"(?i)aws_secret_access_key\s*[:=]\s*['\"]?[A-Za-z0-9/+=]{40}"),
    "generic_api_key": re.compile(r"(?i)\b(api[_-]?key|secret|token)\b\s*[:=]\s*['\"]?[A-Za-z0-9\-_]{16,}"),
    "private_key_block": re.compile(r"-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    "jwt": re.compile(r"\beyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b"),
    "email": re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
    "ssn": re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
    "phone": re.compile(r"\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b"),
    "credit_card": re.compile(r"\b(?:\d[ -]*?){13,19}\b"),
}


def _luhn_valid(number: str) -> bool:
    digits = [int(d) for d in re.sub(r"\D", "", number)]
    if len(digits) < 13:
        return False
    checksum = 0
    parity = len(digits) % 2
    for i, d in enumerate(digits):
        if i % 2 == parity:
            d *= 2
            if d > 9:
                d -= 9
        checksum += d
    return checksum % 10 == 0


def scan_text(text: str) -> list[Finding]:
    findings: list[Finding] = []
    if not text:
        return findings

    for category, pattern in _PATTERNS.items():
        for m in pattern.finditer(text):
            if category == "credit_card":
                if not _luhn_valid(m.group(0)):
                    continue
            findings.append(Finding(
                category=category,
                detail=f"Matched {category} pattern",
                confidence=0.9,
                span=(m.start(), m.end()),
            ))
    return findings


def redact(text: str, findings: list[Finding]) -> str:
    """Replace each finding's span with a category-tagged placeholder,
    processing right-to-left so earlier spans stay valid."""
    for f in sorted(findings, key=lambda x: x.span[0] if x.span else 0, reverse=True):
        if f.span:
            start, end = f.span
            text = text[:start] + f"[REDACTED:{f.category.upper()}]" + text[end:]
    return text


def scan_arguments(arguments: dict, action: str = "block") -> ScanVerdict:
    """
    action: "block" -> disallow the call if any PII/secret found
            "redact" -> allow but return redacted_text for string args (caller applies it)
            "allow"  -> log only, never block
    """
    all_findings: list[Finding] = []

    def _walk(value):
        if isinstance(value, str):
            all_findings.extend(scan_text(value))
        elif isinstance(value, dict):
            for v in value.values():
                _walk(v)
        elif isinstance(value, (list, tuple)):
            for v in value:
                _walk(v)

    _walk(arguments)

    if not all_findings:
        return ScanVerdict(allowed=True, findings=[])

    if action == "allow":
        return ScanVerdict(allowed=True, findings=all_findings, reason="PII/secrets found but action=allow (logged only)")
    if action == "redact":
        return ScanVerdict(allowed=True, findings=all_findings, reason="PII/secrets redacted before forwarding")
    return ScanVerdict(
        allowed=False,
        findings=all_findings,
        reason=f"Blocked: {len(all_findings)} PII/secret finding(s) detected ({', '.join(sorted({f.category for f in all_findings}))})",
    )
